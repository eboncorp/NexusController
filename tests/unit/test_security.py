#!/usr/bin/env python3
"""
Unit tests for NexusController security module
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

try:
    from nexuscontroller.security.auth import (
        SecurityService, SecurityConfig, UserModel, Role, Permission,
        APIKeyService, security_headers_middleware
    )
    NEXUS_MODULES_AVAILABLE = True
except ImportError:
    NEXUS_MODULES_AVAILABLE = False

pytestmark = pytest.mark.unit


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestSecurityService:
    """Test SecurityService functionality"""
    
    def test_password_hashing(self, security_service):
        """Test password hashing and verification"""
        password = "SecureP@ssw0rd123!"
        
        # Test hashing
        hashed = SecurityService.hash_password(password)
        assert hashed != password
        assert len(hashed) > 50  # bcrypt hashes are long
        
        # Test verification
        assert SecurityService.verify_password(password, hashed)
        assert not SecurityService.verify_password("wrong_password", hashed)
    
    def test_password_strength_validation(self, security_service):
        """Test password strength validation"""
        # Valid password
        valid, message = security_service.validate_password_strength("SecureP@ssw0rd123!")
        assert valid
        assert "strong" in message.lower()
        
        # Too short
        valid, message = security_service.validate_password_strength("short")
        assert not valid
        assert "length" in message.lower()
        
        # No uppercase
        valid, message = security_service.validate_password_strength("nouppercase123!")
        assert not valid
        assert "uppercase" in message.lower()
        
        # No special characters
        valid, message = security_service.validate_password_strength("NoSpecialChar123")
        assert not valid
        assert "special" in message.lower()
    
    def test_jwt_token_creation_and_verification(self, security_service, test_user):
        """Test JWT token creation and verification"""
        # Create access token
        access_token = security_service.create_access_token(test_user)
        assert isinstance(access_token, str)
        assert len(access_token) > 100  # JWT tokens are long
        
        # Verify token
        token_data = security_service.verify_token(access_token)
        assert token_data is not None
        assert token_data.username == test_user.username
        assert token_data.token_type == "access"
        
        # Create refresh token
        refresh_token = security_service.create_refresh_token(test_user)
        refresh_data = security_service.verify_token(refresh_token)
        assert refresh_data.token_type == "refresh"
    
    def test_invalid_token_verification(self, security_service):
        """Test verification of invalid tokens"""
        # Invalid token
        assert security_service.verify_token("invalid.token.here") is None
        
        # Empty token
        assert security_service.verify_token("") is None
    
    @pytest.mark.asyncio
    async def test_token_revocation(self, security_service, test_user):
        """Test token revocation"""
        token = security_service.create_access_token(test_user)
        
        # Token should be valid initially
        assert security_service.verify_token(token) is not None
        
        # Revoke token
        await security_service.revoke_token(token)
        
        # Token should be invalid after revocation
        assert security_service.verify_token(token) is None
    
    def test_role_based_permissions(self, security_service):
        """Test RBAC permission checking"""
        # Admin should have all permissions
        admin_roles = [Role.ADMIN]
        assert security_service.check_permission(admin_roles, Permission.RESOURCE_READ)
        assert security_service.check_permission(admin_roles, Permission.ADMIN_ACCESS)
        
        # Viewer should have limited permissions
        viewer_roles = [Role.VIEWER]
        assert security_service.check_permission(viewer_roles, Permission.RESOURCE_READ)
        assert not security_service.check_permission(viewer_roles, Permission.RESOURCE_DELETE)
        assert not security_service.check_permission(viewer_roles, Permission.ADMIN_ACCESS)
        
        # Operator should have intermediate permissions
        operator_roles = [Role.OPERATOR]
        assert security_service.check_permission(operator_roles, Permission.RESOURCE_READ)
        assert security_service.check_permission(operator_roles, Permission.RESOURCE_WRITE)
        assert not security_service.check_permission(operator_roles, Permission.ADMIN_ACCESS)
    
    def test_multiple_permissions_check(self, security_service):
        """Test checking multiple permissions at once"""
        admin_roles = [Role.ADMIN]
        required_permissions = [Permission.RESOURCE_READ, Permission.RESOURCE_WRITE]
        
        assert security_service.check_permissions(admin_roles, required_permissions)
        
        viewer_roles = [Role.VIEWER]
        assert not security_service.check_permissions(viewer_roles, required_permissions)
    
    @pytest.mark.asyncio
    async def test_session_management(self, security_service):
        """Test session creation and validation"""
        username = "testuser"
        
        # Create session
        session_id = await security_service.create_session(username)
        assert isinstance(session_id, str)
        assert len(session_id) > 20
        
        # Validate session
        is_valid = await security_service.validate_session(session_id)
        assert is_valid
        
        # Destroy session
        await security_service.destroy_session(session_id)
        is_valid = await security_service.validate_session(session_id)
        assert not is_valid
    
    @pytest.mark.asyncio
    async def test_session_timeout(self, security_service):
        """Test session timeout functionality"""
        # Create service with short timeout
        config = SecurityConfig(
            jwt_secret_key="test-key",
            session_timeout_minutes=0.01  # Very short timeout for testing
        )
        short_timeout_service = SecurityService(config)
        
        username = "testuser"
        session_id = await short_timeout_service.create_session(username)
        
        # Session should be valid initially
        assert await short_timeout_service.validate_session(session_id)
        
        # Wait for timeout
        await asyncio.sleep(1)
        
        # Session should be invalid after timeout
        assert not await short_timeout_service.validate_session(session_id)
    
    @pytest.mark.asyncio
    async def test_failed_login_handling(self, security_service):
        """Test failed login attempt handling"""
        user = UserModel(
            username="testuser",
            email="test@example.com",
            roles=[Role.VIEWER]
        )
        
        # Simulate failed logins
        for i in range(3):
            is_locked = await security_service.handle_failed_login(user)
            if i < 2:
                assert not is_locked
                assert user.failed_login_attempts == i + 1
            else:
                assert is_locked
                assert user.is_locked
    
    @pytest.mark.asyncio
    async def test_successful_login_reset(self, security_service):
        """Test successful login resetting failed attempts"""
        user = UserModel(
            username="testuser",
            email="test@example.com",
            roles=[Role.VIEWER]
        )
        
        # Simulate failed attempts
        user.failed_login_attempts = 2
        
        # Successful login should reset counter
        await security_service.handle_successful_login(user)
        assert user.failed_login_attempts == 0
        assert user.last_login is not None
    
    def test_mfa_secret_generation(self, security_service):
        """Test MFA secret generation"""
        secret = security_service.generate_mfa_secret()
        assert isinstance(secret, str)
        assert len(secret) > 20
        
        # Should generate different secrets
        secret2 = security_service.generate_mfa_secret()
        assert secret != secret2
    
    def test_totp_uri_generation(self, security_service):
        """Test TOTP URI generation for QR codes"""
        username = "testuser"
        secret = "TESTSECRET123456"
        
        uri = security_service.generate_totp_uri(username, secret)
        assert uri.startswith("otpauth://totp/")
        assert username in uri
        assert secret in uri
        assert "NexusController" in uri


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestAPIKeyService:
    """Test APIKeyService functionality"""
    
    @pytest.mark.asyncio
    async def test_api_key_generation(self):
        """Test API key generation"""
        service = APIKeyService()
        user = UserModel(
            username="testuser",
            email="test@example.com",
            roles=[Role.VIEWER]
        )
        
        api_key = await service.generate_api_key(user, "Test Key")
        assert isinstance(api_key, str)
        assert api_key.startswith("nxc_")
        assert len(api_key) > 40
    
    @pytest.mark.asyncio
    async def test_api_key_validation(self):
        """Test API key validation"""
        service = APIKeyService()
        user = UserModel(
            username="testuser",
            email="test@example.com",
            roles=[Role.VIEWER]
        )
        
        # Generate key
        api_key = await service.generate_api_key(user, "Test Key")
        
        # Validate key
        key_data = await service.validate_api_key(api_key)
        assert key_data is not None
        assert key_data["username"] == user.username
        assert key_data["name"] == "Test Key"
        assert key_data["usage_count"] == 1  # First validation increments count
        
        # Invalid key
        invalid_data = await service.validate_api_key("invalid_key")
        assert invalid_data is None
    
    @pytest.mark.asyncio
    async def test_api_key_revocation(self):
        """Test API key revocation"""
        service = APIKeyService()
        user = UserModel(
            username="testuser",
            email="test@example.com",
            roles=[Role.VIEWER]
        )
        
        # Generate and validate key
        api_key = await service.generate_api_key(user, "Test Key")
        assert await service.validate_api_key(api_key) is not None
        
        # Revoke key
        revoked = await service.revoke_api_key(api_key)
        assert revoked
        
        # Key should be invalid after revocation
        assert await service.validate_api_key(api_key) is None
        
        # Revoking again should return False
        assert not await service.revoke_api_key(api_key)
    
    @pytest.mark.asyncio
    async def test_api_key_expiration(self):
        """Test API key expiration"""
        service = APIKeyService()
        user = UserModel(
            username="testuser",
            email="test@example.com",
            roles=[Role.VIEWER]
        )
        
        # Generate key with very short expiration for testing
        api_key = await service.generate_api_key(user, "Test Key", expires_in_days=0)
        
        # Key should be expired immediately
        key_data = await service.validate_api_key(api_key)
        assert key_data is None


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestUserModel:
    """Test UserModel validation"""
    
    def test_valid_user_creation(self):
        """Test creating valid user"""
        user = UserModel(
            username="validuser",
            email="valid@example.com",
            roles=[Role.VIEWER]
        )
        assert user.username == "validuser"
        assert user.email == "valid@example.com"
        assert user.roles == [Role.VIEWER]
        assert user.is_active
        assert not user.is_locked
    
    def test_invalid_username_validation(self):
        """Test username validation"""
        # Too short
        with pytest.raises(ValueError):
            UserModel(
                username="ab",
                email="test@example.com",
                roles=[Role.VIEWER]
            )
        
        # Invalid characters
        with pytest.raises(ValueError):
            UserModel(
                username="user@invalid",
                email="test@example.com",
                roles=[Role.VIEWER]
            )
    
    def test_invalid_email_validation(self):
        """Test email validation"""
        with pytest.raises(ValueError):
            UserModel(
                username="testuser",
                email="invalid-email",
                roles=[Role.VIEWER]
            )
    
    def test_empty_roles_validation(self):
        """Test that user must have at least one role"""
        with pytest.raises(ValueError):
            UserModel(
                username="testuser",
                email="test@example.com",
                roles=[]
            )


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestSecurityConfig:
    """Test SecurityConfig validation"""
    
    def test_valid_config_creation(self):
        """Test creating valid security config"""
        config = SecurityConfig(
            jwt_secret_key="test-key",
            access_token_expire_minutes=30,
            max_login_attempts=5
        )
        assert config.jwt_secret_key == "test-key"
        assert config.access_token_expire_minutes == 30
        assert config.max_login_attempts == 5
    
    def test_invalid_config_validation(self):
        """Test config validation"""
        # Negative expiration time
        with pytest.raises(ValueError):
            SecurityConfig(
                jwt_secret_key="test-key",
                access_token_expire_minutes=-1
            )
        
        # Zero max login attempts
        with pytest.raises(ValueError):
            SecurityConfig(
                jwt_secret_key="test-key",
                max_login_attempts=0
            )


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
@pytest.mark.asyncio
async def test_security_headers_middleware():
    """Test security headers middleware"""
    from fastapi import Request, Response
    from fastapi.responses import JSONResponse
    
    # Mock request and response
    request = MagicMock(spec=Request)
    
    async def mock_call_next(req):
        return JSONResponse(content={"test": "response"})
    
    # Apply middleware
    response = await security_headers_middleware(request, mock_call_next)
    
    # Check security headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-XSS-Protection"] == "1; mode=block"
    assert "Strict-Transport-Security" in response.headers
    assert "Content-Security-Policy" in response.headers
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestPermissionEnums:
    """Test permission and role enums"""
    
    def test_permission_enum_values(self):
        """Test permission enum values"""
        assert Permission.RESOURCE_READ.value == "resource:read"
        assert Permission.RESOURCE_WRITE.value == "resource:write"
        assert Permission.ADMIN_ACCESS.value == "admin:access"
    
    def test_role_enum_values(self):
        """Test role enum values"""
        assert Role.ADMIN.value == "admin"
        assert Role.OPERATOR.value == "operator"
        assert Role.VIEWER.value == "viewer"
    
    def test_permission_in_role_mapping(self, security_service):
        """Test that all permissions are mapped to roles"""
        all_permissions = set(Permission)
        mapped_permissions = set()
        
        for role_permissions in SecurityService.ROLE_PERMISSIONS.values():
            mapped_permissions.update(role_permissions)
        
        # All permissions should be mapped to at least one role
        assert all_permissions.issubset(mapped_permissions)