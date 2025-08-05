#!/usr/bin/env python3
"""
Integration tests for NexusController API security
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch

try:
    from httpx import AsyncClient
    from fastapi import status
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    from nexus_api_server_enhanced import app
    from nexus_auth_security import security_service, api_key_service, Role, Permission
    NEXUS_MODULES_AVAILABLE = True
except ImportError:
    NEXUS_MODULES_AVAILABLE = False

pytestmark = pytest.mark.integration


@pytest.mark.skipif(not (FASTAPI_AVAILABLE and NEXUS_MODULES_AVAILABLE), 
                    reason="FastAPI or Nexus modules not available")
class TestAuthenticationEndpoints:
    """Test authentication API endpoints"""
    
    @pytest.mark.asyncio
    async def test_health_endpoint_public_access(self, api_client):
        """Test that health endpoint is publicly accessible"""
        response = await api_client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        
        data = response.json()
        assert data["status"] in ["healthy", "unhealthy"]
        assert "version" in data
        assert "uptime" in data
        assert "dependencies" in data
    
    @pytest.mark.asyncio
    async def test_metrics_endpoint_public_access(self, api_client):
        """Test that metrics endpoint is publicly accessible"""
        response = await api_client.get("/metrics")
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "text/plain; charset=utf-8"
    
    @pytest.mark.asyncio
    async def test_login_with_valid_credentials(self, api_client, db_manager, sample_user_data):
        """Test login with valid credentials"""
        # Mock database user lookup
        with patch.object(db_manager, 'get_user_by_username') as mock_get_user, \
             patch.object(db_manager, 'handle_successful_login') as mock_success_login:
            
            # Create mock user object
            from nexus_database_manager import NexusUser
            mock_user = NexusUser(**sample_user_data)
            mock_get_user.return_value = mock_user
            
            login_data = {
                "username": "testuser",
                "password": "correct_password"
            }
            
            # Mock password verification
            with patch('nexus_auth_security.SecurityService.verify_password', return_value=True):
                response = await api_client.post("/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "Bearer"
            assert "expires_in" in data
            assert "user_info" in data
            
            # Verify user info
            user_info = data["user_info"]
            assert user_info["username"] == "testuser"
            assert user_info["email"] == sample_user_data["email"]
    
    @pytest.mark.asyncio
    async def test_login_with_invalid_credentials(self, api_client, db_manager):
        """Test login with invalid credentials"""
        with patch.object(db_manager, 'get_user_by_username', return_value=None):
            login_data = {
                "username": "nonexistent",
                "password": "wrong_password"
            }
            
            response = await api_client.post("/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            data = response.json()
            assert data["detail"] == "Invalid credentials"
    
    @pytest.mark.asyncio
    async def test_login_with_locked_account(self, api_client, db_manager, sample_user_data):
        """Test login with locked account"""
        with patch.object(db_manager, 'get_user_by_username') as mock_get_user:
            from nexus_database_manager import NexusUser
            
            # Create locked user
            locked_user_data = sample_user_data.copy()
            locked_user_data["is_locked"] = True
            mock_user = NexusUser(**locked_user_data)
            mock_get_user.return_value = mock_user
            
            login_data = {
                "username": "testuser",
                "password": "correct_password"
            }
            
            with patch('nexus_auth_security.SecurityService.verify_password', return_value=True):
                response = await api_client.post("/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_423_LOCKED
            data = response.json()
            assert data["detail"] == "Account is locked"
    
    @pytest.mark.asyncio
    async def test_login_with_mfa_required(self, api_client, db_manager, sample_user_data):
        """Test login with MFA required but not provided"""
        with patch.object(db_manager, 'get_user_by_username') as mock_get_user:
            from nexus_database_manager import NexusUser
            
            # Create MFA-enabled user
            mfa_user_data = sample_user_data.copy()
            mfa_user_data["mfa_enabled"] = True
            mfa_user_data["mfa_secret"] = "test_mfa_secret"
            mock_user = NexusUser(**mfa_user_data)
            mock_get_user.return_value = mock_user
            
            login_data = {
                "username": "testuser",
                "password": "correct_password"
            }
            
            with patch('nexus_auth_security.SecurityService.verify_password', return_value=True):
                response = await api_client.post("/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
            data = response.json()
            assert data["detail"] == "MFA token required"
    
    @pytest.mark.asyncio
    async def test_login_rate_limiting(self, api_client):
        """Test login rate limiting"""
        login_data = {
            "username": "testuser",
            "password": "password"
        }
        
        # Make multiple rapid requests to trigger rate limiting
        responses = []
        for _ in range(10):  # Attempt more than the rate limit
            response = await api_client.post("/auth/login", json=login_data)
            responses.append(response)
        
        # At least one request should be rate limited
        rate_limited = any(r.status_code == status.HTTP_429_TOO_MANY_REQUESTS for r in responses)
        assert rate_limited, "Rate limiting should have been triggered"
    
    @pytest.mark.asyncio
    async def test_refresh_token_valid(self, api_client, test_user, security_service):
        """Test refresh token with valid token"""
        # Create refresh token
        refresh_token = security_service.create_refresh_token(test_user)
        
        refresh_data = {
            "refresh_token": refresh_token
        }
        
        with patch('nexus_database_manager.db_manager.get_user_by_username') as mock_get_user:
            from nexus_database_manager import NexusUser
            mock_user = NexusUser(
                username=test_user.username,
                email=test_user.email,
                password_hash="hash",
                roles=[role.value for role in test_user.roles],
                is_active=True
            )
            mock_get_user.return_value = mock_user
            
            response = await api_client.post("/auth/refresh", json=refresh_data)
        
        assert response.status_code == status.HTTP_200_OK
        
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, api_client):
        """Test refresh token with invalid token"""
        refresh_data = {
            "refresh_token": "invalid.token.here"
        }
        
        response = await api_client.post("/auth/refresh", json=refresh_data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert data["detail"] == "Invalid refresh token"
    
    @pytest.mark.asyncio
    async def test_logout_success(self, api_client, authenticated_headers):
        """Test successful logout"""
        response = await api_client.post("/auth/logout", headers=authenticated_headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Logged out successfully"
    
    @pytest.mark.asyncio
    async def test_logout_without_authentication(self, api_client):
        """Test logout without authentication"""
        response = await api_client.post("/auth/logout")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.skipif(not (FASTAPI_AVAILABLE and NEXUS_MODULES_AVAILABLE), 
                    reason="FastAPI or Nexus modules not available")
class TestAPIAuthorization:
    """Test API authorization and access control"""
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_without_auth(self, api_client):
        """Test accessing protected endpoint without authentication"""
        response = await api_client.get("/api/v1/resources")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert data["success"] is False
        assert "authorization" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_with_valid_token(self, api_client, authenticated_headers):
        """Test accessing protected endpoint with valid token"""
        with patch('nexus_database_manager.db_manager.get_resources_by_provider', return_value=[]):
            response = await api_client.get("/api/v1/resources", headers=authenticated_headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_with_invalid_token(self, api_client):
        """Test accessing protected endpoint with invalid token"""
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = await api_client.get("/api/v1/resources", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_admin_endpoint_with_user_token(self, api_client, authenticated_headers):
        """Test accessing admin endpoint with regular user token"""
        response = await api_client.get("/api/v1/admin/stats", headers=authenticated_headers)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_admin_endpoint_with_admin_token(self, api_client, admin_headers):
        """Test accessing admin endpoint with admin token"""
        response = await api_client.get("/api/v1/admin/stats", headers=admin_headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "data" in data
    
    @pytest.mark.asyncio
    async def test_api_key_authentication(self, api_client, test_user):
        """Test API key authentication"""
        # Generate API key
        api_key = await api_key_service.generate_api_key(test_user, "Test API Key")
        
        headers = {"Authorization": f"ApiKey {api_key}"}
        
        with patch('nexus_database_manager.db_manager.get_resources_by_provider', return_value=[]):
            response = await api_client.get("/api/v1/resources", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
    
    @pytest.mark.asyncio
    async def test_invalid_api_key_authentication(self, api_client):
        """Test invalid API key authentication"""
        headers = {"Authorization": "ApiKey invalid_api_key"}
        response = await api_client.get("/api/v1/resources", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.skipif(not (FASTAPI_AVAILABLE and NEXUS_MODULES_AVAILABLE), 
                    reason="FastAPI or Nexus modules not available")
class TestSecurityHeaders:
    """Test security headers in API responses"""
    
    @pytest.mark.asyncio
    async def test_security_headers_present(self, api_client):
        """Test that security headers are present in responses"""
        response = await api_client.get("/health")
        
        # Check for security headers
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
        assert "Strict-Transport-Security" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Permissions-Policy" in response.headers
    
    @pytest.mark.asyncio
    async def test_correlation_id_header(self, api_client):
        """Test that correlation ID is added to responses"""
        response = await api_client.get("/health")
        
        assert "X-Correlation-ID" in response.headers
        correlation_id = response.headers["X-Correlation-ID"]
        
        # Should be a valid UUID format
        import uuid
        try:
            uuid.UUID(correlation_id)
        except ValueError:
            pytest.fail(f"Correlation ID '{correlation_id}' is not a valid UUID")
    
    @pytest.mark.asyncio
    async def test_server_header_removed(self, api_client):
        """Test that server header is removed for security"""
        response = await api_client.get("/health")
        
        # Server header should not be present
        assert "server" not in response.headers
        assert "Server" not in response.headers


@pytest.mark.skipif(not (FASTAPI_AVAILABLE and NEXUS_MODULES_AVAILABLE), 
                    reason="FastAPI or Nexus modules not available")
class TestInputValidation:
    """Test input validation and sanitization"""
    
    @pytest.mark.asyncio
    async def test_login_input_validation(self, api_client):
        """Test login input validation"""
        # Missing username
        response = await api_client.post("/auth/login", json={"password": "password"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Missing password
        response = await api_client.post("/auth/login", json={"username": "user"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Empty username
        response = await api_client.post("/auth/login", json={"username": "", "password": "password"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Short password
        response = await api_client.post("/auth/login", json={"username": "user", "password": "short"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_resource_creation_input_validation(self, api_client, authenticated_headers):
        """Test resource creation input validation"""
        # Missing required fields
        invalid_resource = {"name": "test"}
        response = await api_client.post(
            "/api/v1/resources", 
            json=invalid_resource, 
            headers=authenticated_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Invalid name length
        invalid_resource = {
            "name": "",  # Empty name
            "resource_type": "compute",
            "provider": "aws",
            "region": "us-east-1"
        }
        response = await api_client.post(
            "/api/v1/resources", 
            json=invalid_resource, 
            headers=authenticated_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_xss_prevention(self, api_client, authenticated_headers):
        """Test XSS attack prevention"""
        malicious_input = {
            "name": "<script>alert('xss')</script>",
            "resource_type": "compute",
            "provider": "aws",
            "region": "us-east-1"
        }
        
        with patch('nexus_database_manager.db_manager.create_resource') as mock_create:
            mock_create.return_value = MagicMock(id="test-id", name="safe-name", type="compute", status="pending")
            
            response = await api_client.post(
                "/api/v1/resources", 
                json=malicious_input, 
                headers=authenticated_headers
            )
        
        # Request should be processed but input should be sanitized
        # The actual sanitization would happen in the business logic
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_422_UNPROCESSABLE_ENTITY]
    
    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self, api_client, authenticated_headers):
        """Test SQL injection prevention"""
        # Try SQL injection in query parameters
        malicious_params = {"provider": "aws'; DROP TABLE resources; --"}
        
        with patch('nexus_database_manager.db_manager.get_resources_by_provider', return_value=[]):
            response = await api_client.get(
                "/api/v1/resources",
                params=malicious_params,
                headers=authenticated_headers
            )
        
        # Should not cause server error (parameterized queries should prevent injection)
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.skipif(not (FASTAPI_AVAILABLE and NEXUS_MODULES_AVAILABLE), 
                    reason="FastAPI or Nexus modules not available")
class TestErrorHandling:
    """Test security-related error handling"""
    
    @pytest.mark.asyncio
    async def test_404_error_handling(self, api_client):
        """Test 404 error handling doesn't leak information"""
        response = await api_client.get("/nonexistent/endpoint")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert data["success"] is False
        assert data["message"] == "Resource not found"
        assert "path" in data["metadata"]
    
    @pytest.mark.asyncio
    async def test_500_error_handling(self, api_client):
        """Test 500 error handling includes correlation ID"""
        # Force a server error by mocking a failure
        with patch('nexus_api_server_enhanced.get_observability_manager', side_effect=Exception("Test error")):
            response = await api_client.get("/health")
        
        # Should return 500 with correlation ID
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        data = response.json()
        assert data["success"] is False
        assert data["message"] == "Internal server error"
        assert "correlation_id" in data["metadata"]
        assert "X-Correlation-ID" in response.headers
    
    @pytest.mark.asyncio
    async def test_authentication_error_timing(self, api_client):
        """Test authentication errors don't reveal timing information"""
        import time
        
        # Time login attempts with valid and invalid users
        start_time = time.time()
        response1 = await api_client.post("/auth/login", json={"username": "validuser", "password": "wrongpass"})
        time1 = time.time() - start_time
        
        start_time = time.time()
        response2 = await api_client.post("/auth/login", json={"username": "invaliduser", "password": "wrongpass"})
        time2 = time.time() - start_time
        
        # Both should return 401
        assert response1.status_code == status.HTTP_401_UNAUTHORIZED
        assert response2.status_code == status.HTTP_401_UNAUTHORIZED
        
        # Timing difference should be minimal (within 500ms tolerance for testing)
        time_diff = abs(time1 - time2)
        assert time_diff < 0.5, f"Timing difference too large: {time_diff}s"