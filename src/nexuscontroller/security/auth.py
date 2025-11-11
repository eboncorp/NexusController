#!/usr/bin/env python3
"""
Enhanced Security Module for NexusController v2.0
Implements JWT authentication, RBAC, and security best practices
"""

import os
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Set, Dict, Any, Protocol
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ConfigDict, field_validator
from functools import wraps
import asyncio
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Permission(Enum):
    """System permissions"""
    RESOURCE_READ = "resource:read"
    RESOURCE_WRITE = "resource:write"
    RESOURCE_DELETE = "resource:delete"
    RESOURCE_EXECUTE = "resource:execute"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    ADMIN_ACCESS = "admin:access"
    MONITOR_READ = "monitor:read"
    MONITOR_WRITE = "monitor:write"
    PLUGIN_MANAGE = "plugin:manage"
    BACKUP_MANAGE = "backup:manage"
    SECURITY_AUDIT = "security:audit"


class Role(Enum):
    """User roles"""
    ADMIN = "admin"
    OPERATOR = "operator"
    DEVELOPER = "developer"
    VIEWER = "viewer"
    AUDITOR = "auditor"
    SERVICE_ACCOUNT = "service_account"


@dataclass
class SecurityConfig:
    """Security configuration"""
    jwt_secret_key: str = os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special: bool = True
    mfa_enabled: bool = True
    session_timeout_minutes: int = 60
    api_rate_limit: int = 100
    api_rate_limit_window: int = 60


class UserModel(BaseModel):
    """User model with validation"""
    model_config = ConfigDict(validate_assignment=True)
    
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    email: str = Field(..., pattern="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
    roles: List[Role] = Field(default_factory=list)
    permissions: Optional[Set[Permission]] = None
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    
    @field_validator('roles')
    def validate_roles(cls, v):
        if not v:
            raise ValueError('User must have at least one role')
        return v


class TokenData(BaseModel):
    """JWT token data"""
    username: str
    roles: List[str]
    permissions: List[str]
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for token revocation
    token_type: str = "access"


class SecurityService:
    """Main security service"""
    
    ROLE_PERMISSIONS = {
        Role.ADMIN: set(Permission),  # All permissions
        Role.OPERATOR: {
            Permission.RESOURCE_READ, Permission.RESOURCE_WRITE, Permission.RESOURCE_EXECUTE,
            Permission.CONFIG_READ, Permission.CONFIG_WRITE,
            Permission.MONITOR_READ, Permission.MONITOR_WRITE,
            Permission.PLUGIN_MANAGE, Permission.BACKUP_MANAGE
        },
        Role.DEVELOPER: {
            Permission.RESOURCE_READ, Permission.RESOURCE_WRITE,
            Permission.CONFIG_READ, Permission.MONITOR_READ,
            Permission.PLUGIN_MANAGE
        },
        Role.VIEWER: {
            Permission.RESOURCE_READ, Permission.CONFIG_READ,
            Permission.MONITOR_READ, Permission.USER_READ
        },
        Role.AUDITOR: {
            Permission.RESOURCE_READ, Permission.CONFIG_READ,
            Permission.MONITOR_READ, Permission.USER_READ,
            Permission.SECURITY_AUDIT
        },
        Role.SERVICE_ACCOUNT: {
            Permission.RESOURCE_READ, Permission.RESOURCE_WRITE,
            Permission.MONITOR_READ
        }
    }
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.revoked_tokens: Set[str] = set()
        self.active_sessions: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()
        logger.info("Security service initialized")
    
    # Password Management
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate password meets security requirements"""
        if len(password) < self.config.password_min_length:
            return False, f"Password must be at least {self.config.password_min_length} characters"
        
        if self.config.password_require_uppercase and not any(c.isupper() for c in password):
            return False, "Password must contain uppercase letters"
        
        if self.config.password_require_lowercase and not any(c.islower() for c in password):
            return False, "Password must contain lowercase letters"
        
        if self.config.password_require_numbers and not any(c.isdigit() for c in password):
            return False, "Password must contain numbers"
        
        if self.config.password_require_special:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                return False, "Password must contain special characters"
        
        return True, "Password is strong"
    
    # JWT Token Management
    def create_access_token(self, user: UserModel) -> str:
        """Create JWT access token"""
        permissions = self.get_user_permissions(user.roles)
        
        token_data = {
            "sub": user.username,
            "roles": [role.value for role in user.roles],
            "permissions": [perm.value for perm in permissions],
            "exp": datetime.utcnow() + timedelta(minutes=self.config.access_token_expire_minutes),
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(32),
            "token_type": "access"
        }
        
        return jwt.encode(token_data, self.config.jwt_secret_key, algorithm=self.config.jwt_algorithm)
    
    def create_refresh_token(self, user: UserModel) -> str:
        """Create JWT refresh token"""
        token_data = {
            "sub": user.username,
            "exp": datetime.utcnow() + timedelta(days=self.config.refresh_token_expire_days),
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(32),
            "token_type": "refresh"
        }
        
        return jwt.encode(token_data, self.config.jwt_secret_key, algorithm=self.config.jwt_algorithm)
    
    def verify_token(self, token: str) -> Optional[TokenData]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token, 
                self.config.jwt_secret_key, 
                algorithms=[self.config.jwt_algorithm]
            )
            
            # Check if token is revoked
            if payload.get("jti") in self.revoked_tokens:
                logger.warning("Attempted use of revoked token", jti=payload.get("jti"))
                return None
            
            return TokenData(**payload)
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.JWTError as e:
            logger.warning("Invalid token", error=str(e))
            return None
    
    async def revoke_token(self, token: str):
        """Revoke a token"""
        try:
            payload = jwt.decode(
                token, 
                self.config.jwt_secret_key, 
                algorithms=[self.config.jwt_algorithm],
                options={"verify_exp": False}
            )
            async with self._lock:
                self.revoked_tokens.add(payload.get("jti"))
            logger.info("Token revoked", jti=payload.get("jti"))
        except jwt.JWTError:
            logger.error("Failed to revoke invalid token")
    
    # RBAC Management
    def get_user_permissions(self, roles: List[Role]) -> Set[Permission]:
        """Get all permissions for user roles"""
        permissions = set()
        for role in roles:
            permissions.update(self.ROLE_PERMISSIONS.get(role, set()))
        return permissions
    
    def check_permission(self, user_roles: List[Role], required_permission: Permission) -> bool:
        """Check if user has required permission"""
        user_permissions = self.get_user_permissions(user_roles)
        return required_permission in user_permissions
    
    def check_permissions(self, user_roles: List[Role], required_permissions: List[Permission]) -> bool:
        """Check if user has all required permissions"""
        user_permissions = self.get_user_permissions(user_roles)
        return all(perm in user_permissions for perm in required_permissions)
    
    # Session Management
    async def create_session(self, username: str) -> str:
        """Create a new session"""
        session_id = secrets.token_urlsafe(32)
        async with self._lock:
            self.active_sessions[session_id] = datetime.utcnow()
        logger.info("Session created", username=username, session_id=session_id)
        return session_id
    
    async def validate_session(self, session_id: str) -> bool:
        """Validate session is active and not expired"""
        async with self._lock:
            if session_id not in self.active_sessions:
                return False
            
            session_start = self.active_sessions[session_id]
            if datetime.utcnow() - session_start > timedelta(minutes=self.config.session_timeout_minutes):
                del self.active_sessions[session_id]
                return False
            
            # Update session activity
            self.active_sessions[session_id] = datetime.utcnow()
            return True
    
    async def destroy_session(self, session_id: str):
        """Destroy a session"""
        async with self._lock:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                logger.info("Session destroyed", session_id=session_id)
    
    # Account Security
    async def handle_failed_login(self, user: UserModel) -> bool:
        """Handle failed login attempt"""
        user.failed_login_attempts += 1
        user.updated_at = datetime.utcnow()
        
        if user.failed_login_attempts >= self.config.max_login_attempts:
            user.is_locked = True
            logger.warning("Account locked due to failed login attempts", username=user.username)
            return True
        
        return False
    
    async def handle_successful_login(self, user: UserModel):
        """Handle successful login"""
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        user.updated_at = datetime.utcnow()
        
        if user.is_locked:
            # Check if lockout period has passed
            lockout_end = user.updated_at + timedelta(minutes=self.config.lockout_duration_minutes)
            if datetime.utcnow() > lockout_end:
                user.is_locked = False
                logger.info("Account unlocked after lockout period", username=user.username)
    
    # MFA Support
    def generate_mfa_secret(self) -> str:
        """Generate MFA secret key"""
        return secrets.token_urlsafe(32)
    
    def generate_totp_uri(self, username: str, secret: str, issuer: str = "NexusController") -> str:
        """Generate TOTP URI for QR code"""
        return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"
    
    def verify_totp(self, token: str, secret: str) -> bool:
        """Verify TOTP token (simplified - use pyotp in production)"""
        # This is a simplified version - use pyotp library in production
        import hmac
        import struct
        import time
        
        counter = int(time.time() // 30)
        
        for i in range(-1, 2):  # Allow 1 period before/after
            test_counter = counter + i
            hmac_hash = hmac.new(
                secret.encode(),
                struct.pack(">Q", test_counter),
                hashlib.sha1
            ).digest()
            
            offset = hmac_hash[-1] & 0x0f
            truncated = struct.unpack(">I", hmac_hash[offset:offset + 4])[0]
            truncated &= 0x7fffffff
            truncated %= 1000000
            
            if str(truncated).zfill(6) == token:
                return True
        
        return False


# Decorator for route protection
def requires_permission(permission: Permission):
    """Decorator to check permissions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This would integrate with your web framework
            # Example for FastAPI:
            # current_user = kwargs.get('current_user')
            # if not security_service.check_permission(current_user.roles, permission):
            #     raise HTTPException(403, "Insufficient permissions")
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def requires_permissions(permissions: List[Permission]):
    """Decorator to check multiple permissions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This would integrate with your web framework
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Security Headers Middleware (for FastAPI/Starlette)
async def security_headers_middleware(request, call_next):
    """Add security headers to responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response


# API Key Management
class APIKeyService:
    """Service for managing API keys"""
    
    def __init__(self):
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
    
    async def generate_api_key(self, user: UserModel, name: str, expires_in_days: int = 365) -> str:
        """Generate a new API key"""
        api_key = f"nxc_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        async with self._lock:
            self.api_keys[key_hash] = {
                "username": user.username,
                "name": name,
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(days=expires_in_days),
                "roles": user.roles,
                "last_used": None,
                "usage_count": 0
            }
        
        logger.info("API key generated", username=user.username, key_name=name)
        return api_key
    
    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate an API key"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        async with self._lock:
            if key_hash not in self.api_keys:
                return None
            
            key_data = self.api_keys[key_hash]
            
            # Check expiration
            if datetime.utcnow() > key_data["expires_at"]:
                logger.warning("Expired API key used", key_name=key_data["name"])
                return None
            
            # Update usage stats
            key_data["last_used"] = datetime.utcnow()
            key_data["usage_count"] += 1
            
            return key_data
    
    async def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        async with self._lock:
            if key_hash in self.api_keys:
                key_name = self.api_keys[key_hash]["name"]
                del self.api_keys[key_hash]
                logger.info("API key revoked", key_name=key_name)
                return True
        
        return False


# Initialize global security service
security_service = SecurityService()
api_key_service = APIKeyService()


if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        # Create a user
        user = UserModel(
            username="admin",
            email="admin@nexuscontroller.com",
            roles=[Role.ADMIN]
        )
        
        # Hash password
        password = "SecureP@ssw0rd123!"
        hashed = SecurityService.hash_password(password)
        print(f"Password hashed: {hashed[:20]}...")
        
        # Verify password
        is_valid = SecurityService.verify_password(password, hashed)
        print(f"Password valid: {is_valid}")
        
        # Create tokens
        access_token = security_service.create_access_token(user)
        refresh_token = security_service.create_refresh_token(user)
        print(f"Access token: {access_token[:50]}...")
        print(f"Refresh token: {refresh_token[:50]}...")
        
        # Verify token
        token_data = security_service.verify_token(access_token)
        if token_data:
            print(f"Token valid for user: {token_data.username}")
            print(f"Permissions: {token_data.permissions}")
        
        # Check permissions
        has_perm = security_service.check_permission(user.roles, Permission.ADMIN_ACCESS)
        print(f"Has admin access: {has_perm}")
        
        # Generate API key
        api_key = await api_key_service.generate_api_key(user, "Production API Key")
        print(f"API Key: {api_key}")
        
        # Validate API key
        key_data = await api_key_service.validate_api_key(api_key)
        if key_data:
            print(f"API Key valid for user: {key_data['username']}")
    
    asyncio.run(main())