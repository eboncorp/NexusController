#!/usr/bin/env python3
"""
NexusController v2.0 - Secure FastAPI REST API Server

Enterprise REST API with comprehensive security, OWASP Top 10 compliance,
and enterprise authentication/authorization features.

Security Features:
- OWASP Top 10 2021 mitigations
- JWT-based authentication with refresh tokens
- Role-Based Access Control (RBAC)
- Advanced input validation and sanitization
- Rate limiting and DDoS protection
- Security headers middleware
- Comprehensive audit logging
- Real-time threat detection
"""

import os
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import uvicorn
import logging
import asyncio
import json

try:
    from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Response, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.base import BaseHTTPMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from pydantic import BaseModel, Field, validator
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("FastAPI not available. Install with: pip install fastapi uvicorn")

# Import security framework
try:
    from nexus_security import (
        EnterpriseSecurityManager,
        SecurityEvent,
        SecurityEventType,
        RiskLevel,
        Permission,
        UserRole
    )
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    print("Security framework not available")

# Configure security logging
security_logger = logging.getLogger('nexus.api.security')
security_logger.setLevel(logging.INFO)

# Secure Pydantic models for API
class SystemStatus(BaseModel):
    """System status response model"""
    status: str
    version: str
    uptime: str
    components: Dict[str, str]

class NetworkDevice(BaseModel):
    """Network device model"""
    ip: str = Field(..., description="IP address", regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    hostname: Optional[str] = Field(None, max_length=255, description="Device hostname")
    mac_address: Optional[str] = Field(None, regex=r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    status: str = Field("unknown", regex=r'^(online|offline|unknown)$')
    last_seen: Optional[datetime] = None

class APIResponse(BaseModel):
    """Standard API response model"""
    success: bool
    message: str = Field(..., max_length=1000)
    data: Optional[Any] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class LoginRequest(BaseModel):
    """User login request"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(..., min_length=8, max_length=128)
    
    @validator('username')
    def validate_username(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Username cannot be empty')
        return v.strip()

class LoginResponse(BaseModel):
    """User login response"""
    success: bool
    message: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[str] = None
    user_info: Optional[Dict[str, Any]] = None

class CreateUserRequest(BaseModel):
    """Create user request"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_.-]+$')
    email: str = Field(..., regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    password: str = Field(..., min_length=8, max_length=128)
    roles: List[str] = Field(default=['user'])
    
    @validator('roles')
    def validate_roles(cls, v):
        valid_roles = [role.value for role in UserRole]
        for role in v:
            if role not in valid_roles:
                raise ValueError(f'Invalid role: {role}')
        return v

class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware"""
    
    def __init__(self, app, security_manager: EnterpriseSecurityManager):
        super().__init__(app)
        self.security_manager = security_manager
        
    async def dispatch(self, request: Request, call_next):
        start_time = datetime.utcnow()
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Rate limiting check
        rate_limit_result = self.security_manager.check_rate_limit(
            client_ip, 
            f"{request.method}:{request.url.path}"
        )
        
        if not rate_limit_result["allowed"]:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "success": False,
                    "message": "Rate limit exceeded",
                    "retry_after": rate_limit_result.get("retry_after", 60)
                }
            )
        
        # Input validation for query parameters and path
        if request.query_params:
            for key, value in request.query_params.items():
                validation_result = self.security_manager.validate_and_sanitize_input(
                    value, "general", client_ip
                )
                if not validation_result["valid"]:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "success": False,
                            "message": "Invalid input detected",
                            "issues": validation_result["issues"]
                        }
                    )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Add security headers
            security_headers = self.security_manager.security_headers.add_security_headers({})
            for header, value in security_headers.items():
                response.headers[header] = value
            
            # Log successful request
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            if response.status_code >= 400:
                self.security_manager.security_auditor.log_security_event(SecurityEvent(
                    event_id=str(uuid.uuid4()),
                    event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
                    risk_level=RiskLevel.MEDIUM,
                    timestamp=start_time,
                    user_id=None,
                    session_id=None,
                    source_ip=client_ip,
                    user_agent=user_agent,
                    resource=request.url.path,
                    action=request.method,
                    success=False,
                    message=f"HTTP {response.status_code} on {request.method} {request.url.path}",
                    metadata={"duration_ms": duration_ms}
                ))
            
            return response
            
        except Exception as e:
            # Log security incident
            self.security_manager.security_auditor.log_security_event(SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
                risk_level=RiskLevel.HIGH,
                timestamp=start_time,
                user_id=None,
                session_id=None,
                source_ip=client_ip,
                user_agent=user_agent,
                resource=request.url.path,
                action=request.method,
                success=False,
                message=f"Request processing error: {str(e)}"
            ))
            
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "success": False,
                    "message": "Internal server error"
                }
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check for forwarded headers (common in reverse proxy setups)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"

# Authentication dependency
security_bearer = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    """Dependency to get current authenticated user"""
    if not SECURITY_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security framework not available"
        )
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required"
        )
    
    # This would be injected by the create_app function
    # For now, return a placeholder
    return {"user_id": "system", "permissions": []}

def create_app(
    event_bus=None,
    state_manager=None,
    plugin_manager=None,
    monitoring_system=None,
    remediation_system=None,
    multicloud_manager=None,
    federation_manager=None,
    security_config: Dict[str, Any] = None
) -> FastAPI:
    """Create secure FastAPI application with all components"""
    
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI not available")
    
    if not SECURITY_AVAILABLE:
        security_logger.warning("Security framework not available - running with limited security")
    
    # Initialize security manager
    security_manager = None
    if SECURITY_AVAILABLE:
        security_manager = EnterpriseSecurityManager(security_config or {})
        
        # Create default admin user if none exist
        if not security_manager.users:
            admin_user_id = security_manager.create_user(
                username="admin",
                email="admin@nexus.local",
                password="NexusAdmin123!",  # Should be changed on first login
                roles=[UserRole.SUPER_ADMIN]
            )
            security_logger.info(f"Created default admin user with ID: {admin_user_id}")
    
    app = FastAPI(
        title="NexusController v2.0 Secure API",
        description="Enterprise Infrastructure Management Platform with OWASP Top 10 Security",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        # Security-focused OpenAPI configuration
        openapi_tags=[
            {"name": "Authentication", "description": "User authentication and authorization"},
            {"name": "Security", "description": "Security monitoring and management"},
            {"name": "System", "description": "System health and monitoring"},
            {"name": "Network", "description": "Network management and discovery"},
            {"name": "Resources", "description": "Infrastructure resource management"}
        ]
    )
    
    # Store components in app state
    app.state.event_bus = event_bus
    app.state.state_manager = state_manager
    app.state.plugin_manager = plugin_manager
    app.state.monitoring_system = monitoring_system
    app.state.remediation_system = remediation_system
    app.state.multicloud_manager = multicloud_manager
    app.state.federation_manager = federation_manager
    app.state.security_manager = security_manager
    app.state.start_time = datetime.now()
    
    # Add security middleware (highest priority)
    if security_manager:
        app.add_middleware(SecurityMiddleware, security_manager=security_manager)
    
    # Add CORS middleware with restricted origins for production
    allowed_origins = ["http://localhost:3000", "https://nexus.local"]  # Configure for your environment
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-Rate-Limit-Remaining", "X-Rate-Limit-Reset"]
    )
    
    # Create authentication dependency with access to security manager
    def get_authenticated_user(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
        """Get current authenticated user from JWT token"""
        if not security_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Security framework not available"
            )
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header required",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Verify JWT token
        token_payload = security_manager.jwt_manager.verify_token(credentials.credentials)
        if not token_payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        user_id = token_payload.get("sub")
        if not user_id or user_id not in security_manager.users:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        user = security_manager.users[user_id]
        return {
            "user_id": user_id,
            "username": user.username,
            "roles": [role.value for role in user.roles],
            "permissions": [perm.value for perm in user.permissions]
        }
    
    def require_permission(required_permission: Permission):
        """Dependency factory for permission-based authorization"""
        def permission_checker(user = Depends(get_authenticated_user)):
            user_permissions = [Permission(perm) for perm in user["permissions"]]
            if required_permission not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: {required_permission.value} required"
                )
            return user
        return permission_checker
    
    # ========== AUTHENTICATION ENDPOINTS ==========
    
    @app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
    async def login(request: Request, login_data: LoginRequest):
        """Authenticate user and return JWT tokens"""
        if not security_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Security framework not available"
            )
        
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        auth_result = security_manager.authenticate_user(
            username=login_data.username,
            password=login_data.password,
            source_ip=client_ip,
            user_agent=user_agent
        )
        
        if not auth_result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        return LoginResponse(
            success=True,
            message="Authentication successful",
            access_token=auth_result["access_token"],
            refresh_token=auth_result["refresh_token"],
            expires_at=auth_result["expires_at"],
            user_info={
                "username": auth_result["username"],
                "roles": auth_result["roles"],
                "permissions": auth_result["permissions"]
            }
        )
    
    @app.post("/auth/users", response_model=APIResponse, tags=["Authentication"])
    async def create_user(
        user_data: CreateUserRequest,
        current_user = Depends(require_permission(Permission.USER_CREATE))
    ):
        """Create new user (Admin only)"""
        if not security_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Security framework not available"
            )
        
        try:
            roles = [UserRole(role) for role in user_data.roles]
            user_id = security_manager.create_user(
                username=user_data.username,
                email=user_data.email,
                password=user_data.password,
                roles=roles
            )
            
            return APIResponse(
                success=True,
                message="User created successfully",
                data={"user_id": user_id, "username": user_data.username}
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to create user: {str(e)}"
            )
    
    # ========== SYSTEM ENDPOINTS ==========
    
    @app.get("/", response_model=APIResponse, tags=["System"])
    async def root():
        """Root endpoint - public access"""
        return APIResponse(
            success=True,
            message="NexusController v2.0 Secure API is running",
            data={
                "version": "2.0.0",
                "security_enabled": security_manager is not None,
                "docs": "/docs",
                "health": "/health",
                "auth": "/auth/login"
            }
        )
    
    @app.get("/health", response_model=SystemStatus, tags=["System"])
    async def health_check():
        """System health check - public access"""
        uptime = datetime.now() - app.state.start_time
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds
        
        components = {
            "event_bus": "healthy" if app.state.event_bus else "unavailable",
            "state_manager": "healthy" if app.state.state_manager else "unavailable",
            "monitoring": "healthy" if app.state.monitoring_system else "unavailable",
            "remediation": "healthy" if app.state.remediation_system else "unavailable",
            "multicloud": "healthy" if app.state.multicloud_manager else "unavailable",
            "federation": "healthy" if app.state.federation_manager else "unavailable",
            "security": "healthy" if app.state.security_manager else "unavailable"
        }
        
        return SystemStatus(
            status="healthy",
            version="2.0.0",
            uptime=uptime_str,
            components=components
        )
    
    @app.get("/metrics", tags=["System"])
    async def get_metrics(
        current_user = Depends(require_permission(Permission.SYSTEM_MONITOR))
    ):
        """Get system metrics - requires monitoring permission"""
        metrics = {}
        
        if app.state.event_bus:
            try:
                metrics["event_bus"] = app.state.event_bus.get_metrics()
            except:
                metrics["event_bus"] = {"error": "not available"}
        
        if app.state.monitoring_system:
            try:
                metrics["monitoring"] = app.state.monitoring_system.get_monitoring_overview()
            except:
                metrics["monitoring"] = {"error": "not available"}
        
        if security_manager:
            try:
                metrics["security"] = security_manager.get_security_overview()
            except Exception as e:
                metrics["security"] = {"error": str(e)}
        
        return APIResponse(
            success=True,
            message="Metrics retrieved successfully",
            data=metrics
        )
    
    # ========== SECURITY ENDPOINTS ==========
    
    @app.get("/security/dashboard", tags=["Security"])
    async def get_security_dashboard(
        current_user = Depends(require_permission(Permission.SECURITY_AUDIT))
    ):
        """Get security dashboard - requires security audit permission"""
        if not security_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Security framework not available"
            )
        
        try:
            dashboard_data = security_manager.security_auditor.get_security_dashboard()
            return APIResponse(
                success=True,
                message="Security dashboard retrieved successfully",
                data=dashboard_data
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get security dashboard: {str(e)}"
            )
    
    @app.get("/security/threats", tags=["Security"])
    async def get_threat_detection(
        current_user = Depends(require_permission(Permission.SECURITY_AUDIT))
    ):
        """Get threat detection results - requires security audit permission"""
        if not security_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Security framework not available"
            )
        
        try:
            threats = security_manager.security_auditor.detect_threats()
            return APIResponse(
                success=True,
                message="Threat detection completed",
                data={"threats": threats, "count": len(threats)}
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to detect threats: {str(e)}"
            )
    
    # ========== NETWORK ENDPOINTS ==========
    
    @app.get("/network/devices", response_model=List[NetworkDevice], tags=["Network"])
    async def list_network_devices(
        current_user = Depends(require_permission(Permission.RESOURCE_READ))
    ):
        """List discovered network devices - requires resource read permission"""
        # Mock data - would integrate with actual network discovery
        devices = [
            NetworkDevice(
                ip="10.0.0.1",
                hostname="router.local",
                mac_address="00:11:22:33:44:55",
                status="online",
                last_seen=datetime.now()
            ),
            NetworkDevice(
                ip="10.0.0.100",
                hostname="server.local", 
                mac_address="AA:BB:CC:DD:EE:FF",
                status="online",
                last_seen=datetime.now()
            )
        ]
        return devices
    
    @app.post("/network/scan", tags=["Network"])
    async def start_network_scan(
        background_tasks: BackgroundTasks,
        current_user = Depends(require_permission(Permission.SYSTEM_CONFIGURE))
    ):
        """Start network scan - requires system configure permission"""
        async def scan_task():
            if app.state.event_bus:
                try:
                    from nexus_event_system import Event, EventType
                    event = Event(
                        event_type=EventType.NETWORK_SCAN_STARTED,
                        source="nexus.api",
                        data={
                            "scan_id": "api_scan_001", 
                            "network_range": "10.0.0.0/24",
                            "initiated_by": current_user["username"]
                        }
                    )
                    await app.state.event_bus.publish(event)
                except Exception as e:
                    security_logger.error(f"Failed to publish network scan event: {e}")
        
        background_tasks.add_task(scan_task)
        
        return APIResponse(
            success=True,
            message="Network scan started successfully",
            data={
                "scan_id": "api_scan_001",
                "initiated_by": current_user["username"]
            }
        )
    
    # ========== RESOURCE MANAGEMENT ENDPOINTS ==========
    
    @app.get("/resources", tags=["Resources"])
    async def list_resources(
        current_user = Depends(require_permission(Permission.RESOURCE_READ))
    ):
        """List infrastructure resources - requires resource read permission"""
        resources = []
        
        # Get resources from multicloud manager
        if app.state.multicloud_manager:
            try:
                resources = await app.state.multicloud_manager.list_all_resources()
            except Exception as e:
                security_logger.error(f"Failed to list resources: {e}")
        
        return APIResponse(
            success=True,
            message="Resources retrieved successfully",
            data={"resources": resources, "count": len(resources)}
        )
    
    # ========== ERROR HANDLERS ==========
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Custom HTTP exception handler with security logging"""
        client_ip = request.client.host if request.client else "unknown"
        
        # Log security-relevant HTTP errors
        if exc.status_code in [401, 403, 429]:
            if security_manager:
                event_type = SecurityEventType.AUTHENTICATION_FAILURE
                if exc.status_code == 403:
                    event_type = SecurityEventType.AUTHORIZATION_DENIED
                elif exc.status_code == 429:
                    event_type = SecurityEventType.RATE_LIMIT_EXCEEDED
                
                security_manager.security_auditor.log_security_event(SecurityEvent(
                    event_id=str(uuid.uuid4()),
                    event_type=event_type,
                    risk_level=RiskLevel.MEDIUM,
                    timestamp=datetime.utcnow(),
                    user_id=None,
                    session_id=None,
                    source_ip=client_ip,
                    user_agent=request.headers.get('User-Agent'),
                    resource=str(request.url.path),
                    action=request.method,
                    success=False,
                    message=f"HTTP {exc.status_code}: {exc.detail}"
                ))
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "message": exc.detail,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    return app

def main():
    """Run the API server directly"""
    if not FASTAPI_AVAILABLE:
        print("FastAPI not available. Install with: pip install fastapi uvicorn")
        return
    
    logging.basicConfig(level=logging.INFO)
    
    # Create app with minimal components
    app = create_app()
    
    # Run with uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )

if __name__ == "__main__":
    main()