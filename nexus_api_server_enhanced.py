#!/usr/bin/env python3
"""
Enhanced NexusController v2.0 - Secure FastAPI REST API Server
Modern FastAPI implementation with advanced security, observability, and enterprise features
"""

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import structlog

# FastAPI and web framework imports
try:
    from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Response, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.base import BaseHTTPMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.responses import JSONResponse, PlainTextResponse
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
    from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
    from fastapi.openapi.utils import get_openapi
    from pydantic import BaseModel, Field, ConfigDict, field_validator
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# Import our enhanced modules
try:
    from .nexus_auth_security import (
        SecurityService, APIKeyService, UserModel, Permission, Role,
        security_service, api_key_service
    )
    from .nexus_database_manager import db_manager
    from .nexus_observability import get_observability_manager, traced, monitored, MetricType
    from .nexus_event_system_enhanced import get_event_bus, EventModel, EventType
    from .nexus_circuit_breaker import circuit_breaker_manager, circuit_breaker
    NEXUS_MODULES_AVAILABLE = True
except ImportError:
    NEXUS_MODULES_AVAILABLE = False

logger = structlog.get_logger(__name__)

# Rate limiter
if FASTAPI_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)
else:
    limiter = None


# Pydantic models
class APIResponse(BaseModel):
    """Standard API response model"""
    model_config = ConfigDict(validate_assignment=True)
    
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class LoginRequest(BaseModel):
    """Login request model"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    remember_me: bool = False
    mfa_token: Optional[str] = None


class LoginResponse(BaseModel):
    """Login response model"""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    user_info: Dict[str, Any]


class RefreshTokenRequest(BaseModel):
    """Refresh token request model"""
    refresh_token: str


class ResourceCreateRequest(BaseModel):
    """Resource creation request"""
    name: str = Field(..., min_length=1, max_length=255)
    resource_type: str
    provider: str
    region: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)


class ResourceUpdateRequest(BaseModel):
    """Resource update request"""
    properties: Optional[Dict[str, Any]] = None
    tags: Optional[Dict[str, str]] = None
    state: Optional[str] = None


class HealthStatus(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    uptime: float
    dependencies: Dict[str, Dict[str, Any]]


# Security middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "object-src 'none'; "
            "media-src 'self'; "
            "frame-src 'none'"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        
        # Remove server header for security
        if "server" in response.headers:
            del response.headers["server"]
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with correlation IDs"""
    
    async def dispatch(self, request: Request, call_next):
        # Generate correlation ID
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        
        start_time = time.time()
        
        # Log request
        logger.info(
            "Request started",
            method=request.method,
            path=request.url.path,
            query_params=str(request.query_params),
            client_ip=get_remote_address(request),
            correlation_id=correlation_id
        )
        
        try:
            response = await call_next(request)
            
            # Add correlation ID to response
            response.headers["X-Correlation-ID"] = correlation_id
            
            # Log response
            duration = time.time() - start_time
            logger.info(
                "Request completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration=duration,
                correlation_id=correlation_id
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "Request failed",
                method=request.method,
                path=request.url.path,
                error=str(e),
                duration=duration,
                correlation_id=correlation_id,
                exc_info=True
            )
            
            return JSONResponse(
                status_code=500,
                content=APIResponse(
                    success=False,
                    message="Internal server error",
                    errors=[str(e)],
                    metadata={"correlation_id": correlation_id}
                ).model_dump(),
                headers={"X-Correlation-ID": correlation_id}
            )


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Handle authentication for protected routes"""
    
    def __init__(self, app, protected_paths: List[str] = None):
        super().__init__(app)
        self.protected_paths = protected_paths or ["/api/v1/", "/api/v2/"]
        self.public_paths = ["/health", "/metrics", "/docs", "/openapi.json", "/auth/"]
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Check if path requires authentication
        needs_auth = any(path.startswith(protected) for protected in self.protected_paths)
        is_public = any(path.startswith(public) for public in self.public_paths)
        
        if not needs_auth or is_public:
            return await call_next(request)
        
        # Check for authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=401,
                content=APIResponse(
                    success=False,
                    message="Authorization header required"
                ).model_dump()
            )
        
        try:
            # Extract token
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                token_data = security_service.verify_token(token)
                
                if token_data:
                    request.state.user = token_data.username
                    request.state.roles = [Role(role) for role in token_data.roles]
                    request.state.permissions = [Permission(perm) for perm in token_data.permissions]
                    return await call_next(request)
            
            elif auth_header.startswith("ApiKey "):
                api_key = auth_header[7:]
                key_data = await api_key_service.validate_api_key(api_key)
                
                if key_data:
                    request.state.user = key_data["username"]
                    request.state.roles = [Role(role) for role in key_data["roles"]]
                    request.state.api_key = True
                    return await call_next(request)
            
            return JSONResponse(
                status_code=401,
                content=APIResponse(
                    success=False,
                    message="Invalid authorization header format"
                ).model_dump()
            )
            
        except Exception as e:
            logger.error("Authentication error", error=str(e))
            return JSONResponse(
                status_code=401,
                content=APIResponse(
                    success=False,
                    message="Authentication failed"
                ).model_dump()
            )


# Dependency functions
async def get_current_user(request: Request) -> str:
    """Get current authenticated user"""
    if not hasattr(request.state, 'user'):
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    return request.state.user


async def get_current_user_roles(request: Request) -> List[Role]:
    """Get current user roles"""
    if not hasattr(request.state, 'roles'):
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    return request.state.roles


def require_permission(permission: Permission):
    """Dependency factory for permission checking"""
    async def check_permission(request: Request):
        if not hasattr(request.state, 'permissions'):
            raise HTTPException(
                status_code=401,
                detail="Authentication required"
            )
        
        if permission not in request.state.permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission {permission.value} required"
            )
        
        return True
    
    return check_permission


def require_roles(*required_roles: Role):
    """Dependency factory for role checking"""
    async def check_roles(request: Request):
        if not hasattr(request.state, 'roles'):
            raise HTTPException(
                status_code=401,
                detail="Authentication required"
            )
        
        user_roles = request.state.roles
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=403,
                detail=f"One of roles {[r.value for r in required_roles]} required"
            )
        
        return True
    
    return check_roles


# Application factory
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting NexusController API server")
    
    try:
        # Initialize database
        if NEXUS_MODULES_AVAILABLE:
            await db_manager.initialize()
            logger.info("Database initialized")
            
            # Initialize observability
            obs_manager = await get_observability_manager()
            app.state.observability = obs_manager
            logger.info("Observability initialized")
            
            # Initialize event bus
            event_bus = await get_event_bus()
            app.state.event_bus = event_bus
            logger.info("Event bus initialized")
        
        logger.info("NexusController API server started successfully")
        
    except Exception as e:
        logger.error("Failed to start API server", error=str(e))
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down NexusController API server")
    
    try:
        if NEXUS_MODULES_AVAILABLE:
            await db_manager.close()
            
            if hasattr(app.state, 'observability'):
                await app.state.observability.close()
            
            if hasattr(app.state, 'event_bus'):
                await app.state.event_bus.close()
        
        logger.info("NexusController API server shutdown complete")
        
    except Exception as e:
        logger.error("Error during shutdown", error=str(e))


def create_app() -> FastAPI:
    """Create FastAPI application"""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI not available")
    
    # Create FastAPI app
    app = FastAPI(
        title="NexusController API",
        description="Enterprise Infrastructure Management Platform",
        version="2.0.0",
        docs_url="/docs" if os.getenv("ENVIRONMENT") != "production" else None,
        redoc_url="/redoc" if os.getenv("ENVIRONMENT") != "production" else None,
        lifespan=lifespan
    )
    
    # Add middleware
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(AuthenticationMiddleware)
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["*"],
        expose_headers=["X-Correlation-ID"]
    )
    
    # Trusted host middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    )
    
    # Rate limiting
    if limiter:
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    return app


# Create app instance
app = create_app()


# Health check endpoint
@app.get("/health", response_model=HealthStatus, tags=["Health"])
async def health_check():
    """Health check endpoint"""
    start_time = getattr(app.state, 'start_time', time.time())
    uptime = time.time() - start_time
    
    dependencies = {}
    
    if NEXUS_MODULES_AVAILABLE:
        # Check database
        dependencies["database"] = {
            "status": "healthy" if db_manager.is_healthy() else "unhealthy",
            "details": db_manager.get_health_status()
        }
        
        # Check observability
        if hasattr(app.state, 'observability'):
            dependencies["observability"] = app.state.observability.get_health_metrics()
        
        # Check event bus
        if hasattr(app.state, 'event_bus'):
            dependencies["event_bus"] = app.state.event_bus.get_metrics()
    
    overall_status = "healthy"
    if any(dep.get("status") == "unhealthy" for dep in dependencies.values()):
        overall_status = "unhealthy"
    
    return HealthStatus(
        status=overall_status,
        version="2.0.0",
        uptime=uptime,
        dependencies=dependencies
    )


# Metrics endpoint
@app.get("/metrics", response_class=PlainTextResponse, tags=["Monitoring"])
async def metrics():
    """Prometheus metrics endpoint"""
    if NEXUS_MODULES_AVAILABLE and hasattr(app.state, 'observability'):
        return await app.state.observability.export_metrics()
    return "# No metrics available\n"


# Authentication endpoints
@app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
@limiter.limit("5/minute") if limiter else lambda *args, **kwargs: None
async def login(request: Request, login_data: LoginRequest):
    """User login endpoint"""
    try:
        # Get user from database
        user = await db_manager.get_user_by_username(login_data.username)
        if not user:
            await asyncio.sleep(1)  # Prevent timing attacks
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
        
        # Verify password
        if not security_service.verify_password(login_data.password, user.password_hash):
            await db_manager.handle_failed_login(user)
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
        
        # Check if account is locked
        if user.is_locked:
            raise HTTPException(
                status_code=423,
                detail="Account is locked"
            )
        
        # Check MFA if enabled
        if user.mfa_enabled and not login_data.mfa_token:
            raise HTTPException(
                status_code=422,
                detail="MFA token required"
            )
        
        if user.mfa_enabled and login_data.mfa_token:
            if not security_service.verify_totp(login_data.mfa_token, user.mfa_secret):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid MFA token"
                )
        
        # Handle successful login
        await db_manager.handle_successful_login(user)
        
        # Create tokens
        user_model = UserModel(
            username=user.username,
            email=user.email,
            roles=[Role(role) for role in user.roles]
        )
        
        access_token = security_service.create_access_token(user_model)
        refresh_token = security_service.create_refresh_token(user_model)
        
        # Create session
        session_id = await security_service.create_session(user.username)
        
        # Log successful login
        if hasattr(app.state, 'event_bus'):
            event = EventModel(
                event_type=EventType.USER_LOGIN,
                source="nexus.api",
                data={
                    "user_id": user.id,
                    "username": user.username,
                    "ip_address": get_remote_address(request),
                    "user_agent": request.headers.get("user-agent", "")
                }
            )
            await app.state.event_bus.publish(event)
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=security_service.config.access_token_expire_minutes * 60,
            user_info={
                "username": user.username,
                "email": user.email,
                "roles": user.roles,
                "session_id": session_id
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login error", error=str(e), username=login_data.username)
        raise HTTPException(
            status_code=500,
            detail="Login failed"
        )


@app.post("/auth/refresh", response_model=LoginResponse, tags=["Authentication"])
@limiter.limit("10/minute") if limiter else lambda *args, **kwargs: None
async def refresh_token(request: Request, refresh_data: RefreshTokenRequest):
    """Refresh access token"""
    try:
        # Verify refresh token
        token_data = security_service.verify_token(refresh_data.refresh_token)
        if not token_data or token_data.token_type != "refresh":
            raise HTTPException(
                status_code=401,
                detail="Invalid refresh token"
            )
        
        # Get user
        user = await db_manager.get_user_by_username(token_data.username)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="User not found or inactive"
            )
        
        # Create new tokens
        user_model = UserModel(
            username=user.username,
            email=user.email,
            roles=[Role(role) for role in user.roles]
        )
        
        new_access_token = security_service.create_access_token(user_model)
        new_refresh_token = security_service.create_refresh_token(user_model)
        
        # Revoke old refresh token
        await security_service.revoke_token(refresh_data.refresh_token)
        
        return LoginResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=security_service.config.access_token_expire_minutes * 60,
            user_info={
                "username": user.username,
                "email": user.email,
                "roles": user.roles
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Token refresh error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Token refresh failed"
        )


@app.post("/auth/logout", response_model=APIResponse, tags=["Authentication"])
async def logout(
    request: Request,
    current_user: str = Depends(get_current_user)
):
    """User logout"""
    try:
        # Revoke token if available
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            await security_service.revoke_token(token)
        
        # Log logout event
        if hasattr(app.state, 'event_bus'):
            event = EventModel(
                event_type=EventType.USER_LOGOUT,
                source="nexus.api",
                data={
                    "username": current_user,
                    "ip_address": get_remote_address(request)
                }
            )
            await app.state.event_bus.publish(event)
        
        return APIResponse(
            success=True,
            message="Logged out successfully"
        )
        
    except Exception as e:
        logger.error("Logout error", error=str(e), user=current_user)
        raise HTTPException(
            status_code=500,
            detail="Logout failed"
        )


# Resource management endpoints
@app.post("/api/v1/resources", response_model=APIResponse, tags=["Resources"])
@traced("create_resource")
@monitored("resource_operations_total", MetricType.COUNTER, {"operation": "create"})
async def create_resource(
    request: Request,
    resource_data: ResourceCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user),
    _: bool = Depends(require_permission(Permission.RESOURCE_WRITE))
):
    """Create a new resource"""
    try:
        # Create resource in database
        resource_record = await db_manager.create_resource({
            "name": resource_data.name,
            "type": resource_data.resource_type,
            "provider": resource_data.provider,
            "region": resource_data.region,
            "config": resource_data.properties,
            "metadata": {"tags": resource_data.tags},
            "created_by": current_user
        })
        
        # Emit resource creation event
        if hasattr(app.state, 'event_bus'):
            event = EventModel(
                event_type=EventType.RESOURCE_CREATED,
                source="nexus.api",
                data={
                    "resource_id": resource_record.id,
                    "resource_type": resource_data.resource_type,
                    "provider": resource_data.provider,
                    "created_by": current_user
                }
            )
            background_tasks.add_task(app.state.event_bus.publish, event)
        
        return APIResponse(
            success=True,
            message="Resource created successfully",
            data={
                "resource_id": resource_record.id,
                "name": resource_record.name,
                "type": resource_record.type,
                "status": resource_record.status
            }
        )
        
    except Exception as e:
        logger.error("Resource creation failed", error=str(e), user=current_user)
        raise HTTPException(
            status_code=500,
            detail="Failed to create resource"
        )


@app.get("/api/v1/resources", response_model=APIResponse, tags=["Resources"])
@traced("list_resources")
async def list_resources(
    request: Request,
    provider: Optional[str] = None,
    resource_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: str = Depends(get_current_user),
    _: bool = Depends(require_permission(Permission.RESOURCE_READ))
):
    """List resources with optional filtering"""
    try:
        # Get resources from database
        if provider:
            resources = await db_manager.get_resources_by_provider(provider, limit, offset)
        else:
            # Would implement more general listing with filters
            resources = []
        
        resource_list = [
            {
                "resource_id": r.id,
                "name": r.name,
                "type": r.type,
                "provider": r.provider,
                "region": r.region,
                "status": r.status,
                "created_at": r.created_at.isoformat(),
                "updated_at": r.updated_at.isoformat()
            }
            for r in resources
        ]
        
        return APIResponse(
            success=True,
            message="Resources retrieved successfully",
            data={
                "resources": resource_list,
                "total": len(resource_list),
                "limit": limit,
                "offset": offset
            }
        )
        
    except Exception as e:
        logger.error("Resource listing failed", error=str(e), user=current_user)
        raise HTTPException(
            status_code=500,
            detail="Failed to list resources"
        )


@app.get("/api/v1/resources/{resource_id}", response_model=APIResponse, tags=["Resources"])
@traced("get_resource")
async def get_resource(
    resource_id: str,
    current_user: str = Depends(get_current_user),
    _: bool = Depends(require_permission(Permission.RESOURCE_READ))
):
    """Get resource by ID"""
    try:
        resource = await db_manager.get_resource(resource_id)
        if not resource:
            raise HTTPException(
                status_code=404,
                detail="Resource not found"
            )
        
        return APIResponse(
            success=True,
            message="Resource retrieved successfully",
            data={
                "resource_id": resource.id,
                "name": resource.name,
                "type": resource.type,
                "provider": resource.provider,
                "region": resource.region,
                "status": resource.status,
                "config": resource.config,
                "metadata": resource.metadata,
                "created_at": resource.created_at.isoformat(),
                "updated_at": resource.updated_at.isoformat(),
                "created_by": resource.created_by
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Resource retrieval failed", error=str(e), resource_id=resource_id, user=current_user)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve resource"
        )


@app.delete("/api/v1/resources/{resource_id}", response_model=APIResponse, tags=["Resources"])
@traced("delete_resource")
@monitored("resource_operations_total", MetricType.COUNTER, {"operation": "delete"})
async def delete_resource(
    resource_id: str,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user),
    _: bool = Depends(require_permission(Permission.RESOURCE_DELETE))
):
    """Delete resource"""
    try:
        success = await db_manager.delete_resource(resource_id)
        if not success:
            raise HTTPException(
                status_code=404,
                detail="Resource not found"
            )
        
        # Emit resource deletion event
        if hasattr(app.state, 'event_bus'):
            event = EventModel(
                event_type=EventType.RESOURCE_DELETED,
                source="nexus.api",
                data={
                    "resource_id": resource_id,
                    "deleted_by": current_user
                }
            )
            background_tasks.add_task(app.state.event_bus.publish, event)
        
        return APIResponse(
            success=True,
            message="Resource deleted successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Resource deletion failed", error=str(e), resource_id=resource_id, user=current_user)
        raise HTTPException(
            status_code=500,
            detail="Failed to delete resource"
        )


# Admin endpoints
@app.get("/api/v1/admin/stats", response_model=APIResponse, tags=["Admin"])
async def get_admin_stats(
    current_user: str = Depends(get_current_user),
    _: bool = Depends(require_roles(Role.ADMIN))
):
    """Get system statistics (admin only)"""
    try:
        stats = {
            "system": {
                "uptime": time.time() - getattr(app.state, 'start_time', time.time()),
                "version": "2.0.0"
            }
        }
        
        if NEXUS_MODULES_AVAILABLE:
            # Database stats
            db_health = db_manager.get_health_status()
            stats["database"] = db_health
            
            # Circuit breaker stats  
            cb_stats = await circuit_breaker_manager.get_all_states()
            stats["circuit_breakers"] = cb_stats
            
            # Event bus stats
            if hasattr(app.state, 'event_bus'):
                stats["event_bus"] = app.state.event_bus.get_metrics()
        
        return APIResponse(
            success=True,
            message="Statistics retrieved successfully",
            data=stats
        )
        
    except Exception as e:
        logger.error("Failed to get admin stats", error=str(e), user=current_user)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve statistics"
        )


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    """Handle 404 errors"""
    return JSONResponse(
        status_code=404,
        content=APIResponse(
            success=False,
            message="Resource not found",
            metadata={"path": request.url.path}
        ).model_dump()
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    """Handle 500 errors"""
    correlation_id = getattr(request.state, 'correlation_id', str(uuid.uuid4()))
    
    return JSONResponse(
        status_code=500,
        content=APIResponse(
            success=False,
            message="Internal server error",
            metadata={"correlation_id": correlation_id}
        ).model_dump()
    )


if __name__ == "__main__":
    # Set start time
    app.state.start_time = time.time()
    
    # Run server
    config = uvicorn.Config(
        app,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        access_log=True,
        server_header=False,
        date_header=False
    )
    
    server = uvicorn.Server(config)
    
    try:
        logger.info("Starting NexusController API server", host=config.host, port=config.port)
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        logger.info("Shutting down NexusController API server")
    except Exception as e:
        logger.error("Failed to start server", error=str(e))
        raise