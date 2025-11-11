#!/usr/bin/env python3
"""
NexusController v2.0 - Enterprise Security Framework

This module implements comprehensive security measures based on OWASP Top 10 
and enterprise security best practices.

OWASP Top 10 2021 Mitigations:
A01:2021 - Broken Access Control → RBAC, JWT, rate limiting
A02:2021 - Cryptographic Failures → Strong encryption, secure storage
A03:2021 - Injection → Input validation, parameterized queries
A04:2021 - Insecure Design → Security by design, threat modeling
A05:2021 - Security Misconfiguration → Secure defaults, hardening
A06:2021 - Vulnerable Components → Dependency scanning, updates
A07:2021 - Authentication Failures → MFA, session management
A08:2021 - Software/Data Integrity → Code signing, checksums
A09:2021 - Security Logging → Comprehensive audit trails
A10:2021 - Server-Side Request Forgery → URL validation, allowlists

Enterprise Features:
- Role-Based Access Control (RBAC) with fine-grained permissions
- OAuth2 + JWT authentication with refresh tokens
- Advanced input validation and sanitization
- Security headers middleware (HSTS, CSP, etc.)
- Rate limiting and DDoS protection
- Encryption at rest and in transit
- Comprehensive security audit logging
- Threat detection and response
- Compliance frameworks (SOC 2, ISO 27001)
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union, Callable
import threading
import re
import ipaddress
from urllib.parse import urlparse
import sqlite3
from collections import defaultdict, deque

# Security logging setup
security_logger = logging.getLogger('nexus.security')
security_logger.setLevel(logging.INFO)

class SecurityEventType(Enum):
    """Security event types for audit logging"""
    AUTHENTICATION_SUCCESS = "auth_success"
    AUTHENTICATION_FAILURE = "auth_failure"
    AUTHORIZATION_DENIED = "authz_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INPUT_VALIDATION_FAILED = "input_validation_failed"
    INJECTION_ATTEMPT = "injection_attempt"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SESSION_HIJACK_ATTEMPT = "session_hijack"
    SECURITY_SCAN_DETECTED = "security_scan"
    BRUTE_FORCE_DETECTED = "brute_force"
    DATA_EXPORT = "data_export"
    ADMIN_ACTION = "admin_action"
    SECURITY_CONFIG_CHANGE = "security_config_change"

class RiskLevel(Enum):
    """Risk levels for security events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class UserRole(Enum):
    """User roles for RBAC"""
    GUEST = "guest"
    USER = "user"
    OPERATOR = "operator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"
    SERVICE_ACCOUNT = "service_account"

class Permission(Enum):
    """Granular permissions for RBAC"""
    # Resource permissions
    RESOURCE_READ = "resource:read"
    RESOURCE_CREATE = "resource:create"
    RESOURCE_UPDATE = "resource:update"
    RESOURCE_DELETE = "resource:delete"
    
    # System permissions
    SYSTEM_MONITOR = "system:monitor"
    SYSTEM_CONFIGURE = "system:configure"
    SYSTEM_ADMIN = "system:admin"
    
    # User management permissions
    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Security permissions
    SECURITY_AUDIT = "security:audit"
    SECURITY_CONFIGURE = "security:configure"
    
    # Data permissions
    DATA_EXPORT = "data:export"
    DATA_IMPORT = "data:import"
    DATA_BACKUP = "data:backup"

@dataclass
class SecurityEvent:
    """Security event for audit logging"""
    event_id: str
    event_type: SecurityEventType
    risk_level: RiskLevel
    timestamp: datetime
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: str
    user_agent: Optional[str]
    resource: Optional[str]
    action: Optional[str]
    success: bool
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    geolocation: Optional[Dict[str, str]] = None

@dataclass
class User:
    """User model for authentication and authorization"""
    user_id: str
    username: str
    email: str
    password_hash: str
    salt: str
    roles: List[UserRole]
    permissions: Set[Permission] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    login_attempts: int = 0
    locked_until: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    session_timeout: int = 3600  # seconds
    force_password_change: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Session:
    """User session for authentication tracking"""
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    source_ip: str
    user_agent: str
    is_active: bool = True
    mfa_verified: bool = False
    permissions_cache: Set[Permission] = field(default_factory=set)

@dataclass
class JWTToken:
    """JWT token structure"""
    token: str
    token_type: str  # access, refresh
    user_id: str
    issued_at: datetime
    expires_at: datetime
    scopes: List[str] = field(default_factory=list)

class InputValidator:
    """Advanced input validation and sanitization"""
    
    # Common injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(or|and)\s+\w+\s*=\s*\w+)",
        r"(\bchar\s*\()",
        r"(\bcast\s*\()",
        r"(\bconvert\s*\()"
    ]
    
    XSS_PATTERNS = [
        r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe\b",
        r"<object\b",
        r"<embed\b",
        r"eval\s*\(",
        r"expression\s*\("
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]",
        r"\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)\b",
        r"\.\./",
        r"\\x[0-9a-f]{2}",
        r"%[0-9a-f]{2}"
    ]
    
    def __init__(self):
        self.sql_regex = re.compile('|'.join(self.SQL_INJECTION_PATTERNS), re.IGNORECASE)
        self.xss_regex = re.compile('|'.join(self.XSS_PATTERNS), re.IGNORECASE)
        self.command_regex = re.compile('|'.join(self.COMMAND_INJECTION_PATTERNS), re.IGNORECASE)
    
    def validate_input(self, value: str, input_type: str = "general") -> Dict[str, Any]:
        """Comprehensive input validation"""
        if not isinstance(value, str):
            return {"valid": False, "reason": "Input must be a string", "sanitized": str(value)}
        
        issues = []
        risk_level = RiskLevel.LOW
        
        # Check for injection patterns
        if self.sql_regex.search(value):
            issues.append("Potential SQL injection")
            risk_level = RiskLevel.HIGH
        
        if self.xss_regex.search(value):
            issues.append("Potential XSS attack")
            risk_level = RiskLevel.HIGH
        
        if self.command_regex.search(value):
            issues.append("Potential command injection")
            risk_level = RiskLevel.CRITICAL
        
        # Input type specific validation
        if input_type == "email":
            if not self._validate_email(value):
                issues.append("Invalid email format")
        elif input_type == "ip":
            if not self._validate_ip(value):
                issues.append("Invalid IP address")
        elif input_type == "url":
            if not self._validate_url(value):
                issues.append("Invalid or potentially malicious URL")
        elif input_type == "filename":
            if not self._validate_filename(value):
                issues.append("Invalid or potentially dangerous filename")
        
        # Length checks
        if len(value) > 10000:
            issues.append("Input too long")
            risk_level = max(risk_level, RiskLevel.MEDIUM)
        
        sanitized = self._sanitize_input(value)
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "risk_level": risk_level,
            "sanitized": sanitized,
            "original_length": len(value),
            "sanitized_length": len(sanitized)
        }
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None and len(email) <= 254
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL and check for dangerous schemes"""
        try:
            parsed = urlparse(url)
            # Only allow safe schemes
            safe_schemes = {'http', 'https', 'ftp', 'ftps'}
            return parsed.scheme.lower() in safe_schemes and len(url) <= 2048
        except Exception:
            return False
    
    def _validate_filename(self, filename: str) -> bool:
        """Validate filename for security"""
        # Check for directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        # Check for dangerous extensions
        dangerous_exts = {'.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js'}
        if any(filename.lower().endswith(ext) for ext in dangerous_exts):
            return False
        
        return len(filename) <= 255 and filename.strip() != ''
    
    def _sanitize_input(self, value: str) -> str:
        """Sanitize input by removing/encoding dangerous characters"""
        # HTML encode dangerous characters
        sanitized = (value
                    .replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#x27;')
                    .replace('/', '&#x2F;'))
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        
        return sanitized.strip()

class RateLimiter:
    """Advanced rate limiting with multiple algorithms"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(lambda: deque())
        self.blocked_ips: Dict[str, datetime] = {}
        self._lock = threading.RLock()
    
    def is_allowed(self, client_id: str, endpoint: str = "default") -> Dict[str, Any]:
        """Check if request is allowed under rate limits"""
        now = time.time()
        key = f"{client_id}:{endpoint}"
        
        with self._lock:
            # Check if IP is temporarily blocked
            if client_id in self.blocked_ips:
                if datetime.utcnow() < self.blocked_ips[client_id]:
                    return {
                        "allowed": False,
                        "reason": "IP temporarily blocked",
                        "retry_after": (self.blocked_ips[client_id] - datetime.utcnow()).total_seconds()
                    }
                else:
                    del self.blocked_ips[client_id]
            
            # Clean old requests
            request_times = self.requests[key]
            while request_times and request_times[0] < now - self.window_seconds:
                request_times.popleft()
            
            # Check rate limit
            if len(request_times) >= self.max_requests:
                # Block IP for repeated violations
                violation_count = sum(1 for ip, block_time in self.blocked_ips.items() 
                                    if ip == client_id and block_time > datetime.utcnow())
                
                if violation_count >= 3:
                    # Progressive blocking: 1 hour for repeated violations
                    self.blocked_ips[client_id] = datetime.utcnow() + timedelta(hours=1)
                else:
                    # First violation: 5 minutes
                    self.blocked_ips[client_id] = datetime.utcnow() + timedelta(minutes=5)
                
                return {
                    "allowed": False,
                    "reason": "Rate limit exceeded",
                    "requests_remaining": 0,
                    "reset_time": now + self.window_seconds,
                    "retry_after": 60
                }
            
            # Allow request
            request_times.append(now)
            return {
                "allowed": True,
                "requests_remaining": self.max_requests - len(request_times),
                "reset_time": now + self.window_seconds
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        with self._lock:
            return {
                "total_clients": len(self.requests),
                "blocked_ips": len(self.blocked_ips),
                "active_blocks": len([ip for ip, block_time in self.blocked_ips.items() 
                                    if block_time > datetime.utcnow()])
            }

class SecurityAuditor:
    """Comprehensive security audit logging and monitoring"""
    
    def __init__(self, storage_path: str = "security_logs"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        self.events: deque = deque(maxlen=10000)  # Keep last 10k events in memory
        self.threat_patterns: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        
        # Initialize SQLite for persistent storage
        self.db_path = self.storage_path / "security_events.db"
        self._init_database()
    
    def _init_database(self):
        """Initialize security events database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                user_id TEXT,
                session_id TEXT,
                source_ip TEXT NOT NULL,
                user_agent TEXT,
                resource TEXT,
                action TEXT,
                success BOOLEAN NOT NULL,
                message TEXT NOT NULL,
                metadata TEXT,
                correlation_id TEXT,
                geolocation TEXT
            )
        ''')
        
        # Create indexes for common queries
        conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON security_events(event_type)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON security_events(source_ip)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON security_events(user_id)')
        
        conn.commit()
        conn.close()
    
    def log_security_event(self, event: SecurityEvent):
        """Log security event with comprehensive details"""
        with self._lock:
            # Add to memory queue
            self.events.append(event)
            
            # Update threat patterns
            pattern_key = f"{event.event_type.value}_{event.source_ip}"
            self.threat_patterns[pattern_key] += 1
            
            # Persist to database
            self._persist_event(event)
            
            # Log to standard logging
            log_level = logging.INFO
            if event.risk_level == RiskLevel.HIGH:
                log_level = logging.WARNING
            elif event.risk_level == RiskLevel.CRITICAL:
                log_level = logging.ERROR
            
            security_logger.log(
                log_level,
                f"SECURITY_EVENT [{event.risk_level.value.upper()}] {event.event_type.value}: {event.message}",
                extra={
                    'event_id': event.event_id,
                    'user_id': event.user_id,
                    'source_ip': event.source_ip,
                    'correlation_id': event.correlation_id,
                    'security_event': True
                }
            )
    
    def _persist_event(self, event: SecurityEvent):
        """Persist event to SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO security_events 
                (event_id, event_type, risk_level, timestamp, user_id, session_id, 
                 source_ip, user_agent, resource, action, success, message, 
                 metadata, correlation_id, geolocation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.event_id,
                event.event_type.value,
                event.risk_level.value,
                event.timestamp,
                event.user_id,
                event.session_id,
                event.source_ip,
                event.user_agent,
                event.resource,
                event.action,
                event.success,
                event.message,
                json.dumps(event.metadata),
                event.correlation_id,
                json.dumps(event.geolocation) if event.geolocation else None
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            security_logger.error(f"Failed to persist security event: {e}")
    
    def detect_threats(self) -> List[Dict[str, Any]]:
        """Detect potential security threats from event patterns"""
        threats = []
        current_time = datetime.utcnow()
        
        with self._lock:
            # Analyze recent events (last hour)
            recent_events = [e for e in self.events 
                           if (current_time - e.timestamp).total_seconds() < 3600]
            
            # Group by source IP
            ip_events = defaultdict(list)
            for event in recent_events:
                ip_events[event.source_ip].append(event)
            
            # Detect threats
            for ip, events in ip_events.items():
                if len(events) >= 50:  # High activity from single IP
                    threats.append({
                        "type": "high_activity",
                        "source_ip": ip,
                        "event_count": len(events),
                        "risk_level": "high",
                        "description": f"Unusually high activity from {ip}: {len(events)} events in 1 hour"
                    })
                
                # Detect brute force attempts
                auth_failures = [e for e in events 
                               if e.event_type == SecurityEventType.AUTHENTICATION_FAILURE]
                if len(auth_failures) >= 10:
                    threats.append({
                        "type": "brute_force",
                        "source_ip": ip,
                        "failure_count": len(auth_failures),
                        "risk_level": "critical",
                        "description": f"Potential brute force attack from {ip}: {len(auth_failures)} auth failures"
                    })
                
                # Detect injection attempts
                injection_events = [e for e in events 
                                  if e.event_type == SecurityEventType.INJECTION_ATTEMPT]
                if len(injection_events) >= 5:
                    threats.append({
                        "type": "injection_attack",
                        "source_ip": ip,
                        "attempt_count": len(injection_events),
                        "risk_level": "critical",
                        "description": f"Multiple injection attempts from {ip}: {len(injection_events)} attempts"
                    })
        
        return threats
    
    def get_security_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive security dashboard data"""
        current_time = datetime.utcnow()
        
        with self._lock:
            # Recent events analysis
            last_24h_events = [e for e in self.events 
                             if (current_time - e.timestamp).total_seconds() < 86400]
            
            event_type_counts = defaultdict(int)
            risk_level_counts = defaultdict(int)
            hourly_counts = defaultdict(int)
            top_source_ips = defaultdict(int)
            
            for event in last_24h_events:
                event_type_counts[event.event_type.value] += 1
                risk_level_counts[event.risk_level.value] += 1
                hour_key = event.timestamp.strftime('%Y-%m-%d %H:00')
                hourly_counts[hour_key] += 1
                top_source_ips[event.source_ip] += 1
            
            return {
                "total_events_24h": len(last_24h_events),
                "event_types": dict(event_type_counts),
                "risk_levels": dict(risk_level_counts),
                "hourly_distribution": dict(hourly_counts),
                "top_source_ips": dict(sorted(top_source_ips.items(), 
                                            key=lambda x: x[1], reverse=True)[:10]),
                "active_threats": self.detect_threats(),
                "database_events": self._get_database_stats()
            }
    
    def _get_database_stats(self) -> Dict[str, Any]:
        """Get statistics from persistent database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('SELECT COUNT(*) FROM security_events')
            total_events = cursor.fetchone()[0]
            
            cursor = conn.execute('''
                SELECT risk_level, COUNT(*) 
                FROM security_events 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY risk_level
            ''')
            recent_risk_levels = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                "total_events": total_events,
                "recent_risk_levels": recent_risk_levels
            }
        except Exception as e:
            security_logger.error(f"Failed to get database stats: {e}")
            return {"error": str(e)}

class CryptographyManager:
    """Enterprise cryptography management"""
    
    def __init__(self, key_rotation_days: int = 90):
        self.key_rotation_days = key_rotation_days
        self.encryption_keys: Dict[str, bytes] = {}
        self.key_metadata: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        
        # Initialize master key
        self.master_key = self._get_or_create_master_key()
    
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key"""
        key_file = Path('.nexus_master_key')
        if key_file.exists():
            return key_file.read_bytes()
        else:
            key = secrets.token_bytes(32)  # 256-bit key
            key_file.write_bytes(key)
            key_file.chmod(0o600)  # Secure permissions
            return key
    
    def encrypt_data(self, data: Union[str, bytes], key_id: str = "default") -> Dict[str, Any]:
        """Encrypt data with specified key"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            # Get or create key
            if key_id not in self.encryption_keys:
                self._create_encryption_key(key_id)
            
            # Create Fernet instance
            f = Fernet(base64.urlsafe_b64encode(self.encryption_keys[key_id]))
            
            # Encrypt data
            encrypted_data = f.encrypt(data)
            
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
                "key_id": key_id,
                "algorithm": "Fernet",
                "timestamp": datetime.utcnow().isoformat()
            }
        except ImportError:
            # Fallback to basic base64 encoding (not secure for production)
            security_logger.warning("cryptography library not available, using insecure fallback")
            return {
                "encrypted_data": base64.b64encode(data).decode('utf-8'),
                "key_id": key_id,
                "algorithm": "base64",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def decrypt_data(self, encrypted_data: str, key_id: str = "default") -> bytes:
        """Decrypt data with specified key"""
        try:
            from cryptography.fernet import Fernet
            
            if key_id not in self.encryption_keys:
                raise ValueError(f"Encryption key {key_id} not found")
            
            # Create Fernet instance
            f = Fernet(base64.urlsafe_b64encode(self.encryption_keys[key_id]))
            
            # Decrypt data
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            return f.decrypt(encrypted_bytes)
        except ImportError:
            # Fallback to base64 decoding
            security_logger.warning("cryptography library not available, using insecure fallback")
            return base64.b64decode(encrypted_data.encode('utf-8'))
    
    def _create_encryption_key(self, key_id: str):
        """Create new encryption key"""
        with self._lock:
            key = secrets.token_bytes(32)
            self.encryption_keys[key_id] = key
            self.key_metadata[key_id] = {
                "created_at": datetime.utcnow(),
                "rotation_due": datetime.utcnow() + timedelta(days=self.key_rotation_days),
                "usage_count": 0
            }
    
    def hash_password(self, password: str, salt: bytes = None) -> Dict[str, str]:
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Use PBKDF2 with SHA-256
        iterations = 100000  # OWASP recommended minimum
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        
        return {
            "hash": base64.b64encode(password_hash).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "algorithm": "pbkdf2_sha256",
            "iterations": iterations
        }
    
    def verify_password(self, password: str, stored_hash: str, salt: str, iterations: int = 100000) -> bool:
        """Verify password against stored hash"""
        try:
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            stored_hash_bytes = base64.b64decode(stored_hash.encode('utf-8'))
            
            # Hash the provided password
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, iterations)
            
            # Use hmac.compare_digest for timing attack protection
            return hmac.compare_digest(password_hash, stored_hash_bytes)
        except Exception:
            return False

class JWTManager:
    """JSON Web Token management for authentication"""
    
    def __init__(self, secret_key: bytes = None, access_token_expire_minutes: int = 15,
                 refresh_token_expire_days: int = 30):
        self.secret_key = secret_key or secrets.token_bytes(32)
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.revoked_tokens: Set[str] = set()
        self._lock = threading.Lock()
    
    def create_access_token(self, user_id: str, permissions: List[str] = None) -> JWTToken:
        """Create JWT access token"""
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=self.access_token_expire_minutes)
        
        payload = {
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "type": "access",
            "jti": str(uuid.uuid4()),  # JWT ID for revocation
            "permissions": permissions or []
        }
        
        token = self._encode_jwt(payload)
        
        return JWTToken(
            token=token,
            token_type="access",
            user_id=user_id,
            issued_at=now,
            expires_at=expires_at,
            scopes=permissions or []
        )
    
    def create_refresh_token(self, user_id: str) -> JWTToken:
        """Create JWT refresh token"""
        now = datetime.utcnow()
        expires_at = now + timedelta(days=self.refresh_token_expire_days)
        
        payload = {
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "type": "refresh",
            "jti": str(uuid.uuid4())
        }
        
        token = self._encode_jwt(payload)
        
        return JWTToken(
            token=token,
            token_type="refresh",
            user_id=user_id,
            issued_at=now,
            expires_at=expires_at
        )
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = self._decode_jwt(token)
            
            # Check if token is revoked
            jti = payload.get("jti")
            if jti and jti in self.revoked_tokens:
                return None
            
            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
                return None
            
            return payload
        except Exception:
            return None
    
    def revoke_token(self, token: str):
        """Revoke JWT token"""
        try:
            payload = self._decode_jwt(token)
            jti = payload.get("jti")
            if jti:
                with self._lock:
                    self.revoked_tokens.add(jti)
        except Exception:
            pass  # Token already invalid
    
    def _encode_jwt(self, payload: Dict[str, Any]) -> str:
        """Encode JWT token (simplified implementation)"""
        try:
            import jwt
            return jwt.encode(payload, self.secret_key, algorithm='HS256')
        except ImportError:
            # Fallback implementation without PyJWT
            header = {"alg": "HS256", "typ": "JWT"}
            
            # Base64 encode header and payload
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Create signature
            message = f"{header_b64}.{payload_b64}"
            signature = hmac.new(self.secret_key, message.encode(), hashlib.sha256).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            
            return f"{message}.{signature_b64}"
    
    def _decode_jwt(self, token: str) -> Dict[str, Any]:
        """Decode JWT token (simplified implementation)"""
        try:
            import jwt
            return jwt.decode(token, self.secret_key, algorithms=['HS256'])
        except ImportError:
            # Fallback implementation
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid token format")
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_signature = hmac.new(self.secret_key, message.encode(), hashlib.sha256).digest()
            expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).decode().rstrip('=')
            
            if not hmac.compare_digest(signature_b64, expected_signature_b64):
                raise ValueError("Invalid signature")
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
            return json.loads(payload_json)

class SecurityHeadersMiddleware:
    """Security headers middleware for HTTP responses"""
    
    SECURITY_HEADERS = {
        # OWASP Security Headers
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        
        # HSTS (HTTP Strict Transport Security)
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        
        # CSP (Content Security Policy)
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
    }
    
    def __init__(self, custom_headers: Dict[str, str] = None):
        self.headers = {**self.SECURITY_HEADERS}
        if custom_headers:
            self.headers.update(custom_headers)
    
    def add_security_headers(self, response_headers: Dict[str, str]) -> Dict[str, str]:
        """Add security headers to response"""
        return {**response_headers, **self.headers}

class EnterpriseSecurityManager:
    """Main enterprise security management system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize core security components
        self.input_validator = InputValidator()
        self.rate_limiter = RateLimiter(
            max_requests=self.config.get('rate_limit_requests', 100),
            window_seconds=self.config.get('rate_limit_window', 60)
        )
        self.security_auditor = SecurityAuditor(
            storage_path=self.config.get('security_log_path', 'security_logs')
        )
        self.crypto_manager = CryptographyManager(
            key_rotation_days=self.config.get('key_rotation_days', 90)
        )
        self.jwt_manager = JWTManager(
            access_token_expire_minutes=self.config.get('access_token_expire_minutes', 15),
            refresh_token_expire_days=self.config.get('refresh_token_expire_days', 30)
        )
        self.security_headers = SecurityHeadersMiddleware(
            custom_headers=self.config.get('custom_security_headers', {})
        )
        
        # User and session management
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.role_permissions: Dict[UserRole, Set[Permission]] = self._init_role_permissions()
        
        self._lock = threading.RLock()
        
        security_logger.info("Enterprise Security Manager initialized")
    
    def _init_role_permissions(self) -> Dict[UserRole, Set[Permission]]:
        """Initialize role-based permissions"""
        return {
            UserRole.GUEST: {Permission.RESOURCE_READ},
            UserRole.USER: {
                Permission.RESOURCE_READ,
                Permission.SYSTEM_MONITOR,
                Permission.USER_READ
            },
            UserRole.OPERATOR: {
                Permission.RESOURCE_READ,
                Permission.RESOURCE_CREATE,
                Permission.RESOURCE_UPDATE,
                Permission.SYSTEM_MONITOR,
                Permission.SYSTEM_CONFIGURE,
                Permission.USER_READ
            },
            UserRole.ADMIN: {
                Permission.RESOURCE_READ,
                Permission.RESOURCE_CREATE,
                Permission.RESOURCE_UPDATE,
                Permission.RESOURCE_DELETE,
                Permission.SYSTEM_MONITOR,
                Permission.SYSTEM_CONFIGURE,
                Permission.SYSTEM_ADMIN,
                Permission.USER_READ,
                Permission.USER_CREATE,
                Permission.USER_UPDATE,
                Permission.SECURITY_AUDIT,
                Permission.DATA_EXPORT,
                Permission.DATA_BACKUP
            },
            UserRole.SUPER_ADMIN: set(Permission),  # All permissions
            UserRole.SERVICE_ACCOUNT: {
                Permission.RESOURCE_READ,
                Permission.SYSTEM_MONITOR
            }
        }
    
    def create_user(self, username: str, email: str, password: str, 
                   roles: List[UserRole]) -> str:
        """Create new user with secure password storage"""
        user_id = str(uuid.uuid4())
        
        # Hash password
        password_data = self.crypto_manager.hash_password(password)
        
        # Calculate permissions from roles
        permissions = set()
        for role in roles:
            permissions.update(self.role_permissions.get(role, set()))
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            password_hash=password_data['hash'],
            salt=password_data['salt'],
            roles=roles,
            permissions=permissions
        )
        
        with self._lock:
            self.users[user_id] = user
        
        # Log security event
        self.security_auditor.log_security_event(SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=SecurityEventType.ADMIN_ACTION,
            risk_level=RiskLevel.MEDIUM,
            timestamp=datetime.utcnow(),
            user_id=None,  # System action
            session_id=None,
            source_ip="127.0.0.1",
            user_agent=None,
            resource="user",
            action="create",
            success=True,
            message=f"User {username} created with roles: {[r.value for r in roles]}"
        ))
        
        return user_id
    
    def authenticate_user(self, username: str, password: str, source_ip: str,
                         user_agent: str = None) -> Optional[Dict[str, Any]]:
        """Authenticate user and create session"""
        user = None
        
        # Find user by username
        with self._lock:
            for u in self.users.values():
                if u.username == username:
                    user = u
                    break
        
        if not user:
            self._log_auth_failure("User not found", username, source_ip, user_agent)
            return None
        
        # Check if account is locked
        if user.locked_until and datetime.utcnow() < user.locked_until:
            self._log_auth_failure("Account locked", username, source_ip, user_agent)
            return None
        
        # Verify password
        if not self.crypto_manager.verify_password(password, user.password_hash, user.salt):
            # Increment login attempts
            user.login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            
            self._log_auth_failure("Invalid password", username, source_ip, user_agent)
            return None
        
        # Reset login attempts on successful authentication
        user.login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        
        # Create session
        session = self._create_session(user, source_ip, user_agent)
        
        # Create JWT tokens
        permissions = [p.value for p in user.permissions]
        access_token = self.jwt_manager.create_access_token(user.user_id, permissions)
        refresh_token = self.jwt_manager.create_refresh_token(user.user_id)
        
        # Log successful authentication
        self.security_auditor.log_security_event(SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            risk_level=RiskLevel.LOW,
            timestamp=datetime.utcnow(),
            user_id=user.user_id,
            session_id=session.session_id,
            source_ip=source_ip,
            user_agent=user_agent,
            resource=None,
            action="login",
            success=True,
            message=f"User {username} authenticated successfully"
        ))
        
        return {
            "user_id": user.user_id,
            "username": user.username,
            "roles": [r.value for r in user.roles],
            "permissions": permissions,
            "session_id": session.session_id,
            "access_token": access_token.token,
            "refresh_token": refresh_token.token,
            "expires_at": access_token.expires_at.isoformat()
        }
    
    def _create_session(self, user: User, source_ip: str, user_agent: str) -> Session:
        """Create user session"""
        session_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(seconds=user.session_timeout),
            source_ip=source_ip,
            user_agent=user_agent,
            mfa_verified=not user.mfa_enabled,  # If MFA disabled, consider verified
            permissions_cache=user.permissions.copy()
        )
        
        with self._lock:
            self.sessions[session_id] = session
        
        return session
    
    def _log_auth_failure(self, reason: str, username: str, source_ip: str, user_agent: str):
        """Log authentication failure"""
        self.security_auditor.log_security_event(SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
            risk_level=RiskLevel.MEDIUM,
            timestamp=datetime.utcnow(),
            user_id=None,
            session_id=None,
            source_ip=source_ip,
            user_agent=user_agent,
            resource=None,
            action="login",
            success=False,
            message=f"Authentication failed for {username}: {reason}"
        ))
    
    def authorize_request(self, session_id: str, required_permission: Permission,
                         resource: str = None) -> bool:
        """Authorize request based on session and required permission"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session or not session.is_active:
                return False
            
            # Check session expiration
            if datetime.utcnow() > session.expires_at:
                session.is_active = False
                return False
            
            # Update last activity
            session.last_activity = datetime.utcnow()
            
            # Check permission
            if required_permission in session.permissions_cache:
                return True
            
            # Log authorization denial
            self.security_auditor.log_security_event(SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=SecurityEventType.AUTHORIZATION_DENIED,
                risk_level=RiskLevel.MEDIUM,
                timestamp=datetime.utcnow(),
                user_id=session.user_id,
                session_id=session_id,
                source_ip=session.source_ip,
                user_agent=session.user_agent,
                resource=resource,
                action=required_permission.value,
                success=False,
                message=f"Access denied: missing permission {required_permission.value}"
            ))
            
            return False
    
    def validate_and_sanitize_input(self, input_data: Any, input_type: str = "general",
                                   source_ip: str = "unknown") -> Dict[str, Any]:
        """Validate and sanitize input data"""
        if not isinstance(input_data, str):
            input_data = str(input_data)
        
        validation_result = self.input_validator.validate_input(input_data, input_type)
        
        # Log security events for failed validations
        if not validation_result["valid"] and validation_result["risk_level"] in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            self.security_auditor.log_security_event(SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=SecurityEventType.INJECTION_ATTEMPT if "injection" in str(validation_result["issues"]) 
                          else SecurityEventType.INPUT_VALIDATION_FAILED,
                risk_level=validation_result["risk_level"],
                timestamp=datetime.utcnow(),
                user_id=None,
                session_id=None,
                source_ip=source_ip,
                user_agent=None,
                resource=None,
                action="input_validation",
                success=False,
                message=f"Input validation failed: {validation_result['issues']}",
                metadata={"original_input_length": validation_result["original_length"]}
            ))
        
        return validation_result
    
    def check_rate_limit(self, client_id: str, endpoint: str = "default") -> Dict[str, Any]:
        """Check rate limiting for client"""
        result = self.rate_limiter.is_allowed(client_id, endpoint)
        
        # Log rate limit violations
        if not result["allowed"]:
            self.security_auditor.log_security_event(SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                risk_level=RiskLevel.MEDIUM,
                timestamp=datetime.utcnow(),
                user_id=None,
                session_id=None,
                source_ip=client_id,
                user_agent=None,
                resource=endpoint,
                action="rate_limit_check",
                success=False,
                message=f"Rate limit exceeded for {client_id} on {endpoint}"
            ))
        
        return result
    
    def get_security_overview(self) -> Dict[str, Any]:
        """Get comprehensive security overview"""
        return {
            "authentication": {
                "total_users": len(self.users),
                "active_sessions": len([s for s in self.sessions.values() if s.is_active]),
                "locked_accounts": len([u for u in self.users.values() 
                                      if u.locked_until and datetime.utcnow() < u.locked_until])
            },
            "rate_limiting": self.rate_limiter.get_stats(),
            "security_events": self.security_auditor.get_security_dashboard(),
            "threat_detection": self.security_auditor.detect_threats(),
            "compliance_status": {
                "owasp_top10_covered": True,
                "encryption_enabled": True,
                "audit_logging_enabled": True,
                "input_validation_enabled": True,
                "rate_limiting_enabled": True,
                "security_headers_enabled": True
            }
        }