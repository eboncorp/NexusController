#!/usr/bin/env python3
"""
Advanced Async Database Manager for NexusController v2.0
Implements SQLAlchemy 2.0 patterns with connection pooling, retry logic, and monitoring
"""

import asyncio
import os
from typing import Optional, Dict, Any, List, AsyncContextManager, TypeVar, Type, Union
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import structlog
from dataclasses import dataclass
import time
import uuid

from sqlalchemy.ext.asyncio import (
    create_async_engine, 
    AsyncSession, 
    async_sessionmaker,
    AsyncEngine
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, JSON,
    text, select, update, delete, func, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, DisconnectionError
from sqlalchemy.pool import StaticPool, QueuePool
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from pydantic import BaseModel, Field, ConfigDict
import prometheus_client

logger = structlog.get_logger(__name__)

# Prometheus metrics
db_connections_total = prometheus_client.Counter('nexus_db_connections_total', 'Total database connections')
db_queries_total = prometheus_client.Counter('nexus_db_queries_total', 'Total database queries', ['operation'])
db_query_duration = prometheus_client.Histogram('nexus_db_query_duration_seconds', 'Database query duration')
db_connection_errors = prometheus_client.Counter('nexus_db_connection_errors_total', 'Database connection errors')
db_pool_size = prometheus_client.Gauge('nexus_db_pool_size', 'Current database pool size')
db_pool_checked_out = prometheus_client.Gauge('nexus_db_pool_checked_out', 'Database connections checked out')


@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str = os.getenv('DATABASE_URL', 'postgresql+asyncpg://nexus:password@localhost/nexusdb')
    pool_size: int = int(os.getenv('DB_POOL_SIZE', '20'))
    max_overflow: int = int(os.getenv('DB_MAX_OVERFLOW', '40'))
    pool_timeout: int = int(os.getenv('DB_POOL_TIMEOUT', '30'))
    pool_recycle: int = int(os.getenv('DB_POOL_RECYCLE', '3600'))
    pool_pre_ping: bool = True
    echo: bool = os.getenv('DB_ECHO', 'false').lower() == 'true'
    echo_pool: bool = False
    query_timeout: int = int(os.getenv('DB_QUERY_TIMEOUT', '30'))
    max_retries: int = 3
    retry_delay: float = 1.0
    connection_retry_attempts: int = 5
    health_check_interval: int = 60
    slow_query_threshold: float = 1.0


class Base(DeclarativeBase):
    """Base class for all database models"""
    pass


# Example models
class NexusResource(Base):
    """Nexus resource model"""
    __tablename__ = 'nexus_resources'
    
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    region: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True)
    metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    
    __table_args__ = (
        Index('idx_resource_provider_status', 'provider', 'status'),
        Index('idx_resource_created_at', 'created_at'),
    )


class NexusUser(Base):
    """Nexus user model"""
    __tablename__ = 'nexus_users'
    
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    roles: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class NexusSession(Base):
    """Nexus session model"""
    __tablename__ = 'nexus_sessions'
    
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_activity: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class NexusAuditLog(Base):
    """Audit log model"""
    __tablename__ = 'nexus_audit_logs'
    
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )


class QueryMetrics:
    """Query performance metrics"""
    
    def __init__(self):
        self.total_queries = 0
        self.slow_queries = 0
        self.failed_queries = 0
        self.total_time = 0.0
        self.last_reset = datetime.utcnow()
    
    def record_query(self, duration: float, success: bool = True, slow_threshold: float = 1.0):
        """Record query metrics"""
        self.total_queries += 1
        self.total_time += duration
        
        if duration > slow_threshold:
            self.slow_queries += 1
            logger.warning("Slow query detected", duration=duration, threshold=slow_threshold)
        
        if not success:
            self.failed_queries += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get query statistics"""
        if self.total_queries == 0:
            return {"avg_duration": 0, "slow_query_rate": 0, "error_rate": 0}
        
        return {
            "total_queries": self.total_queries,
            "avg_duration": self.total_time / self.total_queries,
            "slow_queries": self.slow_queries,
            "slow_query_rate": self.slow_queries / self.total_queries,
            "failed_queries": self.failed_queries,
            "error_rate": self.failed_queries / self.total_queries,
            "uptime": (datetime.utcnow() - self.last_reset).total_seconds()
        }
    
    def reset(self):
        """Reset metrics"""
        self.total_queries = 0
        self.slow_queries = 0
        self.failed_queries = 0
        self.total_time = 0.0
        self.last_reset = datetime.utcnow()


T = TypeVar('T')


class DatabaseManager:
    """Advanced async database manager"""
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or DatabaseConfig()
        self.engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[async_sessionmaker] = None
        self.metrics = QueryMetrics()
        self._health_check_task: Optional[asyncio.Task] = None
        self._is_healthy = True
        self._last_health_check = datetime.utcnow()
        logger.info("Database manager initializing", config=self.config.url.split('@')[0] + '@***')
    
    async def initialize(self):
        """Initialize database connection and engine"""
        try:
            self.engine = create_async_engine(
                self.config.url,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                pool_pre_ping=self.config.pool_pre_ping,
                echo=self.config.echo,
                echo_pool=self.config.echo_pool,
                poolclass=QueuePool,
                connect_args={
                    "server_settings": {
                        "application_name": "NexusController",
                        "statement_timeout": str(self.config.query_timeout * 1000)
                    }
                }
            )
            
            self.session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False
            )
            
            # Test connection
            await self._test_connection()
            
            # Start health check task
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            # Update metrics
            db_connections_total.inc()
            
            logger.info("Database manager initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize database manager", error=str(e))
            db_connection_errors.inc()
            raise
    
    async def close(self):
        """Close database connections"""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connections closed")
    
    @asynccontextmanager
    async def get_session(self) -> AsyncContextManager[AsyncSession]:
        """Get database session with automatic cleanup"""
        if not self.session_factory:
            raise RuntimeError("Database manager not initialized")
        
        session = self.session_factory()
        start_time = time.time()
        
        try:
            yield session
            await session.commit()
            
            # Record successful transaction
            duration = time.time() - start_time
            self.metrics.record_query(duration, success=True, slow_threshold=self.config.slow_query_threshold)
            db_query_duration.observe(duration)
            db_queries_total.labels(operation='transaction').inc()
            
        except Exception as e:
            await session.rollback()
            
            # Record failed transaction
            duration = time.time() - start_time
            self.metrics.record_query(duration, success=False, slow_threshold=self.config.slow_query_threshold)
            db_query_duration.observe(duration)
            db_queries_total.labels(operation='transaction_failed').inc()
            
            logger.error("Database transaction failed", error=str(e), duration=duration)
            raise
        finally:
            await session.close()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((DisconnectionError, OSError))
    )
    async def execute_with_retry(self, query, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute query with retry logic"""
        async with self.get_session() as session:
            if params:
                result = await session.execute(query, params)
            else:
                result = await session.execute(query)
            return result
    
    async def execute_raw_sql(self, sql: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute raw SQL with timing and error handling"""
        start_time = time.time()
        
        try:
            result = await self.execute_with_retry(text(sql), params)
            
            duration = time.time() - start_time
            self.metrics.record_query(duration, success=True, slow_threshold=self.config.slow_query_threshold)
            db_query_duration.observe(duration)
            db_queries_total.labels(operation='raw_sql').inc()
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            self.metrics.record_query(duration, success=False, slow_threshold=self.config.slow_query_threshold)
            db_query_duration.observe(duration)
            db_queries_total.labels(operation='raw_sql_failed').inc()
            
            logger.error("Raw SQL execution failed", sql=sql, error=str(e), duration=duration)
            raise
    
    # CRUD Operations with type safety
    async def create_resource(self, resource_data: Dict[str, Any]) -> NexusResource:
        """Create a new resource"""
        async with self.get_session() as session:
            resource = NexusResource(**resource_data)
            session.add(resource)
            await session.flush()
            await session.refresh(resource)
            return resource
    
    async def get_resource(self, resource_id: str) -> Optional[NexusResource]:
        """Get resource by ID"""
        async with self.get_session() as session:
            result = await session.execute(
                select(NexusResource).where(NexusResource.id == resource_id)
            )
            return result.scalar_one_or_none()
    
    async def get_resources_by_provider(self, provider: str, limit: int = 100, offset: int = 0) -> List[NexusResource]:
        """Get resources by provider with pagination"""
        async with self.get_session() as session:
            result = await session.execute(
                select(NexusResource)
                .where(NexusResource.provider == provider)
                .order_by(NexusResource.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
    
    async def update_resource(self, resource_id: str, updates: Dict[str, Any]) -> Optional[NexusResource]:
        """Update resource"""
        async with self.get_session() as session:
            result = await session.execute(
                update(NexusResource)
                .where(NexusResource.id == resource_id)
                .values(**updates, updated_at=datetime.utcnow())
                .returning(NexusResource)
            )
            return result.scalar_one_or_none()
    
    async def delete_resource(self, resource_id: str) -> bool:
        """Delete resource"""
        async with self.get_session() as session:
            result = await session.execute(
                delete(NexusResource).where(NexusResource.id == resource_id)
            )
            return result.rowcount > 0
    
    # User management
    async def create_user(self, user_data: Dict[str, Any]) -> NexusUser:
        """Create a new user"""
        async with self.get_session() as session:
            user = NexusUser(**user_data)
            session.add(user)
            await session.flush()
            await session.refresh(user)
            return user
    
    async def get_user_by_username(self, username: str) -> Optional[NexusUser]:
        """Get user by username"""
        async with self.get_session() as session:
            result = await session.execute(
                select(NexusUser).where(NexusUser.username == username)
            )
            return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[NexusUser]:
        """Get user by email"""
        async with self.get_session() as session:
            result = await session.execute(
                select(NexusUser).where(NexusUser.email == email)
            )
            return result.scalar_one_or_none()
    
    # Session management
    async def create_session(self, session_data: Dict[str, Any]) -> NexusSession:
        """Create a new session"""
        async with self.get_session() as session:
            nexus_session = NexusSession(**session_data)
            session.add(nexus_session)
            await session.flush()
            await session.refresh(nexus_session)
            return nexus_session
    
    async def get_active_session(self, session_id: str) -> Optional[NexusSession]:
        """Get active session"""
        async with self.get_session() as session:
            result = await session.execute(
                select(NexusSession)
                .where(
                    NexusSession.id == session_id,
                    NexusSession.is_active == True,
                    NexusSession.expires_at > datetime.utcnow()
                )
            )
            return result.scalar_one_or_none()
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        async with self.get_session() as session:
            result = await session.execute(
                delete(NexusSession)
                .where(NexusSession.expires_at < datetime.utcnow())
            )
            return result.rowcount
    
    # Audit logging
    async def log_audit_event(self, audit_data: Dict[str, Any]) -> NexusAuditLog:
        """Log audit event"""
        async with self.get_session() as session:
            audit_log = NexusAuditLog(**audit_data)
            session.add(audit_log)
            await session.flush()
            await session.refresh(audit_log)
            return audit_log
    
    async def get_audit_logs(
        self, 
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[NexusAuditLog]:
        """Get audit logs with filters"""
        async with self.get_session() as session:
            query = select(NexusAuditLog)
            
            if user_id:
                query = query.where(NexusAuditLog.user_id == user_id)
            if action:
                query = query.where(NexusAuditLog.action == action)
            if resource_type:
                query = query.where(NexusAuditLog.resource_type == resource_type)
            if start_date:
                query = query.where(NexusAuditLog.timestamp >= start_date)
            if end_date:
                query = query.where(NexusAuditLog.timestamp <= end_date)
            
            query = query.order_by(NexusAuditLog.timestamp.desc()).limit(limit).offset(offset)
            
            result = await session.execute(query)
            return list(result.scalars().all())
    
    # Health and monitoring
    async def _test_connection(self):
        """Test database connection"""
        try:
            async with self.get_session() as session:
                await session.execute(text("SELECT 1"))
            self._is_healthy = True
            self._last_health_check = datetime.utcnow()
        except Exception as e:
            self._is_healthy = False
            logger.error("Database health check failed", error=str(e))
            raise
    
    async def _health_check_loop(self):
        """Periodic health check loop"""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._test_connection()
                
                # Update pool metrics
                if self.engine and hasattr(self.engine.pool, 'size'):
                    db_pool_size.set(self.engine.pool.size())
                    db_pool_checked_out.set(self.engine.pool.checkedout())
                
                logger.debug("Database health check passed")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check loop error", error=str(e))
                self._is_healthy = False
    
    def is_healthy(self) -> bool:
        """Check if database is healthy"""
        return self._is_healthy
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get detailed health status"""
        pool_status = {}
        if self.engine and hasattr(self.engine.pool, 'status'):
            pool_status = {
                "pool_size": getattr(self.engine.pool, 'size', lambda: 0)(),
                "checked_out": getattr(self.engine.pool, 'checkedout', lambda: 0)(),
                "overflow": getattr(self.engine.pool, 'overflow', lambda: 0)(),
                "invalid": getattr(self.engine.pool, 'invalid', lambda: 0)(),
            }
        
        return {
            "is_healthy": self._is_healthy,
            "last_health_check": self._last_health_check.isoformat(),
            "query_metrics": self.metrics.get_stats(),
            "pool_status": pool_status,
            "config": {
                "pool_size": self.config.pool_size,
                "max_overflow": self.config.max_overflow,
                "pool_timeout": self.config.pool_timeout,
                "query_timeout": self.config.query_timeout
            }
        }
    
    async def create_tables(self):
        """Create all tables"""
        if not self.engine:
            raise RuntimeError("Database manager not initialized")
        
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created")
    
    async def drop_tables(self):
        """Drop all tables (use with caution!)"""
        if not self.engine:
            raise RuntimeError("Database manager not initialized")
        
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        
        logger.info("Database tables dropped")


# Global database manager instance
db_manager = DatabaseManager()


# Context manager for database operations
@asynccontextmanager
async def get_db_session():
    """Get database session - convenience function"""
    async with db_manager.get_session() as session:
        yield session


if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        # Initialize database
        await db_manager.initialize()
        
        try:
            # Create tables
            await db_manager.create_tables()
            
            # Create a test resource
            resource_data = {
                "name": "test-server",
                "type": "vm",
                "provider": "aws",
                "region": "us-east-1",
                "status": "running",
                "config": {"instance_type": "t3.micro"},
                "created_by": "admin"
            }
            
            resource = await db_manager.create_resource(resource_data)
            print(f"Created resource: {resource.id}")
            
            # Get the resource
            retrieved = await db_manager.get_resource(resource.id)
            if retrieved:
                print(f"Retrieved resource: {retrieved.name} ({retrieved.status})")
            
            # Update resource
            updated = await db_manager.update_resource(resource.id, {"status": "stopped"})
            if updated:
                print(f"Updated resource status: {updated.status}")
            
            # Create a test user
            user_data = {
                "username": "testuser",
                "email": "test@example.com",
                "password_hash": "hashed_password",
                "roles": ["viewer"]
            }
            
            user = await db_manager.create_user(user_data)
            print(f"Created user: {user.username}")
            
            # Log audit event
            audit_data = {
                "user_id": user.id,
                "action": "resource_created",
                "resource_type": "vm",
                "resource_id": resource.id,
                "details": {"provider": "aws", "region": "us-east-1"}
            }
            
            audit_log = await db_manager.log_audit_event(audit_data)
            print(f"Logged audit event: {audit_log.action}")
            
            # Get health status
            health = db_manager.get_health_status()
            print(f"Database health: {health['is_healthy']}")
            print(f"Query metrics: {health['query_metrics']}")
            
        finally:
            await db_manager.close()
    
    asyncio.run(main())