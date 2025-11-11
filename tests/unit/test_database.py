#!/usr/bin/env python3
"""
Unit tests for NexusController database module
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

try:
    from nexuscontroller.data.database import (
        DatabaseManager, DatabaseConfig, NexusResource, NexusUser, 
        NexusSession, NexusAuditLog, QueryMetrics
    )
    NEXUS_MODULES_AVAILABLE = True
except ImportError:
    NEXUS_MODULES_AVAILABLE = False

pytestmark = pytest.mark.unit


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestDatabaseConfig:
    """Test DatabaseConfig validation"""
    
    def test_valid_config_creation(self):
        """Test creating valid database config"""
        config = DatabaseConfig(
            url="postgresql+asyncpg://user:pass@localhost/db",
            pool_size=20,
            max_overflow=40
        )
        assert config.url == "postgresql+asyncpg://user:pass@localhost/db"
        assert config.pool_size == 20
        assert config.max_overflow == 40
        assert config.pool_pre_ping is True
    
    def test_default_values(self):
        """Test default configuration values"""
        config = DatabaseConfig()
        assert "postgresql+asyncpg" in config.url
        assert config.pool_size == 20
        assert config.max_overflow == 40
        assert config.pool_timeout == 30
        assert config.pool_recycle == 3600
        assert config.max_retries == 3
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Invalid pool size
        with pytest.raises(ValueError):
            DatabaseConfig(pool_size=0)
        
        # Invalid timeout
        with pytest.raises(ValueError):
            DatabaseConfig(pool_timeout=-1)


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestQueryMetrics:
    """Test QueryMetrics functionality"""
    
    def test_metrics_initialization(self):
        """Test metrics initialization"""
        metrics = QueryMetrics()
        assert metrics.total_queries == 0
        assert metrics.slow_queries == 0
        assert metrics.failed_queries == 0
        assert metrics.total_time == 0.0
        assert isinstance(metrics.last_reset, datetime)
    
    def test_record_successful_query(self):
        """Test recording successful query"""
        metrics = QueryMetrics()
        duration = 0.5
        
        metrics.record_query(duration, success=True, slow_threshold=1.0)
        
        assert metrics.total_queries == 1
        assert metrics.slow_queries == 0
        assert metrics.failed_queries == 0
        assert metrics.total_time == duration
    
    def test_record_slow_query(self):
        """Test recording slow query"""
        metrics = QueryMetrics()
        duration = 2.0
        slow_threshold = 1.0
        
        metrics.record_query(duration, success=True, slow_threshold=slow_threshold)
        
        assert metrics.total_queries == 1
        assert metrics.slow_queries == 1
        assert metrics.failed_queries == 0
    
    def test_record_failed_query(self):
        """Test recording failed query"""
        metrics = QueryMetrics()
        duration = 0.5
        
        metrics.record_query(duration, success=False)
        
        assert metrics.total_queries == 1
        assert metrics.slow_queries == 0
        assert metrics.failed_queries == 1
    
    def test_get_stats(self):
        """Test getting statistics"""
        metrics = QueryMetrics()
        
        # Record some queries
        metrics.record_query(0.5, success=True)
        metrics.record_query(1.5, success=True, slow_threshold=1.0)  # Slow
        metrics.record_query(0.3, success=False)  # Failed
        
        stats = metrics.get_stats()
        
        assert stats["total_queries"] == 3
        assert stats["avg_duration"] == (0.5 + 1.5 + 0.3) / 3
        assert stats["slow_queries"] == 1
        assert stats["slow_query_rate"] == 1/3
        assert stats["failed_queries"] == 1
        assert stats["error_rate"] == 1/3
        assert "uptime" in stats
    
    def test_reset_metrics(self):
        """Test resetting metrics"""
        metrics = QueryMetrics()
        
        # Record some data
        metrics.record_query(0.5, success=True)
        assert metrics.total_queries == 1
        
        # Reset
        old_reset_time = metrics.last_reset
        metrics.reset()
        
        assert metrics.total_queries == 0
        assert metrics.slow_queries == 0
        assert metrics.failed_queries == 0
        assert metrics.total_time == 0.0
        assert metrics.last_reset > old_reset_time


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestDatabaseModels:
    """Test database model definitions"""
    
    def test_nexus_resource_model(self):
        """Test NexusResource model"""
        # Test that model has required fields
        assert hasattr(NexusResource, 'id')
        assert hasattr(NexusResource, 'name')
        assert hasattr(NexusResource, 'type')
        assert hasattr(NexusResource, 'provider')
        assert hasattr(NexusResource, 'region')
        assert hasattr(NexusResource, 'status')
        assert hasattr(NexusResource, 'config')
        assert hasattr(NexusResource, 'metadata')
        assert hasattr(NexusResource, 'created_at')
        assert hasattr(NexusResource, 'updated_at')
        assert hasattr(NexusResource, 'created_by')
    
    def test_nexus_user_model(self):
        """Test NexusUser model"""
        assert hasattr(NexusUser, 'id')
        assert hasattr(NexusUser, 'username')
        assert hasattr(NexusUser, 'email')
        assert hasattr(NexusUser, 'password_hash')
        assert hasattr(NexusUser, 'roles')
        assert hasattr(NexusUser, 'is_active')
        assert hasattr(NexusUser, 'is_locked')
        assert hasattr(NexusUser, 'failed_login_attempts')
        assert hasattr(NexusUser, 'last_login')
        assert hasattr(NexusUser, 'mfa_enabled')
        assert hasattr(NexusUser, 'mfa_secret')
    
    def test_nexus_session_model(self):
        """Test NexusSession model"""
        assert hasattr(NexusSession, 'id')
        assert hasattr(NexusSession, 'user_id')
        assert hasattr(NexusSession, 'created_at')
        assert hasattr(NexusSession, 'last_activity')
        assert hasattr(NexusSession, 'expires_at')
        assert hasattr(NexusSession, 'ip_address')
        assert hasattr(NexusSession, 'user_agent')
        assert hasattr(NexusSession, 'is_active')
    
    def test_nexus_audit_log_model(self):
        """Test NexusAuditLog model"""
        assert hasattr(NexusAuditLog, 'id')
        assert hasattr(NexusAuditLog, 'user_id')
        assert hasattr(NexusAuditLog, 'action')
        assert hasattr(NexusAuditLog, 'resource_type')
        assert hasattr(NexusAuditLog, 'resource_id')
        assert hasattr(NexusAuditLog, 'details')
        assert hasattr(NexusAuditLog, 'ip_address')
        assert hasattr(NexusAuditLog, 'user_agent')
        assert hasattr(NexusAuditLog, 'timestamp')


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestDatabaseManager:
    """Test DatabaseManager functionality"""
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self):
        """Test database manager initialization"""
        config = DatabaseConfig(url="sqlite+aiosqlite:///:memory:")
        manager = DatabaseManager(config)
        
        assert manager.config == config
        assert manager.engine is None
        assert manager.session_factory is None
        assert not manager.initialized
        assert isinstance(manager.metrics, QueryMetrics)
    
    @pytest.mark.asyncio
    async def test_initialization_with_sqlite(self):
        """Test initialization with SQLite for testing"""
        config = DatabaseConfig(url="sqlite+aiosqlite:///:memory:")
        manager = DatabaseManager(config)
        
        # Mock the actual SQLAlchemy components to avoid real database
        with patch('nexus_database_manager.create_async_engine') as mock_engine, \
             patch('nexus_database_manager.async_sessionmaker') as mock_sessionmaker:
            
            mock_engine.return_value = MagicMock()
            mock_sessionmaker.return_value = MagicMock()
            
            await manager.initialize()
            
            assert manager.initialized
            assert mock_engine.called
            assert mock_sessionmaker.called
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self):
        """Test health check when database is healthy"""
        manager = DatabaseManager()
        manager._is_healthy = True
        
        assert manager.is_healthy()
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self):
        """Test health check when database is unhealthy"""
        manager = DatabaseManager()
        manager._is_healthy = False
        
        assert not manager.is_healthy()
    
    def test_get_health_status(self):
        """Test getting detailed health status"""
        manager = DatabaseManager()
        manager._is_healthy = True
        manager._last_health_check = datetime.utcnow()
        
        status = manager.get_health_status()
        
        assert isinstance(status, dict)
        assert "is_healthy" in status
        assert "last_health_check" in status
        assert "query_metrics" in status
        assert "config" in status
        
        assert status["is_healthy"] is True
    
    @pytest.mark.asyncio
    async def test_session_context_manager_success(self, db_manager):
        """Test session context manager with successful transaction"""
        # Mock session for testing
        mock_session = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        async with db_manager.get_session() as session:
            assert session == mock_session
        
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()
        mock_session.rollback.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_session_context_manager_failure(self, db_manager):
        """Test session context manager with failed transaction"""
        mock_session = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        with pytest.raises(ValueError):
            async with db_manager.get_session() as session:
                raise ValueError("Test error")
        
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
        mock_session.commit.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_create_resource(self, db_manager):
        """Test creating a resource"""
        resource_data = {
            "name": "test-resource",
            "type": "compute",
            "provider": "aws",
            "region": "us-east-1",
            "config": {"instance_type": "t3.micro"},
            "created_by": "testuser"
        }
        
        # Mock the actual database operations
        mock_session = AsyncMock()
        mock_resource = MagicMock()
        mock_resource.id = "test-resource-id"
        
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.refresh = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        with patch('nexus_database_manager.NexusResource', return_value=mock_resource):
            resource = await db_manager.create_resource(resource_data)
        
        assert resource == mock_resource
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()
        mock_session.refresh.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cache_operations(self):
        """Test cache functionality"""
        manager = DatabaseManager()
        manager._cache_ttl = 1  # 1 second for testing
        
        # Test cache miss
        result = manager._cache.get("test_key")
        assert result is None
        
        # Test cache set
        test_data = {"test": "data"}
        manager._cache["test_key"] = (test_data, manager._cache_ttl)
        
        # Test cache hit
        cached_data, cached_time = manager._cache["test_key"]
        assert cached_data == test_data
        
        # Test cache clear
        manager._clear_cache()
        assert len(manager._cache) == 0
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, db_manager):
        """Test audit logging functionality"""
        audit_data = {
            "user_id": "user123",
            "action": "resource_created",
            "resource_type": "compute",
            "resource_id": "resource123",
            "details": {"provider": "aws"},
            "ip_address": "192.168.1.100"
        }
        
        # Mock the database operations
        mock_session = AsyncMock()
        mock_audit_log = MagicMock()
        mock_audit_log.id = "audit-log-id"
        
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.refresh = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        with patch('nexus_database_manager.NexusAuditLog', return_value=mock_audit_log):
            audit_log = await db_manager.log_audit_event(audit_data)
        
        assert audit_log == mock_audit_log
        mock_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_with_retry_success(self, db_manager):
        """Test execute with retry - successful on first attempt"""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        query = "SELECT 1"
        result = await db_manager.execute_with_retry(query)
        
        assert result == mock_result
        assert mock_session.execute.call_count == 1
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, db_manager):
        """Test cleanup of expired sessions"""
        # Mock the database operations
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        deleted_count = await db_manager.cleanup_expired_sessions()
        
        assert deleted_count == 5
        mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_close_manager(self):
        """Test closing database manager"""
        manager = DatabaseManager()
        
        # Mock engine
        mock_engine = AsyncMock()
        mock_engine.dispose = AsyncMock()
        manager.engine = mock_engine
        
        # Mock health check task
        mock_task = AsyncMock()
        mock_task.cancel = MagicMock()
        manager._health_check_task = mock_task
        
        await manager.close()
        
        mock_task.cancel.assert_called_once()
        mock_engine.dispose.assert_called_once()


@pytest.mark.skipif(not NEXUS_MODULES_AVAILABLE, reason="Nexus modules not available")
class TestDatabaseIntegration:
    """Test database integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_user_resource_relationship(self, db_manager):
        """Test relationships between users and resources"""
        # This would test foreign key relationships and joins
        # For unit tests, we'll mock the complex queries
        
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        # Test getting resources by user
        user_id = "user123"
        await db_manager.get_resources_by_provider("aws", limit=10, offset=0)
        
        mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_audit_trail_integrity(self, db_manager):
        """Test audit trail maintains integrity"""
        # Mock audit log creation for multiple actions
        audit_events = [
            {"action": "user_login", "user_id": "user1"},
            {"action": "resource_created", "user_id": "user1", "resource_id": "res1"},
            {"action": "resource_deleted", "user_id": "user1", "resource_id": "res1"},
        ]
        
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.refresh = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.close = AsyncMock()
        
        db_manager.session_factory = MagicMock(return_value=mock_session)
        
        # Log multiple audit events
        for event_data in audit_events:
            with patch('nexus_database_manager.NexusAuditLog') as mock_audit:
                mock_audit.return_value = MagicMock()
                await db_manager.log_audit_event(event_data)
        
        # Should have called add for each event
        assert mock_session.add.call_count == len(audit_events)