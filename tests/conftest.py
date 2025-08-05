#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for NexusController tests
"""

import asyncio
import os
import uuid
from datetime import datetime
from typing import AsyncGenerator, Dict, Any
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

# Test configuration
os.environ.setdefault("TESTING", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")  # Use test database
os.environ.setdefault("LOG_LEVEL", "DEBUG")

# Import modules to test
try:
    from nexus_auth_security import SecurityService, UserModel, Role, Permission
    from nexus_database_manager import DatabaseManager, DatabaseConfig
    from nexus_event_system_enhanced import EnhancedEventBus, EventBusConfig, EventModel, EventType
    from nexus_plugin_system_enhanced import EnhancedPluginManager
    from nexus_circuit_breaker import CircuitBreaker, CircuitBreakerConfig
    from nexus_observability import ObservabilityManager, ObservabilityConfig
    NEXUS_MODULES_AVAILABLE = True
except ImportError:
    NEXUS_MODULES_AVAILABLE = False

# FastAPI test client
try:
    from fastapi.testclient import TestClient
    from httpx import AsyncClient
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Mock configuration for testing"""
    return {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "jwt_secret_key": "test-secret-key-for-testing-only",
        "environment": "test",
        "debug": True
    }


@pytest.fixture
def sample_user_data() -> Dict[str, Any]:
    """Sample user data for testing"""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password_hash": "$2b$12$test.hash.for.testing.only",
        "roles": ["viewer"],
        "is_active": True,
        "is_locked": False,
        "failed_login_attempts": 0,
        "mfa_enabled": False
    }


@pytest.fixture
def sample_resource_data() -> Dict[str, Any]:
    """Sample resource data for testing"""
    return {
        "name": "test-resource",
        "type": "compute",
        "provider": "aws",
        "region": "us-east-1",
        "config": {"instance_type": "t3.micro"},
        "metadata": {"tags": {"Environment": "test"}},
        "created_by": "testuser"
    }


@pytest.fixture
def sample_event_data() -> Dict[str, Any]:
    """Sample event data for testing"""
    return {
        "event_type": EventType.RESOURCE_CREATED,
        "source": "test",
        "data": {"test": "data"},
        "metadata": {"correlation_id": str(uuid.uuid4())}
    }


# Database fixtures
@pytest_asyncio.fixture
async def db_manager() -> AsyncGenerator[DatabaseManager, None]:
    """Database manager fixture with in-memory SQLite"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    config = DatabaseConfig(url="sqlite+aiosqlite:///:memory:")
    manager = DatabaseManager(config)
    
    await manager.initialize()
    await manager.create_tables()
    
    yield manager
    
    await manager.close()


# Security fixtures
@pytest.fixture
def security_service() -> SecurityService:
    """Security service fixture"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    from nexus_auth_security import SecurityConfig
    config = SecurityConfig(
        jwt_secret_key="test-secret-key-for-testing-only",
        access_token_expire_minutes=15,
        max_login_attempts=3
    )
    return SecurityService(config)


@pytest.fixture
def test_user() -> UserModel:
    """Test user fixture"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    return UserModel(
        username="testuser",
        email="test@example.com",
        roles=[Role.VIEWER]
    )


@pytest.fixture
def admin_user() -> UserModel:
    """Admin user fixture"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    return UserModel(
        username="admin",
        email="admin@example.com",
        roles=[Role.ADMIN]
    )


# Event system fixtures
@pytest_asyncio.fixture
async def event_bus() -> AsyncGenerator[EnhancedEventBus, None]:
    """Event bus fixture"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    config = EventBusConfig(backend="memory")
    bus = EnhancedEventBus(config)
    
    await bus.initialize()
    
    yield bus
    
    await bus.close()


# Circuit breaker fixtures
@pytest.fixture
def circuit_breaker() -> CircuitBreaker:
    """Circuit breaker fixture"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    config = CircuitBreakerConfig(
        name="test-circuit-breaker",
        failure_threshold=3,
        recovery_timeout=5.0,
        timeout=1.0
    )
    return CircuitBreaker(config)


# Plugin system fixtures
@pytest_asyncio.fixture
async def plugin_manager() -> AsyncGenerator[EnhancedPluginManager, None]:
    """Plugin manager fixture"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    config = {
        "plugin_paths": ["./tests/fixtures/plugins"],
        "auto_discovery": False,
        "hot_reload": False
    }
    manager = EnhancedPluginManager(config)
    
    await manager.start()
    
    yield manager
    
    await manager.stop()


# Observability fixtures
@pytest_asyncio.fixture
async def observability_manager() -> AsyncGenerator[ObservabilityManager, None]:
    """Observability manager fixture"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    config = ObservabilityConfig(
        service_name="test-service",
        tracing_enabled=False,  # Disable for tests
        metrics_enabled=False   # Disable for tests
    )
    manager = ObservabilityManager(config)
    
    await manager.initialize()
    
    yield manager
    
    await manager.close()


# API fixtures
@pytest_asyncio.fixture
async def api_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for API testing"""
    if not (FASTAPI_AVAILABLE and NEXUS_MODULES_AVAILABLE):
        pytest.skip("FastAPI or Nexus modules not available")
    
    from nexus_api_server_enhanced import app
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def authenticated_headers(security_service, test_user) -> Dict[str, str]:
    """Headers with valid JWT token"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    token = security_service.create_access_token(test_user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(security_service, admin_user) -> Dict[str, str]:
    """Headers with admin JWT token"""
    if not NEXUS_MODULES_AVAILABLE:
        pytest.skip("Nexus modules not available")
    
    token = security_service.create_access_token(admin_user)
    return {"Authorization": f"Bearer {token}"}


# Mock fixtures
@pytest.fixture
def mock_aws_client():
    """Mock AWS client"""
    client = MagicMock()
    client.run_instances.return_value = {
        "Instances": [{
            "InstanceId": "i-1234567890abcdef0",
            "InstanceType": "t3.micro",
            "ImageId": "ami-12345678",
            "Placement": {"AvailabilityZone": "us-east-1a"},
            "VpcId": "vpc-12345678",
            "SubnetId": "subnet-12345678"
        }]
    }
    return client


@pytest.fixture
def mock_azure_client():
    """Mock Azure client"""
    client = MagicMock()
    return client


@pytest.fixture
def mock_gcp_client():
    """Mock GCP client"""
    client = MagicMock()
    return client


@pytest.fixture
def mock_kafka_producer():
    """Mock Kafka producer"""
    producer = AsyncMock()
    producer.start = AsyncMock()
    producer.stop = AsyncMock()
    producer.send = AsyncMock()
    return producer


@pytest.fixture
def mock_kafka_consumer():
    """Mock Kafka consumer"""
    consumer = AsyncMock()
    consumer.start = AsyncMock()
    consumer.stop = AsyncMock()
    return consumer


# Test data factories
class UserFactory:
    """Factory for creating test users"""
    
    @staticmethod
    def create_user(
        username: str = None,
        email: str = None,
        roles: list = None,
        **kwargs
    ) -> UserModel:
        if not NEXUS_MODULES_AVAILABLE:
            pytest.skip("Nexus modules not available")
        
        return UserModel(
            username=username or f"user_{uuid.uuid4().hex[:8]}",
            email=email or f"test_{uuid.uuid4().hex[:8]}@example.com",
            roles=roles or [Role.VIEWER],
            **kwargs
        )


class EventFactory:
    """Factory for creating test events"""
    
    @staticmethod
    def create_event(
        event_type: EventType = None,
        source: str = None,
        data: dict = None,
        **kwargs
    ) -> EventModel:
        if not NEXUS_MODULES_AVAILABLE:
            pytest.skip("Nexus modules not available")
        
        return EventModel(
            event_type=event_type or EventType.CUSTOM,
            source=source or "test",
            data=data or {"test": "data"},
            **kwargs
        )


# Register factories as fixtures
@pytest.fixture
def user_factory():
    return UserFactory


@pytest.fixture
def event_factory():
    return EventFactory


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as an end-to-end test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    for item in items:
        # Add unit marker to tests in unit directory
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        # Add integration marker to tests in integration directory
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        # Add e2e marker to tests in e2e directory
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)


# Helper functions for tests
def assert_valid_uuid(uuid_string: str):
    """Assert that string is a valid UUID"""
    try:
        uuid.UUID(uuid_string)
    except ValueError:
        pytest.fail(f"'{uuid_string}' is not a valid UUID")


def assert_datetime_recent(dt: datetime, tolerance_seconds: int = 60):
    """Assert that datetime is recent (within tolerance)"""
    now = datetime.utcnow()
    diff = abs((now - dt).total_seconds())
    assert diff <= tolerance_seconds, f"DateTime {dt} is not recent (diff: {diff}s)"


# Test utilities
class TestUtilities:
    """Utility functions for tests"""
    
    @staticmethod
    def create_mock_response(status_code: int = 200, json_data: dict = None):
        """Create mock HTTP response"""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_data or {}
        return mock_response
    
    @staticmethod
    async def wait_for_condition(condition_func, timeout: float = 5.0, interval: float = 0.1):
        """Wait for condition to be true"""
        import time
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if await condition_func() if asyncio.iscoroutinefunction(condition_func) else condition_func():
                return True
            await asyncio.sleep(interval)
        
        return False


@pytest.fixture
def test_utils():
    return TestUtilities