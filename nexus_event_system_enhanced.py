#!/usr/bin/env python3
"""
Enhanced NexusController v2.0 Event-Driven Architecture
Advanced event bus with Kafka, circuit breakers, and observability
"""

import asyncio
import json
import os
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Set, Union
import structlog
from pydantic import BaseModel, Field, ConfigDict

# Kafka imports
try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer, ConsumerRecord
    from aiokafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logger = structlog.get_logger(__name__)
    logger.warning("Kafka libraries not available, using in-memory backend only")

# OpenTelemetry imports
try:
    from opentelemetry import trace, metrics
    from opentelemetry.trace import Status, StatusCode
    TELEMETRY_AVAILABLE = True
except ImportError:
    TELEMETRY_AVAILABLE = False

# Prometheus metrics
try:
    import prometheus_client
    events_published_total = prometheus_client.Counter('nexus_events_published_total', 'Total events published', ['event_type'])
    events_processed_total = prometheus_client.Counter('nexus_events_processed_total', 'Total events processed', ['handler'])
    event_processing_duration = prometheus_client.Histogram('nexus_event_processing_duration_seconds', 'Event processing duration')
    event_handler_errors = prometheus_client.Counter('nexus_event_handler_errors_total', 'Event handler errors', ['handler', 'error_type'])
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = structlog.get_logger(__name__)


class EventPriority(Enum):
    """Event priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatus(Enum):
    """Event processing status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"


class EventType(Enum):
    """Comprehensive event types"""
    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    SYSTEM_HEALTH_CHECK = "system.health_check"
    
    # Resource events
    RESOURCE_CREATED = "resource.created"
    RESOURCE_UPDATED = "resource.updated"
    RESOURCE_DELETED = "resource.deleted"
    RESOURCE_STATE_CHANGED = "resource.state_changed"
    RESOURCE_HEALTH_CHECK = "resource.health_check"
    
    # Authentication events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_LOGIN_FAILED = "user.login_failed"
    SESSION_CREATED = "session.created"
    SESSION_EXPIRED = "session.expired"
    
    # Security events
    SECURITY_ALERT = "security.alert"
    UNAUTHORIZED_ACCESS = "security.unauthorized_access"
    PERMISSION_DENIED = "security.permission_denied"
    API_KEY_USED = "security.api_key_used"
    
    # Infrastructure events
    DEPLOYMENT_STARTED = "deployment.started"
    DEPLOYMENT_COMPLETED = "deployment.completed"
    DEPLOYMENT_FAILED = "deployment.failed"
    BACKUP_STARTED = "backup.started"
    BACKUP_COMPLETED = "backup.completed"
    
    # Monitoring events
    METRIC_THRESHOLD_EXCEEDED = "monitoring.threshold_exceeded"
    ALERT_TRIGGERED = "monitoring.alert_triggered"
    ALERT_RESOLVED = "monitoring.alert_resolved"
    
    # Cloud events
    CLOUD_SYNC_STARTED = "cloud.sync.started"
    CLOUD_SYNC_COMPLETED = "cloud.sync.completed"
    CLOUD_RESOURCE_CREATED = "cloud.resource.created"
    CLOUD_RESOURCE_DELETED = "cloud.resource.deleted"
    
    # Network events
    NETWORK_SCAN_STARTED = "network.scan.started"
    NETWORK_SCAN_COMPLETED = "network.scan.completed"
    DEVICE_DISCOVERED = "network.device.discovered"
    DEVICE_LOST = "network.device.lost"
    
    # Plugin events
    PLUGIN_LOADED = "plugin.loaded"
    PLUGIN_UNLOADED = "plugin.unloaded"
    PLUGIN_ERROR = "plugin.error"
    
    # Custom events
    CUSTOM = "custom"


@dataclass
class EventMetadata:
    """Event metadata for tracking and correlation"""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    causation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    source_component: str = "unknown"
    trace_id: Optional[str] = None
    span_id: Optional[str] = None


class EventModel(BaseModel):
    """Pydantic model for event validation"""
    model_config = ConfigDict(validate_assignment=True, use_enum_values=True)
    
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    source: str = "nexus.controller"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = Field(default_factory=dict)
    metadata: EventMetadata = Field(default_factory=EventMetadata)
    priority: EventPriority = EventPriority.NORMAL
    status: EventStatus = EventStatus.PENDING
    retry_count: int = 0
    max_retries: int = 3
    expires_at: Optional[datetime] = None
    tags: Set[str] = Field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = self.model_dump()
        data['timestamp'] = self.timestamp.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventModel':
        """Create from dictionary"""
        data = data.copy()
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)
    
    def is_expired(self) -> bool:
        """Check if event has expired"""
        return self.expires_at is not None and datetime.utcnow() > self.expires_at
    
    def should_retry(self) -> bool:
        """Check if event should be retried"""
        return self.status == EventStatus.FAILED and self.retry_count < self.max_retries


class EventHandlerProtocol(Protocol):
    """Protocol for event handlers"""
    
    async def handle(self, event: EventModel) -> bool:
        """Handle an event, return True if successful"""
        ...
    
    def can_handle(self, event: EventModel) -> bool:
        """Check if this handler can process the event"""
        ...
    
    @property
    def name(self) -> str:
        """Handler name for identification"""
        ...


class BaseEventHandler(ABC):
    """Abstract base class for event handlers"""
    
    def __init__(self, name: str):
        self._name = name
        self.processed_count = 0
        self.error_count = 0
        self.last_processed = None
    
    @property
    def name(self) -> str:
        return self._name
    
    @abstractmethod
    async def handle(self, event: EventModel) -> bool:
        """Handle an event"""
        pass
    
    @abstractmethod
    def can_handle(self, event: EventModel) -> bool:
        """Check if this handler can process the event"""
        pass
    
    async def _execute_with_metrics(self, event: EventModel) -> bool:
        """Execute handler with metrics and error handling"""
        start_time = time.time()
        
        try:
            if TELEMETRY_AVAILABLE:
                tracer = trace.get_tracer(__name__)
                with tracer.start_as_current_span(f"event_handler_{self.name}") as span:
                    span.set_attribute("event.type", event.event_type.value)
                    span.set_attribute("event.id", event.event_id)
                    span.set_attribute("handler.name", self.name)
                    
                    result = await self.handle(event)
                    
                    if result:
                        span.set_status(Status(StatusCode.OK))
                    else:
                        span.set_status(Status(StatusCode.ERROR))
                    
                    return result
            else:
                return await self.handle(event)
                
        except Exception as e:
            self.error_count += 1
            
            if METRICS_AVAILABLE:
                event_handler_errors.labels(
                    handler=self.name,
                    error_type=type(e).__name__
                ).inc()
            
            logger.error(
                "Event handler error",
                handler=self.name,
                event_id=event.event_id,
                error=str(e),
                exc_info=True
            )
            return False
        finally:
            duration = time.time() - start_time
            self.processed_count += 1
            self.last_processed = datetime.utcnow()
            
            if METRICS_AVAILABLE:
                event_processing_duration.observe(duration)
                events_processed_total.labels(handler=self.name).inc()


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker for event handler protection"""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 3
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        async with self._lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                    logger.info("Circuit breaker transitioning to HALF_OPEN")
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = await func(*args, **kwargs)
                await self._on_success()
                return result
            except Exception as e:
                await self._on_failure()
                raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        if self.last_failure_time is None:
            return False
        
        return (datetime.utcnow() - self.last_failure_time).total_seconds() > self.recovery_timeout
    
    async def _on_success(self):
        """Handle successful execution"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                logger.info("Circuit breaker transitioned to CLOSED")
        else:
            self.failure_count = 0
    
    async def _on_failure(self):
        """Handle failed execution"""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker transitioned to OPEN from HALF_OPEN")
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker transitioned to OPEN due to failures")


class EventBusConfig(BaseModel):
    """Event bus configuration"""
    backend: str = "memory"  # memory, kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_prefix: str = "nexus"
    kafka_consumer_group: str = "nexus-controller"
    max_retries: int = 3
    retry_delay: float = 1.0
    circuit_breaker_enabled: bool = True
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 60
    batch_size: int = 100
    flush_interval: float = 1.0
    dead_letter_queue_enabled: bool = True


class KafkaEventBackend:
    """Kafka backend for event bus"""
    
    def __init__(self, config: EventBusConfig):
        if not KAFKA_AVAILABLE:
            raise RuntimeError("Kafka libraries not available")
        
        self.config = config
        self.producer: Optional[AIOKafkaProducer] = None
        self.consumers: Dict[str, AIOKafkaConsumer] = {}
        self.topics: Set[str] = set()
        self._running = False
        
    async def initialize(self):
        """Initialize Kafka connections"""
        try:
            # Initialize producer
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.config.kafka_bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                retry_backoff_ms=int(self.config.retry_delay * 1000),
                retries=self.config.max_retries,
                acks='all',
                enable_idempotence=True,
                compression_type='gzip'
            )
            await self.producer.start()
            
            self._running = True
            logger.info("Kafka backend initialized", servers=self.config.kafka_bootstrap_servers)
            
        except Exception as e:
            logger.error("Failed to initialize Kafka backend", error=str(e))
            raise
    
    async def publish(self, topic: str, event: EventModel):
        """Publish event to Kafka topic"""
        if not self.producer:
            raise RuntimeError("Kafka backend not initialized")
        
        try:
            await self.producer.send(
                topic,
                value=event.to_dict(),
                key=event.event_id,
                headers=[
                    ('event_type', event.event_type.value.encode()),
                    ('priority', event.priority.value.encode()),
                    ('correlation_id', event.metadata.correlation_id.encode())
                ]
            )
            
            if METRICS_AVAILABLE:
                events_published_total.labels(event_type=event.event_type.value).inc()
            
            logger.debug("Event published to Kafka", topic=topic, event_id=event.event_id)
            
        except KafkaError as e:
            logger.error("Failed to publish event to Kafka", topic=topic, error=str(e))
            raise
    
    async def subscribe(self, topics: List[str], handler: Callable[[EventModel], bool]):
        """Subscribe to Kafka topics"""
        consumer_id = str(uuid.uuid4())
        
        try:
            consumer = AIOKafkaConsumer(
                *topics,
                bootstrap_servers=self.config.kafka_bootstrap_servers,
                group_id=self.config.kafka_consumer_group,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                enable_auto_commit=False,  # Manual commit for reliability
                auto_offset_reset='earliest',
                max_poll_records=self.config.batch_size
            )
            
            await consumer.start()
            self.consumers[consumer_id] = consumer
            
            # Start consumption task
            asyncio.create_task(self._consume_messages(consumer, handler))
            
            logger.info("Subscribed to Kafka topics", topics=topics, consumer_id=consumer_id)
            
        except Exception as e:
            logger.error("Failed to subscribe to Kafka topics", topics=topics, error=str(e))
            raise
    
    async def _consume_messages(self, consumer: AIOKafkaConsumer, handler: Callable):
        """Consume messages from Kafka"""
        try:
            async for msg in consumer:
                try:
                    event = EventModel.from_dict(msg.value)
                    
                    # Process event
                    success = await handler(event)
                    
                    if success:
                        await consumer.commit()
                    else:
                        # Handle failure - could implement dead letter queue here
                        logger.warning("Event processing failed", event_id=event.event_id)
                        
                except Exception as e:
                    logger.error("Error consuming Kafka message", error=str(e))
                    
        except Exception as e:
            logger.error("Kafka consumer error", error=str(e))
    
    async def close(self):
        """Close Kafka connections"""
        self._running = False
        
        if self.producer:
            await self.producer.stop()
        
        for consumer in self.consumers.values():
            await consumer.stop()
        
        logger.info("Kafka backend closed")


class MemoryEventBackend:
    """In-memory backend for event bus"""
    
    def __init__(self, config: EventBusConfig):
        self.config = config
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize memory backend"""
        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("Memory backend initialized")
    
    async def publish(self, topic: str, event: EventModel):
        """Publish event to memory queue"""
        try:
            await self.event_queue.put((topic, event))
            
            if METRICS_AVAILABLE:
                events_published_total.labels(event_type=event.event_type.value).inc()
            
        except asyncio.QueueFull:
            logger.error("Event queue full, dropping event", event_id=event.event_id)
    
    async def subscribe(self, topics: List[str], handler: Callable):
        """Subscribe to topics"""
        for topic in topics:
            self.subscribers[topic].append(handler)
        
        logger.info("Subscribed to memory topics", topics=topics)
    
    async def _process_events(self):
        """Process events from queue"""
        while self._running:
            try:
                topic, event = await asyncio.wait_for(
                    self.event_queue.get(), 
                    timeout=1.0
                )
                
                # Send to all subscribers
                handlers = self.subscribers.get(topic, [])
                for handler in handlers:
                    try:
                        asyncio.create_task(handler(event))
                    except Exception as e:
                        logger.error("Error dispatching event", error=str(e))
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Error processing events", error=str(e))
    
    async def close(self):
        """Close memory backend"""
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Memory backend closed")


class EnhancedEventBus:
    """Enhanced event bus with multiple backends and advanced features"""
    
    def __init__(self, config: Optional[EventBusConfig] = None):
        self.config = config or EventBusConfig()
        self.backend = None
        self.handlers: Dict[EventType, List[EventHandlerProtocol]] = defaultdict(list)
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.dead_letter_queue: deque = deque(maxlen=1000)
        self.metrics = {
            'events_published': 0,
            'events_processed': 0,
            'events_failed': 0,
            'handlers_registered': 0
        }
        self._running = False
        
        logger.info("Enhanced event bus initialized", backend=self.config.backend)
    
    async def initialize(self):
        """Initialize the event bus"""
        # Choose backend
        if self.config.backend == "kafka" and KAFKA_AVAILABLE:
            self.backend = KafkaEventBackend(self.config)
        else:
            self.backend = MemoryEventBackend(self.config)
        
        await self.backend.initialize()
        self._running = True
        
        logger.info("Event bus initialized successfully")
    
    def subscribe(self, event_types: Union[EventType, List[EventType]], handler: EventHandlerProtocol):
        """Subscribe handler to event types"""
        if isinstance(event_types, EventType):
            event_types = [event_types]
        
        for event_type in event_types:
            self.handlers[event_type].append(handler)
            
            # Create circuit breaker for handler if enabled
            if self.config.circuit_breaker_enabled:
                cb_key = f"{handler.name}_{event_type.value}"
                self.circuit_breakers[cb_key] = CircuitBreaker(
                    failure_threshold=self.config.circuit_breaker_failure_threshold,
                    recovery_timeout=self.config.circuit_breaker_recovery_timeout
                )
        
        self.metrics['handlers_registered'] += len(event_types)
        
        # Subscribe to backend
        topics = [self._get_topic_name(et) for et in event_types]
        asyncio.create_task(
            self.backend.subscribe(topics, self._handle_event)
        )
        
        logger.info(
            "Handler subscribed to event types",
            handler=handler.name,
            event_types=[et.value for et in event_types]
        )
    
    async def publish(self, event: EventModel):
        """Publish an event"""
        if not self._running:
            raise RuntimeError("Event bus not running")
        
        # Validate event
        if event.is_expired():
            logger.warning("Dropping expired event", event_id=event.event_id)
            return
        
        # Add telemetry context
        if TELEMETRY_AVAILABLE:
            span = trace.get_current_span()
            if span:
                event.metadata.trace_id = format(span.get_span_context().trace_id, '032x')
                event.metadata.span_id = format(span.get_span_context().span_id, '016x')
        
        try:
            topic = self._get_topic_name(event.event_type)
            await self.backend.publish(topic, event)
            
            self.metrics['events_published'] += 1
            
            logger.debug(
                "Event published",
                event_id=event.event_id,
                event_type=event.event_type.value,
                topic=topic
            )
            
        except Exception as e:
            logger.error("Failed to publish event", event_id=event.event_id, error=str(e))
            raise
    
    async def _handle_event(self, event: EventModel) -> bool:
        """Handle incoming event"""
        handlers = self.handlers.get(event.event_type, [])
        
        if not handlers:
            logger.debug("No handlers for event type", event_type=event.event_type.value)
            return True
        
        results = []
        
        for handler in handlers:
            if not handler.can_handle(event):
                continue
            
            try:
                # Use circuit breaker if enabled
                if self.config.circuit_breaker_enabled:
                    cb_key = f"{handler.name}_{event.event_type.value}"
                    circuit_breaker = self.circuit_breakers.get(cb_key)
                    
                    if circuit_breaker:
                        result = await circuit_breaker.call(handler._execute_with_metrics, event)
                    else:
                        result = await handler._execute_with_metrics(event)
                else:
                    result = await handler._execute_with_metrics(event)
                
                results.append(result)
                
            except Exception as e:
                logger.error(
                    "Handler execution failed",
                    handler=handler.name,
                    event_id=event.event_id,
                    error=str(e)
                )
                results.append(False)
        
        # Update metrics
        if any(results):
            self.metrics['events_processed'] += 1
        else:
            self.metrics['events_failed'] += 1
            
            # Add to dead letter queue if enabled
            if self.config.dead_letter_queue_enabled:
                self.dead_letter_queue.append({
                    'event': event.to_dict(),
                    'failed_at': datetime.utcnow().isoformat(),
                    'handlers_attempted': [h.name for h in handlers]
                })
        
        return any(results)
    
    def _get_topic_name(self, event_type: EventType) -> str:
        """Get Kafka topic name for event type"""
        return f"{self.config.kafka_topic_prefix}.{event_type.value.replace('.', '_')}"
    
    async def close(self):
        """Close the event bus"""
        self._running = False
        if self.backend:
            await self.backend.close()
        
        logger.info("Event bus closed")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get event bus metrics"""
        return {
            **self.metrics,
            'dead_letter_queue_size': len(self.dead_letter_queue),
            'handlers_count': sum(len(handlers) for handlers in self.handlers.values()),
            'circuit_breakers': {
                name: cb.state.value for name, cb in self.circuit_breakers.items()
            }
        }
    
    def get_dead_letter_queue(self) -> List[Dict[str, Any]]:
        """Get dead letter queue contents"""
        return list(self.dead_letter_queue)


# Example event handlers
class LoggingEventHandler(BaseEventHandler):
    """Handler that logs all events"""
    
    def __init__(self):
        super().__init__("logging")
    
    async def handle(self, event: EventModel) -> bool:
        """Log the event"""
        logger.info(
            "Event received",
            event_id=event.event_id,
            event_type=event.event_type.value,
            source=event.source,
            data=event.data
        )
        return True
    
    def can_handle(self, event: EventModel) -> bool:
        """Can handle all events"""
        return True


class SecurityEventHandler(BaseEventHandler):
    """Handler for security events"""
    
    def __init__(self):
        super().__init__("security")
        self.alert_threshold = 5
        self.failed_logins = defaultdict(int)
    
    async def handle(self, event: EventModel) -> bool:
        """Handle security events"""
        if event.event_type == EventType.USER_LOGIN_FAILED:
            user_id = event.data.get('user_id')
            if user_id:
                self.failed_logins[user_id] += 1
                
                if self.failed_logins[user_id] >= self.alert_threshold:
                    logger.warning(
                        "Multiple failed login attempts detected",
                        user_id=user_id,
                        attempts=self.failed_logins[user_id]
                    )
                    # Could trigger additional security measures here
        
        elif event.event_type == EventType.USER_LOGIN:
            # Reset failed login counter on successful login
            user_id = event.data.get('user_id')
            if user_id and user_id in self.failed_logins:
                del self.failed_logins[user_id]
        
        return True
    
    def can_handle(self, event: EventModel) -> bool:
        """Handle security-related events"""
        return event.event_type in [
            EventType.USER_LOGIN,
            EventType.USER_LOGIN_FAILED,
            EventType.UNAUTHORIZED_ACCESS,
            EventType.SECURITY_ALERT
        ]


# Global event bus instance
event_bus: Optional[EnhancedEventBus] = None


async def get_event_bus() -> EnhancedEventBus:
    """Get global event bus instance"""
    global event_bus
    if event_bus is None:
        event_bus = EnhancedEventBus()
        await event_bus.initialize()
    return event_bus


@asynccontextmanager
async def event_bus_context(config: Optional[EventBusConfig] = None):
    """Context manager for event bus"""
    bus = EnhancedEventBus(config)
    await bus.initialize()
    try:
        yield bus
    finally:
        await bus.close()


if __name__ == "__main__":
    # Example usage
    async def main():
        config = EventBusConfig(backend="memory")
        
        async with event_bus_context(config) as bus:
            # Register handlers
            logging_handler = LoggingEventHandler()
            security_handler = SecurityEventHandler()
            
            bus.subscribe([EventType.SYSTEM_STARTUP, EventType.RESOURCE_CREATED], logging_handler)
            bus.subscribe([EventType.USER_LOGIN, EventType.USER_LOGIN_FAILED], security_handler)
            
            # Publish some events
            startup_event = EventModel(
                event_type=EventType.SYSTEM_STARTUP,
                source="nexus.main",
                data={"version": "2.0.0", "environment": "production"}
            )
            
            await bus.publish(startup_event)
            
            login_event = EventModel(
                event_type=EventType.USER_LOGIN,
                source="nexus.auth",
                data={"user_id": "user123", "ip_address": "192.168.1.100"}
            )
            
            await bus.publish(login_event)
            
            # Wait a bit for processing
            await asyncio.sleep(2)
            
            # Get metrics
            metrics = bus.get_metrics()
            logger.info("Event bus metrics", **metrics)
    
    asyncio.run(main())