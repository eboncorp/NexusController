#!/usr/bin/env python3
"""
NexusController v2.0 Observability Suite
Comprehensive observability with OpenTelemetry, Prometheus, and structured logging
"""

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable
import structlog
from pydantic import BaseModel, Field, ConfigDict
import json

# OpenTelemetry imports
try:
    from opentelemetry import trace, metrics, baggage
    from opentelemetry.sdk.trace import TracerProvider, Resource
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader, ConsoleMetricExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.instrumentation.asyncio import AsyncIOInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    from opentelemetry.propagate import set_global_textmap
    from opentelemetry.propagators.b3 import B3MultiFormat
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.util.http import get_excluded_urls
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False

# Prometheus metrics
try:
    import prometheus_client
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, Summary, Info
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = structlog.get_logger(__name__)


class ObservabilityBackend(Enum):
    """Supported observability backends"""
    CONSOLE = "console"
    JAEGER = "jaeger"
    OTLP = "otlp"
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    GAUGE = "gauge"
    SUMMARY = "summary"
    INFO = "info"


@dataclass
class SpanContext:
    """Span context information"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, str] = field(default_factory=dict)


class ObservabilityConfig(BaseModel):
    """Configuration for observability"""
    model_config = ConfigDict(validate_assignment=True)
    
    service_name: str = "nexuscontroller"
    service_version: str = "2.0.0"
    environment: str = "production"
    
    # Tracing configuration
    tracing_enabled: bool = True
    tracing_backend: ObservabilityBackend = ObservabilityBackend.CONSOLE
    tracing_endpoint: Optional[str] = None
    trace_sample_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    
    # Metrics configuration
    metrics_enabled: bool = True
    metrics_backend: ObservabilityBackend = ObservabilityBackend.PROMETHEUS
    metrics_endpoint: Optional[str] = None
    metrics_export_interval: int = Field(default=60, gt=0)
    
    # Logging configuration
    structured_logging: bool = True
    log_level: str = "INFO"
    log_correlation: bool = True
    
    # Resource attributes
    resource_attributes: Dict[str, str] = Field(default_factory=dict)
    
    # Instrumentation
    auto_instrument: bool = True
    instrument_asyncio: bool = True
    instrument_httpx: bool = True
    instrument_sqlalchemy: bool = True


class TracingManager:
    """Manages distributed tracing"""
    
    def __init__(self, config: ObservabilityConfig):
        self.config = config
        self.tracer_provider: Optional[TracerProvider] = None
        self.tracer = None
        self.initialized = False
        
    async def initialize(self):
        """Initialize tracing"""
        if not OPENTELEMETRY_AVAILABLE:
            logger.warning("OpenTelemetry not available, tracing disabled")
            return
        
        if not self.config.tracing_enabled:
            logger.info("Tracing disabled in configuration")
            return
        
        try:
            # Create resource
            resource = Resource.create({
                "service.name": self.config.service_name,
                "service.version": self.config.service_version,
                "deployment.environment": self.config.environment,
                **self.config.resource_attributes
            })
            
            # Create tracer provider
            self.tracer_provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(self.tracer_provider)
            
            # Configure exporter based on backend
            if self.config.tracing_backend == ObservabilityBackend.CONSOLE:
                exporter = ConsoleSpanExporter()
            elif self.config.tracing_backend == ObservabilityBackend.JAEGER:
                exporter = JaegerExporter(
                    agent_host_name="localhost",
                    agent_port=14268,
                    collector_endpoint=self.config.tracing_endpoint or "http://localhost:14268/api/traces"
                )
            elif self.config.tracing_backend == ObservabilityBackend.OTLP:
                exporter = OTLPSpanExporter(
                    endpoint=self.config.tracing_endpoint or "http://localhost:4317"
                )
            else:
                exporter = ConsoleSpanExporter()
            
            # Add span processor
            span_processor = BatchSpanProcessor(exporter)
            self.tracer_provider.add_span_processor(span_processor)
            
            # Get tracer
            self.tracer = trace.get_tracer(__name__)
            
            # Set up propagation
            set_global_textmap(B3MultiFormat())
            
            # Auto-instrumentation
            if self.config.auto_instrument:
                await self._setup_auto_instrumentation()
            
            self.initialized = True
            logger.info("Tracing initialized", backend=self.config.tracing_backend.value)
            
        except Exception as e:
            logger.error("Failed to initialize tracing", error=str(e))
    
    async def _setup_auto_instrumentation(self):
        """Set up automatic instrumentation"""
        try:
            if self.config.instrument_asyncio:
                AsyncIOInstrumentor().instrument()
                logger.debug("AsyncIO instrumentation enabled")
            
            if self.config.instrument_httpx:
                HTTPXClientInstrumentor().instrument()
                logger.debug("HTTPX instrumentation enabled")
            
            if self.config.instrument_sqlalchemy:
                SQLAlchemyInstrumentor().instrument()
                logger.debug("SQLAlchemy instrumentation enabled")
                
        except Exception as e:
            logger.error("Failed to setup auto-instrumentation", error=str(e))
    
    @asynccontextmanager
    async def start_span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        links: Optional[List] = None
    ):
        """Start a new span with context management"""
        if not self.initialized or not self.tracer:
            # If tracing is not available, provide a no-op context manager
            yield None
            return
        
        with self.tracer.start_as_current_span(name, attributes=attributes, links=links) as span:
            try:
                yield span
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise
    
    def get_current_span_context(self) -> Optional[SpanContext]:
        """Get current span context"""
        if not self.initialized:
            return None
        
        current_span = trace.get_current_span()
        if current_span is None or not current_span.is_recording():
            return None
        
        span_context = current_span.get_span_context()
        
        return SpanContext(
            trace_id=format(span_context.trace_id, '032x'),
            span_id=format(span_context.span_id, '016x'),
            baggage=dict(baggage.get_all())
        )
    
    def add_baggage(self, key: str, value: str):
        """Add baggage to current context"""
        if self.initialized:
            baggage.set_baggage(key, value)
    
    async def close(self):
        """Close tracing"""
        if self.tracer_provider:
            if hasattr(self.tracer_provider, 'shutdown'):
                self.tracer_provider.shutdown()
        logger.info("Tracing closed")


class MetricsManager:
    """Manages application metrics"""
    
    def __init__(self, config: ObservabilityConfig):
        self.config = config
        self.meter_provider: Optional[MeterProvider] = None
        self.meter = None
        self.registry: Optional[CollectorRegistry] = None
        self.metrics: Dict[str, Any] = {}
        self.initialized = False
        
    async def initialize(self):
        """Initialize metrics"""
        if not self.config.metrics_enabled:
            logger.info("Metrics disabled in configuration")
            return
        
        try:
            # Initialize based on backend
            if self.config.metrics_backend == ObservabilityBackend.PROMETHEUS and PROMETHEUS_AVAILABLE:
                await self._initialize_prometheus()
            elif OPENTELEMETRY_AVAILABLE:
                await self._initialize_opentelemetry()
            else:
                logger.warning("No metrics backend available")
                return
            
            # Create common metrics
            await self._create_common_metrics()
            
            self.initialized = True
            logger.info("Metrics initialized", backend=self.config.metrics_backend.value)
            
        except Exception as e:
            logger.error("Failed to initialize metrics", error=str(e))
    
    async def _initialize_prometheus(self):
        """Initialize Prometheus metrics"""
        self.registry = CollectorRegistry()
        
    async def _initialize_opentelemetry(self):
        """Initialize OpenTelemetry metrics"""
        # Create resource
        resource = Resource.create({
            "service.name": self.config.service_name,
            "service.version": self.config.service_version,
            "deployment.environment": self.config.environment,
            **self.config.resource_attributes
        })
        
        # Configure exporter
        if self.config.metrics_backend == ObservabilityBackend.OTLP:
            exporter = OTLPMetricExporter(
                endpoint=self.config.metrics_endpoint or "http://localhost:4317"
            )
        else:
            exporter = ConsoleMetricExporter()
        
        # Create meter provider
        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=self.config.metrics_export_interval * 1000
        )
        
        self.meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(self.meter_provider)
        
        # Get meter
        self.meter = metrics.get_meter(__name__)
    
    async def _create_common_metrics(self):
        """Create common application metrics"""
        if self.config.metrics_backend == ObservabilityBackend.PROMETHEUS and self.registry:
            # Prometheus metrics
            self.metrics.update({
                'http_requests_total': Counter(
                    'nexus_http_requests_total',
                    'Total HTTP requests',
                    ['method', 'endpoint', 'status'],
                    registry=self.registry
                ),
                'http_request_duration': Histogram(
                    'nexus_http_request_duration_seconds',
                    'HTTP request duration',
                    ['method', 'endpoint'],
                    registry=self.registry
                ),
                'active_connections': Gauge(
                    'nexus_active_connections',
                    'Active connections',
                    registry=self.registry
                ),
                'resource_operations_total': Counter(
                    'nexus_resource_operations_total',
                    'Total resource operations',
                    ['operation', 'provider', 'status'],
                    registry=self.registry
                ),
                'resource_operation_duration': Histogram(
                    'nexus_resource_operation_duration_seconds',
                    'Resource operation duration',
                    ['operation', 'provider'],
                    registry=self.registry
                ),
                'plugin_operations_total': Counter(
                    'nexus_plugin_operations_total',
                    'Total plugin operations',
                    ['plugin', 'operation', 'status'],
                    registry=self.registry
                ),
                'event_bus_events_total': Counter(
                    'nexus_event_bus_events_total',
                    'Total event bus events',
                    ['event_type', 'status'],
                    registry=self.registry
                ),
                'database_connections': Gauge(
                    'nexus_database_connections',
                    'Database connections',
                    ['state'],
                    registry=self.registry
                ),
                'cache_operations_total': Counter(
                    'nexus_cache_operations_total',
                    'Total cache operations',
                    ['operation', 'result'],
                    registry=self.registry
                )
            })
        
        elif self.meter:
            # OpenTelemetry metrics
            self.metrics.update({
                'http_requests_total': self.meter.create_counter(
                    'nexus_http_requests_total',
                    description='Total HTTP requests'
                ),
                'http_request_duration': self.meter.create_histogram(
                    'nexus_http_request_duration',
                    description='HTTP request duration',
                    unit='s'
                ),
                'active_connections': self.meter.create_up_down_counter(
                    'nexus_active_connections',
                    description='Active connections'
                ),
                'resource_operations_total': self.meter.create_counter(
                    'nexus_resource_operations_total',
                    description='Total resource operations'
                ),
                'resource_operation_duration': self.meter.create_histogram(
                    'nexus_resource_operation_duration',
                    description='Resource operation duration',
                    unit='s'
                )
            })
    
    def increment_counter(self, name: str, value: float = 1, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        if not self.initialized or name not in self.metrics:
            return
        
        metric = self.metrics[name]
        
        if hasattr(metric, 'labels'):  # Prometheus
            if labels:
                metric.labels(**labels).inc(value)
            else:
                metric.inc(value)
        elif hasattr(metric, 'add'):  # OpenTelemetry
            attributes = labels or {}
            metric.add(value, attributes)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric value"""
        if not self.initialized or name not in self.metrics:
            return
        
        metric = self.metrics[name]
        
        if hasattr(metric, 'labels'):  # Prometheus
            if labels:
                metric.labels(**labels).set(value)
            else:
                metric.set(value)
        elif hasattr(metric, 'add'):  # OpenTelemetry up-down counter
            # For OpenTelemetry, we'd need to track previous values to set absolute values
            # This is a simplified implementation
            attributes = labels or {}
            metric.add(value, attributes)
    
    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Observe a histogram metric"""
        if not self.initialized or name not in self.metrics:
            return
        
        metric = self.metrics[name]
        
        if hasattr(metric, 'labels'):  # Prometheus
            if labels:
                metric.labels(**labels).observe(value)
            else:
                metric.observe(value)
        elif hasattr(metric, 'record'):  # OpenTelemetry
            attributes = labels or {}
            metric.record(value, attributes)
    
    def get_registry(self) -> Optional[CollectorRegistry]:
        """Get Prometheus registry for HTTP exposition"""
        return self.registry
    
    async def close(self):
        """Close metrics"""
        if self.meter_provider and hasattr(self.meter_provider, 'shutdown'):
            self.meter_provider.shutdown()
        logger.info("Metrics closed")


class LoggingManager:
    """Manages structured logging with correlation"""
    
    def __init__(self, config: ObservabilityConfig):
        self.config = config
        self.logger = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize structured logging"""
        try:
            if self.config.structured_logging:
                # Configure structlog
                structlog.configure(
                    processors=[
                        structlog.contextvars.merge_contextvars,
                        structlog.processors.add_log_level,
                        structlog.processors.StackInfoRenderer(),
                        structlog.dev.set_exc_info,
                        self._add_correlation_processor if self.config.log_correlation else structlog.processors.JSONRenderer(),
                        structlog.processors.JSONRenderer() if self.config.log_correlation else structlog.dev.ConsoleRenderer()
                    ],
                    wrapper_class=structlog.make_filtering_bound_logger(
                        getattr(structlog.stdlib, self.config.log_level.upper(), structlog.stdlib.INFO)
                    ),
                    logger_factory=structlog.WriteLoggerFactory(),
                    cache_logger_on_first_use=True,
                )
                
                self.logger = structlog.get_logger("nexus.observability")
            else:
                import logging
                logging.basicConfig(
                    level=getattr(logging, self.config.log_level.upper()),
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                self.logger = logging.getLogger("nexus.observability")
            
            self.initialized = True
            self.logger.info("Logging initialized", structured=self.config.structured_logging)
            
        except Exception as e:
            print(f"Failed to initialize logging: {e}")
    
    def _add_correlation_processor(self, logger, method_name, event_dict):
        """Add correlation IDs to log entries"""
        # Add trace context if available
        if OPENTELEMETRY_AVAILABLE:
            current_span = trace.get_current_span()
            if current_span and current_span.is_recording():
                span_context = current_span.get_span_context()
                event_dict['trace_id'] = format(span_context.trace_id, '032x')
                event_dict['span_id'] = format(span_context.span_id, '016x')
        
        # Add service information
        event_dict['service'] = self.config.service_name
        event_dict['version'] = self.config.service_version
        event_dict['environment'] = self.config.environment
        
        return event_dict
    
    def get_logger(self, name: str = None):
        """Get logger with correlation"""
        if not self.initialized:
            return logger  # Return default logger
        
        if self.config.structured_logging:
            return structlog.get_logger(name or "nexus")
        else:
            import logging
            return logging.getLogger(name or "nexus")


class ObservabilityManager:
    """Main observability manager"""
    
    def __init__(self, config: Optional[ObservabilityConfig] = None):
        self.config = config or ObservabilityConfig()
        self.tracing = TracingManager(self.config)
        self.metrics = MetricsManager(self.config)
        self.logging = LoggingManager(self.config)
        self.initialized = False
        
    async def initialize(self):
        """Initialize all observability components"""
        try:
            # Initialize components
            await self.logging.initialize()
            await self.tracing.initialize()
            await self.metrics.initialize()
            
            self.initialized = True
            logger.info("Observability manager initialized", config=self.config.model_dump())
            
        except Exception as e:
            logger.error("Failed to initialize observability", error=str(e))
            raise
    
    @asynccontextmanager
    async def trace_operation(
        self,
        operation_name: str,
        attributes: Optional[Dict[str, Any]] = None,
        record_metrics: bool = True
    ):
        """Trace an operation with optional metrics"""
        start_time = time.time()
        
        async with self.tracing.start_span(operation_name, attributes) as span:
            try:
                yield span
                
                # Record success metrics
                if record_metrics:
                    duration = time.time() - start_time
                    operation_type = attributes.get('operation.type', 'unknown') if attributes else 'unknown'
                    
                    self.metrics.increment_counter(
                        'resource_operations_total',
                        labels={'operation': operation_type, 'provider': 'unknown', 'status': 'success'}
                    )
                    self.metrics.observe_histogram(
                        'resource_operation_duration',
                        duration,
                        labels={'operation': operation_type, 'provider': 'unknown'}
                    )
                
            except Exception as e:
                # Record failure metrics
                if record_metrics:
                    operation_type = attributes.get('operation.type', 'unknown') if attributes else 'unknown'
                    self.metrics.increment_counter(
                        'resource_operations_total',
                        labels={'operation': operation_type, 'provider': 'unknown', 'status': 'error'}
                    )
                
                raise
    
    def get_health_metrics(self) -> Dict[str, Any]:
        """Get observability health metrics"""
        return {
            'initialized': self.initialized,
            'tracing_enabled': self.config.tracing_enabled and self.tracing.initialized,
            'metrics_enabled': self.config.metrics_enabled and self.metrics.initialized,
            'logging_enabled': self.logging.initialized,
            'backends': {
                'tracing': self.config.tracing_backend.value,
                'metrics': self.config.metrics_backend.value
            }
        }
    
    async def export_metrics(self) -> str:
        """Export metrics in Prometheus format"""
        if not self.metrics.initialized or not self.metrics.registry:
            return ""
        
        if PROMETHEUS_AVAILABLE:
            from prometheus_client import generate_latest
            return generate_latest(self.metrics.registry).decode('utf-8')
        
        return ""
    
    async def close(self):
        """Close all observability components"""
        await self.tracing.close()
        await self.metrics.close()
        logger.info("Observability manager closed")


# Decorators for easy observability
def traced(operation_name: str = None, attributes: Dict[str, Any] = None):
    """Decorator to add tracing to functions"""
    def decorator(func):
        nonlocal operation_name
        if operation_name is None:
            operation_name = f"{func.__module__}.{func.__name__}"
        
        if asyncio.iscoroutinefunction(func):
            async def async_wrapper(*args, **kwargs):
                if not hasattr(func, '_observability_manager'):
                    return await func(*args, **kwargs)
                
                obs_manager = func._observability_manager
                async with obs_manager.trace_operation(operation_name, attributes):
                    return await func(*args, **kwargs)
            
            return async_wrapper
        else:
            def sync_wrapper(*args, **kwargs):
                # For sync functions, we'd need a different approach
                # This is a simplified version
                return func(*args, **kwargs)
            
            return sync_wrapper
    
    return decorator


def monitored(metric_name: str, metric_type: MetricType = MetricType.COUNTER, labels: Dict[str, str] = None):
    """Decorator to add metrics to functions"""
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            async def async_wrapper(*args, **kwargs):
                if not hasattr(func, '_observability_manager'):
                    return await func(*args, **kwargs)
                
                obs_manager = func._observability_manager
                start_time = time.time()
                
                try:
                    result = await func(*args, **kwargs)
                    
                    # Record success metrics
                    if metric_type == MetricType.COUNTER:
                        obs_manager.metrics.increment_counter(metric_name, labels=labels)
                    elif metric_type == MetricType.HISTOGRAM:
                        duration = time.time() - start_time
                        obs_manager.metrics.observe_histogram(metric_name, duration, labels=labels)
                    
                    return result
                    
                except Exception as e:
                    # Record error metrics
                    error_labels = {**(labels or {}), 'status': 'error'}
                    obs_manager.metrics.increment_counter(metric_name, labels=error_labels)
                    raise
            
            return async_wrapper
        else:
            # Sync version would be similar
            return func
    
    return decorator


# Global observability manager
observability_manager: Optional[ObservabilityManager] = None


async def get_observability_manager() -> ObservabilityManager:
    """Get global observability manager"""
    global observability_manager
    if observability_manager is None:
        observability_manager = ObservabilityManager()
        await observability_manager.initialize()
    return observability_manager


@asynccontextmanager
async def observability_context(config: Optional[ObservabilityConfig] = None):
    """Context manager for observability"""
    manager = ObservabilityManager(config)
    await manager.initialize()
    try:
        yield manager
    finally:
        await manager.close()


if __name__ == "__main__":
    # Example usage
    async def main():
        config = ObservabilityConfig(
            service_name="nexus-example",
            tracing_enabled=True,
            tracing_backend=ObservabilityBackend.CONSOLE,
            metrics_enabled=True,
            metrics_backend=ObservabilityBackend.PROMETHEUS
        )
        
        async with observability_context(config) as obs:
            # Example traced operation
            async with obs.trace_operation("example_operation", {"user_id": "123"}):
                await asyncio.sleep(0.1)
                logger.info("Operation completed")
            
            # Example metrics
            obs.metrics.increment_counter(
                'http_requests_total',
                labels={'method': 'GET', 'endpoint': '/health', 'status': '200'}
            )
            
            obs.metrics.observe_histogram(
                'http_request_duration',
                0.1,
                labels={'method': 'GET', 'endpoint': '/health'}
            )
            
            # Get health metrics
            health = obs.get_health_metrics()
            logger.info("Observability health", **health)
    
    asyncio.run(main())