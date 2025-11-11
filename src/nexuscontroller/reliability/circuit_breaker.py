#!/usr/bin/env python3
"""
Advanced Circuit Breaker Implementation for NexusController v2.0
Implements circuit breaker pattern with bulkheads, timeouts, and observability
"""

import asyncio
import time
from abc import ABC, abstractmethod
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
import structlog
from pydantic import BaseModel, Field, ConfigDict

# Prometheus metrics
try:
    import prometheus_client
    circuit_breaker_state = prometheus_client.Gauge('nexus_circuit_breaker_state', 'Circuit breaker state (0=closed, 1=open, 2=half_open)', ['name'])
    circuit_breaker_requests = prometheus_client.Counter('nexus_circuit_breaker_requests_total', 'Total circuit breaker requests', ['name', 'state'])
    circuit_breaker_failures = prometheus_client.Counter('nexus_circuit_breaker_failures_total', 'Circuit breaker failures', ['name'])
    circuit_breaker_successes = prometheus_client.Counter('nexus_circuit_breaker_successes_total', 'Circuit breaker successes', ['name'])
    circuit_breaker_timeouts = prometheus_client.Counter('nexus_circuit_breaker_timeouts_total', 'Circuit breaker timeouts', ['name'])
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = structlog.get_logger(__name__)

T = TypeVar('T')


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class FailureType(Enum):
    """Types of failures"""
    TIMEOUT = "timeout"
    EXCEPTION = "exception"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    CUSTOM = "custom"


@dataclass
class FailureRecord:
    """Record of a failure"""
    timestamp: float
    failure_type: FailureType
    error_type: str
    message: str
    duration: Optional[float] = None


class CircuitBreakerConfig(BaseModel):
    """Circuit breaker configuration"""
    model_config = ConfigDict(validate_assignment=True)
    
    name: str = Field(..., min_length=1)
    failure_threshold: int = Field(default=5, gt=0, le=100)
    success_threshold: int = Field(default=3, gt=0, le=20)
    timeout: float = Field(default=30.0, gt=0, le=300)
    recovery_timeout: float = Field(default=60.0, gt=0, le=3600)
    expected_exceptions: List[str] = Field(default_factory=list)
    ignored_exceptions: List[str] = Field(default_factory=list)
    failure_rate_threshold: float = Field(default=0.5, gt=0, le=1.0)
    minimum_requests: int = Field(default=10, gt=0)
    sliding_window_size: int = Field(default=100, gt=0, le=1000)
    slow_call_threshold: float = Field(default=10.0, gt=0)
    slow_call_rate_threshold: float = Field(default=0.5, gt=0, le=1.0)
    enable_metrics: bool = True


class CircuitBreakerError(Exception):
    """Circuit breaker specific exceptions"""
    pass


class CircuitBreakerOpenError(CircuitBreakerError):
    """Raised when circuit breaker is open"""
    pass


class CircuitBreakerTimeoutError(CircuitBreakerError):
    """Raised when operation times out"""
    pass


class SlidingWindow:
    """Sliding window for tracking request metrics"""
    
    def __init__(self, size: int):
        self.size = size
        self.requests: deque = deque(maxlen=size)
        self._lock = asyncio.Lock()
    
    async def add_request(self, success: bool, duration: float, error_type: Optional[str] = None):
        """Add a request to the sliding window"""
        async with self._lock:
            self.requests.append({
                'success': success,
                'duration': duration,
                'timestamp': time.time(),
                'error_type': error_type
            })
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get current window metrics"""
        async with self._lock:
            if not self.requests:
                return {
                    'total_requests': 0,
                    'failure_rate': 0.0,
                    'success_rate': 1.0,
                    'avg_duration': 0.0,
                    'slow_call_rate': 0.0
                }
            
            total_requests = len(self.requests)
            failures = sum(1 for r in self.requests if not r['success'])
            successes = total_requests - failures
            
            total_duration = sum(r['duration'] for r in self.requests)
            avg_duration = total_duration / total_requests if total_requests > 0 else 0.0
            
            return {
                'total_requests': total_requests,
                'failure_rate': failures / total_requests,
                'success_rate': successes / total_requests,
                'avg_duration': avg_duration,
                'slow_call_rate': 0.0  # Would need slow call threshold to calculate
            }
    
    async def clear(self):
        """Clear the sliding window"""
        async with self._lock:
            self.requests.clear()


class CircuitBreaker:
    """Advanced circuit breaker implementation"""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.last_success_time: Optional[float] = None
        self.next_attempt_time: Optional[float] = None
        
        # Sliding window for advanced metrics
        self.sliding_window = SlidingWindow(config.sliding_window_size)
        
        # Failure tracking
        self.recent_failures: deque = deque(maxlen=100)
        
        # Locks for thread safety
        self._state_lock = asyncio.Lock()
        self._metrics_lock = asyncio.Lock()
        
        # Metrics
        self.total_requests = 0
        self.total_failures = 0
        self.total_successes = 0
        self.total_timeouts = 0
        
        logger.info("Circuit breaker initialized", name=config.name, config=config.model_dump())
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit breaker is closed"""
        return self.state == CircuitBreakerState.CLOSED
    
    @property
    def is_open(self) -> bool:
        """Check if circuit breaker is open"""
        return self.state == CircuitBreakerState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        """Check if circuit breaker is half-open"""
        return self.state == CircuitBreakerState.HALF_OPEN
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with circuit breaker protection"""
        async with self._state_lock:
            self.total_requests += 1
            
            # Update metrics
            if METRICS_AVAILABLE and self.config.enable_metrics:
                circuit_breaker_requests.labels(
                    name=self.config.name,
                    state=self.state.value
                ).inc()
            
            # Check if circuit breaker should allow the call
            if not await self._should_allow_request():
                if METRICS_AVAILABLE and self.config.enable_metrics:
                    circuit_breaker_failures.labels(name=self.config.name).inc()
                
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.config.name}' is open. "
                    f"Next attempt allowed at {datetime.fromtimestamp(self.next_attempt_time or 0)}"
                )
        
        # Execute the function with timeout
        start_time = time.time()
        success = False
        error_type = None
        
        try:
            # Apply timeout
            result = await asyncio.wait_for(
                self._execute_async(func, *args, **kwargs),
                timeout=self.config.timeout
            )
            
            success = True
            await self._on_success(time.time() - start_time)
            return result
            
        except asyncio.TimeoutError:
            error_type = "TimeoutError"
            self.total_timeouts += 1
            
            if METRICS_AVAILABLE and self.config.enable_metrics:
                circuit_breaker_timeouts.labels(name=self.config.name).inc()
            
            await self._on_failure(
                FailureRecord(
                    timestamp=time.time(),
                    failure_type=FailureType.TIMEOUT,
                    error_type=error_type,
                    message="Operation timed out",
                    duration=time.time() - start_time
                )
            )
            
            raise CircuitBreakerTimeoutError(
                f"Operation timed out after {self.config.timeout} seconds"
            )
            
        except Exception as e:
            error_type = type(e).__name__
            
            # Check if exception should be ignored
            if error_type in self.config.ignored_exceptions:
                success = True
                await self._on_success(time.time() - start_time)
                raise
            
            # Check if it's an expected exception
            if (self.config.expected_exceptions and 
                error_type not in self.config.expected_exceptions):
                # Unexpected exception - treat as success for circuit breaker purposes
                success = True
                await self._on_success(time.time() - start_time)
                raise
            
            await self._on_failure(
                FailureRecord(
                    timestamp=time.time(),
                    failure_type=FailureType.EXCEPTION,
                    error_type=error_type,
                    message=str(e),
                    duration=time.time() - start_time
                )
            )
            
            raise
    
    async def _execute_async(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function, handling both sync and async functions"""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, *args, **kwargs)
    
    async def _should_allow_request(self) -> bool:
        """Determine if request should be allowed"""
        current_time = time.time()
        
        if self.state == CircuitBreakerState.CLOSED:
            return True
        
        elif self.state == CircuitBreakerState.OPEN:
            # Check if recovery timeout has passed
            if (self.next_attempt_time and 
                current_time >= self.next_attempt_time):
                await self._transition_to_half_open()
                return True
            return False
        
        elif self.state == CircuitBreakerState.HALF_OPEN:
            # Allow limited requests in half-open state
            return self.success_count < self.config.success_threshold
        
        return False
    
    async def _on_success(self, duration: float):
        """Handle successful execution"""
        async with self._state_lock:
            self.total_successes += 1
            self.last_success_time = time.time()
            
            # Add to sliding window
            await self.sliding_window.add_request(True, duration)
            
            if METRICS_AVAILABLE and self.config.enable_metrics:
                circuit_breaker_successes.labels(name=self.config.name).inc()
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.success_count += 1
                
                if self.success_count >= self.config.success_threshold:
                    await self._transition_to_closed()
            
            elif self.state == CircuitBreakerState.CLOSED:
                # Reset failure count on success
                self.failure_count = 0
    
    async def _on_failure(self, failure_record: FailureRecord):
        """Handle failed execution"""
        async with self._state_lock:
            self.total_failures += 1
            self.failure_count += 1
            self.last_failure_time = failure_record.timestamp
            self.recent_failures.append(failure_record)
            
            # Add to sliding window
            await self.sliding_window.add_request(
                False, 
                failure_record.duration or 0.0,
                failure_record.error_type
            )
            
            if METRICS_AVAILABLE and self.config.enable_metrics:
                circuit_breaker_failures.labels(name=self.config.name).inc()
            
            logger.warning(
                "Circuit breaker failure recorded",
                name=self.config.name,
                failure_type=failure_record.failure_type.value,
                error_type=failure_record.error_type,
                state=self.state.value
            )
            
            # Check if we should transition to open state
            if await self._should_open():
                await self._transition_to_open()
    
    async def _should_open(self) -> bool:
        """Determine if circuit breaker should open"""
        if self.state == CircuitBreakerState.OPEN:
            return False
        
        # Simple failure count threshold
        if self.failure_count >= self.config.failure_threshold:
            return True
        
        # Advanced failure rate check using sliding window
        metrics = await self.sliding_window.get_metrics()
        
        if (metrics['total_requests'] >= self.config.minimum_requests and
            metrics['failure_rate'] >= self.config.failure_rate_threshold):
            return True
        
        return False
    
    async def _transition_to_open(self):
        """Transition to open state"""
        self.state = CircuitBreakerState.OPEN
        self.next_attempt_time = time.time() + self.config.recovery_timeout
        self.success_count = 0
        
        if METRICS_AVAILABLE and self.config.enable_metrics:
            circuit_breaker_state.labels(name=self.config.name).set(1)
        
        logger.warning(
            "Circuit breaker opened",
            name=self.config.name,
            failure_count=self.failure_count,
            next_attempt_time=datetime.fromtimestamp(self.next_attempt_time)
        )
    
    async def _transition_to_half_open(self):
        """Transition to half-open state"""
        self.state = CircuitBreakerState.HALF_OPEN
        self.success_count = 0
        
        if METRICS_AVAILABLE and self.config.enable_metrics:
            circuit_breaker_state.labels(name=self.config.name).set(2)
        
        logger.info("Circuit breaker transitioned to half-open", name=self.config.name)
    
    async def _transition_to_closed(self):
        """Transition to closed state"""
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.next_attempt_time = None
        
        if METRICS_AVAILABLE and self.config.enable_metrics:
            circuit_breaker_state.labels(name=self.config.name).set(0)
        
        logger.info("Circuit breaker transitioned to closed", name=self.config.name)
    
    async def force_open(self):
        """Force circuit breaker to open state"""
        async with self._state_lock:
            await self._transition_to_open()
            logger.warning("Circuit breaker forced open", name=self.config.name)
    
    async def force_close(self):
        """Force circuit breaker to closed state"""
        async with self._state_lock:
            await self._transition_to_closed()
            await self.sliding_window.clear()
            self.recent_failures.clear()
            logger.info("Circuit breaker forced closed", name=self.config.name)
    
    async def force_half_open(self):
        """Force circuit breaker to half-open state"""
        async with self._state_lock:
            await self._transition_to_half_open()
            logger.info("Circuit breaker forced half-open", name=self.config.name)
    
    async def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state"""
        metrics = await self.sliding_window.get_metrics()
        
        return {
            'name': self.config.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'total_requests': self.total_requests,
            'total_failures': self.total_failures,
            'total_successes': self.total_successes,
            'total_timeouts': self.total_timeouts,
            'last_failure_time': datetime.fromtimestamp(self.last_failure_time) if self.last_failure_time else None,
            'last_success_time': datetime.fromtimestamp(self.last_success_time) if self.last_success_time else None,
            'next_attempt_time': datetime.fromtimestamp(self.next_attempt_time) if self.next_attempt_time else None,
            'sliding_window_metrics': metrics,
            'recent_failures': [
                {
                    'timestamp': datetime.fromtimestamp(f.timestamp),
                    'type': f.failure_type.value,
                    'error_type': f.error_type,
                    'message': f.message,
                    'duration': f.duration
                }
                for f in list(self.recent_failures)[-10:]  # Last 10 failures
            ]
        }


class Bulkhead:
    """Bulkhead pattern for resource isolation"""
    
    def __init__(self, name: str, max_concurrent: int, queue_size: int = 0):
        self.name = name
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.queue_size = queue_size
        self.active_requests = 0
        self.total_requests = 0
        self.rejected_requests = 0
        self._lock = asyncio.Lock()
        
        logger.info("Bulkhead initialized", name=name, max_concurrent=max_concurrent)
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire bulkhead resource"""
        async with self._lock:
            self.total_requests += 1
            
            # Check if we should reject the request
            if self.queue_size > 0 and self.active_requests >= self.queue_size:
                self.rejected_requests += 1
                raise Exception(f"Bulkhead '{self.name}' queue full")
        
        # Acquire semaphore
        async with self.semaphore:
            async with self._lock:
                self.active_requests += 1
            
            try:
                yield
            finally:
                async with self._lock:
                    self.active_requests -= 1
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get bulkhead statistics"""
        return {
            'name': self.name,
            'active_requests': self.active_requests,
            'total_requests': self.total_requests,
            'rejected_requests': self.rejected_requests,
            'available_permits': self.semaphore._value
        }


class CircuitBreakerManager:
    """Manager for multiple circuit breakers"""
    
    def __init__(self):
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._bulkheads: Dict[str, Bulkhead] = {}
        self._lock = asyncio.Lock()
    
    async def create_circuit_breaker(self, config: CircuitBreakerConfig) -> CircuitBreaker:
        """Create a new circuit breaker"""
        async with self._lock:
            if config.name in self._circuit_breakers:
                logger.warning("Circuit breaker already exists", name=config.name)
                return self._circuit_breakers[config.name]
            
            cb = CircuitBreaker(config)
            self._circuit_breakers[config.name] = cb
            
            logger.info("Circuit breaker created", name=config.name)
            return cb
    
    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        return self._circuit_breakers.get(name)
    
    async def create_bulkhead(self, name: str, max_concurrent: int, queue_size: int = 0) -> Bulkhead:
        """Create a new bulkhead"""
        async with self._lock:
            if name in self._bulkheads:
                logger.warning("Bulkhead already exists", name=name)
                return self._bulkheads[name]
            
            bulkhead = Bulkhead(name, max_concurrent, queue_size)
            self._bulkheads[name] = bulkhead
            
            logger.info("Bulkhead created", name=name)
            return bulkhead
    
    def get_bulkhead(self, name: str) -> Optional[Bulkhead]:
        """Get bulkhead by name"""
        return self._bulkheads.get(name)
    
    async def get_all_states(self) -> Dict[str, Any]:
        """Get state of all circuit breakers and bulkheads"""
        circuit_breaker_states = {}
        for name, cb in self._circuit_breakers.items():
            circuit_breaker_states[name] = await cb.get_state()
        
        bulkhead_states = {}
        for name, bulkhead in self._bulkheads.items():
            bulkhead_states[name] = await bulkhead.get_stats()
        
        return {
            'circuit_breakers': circuit_breaker_states,
            'bulkheads': bulkhead_states
        }
    
    async def force_open_all(self):
        """Force all circuit breakers to open state"""
        for cb in self._circuit_breakers.values():
            await cb.force_open()
    
    async def force_close_all(self):
        """Force all circuit breakers to closed state"""
        for cb in self._circuit_breakers.values():
            await cb.force_close()


# Decorators for easy usage
def circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    timeout: float = 30.0,
    recovery_timeout: float = 60.0,
    **kwargs
):
    """Decorator to apply circuit breaker to a function"""
    def decorator(func):
        config = CircuitBreakerConfig(
            name=name,
            failure_threshold=failure_threshold,
            timeout=timeout,
            recovery_timeout=recovery_timeout,
            **kwargs
        )
        
        cb = CircuitBreaker(config)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await cb.call(func, *args, **kwargs)
        
        wrapper._circuit_breaker = cb
        return wrapper
    
    return decorator


def bulkhead(name: str, max_concurrent: int, queue_size: int = 0):
    """Decorator to apply bulkhead to a function"""
    def decorator(func):
        bh = Bulkhead(name, max_concurrent, queue_size)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            async with bh.acquire():
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    loop = asyncio.get_event_loop()
                    return await loop.run_in_executor(None, func, *args, **kwargs)
        
        wrapper._bulkhead = bh
        return wrapper
    
    return decorator


# Global manager instance
circuit_breaker_manager = CircuitBreakerManager()


# Example usage functions
@circuit_breaker(
    name="database_operations",
    failure_threshold=3,
    timeout=10.0,
    recovery_timeout=30.0
)
async def example_database_operation():
    """Example database operation with circuit breaker"""
    # Simulate database operation
    await asyncio.sleep(0.1)
    return "database_result"


@bulkhead(name="api_calls", max_concurrent=5)
async def example_api_call():
    """Example API call with bulkhead"""
    # Simulate API call
    await asyncio.sleep(0.5)
    return "api_result"


if __name__ == "__main__":
    # Example usage
    async def main():
        # Test circuit breaker
        try:
            result = await example_database_operation()
            logger.info("Database operation result", result=result)
        except CircuitBreakerOpenError as e:
            logger.error("Circuit breaker open", error=str(e))
        
        # Test bulkhead
        tasks = []
        for i in range(10):
            task = asyncio.create_task(example_api_call())
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("API call results", count=len([r for r in results if not isinstance(r, Exception)]))
        
        # Get states
        states = await circuit_breaker_manager.get_all_states()
        logger.info("Circuit breaker and bulkhead states", **states)
    
    asyncio.run(main())