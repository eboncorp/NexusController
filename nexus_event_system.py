#!/usr/bin/env python3
"""
NexusController v2.0 Event-Driven Architecture
Advanced event bus and reactive automation system
"""

import os
import sys
import json
import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from abc import ABC, abstractmethod
import uuid
import weakref
from collections import defaultdict, deque

class EventType(Enum):
    """Event types for infrastructure management"""
    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    
    # Network events
    NETWORK_SCAN_STARTED = "network.scan.started"
    NETWORK_SCAN_COMPLETED = "network.scan.completed"
    DEVICE_DISCOVERED = "network.device.discovered"
    DEVICE_LOST = "network.device.lost"
    DEVICE_STATE_CHANGED = "network.device.state_changed"
    
    # SSH events
    SSH_CONNECTION_ESTABLISHED = "ssh.connection.established"
    SSH_CONNECTION_FAILED = "ssh.connection.failed"
    SSH_CONNECTION_CLOSED = "ssh.connection.closed"
    SSH_COMMAND_EXECUTED = "ssh.command.executed"
    
    # Security events
    SECURITY_ALERT = "security.alert"
    AUTHENTICATION_SUCCESS = "security.auth.success"
    AUTHENTICATION_FAILURE = "security.auth.failure"
    UNAUTHORIZED_ACCESS = "security.unauthorized"
    
    # Infrastructure events
    INFRA_STATE_DRIFT = "infra.state.drift"
    INFRA_REMEDIATION_STARTED = "infra.remediation.started"
    INFRA_REMEDIATION_COMPLETED = "infra.remediation.completed"
    
    # Cloud events
    CLOUD_SYNC_STARTED = "cloud.sync.started"
    CLOUD_SYNC_COMPLETED = "cloud.sync.completed"
    CLOUD_BACKUP_CREATED = "cloud.backup.created"
    
    # Custom events
    CUSTOM_EVENT = "custom.event"

@dataclass
class Event:
    """Infrastructure event data structure"""
    
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType = EventType.CUSTOM_EVENT
    source: str = "nexus.controller"
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    severity: str = "info"  # debug, info, warning, error, critical
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        result = asdict(self)
        result['event_type'] = self.event_type.value
        result['timestamp'] = self.timestamp.isoformat()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """Create event from dictionary"""
        data = data.copy()
        data['event_type'] = EventType(data['event_type'])
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)

class EventHandler(ABC):
    """Abstract base class for event handlers"""
    
    @abstractmethod
    async def handle(self, event: Event) -> None:
        """Handle an event"""
        pass
    
    @abstractmethod
    def can_handle(self, event: Event) -> bool:
        """Check if this handler can process the event"""
        pass

class EventBus:
    """Central event bus for publish/subscribe messaging"""
    
    def __init__(self, backend: str = "memory"):
        self.backend = backend
        self.subscribers = defaultdict(list)
        self._running = False
        self._tasks = []
        self._lock = threading.RLock()
        
        # Metrics
        self.metrics = {
            'events_published': 0,
            'events_processed': 0,
            'handlers_executed': 0,
            'errors': 0
        }
        
        logging.info(f"EventBus initialized with backend: {backend}")
    
    def subscribe(self, event_types: Union[EventType, List[EventType]], 
                 handler: EventHandler):
        """Subscribe handler to specific event types"""
        if isinstance(event_types, EventType):
            event_types = [event_types]
        
        with self._lock:
            for event_type in event_types:
                self.subscribers[event_type].append(handler)
        
        logging.info(f"Handler subscribed to {len(event_types)} event types")
    
    async def publish(self, event: Event):
        """Publish an event to all subscribers"""
        try:
            # Update metrics
            self.metrics['events_published'] += 1
            
            # Find and notify subscribers
            subscribers = self.subscribers.get(event.event_type, [])
            
            for handler in subscribers:
                try:
                    # Check if handler can process event
                    if not handler.can_handle(event):
                        continue
                    
                    # Execute handler asynchronously
                    await handler.handle(event)
                    self.metrics['handlers_executed'] += 1
                    
                except Exception as e:
                    logging.error(f"Error processing event {event.event_id}: {e}")
                    self.metrics['errors'] += 1
            
            self.metrics['events_processed'] += 1
            logging.debug(f"Event published: {event.event_type.value}")
            
        except Exception as e:
            logging.error(f"Error publishing event: {e}")
            self.metrics['errors'] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get event bus metrics"""
        return self.metrics.copy()
    
    async def start(self):
        """Start the event bus"""
        self._running = True
        logging.info("EventBus started")
    
    async def stop(self):
        """Stop the event bus"""
        self._running = False
        logging.info("EventBus stopped")

class LoggingEventHandler(EventHandler):
    """Handler that logs all events"""
    
    def __init__(self, log_level: str = "INFO"):
        self.logger = logging.getLogger("nexus.events")
        self.log_level = getattr(logging, log_level.upper())
    
    async def handle(self, event: Event):
        """Log the event"""
        message = f"Event: {event.event_type.value} from {event.source}"
        if event.data:
            message += f" - {json.dumps(event.data, default=str)}"
        
        severity_level = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL
        }.get(event.severity, logging.INFO)
        
        self.logger.log(severity_level, message)
    
    def can_handle(self, event: Event) -> bool:
        """Can handle all events"""
        return True

class EventBusFactory:
    """Factory for creating event bus instances"""
    
    @staticmethod
    def create_event_bus(backend: str = "memory", **kwargs) -> EventBus:
        """Create event bus with specified backend"""
        return EventBus(backend="memory")

class NexusEventIntegration:
    """Integration helper for NexusController components"""
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        
        # Setup default handlers
        self._setup_default_handlers()
    
    def _setup_default_handlers(self):
        """Setup default event handlers"""
        
        # Logging handler
        logging_handler = LoggingEventHandler()
        self.event_bus.subscribe(
            [event_type for event_type in EventType],
            logging_handler
        )
    
    async def emit_network_scan_started(self, network_range: str, scan_id: str):
        """Emit network scan started event"""
        event = Event(
            event_type=EventType.NETWORK_SCAN_STARTED,
            source="nexus.network_discovery",
            data={
                'network_range': network_range,
                'scan_id': scan_id
            }
        )
        await self.event_bus.publish(event)
    
    async def emit_device_discovered(self, device_info: Dict[str, Any]):
        """Emit device discovered event"""
        event = Event(
            event_type=EventType.DEVICE_DISCOVERED,
            source="nexus.network_discovery",
            data=device_info
        )
        await self.event_bus.publish(event)
    
    async def emit_ssh_connection_established(self, connection_info: Dict[str, Any]):
        """Emit SSH connection established event"""
        event = Event(
            event_type=EventType.SSH_CONNECTION_ESTABLISHED,
            source="nexus.ssh_manager",
            data=connection_info
        )
        await self.event_bus.publish(event)
    
    async def emit_security_alert(self, alert_type: str, details: Dict[str, Any]):
        """Emit security alert event"""
        event = Event(
            event_type=EventType.SECURITY_ALERT,
            source="nexus.security",
            data={
                'alert_type': alert_type,
                'details': details
            },
            severity="warning"
        )
        await self.event_bus.publish(event)