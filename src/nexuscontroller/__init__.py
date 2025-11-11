"""
NexusController v2.0 - Enterprise Infrastructure Management Platform

A comprehensive platform for managing multi-cloud infrastructure with
advanced monitoring, security, and automation capabilities.
"""

__version__ = "2.0.0"
__author__ = "EbonCorp"
__license__ = "MIT"

# Core exports
from nexuscontroller.core.controller import NexusController
from nexuscontroller.core.event_system import EventBus, EventModel, EventType
from nexuscontroller.core.state_manager import StateManager

# API exports
from nexuscontroller.api.server import create_app

# Security exports
from nexuscontroller.security.auth import SecurityService, APIKeyService

# Infrastructure exports
from nexuscontroller.infrastructure.provider import ProviderManager
from nexuscontroller.infrastructure.monitoring import MonitoringSystem
from nexuscontroller.infrastructure.observability import ObservabilityManager

# Data exports
from nexuscontroller.data.database import DatabaseManager

# Plugin exports
from nexuscontroller.plugins.plugin_system import PluginManager

# Reliability exports
from nexuscontroller.reliability.circuit_breaker import CircuitBreakerManager
from nexuscontroller.reliability.disaster_recovery import DisasterRecoveryManager
from nexuscontroller.reliability.remediation import RemediationSystem

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    # Core
    "NexusController",
    "EventBus",
    "EventModel",
    "EventType",
    "StateManager",
    # API
    "create_app",
    # Security
    "SecurityService",
    "APIKeyService",
    # Infrastructure
    "ProviderManager",
    "MonitoringSystem",
    "ObservabilityManager",
    # Data
    "DatabaseManager",
    # Plugins
    "PluginManager",
    # Reliability
    "CircuitBreakerManager",
    "DisasterRecoveryManager",
    "RemediationSystem",
]
