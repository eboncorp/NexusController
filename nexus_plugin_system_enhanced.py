#!/usr/bin/env python3
"""
Enhanced NexusController v2.0 Plugin System
Advanced plugin architecture with Protocol types, dependency injection, and hot-reloading
"""

import asyncio
import importlib
import importlib.util
import inspect
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Set, Type, Union, runtime_checkable
import structlog
from pydantic import BaseModel, Field, ConfigDict
import weakref

# Entry points for plugin discovery
try:
    from importlib.metadata import entry_points
    ENTRY_POINTS_AVAILABLE = True
except ImportError:
    try:
        from importlib_metadata import entry_points
        ENTRY_POINTS_AVAILABLE = True
    except ImportError:
        ENTRY_POINTS_AVAILABLE = False

logger = structlog.get_logger(__name__)


class PluginType(Enum):
    """Types of plugins supported"""
    INFRASTRUCTURE = "infrastructure"
    CLOUD_PROVIDER = "cloud_provider"
    MONITORING = "monitoring"
    BACKUP = "backup"
    AUTHENTICATION = "authentication"
    NOTIFICATION = "notification"
    VALIDATION = "validation"
    TRANSFORM = "transform"
    WEBHOOK = "webhook"
    CUSTOM = "custom"


class PluginStatus(Enum):
    """Plugin lifecycle status"""
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNLOADING = "unloading"
    ERROR = "error"
    DISABLED = "disabled"


class PluginLifecycleEvent(Enum):
    """Plugin lifecycle events"""
    DISCOVERED = "plugin.discovered"
    LOADED = "plugin.loaded"
    INITIALIZED = "plugin.initialized"
    ACTIVATED = "plugin.activated"
    DEACTIVATED = "plugin.deactivated"
    UNLOADED = "plugin.unloaded"
    ERROR = "plugin.error"


class PluginMetadata(BaseModel):
    """Plugin metadata with validation"""
    model_config = ConfigDict(validate_assignment=True)
    
    plugin_id: str = Field(..., min_length=1, max_length=100, pattern=r'^[a-zA-Z0-9_.-]+$')
    name: str = Field(..., min_length=1, max_length=200)
    version: str = Field(..., pattern=r'^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$')
    plugin_type: PluginType
    description: str = Field(default="", max_length=1000)
    author: str = Field(default="", max_length=200)
    homepage: Optional[str] = Field(default=None, max_length=500)
    license: str = Field(default="", max_length=100)
    python_requires: str = Field(default=">=3.10", max_length=50)
    dependencies: List[str] = Field(default_factory=list)
    entry_point: str = Field(..., min_length=1)
    config_schema: Optional[Dict[str, Any]] = None
    permissions: List[str] = Field(default_factory=list)
    tags: Set[str] = Field(default_factory=set)
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=1000)


@runtime_checkable
class PluginProtocol(Protocol):
    """Protocol defining the plugin interface"""
    
    @property
    def metadata(self) -> PluginMetadata:
        """Plugin metadata"""
        ...
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize plugin with configuration"""
        ...
    
    async def activate(self) -> None:
        """Activate the plugin"""
        ...
    
    async def deactivate(self) -> None:
        """Deactivate the plugin"""
        ...
    
    async def cleanup(self) -> None:
        """Clean up plugin resources"""
        ...
    
    def is_healthy(self) -> bool:
        """Check if plugin is healthy"""
        ...


class BasePlugin(ABC):
    """Abstract base class for plugins"""
    
    def __init__(self):
        self._initialized = False
        self._active = False
        self._config: Dict[str, Any] = {}
        self._dependencies: Dict[str, Any] = {}
        self.logger = structlog.get_logger(f"nexus.plugin.{self.__class__.__name__}")
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Plugin metadata"""
        pass
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize plugin with configuration"""
        self._config = config.copy()
        self._initialized = True
        self.logger.info("Plugin initialized", plugin_id=self.metadata.plugin_id)
    
    async def activate(self) -> None:
        """Activate the plugin"""
        if not self._initialized:
            raise RuntimeError("Plugin must be initialized before activation")
        
        self._active = True
        self.logger.info("Plugin activated", plugin_id=self.metadata.plugin_id)
    
    async def deactivate(self) -> None:
        """Deactivate the plugin"""
        self._active = False
        self.logger.info("Plugin deactivated", plugin_id=self.metadata.plugin_id)
    
    async def cleanup(self) -> None:
        """Clean up plugin resources"""
        await self.deactivate()
        self._initialized = False
        self.logger.info("Plugin cleaned up", plugin_id=self.metadata.plugin_id)
    
    def is_healthy(self) -> bool:
        """Check if plugin is healthy"""
        return self._initialized and self._active
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self._config.get(key, default)
    
    def inject_dependency(self, name: str, dependency: Any) -> None:
        """Inject a dependency"""
        self._dependencies[name] = dependency
    
    def get_dependency(self, name: str) -> Any:
        """Get an injected dependency"""
        return self._dependencies.get(name)


# Plugin types for different infrastructure components
class InfrastructurePlugin(BasePlugin):
    """Base class for infrastructure plugins"""
    
    @abstractmethod
    async def provision_resource(self, resource_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Provision an infrastructure resource"""
        pass
    
    @abstractmethod
    async def destroy_resource(self, resource_id: str) -> bool:
        """Destroy an infrastructure resource"""
        pass
    
    @abstractmethod
    async def get_resource_status(self, resource_id: str) -> Dict[str, Any]:
        """Get resource status"""
        pass


class MonitoringPlugin(BasePlugin):
    """Base class for monitoring plugins"""
    
    @abstractmethod
    async def collect_metrics(self, resource_id: str) -> Dict[str, Any]:
        """Collect metrics for a resource"""
        pass
    
    @abstractmethod
    async def check_health(self, resource_id: str) -> bool:
        """Check resource health"""
        pass
    
    @abstractmethod
    async def create_alert(self, alert_spec: Dict[str, Any]) -> str:
        """Create monitoring alert"""
        pass


class NotificationPlugin(BasePlugin):
    """Base class for notification plugins"""
    
    @abstractmethod
    async def send_notification(self, message: str, recipients: List[str], **kwargs) -> bool:
        """Send notification"""
        pass


@dataclass
class PluginInstance:
    """Loaded plugin instance with runtime information"""
    plugin_id: str
    metadata: PluginMetadata
    plugin_class: Type[PluginProtocol]
    instance: Optional[PluginProtocol] = None
    status: PluginStatus = PluginStatus.DISCOVERED
    loaded_at: Optional[datetime] = None
    error_message: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    dependencies_resolved: bool = False
    
    def is_active(self) -> bool:
        """Check if plugin is active"""
        return self.status == PluginStatus.ACTIVE and self.instance is not None


class DependencyInjector:
    """Dependency injection container for plugins"""
    
    def __init__(self):
        self._services: Dict[str, Any] = {}
        self._factories: Dict[str, callable] = {}
        self._singletons: Dict[str, Any] = {}
    
    def register_service(self, name: str, service: Any) -> None:
        """Register a service instance"""
        self._services[name] = service
        logger.debug("Service registered", service_name=name)
    
    def register_factory(self, name: str, factory: callable) -> None:
        """Register a service factory"""
        self._factories[name] = factory
        logger.debug("Factory registered", factory_name=name)
    
    def register_singleton(self, name: str, factory: callable) -> None:
        """Register a singleton factory"""
        self._factories[name] = factory
        logger.debug("Singleton factory registered", singleton_name=name)
    
    def get_service(self, name: str) -> Any:
        """Get a service"""
        # Check direct services
        if name in self._services:
            return self._services[name]
        
        # Check singletons
        if name in self._singletons:
            return self._singletons[name]
        
        # Check factories
        if name in self._factories:
            service = self._factories[name]()
            
            # Cache as singleton if registered as such
            if name in self._factories:
                self._singletons[name] = service
            
            return service
        
        raise KeyError(f"Service '{name}' not found")
    
    def inject_dependencies(self, plugin: BasePlugin) -> None:
        """Inject dependencies into plugin"""
        # Get plugin dependencies from metadata
        dependencies = plugin.metadata.dependencies
        
        for dep_name in dependencies:
            try:
                service = self.get_service(dep_name)
                plugin.inject_dependency(dep_name, service)
                logger.debug("Dependency injected", plugin_id=plugin.metadata.plugin_id, dependency=dep_name)
            except KeyError:
                logger.warning("Dependency not found", plugin_id=plugin.metadata.plugin_id, dependency=dep_name)


class PluginRegistry:
    """Registry for plugin discovery and management"""
    
    def __init__(self):
        self._plugins: Dict[str, PluginInstance] = {}
        self._by_type: Dict[PluginType, List[str]] = {pt: [] for pt in PluginType}
        self._watchers: List[weakref.ReferenceType] = []
    
    def register_plugin(self, plugin_instance: PluginInstance) -> None:
        """Register a plugin instance"""
        plugin_id = plugin_instance.plugin_id
        
        if plugin_id in self._plugins:
            logger.warning("Plugin already registered, updating", plugin_id=plugin_id)
        
        self._plugins[plugin_id] = plugin_instance
        
        # Add to type index
        plugin_type = plugin_instance.metadata.plugin_type
        if plugin_id not in self._by_type[plugin_type]:
            self._by_type[plugin_type].append(plugin_id)
        
        logger.info("Plugin registered", plugin_id=plugin_id, plugin_type=plugin_type.value)
        self._notify_watchers('registered', plugin_instance)
    
    def unregister_plugin(self, plugin_id: str) -> bool:
        """Unregister a plugin"""
        if plugin_id not in self._plugins:
            return False
        
        plugin_instance = self._plugins[plugin_id]
        del self._plugins[plugin_id]
        
        # Remove from type index
        plugin_type = plugin_instance.metadata.plugin_type
        if plugin_id in self._by_type[plugin_type]:
            self._by_type[plugin_type].remove(plugin_id)
        
        logger.info("Plugin unregistered", plugin_id=plugin_id)
        self._notify_watchers('unregistered', plugin_instance)
        return True
    
    def get_plugin(self, plugin_id: str) -> Optional[PluginInstance]:
        """Get plugin by ID"""
        return self._plugins.get(plugin_id)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginInstance]:
        """Get all plugins of a specific type"""
        plugin_ids = self._by_type[plugin_type]
        return [self._plugins[pid] for pid in plugin_ids]
    
    def list_plugins(self) -> List[PluginInstance]:
        """List all registered plugins"""
        return list(self._plugins.values())
    
    def add_watcher(self, callback: callable) -> None:
        """Add a registry watcher"""
        self._watchers.append(weakref.ref(callback))
    
    def _notify_watchers(self, action: str, plugin_instance: PluginInstance) -> None:
        """Notify watchers of registry changes"""
        # Clean up dead references
        self._watchers = [w for w in self._watchers if w() is not None]
        
        for watcher_ref in self._watchers:
            watcher = watcher_ref()
            if watcher:
                try:
                    watcher(action, plugin_instance)
                except Exception as e:
                    logger.error("Watcher error", error=str(e))


class PluginLoader:
    """Plugin loading and hot-reloading functionality"""
    
    def __init__(self, search_paths: List[Path]):
        self.search_paths = [Path(p) for p in search_paths]
        self._loaded_modules: Dict[str, Any] = {}
    
    def discover_plugins(self) -> List[PluginMetadata]:
        """Discover plugins from search paths and entry points"""
        discovered = []
        
        # Discover from filesystem
        for search_path in self.search_paths:
            discovered.extend(self._discover_from_path(search_path))
        
        # Discover from entry points
        if ENTRY_POINTS_AVAILABLE:
            discovered.extend(self._discover_from_entry_points())
        
        logger.info("Plugin discovery completed", count=len(discovered))
        return discovered
    
    def _discover_from_path(self, path: Path) -> List[PluginMetadata]:
        """Discover plugins from filesystem path"""
        plugins = []
        
        if not path.exists():
            logger.debug("Plugin search path does not exist", path=str(path))
            return plugins
        
        # Look for plugin.py files
        for plugin_file in path.rglob("plugin.py"):
            try:
                metadata = self._extract_metadata_from_file(plugin_file)
                if metadata:
                    plugins.append(metadata)
            except Exception as e:
                logger.error("Error discovering plugin", file=str(plugin_file), error=str(e))
        
        return plugins
    
    def _discover_from_entry_points(self) -> List[PluginMetadata]:
        """Discover plugins from entry points"""
        plugins = []
        
        try:
            for ep in entry_points(group='nexus.plugins'):
                try:
                    plugin_class = ep.load()
                    if hasattr(plugin_class, 'metadata'):
                        if isinstance(plugin_class.metadata, PluginMetadata):
                            plugins.append(plugin_class.metadata)
                        else:
                            # Try to create metadata from class attributes
                            metadata = PluginMetadata(**plugin_class.metadata)
                            metadata.entry_point = f"{ep.module}:{ep.attr}"
                            plugins.append(metadata)
                except Exception as e:
                    logger.error("Error loading entry point", entry_point=ep.name, error=str(e))
        except Exception as e:
            logger.error("Error discovering entry points", error=str(e))
        
        return plugins
    
    def _extract_metadata_from_file(self, plugin_file: Path) -> Optional[PluginMetadata]:
        """Extract plugin metadata from Python file"""
        try:
            spec = importlib.util.spec_from_file_location("plugin_temp", plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Look for plugin class or metadata
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj != BasePlugin:
                        if hasattr(obj, 'metadata'):
                            metadata = obj.metadata
                            if isinstance(metadata, dict):
                                metadata = PluginMetadata(**metadata)
                            metadata.entry_point = f"{plugin_file}:{name}"
                            return metadata
                
        except Exception as e:
            logger.error("Error extracting metadata", file=str(plugin_file), error=str(e))
        
        return None
    
    async def load_plugin(self, metadata: PluginMetadata) -> Optional[PluginInstance]:
        """Load a plugin from metadata"""
        try:
            # Parse entry point
            if ':' in metadata.entry_point:
                module_path, class_name = metadata.entry_point.rsplit(':', 1)
            else:
                raise ValueError(f"Invalid entry point format: {metadata.entry_point}")
            
            # Load module
            if module_path.endswith('.py'):
                # File-based plugin
                spec = importlib.util.spec_from_file_location(metadata.plugin_id, module_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self._loaded_modules[metadata.plugin_id] = module
            else:
                # Module-based plugin
                module = importlib.import_module(module_path)
                self._loaded_modules[metadata.plugin_id] = module
            
            # Get plugin class
            plugin_class = getattr(module, class_name)
            
            # Validate plugin class
            if not issubclass(plugin_class, BasePlugin):
                raise TypeError(f"Plugin class must inherit from BasePlugin")
            
            # Create plugin instance
            plugin_instance = PluginInstance(
                plugin_id=metadata.plugin_id,
                metadata=metadata,
                plugin_class=plugin_class,
                status=PluginStatus.LOADED,
                loaded_at=datetime.utcnow()
            )
            
            logger.info("Plugin loaded successfully", plugin_id=metadata.plugin_id)
            return plugin_instance
            
        except Exception as e:
            logger.error("Failed to load plugin", plugin_id=metadata.plugin_id, error=str(e))
            return PluginInstance(
                plugin_id=metadata.plugin_id,
                metadata=metadata,
                plugin_class=None,
                status=PluginStatus.ERROR,
                error_message=str(e)
            )
    
    async def reload_plugin(self, plugin_id: str) -> bool:
        """Hot-reload a plugin"""
        try:
            if plugin_id in self._loaded_modules:
                module = self._loaded_modules[plugin_id]
                importlib.reload(module)
                logger.info("Plugin reloaded", plugin_id=plugin_id)
                return True
        except Exception as e:
            logger.error("Failed to reload plugin", plugin_id=plugin_id, error=str(e))
        
        return False


class EnhancedPluginManager:
    """Enhanced plugin manager with advanced features"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.plugin_paths = self.config.get('plugin_paths', ['./plugins'])
        self.auto_discovery = self.config.get('auto_discovery', True)
        self.hot_reload = self.config.get('hot_reload', False)
        
        self.registry = PluginRegistry()
        self.loader = PluginLoader(self.plugin_paths)
        self.injector = DependencyInjector()
        
        self._running = False
        self._discovery_task: Optional[asyncio.Task] = None
        self._event_bus = None
        
        logger.info("Enhanced plugin manager initialized", config=self.config)
    
    def set_event_bus(self, event_bus) -> None:
        """Set event bus for plugin communication"""
        self._event_bus = event_bus
        self.injector.register_service('event_bus', event_bus)
    
    async def start(self) -> None:
        """Start the plugin manager"""
        if self._running:
            return
        
        self._running = True
        
        # Register core services
        self.injector.register_service('plugin_manager', self)
        self.injector.register_service('plugin_registry', self.registry)
        
        # Discover and load plugins
        if self.auto_discovery:
            await self.discover_and_load_all()
        
        # Start hot-reload monitoring if enabled
        if self.hot_reload:
            self._discovery_task = asyncio.create_task(self._hot_reload_monitor())
        
        logger.info("Plugin manager started")
    
    async def stop(self) -> None:
        """Stop the plugin manager"""
        if not self._running:
            return
        
        self._running = False
        
        # Stop hot-reload monitoring
        if self._discovery_task:
            self._discovery_task.cancel()
            try:
                await self._discovery_task
            except asyncio.CancelledError:
                pass
        
        # Deactivate and cleanup all plugins
        for plugin_instance in self.registry.list_plugins():
            if plugin_instance.instance:
                try:
                    await plugin_instance.instance.cleanup()
                except Exception as e:
                    logger.error("Error cleaning up plugin", plugin_id=plugin_instance.plugin_id, error=str(e))
        
        logger.info("Plugin manager stopped")
    
    async def discover_and_load_all(self) -> None:
        """Discover and load all available plugins"""
        discovered_plugins = self.loader.discover_plugins()
        
        for metadata in discovered_plugins:
            if metadata.enabled:
                await self.load_plugin(metadata.plugin_id, metadata)
    
    async def load_plugin(self, plugin_id: str, metadata: Optional[PluginMetadata] = None) -> bool:
        """Load and initialize a plugin"""
        try:
            # Load plugin
            if metadata:
                plugin_instance = await self.loader.load_plugin(metadata)
            else:
                # Try to find plugin in registry
                existing = self.registry.get_plugin(plugin_id)
                if existing:
                    plugin_instance = existing
                else:
                    logger.error("Plugin not found", plugin_id=plugin_id)
                    return False
            
            if not plugin_instance or plugin_instance.status == PluginStatus.ERROR:
                return False
            
            # Register plugin
            self.registry.register_plugin(plugin_instance)
            
            # Create instance
            plugin_instance.instance = plugin_instance.plugin_class()
            plugin_instance.status = PluginStatus.INITIALIZING
            
            # Inject dependencies
            self.injector.inject_dependencies(plugin_instance.instance)
            plugin_instance.dependencies_resolved = True
            
            # Initialize plugin
            await plugin_instance.instance.initialize(plugin_instance.config)
            plugin_instance.status = PluginStatus.LOADED
            
            # Activate plugin
            await plugin_instance.instance.activate()
            plugin_instance.status = PluginStatus.ACTIVE
            
            # Emit event
            if self._event_bus:
                await self._emit_plugin_event(PluginLifecycleEvent.ACTIVATED, plugin_instance)
            
            logger.info("Plugin loaded and activated", plugin_id=plugin_id)
            return True
            
        except Exception as e:
            logger.error("Failed to load plugin", plugin_id=plugin_id, error=str(e))
            
            # Update plugin status
            if 'plugin_instance' in locals() and plugin_instance:
                plugin_instance.status = PluginStatus.ERROR
                plugin_instance.error_message = str(e)
            
            return False
    
    async def unload_plugin(self, plugin_id: str) -> bool:
        """Unload a plugin"""
        plugin_instance = self.registry.get_plugin(plugin_id)
        if not plugin_instance:
            return False
        
        try:
            plugin_instance.status = PluginStatus.UNLOADING
            
            if plugin_instance.instance:
                await plugin_instance.instance.cleanup()
            
            self.registry.unregister_plugin(plugin_id)
            
            # Emit event
            if self._event_bus:
                await self._emit_plugin_event(PluginLifecycleEvent.UNLOADED, plugin_instance)
            
            logger.info("Plugin unloaded", plugin_id=plugin_id)
            return True
            
        except Exception as e:
            logger.error("Failed to unload plugin", plugin_id=plugin_id, error=str(e))
            plugin_instance.status = PluginStatus.ERROR
            plugin_instance.error_message = str(e)
            return False
    
    async def reload_plugin(self, plugin_id: str) -> bool:
        """Hot-reload a plugin"""
        if not self.hot_reload:
            logger.warning("Hot-reload not enabled")
            return False
        
        # Unload first
        await self.unload_plugin(plugin_id)
        
        # Reload module
        success = await self.loader.reload_plugin(plugin_id)
        if not success:
            return False
        
        # Load again
        return await self.load_plugin(plugin_id)
    
    def get_plugin(self, plugin_id: str) -> Optional[PluginInstance]:
        """Get plugin instance"""
        return self.registry.get_plugin(plugin_id)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginInstance]:
        """Get plugins by type"""
        return self.registry.get_plugins_by_type(plugin_type)
    
    def list_active_plugins(self) -> List[PluginInstance]:
        """List all active plugins"""
        return [p for p in self.registry.list_plugins() if p.is_active()]
    
    async def _hot_reload_monitor(self) -> None:
        """Monitor for plugin changes and hot-reload"""
        while self._running:
            try:
                # Check for plugin file changes
                # This is a simplified version - in production you'd use file system watchers
                await asyncio.sleep(5)  # Check every 5 seconds
                
                # Re-discover plugins
                discovered = self.loader.discover_plugins()
                
                # Check for new or updated plugins
                for metadata in discovered:
                    existing = self.registry.get_plugin(metadata.plugin_id)
                    if existing and existing.metadata.version != metadata.version:
                        logger.info("Plugin version changed, reloading", plugin_id=metadata.plugin_id)
                        await self.reload_plugin(metadata.plugin_id)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Hot-reload monitor error", error=str(e))
    
    async def _emit_plugin_event(self, event_type: PluginLifecycleEvent, plugin_instance: PluginInstance) -> None:
        """Emit plugin lifecycle event"""
        if not self._event_bus:
            return
        
        try:
            from .nexus_event_system_enhanced import EventModel, EventType
            
            event = EventModel(
                event_type=EventType.CUSTOM,
                source="nexus.plugin_manager",
                data={
                    "lifecycle_event": event_type.value,
                    "plugin_id": plugin_instance.plugin_id,
                    "plugin_type": plugin_instance.metadata.plugin_type.value,
                    "plugin_version": plugin_instance.metadata.version,
                    "status": plugin_instance.status.value
                }
            )
            
            await self._event_bus.publish(event)
            
        except Exception as e:
            logger.error("Failed to emit plugin event", error=str(e))
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get plugin manager health status"""
        plugins = self.registry.list_plugins()
        active_plugins = [p for p in plugins if p.is_active()]
        error_plugins = [p for p in plugins if p.status == PluginStatus.ERROR]
        
        return {
            "running": self._running,
            "total_plugins": len(plugins),
            "active_plugins": len(active_plugins),
            "error_plugins": len(error_plugins),
            "plugin_status": {
                p.plugin_id: {
                    "status": p.status.value,
                    "healthy": p.instance.is_healthy() if p.instance else False,
                    "error": p.error_message
                }
                for p in plugins
            }
        }


# Example plugin implementations
class ExampleInfrastructurePlugin(InfrastructurePlugin):
    """Example infrastructure plugin"""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            plugin_id="example_infra",
            name="Example Infrastructure Plugin",
            version="1.0.0",
            plugin_type=PluginType.INFRASTRUCTURE,
            description="Example plugin for demonstration",
            entry_point="example:ExampleInfrastructurePlugin"
        )
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        await super().initialize(config)
        self.logger.info("Example infrastructure plugin initialized")
    
    async def provision_resource(self, resource_spec: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info("Provisioning resource", spec=resource_spec)
        return {"resource_id": "example-123", "status": "provisioned"}
    
    async def destroy_resource(self, resource_id: str) -> bool:
        self.logger.info("Destroying resource", resource_id=resource_id)
        return True
    
    async def get_resource_status(self, resource_id: str) -> Dict[str, Any]:
        return {"resource_id": resource_id, "status": "running"}


# Global plugin manager instance
plugin_manager: Optional[EnhancedPluginManager] = None


async def get_plugin_manager() -> EnhancedPluginManager:
    """Get global plugin manager instance"""
    global plugin_manager
    if plugin_manager is None:
        plugin_manager = EnhancedPluginManager()
        await plugin_manager.start()
    return plugin_manager


if __name__ == "__main__":
    # Example usage
    async def main():
        config = {
            'plugin_paths': ['./plugins'],
            'auto_discovery': True,
            'hot_reload': True
        }
        
        manager = EnhancedPluginManager(config)
        await manager.start()
        
        try:
            # List plugins
            plugins = manager.list_active_plugins()
            logger.info("Active plugins", count=len(plugins))
            
            # Get health status
            health = manager.get_health_status()
            logger.info("Plugin manager health", **health)
            
            # Wait a bit
            await asyncio.sleep(5)
            
        finally:
            await manager.stop()
    
    asyncio.run(main())