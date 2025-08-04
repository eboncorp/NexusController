#!/usr/bin/env python3
"""
NexusController v2.0 - Enterprise Infrastructure Management Platform
Main application entry point

Version: 2.0.0
Author: NexusController Development Team
License: MIT
"""

import os
import sys
import json
import asyncio
import logging
import signal
import argparse
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Version information
__version__ = "2.0.0"
__build__ = datetime.now().strftime("%Y%m%d")

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

try:
    # Import core systems
    from nexus_event_system import EventBusFactory, NexusEventIntegration
    from nexus_state_manager import StateManager, FileStateBackend
    from nexus_plugin_system import PluginManager
    from nexus_websocket_server import WebSocketServer
    from nexus_federation import FederationManager
    from nexus_provider_abstraction import MultiCloudManager
    from nexus_monitoring_system import MonitoringSystem
    from nexus_remediation_system import RemediationSystem
    from nexus_api_server import create_app
    
    CORE_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some core modules not available: {e}")
    CORE_MODULES_AVAILABLE = False

class NexusController:
    """Main NexusController application class"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or "config.yaml"
        self.config = self._load_config()
        self.running = False
        
        # Core components
        self.event_bus = None
        self.event_integration = None
        self.state_manager = None
        self.plugin_manager = None
        self.websocket_server = None
        self.federation_manager = None
        self.multicloud_manager = None
        self.monitoring_system = None
        self.remediation_system = None
        self.api_server = None
        
        # Setup logging
        self._setup_logging()
        
        # Register signal handlers
        self._setup_signal_handlers()
        
        logging.info(f"NexusController v{__version__} (build {__build__}) initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                import yaml
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                logging.info(f"Configuration loaded from {config_path}")
                return config
            except Exception as e:
                logging.error(f"Failed to load config from {config_path}: {e}")
        
        # Default configuration
        default_config = {
            'nexus': {
                'version': __version__,
                'node_id': 'nexus-001',
                'data_dir': './data',
                'log_level': 'INFO',
                'debug': False
            },
            'network': {
                'discovery_range': '10.0.0.0/24',
                'scan_interval': 300,
                'timeout': 10
            },
            'api': {
                'host': '0.0.0.0',
                'port': 8080,
                'enable_cors': True
            },
            'websocket': {
                'host': '0.0.0.0',
                'port': 8765,
                'auth_required': False
            },
            'federation': {
                'enabled': False,
                'port': 8081,
                'bootstrap_nodes': []
            },
            'monitoring': {
                'enabled': True,
                'collection_interval': 30,
                'retention_days': 30
            },
            'remediation': {
                'enabled': True,
                'auto_remediation': False
            },
            'plugins': {
                'enabled': True,
                'plugin_dir': './plugins'
            },
            'security': {
                'encryption_key_file': './keys/nexus.key',
                'ssh_key_file': '~/.ssh/id_rsa',
                'known_hosts_file': '~/.ssh/known_hosts'
            }
        }
        
        logging.info("Using default configuration")
        return default_config
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('nexus', {}).get('log_level', 'INFO')
        debug = self.config.get('nexus', {}).get('debug', False)
        
        if debug:
            log_level = 'DEBUG'
        
        # Create logs directory
        log_dir = Path('./logs')
        log_dir.mkdir(exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'nexus.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Set third-party loggers to WARNING to reduce noise
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('asyncio').setLevel(logging.WARNING)
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logging.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start(self):
        """Start all NexusController services"""
        if not CORE_MODULES_AVAILABLE:
            logging.error("Core modules not available. Please install dependencies.")
            return False
        
        logging.info("Starting NexusController services...")
        self.running = True
        
        try:
            # Initialize core systems in dependency order
            await self._initialize_event_system()
            await self._initialize_state_manager()
            await self._initialize_plugin_manager()
            await self._initialize_monitoring()
            await self._initialize_remediation()
            await self._initialize_multicloud()
            await self._initialize_websocket()
            await self._initialize_federation()
            await self._initialize_api_server()
            
            logging.info("✅ All NexusController services started successfully")
            
            # Print startup summary
            self._print_startup_summary()
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to start NexusController: {e}")
            await self.stop()
            return False
    
    async def _initialize_event_system(self):
        """Initialize event bus and integration"""
        logging.info("Initializing event system...")
        
        self.event_bus = EventBusFactory.create_event_bus("memory")
        await self.event_bus.start()
        
        self.event_integration = NexusEventIntegration(self.event_bus)
        
        logging.info("✅ Event system initialized")
    
    async def _initialize_state_manager(self):
        """Initialize state management"""
        logging.info("Initializing state manager...")
        
        data_dir = Path(self.config['nexus']['data_dir'])
        data_dir.mkdir(exist_ok=True)
        
        backend = FileStateBackend(data_dir / "state")
        self.state_manager = StateManager(backend, self.event_bus)
        await self.state_manager.start()
        
        logging.info("✅ State manager initialized")
    
    async def _initialize_plugin_manager(self):
        """Initialize plugin system"""
        if not self.config['plugins']['enabled']:
            logging.info("Plugin system disabled")
            return
        
        logging.info("Initializing plugin manager...")
        
        plugin_dir = Path(self.config['plugins']['plugin_dir'])
        plugin_dir.mkdir(exist_ok=True)
        
        self.plugin_manager = PluginManager(plugin_dir, self.event_bus)
        await self.plugin_manager.start()
        
        logging.info("✅ Plugin manager initialized")
    
    async def _initialize_monitoring(self):
        """Initialize monitoring system"""
        if not self.config['monitoring']['enabled']:
            logging.info("Monitoring system disabled")
            return
        
        logging.info("Initializing monitoring system...")
        
        self.monitoring_system = MonitoringSystem(self.event_bus)
        await self.monitoring_system.start()
        
        logging.info("✅ Monitoring system initialized")
    
    async def _initialize_remediation(self):
        """Initialize remediation system"""
        if not self.config['remediation']['enabled']:
            logging.info("Remediation system disabled")
            return
        
        logging.info("Initializing remediation system...")
        
        self.remediation_system = RemediationSystem(self.event_bus)
        await self.remediation_system.start()
        
        logging.info("✅ Remediation system initialized")
    
    async def _initialize_multicloud(self):
        """Initialize multi-cloud manager"""
        logging.info("Initializing multi-cloud manager...")
        
        self.multicloud_manager = MultiCloudManager(self.event_bus)
        await self.multicloud_manager.start()
        
        logging.info("✅ Multi-cloud manager initialized")
    
    async def _initialize_websocket(self):
        """Initialize WebSocket server"""
        logging.info("Initializing WebSocket server...")
        
        ws_config = self.config['websocket']
        self.websocket_server = WebSocketServer(
            host=ws_config['host'],
            port=ws_config['port'],
            event_bus=self.event_bus
        )
        
        self.websocket_server.auth_required = ws_config['auth_required']
        await self.websocket_server.start()
        
        logging.info(f"✅ WebSocket server listening on ws://{ws_config['host']}:{ws_config['port']}")
    
    async def _initialize_federation(self):
        """Initialize federation manager"""
        fed_config = self.config['federation']
        if not fed_config['enabled']:
            logging.info("Federation disabled")
            return
        
        logging.info("Initializing federation manager...")
        
        self.federation_manager = FederationManager(
            node_id=self.config['nexus']['node_id'],
            name=f"NexusController-{self.config['nexus']['node_id']}",
            host="0.0.0.0",
            port=fed_config['port'],
            event_bus=self.event_bus,
            state_manager=self.state_manager
        )
        
        bootstrap_nodes = fed_config.get('bootstrap_nodes', [])
        await self.federation_manager.start(bootstrap_nodes)
        
        logging.info(f"✅ Federation manager initialized on port {fed_config['port']}")
    
    async def _initialize_api_server(self):
        """Initialize API server"""
        logging.info("Initializing API server...")
        
        api_config = self.config['api']
        
        # Create FastAPI app with all components
        app = create_app(
            event_bus=self.event_bus,
            state_manager=self.state_manager,
            plugin_manager=self.plugin_manager,
            monitoring_system=self.monitoring_system,
            remediation_system=self.remediation_system,
            multicloud_manager=self.multicloud_manager,
            federation_manager=self.federation_manager
        )
        
        # Start API server (would typically use uvicorn in production)
        logging.info(f"✅ API server ready on http://{api_config['host']}:{api_config['port']}")
        logging.info("Note: Use 'uvicorn nexus_api_server:app' to start the API server")
    
    def _print_startup_summary(self):
        """Print startup summary"""
        api_config = self.config['api']
        ws_config = self.config['websocket']
        
        print("\n" + "="*60)
        print(f"🚀 NexusController v{__version__} - READY")
        print("="*60)
        print(f"📊 Web Interface: http://{api_config['host']}:{api_config['port']}")
        print(f"🔌 WebSocket API:  ws://{ws_config['host']}:{ws_config['port']}")
        print(f"📁 Data Directory: {self.config['nexus']['data_dir']}")
        print(f"🔧 Node ID: {self.config['nexus']['node_id']}")
        
        if self.config['federation']['enabled']:
            print(f"🌐 Federation: Enabled (port {self.config['federation']['port']})")
        
        if self.config['plugins']['enabled']:
            print(f"🧩 Plugins: Enabled ({self.config['plugins']['plugin_dir']})")
        
        print("\n📚 Quick Commands:")
        print("  • View API docs: http://localhost:8080/docs")
        print("  • Health check: http://localhost:8080/health")
        print("  • Metrics: http://localhost:8080/metrics")
        print("\n🛑 Press Ctrl+C to stop")
        print("="*60 + "\n")
    
    async def stop(self):
        """Stop all NexusController services"""
        logging.info("Stopping NexusController services...")
        self.running = False
        
        # Stop services in reverse order
        services = [
            ('API Server', self.api_server),
            ('Federation Manager', self.federation_manager),
            ('WebSocket Server', self.websocket_server),
            ('Multi-Cloud Manager', self.multicloud_manager),
            ('Remediation System', self.remediation_system),
            ('Monitoring System', self.monitoring_system),
            ('Plugin Manager', self.plugin_manager),
            ('State Manager', self.state_manager),
            ('Event Bus', self.event_bus)
        ]
        
        for service_name, service in services:
            if service:
                try:
                    if hasattr(service, 'stop'):
                        await service.stop()
                    logging.info(f"✅ {service_name} stopped")
                except Exception as e:
                    logging.error(f"Error stopping {service_name}: {e}")
        
        logging.info("🛑 NexusController stopped")
    
    async def run_forever(self):
        """Run the controller indefinitely"""
        if await self.start():
            try:
                while self.running:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                logging.info("Received keyboard interrupt")
            finally:
                await self.stop()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description=f"NexusController v{__version__}")
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='Configuration file path (default: config.yaml)'
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'NexusController v{__version__} (build {__build__})'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Create controller instance
    controller = NexusController(args.config)
    
    if args.debug:
        controller.config['nexus']['debug'] = True
        controller._setup_logging()
    
    # Run the controller
    try:
        asyncio.run(controller.run_forever())
    except KeyboardInterrupt:
        print("\n🛑 Shutdown complete")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()