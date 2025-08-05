#!/usr/bin/env python3
"""
Nexus Intelligent Monitoring Agent
Autonomous monitoring and self-healing for HP Z4 G4 Media Server

Features:
- Real-time service health monitoring
- Automatic failure recovery
- Predictive maintenance
- Resource optimization
- Smart alerting
- Integration with existing monitoring
"""

import asyncio
import json
import logging
import psutil
import docker
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import aiohttp
import sqlite3
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nexus-agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NexusAgent')

class ServiceStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    RECOVERING = "recovering"
    UNKNOWN = "unknown"

@dataclass
class ServiceHealth:
    name: str
    status: ServiceStatus
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    response_time: Optional[float]
    last_check: datetime
    restart_count: int = 0
    issues: List[str] = None
    
    def __post_init__(self):
        if self.issues is None:
            self.issues = []

class NexusIntelligentAgent:
    def __init__(self, config_path: str = "/etc/nexus-agent/config.json"):
        self.config = self._load_config(config_path)
        self.docker_client = docker.from_env()
        self.db_path = "/var/lib/nexus-agent/agent.db"
        self.services = {}
        self.recovery_attempts = {}
        self.maintenance_schedule = {}
        self._init_database()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load agent configuration"""
        default_config = {
            "services": {
                "nexuscontroller": {
                    "container_name": "nexuscontroller",
                    "health_url": "http://localhost:8000/health",
                    "critical": True,
                    "auto_restart": True,
                    "max_restarts": 3
                },
                "jellyfin": {
                    "container_name": "jellyfin",
                    "health_url": "http://localhost:8096/health",
                    "critical": True,
                    "auto_restart": True,
                    "max_restarts": 2
                },
                "homeassistant": {
                    "container_name": "homeassistant",
                    "health_url": "http://localhost:8123",
                    "critical": True,
                    "auto_restart": True,
                    "max_restarts": 2
                },
                "mosquitto": {
                    "container_name": "mosquitto",
                    "port": 1883,
                    "critical": True,
                    "auto_restart": True,
                    "max_restarts": 3
                }
            },
            "thresholds": {
                "cpu_warning": 80,
                "cpu_critical": 95,
                "memory_warning": 85,
                "memory_critical": 95,
                "disk_warning": 85,
                "disk_critical": 95,
                "response_time_warning": 5.0,
                "response_time_critical": 10.0
            },
            "monitoring": {
                "check_interval": 30,
                "health_check_timeout": 10,
                "maintenance_window": "02:00-04:00",
                "log_retention_days": 30
            },
            "notifications": {
                "webhook_url": None,
                "email_enabled": False,
                "critical_only": False
            }
        }
        
        try:
            if Path(config_path).exists():
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                # Merge with defaults
                default_config.update(user_config)
            else:
                # Create default config
                Path(config_path).parent.mkdir(parents=True, exist_ok=True)
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                logger.info(f"Created default config at {config_path}")
        except Exception as e:
            logger.warning(f"Error loading config: {e}, using defaults")
            
        return default_config
    
    def _init_database(self):
        """Initialize SQLite database for storing metrics and events"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS service_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    status TEXT NOT NULL,
                    cpu_usage REAL,
                    memory_usage REAL,
                    disk_usage REAL,
                    response_time REAL,
                    issues TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    service_name TEXT,
                    description TEXT,
                    action_taken TEXT,
                    success BOOLEAN
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_service_timestamp 
                ON service_metrics(service_name, timestamp)
            ''')
    
    async def check_service_health(self, service_name: str, config: Dict[str, Any]) -> ServiceHealth:
        """Comprehensive health check for a service"""
        issues = []
        response_time = None
        
        try:
            # Get container if it exists
            container = None
            try:
                container = self.docker_client.containers.get(config['container_name'])
            except docker.errors.NotFound:
                issues.append(f"Container {config['container_name']} not found")
                return ServiceHealth(
                    name=service_name,
                    status=ServiceStatus.CRITICAL,
                    cpu_usage=0,
                    memory_usage=0,
                    disk_usage=0,
                    response_time=None,
                    last_check=datetime.now(),
                    issues=issues
                )
            
            # Check container status
            if container.status != 'running':
                issues.append(f"Container status: {container.status}")
            
            # Get resource usage
            stats = container.stats(stream=False)
            cpu_usage = self._calculate_cpu_usage(stats)
            memory_usage = self._calculate_memory_usage(stats)
            
            # Get disk usage (approximate from container size)
            disk_usage = self._get_container_disk_usage(container)
            
            # Health check via HTTP if configured
            if 'health_url' in config:
                response_time = await self._http_health_check(config['health_url'])
                if response_time is None:
                    issues.append("HTTP health check failed")
            elif 'port' in config:
                # TCP port check
                if not await self._tcp_health_check('localhost', config['port']):
                    issues.append(f"Port {config['port']} not responding")
            
            # Analyze resource usage
            if cpu_usage > self.config['thresholds']['cpu_critical']:
                issues.append(f"Critical CPU usage: {cpu_usage:.1f}%")
            elif cpu_usage > self.config['thresholds']['cpu_warning']:
                issues.append(f"High CPU usage: {cpu_usage:.1f}%")
            
            if memory_usage > self.config['thresholds']['memory_critical']:
                issues.append(f"Critical memory usage: {memory_usage:.1f}%")
            elif memory_usage > self.config['thresholds']['memory_warning']:
                issues.append(f"High memory usage: {memory_usage:.1f}%")
            
            # Determine status
            if issues:
                if any('Critical' in issue or 'failed' in issue for issue in issues):
                    status = ServiceStatus.CRITICAL
                else:
                    status = ServiceStatus.WARNING
            else:
                status = ServiceStatus.HEALTHY
            
            return ServiceHealth(
                name=service_name,
                status=status,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                disk_usage=disk_usage,
                response_time=response_time,
                last_check=datetime.now(),
                issues=issues
            )
            
        except Exception as e:
            logger.error(f"Error checking {service_name}: {e}")
            return ServiceHealth(
                name=service_name,
                status=ServiceStatus.UNKNOWN,
                cpu_usage=0,
                memory_usage=0,
                disk_usage=0,
                response_time=None,
                last_check=datetime.now(),
                issues=[f"Health check error: {str(e)}"]
            )
    
    async def _http_health_check(self, url: str) -> Optional[float]:
        """Perform HTTP health check and return response time"""
        try:
            timeout = aiohttp.ClientTimeout(
                total=self.config['monitoring']['health_check_timeout']
            )
            start_time = time.time()
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    response_time = time.time() - start_time
                    if response.status == 200:
                        return response_time
                    else:
                        logger.warning(f"HTTP check failed: {url} returned {response.status}")
                        return None
        except Exception as e:
            logger.debug(f"HTTP health check failed for {url}: {e}")
            return None
    
    async def _tcp_health_check(self, host: str, port: int) -> bool:
        """Perform TCP port health check"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config['monitoring']['health_check_timeout']
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    def _calculate_cpu_usage(self, stats: Dict) -> float:
        """Calculate CPU usage percentage from Docker stats"""
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            
            if system_delta > 0:
                cpu_usage = (cpu_delta / system_delta) * 100.0
                # Adjust for number of CPUs
                cpu_count = len(stats['cpu_stats']['cpu_usage']['percpu_usage'])
                return min(cpu_usage * cpu_count, 100.0)
            return 0.0
        except (KeyError, ZeroDivisionError):
            return 0.0
    
    def _calculate_memory_usage(self, stats: Dict) -> float:
        """Calculate memory usage percentage from Docker stats"""
        try:
            usage = stats['memory_stats']['usage']
            limit = stats['memory_stats']['limit']
            return (usage / limit) * 100.0
        except (KeyError, ZeroDivisionError):
            return 0.0
    
    def _get_container_disk_usage(self, container) -> float:
        """Get approximate disk usage for container"""
        try:
            # This is a simplified approximation
            # In practice, you might want to check specific mount points
            disk_usage = psutil.disk_usage('/')
            return (disk_usage.used / disk_usage.total) * 100.0
        except Exception:
            return 0.0
    
    async def attempt_recovery(self, service_name: str, health: ServiceHealth) -> bool:
        """Attempt to recover a failed service"""
        config = self.config['services'][service_name]
        
        if not config.get('auto_restart', False):
            logger.info(f"Auto-restart disabled for {service_name}")
            return False
        
        # Check restart limits
        restart_count = self.recovery_attempts.get(service_name, 0)
        max_restarts = config.get('max_restarts', 3)
        
        if restart_count >= max_restarts:
            logger.error(f"Max restart attempts reached for {service_name}")
            await self._log_event('max_restarts_reached', service_name, 
                                f"Reached maximum restart attempts ({max_restarts})")
            return False
        
        try:
            logger.info(f"Attempting recovery for {service_name} (attempt {restart_count + 1})")
            
            # Get container
            container = self.docker_client.containers.get(config['container_name'])
            
            # Different recovery strategies based on the issue
            if health.status == ServiceStatus.CRITICAL:
                # Force restart for critical issues
                logger.info(f"Performing hard restart of {service_name}")
                container.restart()
            else:
                # Try gentle restart first
                logger.info(f"Performing gentle restart of {service_name}")
                container.restart()
            
            # Wait for service to come back up
            await asyncio.sleep(10)
            
            # Verify recovery
            recovery_health = await self.check_service_health(service_name, config)
            
            if recovery_health.status in [ServiceStatus.HEALTHY, ServiceStatus.WARNING]:
                logger.info(f"Successfully recovered {service_name}")
                self.recovery_attempts[service_name] = 0  # Reset counter
                await self._log_event('recovery_success', service_name, 
                                    f"Service recovered after restart")
                return True
            else:
                logger.warning(f"Recovery attempt failed for {service_name}")
                self.recovery_attempts[service_name] = restart_count + 1
                await self._log_event('recovery_failed', service_name, 
                                    f"Recovery attempt {restart_count + 1} failed")
                return False
                
        except Exception as e:
            logger.error(f"Recovery attempt failed for {service_name}: {e}")
            self.recovery_attempts[service_name] = restart_count + 1
            await self._log_event('recovery_error', service_name, 
                                f"Recovery error: {str(e)}")
            return False
    
    async def perform_predictive_maintenance(self):
        """Perform predictive maintenance tasks"""
        logger.info("Starting predictive maintenance")
        
        try:
            # Clean up old logs
            await self._cleanup_old_logs()
            
            # Check disk space and clean if needed
            await self._manage_disk_space()
            
            # Optimize Docker containers
            await self._optimize_containers()
            
            # Update service health trends
            await self._analyze_trends()
            
            logger.info("Predictive maintenance completed")
            
        except Exception as e:
            logger.error(f"Predictive maintenance error: {e}")
    
    async def _cleanup_old_logs(self):
        """Clean up old log files"""
        retention_days = self.config['monitoring']['log_retention_days']
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # Clean database records
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                DELETE FROM service_metrics 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            
            conn.execute('''
                DELETE FROM events 
                WHERE timestamp < ?
            ''', (cutoff_date,))
        
        # Clean Docker logs if they're getting too large
        try:
            result = subprocess.run(['docker', 'system', 'df'], 
                                  capture_output=True, text=True)
            if 'Local Volumes' in result.stdout:
                # Consider cleaning if logs are using too much space
                pass
        except Exception as e:
            logger.debug(f"Docker cleanup check failed: {e}")
    
    async def _manage_disk_space(self):
        """Monitor and manage disk space"""
        disk_usage = psutil.disk_usage('/')
        usage_percent = (disk_usage.used / disk_usage.total) * 100
        
        if usage_percent > self.config['thresholds']['disk_critical']:
            logger.warning(f"Critical disk usage: {usage_percent:.1f}%")
            # Attempt cleanup
            try:
                subprocess.run(['docker', 'system', 'prune', '-f'], 
                             capture_output=True)
                logger.info("Performed Docker system cleanup")
            except Exception as e:
                logger.error(f"Docker cleanup failed: {e}")
    
    async def _optimize_containers(self):
        """Optimize container resource usage"""
        for container in self.docker_client.containers.list():
            try:
                stats = container.stats(stream=False)
                cpu_usage = self._calculate_cpu_usage(stats)
                memory_usage = self._calculate_memory_usage(stats)
                
                # Log resource usage for analysis
                logger.debug(f"{container.name}: CPU {cpu_usage:.1f}%, Memory {memory_usage:.1f}%")
                
            except Exception as e:
                logger.debug(f"Stats error for {container.name}: {e}")
    
    async def _analyze_trends(self):
        """Analyze service health trends for predictive insights"""
        # This could be expanded with machine learning
        # For now, just log basic trend analysis
        with sqlite3.connect(self.db_path) as conn:
            for service_name in self.config['services']:
                cursor = conn.execute('''
                    SELECT AVG(cpu_usage), AVG(memory_usage), AVG(response_time)
                    FROM service_metrics 
                    WHERE service_name = ? AND timestamp > datetime('now', '-24 hours')
                ''', (service_name,))
                
                result = cursor.fetchone()
                if result and any(result):
                    avg_cpu, avg_memory, avg_response = result
                    logger.debug(f"{service_name} 24h averages: "
                               f"CPU {avg_cpu:.1f}%, Memory {avg_memory:.1f}%, "
                               f"Response {avg_response:.2f}s")
    
    async def _log_event(self, event_type: str, service_name: str, 
                        description: str, action_taken: str = None, 
                        success: bool = None):
        """Log events to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO events (timestamp, event_type, service_name, 
                                  description, action_taken, success)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (datetime.now(), event_type, service_name, description, 
                  action_taken, success))
    
    async def _store_metrics(self, health: ServiceHealth):
        """Store service metrics in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO service_metrics (service_name, timestamp, status,
                                           cpu_usage, memory_usage, disk_usage,
                                           response_time, issues)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (health.name, health.last_check, health.status.value,
                  health.cpu_usage, health.memory_usage, health.disk_usage,
                  health.response_time, json.dumps(health.issues)))
    
    async def send_notification(self, health: ServiceHealth, recovered: bool = False):
        """Send notifications for service issues"""
        if self.config['notifications']['critical_only'] and \
           health.status != ServiceStatus.CRITICAL:
            return
        
        message = {
            'service': health.name,
            'status': health.status.value,
            'timestamp': health.last_check.isoformat(),
            'issues': health.issues,
            'recovered': recovered,
            'cpu_usage': health.cpu_usage,
            'memory_usage': health.memory_usage,
            'response_time': health.response_time
        }
        
        # Webhook notification
        webhook_url = self.config['notifications'].get('webhook_url')
        if webhook_url:
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(webhook_url, json=message)
                logger.info(f"Sent webhook notification for {health.name}")
            except Exception as e:
                logger.error(f"Webhook notification failed: {e}")
        
        # Log notification
        logger.info(f"Notification: {health.name} is {health.status.value}")
        if health.issues:
            logger.info(f"Issues: {', '.join(health.issues)}")
    
    async def monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting Nexus Intelligent Agent monitoring loop")
        
        while True:
            try:
                check_start = time.time()
                
                # Check all configured services
                for service_name, config in self.config['services'].items():
                    health = await self.check_service_health(service_name, config)
                    
                    # Store metrics
                    await self._store_metrics(health)
                    
                    # Compare with previous state
                    previous_health = self.services.get(service_name)
                    self.services[service_name] = health
                    
                    # Handle status changes
                    if previous_health and previous_health.status != health.status:
                        if health.status in [ServiceStatus.WARNING, ServiceStatus.CRITICAL]:
                            logger.warning(f"{service_name} status changed: "
                                         f"{previous_health.status.value} -> {health.status.value}")
                            await self.send_notification(health)
                            
                            # Attempt recovery for critical services
                            if health.status == ServiceStatus.CRITICAL:
                                recovered = await self.attempt_recovery(service_name, health)
                                if recovered:
                                    # Re-check after recovery
                                    health = await self.check_service_health(service_name, config)
                                    self.services[service_name] = health
                                    await self.send_notification(health, recovered=True)
                        
                        elif health.status == ServiceStatus.HEALTHY and \
                             previous_health.status in [ServiceStatus.WARNING, ServiceStatus.CRITICAL]:
                            logger.info(f"{service_name} recovered to healthy state")
                            await self.send_notification(health, recovered=True)
                    
                    # Initial notification for new services
                    elif not previous_health and \
                         health.status in [ServiceStatus.WARNING, ServiceStatus.CRITICAL]:
                        await self.send_notification(health)
                
                # Perform maintenance during maintenance window
                current_time = datetime.now().strftime("%H:%M")
                maintenance_window = self.config['monitoring']['maintenance_window']
                start_time, end_time = maintenance_window.split('-')
                
                if start_time <= current_time <= end_time:
                    # Only run maintenance once per window
                    if not hasattr(self, '_maintenance_done_today'):
                        await self.perform_predictive_maintenance()
                        self._maintenance_done_today = True
                else:
                    # Reset maintenance flag outside window
                    if hasattr(self, '_maintenance_done_today'):
                        delattr(self, '_maintenance_done_today')
                
                # Calculate next check time
                check_duration = time.time() - check_start
                sleep_time = max(0, self.config['monitoring']['check_interval'] - check_duration)
                
                logger.debug(f"Monitoring check completed in {check_duration:.2f}s, "
                           f"sleeping for {sleep_time:.2f}s")
                
                await asyncio.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get current status summary"""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'services': {},
            'system_health': 'unknown'
        }
        
        healthy_count = 0
        total_count = len(self.services)
        
        for service_name, health in self.services.items():
            summary['services'][service_name] = {
                'status': health.status.value,
                'cpu_usage': health.cpu_usage,
                'memory_usage': health.memory_usage,
                'response_time': health.response_time,
                'issues': health.issues,
                'last_check': health.last_check.isoformat()
            }
            
            if health.status == ServiceStatus.HEALTHY:
                healthy_count += 1
        
        # Overall system health
        if total_count == 0:
            summary['system_health'] = 'unknown'
        elif healthy_count == total_count:
            summary['system_health'] = 'healthy'
        elif healthy_count > total_count / 2:
            summary['system_health'] = 'warning'
        else:
            summary['system_health'] = 'critical'
        
        return summary

async def main():
    """Main entry point"""
    agent = NexusIntelligentAgent()
    
    try:
        await agent.monitoring_loop()
    except KeyboardInterrupt:
        logger.info("Nexus Intelligent Agent shutting down")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())