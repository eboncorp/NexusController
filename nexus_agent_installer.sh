#!/bin/bash
# Nexus Intelligent Agent Installer
# Sets up the monitoring agent as a systemd service

echo "🤖 NEXUS INTELLIGENT AGENT INSTALLER"
echo "====================================="
echo "Installing autonomous monitoring agent for HP Z4 G4 Media Server"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "❌ Don't run this script as root. It will use sudo when needed."
    exit 1
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
sudo apt update
sudo apt install -y python3-pip python3-venv python3-dev

# Create virtual environment
echo "🐍 Setting up Python virtual environment..."
sudo mkdir -p /opt/nexus-agent
sudo chown $USER:$USER /opt/nexus-agent
python3 -m venv /opt/nexus-agent/venv

# Activate virtual environment and install packages
source /opt/nexus-agent/venv/bin/activate
pip install --upgrade pip
pip install docker psutil aiohttp sqlite3

# Copy agent script
echo "📁 Installing agent files..."
sudo cp /home/dave/nexus_intelligent_agent.py /opt/nexus-agent/
sudo chmod +x /opt/nexus-agent/nexus_intelligent_agent.py

# Create configuration directory
sudo mkdir -p /etc/nexus-agent
sudo mkdir -p /var/lib/nexus-agent
sudo mkdir -p /var/log/nexus-agent

# Create default configuration
sudo tee /etc/nexus-agent/config.json << 'EOF'
{
    "services": {
        "nexuscontroller": {
            "container_name": "nexuscontroller",
            "health_url": "http://localhost:8000/health",
            "critical": true,
            "auto_restart": true,
            "max_restarts": 3
        },
        "jellyfin": {
            "container_name": "jellyfin",
            "health_url": "http://localhost:8096/health",
            "critical": true,
            "auto_restart": true,
            "max_restarts": 2
        },
        "homeassistant": {
            "container_name": "homeassistant",
            "health_url": "http://localhost:8123",
            "critical": true,
            "auto_restart": true,
            "max_restarts": 2
        },
        "mosquitto": {
            "container_name": "mosquitto",
            "port": 1883,
            "critical": true,
            "auto_restart": true,
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
        "webhook_url": null,
        "email_enabled": false,
        "critical_only": false
    }
}
EOF

# Set permissions
sudo chown -R $USER:$USER /var/lib/nexus-agent
sudo chown -R $USER:$USER /var/log/nexus-agent
sudo chown $USER:$USER /etc/nexus-agent/config.json

# Create systemd service
sudo tee /etc/systemd/system/nexus-agent.service << 'EOF'
[Unit]
Description=Nexus Intelligent Monitoring Agent
After=docker.service
Requires=docker.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=ebon
Group=ebon
WorkingDirectory=/opt/nexus-agent
Environment=PATH=/opt/nexus-agent/venv/bin
ExecStart=/opt/nexus-agent/venv/bin/python /opt/nexus-agent/nexus_intelligent_agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nexus-agent

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nexus-agent /var/log/nexus-agent /tmp
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

# Add user to docker group if not already
if ! groups $USER | grep -q docker; then
    echo "👤 Adding user to docker group..."
    sudo usermod -aG docker $USER
    echo "⚠️  You'll need to log out and back in for docker group membership to take effect"
fi

# Create management scripts
echo "🔧 Creating management scripts..."

# Status script
tee /home/dave/nexus_agent_status.sh << 'EOF'
#!/bin/bash
# Nexus Agent Status Checker
echo "🤖 Nexus Intelligent Agent Status"
echo "=================================="

# Service status
systemctl is-active --quiet nexus-agent && echo "✅ Service: Running" || echo "❌ Service: Stopped"

# Recent logs
echo ""
echo "📋 Recent Activity:"
journalctl -u nexus-agent --no-pager -n 10 --output=short

# Database status
if [ -f /var/lib/nexus-agent/agent.db ]; then
    echo ""
    echo "💾 Database Status:"
    sqlite3 /var/lib/nexus-agent/agent.db "SELECT COUNT(*) || ' metrics stored' FROM service_metrics;"
    sqlite3 /var/lib/nexus-agent/agent.db "SELECT COUNT(*) || ' events logged' FROM events;"
fi
EOF

# Control script
tee /home/dave/nexus_agent_control.sh << 'EOF'
#!/bin/bash
# Nexus Agent Control Script

case "$1" in
    start)
        echo "🚀 Starting Nexus Agent..."
        sudo systemctl start nexus-agent
        ;;
    stop)
        echo "🛑 Stopping Nexus Agent..."
        sudo systemctl stop nexus-agent
        ;;
    restart)
        echo "🔄 Restarting Nexus Agent..."
        sudo systemctl restart nexus-agent
        ;;
    status)
        ./nexus_agent_status.sh
        ;;
    logs)
        echo "📋 Nexus Agent Logs (press Ctrl+C to exit):"
        journalctl -u nexus-agent -f
        ;;
    config)
        echo "⚙️  Opening configuration file..."
        ${EDITOR:-nano} /etc/nexus-agent/config.json
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|config}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the agent"
        echo "  stop    - Stop the agent" 
        echo "  restart - Restart the agent"
        echo "  status  - Show agent status"
        echo "  logs    - Show live logs"
        echo "  config  - Edit configuration"
        exit 1
        ;;
esac
EOF

chmod +x /home/dave/nexus_agent_*.sh

# Reload systemd and enable service
echo "🔄 Configuring systemd service..."
sudo systemctl daemon-reload
sudo systemctl enable nexus-agent

echo ""
echo "✅ Nexus Intelligent Agent installed successfully!"
echo ""
echo "🎯 Next Steps:"
echo "1. Start the agent: ./nexus_agent_control.sh start"
echo "2. Check status: ./nexus_agent_control.sh status"
echo "3. View logs: ./nexus_agent_control.sh logs"
echo "4. Edit config: ./nexus_agent_control.sh config"
echo ""
echo "🔧 Configuration file: /etc/nexus-agent/config.json"
echo "📊 Logs: journalctl -u nexus-agent"
echo "💾 Database: /var/lib/nexus-agent/agent.db"
echo ""
echo "The agent will:"
echo "- Monitor all Docker services every 30 seconds"
echo "- Automatically restart failed critical services"
echo "- Perform maintenance at 2-4 AM"
echo "- Store metrics and events in SQLite database"
echo "- Log all activities to system journal"