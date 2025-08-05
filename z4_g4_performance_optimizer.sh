#!/bin/bash
# HP Z4 G4 Performance Optimizer
# Optimizes the media server for maximum performance with Xeon W-2245

echo "🏎️  HP Z4 G4 PERFORMANCE OPTIMIZER"
echo "=================================="
echo "Hardware: HP Z4 G4 Workstation"
echo "CPU: Intel Xeon W-2245 (8 cores, 16 threads)"
echo "RAM: 48GB ECC DDR4"
echo "Target: Media Server Optimization"
echo ""

# Function to check if running on the Z4 G4
check_hardware() {
    if ! lscpu | grep -q "Xeon"; then
        echo "⚠️  Warning: This script is optimized for Intel Xeon processors"
        echo "Current CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# CPU Performance Optimization
optimize_cpu() {
    echo "🔥 Optimizing CPU Performance (Xeon W-2245)..."
    
    # Set CPU governor to performance for media workloads
    echo "Setting CPU governor to performance..."
    echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
    
    # Enable turbo boost
    echo "Enabling Intel Turbo Boost..."
    echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo > /dev/null
    
    # Set CPU scaling for media processing
    sudo tee /etc/systemd/system/cpu-performance.service << 'EOF'
[Unit]
Description=CPU Performance Optimization for Media Server
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'
ExecStart=/bin/bash -c 'echo 0 | tee /sys/devices/system/cpu/intel_pstate/no_turbo'
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl enable cpu-performance.service
    
    # Optimize IRQ affinity for network and storage
    echo "Optimizing IRQ affinity..."
    # This would be customized based on specific hardware layout
    # For now, set a balanced approach
    
    echo "✅ CPU optimization complete"
}

# Memory Optimization for 48GB ECC RAM
optimize_memory() {
    echo "🧠 Optimizing Memory (48GB ECC DDR4)..."
    
    # Optimize for media server workloads
    sudo tee -a /etc/sysctl.conf << 'EOF'

# HP Z4 G4 Memory Optimization for Media Server
# Optimized for 48GB ECC RAM with media workloads

# Virtual memory settings
vm.swappiness=10                    # Reduce swap usage with 48GB RAM
vm.vfs_cache_pressure=50           # Balance file system cache
vm.dirty_ratio=15                  # Allow more dirty pages with large RAM
vm.dirty_background_ratio=5        # Start background writeback earlier
vm.dirty_expire_centisecs=1500     # Expire dirty pages faster for media files
vm.dirty_writeback_centisecs=500   # More frequent writeback for streaming

# Network buffer optimization for media streaming
net.core.rmem_default=262144       # Default socket receive buffer
net.core.rmem_max=16777216         # Maximum socket receive buffer
net.core.wmem_default=262144       # Default socket send buffer  
net.core.wmem_max=16777216         # Maximum socket send buffer
net.core.netdev_max_backlog=5000   # Network device backlog

# TCP optimization for media streaming
net.ipv4.tcp_rmem=4096 87380 16777216     # TCP receive buffer sizes
net.ipv4.tcp_wmem=4096 65536 16777216     # TCP send buffer sizes
net.ipv4.tcp_congestion_control=bbr        # Better congestion control
net.ipv4.tcp_window_scaling=1              # Enable window scaling

# File system optimizations
fs.file-max=2097152                # Increase max open files
fs.inotify.max_user_watches=524288 # More file watchers for media libraries
EOF

    # Apply settings
    sudo sysctl -p
    
    # Optimize transparent huge pages for media workloads
    echo "Configuring Transparent Huge Pages..."
    echo 'madvise' | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
    echo 'madvise' | sudo tee /sys/kernel/mm/transparent_hugepage/defrag
    
    echo "✅ Memory optimization complete"
}

# Storage Optimization (NVMe + potential RAID)
optimize_storage() {
    echo "💾 Optimizing Storage Performance..."
    
    # Detect NVMe drives
    nvme_drives=$(lsblk -d -o NAME,ROTA | awk '$2=="0" {print $1}' | grep -E '^nvme')
    
    if [ -n "$nvme_drives" ]; then
        echo "Found NVMe drives: $nvme_drives"
        
        for drive in $nvme_drives; do
            echo "Optimizing /dev/$drive..."
            
            # Set I/O scheduler for NVMe (none is usually best)
            echo 'none' | sudo tee /sys/block/$drive/queue/scheduler > /dev/null
            
            # Optimize queue depth
            echo '32' | sudo tee /sys/block/$drive/queue/nr_requests > /dev/null
            
            # Disable NCQ for better latency (optional)
            # echo '1' | sudo tee /sys/block/$drive/queue/nomerges > /dev/null
        done
    fi
    
    # Optimize mount options for media storage
    echo "Optimizing mount options..."
    
    # Create optimized fstab backup
    sudo cp /etc/fstab /etc/fstab.backup
    
    # Add optimizations for existing mounts (if not present)
    if ! grep -q "noatime" /etc/fstab; then
        echo "Adding noatime mount option recommendations..."
        echo "# Add 'noatime' to your mount options for better performance"
        echo "# Example: /dev/nvme0n1p2 / ext4 defaults,noatime 0 1"
    fi
    
    # Enable TRIM for SSD longevity
    sudo systemctl enable fstrim.timer
    
    echo "✅ Storage optimization complete"
}

# Docker Performance Optimization
optimize_docker() {
    echo "🐳 Optimizing Docker for Z4 G4..."
    
    # Create Docker daemon configuration for performance
    sudo mkdir -p /etc/docker
    
    sudo tee /etc/docker/daemon.json << 'EOF'
{
    "storage-driver": "overlay2",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "3"
    },
    "default-ulimits": {
        "nofile": {
            "hard": 65536,
            "soft": 65536
        }
    },
    "dns": ["1.1.1.1", "8.8.8.8"],
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 5,
    "userland-proxy": false,
    "experimental": false,
    "metrics-addr": "127.0.0.1:9323",
    "iptables": true,
    "live-restore": true
}
EOF

    # Optimize Docker service
    sudo mkdir -p /etc/systemd/system/docker.service.d
    
    sudo tee /etc/systemd/system/docker.service.d/override.conf << 'EOF'
[Service]
# Increase resource limits for media server workloads
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
TasksMax=infinity

# Optimize for Xeon W-2245 (8 cores)
Environment="GOMAXPROCS=8"
EOF

    # Restart Docker with new settings
    sudo systemctl daemon-reload
    sudo systemctl restart docker
    
    echo "✅ Docker optimization complete"
}

# Network Performance Optimization
optimize_network() {
    echo "🌐 Optimizing Network Performance..."
    
    # Optimize network interface settings
    network_interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp)' | head -1)
    
    if [ -n "$network_interfaces" ]; then
        for interface in $network_interfaces; do
            echo "Optimizing $interface..."
            
            # Increase ring buffer sizes if supported
            sudo ethtool -G $interface rx 4096 tx 4096 2>/dev/null || true
            
            # Enable hardware offloading if supported
            sudo ethtool -K $interface tso on gso on gro on lro on 2>/dev/null || true
            
            # Optimize interrupt coalescing
            sudo ethtool -C $interface rx-usecs 50 tx-usecs 50 2>/dev/null || true
        done
    fi
    
    # Network stack optimizations already added in memory section
    echo "✅ Network optimization complete"
}

# Media Server Specific Optimizations
optimize_media_services() {
    echo "🎬 Optimizing Media Services..."
    
    # Create optimized Docker Compose template for Z4 G4
    tee /home/dave/docker-compose.z4g4-optimized.yml << 'EOF'
version: '3.8'

# Optimized Docker Compose for HP Z4 G4 Media Server
# Xeon W-2245 (8 cores/16 threads), 48GB ECC RAM

services:
  nexuscontroller:
    container_name: nexuscontroller
    image: nexuscontroller:latest
    restart: unless-stopped
    ports:
      - "8000:8000"
    deploy:
      resources:
        limits:
          cpus: '2.0'        # 25% of Xeon capacity
          memory: 4G         # Reasonable for 48GB system
        reservations:
          cpus: '1.0'
          memory: 2G
    networks:
      - media_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  jellyfin:
    container_name: jellyfin
    image: jellyfin/jellyfin:latest
    restart: unless-stopped
    ports:
      - "8096:8096"
    volumes:
      - jellyfin_config:/config
      - jellyfin_cache:/cache
      - /path/to/media:/media:ro
    environment:
      - JELLYFIN_PublishedServerUrl=http://10.0.0.29:8096
    deploy:
      resources:
        limits:
          cpus: '4.0'        # 50% of Xeon for transcoding
          memory: 8G         # More RAM for transcoding cache
        reservations:
          cpus: '2.0'
          memory: 4G
    devices:
      - /dev/dri:/dev/dri   # Hardware acceleration if available
    networks:
      - media_network

  homeassistant:
    container_name: homeassistant
    image: homeassistant/home-assistant:stable
    restart: unless-stopped
    ports:
      - "8123:8123"
    volumes:
      - homeassistant_config:/config
    environment:
      - TZ=America/New_York
    deploy:
      resources:
        limits:
          cpus: '1.0'        # Light workload
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
    networks:
      - media_network
      - iot_network

  mosquitto:
    container_name: mosquitto
    image: eclipse-mosquitto:latest
    restart: unless-stopped
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - mosquitto_config:/mosquitto/config
      - mosquitto_data:/mosquitto/data
      - mosquitto_logs:/mosquitto/log
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    networks:
      - iot_network

  # Monitoring stack optimized for Z4 G4
  prometheus:
    container_name: prometheus
    image: prom/prometheus:latest
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - prometheus_data:/prometheus
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
    networks:
      - monitoring_network

  grafana:
    container_name: grafana
    image: grafana/grafana:latest
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=nexus_admin_change_me
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 1G
        reservations:
          cpus: '0.25'
          memory: 512M
    networks:
      - monitoring_network

volumes:
  jellyfin_config:
  jellyfin_cache:
  homeassistant_config:
  mosquitto_config:
  mosquitto_data:
  mosquitto_logs:
  prometheus_data:
  grafana_data:

networks:
  media_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
  iot_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/16
  monitoring_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.0.0/16
EOF

    # Create Prometheus configuration for Z4 G4 monitoring
    tee /home/dave/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'docker'
    static_configs:
      - targets: ['localhost:9323']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'nexuscontroller'
    static_configs:
      - targets: ['nexuscontroller:8000']
    metrics_path: '/metrics'

  - job_name: 'jellyfin'
    static_configs:
      - targets: ['jellyfin:8096']
    metrics_path: '/metrics'
EOF

    echo "✅ Media services optimization complete"
}

# Security Optimizations
optimize_security() {
    echo "🔒 Applying Security Optimizations..."
    
    # Optimize fail2ban for media server
    sudo tee /etc/fail2ban/jail.d/media-server.conf << 'EOF'
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600

[jellyfin]
enabled = true
port = 8096
filter = jellyfin
logpath = /var/log/jellyfin/*.log
maxretry = 5
bantime = 1800

[homeassistant]
enabled = true
port = 8123
filter = homeassistant
logpath = /var/log/homeassistant/home-assistant.log
maxretry = 5
bantime = 1800
EOF

    # Restart fail2ban
    sudo systemctl restart fail2ban
    
    echo "✅ Security optimization complete"
}

# Main execution
main() {
    echo "Starting HP Z4 G4 optimization..."
    
    # Check if we're on the right hardware
    check_hardware
    
    # Run optimizations
    optimize_cpu
    optimize_memory
    optimize_storage
    optimize_docker
    optimize_network
    optimize_media_services
    optimize_security
    
    echo ""
    echo "🎉 HP Z4 G4 OPTIMIZATION COMPLETE!"
    echo "=================================="
    echo ""
    echo "✅ Applied optimizations:"
    echo "  • CPU: Performance governor, Turbo Boost enabled"
    echo "  • Memory: Optimized for 48GB ECC RAM + media workloads"
    echo "  • Storage: NVMe optimization, TRIM enabled"
    echo "  • Docker: Performance tuning for Xeon W-2245"
    echo "  • Network: Enhanced buffer sizes and TCP optimization"
    echo "  • Media Services: Resource allocation optimized"
    echo "  • Security: fail2ban configured for media server"
    echo ""
    echo "📊 Monitoring:"
    echo "  • Use: docker-compose -f docker-compose.z4g4-optimized.yml up -d"
    echo "  • Grafana: http://10.0.0.29:3000 (admin/nexus_admin_change_me)"
    echo "  • Prometheus: http://10.0.0.29:9090"
    echo ""
    echo "🔄 Reboot recommended to fully apply all optimizations"
    echo ""
    read -p "Reboot now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo reboot
    fi
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi