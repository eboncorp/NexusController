#!/bin/bash
# Dell Latitude 3520 Development Environment Optimizer
# Optimizes the development workstation for software development

echo "💻 DELL LATITUDE 3520 DEV OPTIMIZER"
echo "==================================="
echo "Hardware: Dell Latitude 3520"  
echo "CPU: Intel Celeron 6305 (2 cores, 2 threads)"
echo "RAM: 16GB DDR4"
echo "Storage: 512GB NVMe SSD"
echo "Target: Development Environment Optimization"
echo ""

# Function to check if running on Latitude 3520
check_hardware() {
    if ! lscpu | grep -q "Celeron"; then
        echo "⚠️  Warning: This script is optimized for Intel Celeron processors"
        echo "Current CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# CPU Optimization for 2-core Celeron
optimize_cpu() {
    echo "🔥 Optimizing CPU (Celeron 6305 - 2 cores)..."
    
    # Use powersave governor to prevent thermal throttling
    echo "Setting CPU governor to powersave for thermal management..."
    echo 'powersave' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
    
    # Create service to maintain CPU settings
    sudo tee /etc/systemd/system/dev-cpu-optimization.service << 'EOF'
[Unit]
Description=Development CPU Optimization for Celeron 6305
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo powersave | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl enable dev-cpu-optimization.service
    
    echo "✅ CPU optimization complete"
}

# Memory Optimization for 16GB RAM
optimize_memory() {
    echo "🧠 Optimizing Memory (16GB DDR4) for Development..."
    
    # Development-focused memory settings
    sudo tee -a /etc/sysctl.conf << 'EOF'

# Dell Latitude 3520 Development Environment Optimization
# Optimized for 16GB RAM with development workloads

# Virtual memory settings for development
vm.swappiness=5                     # Minimize swap usage
vm.vfs_cache_pressure=50           # Balanced cache pressure
vm.dirty_ratio=10                  # Lower dirty ratio for smaller RAM
vm.dirty_background_ratio=3        # Earlier background writeback
vm.overcommit_memory=1             # Allow overcommit for development

# Development-specific optimizations
kernel.shmmax=8589934592           # 8GB shared memory for IDEs
kernel.shmall=2097152              # Shared memory pages
fs.file-max=1048576                # Sufficient open files for development
fs.inotify.max_user_watches=524288 # File watchers for IDEs and build tools

# Network optimizations for development
net.core.rmem_default=131072       # Socket receive buffer
net.core.rmem_max=16777216         # Max socket receive buffer
net.core.wmem_default=131072       # Socket send buffer
net.core.wmem_max=16777216         # Max socket send buffer
EOF

    # Apply settings
    sudo sysctl -p
    
    # Optimize zram for development workloads
    if command -v zramctl &> /dev/null; then
        echo "Configuring zram for development..."
        # Create zram configuration for better memory management
        sudo tee /etc/systemd/system/zram-dev.service << 'EOF'
[Unit]
Description=Zram configuration for development
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'modprobe zram; echo lz4 > /sys/block/zram0/comp_algorithm; echo 4G > /sys/block/zram0/disksize; mkswap /dev/zram0; swapon -p 10 /dev/zram0'
ExecStop=/bin/bash -c 'swapoff /dev/zram0; echo 1 > /sys/block/zram0/reset'
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl enable zram-dev.service
    fi
    
    echo "✅ Memory optimization complete"
}

# Storage Optimization for Development
optimize_storage() {
    echo "💾 Optimizing Storage for Development..."
    
    # NVMe optimization for development workloads
    nvme_drives=$(lsblk -d -o NAME,ROTA | awk '$2=="0" {print $1}' | grep -E '^nvme')
    
    if [ -n "$nvme_drives" ]; then
        echo "Optimizing NVMe for development: $nvme_drives"
        
        for drive in $nvme_drives; do
            # Use mq-deadline for better development workload performance
            echo 'mq-deadline' | sudo tee /sys/block/$drive/queue/scheduler > /dev/null
            
            # Optimize for development I/O patterns
            echo '8' | sudo tee /sys/block/$drive/queue/nr_requests > /dev/null
        done
    fi
    
    # Create development-optimized mount options
    echo "Setting up development-optimized mounts..."
    
    # Enable TRIM
    sudo systemctl enable fstrim.timer
    
    # Optimize tmpfs for development
    sudo tee -a /etc/fstab << 'EOF'

# Development optimizations
tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,size=2G 0 0
tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,size=1G 0 0
EOF

    echo "✅ Storage optimization complete"
}

# Development Tools Optimization
optimize_dev_tools() {
    echo "🛠️  Optimizing Development Tools..."
    
    # Install essential development packages
    echo "Installing development essentials..."
    sudo apt update
    sudo apt install -y \
        build-essential \
        git \
        curl \
        wget \
        vim \
        htop \
        tree \
        jq \
        unzip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release
    
    # Configure Git for better performance
    echo "Configuring Git for performance..."
    git config --global core.preloadindex true
    git config --global core.fscache true
    git config --global gc.auto 256
    
    # Create development workspace structure
    echo "Creating development workspace..."
    mkdir -p ~/Development/{Projects,Tools,Scripts,Docs}
    mkdir -p ~/.local/bin
    
    # Add local bin to PATH if not already there
    if ! echo $PATH | grep -q "$HOME/.local/bin"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    fi
    
    echo "✅ Development tools optimization complete"
}

# IDE and Editor Optimizations
optimize_editors() {
    echo "📝 Optimizing Editors and IDEs..."
    
    # VS Code optimizations for Celeron
    if command -v code &> /dev/null; then
        echo "Configuring VS Code for Celeron performance..."
        
        # Create VS Code settings for performance
        mkdir -p ~/.config/Code/User
        tee ~/.config/Code/User/settings.json << 'EOF'
{
    "files.watcherExclude": {
        "**/.git/objects/**": true,
        "**/.git/subtree-cache/**": true,
        "**/node_modules/*/**": true,
        "**/.hg/store/**": true
    },
    "search.exclude": {
        "**/node_modules": true,
        "**/bower_components": true,
        "**/*.code-search": true
    },
    "files.exclude": {
        "**/.classpath": true,
        "**/.project": true,
        "**/.settings": true,
        "**/.factorypath": true
    },
    "typescript.suggest.autoImports": "off",
    "javascript.suggest.autoImports": "off",
    "extensions.autoUpdate": false,
    "extensions.autoCheckUpdates": false,
    "telemetry.enableTelemetry": false,
    "update.mode": "manual",
    "workbench.startupEditor": "none",
    "git.enabled": true,
    "git.path": "/usr/bin/git",
    "terminal.integrated.gpuAcceleration": "off",
    "editor.minimap.enabled": false,
    "editor.fontLigatures": false,
    "workbench.reduceMotion": "on",
    "editor.smoothScrolling": false,
    "workbench.list.smoothScrolling": false,
    "editor.cursorSmoothCaretAnimation": false
}
EOF
    fi
    
    # Vim optimizations
    echo "Configuring Vim for performance..."
    tee ~/.vimrc << 'EOF'
" Performance optimizations for Celeron
set nocompatible
set ttyfast
set lazyredraw
set synmaxcol=200
set regexpengine=1

" Basic settings
set number
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
set hlsearch
set incsearch
set ignorecase
set smartcase

" Disable heavy features for performance
set noshowmatch
set nocursorline
set nocursorcolumn

" File handling
set noswapfile
set nobackup
set autoread
EOF

    echo "✅ Editor optimization complete"
}

# Network Optimization for Development
optimize_network() {
    echo "🌐 Optimizing Network for Development..."
    
    # DNS optimization for development
    echo "Configuring DNS for development..."
    sudo tee /etc/systemd/resolved.conf << 'EOF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 8.8.8.8#dns.google
DNSOverTLS=yes
Cache=yes
DNSStubListener=yes
ReadEtcHosts=yes
EOF

    sudo systemctl restart systemd-resolved
    
    # SSH optimization for Git operations
    echo "Optimizing SSH for Git..."
    mkdir -p ~/.ssh
    tee ~/.ssh/config << 'EOF'
# SSH optimization for development
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    Compression yes
    ControlMaster auto
    ControlPath ~/.ssh/control-%r@%h:%p
    ControlPersist 10m

# GitHub optimizations
Host github.com
    HostName github.com
    User git
    PreferredAuthentications publickey
    IdentityFile ~/.ssh/id_rsa
EOF

    chmod 600 ~/.ssh/config
    
    echo "✅ Network optimization complete"
}

# Docker Optimization for Development
optimize_docker_dev() {
    echo "🐳 Optimizing Docker for Development..."
    
    # Docker configuration optimized for Celeron
    sudo mkdir -p /etc/docker
    sudo tee /etc/docker/daemon.json << 'EOF'
{
    "storage-driver": "overlay2",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "default-ulimits": {
        "nofile": {
            "hard": 32768,
            "soft": 32768
        }
    },
    "dns": ["1.1.1.1", "8.8.8.8"],
    "max-concurrent-downloads": 3,
    "max-concurrent-uploads": 2,
    "userland-proxy": false,
    "live-restore": true,
    "experimental": false
}
EOF

    # Docker service optimization for limited resources
    sudo mkdir -p /etc/systemd/system/docker.service.d
    sudo tee /etc/systemd/system/docker.service.d/override.conf << 'EOF'
[Service]
# Resource limits for Celeron 6305
LimitNOFILE=32768
LimitNPROC=16384

# Optimize for 2 cores
Environment="GOMAXPROCS=2"
EOF

    # Create development Docker Compose template
    tee ~/Development/docker-compose.dev-template.yml << 'EOF'
version: '3.8'

# Development Docker Compose Template for Dell Latitude 3520
# Celeron 6305 (2 cores), 16GB RAM - Resource-constrained optimization

services:
  # Example development service
  app:
    build: .
    container_name: dev_app
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - .:/app
      - /app/node_modules  # Prevent node_modules bind mount
    environment:
      - NODE_ENV=development
    deploy:
      resources:
        limits:
          cpus: '1.0'        # 50% of Celeron capacity
          memory: 2G         # Reasonable for 16GB system
        reservations:
          cpus: '0.5'
          memory: 1G
    networks:
      - dev_network

  # Database for development
  db:
    image: postgres:13-alpine
    container_name: dev_db
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=devdb
      - POSTGRES_USER=devuser
      - POSTGRES_PASSWORD=devpass
    volumes:
      - db_data:/var/lib/postgresql/data
    deploy:
      resources:
        limits:
          cpus: '0.5'        # Limited for development
          memory: 1G
        reservations:
          cpus: '0.25'
          memory: 512M
    networks:
      - dev_network

  # Redis for caching/sessions
  redis:
    image: redis:6-alpine
    container_name: dev_redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    deploy:
      resources:
        limits:
          cpus: '0.25'
          memory: 256M
        reservations:
          cpus: '0.1'
          memory: 128M
    networks:
      - dev_network

volumes:
  db_data:

networks:
  dev_network:
    driver: bridge
EOF

    sudo systemctl daemon-reload
    sudo systemctl restart docker
    
    echo "✅ Docker development optimization complete"
}

# Development Monitoring Setup
setup_dev_monitoring() {
    echo "📊 Setting up Development Monitoring..."
    
    # Create simple monitoring script for development
    tee ~/Development/Scripts/dev_monitor.sh << 'EOF'
#!/bin/bash
# Simple development environment monitor for Celeron systems

echo "💻 Dell Latitude 3520 Development Monitor"
echo "========================================"
echo "Hardware: Celeron 6305 (2 cores), 16GB RAM"
echo ""

# CPU Usage
echo "🔥 CPU Usage:"
top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print "CPU Usage: " 100 - $1 "%"}'

# Memory Usage  
echo ""
echo "🧠 Memory Usage:"
free -h | awk 'NR==2{printf "RAM: %s/%s (%.2f%%)\n", $3,$2,$3*100/$2 }'

# Disk Usage
echo ""
echo "💾 Disk Usage:"
df -h / | awk 'NR==2{printf "Root: %s/%s (%s)\n", $3,$2,$5}'

# Docker Status (if running)
if systemctl is-active --quiet docker; then
    echo ""
    echo "🐳 Docker Status:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null || echo "No containers running"
fi

# Development Processes
echo ""
echo "🛠️  Development Processes:"
ps aux | grep -E "(code|vim|git|node|python|docker)" | grep -v grep | wc -l | awk '{print $1 " development processes active"}'

# Load Average
echo ""
echo "📈 System Load:"
uptime | awk -F'load average:' '{print "Load Average:" $2}'

echo ""
echo "Last updated: $(date)"
EOF

    chmod +x ~/Development/Scripts/dev_monitor.sh
    
    # Create alias for easy monitoring
    echo 'alias devmon="~/Development/Scripts/dev_monitor.sh"' >> ~/.bashrc
    
    echo "✅ Development monitoring setup complete"
}

# Main execution
main() {
    echo "Starting Dell Latitude 3520 development optimization..."
    
    # Check hardware
    check_hardware
    
    # Run optimizations
    optimize_cpu
    optimize_memory
    optimize_storage
    optimize_dev_tools
    optimize_editors
    optimize_network
    optimize_docker_dev
    setup_dev_monitoring
    
    echo ""
    echo "🎉 DELL LATITUDE 3520 DEV OPTIMIZATION COMPLETE!"
    echo "==============================================="
    echo ""
    echo "✅ Applied optimizations:"
    echo "  • CPU: Powersave governor for thermal management"
    echo "  • Memory: Optimized for 16GB + development workloads"
    echo "  • Storage: NVMe tuned for development I/O patterns"
    echo "  • Development Tools: Git, editors, and workspace setup"
    echo "  • Docker: Resource-constrained configuration"
    echo "  • Network: DNS and SSH optimization"
    echo "  • Monitoring: Development environment monitor"
    echo ""
    echo "🛠️  Development Setup:"
    echo "  • Workspace: ~/Development/{Projects,Tools,Scripts,Docs}"
    echo "  • Monitor: Run 'devmon' to check system status"
    echo "  • Docker: Template at ~/Development/docker-compose.dev-template.yml"
    echo ""
    echo "📝 Editors Optimized:"
    echo "  • VS Code: Performance settings applied"
    echo "  • Vim: Lightweight configuration"
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