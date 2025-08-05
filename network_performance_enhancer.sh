#!/bin/bash
# Network Performance Enhancer
# Optimizes network performance between Dell Latitude 3520 and HP Z4 G4

echo "🌐 NETWORK PERFORMANCE ENHANCER"
echo "==============================="
echo "Optimizing network between:"
echo "  • Dell Latitude 3520 (10.0.0.25) - Dev Workstation"
echo "  • HP Z4 G4 (10.0.0.29) - Media Server"
echo "  • Network: 10.0.0.0/24"
echo ""

# Function to detect current system
detect_system() {
    if lscpu | grep -q "Xeon"; then
        echo "z4g4"
    elif lscpu | grep -q "Celeron"; then
        echo "latitude"
    else
        echo "unknown"
    fi
}

# Network Analysis and Optimization
analyze_network() {
    echo "📊 Analyzing Network Performance..."
    
    local system_type=$(detect_system)
    local current_ip=$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')
    
    echo "Current system: $system_type"
    echo "Current IP: $current_ip"
    
    # Test connectivity between systems
    if [ "$current_ip" = "10.0.0.25" ]; then
        echo "Testing connectivity from Latitude to Z4 G4..."
        target_ip="10.0.0.29"
    elif [ "$current_ip" = "10.0.0.29" ]; then
        echo "Testing connectivity from Z4 G4 to Latitude..."
        target_ip="10.0.0.25"
    else
        echo "Warning: Not on expected network segment"
        target_ip="10.0.0.1"
    fi
    
    # Ping test
    echo "Ping test to $target_ip:"
    ping -c 5 $target_ip | tail -1
    
    # Network interface detection
    echo ""
    echo "Network interfaces:"
    ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|enp|wlp)' | while read interface; do
        speed=$(ethtool $interface 2>/dev/null | grep Speed | awk '{print $2}' || echo "Unknown")
        echo "  $interface: $speed"
    done
    
    echo "✅ Network analysis complete"
}

# Optimize TCP/IP Stack
optimize_tcp_stack() {
    echo "🔧 Optimizing TCP/IP Stack..."
    
    # Create network optimizations based on system type
    local system_type=$(detect_system)
    
    if [ "$system_type" = "z4g4" ]; then
        # Z4 G4 Server optimizations
        sudo tee -a /etc/sysctl.conf << 'EOF'

# HP Z4 G4 Network Optimizations (Server Role)
# Optimized for serving media content to development workstation

# TCP Buffer sizes for media streaming
net.core.rmem_default=262144
net.core.rmem_max=33554432
net.core.wmem_default=262144  
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 131072 33554432
net.ipv4.tcp_wmem=4096 131072 33554432

# Network performance
net.core.netdev_max_backlog=10000
net.core.netdev_budget=600
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_fastopen=3

# Server-specific optimizations
net.ipv4.tcp_max_syn_backlog=8192
net.core.somaxconn=32768
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30

# Media streaming optimizations
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
EOF

    elif [ "$system_type" = "latitude" ]; then
        # Latitude client optimizations
        sudo tee -a /etc/sysctl.conf << 'EOF'

# Dell Latitude 3520 Network Optimizations (Client Role)
# Optimized for development and media consumption

# TCP Buffer sizes for client workloads
net.core.rmem_default=131072
net.core.rmem_max=16777216
net.core.wmem_default=131072
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216

# Client performance optimizations
net.core.netdev_max_backlog=5000
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_fastopen=1

# Development workload optimizations
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_intvl=75
net.ipv4.tcp_fin_timeout=30
EOF
    fi
    
    # Apply settings
    sudo sysctl -p
    
    echo "✅ TCP/IP optimization complete"
}

# Optimize Network Interfaces
optimize_interfaces() {
    echo "🔌 Optimizing Network Interfaces..."
    
    # Find active network interfaces
    active_interfaces=$(ip -o link show up | awk -F': ' '{print $2}' | grep -E '^(eth|enp|wlp)')
    
    for interface in $active_interfaces; do
        echo "Optimizing $interface..."
        
        # Get current settings
        current_speed=$(ethtool $interface 2>/dev/null | grep Speed | awk '{print $2}' || echo "Unknown")
        echo "Current speed: $current_speed"
        
        # Optimize ring buffers if supported
        if ethtool -g $interface &>/dev/null; then
            echo "Optimizing ring buffers for $interface..."
            # Set conservative values that work on most hardware
            sudo ethtool -G $interface rx 1024 tx 1024 2>/dev/null || true
        fi
        
        # Enable hardware offloading if supported
        if ethtool -k $interface &>/dev/null; then
            echo "Enabling hardware offloading for $interface..."
            sudo ethtool -K $interface tso on gso on gro on 2>/dev/null || true
            sudo ethtool -K $interface rx-checksumming on tx-checksumming on 2>/dev/null || true
        fi
        
        # Optimize interrupt coalescing if supported
        if ethtool -c $interface &>/dev/null; then
            echo "Optimizing interrupt coalescing for $interface..."
            sudo ethtool -C $interface rx-usecs 50 tx-usecs 50 2>/dev/null || true
        fi
    done
    
    echo "✅ Interface optimization complete"
}

# Create Network Performance Monitor
create_network_monitor() {
    echo "📊 Creating Network Performance Monitor..."
    
    tee /home/dave/network_monitor.sh << 'EOF'
#!/bin/bash
# Network Performance Monitor for Latitude <-> Z4 G4 Communication

echo "🌐 Network Performance Monitor"  
echo "=============================="
echo "Monitoring: Dell Latitude 3520 <-> HP Z4 G4"
echo ""

# Detect current system and target
current_ip=$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')
if [ "$current_ip" = "10.0.0.25" ]; then
    system_name="Dell Latitude 3520"
    target_ip="10.0.0.29"
    target_name="HP Z4 G4"
elif [ "$current_ip" = "10.0.0.29" ]; then
    system_name="HP Z4 G4"
    target_ip="10.0.0.25"
    target_name="Dell Latitude 3520"
else
    system_name="Unknown System"
    target_ip="10.0.0.1"
    target_name="Gateway"
fi

echo "Current System: $system_name ($current_ip)"
echo "Target System: $target_name ($target_ip)"
echo ""

# Network Interface Status
echo "🔌 Network Interfaces:"
ip -o link show up | awk -F': ' '{print $2}' | grep -E '^(eth|enp|wlp)' | while read iface; do
    speed=$(ethtool $iface 2>/dev/null | grep Speed | awk '{print $2}' || echo "Unknown")
    status=$(ip link show $iface | grep -o 'state [A-Z]*' | awk '{print $2}')
    echo "  $iface: $status @ $speed"
done

echo ""

# Ping Test
echo "📡 Connectivity Test:"
ping_result=$(ping -c 3 -W 2 $target_ip 2>/dev/null)
if [ $? -eq 0 ]; then
    avg_time=$(echo "$ping_result" | tail -1 | awk -F'/' '{print $5}')
    echo "  ✅ $target_name: ${avg_time}ms average"
else
    echo "  ❌ $target_name: Unreachable"
fi

# Bandwidth Test (simple iperf3 if available)
if command -v iperf3 &> /dev/null; then
    echo ""
    echo "🚀 Bandwidth Test (if server running on target):"
    timeout 5 iperf3 -c $target_ip -t 3 -f M 2>/dev/null | grep "receiver" | awk '{print "  Bandwidth: " $7 " " $8}' || echo "  Server not available"
fi

echo ""

# Network Statistics
echo "📊 Network Statistics:"
rx_packets=$(cat /sys/class/net/*/statistics/rx_packets | paste -sd+ | bc 2>/dev/null || echo "0")
tx_packets=$(cat /sys/class/net/*/statistics/tx_packets | paste -sd+ | bc 2>/dev/null || echo "0")
rx_errors=$(cat /sys/class/net/*/statistics/rx_errors | paste -sd+ | bc 2>/dev/null || echo "0")
tx_errors=$(cat /sys/class/net/*/statistics/tx_errors | paste -sd+ | bc 2>/dev/null || echo "0")

echo "  RX Packets: $rx_packets"
echo "  TX Packets: $tx_packets" 
echo "  RX Errors: $rx_errors"
echo "  TX Errors: $tx_errors"

echo ""

# TCP Connection Status
echo "🔗 Active Connections to Target:"
netstat -tn 2>/dev/null | grep "$target_ip" | wc -l | awk '{print "  Active connections: " $1}'

echo ""
echo "Last updated: $(date)"
EOF

    chmod +x /home/dave/network_monitor.sh
    
    # Create alias
    echo 'alias netmon="/home/dave/network_monitor.sh"' >> ~/.bashrc
    
    echo "✅ Network monitor created"
}

# Optimize SSH for Development
optimize_ssh() {
    echo "🔐 Optimizing SSH for Development..."
    
    # Create SSH config optimized for local network
    mkdir -p ~/.ssh
    
    # Backup existing config
    [ -f ~/.ssh/config ] && cp ~/.ssh/config ~/.ssh/config.backup
    
    tee ~/.ssh/config << 'EOF'
# Network-optimized SSH configuration for development
# Dell Latitude 3520 <-> HP Z4 G4 communication

# Global optimizations
Host *
    # Connection optimization
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    
    # Performance optimization
    Compression yes
    CompressionLevel 6
    
    # Connection multiplexing
    ControlMaster auto
    ControlPath ~/.ssh/control-%r@%h:%p
    ControlPersist 10m
    
    # Security with performance balance
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Local network hosts
Host z4g4 mediaserver 10.0.0.29
    HostName 10.0.0.29
    User ebon
    # Fast ciphers for local network
    Ciphers chacha20-poly1305@openssh.com
    # Skip host key checking for local network (optional)
    # StrictHostKeyChecking no

Host latitude dev 10.0.0.25  
    HostName 10.0.0.25
    User dave
    Ciphers chacha20-poly1305@openssh.com

# GitHub optimizations
Host github.com
    HostName github.com
    User git
    PreferredAuthentications publickey
    IdentityFile ~/.ssh/id_rsa
    # GitHub-specific optimizations
    TCPKeepAlive yes
    ServerAliveInterval 15
    ServerAliveCountMax 6
EOF

    chmod 600 ~/.ssh/config
    
    # Create SSH key if it doesn't exist
    if [ ! -f ~/.ssh/id_rsa ]; then
        echo "Generating SSH key for development..."
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C "$(whoami)@$(hostname)"
        echo "SSH key generated. Add ~/.ssh/id_rsa.pub to target systems."
    fi
    
    echo "✅ SSH optimization complete"
}

# Create Network Troubleshooting Tools
create_troubleshooting_tools() {
    echo "🛠️  Creating Network Troubleshooting Tools..."
    
    tee /home/dave/network_troubleshoot.sh << 'EOF'
#!/bin/bash
# Network Troubleshooting Tool for Latitude <-> Z4 G4

echo "🔍 Network Troubleshooting Tool"
echo "==============================="

# Basic connectivity test
test_connectivity() {
    echo "📡 Testing Basic Connectivity..."
    
    # Test gateway
    gateway=$(ip route | grep default | awk '{print $3}')
    echo "Gateway ($gateway): $(ping -c 1 -W 2 $gateway >/dev/null 2>&1 && echo '✅ OK' || echo '❌ FAIL')"
    
    # Test DNS
    echo "DNS (1.1.1.1): $(ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 && echo '✅ OK' || echo '❌ FAIL')"
    
    # Test target system
    current_ip=$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')
    if [ "$current_ip" = "10.0.0.25" ]; then
        target="10.0.0.29"
    else
        target="10.0.0.25"
    fi
    echo "Target System ($target): $(ping -c 1 -W 2 $target >/dev/null 2>&1 && echo '✅ OK' || echo '❌ FAIL')"
}

# Network interface diagnostics
check_interfaces() {
    echo ""
    echo "🔌 Network Interface Diagnostics..."
    
    ip -o link show | grep -E '^[0-9]+: (eth|enp|wlp)' | while read line; do
        iface=$(echo $line | awk -F': ' '{print $2}')
        state=$(echo $line | grep -o 'state [A-Z]*' | awk '{print $2}')
        
        echo "Interface: $iface"
        echo "  State: $state"
        
        if [ "$state" = "UP" ]; then
            # Get IP address
            ip_addr=$(ip addr show $iface | grep 'inet ' | awk '{print $2}')
            echo "  IP: ${ip_addr:-None}"
            
            # Get speed if available
            speed=$(ethtool $iface 2>/dev/null | grep Speed | awk '{print $2}' || echo "Unknown")
            echo "  Speed: $speed"
            
            # Check errors
            rx_errors=$(cat /sys/class/net/$iface/statistics/rx_errors 2>/dev/null || echo "0")
            tx_errors=$(cat /sys/class/net/$iface/statistics/tx_errors 2>/dev/null || echo "0")
            echo "  Errors: RX=$rx_errors TX=$tx_errors"
        fi
        echo ""
    done
}

# Port connectivity test
test_ports() {
    echo "🔗 Testing Service Ports..."
    
    current_ip=$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')
    if [ "$current_ip" = "10.0.0.25" ]; then
        target="10.0.0.29"
        services=("8000:NexusController" "8096:Jellyfin" "8123:HomeAssistant" "1883:MQTT")
    else
        target="10.0.0.25"
        services=("22:SSH" "3000:Development")
    fi
    
    for service in "${services[@]}"; do
        port=$(echo $service | cut -d: -f1)
        name=$(echo $service | cut -d: -f2)
        
        if timeout 3 bash -c "</dev/tcp/$target/$port" 2>/dev/null; then
            echo "  $name ($port): ✅ Open"
        else
            echo "  $name ($port): ❌ Closed/Filtered"
        fi
    done
}

# DNS resolution test
test_dns() {
    echo ""
    echo "🔍 DNS Resolution Test..."
    
    test_hosts=("google.com" "github.com" "docker.io")
    
    for host in "${test_hosts[@]}"; do
        resolve_time=$(dig +short +time=2 +tries=1 $host 2>/dev/null | wc -l)
        if [ "$resolve_time" -gt 0 ]; then
            echo "  $host: ✅ Resolved"
        else
            echo "  $host: ❌ Failed"
        fi
    done
}

# Run all tests
echo "Running comprehensive network diagnostics..."
echo ""

test_connectivity
check_interfaces  
test_ports
test_dns

echo ""
echo "Troubleshooting complete!"
EOF

    chmod +x /home/dave/network_troubleshoot.sh
    
    # Create alias
    echo 'alias nettrouble="/home/dave/network_troubleshoot.sh"' >> ~/.bashrc
    
    echo "✅ Troubleshooting tools created"
}

# Main execution
main() {
    echo "Starting network performance optimization..."
    
    # Run optimizations
    analyze_network
    optimize_tcp_stack
    optimize_interfaces
    create_network_monitor
    optimize_ssh
    create_troubleshooting_tools
    
    echo ""
    echo "🎉 NETWORK PERFORMANCE OPTIMIZATION COMPLETE!"
    echo "=============================================="
    echo ""
    echo "✅ Applied optimizations:"
    echo "  • TCP/IP stack tuned for media streaming and development"
    echo "  • Network interfaces optimized with hardware offloading"
    echo "  • SSH configured for fast local network communication"
    echo "  • Network monitoring and troubleshooting tools created"
    echo ""
    echo "🛠️  Available Commands:"
    echo "  • netmon - Monitor network performance"
    echo "  • nettrouble - Network troubleshooting diagnostics"
    echo ""
    echo "🔧 SSH Optimizations:"
    echo "  • Connection multiplexing enabled"
    echo "  • Fast ciphers for local network"
    echo "  • Use 'ssh z4g4' or 'ssh latitude' for quick connections"
    echo ""
    echo "📊 Monitoring:"
    echo "  • Run 'netmon' to check network performance"
    echo "  • Run 'nettrouble' for diagnostics"
    echo ""
    echo "🔄 Network settings applied. Reboot recommended for full effect."
    echo ""
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi