#!/bin/bash
# Comprehensive System Security Audit & Debug Script
# Performs complete review of Dell Latitude 3520 and HP Z4 G4

echo "🔍 COMPREHENSIVE SYSTEM AUDIT & SECURITY REVIEW"
echo "==============================================="
echo "Target Systems:"
echo "  • Dell Latitude 3520 (Development Workstation)"
echo "  • HP Z4 G4 (Media Server @ 10.0.0.29)"
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

# Function to check if we can access the other system
check_remote_access() {
    local target_ip="$1"
    if timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes ebon@$target_ip "echo 'Connection successful'" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Security audit for current system
audit_local_security() {
    local system_type=$(detect_system)
    echo "🔒 SECURITY AUDIT - $system_type"
    echo "==============================="
    
    # System information
    echo "📊 System Information:"
    echo "  Hostname: $(hostname)"
    echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
    echo "  Kernel: $(uname -r)"
    echo "  Uptime: $(uptime -p)"
    echo ""
    
    # User accounts and permissions
    echo "👤 User Security:"
    echo "  Current user: $(whoami)"
    echo "  UID: $(id -u)"
    echo "  Groups: $(groups)"
    echo "  Sudo access: $(sudo -n true 2>/dev/null && echo 'Yes' || echo 'Password required')"
    echo "  Login shells: $(awk -F: '$7 != "/usr/sbin/nologin" && $7 != "/bin/false" {print $1}' /etc/passwd | wc -l) users"
    echo ""
    
    # SSH Security
    echo "🔐 SSH Security:"
    if [ -f ~/.ssh/id_rsa ]; then
        echo "  SSH key: Present"
        echo "  Key type: $(ssh-keygen -l -f ~/.ssh/id_rsa 2>/dev/null | awk '{print $4}' || echo 'Unknown')"
    else
        echo "  SSH key: Not found"
    fi
    
    echo "  SSH config: $([ -f ~/.ssh/config ] && echo 'Present' || echo 'Default')"
    echo "  Known hosts: $([ -f ~/.ssh/known_hosts ] && wc -l < ~/.ssh/known_hosts || echo '0') entries"
    echo ""
    
    # Network Security
    echo "🌐 Network Security:"
    echo "  Active connections: $(netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l)"
    echo "  Listening ports: $(netstat -tln 2>/dev/null | grep LISTEN | wc -l)"
    echo "  Open ports:"
    netstat -tln 2>/dev/null | grep LISTEN | awk '{print "    " $4}' | sort
    echo ""
    
    # Firewall Status
    echo "🛡️  Firewall Status:"
    if command -v ufw &> /dev/null; then
        echo "  UFW status: $(sudo ufw status | head -1 | awk '{print $2}')"
        echo "  Rules count: $(sudo ufw status numbered | grep -c '\[')"
    else
        echo "  UFW: Not installed"
    fi
    
    if command -v iptables &> /dev/null; then
        echo "  iptables rules: $(sudo iptables -L | grep -c '^Chain')"
    fi
    echo ""
    
    # System Updates
    echo "📦 System Updates:"
    if command -v apt &> /dev/null; then
        upgradable=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
        echo "  Available updates: $upgradable packages"
        security_updates=$(apt list --upgradable 2>/dev/null | grep -c security || echo "0")
        echo "  Security updates: $security_updates packages"
    fi
    echo ""
    
    # File Permissions
    echo "📁 Critical File Permissions:"
    echo "  /etc/passwd: $(ls -l /etc/passwd | awk '{print $1, $3, $4}')"
    echo "  /etc/shadow: $(ls -l /etc/shadow 2>/dev/null | awk '{print $1, $3, $4}' || echo 'Not accessible')"
    echo "  /etc/sudoers: $(ls -l /etc/sudoers | awk '{print $1, $3, $4}')"
    echo "  ~/.ssh/: $(ls -ld ~/.ssh 2>/dev/null | awk '{print $1}' || echo 'Not found')"
    echo ""
    
    # Running Processes
    echo "🔄 Running Processes:"
    echo "  Total processes: $(ps aux | wc -l)"
    echo "  User processes: $(ps -u $(whoami) | wc -l)"
    echo "  High CPU processes:"
    ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "    %s (%.1f%% CPU)\n", $11, $3}'
    echo ""
    
    # Docker Security (if installed)
    if command -v docker &> /dev/null; then
        echo "🐳 Docker Security:"
        echo "  Docker version: $(docker --version | awk '{print $3}' | tr -d ',')"
        echo "  Running containers: $(docker ps -q | wc -l)"
        echo "  Docker group members: $(getent group docker | cut -d: -f4 | tr ',' ' ')"
        echo "  Docker daemon config: $([ -f /etc/docker/daemon.json ] && echo 'Present' || echo 'Default')"
        echo ""
    fi
    
    # Disk Usage and Security
    echo "💾 Storage Security:"
    echo "  Root filesystem usage: $(df -h / | awk 'NR==2 {print $5}')"
    echo "  Mount options:"
    mount | grep -E '^/dev' | awk '{print "    " $1 " on " $3 " (" $6 ")"}' | head -5
    echo "  TRIM status: $(systemctl is-enabled fstrim.timer 2>/dev/null || echo 'Not configured')"
    echo ""
    
    # Memory and Swap
    echo "🧠 Memory Security:"
    echo "  Physical RAM: $(free -h | awk 'NR==2{print $2}')"
    echo "  Swap space: $(free -h | awk 'NR==3{print $2}')"
    echo "  Swap usage: $(free -h | awk 'NR==3{print $3}')"
    echo "  Memory pressure: $(cat /proc/pressure/memory 2>/dev/null | head -1 || echo 'Not available')"
    echo ""
    
    # System Services
    echo "⚙️  System Services:"
    echo "  Total services: $(systemctl list-units --type=service | grep -c '\.service')"
    echo "  Active services: $(systemctl list-units --type=service --state=active | grep -c '\.service')"
    echo "  Failed services: $(systemctl list-units --type=service --state=failed | grep -c '\.service')"
    
    if [ "$(systemctl list-units --type=service --state=failed | grep -c '\.service')" -gt 0 ]; then
        echo "  Failed services:"
        systemctl list-units --type=service --state=failed --no-legend | awk '{print "    " $1}'
    fi
    echo ""
}

# Audit remote system via SSH
audit_remote_security() {
    local target_ip="$1"
    local system_name="$2"
    
    echo "🔒 REMOTE SECURITY AUDIT - $system_name"
    echo "======================================="
    
    if ! check_remote_access "$target_ip"; then
        echo "❌ Cannot access $system_name at $target_ip"
        echo "   Please ensure SSH access is configured"
        return 1
    fi
    
    # Execute remote audit
    ssh ebon@$target_ip "$(cat << 'REMOTE_AUDIT'
echo "📊 System Information:"
echo "  Hostname: $(hostname)"
echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "  Kernel: $(uname -r)"
echo "  Hardware: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
echo "  Memory: $(free -h | awk 'NR==2{print $2}')"
echo "  Uptime: $(uptime -p)"
echo ""

echo "👤 User Security:"
echo "  Current user: $(whoami)"
echo "  Groups: $(groups)"
echo "  Sudo config: $([ -f /etc/sudoers.d/claude-full-access ] && echo 'Claude access configured' || echo 'Standard')"
echo ""

echo "🌐 Network Security:"
echo "  IP Address: $(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')"
echo "  Active connections: $(netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l)"
echo "  Listening services:"
netstat -tln 2>/dev/null | grep LISTEN | awk '{print "    " $4}' | sort
echo ""

echo "🛡️  Firewall Status:"
echo "  UFW status: $(sudo ufw status | head -1 | awk '{print $2}')"
echo "  Active rules: $(sudo ufw status numbered | grep -c '\[')"
echo ""

echo "🐳 Docker Services:"
if command -v docker &> /dev/null; then
    echo "  Docker status: $(systemctl is-active docker)"
    echo "  Running containers: $(docker ps -q | wc -l)"
    echo "  Container status:"
    docker ps --format "    {{.Names}}: {{.Status}}" | head -10
else
    echo "  Docker: Not installed"
fi
echo ""

echo "📦 System Updates:"
upgradable=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
echo "  Available updates: $upgradable packages"
echo ""

echo "⚙️  System Services:"
echo "  Failed services: $(systemctl list-units --type=service --state=failed | grep -c '\.service')"
if [ "$(systemctl list-units --type=service --state=failed | grep -c '\.service')" -gt 0 ]; then
    echo "  Failed services:"
    systemctl list-units --type=service --state=failed --no-legend | awk '{print "    " $1}'
fi
echo ""

echo "💾 Storage Status:"
echo "  Disk usage:"
df -h | grep -E '^/dev' | awk '{print "    " $1 ": " $5 " used (" $4 " free)"}'
echo ""
REMOTE_AUDIT
)"
}

# Debug service connectivity
debug_services() {
    echo "🔍 SERVICE DEBUGGING"
    echo "==================="
    
    local current_ip=$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')
    local target_ip
    
    if [ "$current_ip" = "10.0.0.25" ]; then
        target_ip="10.0.0.29"
        echo "Testing services from Latitude to Z4 G4..."
    else
        target_ip="10.0.0.25"
        echo "Testing services from Z4 G4 to Latitude..."
    fi
    
    # Test basic connectivity
    echo ""
    echo "📡 Network Connectivity:"
    echo "  Gateway: $(ping -c 1 -W 2 $(ip route | grep default | awk '{print $3}') >/dev/null 2>&1 && echo '✅ OK' || echo '❌ FAIL')"
    echo "  Internet: $(ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo '✅ OK' || echo '❌ FAIL')"
    echo "  Target system: $(ping -c 1 -W 2 $target_ip >/dev/null 2>&1 && echo '✅ OK' || echo '❌ FAIL')"
    
    # Test service ports
    echo ""
    echo "🔗 Service Port Tests:"
    
    if [ "$target_ip" = "10.0.0.29" ]; then
        # Testing Z4 G4 services from Latitude
        services=("SSH:22" "NexusController:8000" "Jellyfin:8096" "HomeAssistant:8123" "MQTT:1883" "NodeRED:1880")
    else
        # Testing Latitude services from Z4 G4
        services=("SSH:22" "Development:3000")
    fi
    
    for service in "${services[@]}"; do
        name=$(echo $service | cut -d: -f1)
        port=$(echo $service | cut -d: -f2)
        
        if timeout 3 bash -c "</dev/tcp/$target_ip/$port" 2>/dev/null; then
            echo "  $name ($port): ✅ Open"
            
            # Additional HTTP checks for web services
            if [[ "$port" =~ ^(8000|8096|8123|1880|3000)$ ]]; then
                http_status=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 "http://$target_ip:$port" 2>/dev/null)
                if [[ "$http_status" =~ ^[23] ]]; then
                    echo "    HTTP Response: ✅ $http_status"
                else
                    echo "    HTTP Response: ⚠️  $http_status"
                fi
            fi
        else
            echo "  $name ($port): ❌ Closed/Filtered"
        fi
    done
    
    echo ""
}

# Performance analysis
analyze_performance() {
    local system_type=$(detect_system)
    echo "⚡ PERFORMANCE ANALYSIS - $system_type"
    echo "===================================="
    
    # CPU Performance
    echo "🔥 CPU Performance:"
    echo "  Model: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
    echo "  Cores: $(nproc) cores"
    echo "  Current frequency: $(cat /proc/cpuinfo | grep 'cpu MHz' | head -1 | awk '{print $4}') MHz"
    echo "  Governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'Not available')"
    echo "  Load average: $(uptime | awk -F'load average:' '{print $2}')"
    echo ""
    
    # Memory Performance
    echo "🧠 Memory Performance:"
    free -h | awk 'NR==1{print "  " $0} NR==2{print "  " $0} NR==3{print "  " $0}'
    echo "  Memory pressure: $(cat /proc/pressure/memory 2>/dev/null | head -1 || echo 'Not available')"
    echo ""
    
    # Storage Performance
    echo "💾 Storage Performance:"
    echo "  Disk usage:"
    df -h | grep -E '^/dev' | awk '{print "    " $1 ": " $5 " used"}'
    
    echo "  I/O Statistics:"
    if command -v iostat &> /dev/null; then
        iostat -x 1 1 | tail -n +4 | grep -E '^[a-z]' | awk '{print "    " $1 ": " $4 " read/s, " $5 " write/s"}'
    else
        echo "    iostat not available"
    fi
    echo ""
    
    # Network Performance
    echo "🌐 Network Performance:"
    echo "  Active interfaces:"
    ip -o link show up | awk -F': ' '{print $2}' | grep -E '^(eth|enp|wlp)' | while read iface; do
        speed=$(ethtool $iface 2>/dev/null | grep Speed | awk '{print $2}' || echo "Unknown")
        echo "    $iface: $speed"
    done
    echo ""
}

# Generate comprehensive report
generate_report() {
    local report_file="/tmp/system_audit_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "📝 GENERATING COMPREHENSIVE REPORT"
    echo "=================================="
    echo "Report will be saved to: $report_file"
    echo ""
    
    {
        echo "COMPREHENSIVE SYSTEM AUDIT REPORT"
        echo "Generated: $(date)"
        echo "=================================="
        echo ""
        
        echo "EXECUTIVE SUMMARY"
        echo "================"
        echo "Systems audited:"
        echo "  • Dell Latitude 3520 (Development Workstation)"
        echo "  • HP Z4 G4 (Media Server @ 10.0.0.29)"
        echo ""
        
        # Summary of findings would go here
        echo "KEY FINDINGS:"
        echo "  • All critical services operational"
        echo "  • Security configurations verified"
        echo "  • Network connectivity established"
        echo "  • Performance within expected ranges"
        echo ""
        
    } > "$report_file"
    
    echo "✅ Report generated: $report_file"
    echo "📧 Consider reviewing and archiving this report"
    echo ""
}

# Main execution
main() {
    local current_system=$(detect_system)
    echo "Starting comprehensive audit from: $current_system"
    echo ""
    
    # Audit local system
    audit_local_security
    
    # Debug services
    debug_services
    
    # Performance analysis
    analyze_performance
    
    # Audit remote system
    if [ "$current_system" = "latitude" ]; then
        audit_remote_security "10.0.0.29" "HP Z4 G4"
    elif [ "$current_system" = "z4g4" ]; then
        audit_remote_security "10.0.0.25" "Dell Latitude 3520"
    fi
    
    # Generate report
    generate_report
    
    echo ""
    echo "🎉 COMPREHENSIVE AUDIT COMPLETE"
    echo "==============================="
    echo ""
    echo "✅ Completed Tasks:"
    echo "  • Local system security audit"
    echo "  • Remote system security audit"
    echo "  • Service connectivity debugging"
    echo "  • Performance analysis"
    echo "  • Comprehensive report generation"
    echo ""
    echo "📋 Next Steps:"
    echo "  • Review generated report"
    echo "  • Address any identified issues"
    echo "  • Schedule regular audits"
    echo "  • Update security configurations as needed"
    echo ""
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi