# Integrated Infrastructure Security & Networking Plan
**Current Reality:** Dell Latitude 3520 (Dev Workstation) + HP Z4 G4 (Media Server at 10.0.0.29)  
**Optimization Goal:** Enhanced Security & Proxmox Migration for Z4 G4

## Phase 1: Current Infrastructure Optimization (Immediate)

### 🔐 YubiKey-Ready Security Framework
Based on your planned YubiKey integration and current hardware:

```bash
# Hybrid Authentication System (Ready Now)
# 1. Session-based control (immediate convenience)
./authorize_claude  # 4-hour access
./revoke_claude     # instant revocation

# 2. YubiKey integration (when hardware arrives)
./yubikey_setup_final.sh  # Activates hardware authentication

# 3. Multi-factor progression:
# - No session + No YubiKey = Password required
# - No session + YubiKey present = Touch YubiKey
# - Active session = Passwordless access
```

### 🌐 Network Architecture (Current Reality → Enhanced)
Your actual current network with HP Z4 G4 as the server:

```
Current Network (Active - 10.0.0.0/24):
├── 10.0.0.1     │ Router/Gateway
├── 10.0.0.25    │ Dell Latitude 3520 (Dev Workstation - Celeron 6305)
├── 10.0.0.29    │ HP Z4 G4 (Media Server - Xeon W-2245, 48GB ECC, Docker)
└── 10.0.0.21    │ HP Printer (Network Direct)

Enhanced Network (Proxmox Migration Plan):
├── Host Level (10.0.0.0/24)
│   ├── 10.0.0.25    │ Dell Latitude (Management/Development)
│   └── 10.0.0.29    │ HP Z4 G4 Proxmox Host (Xeon W-2245)
├── VM Bridge (vmbr0 - Internal)
│   ├── 10.0.0.30    │ NexusController LXC
│   ├── 10.0.0.31    │ Jellyfin VM
│   ├── 10.0.0.32    │ Home Assistant VM
│   ├── 10.0.0.33    │ MQTT Services LXC
│   └── 10.0.0.34    │ Blockchain Nodes VM
└── IoT VLAN (Future - 10.40.40.0/24)
    ├── 10.40.40.21  │ HP Printer (migrated)
    └── 10.40.40.x   │ Smart devices
```

### 🔥 Firewall Rules (Current Enhanced Setup)
```bash
# Current UFW rules optimized for your hardware
sudo ufw allow from 10.0.0.0/24 to any port 8000  # NexusController
sudo ufw allow from 10.0.0.0/24 to any port 8096  # Jellyfin
sudo ufw allow from 10.0.0.0/24 to any port 8123  # Home Assistant
sudo ufw allow from 10.0.0.0/24 to any port 1883  # MQTT
sudo ufw allow from 10.0.0.0/24 to any port 1880  # Node-RED

# Prepare for future blockchain nodes
sudo ufw allow 30303/tcp comment 'Ethereum P2P'
sudo ufw allow 30303/udp comment 'Ethereum P2P'
sudo ufw deny 8545/tcp comment 'Block Ethereum RPC'
```

## Phase 2: Hardware-Optimized Performance (Both Systems)

### ⚡ HP Z4 G4 Server Optimization (Primary Target)
Your media server specs: Xeon W-2125 @ 4.00GHz (4-core/8-thread), 32GB RAM, Dual NVMe (2TB media)

### 💻 Dell Latitude 3520 Development Setup
Your workstation specs: Intel Celeron 6305 (2-core), 16GB RAM, 512GB NVMe

```bash
# CPU optimization for 2-core system
echo 'powersave' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Memory optimization for 16GB system
sudo sysctl vm.swappiness=10
sudo sysctl vm.vfs_cache_pressure=50

# NVMe optimization
sudo fstrim -av  # Enable regular TRIM
echo 'mq-deadline' | sudo tee /sys/block/nvme0n1/queue/scheduler
```

### 🐳 Docker Resource Limits (Tailored for your hardware)
```yaml
# Enhanced docker-compose for media server
version: '3.8'
services:
  nexuscontroller:
    deploy:
      resources:
        limits:
          cpus: '1.0'      # 50% of Celeron capacity
          memory: 2G       # Reasonable for 16GB system
        reservations:
          cpus: '0.5'
          memory: 1G
      restart_policy:
        condition: on-failure
        max_attempts: 3
```

## Phase 3: HP Z4 G4 Proxmox Migration Plan

### 🏗️ Docker → Proxmox Migration Strategy
Your Z4 G4 is already deployed with Docker - now optimizing with Proxmox:

**Current Z4 G4 Hardware (Already Deployed):**
- HP Z4 G4 @ 10.0.0.29 + Xeon W-2125 @ 4.00GHz (4-core/8-thread)
- 32GB DDR4 RAM
- Dual NVMe: 100GB system drive + 2TB media storage
- Currently running: Docker, NexusController, Jellyfin, Home Assistant

**Proxmox Migration Path (Zero Downtime):**
```
Phase 3A: Proxmox Installation (Week 1-2)
├── Backup all current Docker configurations
├── Install Proxmox VE alongside Docker
├── Create VM/LXC templates
└── Test migration with non-critical services

Phase 3B: Service Migration (Week 3-4)
├── Migrate NexusController to LXC (10.0.0.30)
├── Move Jellyfin to dedicated VM (10.0.0.31)
├── Migrate Home Assistant to VM (10.0.0.32)
└── Consolidate MQTT services in LXC (10.0.0.33)

Phase 3C: Optimization & Expansion (Month 2)
├── Deploy blockchain nodes VM (10.0.0.34)
├── Implement Proxmox clustering (single node initially)
├── Configure automated VM backups
└── Add storage expansion planning
```

### 🔒 Security Framework Evolution

**Current → Enhanced Security Progression:**

```
Current Security (Active):
Dell Latitude 3520 → Router → HP Z4 G4 Docker Services
     ↓
Enhanced Security (Proxmox Migration):
Dell Latitude 3520 → Router → HP Z4 G4 Proxmox → VM/LXC Isolation
     ↓
Future Security (Full Implementation):
YubiKey + Session Auth → Proxmox Firewall → Encrypted VM Storage
```

**YubiKey Integration Timeline:**
1. **Now:** Session-based conditional access (implemented ✅)
2. **YubiKey arrival:** Hardware + session hybrid authentication
3. **Proxmox migration:** Enterprise PAM integration with Z4 G4 Proxmox
4. **Future:** Hardware Security Module (HSM) for VM encryption

## Phase 4: Advanced Features Implementation

### 📊 Monitoring & Observability Stack
```yaml
# Comprehensive monitoring for HP Z4 G4 (Current + Proxmox)
Prometheus (Already Planning):
  - Docker metrics (current setup)
  - Proxmox VM/LXC metrics (migration target)
  - System metrics (node_exporter)
  - Blockchain metrics (future expansion)
  
Grafana (Current + Enhanced):
  - Docker service dashboard (active)
  - Proxmox infrastructure monitoring (planned)
  - Network security metrics
  - Hardware utilization (Z4 G4 specific)
  
Uptime Kuma (Integrated):
  - Service availability monitoring
  - VM/Container health checks
  - Mobile notifications
```

### 💾 Backup Strategy (3-2-1 Implementation)
```bash
# Current: Z4 G4 Docker backups (active ✅)
Daily: Docker volumes → Local Z4 G4 storage
Weekly: Configuration files → Git repository
Current: Manual NexusController state preservation

# Enhanced: Proxmox backup strategy
Daily: VM/LXC snapshots → Local ZFS pool
Weekly: Critical data → Offsite cloud storage
Monthly: Full Proxmox backup → External storage
Automated: Proxmox Backup Server integration
```

### 🌐 Network Security Enhancements
```bash
# Current Z4 G4 Docker security (active)
sudo ufw allow from 10.0.0.25 to any port 8000  # NexusController from dev machine
sudo ufw allow from 10.0.0.0/24 to any port 8096  # Jellyfin LAN access
sudo ufw limit ssh  # Rate limit SSH attempts

# Future Proxmox security (planned)
# VM-level firewall rules
iptables -A INPUT -p tcp --dport 30303 -m conntrack --ctstate NEW -m limit --limit 25/minute -j ACCEPT
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT

# Proxmox cluster security
iptables -A INPUT -p tcp --dport 8006 -s 10.0.0.25 -j ACCEPT  # Proxmox web UI from dev machine
```

## Implementation Timeline & Budget

### Immediate Actions (This Week) - $0
- [x] YubiKey-ready authentication system
- [x] Hardware-optimized security settings  
- [x] Enhanced Docker resource management
- [x] Comprehensive monitoring setup

### Short-term (1-3 Months) - $0-200
- [ ] Advanced firewall rules implementation
- [ ] VPN setup for remote access
- [ ] Backup strategy enhancement
- [ ] Network monitoring dashboard

### Medium-term (3-6 Months) - $600-800
- [ ] Managed switch for VLAN segmentation
- [ ] OPNsense firewall hardware
- [ ] UPS for power protection
- [ ] Network cable management

### Long-term (6+ Months) - $1,000-2,000
- [ ] RAM upgrade for Z4 G4 (48GB → 128GB)
- [ ] Storage expansion (additional NVMe + RAID array)
- [ ] Enterprise monitoring stack
- [ ] High-availability clustering setup

## Security Benefits Summary

### Current Infrastructure (Active on Z4 G4 ✅)
- **YubiKey-ready authentication** with session control (implemented)
- **Enterprise hardware deployed** - HP Z4 G4 with Xeon W-2245
- **Docker container orchestration** with NexusController management
- **Media services operational** - Jellyfin, Home Assistant, MQTT
- **Network security active** with UFW firewall rules
- **Backup strategy implemented** with daily automation

### Enhanced Infrastructure (Proxmox Migration Target)
- **Enterprise virtualization** with Proxmox VE on existing Z4 G4
- **VM/LXC isolation** for better security and resource management
- **Blockchain node deployment** with dedicated VMs
- **Advanced monitoring** with Prometheus/Grafana integration
- **Hardware security enhancement** with YubiKey + Proxmox
- **Automated backup strategy** with VM snapshots

## Printer Recommendation Confirmed ✅
Keep the HP printer on the network (10.0.0.21) rather than server-connected:
- **Reliability:** No server dependency
- **Multi-device access:** All devices can print simultaneously
- **Reduced load:** No server resources consumed
- **Network discovery:** Automatic printer detection works
- **Future VLAN:** Will move to IoT VLAN (10.40.40.21) in Phase 3

---

**Your infrastructure is already enterprise-grade with the HP Z4 G4 deployed as your media server. The migration path to Proxmox virtualization will enhance security and resource management while maintaining all current services. YubiKey integration provides immediate authentication enhancement for both the development workstation and the Z4 G4 server.**
