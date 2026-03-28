# 👁️ Eyes Cerberus

**Automated Malware Detection, Containment & Defense System**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-4.0+-blue.svg)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-Defense-red.svg)](https://github.com/sg915156850-source/eyes_cerberus)

---

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/sg915156850-source/eyes_cerberus.git
cd eyes_cerberus

# Make scripts executable
chmod +x *.sh defense/*.sh

# Start monitoring
./master.sh start

# Check status
./master.sh status
```

---

## 📖 Description

**Eyes Cerberus** is an automated malware detection and containment system inspired by the "System Eyes" concept. It continuously monitors your server for suspicious processes, network connections, and known malware signatures, then automatically isolates threats without deleting them (preserving evidence for forensic analysis).

### Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Auto-Detection** | Monitors CPU usage, network connections, known malware patterns |
| ⚔️ **Auto-Kill** | Terminates malicious processes immediately |
| 📦 **Auto-Isolation** | Copies malware to quarantine without deleting originals |
| 🚫 **Auto-Block** | Blocks network access to C2 servers via iptables |
| 📊 **Evidence Collection** | Logs all activity for forensic analysis |
| 🍯 **Honeypot** | Optional decoy system to trap attackers |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    EYES CERBERUS SYSTEM                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │  watcher.sh │    │  auto_      │    │  defense/   │        │
│  │  (CPU mon)  │    │  containment│    │  anti_      │        │
│  │             │    │  (auto-kill)│    │  malware.sh │        │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘        │
│         │                  │                  │                │
│         └──────────────────┼──────────────────┘                │
│                            ▼                                    │
│                   ┌─────────────────┐                          │
│                   │  master.sh      │                          │
│                   │  (control hub)  │                          │
│                   └────────┬────────┘                          │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         ▼                  ▼                  ▼                │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │  /var/      │    │  evidence/  │    │  iptables   │        │
│  │  malware_   │    │  (forensic  │    │  (network   │        │
│  │  contain/   │    │   logs)     │    │   block)    │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
eyes_cerberus/
├── master.sh              # Main control script
├── watcher.sh             # CPU-based process monitoring
├── auto_containment.sh    # Automated malware response
├── quick_response.sh      # Emergency response commands
├── containment.sh         # Docker-based isolation
├── honeypot.sh            # Attacker trap system
├── emergency_remediation.sh # Full incident response
│
├── defense/
│   ├── anti_malware.sh    # Signature-based detection
│   ├── defense_config.cfg # Configuration
│   └── quarantine/        # Isolated malware samples
│
├── evidence/              # Forensic evidence storage
├── logs/                  # System logs
│
├── README.md              # This file
├── LICENSE                # MIT License
└── KNOWN_THREATS.md       # Known malware signatures
```

---

## 🛡️ Detection Capabilities

### Automatically Detects & Neutralizes:

| Threat Type | Patterns | Action |
|-------------|----------|--------|
| **C2 Connections** | `nc 107.175.89.136`, `nc 87.121.84.56` | Kill + Block IP |
| **Port 9009** | `nc .* 9009` | Kill + Block Port |
| **Crypto Miners** | `xmrig`, `minerd`, `cpuminer` | Kill + Isolate |
| **Mining Pools** | `nanopool.org`, `nicehash.com` | Kill Connection |
| **Known Hashes** | MD5 from `known_malware_hashes.txt` | Kill + Isolate |
| **High CPU** | >60% (non-whitelisted) | Alert + Check Hash |

---

## ⚡ Quick Commands

### Start/Stop Monitoring

```bash
# Start all services
./master.sh start

# Stop all services
./master.sh stop

# Check status
./master.sh status
```

### Emergency Response

```bash
# Stop malicious processes
./quick_response.sh stop

# Block C2 servers
./quick_response.sh block

# Collect evidence
./quick_response.sh evidence

# Quarantine malware
./quick_response.sh quarantine

# Start monitoring
./quick_response.sh monitor
```

### Manual Operations

```bash
# Scan for malware
./defense/anti_malware.sh scan

# Generate report
./master.sh report

# View logs
tail -f logs/auto_containment.log
```

---

## 🔧 Configuration

### Edit `defense/defense_config.cfg`:

```bash
# CPU threshold (percentage)
CPU_THRESHOLD=60

# Monitoring interval (seconds)
MONITOR_INTERVAL=10

# Known malicious IPs
MALICIOUS_IPS="107.175.89.136 87.121.84.56"

# Block suspicious ports
BLOCK_PORTS="9009 14444 4444 5555"
```

### Whitelist Safe Processes

Edit `white_list.txt`:
```
node
postgres
nginx
python3
```

---

## 📊 Evidence & Forensics

All detected threats are logged to `evidence/`:

```
evidence/
├── auto_YYYYMMDD_HHMMSS/
│   ├── process_<PID>.txt    # Process information
│   ├── metadata.log         # Malware metadata
│   └── network_blocks.log   # Blocked connections
└── malware_hashes.txt       # Known malware signatures
```

### Isolation Storage

Malware copies are stored in:
```
/var/malware_containment/malware/
├── let_root_<hash>
├── let_var_<hash>
├── let_dev_<hash>
└── ...
```

**Note:** Original files are NOT deleted (chmod 000) to avoid triggering malware self-defense mechanisms.

---

## 🐳 Docker Isolation (Optional)

For enhanced isolation, use Docker containment:

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Setup containment
./containment.sh setup

# Check status
./containment.sh status
```

This creates a fully isolated container with:
- No network access
- Limited resources (256MB RAM, 5% CPU)
- Read-only filesystem
- Full activity monitoring

---

## 🔍 Known Threats

### Tracked Signatures

| MD5 | Description |
|-----|-------------|
| `ac65b89c09bbb53406dad3d42915c231` | `/let` - UPX packed ELF backdoor |

### Tracked C2 Servers

| IP | Port | Description |
|----|------|-------------|
| `107.175.89.136` | 9009 | Command & Control #1 |
| `87.121.84.56` | 9009 | Command & Control #2 |

---

## 🚨 Incident Response

If you detect an active infection:

1. **Stop malicious processes:**
   ```bash
   ./quick_response.sh stop
   ```

2. **Block network access:**
   ```bash
   ./quick_response.sh block
   ```

3. **Collect evidence:**
   ```bash
   ./quick_response.sh evidence
   ```

4. **Quarantine malware:**
   ```bash
   ./quick_response.sh quarantine
   ```

5. **Enable continuous monitoring:**
   ```bash
   ./quick_response.sh monitor
   ```

---

## 📈 Monitoring Dashboard

Check current protection status:

```bash
./master.sh status
```

Example output:
```
═══════════════════════════════════════════════════
       SYSTEM EYES - DEFENSE COMMAND CENTER
═══════════════════════════════════════════════════

=== System Status ===

[+] Watcher: RUNNING (PID: 12345)
[+] Anti-Malware: RUNNING
[+] Honeypot: NOT STARTED

=== Malware Check ===

[+] Malware /let: NOT PRESENT
[+] Malicious NC processes: NONE

═══════════════════════════════════════════════════
```

---

## 🔐 Security Considerations

### What This System Does:
- ✅ Monitors processes and network connections
- ✅ Automatically kills detected threats
- ✅ Isolates malware samples (without deletion)
- ✅ Blocks known C2 servers
- ✅ Collects forensic evidence

### What This System Does NOT Do:
- ❌ Delete malware files (preserves evidence)
- ❌ Modify system files
- ❌ Send data externally
- ❌ Replace antivirus software
- ❌ Guarantee 100% protection

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**This tool is for defensive security purposes only.** Use responsibly and only on systems you own or have explicit permission to monitor. The authors are not responsible for any misuse or damage caused by this software.

**Important:** This system does NOT delete malware files - it isolates them. This is intentional for forensic preservation. If you need complete removal, additional manual steps are required.

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/sg915156850-source/eyes_cerberus/issues)
- **Discussions:** [GitHub Discussions](https://github.com/sg915156850-source/eyes_cerberus/discussions)

---

## 🙏 Acknowledgments

- Inspired by the "System Eyes" concept
- Built with ❤️ for the security community

---

**"The eyes of the system never close"** 👁️
