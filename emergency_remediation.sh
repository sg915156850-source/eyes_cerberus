#!/usr/bin/env bash
#===============================================================================
# System Eyes - Emergency Malware Remediation
# CRITICAL: Active Next.js Application Compromise
#
# ⚠️ WARNING: This script will stop the compromised application!
# Only run if you understand the consequences.
#===============================================================================

set -euo pipefail

ROOT="/root/eyes_cerberus"
EVIDENCE_DIR="$ROOT/evidence"
QUARANTINE_DIR="$ROOT/quarantine"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[*]${NC} $(date -Iseconds) $*" | tee -a "$ROOT/remediation.log"
}

alert() {
    echo -e "${RED}[!]${NC} $(date -Iseconds) $*" | tee -a "$ROOT/remediation.log"
}

success() {
    echo -e "${GREEN}[+]${NC} $(date -Iseconds) $*" | tee -a "$ROOT/remediation.log"
}

#===============================================================================
# PRE-REMEDIATION CHECKS
#===============================================================================

pre_check() {
    echo ""
    echo "=============================================="
    echo "  SYSTEM EYES - EMERGENCY REMEDIATION"
    echo "=============================================="
    echo ""
    echo -e "${RED}⚠️  WARNING: This will stop the compromised application!${NC}"
    echo ""
    echo "Target: Next.js server (PID 4144912)"
    echo "Location: /root/NaviomSite/server-deploy/site/"
    echo ""
    echo "Actions to be taken:"
    echo "  1. Collect forensic evidence"
    echo "  2. Kill malicious processes"
    echo "  3. Quarantine malware files"
    echo "  4. Block C2 network access"
    echo "  5. Quarantine compromised application"
    echo ""
    read -p "Continue? Type 'I UNDERSTAND' to confirm: " confirm
    
    if [ "$confirm" != "I UNDERSTAND" ]; then
        echo "Cancelled."
        exit 1
    fi
    
    echo ""
    log "Starting emergency remediation..."
}

#===============================================================================
# EVIDENCE COLLECTION
#===============================================================================

collect_evidence() {
    log "Collecting forensic evidence..."
    
    mkdir -p "$EVIDENCE_DIR"/{process,network,files,app}
    
    # Find the malicious next-server PID
    local malware_pid
    malware_pid=$(ps aux | grep "next-server.*v15" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$malware_pid" ]; then
        log "Found malicious process: PID $malware_pid"
        
        # Process tree
        pstree -p -a "$malware_pid" > "$EVIDENCE_DIR/process/tree_$TIMESTAMP.txt" 2>/dev/null || true
        
        # Process details
        ps -p "$malware_pid" -o pid,ppid,pcpu,pmem,user,etimes,cmd > "$EVIDENCE_DIR/process/details_$TIMESTAMP.txt" 2>/dev/null || true
        
        # Open files
        lsof -p "$malware_pid" > "$EVIDENCE_DIR/process/open_files_$TIMESTAMP.txt" 2>/dev/null || true
        
        # Network connections
        ss -tulpn | grep "$malware_pid" > "$EVIDENCE_DIR/process/network_$TIMESTAMP.txt" 2>/dev/null || true
        
        # Memory maps
        cat "/proc/$malware_pid/maps" > "$EVIDENCE_DIR/process/memory_maps_$TIMESTAMP.txt" 2>/dev/null || true
        
        # Environment
        tr '\0' '\n' < "/proc/$malware_pid/environ" > "$EVIDENCE_DIR/process/environ_$TIMESTAMP.txt" 2>/dev/null || true
        
        # Current working directory
        ls -la "/proc/$malware_pid/cwd" > "$EVIDENCE_DIR/process/cwd_$TIMESTAMP.txt" 2>/dev/null || true
        
        success "Process evidence collected"
    fi
    
    # Collect all nc processes
    ps aux | grep -E "nc\s+(107\.175\.89\.136|87\.121\.84\.56)" | grep -v grep > "$EVIDENCE_DIR/process/nc_processes_$TIMESTAMP.txt" 2>/dev/null || true
    
    # Network state
    ss -tulpn > "$EVIDENCE_DIR/network/all_connections_$TIMESTAMP.txt" 2>/dev/null || true
    netstat -tulpn > "$EVIDENCE_DIR/network/netstat_$TIMESTAMP.txt" 2>/dev/null || true
    
    # Malware files
    for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
        if [ -f "$f" ]; then
            cp "$f" "$EVIDENCE_DIR/files/" 2>/dev/null || true
            md5sum "$f" > "$EVIDENCE_DIR/files/$(basename $f)_md5.txt" 2>/dev/null || true
        fi
    done
    
    # Application files
    if [ -d /root/NaviomSite/server-deploy/site ]; then
        cp /root/NaviomSite/server-deploy/site/package.json "$EVIDENCE_DIR/app/" 2>/dev/null || true
        cp /root/NaviomSite/server-deploy/site/start.sh "$EVIDENCE_DIR/app/" 2>/dev/null || true
        ls -la /root/NaviomSite/server-deploy/site/.next/standalone/ > "$EVIDENCE_DIR/app/standalone_contents_$TIMESTAMP.txt" 2>/dev/null || true
    fi
    
    success "Evidence collection complete"
}

#===============================================================================
# KILL MALICIOUS PROCESSES
#===============================================================================

kill_malicious() {
    log "Terminating malicious processes..."
    
    # Find and kill the main next-server v15
    local malware_pid
    malware_pid=$(ps aux | grep "next-server.*v15" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$malware_pid" ]; then
        log "Killing main malicious process: PID $malware_pid"
        kill -9 "$malware_pid" 2>/dev/null && success "Killed PID $malware_pid" || true
    fi
    
    # Kill all nc processes to C2 IPs
    log "Killing netcat processes..."
    pkill -9 -f "nc 107.175.89.136" 2>/dev/null && success "Killed nc to 107.175.89.136" || true
    pkill -9 -f "nc 87.121.84.56" 2>/dev/null && success "Killed nc to 87.121.84.56" || true
    
    # Kill all /let processes
    log "Killing /let processes..."
    pkill -9 -f "/let" 2>/dev/null && success "Killed /let processes" || true
    pkill -9 -f "let$" 2>/dev/null && success "Killed let processes" || true
    
    # Kill shell commands spawned by malware
    pkill -9 -f "chmod.*let" 2>/dev/null || true
    
    # Verify
    sleep 2
    local remaining
    remaining=$(ps aux | grep -E "nc\s+(107\.175\.89\.136|87\.121\.84\.56)" | grep -v grep | wc -l)
    
    if [ "$remaining" -eq 0 ]; then
        success "All malicious processes terminated"
    else
        alert "$remaining malicious processes still running!"
    fi
}

#===============================================================================
# QUARANTINE MALWARE FILES
#===============================================================================

quarantine_malware() {
    log "Quarantining malware files..."
    
    mkdir -p "$QUARANTINE_DIR/malware"
    
    local count=0
    for f in /let /var/let /dev/let /dev/shm/let /etc/let /tmp/let; do
        if [ -f "$f" ]; then
            local hash
            hash=$(md5sum "$f" | cut -d' ' -f1)
            mv "$f" "$QUARANTINE_DIR/malware/$(basename $f)_$hash" 2>/dev/null && {
                log "Quarantined: $f"
                ((count++))
            }
        fi
    done
    
    # Also quarantine from standalone directory
    if [ -f /root/NaviomSite/server-deploy/site/.next/standalone/let ]; then
        mv /root/NaviomSite/server-deploy/site/.next/standalone/let \
           "$QUARANTINE_DIR/malware/standalone_let_$(date +%s)" 2>/dev/null && {
            log "Quarantined standalone/let"
            ((count++))
        }
    fi
    
    success "Quarantined $count malware files"
}

#===============================================================================
# BLOCK NETWORK ACCESS
#===============================================================================

block_network() {
    log "Blocking network access to C2 servers..."
    
    # Block C2 IPs
    iptables -A OUTPUT -d 107.175.89.136 -j DROP 2>/dev/null && \
        log "Blocked outbound to 107.175.89.136" || \
        alert "Failed to block 107.175.89.136 (no iptables?)"
    
    iptables -A OUTPUT -d 87.121.84.56 -j DROP 2>/dev/null && \
        log "Blocked outbound to 87.121.84.56" || \
        alert "Failed to block 87.121.84.56"
    
    iptables -A INPUT -s 107.175.89.136 -j DROP 2>/dev/null || true
    iptables -A INPUT -s 87.121.84.56 -j DROP 2>/dev/null || true
    
    # Block port 9009
    iptables -A OUTPUT -p tcp --dport 9009 -j DROP 2>/dev/null && \
        log "Blocked outbound port 9009" || true
    
    success "Network blocks applied"
}

#===============================================================================
# QUARANTINE APPLICATION
#===============================================================================

quarantine_app() {
    log "Quarantining compromised application..."
    
    local app_dir="/root/NaviomSite/server-deploy/site"
    local quarantine_path="/root/NaviomSite/server-deploy/site.QUARANTINED_$TIMESTAMP"
    
    if [ -d "$app_dir" ]; then
        mv "$app_dir" "$quarantine_path"
        success "Application quarantined to: $quarantine_path"
        
        # Create placeholder
        mkdir -p "$app_dir"
        cat > "$app_dir/README_QUARANTINE.txt" << EOF
This application was quarantined due to malware infection.
Date: $TIMESTAMP
Reason: Active compromise - Next.js server spawning malware
Original location: $quarantine_path

DO NOT RUN THIS APPLICATION until it has been:
1. Rebuilt from verified clean source
2. All dependencies audited
3. Build pipeline reviewed

See: /root/eyes_cerberus/CRITICAL_UPDATE.md
EOF
    fi
}

#===============================================================================
# POST-REMEDIATION
#===============================================================================

post_check() {
    echo ""
    log "Post-remediation verification..."
    
    # Check for remaining malicious processes
    local remaining
    remaining=$(ps aux | grep -E "nc\s+(107\.175\.89\.136|87\.121\.84\.56)" | grep -v grep | wc -l)
    
    if [ "$remaining" -eq 0 ]; then
        success "No malicious processes detected"
    else
        alert "WARNING: $remaining malicious processes still running!"
    fi
    
    # Check for malware files
    if [ -f /let ] || [ -f /tmp/let ] || [ -f /var/let ]; then
        alert "WARNING: Malware files still present!"
    else
        success "Malware files removed"
    fi
    
    # Check next-server status
    if ps aux | grep "next-server.*v15" | grep -v grep > /dev/null; then
        alert "WARNING: Compromised next-server v15 still running!"
    else
        success "Compromised next-server stopped"
    fi
    
    echo ""
    echo "=============================================="
    echo "  REMEDIATION COMPLETE"
    echo "=============================================="
    echo ""
    echo "Evidence collected: $EVIDENCE_DIR/"
    echo "Malware quarantined: $QUARANTINE_DIR/"
    echo "Application quarantined: /root/NaviomSite/server-deploy/site.QUARANTINED_$TIMESTAMP"
    echo ""
    echo "NEXT STEPS:"
    echo "  1. Review evidence in $EVIDENCE_DIR/"
    echo "  2. Rebuild application from CLEAN source"
    echo "  3. Audit all npm dependencies"
    echo "  4. Review build pipeline security"
    echo "  5. Start System Eyes monitoring: /root/eyes_cerberus/master.sh start"
    echo ""
    echo "See: /root/eyes_cerberus/CRITICAL_UPDATE.md for full details"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    pre_check
    collect_evidence
    kill_malicious
    quarantine_malware
    block_network
    quarantine_app
    post_check
}

main
