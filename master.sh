#!/usr/bin/env bash
#===============================================================================
# System Eyes - Master Control Script
# Centralized management for all defense modules
#===============================================================================

set -euo pipefail

ROOT="/root/eyes_cerberus"
VERSION="1.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    cat << 'EOF'
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║           SYSTEM EYES - DEFENSE COMMAND CENTER            ║
  ║              Malware Analysis & Protection                ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
EOF
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

#===============================================================================
# STATUS CHECK
#===============================================================================

check_status() {
    echo ""
    echo "=== System Status ==="
    echo ""
    
    # Check watcher
    if [ -f "$ROOT/watcher.pid" ]; then
        pid=$(cat "$ROOT/watcher.pid")
        if kill -0 "$pid" 2>/dev/null; then
            print_success "Watcher: RUNNING (PID: $pid)"
        else
            print_warning "Watcher: NOT RUNNING (stale PID)"
        fi
    else
        print_warning "Watcher: NOT STARTED"
    fi
    
    # Check defense module
    if pgrep -f "anti_malware.sh" > /dev/null 2>&1; then
        print_success "Anti-Malware: RUNNING"
    else
        print_warning "Anti-Malware: NOT RUNNING"
    fi
    
    # Check honeypot
    if [ -f "$ROOT/honeypot/honeypot.pid" ]; then
        pid=$(cat "$ROOT/honeypot/honeypot.pid")
        if kill -0 "$pid" 2>/dev/null; then
            print_success "Honeypot: RUNNING (PID: $pid)"
        else
            print_warning "Honeypot: NOT RUNNING (stale PID)"
        fi
    else
        print_warning "Honeypot: NOT STARTED"
    fi
    
    # Check for malware
    echo ""
    echo "=== Malware Check ==="
    
    if [ -f /let ]; then
        print_error "MALWARE FOUND: /let exists!"
    else
        print_success "Malware /let: NOT PRESENT"
    fi
    
    # Check for malicious processes
    local nc_count
    nc_count=$(ps aux | grep -E "nc\s+(107\.175\.89\.136|87\.121\.84\.56)" | grep -v grep | wc -l)
    
    if [ "$nc_count" -gt 0 ]; then
        print_error "MALICIOUS NC PROCESSES: $nc_count found!"
    else
        print_success "Malicious NC processes: NONE"
    fi
    
    echo ""
}

#===============================================================================
# START ALL SERVICES
#===============================================================================

start_all() {
    print_status "Starting all defense services..."
    echo ""
    
    # Start watcher
    print_status "Starting watcher..."
    nohup "$ROOT/watcher.sh" > "$ROOT/watcher.out" 2>&1 &
    echo $! > "$ROOT/watcher.pid"
    print_success "Watcher started (PID: $(cat $ROOT/watcher.pid))"
    
    # Start defense module in monitor mode
    print_status "Starting anti-malware monitor..."
    nohup "$ROOT/defense/anti_malware.sh" monitor > "$ROOT/defense/monitor.out" 2>&1 &
    print_success "Anti-malware monitor started"
    
    echo ""
    print_success "All services started!"
    check_status
}

#===============================================================================
# STOP ALL SERVICES
#===============================================================================

stop_all() {
    print_status "Stopping all defense services..."
    echo ""
    
    # Stop watcher
    if [ -f "$ROOT/watcher.pid" ]; then
        pid=$(cat "$ROOT/watcher.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            print_success "Watcher stopped (PID: $pid)"
        fi
        rm -f "$ROOT/watcher.pid"
    fi
    
    # Stop anti-malware monitor
    pkill -f "anti_malware.sh" 2>/dev/null && print_success "Anti-malware monitor stopped"
    
    # Stop honeypot
    if [ -f "$ROOT/honeypot/honeypot.pid" ]; then
        pid=$(cat "$ROOT/honeypot/honeypot.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            print_success "Honeypot stopped (PID: $pid)"
        fi
        rm -f "$ROOT/honeypot/honeypot.pid"
    fi
    
    echo ""
    print_success "All services stopped!"
}

#===============================================================================
# RUN MALWARE SCAN
#===============================================================================

run_scan() {
    print_status "Running malware scan..."
    echo ""
    
    "$ROOT/defense/anti_malware.sh" scan
    
    echo ""
    print_status "Scan complete!"
}

#===============================================================================
# GENERATE REPORTS
#===============================================================================

generate_reports() {
    print_status "Generating reports..."
    echo ""
    
    # Defense report
    "$ROOT/defense/anti_malware.sh" report
    
    # Honeypot report (if available)
    if [ -d "$ROOT/honeypot/logs" ]; then
        "$ROOT/honeypot.sh" report
    fi
    
    # System status
    echo ""
    echo "=== Current Process Status ==="
    ps aux --sort=-pcpu | head -10
    
    echo ""
    echo "=== Network Connections (suspicious ports) ==="
    ss -tulpn | grep -E "9009|14444|4444|5555|6666|7777" || echo "None on suspicious ports"
    
    echo ""
    print_success "Reports generated!"
}

#===============================================================================
# BLOCK MALICIOUS IPS
#===============================================================================

block_ips() {
    print_status "Blocking known malicious IPs..."
    echo ""
    
    "$ROOT/defense/anti_malware.sh" block
    
    echo ""
    print_success "IPs blocked!"
}

#===============================================================================
# VIEW LOGS
#===============================================================================

view_logs() {
    local log_file="${1:-$ROOT/hunt.log}"
    
    if [ ! -f "$log_file" ]; then
        print_error "Log file not found: $log_file"
        return 1
    fi
    
    print_status "Showing last 50 lines of $log_file..."
    echo ""
    tail -50 "$log_file"
}

#===============================================================================
# CLEANUP MALWARE
#===============================================================================

cleanup_malware() {
    print_warning "This will QUARANTINE (not delete) all malware samples"
    print_warning "Files will be moved to: $ROOT/defense/quarantine/"
    echo ""
    read -p "Continue? (y/N): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        print_status "Quarantining malware..."
        "$ROOT/defense/anti_malware.sh" scan
        print_success "Cleanup complete!"
    else
        print_status "Cancelled"
    fi
}

#===============================================================================
# HELP
#===============================================================================

show_help() {
    cat << EOF
System Eyes v$VERSION - Malware Defense System

Usage: $0 <command> [options]

Commands:
  status      Check status of all services
  start       Start all defense services
  stop        Stop all defense services
  restart     Restart all services
  scan        Run malware scan
  block       Block known malicious IPs
  report      Generate defense reports
  logs [file] View logs (default: hunt.log)
  cleanup     Quarantine malware samples
  help        Show this help message

Modules:
  watcher.sh      - Process monitoring (CPU-based detection)
  defense/        - Anti-malware defense module
  honeypot.sh     - Honeypot/counter-attack tool

Quick Start:
  $0 start        # Start all services
  $0 status       # Check status
  $0 scan         # Run scan
  $0 report       # Generate reports

Files:
  $ROOT/hunt.log           - Main hunt log
  $ROOT/defense/defense.log    - Defense module log
  $ROOT/honeypot/logs/   - Honeypot logs

EOF
}

#===============================================================================
# MAIN
#===============================================================================

print_banner

case "${1:-status}" in
    status)
        check_status
        ;;
    start)
        start_all
        ;;
    stop)
        stop_all
        ;;
    restart)
        stop_all
        sleep 2
        start_all
        ;;
    scan)
        run_scan
        ;;
    block)
        block_ips
        ;;
    report)
        generate_reports
        ;;
    logs)
        view_logs "${2:-}"
        ;;
    cleanup)
        cleanup_malware
        ;;
    help|*)
        show_help
        ;;
esac
