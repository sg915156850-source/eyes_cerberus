#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - guided emergency remediation (manual, interactive)
#
#   ir/emergency_remediation.sh [app_dir_to_quarantine]
#
# Walks a full response: evidence -> kill -> quarantine -> firewall -> (optional)
# quarantine a compromised app directory. Prompts before doing anything.
# Indicators come from ../etc/signatures/. Files are chmod 000, never deleted.
#===============================================================================
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
SIG="$ROOT/etc/signatures"
TS="$(date +%Y%m%d_%H%M%S)"
EV="$ROOT/state/evidence/remediation_$TS"
Q="$ROOT/state/quarantine/remediation_$TS"
APP_DIR="${1:-}"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'; NC=$'\033[0m'
log(){ echo "${GRN}[+]${NC} $*" | tee -a "$ROOT/state/remediation.log"; }
warn(){ echo "${YEL}[!]${NC} $*" | tee -a "$ROOT/state/remediation.log"; }

sig(){ sed -e 's/#.*//' -e '/^[[:space:]]*$/d' -e 's/^[[:space:]]*//;s/[[:space:]]*$//' "$SIG/$1" 2>/dev/null; }

# PIDs whose executable IS $1 (exact /proc/<pid>/exe match, not an argv match).
pids_executing(){
  local t="$1" pid exe
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"; exe="${exe% (deleted)}"
    [ "$exe" = "$t" ] && echo "$pid"
  done
}

mkdir -p "$EV" "$Q" "$ROOT/state"

echo "=============================================="
echo "  Eyes Cerberus - EMERGENCY REMEDIATION"
echo "=============================================="
echo "Indicators : $SIG/{c2_ips,c2_ports,malware_paths}.txt"
echo "Evidence   : $EV"
echo "Quarantine : $Q"
[ -n "$APP_DIR" ] && echo "App to quarantine: $APP_DIR"
echo
read -r -p "Type 'I UNDERSTAND' to proceed: " c
[ "$c" = "I UNDERSTAND" ] || { echo "Cancelled."; exit 1; }

# 1. Evidence -------------------------------------------------------------
log "collecting evidence"
ps auxf                       > "$EV/ps.txt"        2>&1
ss -tanp                      > "$EV/sockets.txt"   2>&1
{ command -v netstat >/dev/null && netstat -tulpn; } > "$EV/netstat.txt" 2>&1
ps -eo pid=,args= | grep -E '(^|/)(nc|ncat|netcat|socat)([[:space:]]|$)' | grep -v grep > "$EV/nc_procs.txt" 2>&1 || true
while read -r p; do [ -f "$p" ] && { cp -p "$p" "$EV/" 2>/dev/null; md5sum "$p" >> "$EV/dropper_hashes.txt"; }; done < <(sig malware_paths.txt)

# 2. Kill ---------------------------------------------------------------
log "killing C2 / dropper processes"
while read -r ip; do
  ss -tanp state established 2>/dev/null | grep -F "$ip" | grep -oE 'pid=[0-9]+' | cut -d= -f2 \
    | while read -r pid; do kill -9 "$pid" 2>/dev/null && log "killed pid $pid (-> $ip)"; done
  pkill -9 -f "nc .*$ip" 2>/dev/null && log "killed nc -> $ip"
done < <(sig c2_ips.txt)
while read -r p; do
  for pid in $(pids_executing "$p"); do kill -9 "$pid" 2>/dev/null && log "killed pid $pid (exe $p)"; done
done < <(sig malware_paths.txt)

# 3. Quarantine dropper files ------------------------------------------
log "quarantining dropper files (chmod 000, not deleted)"
while read -r p; do
  [ -f "$p" ] || continue
  h=$(md5sum "$p" | cut -d' ' -f1)
  cp -p "$p" "$Q/$(basename "$p")_$h" && chmod 000 "$Q/$(basename "$p")_$h" && chmod 000 "$p" \
    && log "quarantined $p"
done < <(sig malware_paths.txt)

# 4. Firewall ---------------------------------------------------------
if command -v iptables >/dev/null; then
  log "applying C2 firewall"
  while read -r ip; do
    iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null || iptables -A OUTPUT -d "$ip" -j DROP
    iptables -C INPUT  -s "$ip" -j DROP 2>/dev/null || iptables -A INPUT  -s "$ip" -j DROP
  done < <(sig c2_ips.txt)
  while read -r port; do
    iptables -C OUTPUT -p tcp --dport "$port" -j DROP 2>/dev/null || iptables -A OUTPUT -p tcp --dport "$port" -j DROP
  done < <(sig c2_ports.txt)
else
  warn "no iptables; skipped firewall"
fi

# 5. Optional: quarantine a compromised app directory ---------------
if [ -n "$APP_DIR" ] && [ -d "$APP_DIR" ]; then
  dst="${APP_DIR%/}.QUARANTINED_$TS"
  read -r -p "Move $APP_DIR -> $dst ? (y/N): " a
  if [[ "$a" =~ ^[Yy]$ ]]; then
    mv "$APP_DIR" "$dst" && log "app quarantined -> $dst"
    mkdir -p "$APP_DIR"
    printf 'Quarantined %s\nOriginal: %s\nDo not run until rebuilt from clean source.\n' "$TS" "$dst" > "$APP_DIR/README_QUARANTINE.txt"
  fi
fi

echo
echo "=============================================="
echo "  DONE.  Evidence: $EV   Quarantine: $Q"
echo "  Next: review evidence, rebuild from clean source, audit deps,"
echo "  then ensure the daemon is running:  ./master.sh status"
echo "=============================================="
