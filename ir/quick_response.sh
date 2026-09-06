#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - manual quick-response card
# Break-glass actions for a live incident. NOT run by the daemon.
# Reads indicators from ../etc/signatures/.
#===============================================================================
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
SIG="$ROOT/etc/signatures"
STATE="$ROOT/state"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'; NC=$'\033[0m'
ok(){ echo "${GRN}[+]${NC} $*"; }
warn(){ echo "${YEL}[!]${NC} $*"; }
bad(){ echo "${RED}[-]${NC} $*"; }

sig(){ sed -e 's/#.*//' -e '/^[[:space:]]*$/d' -e 's/^[[:space:]]*//;s/[[:space:]]*$//' "$SIG/$1" 2>/dev/null; }

# PIDs whose executable IS $1 (exact /proc/<pid>/exe match, not an argv match).
pids_executing(){
  local t="$1" d pid exe
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"; exe="${exe% (deleted)}"
    [ "$exe" = "$t" ] && echo "$pid"
  done
}

case "${1:-help}" in
  status)
    echo "== dropper paths =="
    f=0; while read -r p; do [ -e "$p" ] && { bad "PRESENT $p (perms $(stat -c %a "$p"))"; f=1; }; done < <(sig malware_paths.txt)
    [ $f = 0 ] && ok "none present"
    echo "== established sockets to known C2 =="
    hit=0; while read -r ip; do
      ss -tanp state established 2>/dev/null | grep -F "$ip" && hit=1
    done < <(sig c2_ips.txt); [ $hit = 0 ] && ok "none"
    echo "== nc/socat processes =="
    ps -eo pid=,args= | grep -E '(^|/)(nc|ncat|netcat|socat)([[:space:]]|$)' | grep -v grep || ok "none"
    echo "== daemon =="
    systemctl is-active --quiet eyes-cerberus.service && ok "eyes-cerberus active" || warn "eyes-cerberus NOT active"
    ;;

  block)
    command -v iptables >/dev/null || { bad "no iptables"; exit 1; }
    while read -r ip; do
      iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null || iptables -A OUTPUT -d "$ip" -j DROP
      iptables -C INPUT  -s "$ip" -j DROP 2>/dev/null || iptables -A INPUT  -s "$ip" -j DROP
      ok "DROP $ip"
    done < <(sig c2_ips.txt)
    while read -r port; do
      iptables -C OUTPUT -p tcp --dport "$port" -j DROP 2>/dev/null || iptables -A OUTPUT -p tcp --dport "$port" -j DROP
      ok "DROP tcp/$port (outbound)"
    done < <(sig c2_ports.txt)
    ;;

  stop)
    warn "killing nc/socat to known C2 and processes on known dropper paths"
    while read -r ip; do pkill -9 -f "nc .*$ip" 2>/dev/null && ok "killed nc -> $ip"; done < <(sig c2_ips.txt)
    while read -r p; do
      for pid in $(pids_executing "$p"); do kill -9 "$pid" 2>/dev/null && ok "killed pid $pid (exe $p)"; done
    done < <(sig malware_paths.txt)
    ;;

  quarantine)
    q="$STATE/quarantine/manual_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$q"
    n=0; while read -r p; do
      [ -f "$p" ] || continue
      h=$(md5sum "$p" | cut -d' ' -f1)
      cp -p "$p" "$q/$(basename "$p")_$h" && chmod 000 "$q/$(basename "$p")_$h" && chmod 000 "$p" \
        && { ok "quarantined $p (original chmod 000, not deleted)"; n=$((n+1)); }
    done < <(sig malware_paths.txt)
    ok "$n file(s) -> $q"
    ;;

  evidence)
    e="$STATE/evidence/manual_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$e"
    ps auxf > "$e/ps.txt" 2>&1; ss -tanp > "$e/sockets.txt" 2>&1
    ps -eo pid=,args= | grep -E '(^|/)(nc|ncat|netcat|socat)([[:space:]]|$)' | grep -v grep > "$e/nc_procs.txt" 2>&1
    while read -r p; do [ -f "$p" ] && md5sum "$p" >> "$e/dropper_hashes.txt" 2>&1; done < <(sig malware_paths.txt)
    ok "evidence -> $e"
    ;;

  scan)
    exec "$ROOT/cerberus.sh" dryscan
    ;;

  *)
    cat <<EOF
Eyes Cerberus quick-response (manual)
Usage: $0 {status|block|stop|quarantine|evidence|scan}
  status      show dropper paths / C2 sockets / nc procs / daemon
  block       iptables DROP for all known C2 IPs + ports
  stop        kill nc/socat to C2 and anything running a known dropper path
  quarantine  copy + chmod 000 files at known dropper paths (never deletes)
  evidence    dump ps / sockets / hashes to state/evidence/manual_*
  scan        one-shot dryscan via the daemon
EOF
    ;;
esac
