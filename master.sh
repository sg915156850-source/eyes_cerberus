#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - control wrapper
# Thin front-end over systemd + the events log. The actual work is done by the
# supervised daemon (cerberus.sh run). See README.md.
#===============================================================================
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
UNIT="eyes-cerberus.service"

# Sourced for the layout resolution (repo vs installed) and read_sig(), so the
# wrapper reads the same config and state the daemon does instead of assuming
# everything lives under the checkout.
# shellcheck source=lib/common.sh
source "$ROOT/lib/common.sh"
EVENTS="$EVENTS_LOG"

# Named apart from common.sh's log()/warn(): those write to the run log with a
# timestamp, these are terminal chrome for a human reading the output.
RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'; NC=$'\033[0m'
say_ok()   { echo "${GRN}[+]${NC} $*"; }
say_warn() { echo "${YEL}[!]${NC} $*"; }
say_bad()  { echo "${RED}[-]${NC} $*"; }

have_unit() { systemctl list-unit-files 2>/dev/null | grep -q "^${UNIT}"; }

cmd_status() {
  echo "=== Eyes Cerberus status ==="
  if have_unit; then
    systemctl --no-pager --lines=0 status "$UNIT" 2>/dev/null | head -6
    if systemctl is-active --quiet "$UNIT"; then
      say_ok "daemon: active ($(systemctl show -p MainPID --value "$UNIT"))"
    else
      say_bad "daemon: NOT active  ->  sudo systemctl start $UNIT"
    fi
  else
    say_bad "unit not installed  ->  see 'Install' below"
    echo "  sudo cp $ROOT/systemd/$UNIT /etc/systemd/system/"
    echo "  sudo systemctl daemon-reload && sudo systemctl enable --now $UNIT"
  fi
  echo
  echo "=== C2 firewall ==="
  if command -v iptables >/dev/null 2>&1; then
    iptables -S 2>/dev/null | grep -E 'DROP' \
      | grep -Ef <(read_sig c2_ips.txt; read_sig c2_ports.txt) \
      && say_ok "C2 DROP rules present" || say_warn "no matching C2 DROP rules (daemon applies them on start)"
  else
    say_warn "iptables not available"
  fi
  echo
  echo "=== Known dropper paths ==="
  local p found=0
  while read -r p; do
    [ -e "$p" ] && { say_bad "PRESENT: $p"; found=1; }
  done < <(read_sig malware_paths.txt)
  [ "$found" = 0 ] && say_ok "none present"
  echo
  cmd_digest 1
}

cmd_digest() {
  local days="${1:-1}"
  echo "=== Events (last ${days}d) ==="
  [ -f "$EVENTS" ] || { say_warn "no events log yet ($EVENTS)"; return 0; }
  local since; since="$(date -d "-${days} days" +%s 2>/dev/null || echo 0)"
  awk -v since="$since" '
    {
      ts=$0; sub(/.*"ts":"/,"",ts); sub(/".*/,"",ts);
      cmd="date -d \"" ts "\" +%s 2>/dev/null"; cmd | getline e; close(cmd);
      if (e+0 < since) next;
      sev=$0; sub(/.*"severity":"/,"",sev); sub(/".*/,"",sev);
      cat=$0; sub(/.*"category":"/,"",cat); sub(/".*/,"",cat);
      key=sev"|"cat; count[key]++; last[key]=ts;
    }
    END{
      if (length(count)==0){ print "  (nothing)"; exit }
      for (k in count){ split(k,a,"|"); printf "  %-5s %-16s x%-4d  last %s\n", a[1], a[2], count[k], last[k] }
    }' "$EVENTS" | sort
  echo
  echo "last 5 raw:"
  tail -n 5 "$EVENTS" 2>/dev/null | sed 's/^/  /'
}

case "${1:-status}" in
  status)  cmd_status ;;
  start)   have_unit && exec systemctl start   "$UNIT" || exec "$ROOT/cerberus.sh" run ;;
  stop)    exec systemctl stop    "$UNIT" ;;
  restart) exec systemctl restart "$UNIT" ;;
  scan)    exec "$ROOT/cerberus.sh" scan ;;
  dryscan) exec "$ROOT/cerberus.sh" dryscan ;;
  baseline) exec "$ROOT/cerberus.sh" baseline ;;
  digest)  cmd_digest "${2:-1}" ;;
  logs)    exec journalctl -u "$UNIT" -n "${2:-100}" --no-pager ;;
  help|*)
    cat <<EOF
Eyes Cerberus control wrapper

Usage: $0 <command>
  status         daemon + firewall + dropper-path + recent-events summary
  start|stop|restart   manage the systemd unit
  scan           run one detect+respond pass now
  dryscan        run one detect pass, print findings, take no action
  baseline       rebuild the persistence baseline (do this after a clean review)
  digest [days]  summarise state/events.jsonl (default 1 day)
  logs [n]       journalctl for the unit (default 100 lines)
EOF
    ;;
esac
