#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus uninstaller.
#
#   sudo ./uninstall.sh            stop, disable, remove code and units
#   sudo ./uninstall.sh --purge    ... and delete config, evidence and quarantine
#
# Without --purge, /etc/eyes-cerberus and /var/lib/eyes-cerberus are left
# alone. That is deliberate: quarantine holds the only copies of neutralised
# payloads and evidence/ is the record of what happened. Nothing about
# uninstalling a daemon says you want that thrown away.
#
# The C2 iptables rules the daemon applied are NOT removed either -- see the
# note printed at the end.
#===============================================================================
set -uo pipefail

CODE_DIR="/opt/eyes-cerberus"
CONF_DIR="/etc/eyes-cerberus"
STATE_DIR="/var/lib/eyes-cerberus"
UNIT_DIR="/etc/systemd/system"
BIN_LINK="/usr/local/sbin/cerberus"
PURGE=0
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --purge)     PURGE=1 ;;
    --code-dir)  CODE_DIR="${2:?}"; shift ;;
    --conf-dir)  CONF_DIR="${2:?}"; shift ;;
    --state-dir) STATE_DIR="${2:?}"; shift ;;
    --unit-dir)  UNIT_DIR="${2:?}"; shift ;;
    --dry-run)   DRY=1 ;;
    -h|--help)   sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
do_() {
  if [ "$DRY" = 1 ]; then printf '    would: %s\n' "$*"; return 0; fi
  "$@" || warn "failed (continuing): $*"
}

[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "[-] must run as root" >&2; exit 1; }

if command -v systemctl >/dev/null 2>&1; then
  say "stopping and disabling the unit"
  do_ systemctl disable --now eyes-cerberus.service
fi

say "removing units"
for unit in eyes-cerberus.service eyes-cerberus-failure.service; do
  [ -e "$UNIT_DIR/$unit" ] && do_ rm -f "$UNIT_DIR/$unit"
done
command -v systemctl >/dev/null 2>&1 && do_ systemctl daemon-reload

if [ -L "$BIN_LINK" ]; then
  say "removing $BIN_LINK"
  do_ rm -f "$BIN_LINK"
fi

if [ -d "$CODE_DIR" ]; then
  say "removing code at $CODE_DIR"
  do_ rm -rf "$CODE_DIR"
fi

if [ "$PURGE" = 1 ]; then
  warn "--purge: deleting configuration, evidence and quarantine"
  for d in "$CONF_DIR" "$STATE_DIR"; do
    [ -d "$d" ] && do_ rm -rf "$d"
  done
else
  cat <<EOF

Kept (delete by hand, or re-run with --purge):
  $CONF_DIR    configuration and signatures
  $STATE_DIR   events.jsonl, evidence/, quarantine/
EOF
fi

cat <<'EOF'

The C2 DROP rules are still in the firewall. They were applied by the daemon
and blocking known-bad addresses does not stop being a good idea when you
uninstall the thing that added them. To review and remove:

    iptables -S | grep DROP
    iptables -D OUTPUT -d <ip> -j DROP
    iptables -D INPUT  -s <ip> -j DROP
EOF
say "done"
