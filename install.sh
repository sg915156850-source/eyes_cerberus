#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus installer.
#
#   sudo ./install.sh              install/upgrade, do not start anything
#   sudo ./install.sh --enable     ... and enable + start the unit
#   sudo ./install.sh --dry-run    print what it would do
#
# Idempotent. Re-running upgrades the code and leaves configuration, signatures
# and state alone -- your edited signature files are never overwritten.
#
# Layout produced (all overridable, see --help):
#   /opt/eyes-cerberus       code
#   /etc/eyes-cerberus       cerberus.env, whitelist.txt, signatures/
#   /var/lib/eyes-cerberus   events.jsonl, evidence/, quarantine/, baseline/
#===============================================================================
set -uo pipefail

SRC="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

CODE_DIR="/opt/eyes-cerberus"
CONF_DIR="/etc/eyes-cerberus"
STATE_DIR="/var/lib/eyes-cerberus"
UNIT_DIR="/etc/systemd/system"
BIN_LINK="/usr/local/sbin/cerberus"
DO_ENABLE=0
DRY=0

usage() {
  sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'
  cat <<EOF

Options:
  --enable              enable and start eyes-cerberus.service when done
  --code-dir DIR        default $CODE_DIR
  --conf-dir DIR        default $CONF_DIR
  --state-dir DIR       default $STATE_DIR
  --unit-dir DIR        default $UNIT_DIR
  --no-symlink          do not create $BIN_LINK
  --dry-run             print actions, change nothing
  -h, --help            this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --enable)     DO_ENABLE=1 ;;
    --code-dir)   CODE_DIR="${2:?}"; shift ;;
    --conf-dir)   CONF_DIR="${2:?}"; shift ;;
    --state-dir)  STATE_DIR="${2:?}"; shift ;;
    --unit-dir)   UNIT_DIR="${2:?}"; shift ;;
    --no-symlink) BIN_LINK="" ;;
    --dry-run)    DRY=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[-] %s\n' "$*" >&2; exit 1; }
do_() {
  if [ "$DRY" = 1 ]; then printf '    would: %s\n' "$*"; return 0; fi
  "$@" || die "failed: $*"
}
# Same, but a failure is reported and the install continues. Used for systemd
# calls: installing into a container or a chroot with no booted systemd is a
# legitimate thing to do, and it must not abort after the files are in place.
try_() {
  if [ "$DRY" = 1 ]; then printf '    would: %s\n' "$*"; return 0; fi
  "$@" || { warn "failed (continuing): $*"; return 1; }
}

[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "must run as root (or use --dry-run)"
[ -f "$SRC/cerberus.sh" ] || die "run this from the source tree (no cerberus.sh next to it)"

# --- code -------------------------------------------------------------------
# Explicit list, so nothing accidental (state/, .git, ir/experimental, tests)
# ends up on a production host.
say "installing code -> $CODE_DIR"
do_ mkdir -p "$CODE_DIR"
for item in cerberus.sh master.sh lib ir/quick_response.sh ir/emergency_remediation.sh ir/docker; do
  [ -e "$SRC/$item" ] || continue
  do_ mkdir -p "$CODE_DIR/$(dirname "$item")"
  do_ cp -a "$SRC/$item" "$CODE_DIR/$(dirname "$item")/"
done
for doc in README.md CHANGELOG.md KNOWN_THREATS.md SECURITY.md LICENSE; do
  [ -f "$SRC/$doc" ] && do_ cp -a "$SRC/$doc" "$CODE_DIR/"
done
do_ chown -R root:root "$CODE_DIR"
do_ chmod 755 "$CODE_DIR/cerberus.sh" "$CODE_DIR/master.sh"

# --- configuration ----------------------------------------------------------
# Never clobber operator edits: signature files and whitelist are copied only
# when absent, so an upgrade adds new signature files without discarding the
# indicators someone added by hand.
say "installing configuration -> $CONF_DIR"
do_ mkdir -p "$CONF_DIR/signatures"
do_ cp -a "$SRC/etc/cerberus.env.example" "$CONF_DIR/cerberus.env.example"

for f in "$SRC"/etc/signatures/*.txt; do
  [ -f "$f" ] || continue
  if [ -e "$CONF_DIR/signatures/$(basename "$f")" ]; then
    say "  keeping existing signatures/$(basename "$f")"
  else
    do_ cp -a "$f" "$CONF_DIR/signatures/"
  fi
done
if [ -e "$CONF_DIR/whitelist.txt" ]; then
  say "  keeping existing whitelist.txt"
else
  do_ cp -a "$SRC/etc/whitelist.txt" "$CONF_DIR/whitelist.txt"
fi
if [ -e "$CONF_DIR/cerberus.env" ]; then
  say "  keeping existing cerberus.env"
else
  do_ cp -a "$SRC/etc/cerberus.env.example" "$CONF_DIR/cerberus.env"
  say "  created cerberus.env from the example -- edit it before enabling"
fi

# cerberus.env is sourced as bash by a root process: write access to it is root
# access, and the daemon refuses to start if that is not locked down.
do_ chown -R root:root "$CONF_DIR"
do_ chmod 750 "$CONF_DIR" "$CONF_DIR/signatures"
do_ chmod 600 "$CONF_DIR/cerberus.env"
do_ chmod 640 "$CONF_DIR/whitelist.txt" "$CONF_DIR/cerberus.env.example"
if [ "$DRY" = 0 ]; then chmod 640 "$CONF_DIR"/signatures/*.txt 2>/dev/null || true; fi

# --- state ------------------------------------------------------------------
say "preparing state -> $STATE_DIR"
do_ mkdir -p "$STATE_DIR/evidence" "$STATE_DIR/quarantine" "$STATE_DIR/baseline"

# Upgrading from a repo-local install: carry evidence, quarantine and the
# baseline over, otherwise the first pass after the upgrade reports every
# existing cron job and listener as new.
if [ -d "$SRC/state" ] && [ -z "$(ls -A "$STATE_DIR/baseline" 2>/dev/null)" ]; then
  say "  migrating existing state from $SRC/state (originals left in place)"
  if [ "$DRY" = 0 ]; then
    cp -a "$SRC/state/." "$STATE_DIR/" 2>/dev/null || warn "  partial migration; check $STATE_DIR"
  else
    printf '    would: cp -a %s/state/. %s/\n' "$SRC" "$STATE_DIR"
  fi
fi
do_ chown -R root:root "$STATE_DIR"
do_ chmod 750 "$STATE_DIR"
do_ chmod 700 "$STATE_DIR/evidence" "$STATE_DIR/quarantine"

# --- systemd ----------------------------------------------------------------
say "installing units -> $UNIT_DIR"
do_ mkdir -p "$UNIT_DIR"
for unit in eyes-cerberus.service eyes-cerberus-failure.service; do
  if [ "$DRY" = 1 ]; then
    printf '    would: install %s with paths rewritten to %s\n' "$unit" "$CODE_DIR"
    continue
  fi
  sed -e "s|/opt/eyes-cerberus|$CODE_DIR|g" "$SRC/systemd/$unit" > "$UNIT_DIR/$unit" \
    || die "failed writing $UNIT_DIR/$unit"
  chmod 644 "$UNIT_DIR/$unit"
done

if command -v systemctl >/dev/null 2>&1; then
  try_ systemctl daemon-reload || warn "units copied but not loaded (no booted systemd?)"
else
  warn "systemctl not found; units copied but not loaded"
fi

# --- convenience symlink ----------------------------------------------------
if [ -n "$BIN_LINK" ]; then
  say "linking $BIN_LINK -> $CODE_DIR/master.sh"
  do_ mkdir -p "$(dirname "$BIN_LINK")"
  do_ ln -sfn "$CODE_DIR/master.sh" "$BIN_LINK"
fi

# --- finish -----------------------------------------------------------------
if [ "$DO_ENABLE" = 1 ]; then
  say "enabling and starting eyes-cerberus.service"
  try_ systemctl enable --now eyes-cerberus.service
else
  cat <<EOF

Not started. Review the config first, then:

    \$EDITOR $CONF_DIR/cerberus.env
    $CODE_DIR/cerberus.sh dryscan          # every detector, no action taken
    systemctl enable --now eyes-cerberus.service
    ${BIN_LINK:-$CODE_DIR/master.sh} status
EOF
fi
say "done"
