#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/common.sh
# Shared paths, config loading, logging, notify(), and a safe command wrapper.
# Sourced by cerberus.sh and the lib/*.sh modules. Never executed directly.
#===============================================================================
# Deliberately NO `set -e`: the sensor loop must survive a detector command that
# exits non-zero (e.g. a grep with no match). We use `set -uo pipefail` and guard
# risky calls explicitly with run_action() / `|| true`.
set -uo pipefail

# --- Resolve the repo root from this file's location (symlink-safe) ----------
_common_src="${BASH_SOURCE[0]}"
while [ -h "$_common_src" ]; do
  _dir="$(cd -P "$(dirname "$_common_src")" >/dev/null 2>&1 && pwd)"
  _common_src="$(readlink "$_common_src")"
  [[ "$_common_src" != /* ]] && _common_src="$_dir/$_common_src"
done
CERBERUS_ROOT="$(cd -P "$(dirname "$_common_src")/.." >/dev/null 2>&1 && pwd)"
export CERBERUS_ROOT

# --- Layout -----------------------------------------------------------------
# Two supported layouts, because the same tree is both a git checkout you hack
# on and something a package installs system-wide:
#
#   repo  config + state inside the checkout ($ROOT/etc, $ROOT/state).
#         This is what a clone gives you and what the old versions did.
#   fhs   config in /etc/eyes-cerberus, state in /var/lib/eyes-cerberus,
#         code in /opt/eyes-cerberus. What install.sh and the .deb produce.
#
# Chosen by looking for $ROOT/etc/signatures: a checkout has one, an installed
# copy does not (install.sh moves etc/ to /etc/eyes-cerberus). Override with
# CERBERUS_LAYOUT=repo|fhs, or point CERBERUS_CONF_DIR / CERBERUS_STATE_DIR
# straight at the directories -- the tests use those, and so can a second
# instance on the same host.
CERBERUS_LAYOUT="${CERBERUS_LAYOUT:-auto}"
if [ "$CERBERUS_LAYOUT" = "auto" ]; then
  if [ -d "$CERBERUS_ROOT/etc/signatures" ]; then
    CERBERUS_LAYOUT=repo
  else
    CERBERUS_LAYOUT=fhs
  fi
fi

case "$CERBERUS_LAYOUT" in
  repo) _def_conf="$CERBERUS_ROOT/etc";     _def_state="$CERBERUS_ROOT/state" ;;
  fhs)  _def_conf="/etc/eyes-cerberus";     _def_state="/var/lib/eyes-cerberus" ;;
  *)    printf 'cerberus: unknown CERBERUS_LAYOUT=%s (want auto|repo|fhs)\n' \
          "$CERBERUS_LAYOUT" >&2; return 1 2>/dev/null || exit 1 ;;
esac

ETC_DIR="${CERBERUS_CONF_DIR:-$_def_conf}"
STATE_DIR="${CERBERUS_STATE_DIR:-$_def_state}"
export CERBERUS_LAYOUT

SIG_DIR="$ETC_DIR/signatures"
EVIDENCE_DIR="$STATE_DIR/evidence"
QUARANTINE_DIR="$STATE_DIR/quarantine"
BASELINE_DIR="$STATE_DIR/baseline"
EVENTS_LOG="$STATE_DIR/events.jsonl"
RUN_LOG="$STATE_DIR/cerberus.log"
WHITELIST_FILE="$ETC_DIR/whitelist.txt"
CONFIG_FILE="$ETC_DIR/cerberus.env"

# State holds evidence and quarantined malware: root-only, and a hard failure
# if we cannot have it. Everything downstream assumes these exist.
if ! mkdir -p "$STATE_DIR" "$EVIDENCE_DIR" "$QUARANTINE_DIR" "$BASELINE_DIR" 2>/dev/null; then
  printf 'cerberus: cannot create state directory %s (need root, or set CERBERUS_STATE_DIR)\n' \
    "$STATE_DIR" >&2
  return 1 2>/dev/null || exit 1
fi
chmod 750 "$STATE_DIR" 2>/dev/null || true
chmod 700 "$QUARANTINE_DIR" "$EVIDENCE_DIR" 2>/dev/null || true

# --- Config defaults (overridden by etc/cerberus.env) ----------------------
# These are read by the sourcing modules, not by this file; shellcheck cannot
# see that across `source`, hence the SC2034 suppression on the block.
# shellcheck disable=SC2034
{
SENSOR_INTERVAL=30
CPU_THRESHOLD=85
CPU_SUSTAIN_SAMPLES=4
DETECT_HIGH_CPU=1
DETECT_NEW_LISTENER=1
DETECT_PERSISTENCE=1
PERSISTENCE_EVERY=10
DETECT_UPX_NEW=1
DETECT_EGRESS=0
DETECT_REVSHELL=1
DETECT_FILELESS=1
DETECT_SETUID=1
DETECT_LOADER=1
AUTO_RESPONSE=1
BLOCK_C2_PORTS=0
DRY_RUN=0
NOTIFY_METHOD=log
NOTIFY_MIN_SEVERITY=SOFT
LOG_MAX_BYTES=10485760
LOG_KEEP=5
TG_TOKEN=""
TG_CHAT=""
WEBHOOK_URL=""
EMAIL_TO=""
}

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

# CERBERUS_DRY_RUN=1 in the environment forces dry run for this invocation.
if [ "${CERBERUS_DRY_RUN:-0}" = "1" ]; then
  DRY_RUN=1
fi

# --- Logging --------------------------------------------------------------
# Human log -> stdout (journald picks it up under systemd) + state/cerberus.log
log()  { printf '%s [%s] %s\n' "$(date -Iseconds)" "${1:-INFO}" "${*:2}" | tee -a "$RUN_LOG" >&2; }
info() { log INFO  "$*"; }
warn() { log WARN  "$*"; }
err()  { log ERROR "$*"; }

# --- Safe command wrapper -----------------------------------------------
# run_action <cmd...> : executes, or just logs when DRY_RUN=1. Never aborts the
# caller. Named run_action rather than run because `run` is a name the shell
# world already spends -- bats defines its own, and a library that is sourced
# into other people's scripts has no business claiming it.
run_action() {
  if [ "$DRY_RUN" = "1" ]; then
    log DRY "$*"
    return 0
  fi
  "$@"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || { warn "missing tool: $1"; return 1; }
}

# iter_pids : every numeric PID currently in /proc, one per line.
# A glob rather than `ls /proc | grep` so a hostile filename can never be
# word-split into the caller's loop.
iter_pids() {
  local d pid
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    [ -d "$d" ] || continue
    printf '%s\n' "$pid"
  done
}

# --- Log rotation ---------------------------------------------------------
# events.jsonl and cerberus.log used to grow without limit. On a host that is
# actually under attack the event rate is exactly when you least want the disk
# to fill, so the daemon rotates them itself rather than depending on logrotate
# being installed and configured.
rotate_logs() {
  local f sz i
  for f in "$EVENTS_LOG" "$RUN_LOG"; do
    [ -f "$f" ] || continue
    sz="$(stat -c '%s' "$f" 2>/dev/null || echo 0)"
    [ "$sz" -gt "${LOG_MAX_BYTES:-10485760}" ] || continue

    rm -f "$f.${LOG_KEEP:-5}"
    for (( i = ${LOG_KEEP:-5} - 1; i >= 1; i-- )); do
      [ -f "$f.$i" ] && mv -f "$f.$i" "$f.$(( i + 1 ))"
    done
    mv -f "$f" "$f.1"
    : > "$f"
    chmod 640 "$f" 2>/dev/null || true
    info "rotated $(basename "$f") at $sz bytes (keeping ${LOG_KEEP:-5})"
  done
}

# --- Configuration integrity ----------------------------------------------
# check_config_perms : refuse to run when the config or the signatures could be
# modified by someone other than root.
#
# etc/cerberus.env is sourced as bash by a root process, and the signature
# files decide what gets killed and quarantined. Write access to either is
# root access, or a way to point the responder at a legitimate binary. Running
# anyway would be worse than not running at all: the host would look defended.
check_config_perms() {
  local strict=1 bad=0 f mode owner
  [ "$(id -u)" = "0" ] || strict=0

  for f in "$CONFIG_FILE" "$WHITELIST_FILE" "$SIG_DIR" "$SIG_DIR"/*.txt; do
    [ -e "$f" ] || continue
    mode="$(stat -c '%a' "$f" 2>/dev/null)" || continue
    owner="$(stat -c '%u' "$f" 2>/dev/null)" || continue
    if [ $(( 8#$mode & 8#022 )) -ne 0 ]; then
      err "$f is writable by group or other (mode $mode) -- refusing to trust it"
      bad=1
    fi
    if [ "$strict" = "1" ] && [ "$owner" != "0" ]; then
      err "$f is owned by uid $owner, not root -- refusing to trust it"
      bad=1
    fi
  done

  if [ "$bad" = "1" ]; then
    err "fix with: chown -R root:root '$ETC_DIR' && chmod -R go-w '$ETC_DIR'"
    return 1
  fi
  return 0
}

# --- Signature file helpers -------------------------------------------
# read_sig <file> : echo non-comment, non-blank lines (trimmed).
read_sig() {
  local f="$SIG_DIR/$1"
  [ -f "$f" ] || return 0
  sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f" | grep -v '^$' || true
}

# is_whitelisted <comm> : 0 if the (truncated) process name is in whitelist.txt
is_whitelisted() {
  [ -f "$WHITELIST_FILE" ] || return 1
  local c="$1"
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$WHITELIST_FILE" | grep -qxF "$c"
}

# --- Event record + notification --------------------------------------
# json_escape <string> : the string as a JSON string literal, quotes included.
#
# Pure bash on purpose. This used to shell out to python3 on every single
# event -- a dependency that was never declared, with a sed fallback that did
# not escape newlines or control characters. Since the detail field is built
# from process argv, an attacker chose whether events.jsonl stayed parseable:
# one newline in a command line split the record in two and every consumer of
# the log saw a truncated event.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"      # backslash first, or it doubles the escapes below
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\b'/\\b}"
  s="${s//$'\f'/\\f}"

  # Anything else below 0x20 (plus DEL) has to become \u00xx. Rare, so the
  # per-character loop only runs when one is actually present.
  if [[ "$s" == *[[:cntrl:]]* ]]; then
    local out="" i c
    for (( i = 0; i < ${#s}; i++ )); do
      c="${s:i:1}"
      [[ "$c" == [[:cntrl:]] ]] && printf -v c '\\u%04x' "'$c"
      out+="$c"
    done
    s="$out"
  fi
  printf '"%s"' "$s"
}

# emit_event <severity> <category> <pid> <detail>
# Appends a JSON line to events.jsonl and forwards to notify() when the
# severity clears NOTIFY_MIN_SEVERITY.
emit_event() {
  local sev="$1" cat="$2" pid="$3" detail="$4"
  local ts; ts="$(date -Iseconds)"
  printf '{"ts":%s,"severity":%s,"category":%s,"pid":%s,"detail":%s}\n' \
    "$(json_escape "$ts")" "$(json_escape "$sev")" "$(json_escape "$cat")" \
    "$(json_escape "$pid")" "$(json_escape "$detail")" >> "$EVENTS_LOG"

  if [ "$sev" = "HARD" ] || [ "$NOTIFY_MIN_SEVERITY" = "SOFT" ]; then
    notify "$sev" "[$sev/$cat] pid=$pid $detail"
  fi
}

# notify <severity> <message>
notify() {
  local sev="$1" msg="$2"
  case "$NOTIFY_METHOD" in
    telegram)
      if [ -n "$TG_TOKEN" ] && [ -n "$TG_CHAT" ] && require_tool curl; then
        curl -sS --max-time 10 \
          -d "chat_id=${TG_CHAT}" \
          --data-urlencode "text=Cerberus ${sev}: ${msg}" \
          "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" >/dev/null 2>&1 \
          || warn "telegram notify failed"
      else
        warn "NOTIFY_METHOD=telegram but TG_TOKEN/TG_CHAT/curl missing; message: $msg"
      fi
      ;;
    webhook)
      if [ -n "$WEBHOOK_URL" ] && require_tool curl; then
        curl -sS --max-time 10 -H 'Content-Type: application/json' \
          -d "$(printf '{"text":"Cerberus %s: %s"}' "$sev" "$(printf '%s' "$msg" | sed 's/"/\\"/g')")" \
          "$WEBHOOK_URL" >/dev/null 2>&1 || warn "webhook notify failed"
      else
        warn "NOTIFY_METHOD=webhook but WEBHOOK_URL/curl missing; message: $msg"
      fi
      ;;
    email)
      if [ -n "$EMAIL_TO" ] && require_tool mail; then
        printf '%s\n' "$msg" | mail -s "Cerberus $sev alert" "$EMAIL_TO" \
          || warn "email notify failed"
      else
        warn "NOTIFY_METHOD=email but EMAIL_TO/mail missing; message: $msg"
      fi
      ;;
    log|*)
      log ALERT "$msg"
      ;;
  esac
}
