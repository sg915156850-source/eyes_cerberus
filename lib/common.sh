#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/common.sh
# Shared paths, config loading, logging, notify(), and a safe command wrapper.
# Sourced by cerberus.sh and the lib/*.sh modules. Never executed directly.
#===============================================================================
# Deliberately NO `set -e`: the sensor loop must survive a detector command that
# exits non-zero (e.g. a grep with no match). We use `set -uo pipefail` and guard
# risky calls explicitly with run() / `|| true`.
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

# --- Canonical layout -------------------------------------------------------
ETC_DIR="$CERBERUS_ROOT/etc"
SIG_DIR="$ETC_DIR/signatures"
STATE_DIR="$CERBERUS_ROOT/state"
EVIDENCE_DIR="$STATE_DIR/evidence"
QUARANTINE_DIR="$STATE_DIR/quarantine"
BASELINE_DIR="$STATE_DIR/baseline"
EVENTS_LOG="$STATE_DIR/events.jsonl"
RUN_LOG="$STATE_DIR/cerberus.log"
WHITELIST_FILE="$ETC_DIR/whitelist.txt"
CONFIG_FILE="$ETC_DIR/cerberus.env"

mkdir -p "$STATE_DIR" "$EVIDENCE_DIR" "$QUARANTINE_DIR" "$BASELINE_DIR"

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
AUTO_RESPONSE=1
BLOCK_C2_PORTS=0
DRY_RUN=0
NOTIFY_METHOD=log
NOTIFY_MIN_SEVERITY=SOFT
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
# run <cmd...>  : executes, or just logs when DRY_RUN=1. Never aborts the caller.
run() {
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
# emit_event <severity> <category> <pid> <detail>
# Appends a JSON line to events.jsonl and forwards to notify() when the
# severity clears NOTIFY_MIN_SEVERITY.
emit_event() {
  local sev="$1" cat="$2" pid="$3" detail="$4"
  local ts; ts="$(date -Iseconds)"
  local esc_detail
  esc_detail="$(printf '%s' "$detail" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$(printf '%s' "$detail" | sed 's/"/\\"/g')")"
  printf '{"ts":"%s","severity":"%s","category":"%s","pid":"%s","detail":%s}\n' \
    "$ts" "$sev" "$cat" "$pid" "$esc_detail" >> "$EVENTS_LOG"

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
