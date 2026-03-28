#!/usr/bin/env bash
set -euo pipefail

ROOT="/root/eyes_cerberus"
M_DIR="$ROOT/m"
HUNT_LOG="$ROOT/hunt.log"
INFO_LOG="$M_DIR/info_about.log"
WHITE="$ROOT/white_list.txt"
# config defaults (can be overridden by /root/eyes_cerberus/config.cfg)
SENSOR_INTERVAL=15       # seconds between sensor polls
ANALYST_DURATION=10      # seconds to gather analyst snapshots
ANALYST_SNAPSHOT=2       # seconds between snapshots during analyst phase
DEEP_LOG=true            # enable deeper logging (ps aux, /proc/[pid]/fd, top snapshot)
CONFIG_FILE="$ROOT/config.cfg"

# load user config if exists
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
  log "Loaded config $CONFIG_FILE"
fi

log() {
  echo "$(date -Iseconds) $*" >> "$HUNT_LOG"
}

mkdir -p "$M_DIR"
touch "$INFO_LOG" "$HUNT_LOG"
[ -f "$WHITE" ] || touch "$WHITE"

collect_info() {
  pid="$1"
  comm="$2"
  cpu="$3"
  args="$4"

  if ! kill -0 "$pid" 2>/dev/null; then
    log "Analyst: PID $pid no longer exists, skipping collection"
    return
  fi

  log "Analyst: collecting info for PID=$pid COMM=$comm CPU=$cpu"
  echo "=== $(date -Iseconds) Detection PID=$pid COMM=$comm CPU=$cpu ARGS=$args ===" >> "$INFO_LOG"

  # note availability
  for tool in lsof pstree; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      log "WARNING: $tool not found"
      echo "WARNING: $tool not found" >> "$INFO_LOG"
    fi
  done

  # collect snapshots for ANALYST_DURATION seconds
  START_SECS=$SECONDS
  while [ $(( SECONDS - START_SECS )) -lt "$ANALYST_DURATION" ]; do
    echo "--- snapshot $(date -Iseconds) ---" >> "$INFO_LOG"

    # lsof (open files & network)
    if command -v lsof >/dev/null 2>&1; then
      echo "lsof -p $pid:" >> "$INFO_LOG"
      lsof -p "$pid" 2>&1 >> "$INFO_LOG" || echo "lsof failed for $pid" >> "$INFO_LOG"
    fi

    # executable path
    echo "ls -l /proc/$pid/exe:" >> "$INFO_LOG"
    ls -l "/proc/$pid/exe" 2>&1 >> "$INFO_LOG" || echo "ls /proc/$pid/exe failed" >> "$INFO_LOG"

    # environ
    echo "environ:" >> "$INFO_LOG"
    if [ -r "/proc/$pid/environ" ]; then
      tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null >> "$INFO_LOG" || echo "cat environ failed" >> "$INFO_LOG"
    else
      echo "cannot read /proc/$pid/environ" >> "$INFO_LOG"
    fi

    # parent tree
    if command -v pstree >/dev/null 2>&1; then
      echo "pstree -s $pid:" >> "$INFO_LOG"
      pstree -s "$pid" 2>&1 >> "$INFO_LOG" || echo "pstree failed for $pid" >> "$INFO_LOG"
    fi

    # deeper artifacts if enabled
    if [ "$DEEP_LOG" = true ]; then
      echo "ps aux | grep \" $pid\" :" >> "$INFO_LOG"
      ps aux | sed -n "1p;$ pid p" 2>/dev/null >> "$INFO_LOG" || ps -p "$pid" -o pid,ppid,pcpu,pmem,user,etimes,cmd 2>&1 >> "$INFO_LOG"

      echo "/proc/$pid/fd listing:" >> "$INFO_LOG"
      ls -l "/proc/$pid/fd" 2>&1 >> "$INFO_LOG" || echo "cannot list /proc/$pid/fd" >> "$INFO_LOG"

      if command -v ss >/dev/null 2>&1; then
        echo "ss -p | grep $pid:" >> "$INFO_LOG"
        ss -p 2>&1 | grep -E "\b$pid\b" || true
      fi

      if command -v top >/dev/null 2>&1; then
        echo "top snapshot for PID $pid:" >> "$INFO_LOG"
        top -b -n1 -p "$pid" 2>&1 >> "$INFO_LOG" || echo "top failed for $pid" >> "$INFO_LOG"
      fi
    fi

    sleep "$ANALYST_SNAPSHOT"
  done

  # Executioner: try graceful then force
  if kill -0 "$pid" 2>/dev/null; then
    log "Executioner: sending SIGTERM to PID $pid"
    kill -15 "$pid" 2>/dev/null || log "Executioner: failed to send SIGTERM to $pid"
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
      log "Executioner: PID $pid still alive, sending SIGKILL"
      kill -9 "$pid" 2>/dev/null || log "Executioner: failed to send SIGKILL to $pid"
    else
      log "Executioner: PID $pid terminated by SIGTERM"
    fi
  else
    log "Executioner: PID $pid already exited before kill"
  fi
}

# Main sensor loop
log "System Eyes watcher started"
while true; do
  # ps: pid comm pcpu args
  ps -eo pid=,comm=,pcpu=,args= | while read -r pid comm pcpu args; do
    # validate pid
    if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
      continue
    fi

    # ignore any process where name or args contain "vscode"
    if [[ "$comm" == *vscode* ]] || [[ "$args" == *vscode* ]]; then
      continue
    fi

    # skip white-listed names (exact match)
    if [ -f "$WHITE" ] && grep -xFq "$comm" "$WHITE" 2>/dev/null; then
      continue
    fi

    # check CPU usage > threshold (60)
    if awk -v v="$pcpu" 'BEGIN{exit !(v+0>60)}'; then
      # double-check pid still exists
      if kill -0 "$pid" 2>/dev/null; then
        log "Potential malicious process detected: PID=$pid COMM=$comm CPU=$pcpu ARGS=$args"
        # also append a brief ps snapshot to hunt log for quick triage
        echo "$(date -Iseconds) ps: $(ps -p $pid -o pid,ppid,pcpu,pmem,user,cmd --no-headers)" >> "$HUNT_LOG"
        collect_info "$pid" "$comm" "$pcpu" "$args"
      fi
    fi
  done
  sleep "$SENSOR_INTERVAL"
done
