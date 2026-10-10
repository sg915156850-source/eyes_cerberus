#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/respond.sh
# Tiered response.
#   HARD  -> forensics, then (if AUTO_RESPONSE=1 and not DRY_RUN) kill +
#            quarantine + iptables DROP. Originals are chmod 000, never deleted.
#   SOFT  -> forensics + notify only. The process/file is never touched.
# Sourced after lib/common.sh, lib/forensics.sh.
#===============================================================================

# apply_c2_firewall : idempotently DROP traffic to every known C2 IP + port.
# Called on daemon start (compensates for no netfilter-persistent) and on any
# c2_* finding.
apply_c2_firewall() {
  require_tool iptables || { warn "iptables unavailable; cannot enforce C2 blocks"; return 1; }
  local ip port
  while read -r ip; do
    [ -n "$ip" ] || continue
    iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null || run_action iptables -A OUTPUT -d "$ip" -j DROP
    iptables -C INPUT  -s "$ip" -j DROP 2>/dev/null || run_action iptables -A INPUT  -s "$ip" -j DROP
  done < <(read_sig c2_ips.txt)

  # Port DROPs are opt-in (BLOCK_C2_PORTS=1): an OUTPUT --dport rule blocks
  # outbound to that port on EVERY host, which can catch legitimate traffic
  # (4444/5555 are used by some dev tooling). Blocking the C2 IPs already stops
  # the known beacon.
  [ "${BLOCK_C2_PORTS:-0}" = "1" ] || return 0
  while read -r port; do
    [ -n "$port" ] || continue
    iptables -C OUTPUT -p tcp --dport "$port" -j DROP 2>/dev/null || \
      run_action iptables -A OUTPUT -p tcp --dport "$port" -j DROP
  done < <(read_sig c2_ports.txt)
}

# _quarantine_file <path> <reason>
_quarantine_file() {
  local f="$1" reason="$2"
  [ -f "$f" ] || return 0
  local ts hash base dst
  ts="$(date +%Y%m%d_%H%M%S)"
  hash="$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)"
  base="$(basename "$f")"
  dst="$QUARANTINE_DIR/${ts}_${base}_${hash}"

  # The metadata write goes through the same dry-run gate as everything else.
  # It used to sit outside it, so a --dryscan left files behind in the
  # quarantine directory -- a dry run that writes is not a dry run.
  if [ "$DRY_RUN" = "1" ]; then
    log DRY "write ${dst}.metadata"
  else
    {
      echo "original_path: $f"
      echo "quarantine_copy: $dst"
      echo "reason: $reason"
      echo "time: $(date -Iseconds)"
      echo "md5: $hash"
      echo "sha256: $(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
      echo "perms_before: $(stat -c '%a' "$f" 2>/dev/null)"
      echo "owner: $(stat -c '%U:%G' "$f" 2>/dev/null)"
      echo "size: $(stat -c '%s' "$f" 2>/dev/null)"
    } > "${dst}.metadata"
  fi
  run_action cp -p "$f" "$dst" && run_action chmod 000 "$dst"
  # neutralise the original in place; keep it for forensics (do NOT delete)
  run_action chmod 000 "$f" && info "neutralised original: $f (chmod 000)"
}

# _pids_executing <path> : PIDs whose /proc/<pid>/exe resolves to <path>.
# Deliberately NOT `pgrep -f <path>` -- an argv substring match is far too broad
# (it would match log tails, editors, this very scan) and could kill bystanders.
_pids_executing() {
  local target="$1" pid exe
  while read -r pid; do
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    [ -n "$exe" ] || continue
    exe="${exe% (deleted)}"
    [ "$exe" = "$target" ] && echo "$pid"
  done < <(iter_pids)
}

# _kill_pid <pid>
_kill_pid() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null || { info "pid $pid already gone"; return 0; }
  run_action kill -TERM "$pid"
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" 2>/dev/null || { info "pid $pid stopped after SIGTERM"; return 0; }
    sleep 1
  done
  run_action kill -KILL "$pid" && info "pid $pid SIGKILLed"
  run_action pkill -KILL -P "$pid" 2>/dev/null || true
}

#---------------------------------------------------------------------------
# Quarantine review and rollback.
#
# Auto-response without a way back is the reason people set AUTO_RESPONSE=0
# after the first false positive and never turn it on again. Every quarantined
# file keeps a .metadata sidecar with its original path and permissions, which
# is all that is needed to undo the containment.
#---------------------------------------------------------------------------

# quarantine_list : one line per quarantined item -- id, time, reason, path.
quarantine_list() {
  local meta id
  local found=0
  for meta in "$QUARANTINE_DIR"/*.metadata; do
    [ -e "$meta" ] || continue
    found=1
    id="$(basename "${meta%.metadata}")"
    printf '%s\t%s\t%s\t%s\n' \
      "$id" \
      "$(sed -n 's/^time: //p' "$meta" | head -1)" \
      "$(sed -n 's/^reason: //p' "$meta" | head -1)" \
      "$(sed -n 's/^original_path: //p' "$meta" | head -1)"
  done
  [ "$found" = 1 ] || return 1
  return 0
}

# quarantine_restore <id> : put a quarantined file back where it came from,
# with the permissions it had. The quarantined copy is authoritative -- the
# original on disk was left in place but chmod 000, and may have been tampered
# with since.
quarantine_restore() {
  local id="$1"
  local meta="$QUARANTINE_DIR/${id}.metadata"
  local copy="$QUARANTINE_DIR/${id}"

  if [ ! -f "$meta" ]; then
    err "no such quarantine entry: $id"
    return 1
  fi
  if [ ! -f "$copy" ]; then
    err "metadata for $id exists but the quarantined copy does not"
    return 1
  fi

  local orig perms
  orig="$(sed -n 's/^original_path: //p' "$meta" | head -1)"
  perms="$(sed -n 's/^perms_before: //p' "$meta" | head -1)"
  if [ -z "$orig" ]; then
    err "$meta has no original_path"
    return 1
  fi
  # Restore only to the path it was taken from. An edited metadata file must
  # not turn this into "write anywhere as root".
  case "$orig" in
    /*) ;;
    *) err "original_path is not absolute: $orig"; return 1 ;;
  esac

  info "restoring $id -> $orig (perms ${perms:-600})"
  run_action mkdir -p "$(dirname "$orig")"

  # The quarantined copy is stored chmod 000 so nothing can execute it by
  # accident. Root reads it regardless; anyone else -- an operator reviewing a
  # false positive on their own machine -- cannot, so make it readable for the
  # copy and put it back afterwards.
  run_action chmod u+r "$copy"
  # Same story at the destination: the original was neutralised in place with
  # chmod 000, and its owner cannot open a 000 file for writing. Root never
  # noticed this; anyone else could not restore at all.
  [ -e "$orig" ] && run_action chmod u+w "$orig"
  if ! run_action cp -p "$copy" "$orig"; then
    run_action chmod 000 "$copy"
    err "restore failed"
    return 1
  fi
  run_action chmod 000 "$copy"
  run_action chmod "${perms:-600}" "$orig"
  emit_event SOFT quarantine_restore "-" "restored $id to $orig with perms ${perms:-600}"
  return 0
}

#---------------------------------------------------------------------------
# Repeat suppression for SOFT findings.
#
# A SOFT finding is a question for the operator, and it stays true on every
# pass until someone answers it -- re-baselines, whitelists, fixes the host.
# Re-emitting it every SENSOR_INTERVAL turned a hundred unanswered questions
# into ~50k identical events a day on a busy host: the log rotated real history
# away in under two days, the evidence directory filled with copies of the same
# snapshot, and any push backend would have been muted by its owner -- after
# which a genuine finding goes unread.
#
# So a SOFT finding is reported when it first appears, again every
# ALERT_REPEAT_SECONDS while it persists, and at once if it went away for
# ALERT_FORGET_SECONDS and came back. HARD findings are never suppressed: each
# one is acted on.
#
# The state is keyed by the finding's text. That text can carry an attacker's
# argv, so keys are only ever used as associative-array subscripts in plain
# expansions and assignments -- never inside (( )), [[ -v ]], unset or read,
# where bash evaluates a subscript a second time.
#---------------------------------------------------------------------------
ALERT_STATE_FILE="$STATE_DIR/alert_state.tsv"
declare -gA _ALERT_LAST=() _ALERT_SEEN=() _ALERT_FIRST=()
_ALERT_NOW=0
_ALERT_FORGET=0
_ALERT_KEY=""
_ALERT_SINCE=""
_ALERT_OPEN=0

# _alert_key <category> <detail> -> $_ALERT_KEY : what stays the same about a
# finding from one pass to the next. PIDs and fds change whenever the same
# service restarts, CPU figures on every sample.
_alert_key() {
  local rest="$1|$2" out=""
  local re='(pid|fd)=[0-9]+|[0-9][0-9.]*%|over [0-9]+ samples'
  while [[ $rest =~ $re ]]; do
    out+="${rest%%"${BASH_REMATCH[0]}"*}#"
    rest="${rest#*"${BASH_REMATCH[0]}"}"
  done
  out+="$rest"
  _ALERT_KEY="${out//$'\t'/ }"
}

# _alert_clock : fix "now" and the forget window for this pass.
_alert_clock() {
  _ALERT_NOW="${CERBERUS_NOW:-${EPOCHSECONDS:-$(date +%s)}}"
  # Never shorter than the slowest periodic detector, or a finding it reports
  # every PERSISTENCE_EVERY passes would be forgotten in between and re-sent.
  _ALERT_FORGET="${ALERT_FORGET_SECONDS:-3600}"
  local floor=$(( 3 * ${SENSOR_INTERVAL:-30} * ${PERSISTENCE_EVERY:-10} ))
  [ "$_ALERT_FORGET" -ge "$floor" ] 2>/dev/null || _ALERT_FORGET="$floor"
}

# alert_state_load : read what was reported before. Once per pass.
alert_state_load() {
  _ALERT_LAST=(); _ALERT_SEEN=(); _ALERT_FIRST=()
  _alert_clock
  [ -f "$ALERT_STATE_FILE" ] || return 0
  local last seen first key
  while IFS=$'\t' read -r last seen first key; do
    [ -n "$key" ] || continue
    _ALERT_LAST["$key"]="$last"
    _ALERT_SEEN["$key"]="$seen"
    _ALERT_FIRST["$key"]="$first"
  done < "$ALERT_STATE_FILE"
}

# alert_state_save : keep what is still open, drop what has been gone long
# enough to be forgotten. Sets $_ALERT_OPEN for the heartbeat.
alert_state_save() {
  [ "$_ALERT_NOW" -gt 0 ] || return 0
  local key seen n=0
  {
    for key in "${!_ALERT_SEEN[@]}"; do
      seen="${_ALERT_SEEN["$key"]}"
      [ $(( _ALERT_NOW - seen )) -lt "$_ALERT_FORGET" ] || continue
      printf '%s\t%s\t%s\t%s\n' "${_ALERT_LAST["$key"]:-0}" "$seen" \
        "${_ALERT_FIRST["$key"]:-$seen}" "$key"
      n=$(( n + 1 ))
    done
  } > "$ALERT_STATE_FILE.tmp" && mv -f "$ALERT_STATE_FILE.tmp" "$ALERT_STATE_FILE"
  _ALERT_OPEN="$n"
}

# alert_should_report <severity> <category> <detail> : 0 = report it this time.
# On a reminder, $_ALERT_SINCE holds when the finding was first reported.
alert_should_report() {
  local sev="$1" cat="$2" detail="$3"
  _ALERT_SINCE=""
  [ "$sev" = "HARD" ] && return 0
  local repeat="${ALERT_REPEAT_SECONDS:-86400}"
  [ "$repeat" -gt 0 ] 2>/dev/null || return 0      # 0 = every pass, as in v2.1.0
  [ "$_ALERT_NOW" -gt 0 ] || _alert_clock

  _alert_key "$cat" "$detail"
  local key="$_ALERT_KEY"
  local last="${_ALERT_LAST["$key"]:-}" seen="${_ALERT_SEEN["$key"]:-}"
  _ALERT_SEEN["$key"]="$_ALERT_NOW"

  if [ -n "$last" ] && [ -n "$seen" ] && [ $(( _ALERT_NOW - seen )) -lt "$_ALERT_FORGET" ]; then
    # still open since the last pass
    [ $(( _ALERT_NOW - last )) -ge "$repeat" ] || return 1
    _ALERT_SINCE="${_ALERT_FIRST["$key"]:-$last}"
  else
    _ALERT_FIRST["$key"]="$_ALERT_NOW"
  fi
  _ALERT_LAST["$key"]="$_ALERT_NOW"
  return 0
}

#---------------------------------------------------------------------------
# handle_finding "SEVERITY|CATEGORY|PID|DETAIL"
#---------------------------------------------------------------------------
handle_finding() {
  local line="$1"
  local sev cat pid detail
  IFS='|' read -r sev cat pid detail <<< "$line"
  [ -n "${sev:-}" ] || return 0

  # ---- already reported and still open: nothing new to say ----
  # Before forensics too: a snapshot per pass of the same process is the same
  # evidence a thousand times over.
  alert_should_report "$sev" "$cat" "$detail" || return 0
  if [ -n "$_ALERT_SINCE" ]; then
    detail="$detail (still open, first reported $(date -d "@$_ALERT_SINCE" -Iseconds 2>/dev/null || echo "$_ALERT_SINCE"))"
  fi

  # ---- forensics first, always ----
  local ev=""
  if [ -n "$pid" ] && [ "$pid" != "-" ] && kill -0 "$pid" 2>/dev/null; then
    ev="$(snapshot_pid "$pid" "$cat")"
  fi
  case "$cat" in
    malware_path|malware_hash|upx_new)
      local fp="${detail%% *}"
      [ -f "$fp" ] && ev="$(snapshot_file "$fp" "$cat")"
      ;;
  esac
  [ -n "$ev" ] && detail="$detail [evidence: $ev]"

  emit_event "$sev" "$cat" "${pid:--}" "$detail"

  # ---- SOFT: nothing else ----
  if [ "$sev" != "HARD" ]; then
    return 0
  fi

  # ---- HARD ----
  if [ "${AUTO_RESPONSE:-1}" != "1" ]; then
    warn "AUTO_RESPONSE=0: HARD/$cat left untouched (pid=$pid)"
    return 0
  fi

  case "$cat" in
    c2_beacon|c2_socket)
      apply_c2_firewall
      [ -n "$pid" ] && [ "$pid" != "-" ] && _kill_pid "$pid"
      ;;
    miner|malware_proc)
      if [ -n "$pid" ] && [ "$pid" != "-" ]; then
        local exe; exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
        _kill_pid "$pid"
        [ -n "$exe" ] && [ -f "$exe" ] && _quarantine_file "$exe" "HARD/$cat"
      fi
      ;;
    malware_path|malware_hash)
      local fp="${detail%% *}"
      # kill only processes whose executable IS this file (never an argv match)
      local rp
      for rp in $(_pids_executing "$fp"); do _kill_pid "$rp"; done
      _quarantine_file "$fp" "HARD/$cat"
      ;;
    *)
      warn "no response handler for HARD/$cat"
      ;;
  esac
}
