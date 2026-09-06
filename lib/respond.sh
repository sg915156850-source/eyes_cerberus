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
  run_action cp -p "$copy" "$orig" || { err "restore failed"; return 1; }
  run_action chmod "${perms:-600}" "$orig"
  emit_event SOFT quarantine_restore "-" "restored $id to $orig with perms ${perms:-600}"
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
