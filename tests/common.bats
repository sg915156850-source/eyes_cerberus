#!/usr/bin/env bats
# lib/common.sh: layout resolution, signature parsing, event records.

setup() {
  load helper
  cerberus_setup
  cerberus_load
}

@test "layout: explicit CERBERUS_CONF_DIR/STATE_DIR win over everything" {
  [ "$ETC_DIR" = "$CERBERUS_CONF_DIR" ]
  [ "$STATE_DIR" = "$CERBERUS_STATE_DIR" ]
}

@test "layout: a checkout resolves to repo, an installed tree to fhs" {
  run env -u CERBERUS_CONF_DIR -u CERBERUS_STATE_DIR CERBERUS_LAYOUT=auto \
    bash -c "source '$REPO_ROOT/lib/common.sh' >/dev/null 2>&1; echo \$CERBERUS_LAYOUT"
  [ "$output" = "repo" ]

  # An installed tree has no etc/signatures next to the code.
  mkdir -p "$TEST_TMP/opt/lib"
  cp "$REPO_ROOT/lib/common.sh" "$TEST_TMP/opt/lib/"
  run env -u CERBERUS_CONF_DIR CERBERUS_STATE_DIR="$TEST_TMP/fhsstate" CERBERUS_LAYOUT=auto \
    bash -c "source '$TEST_TMP/opt/lib/common.sh' >/dev/null 2>&1; echo \$CERBERUS_LAYOUT \$ETC_DIR"
  [ "$output" = "fhs /etc/eyes-cerberus" ]
}

@test "layout: an unknown CERBERUS_LAYOUT is refused, not guessed" {
  run env CERBERUS_LAYOUT=nonsense bash -c "source '$REPO_ROOT/lib/common.sh'"
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown CERBERUS_LAYOUT"* ]]
}

@test "state directories are created and are not world-readable" {
  [ -d "$STATE_DIR/evidence" ]
  [ -d "$STATE_DIR/quarantine" ]
  [ -d "$STATE_DIR/baseline" ]
  run stat -c '%a' "$STATE_DIR/quarantine"
  [ "$output" = "700" ]
}

@test "read_sig strips comments, blanks and surrounding whitespace" {
  printf '# a comment\n\n  1.2.3.4  \n5.6.7.8 # trailing\n\t\n' \
    > "$CERBERUS_CONF_DIR/signatures/c2_ips.txt"
  run read_sig c2_ips.txt
  [ "${#lines[@]}" -eq 2 ]
  [ "${lines[0]}" = "1.2.3.4" ]
  [ "${lines[1]}" = "5.6.7.8" ]
}

@test "read_sig on a missing file is silent and succeeds" {
  run read_sig does_not_exist.txt
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "is_whitelisted matches exactly, not as a substring" {
  printf 'pg_dump\n# comment\nfwupd\n' > "$CERBERUS_CONF_DIR/whitelist.txt"
  run is_whitelisted pg_dump
  [ "$status" -eq 0 ]
  run is_whitelisted pg_dum
  [ "$status" -ne 0 ]
  run is_whitelisted xpg_dumpx
  [ "$status" -ne 0 ]
}

@test "emit_event writes one parseable JSON object per finding" {
  emit_event SOFT high_cpu 1234 "a plain detail"
  run jq -er '.severity + "|" + .category + "|" + .pid + "|" + .detail' "$EVENTS_LOG"
  [ "$status" -eq 0 ]
  [ "$output" = "SOFT|high_cpu|1234|a plain detail" ]
}

@test "emit_event survives quotes, backslashes and newlines in attacker argv" {
  # The detail string is built from process argv, so it is attacker-controlled.
  local nasty
  nasty="$(printf 'he said "hi" \\ then\nnewline\tand tab')"
  emit_event HARD c2_beacon 7 "$nasty"

  # One line in, one line out: a raw newline in the payload must not split the
  # record, or every downstream consumer of events.jsonl sees a truncated event.
  run wc -l < "$EVENTS_LOG"
  [ "$output" = "1" ]

  run jq -er '.detail' "$EVENTS_LOG"
  [ "$status" -eq 0 ]
  [ "$output" = "$nasty" ]
}

@test "emit_event escapes control characters" {
  emit_event HARD malware_proc 9 "$(printf 'bell:\a esc:\033 nul-free')"
  run jq -e . "$EVENTS_LOG"
  [ "$status" -eq 0 ]
}

@test "NOTIFY_MIN_SEVERITY=HARD records SOFT findings but does not notify" {
  NOTIFY_MIN_SEVERITY=HARD
  NOTIFY_METHOD=log
  emit_event SOFT miner 5 "miner-like argv"
  run jq -er '.severity' "$EVENTS_LOG"
  [ "$output" = "SOFT" ]
  run bash -c "grep -c ALERT '$RUN_LOG' 2>/dev/null || echo 0"
  [ "$output" = "0" ]
}

@test "run_action executes normally and only logs under DRY_RUN" {
  local marker="$TEST_TMP/marker"
  DRY_RUN=0 run_action touch "$marker"
  [ -f "$marker" ]

  rm -f "$marker"
  DRY_RUN=1 run_action touch "$marker"
  [ ! -f "$marker" ]
  run grep -c '\[DRY\]' "$RUN_LOG"
  [ "$output" -ge 1 ]
}

@test "iter_pids lists this shell and only numeric entries" {
  run iter_pids
  [ "$status" -eq 0 ]
  [[ "$output" == *"$$"* ]]
  run bash -c "source '$REPO_ROOT/lib/common.sh' >/dev/null 2>&1; iter_pids | grep -cvE '^[0-9]+$'"
  [ "$output" = "0" ]
}

@test "json_escape produces exactly what a JSON parser expects" {
  # Round-trip through jq: whatever goes in must come back byte for byte.
  local cases=(
    'plain'
    'quote " inside'
    'backslash \ inside'
    'both \" together'
    'tab	and newline
here'
    'unicode: привет ✓'
    'slash / and control'
  )
  local c esc back
  for c in "${cases[@]}"; do
    esc="$(json_escape "$c")"
    back="$(printf '%s' "$esc" | jq -er . )" || {
      echo "not valid JSON: $esc" >&2
      return 1
    }
    [ "$back" = "$c" ] || {
      echo "round trip changed the value: [$c] -> [$back]" >&2
      return 1
    }
  done
}

@test "json_escape does not call python3" {
  # It used to shell out per event, on an undeclared dependency.
  printf '#!/bin/sh\nexit 42\n' > "$SHIM_DIR/python3"
  chmod +x "$SHIM_DIR/python3"
  emit_event SOFT miner 1 'detail with "quotes" and \backslash'
  run jq -er '.detail' "$EVENTS_LOG"
  [ "$output" = 'detail with "quotes" and \backslash' ]
}

@test "an event line is always exactly one line" {
  emit_event HARD c2_beacon 1 "$(printf 'first\nsecond\nthird')"
  emit_event HARD c2_beacon 2 "plain"
  run wc -l < "$EVENTS_LOG"
  [ "$output" = "2" ]
  run jq -es 'length' "$EVENTS_LOG"
  [ "$output" = "2" ]
}

@test "rotate_logs rotates past the size limit and keeps LOG_KEEP generations" {
  LOG_MAX_BYTES=100
  LOG_KEEP=2
  head -c 500 /dev/zero | tr '\0' 'x' > "$EVENTS_LOG"

  rotate_logs
  [ -f "$EVENTS_LOG.1" ]
  run stat -c '%s' "$EVENTS_LOG"
  [ "$output" = "0" ]

  head -c 500 /dev/zero | tr '\0' 'y' > "$EVENTS_LOG"
  rotate_logs
  [ -f "$EVENTS_LOG.2" ]

  head -c 500 /dev/zero | tr '\0' 'z' > "$EVENTS_LOG"
  rotate_logs
  [ ! -f "$EVENTS_LOG.3" ]      # LOG_KEEP=2 means two, not three
}

@test "rotate_logs leaves a small log alone" {
  LOG_MAX_BYTES=1000000
  emit_event SOFT miner 1 "small"
  rotate_logs
  [ ! -f "$EVENTS_LOG.1" ]
  run wc -l < "$EVENTS_LOG"
  [ "$output" = "1" ]
}

@test "check_config_perms rejects a config anyone can rewrite" {
  : > "$CONFIG_FILE"
  chmod 666 "$CONFIG_FILE"
  run check_config_perms
  [ "$status" -ne 0 ]
  [[ "$output" == *"writable by group or other"* ]]
}

@test "check_config_perms rejects a world-writable signature file" {
  sig c2_ips.txt "203.0.113.9"
  chmod 646 "$CERBERUS_CONF_DIR/signatures/c2_ips.txt"
  run check_config_perms
  [ "$status" -ne 0 ]
}

@test "check_config_perms accepts a properly locked down config" {
  : > "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
  chmod 750 "$CERBERUS_CONF_DIR" "$SIG_DIR"
  sig c2_ips.txt "203.0.113.9"
  chmod 640 "$SIG_DIR"/*.txt
  run check_config_perms
  [ "$status" -eq 0 ]
}
