#!/usr/bin/env bats
# lib/respond.sh: the firewall, the quarantine contract, and the HARD/SOFT
# boundary on the response side.

setup() {
  load helper
  cerberus_setup
  cerberus_load
  sig c2_ips.txt "203.0.113.9" "198.51.100.4"
  sig c2_ports.txt "9009"
}

teardown() {
  reap ${SPAWNED:-}
}

# --- firewall --------------------------------------------------------------

@test "apply_c2_firewall drops every known C2 address in both directions" {
  run apply_c2_firewall
  run calls iptables
  [[ "$output" == *"-A OUTPUT -d 203.0.113.9 -j DROP"* ]]
  [[ "$output" == *"-A INPUT -s 203.0.113.9 -j DROP"* ]]
  [[ "$output" == *"-A OUTPUT -d 198.51.100.4 -j DROP"* ]]
}

@test "apply_c2_firewall does not re-add a rule that already exists" {
  IPTABLES_CHECK_RC=0 apply_c2_firewall     # -C says: already there
  run calls iptables
  [[ "$output" != *"-A "* ]]
}

@test "port blocking stays off unless BLOCK_C2_PORTS=1" {
  BLOCK_C2_PORTS=0 apply_c2_firewall
  run calls iptables
  [[ "$output" != *"--dport"* ]]

  : > "$FIXTURE_DIR/iptables.calls"
  BLOCK_C2_PORTS=1 apply_c2_firewall
  run calls iptables
  [[ "$output" == *"-A OUTPUT -p tcp --dport 9009 -j DROP"* ]]
}

@test "DRY_RUN blocks the firewall change but still probes" {
  DRY_RUN=1 apply_c2_firewall
  run calls iptables
  [[ "$output" == *"-C OUTPUT"* ]]
  [[ "$output" != *"-A "* ]]
}

# --- quarantine ------------------------------------------------------------

@test "HARD/malware_path quarantines a copy and neutralises the original" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"
  chmod 755 "$payload"

  AUTO_RESPONSE=1 DRY_RUN=0 handle_finding "HARD|malware_path|-|$payload perms=755"

  # original kept for forensics, but unusable
  # (stat -c %a prints "0" for mode 000 -- that is the form detect_malware_paths
  # compares against, so an assertion on "000" would be testing the wrong thing)
  [ -f "$payload" ]
  run stat -c '%a' "$payload"
  [ "$output" = "0" ]

  # exactly one quarantined copy, with its metadata
  run bash -c "ls '$QUARANTINE_DIR' | grep -c 'let' "
  [ "$output" = "2" ]     # the copy and its .metadata
  run bash -c "cat '$QUARANTINE_DIR'/*.metadata"
  [[ "$output" == *"original_path: $payload"* ]]
  [[ "$output" == *"perms_before: 755"* ]]
  [[ "$output" == *"sha256:"* ]]
}

@test "quarantine never deletes the original" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"
  chmod 700 "$payload"
  AUTO_RESPONSE=1 DRY_RUN=0 handle_finding "HARD|malware_path|-|$payload perms=700"
  [ -e "$payload" ]
}

@test "DRY_RUN leaves the payload completely untouched" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"
  chmod 755 "$payload"

  AUTO_RESPONSE=1 DRY_RUN=1 handle_finding "HARD|malware_path|-|$payload perms=755"

  run stat -c '%a' "$payload"
  [ "$output" = "755" ]
  run bash -c "ls -A '$QUARANTINE_DIR' | wc -l"
  [ "$output" = "0" ]
}

@test "AUTO_RESPONSE=0 records a HARD finding but changes nothing" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"
  chmod 755 "$payload"

  AUTO_RESPONSE=0 DRY_RUN=0 handle_finding "HARD|malware_path|-|$payload perms=755"

  run stat -c '%a' "$payload"
  [ "$output" = "755" ]
  run jq -er '.severity + "/" + .category' "$EVENTS_LOG"
  [ "$output" = "HARD/malware_path" ]
}

# --- severity boundary -----------------------------------------------------

@test "a SOFT finding is recorded and the process is left alone" {
  SPAWNED="$(spawn_idle)"
  AUTO_RESPONSE=1 DRY_RUN=0 handle_finding "SOFT|high_cpu|$SPAWNED|sustained 99% CPU"

  run kill -0 "$SPAWNED"
  [ "$status" -eq 0 ]
  run jq -er '.severity' "$EVENTS_LOG"
  [ "$output" = "SOFT" ]
}

@test "every finding leaves an evidence file behind" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"
  chmod 755 "$payload"
  AUTO_RESPONSE=0 handle_finding "HARD|malware_path|-|$payload perms=755"

  run bash -c "ls -A '$EVIDENCE_DIR' | wc -l"
  [ "$output" -ge 1 ]
  run jq -er '.detail' "$EVENTS_LOG"
  [[ "$output" == *"[evidence:"* ]]
}

@test "an unhandled HARD category warns instead of guessing at a response" {
  run handle_finding "HARD|something_new|-|whatever"
  run cat "$RUN_LOG"
  [[ "$output" == *"no response handler for HARD/something_new"* ]]
}

# --- process targeting -----------------------------------------------------

@test "_pids_executing matches the executable, never the command line" {
  # A process merely *mentioning* the path in its argv must not be killed --
  # that is how v1 shot legitimate processes.
  local payload="$TEST_TMP/let"
  printf '#!/bin/sh\nsleep 300\n' > "$payload"
  chmod 755 "$payload"

  bash -c "exec -a 'tail -f $payload' sleep 300" </dev/null >/dev/null 2>&1 &
  SPAWNED=$!
  disown "$SPAWNED" 2>/dev/null || true

  run _pids_executing "$payload"
  [[ "$output" != *"$SPAWNED"* ]]
}

# --- rollback --------------------------------------------------------------

@test "quarantine_list reports nothing when nothing has been contained" {
  run quarantine_list
  [ "$status" -ne 0 ]
  [ -z "$output" ]
}

@test "quarantine_list shows the original path and reason" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"; chmod 755 "$payload"
  AUTO_RESPONSE=1 DRY_RUN=0 handle_finding "HARD|malware_path|-|$payload perms=755"

  run quarantine_list
  [ "$status" -eq 0 ]
  [[ "$output" == *"$payload"* ]]
  [[ "$output" == *"HARD/malware_path"* ]]
}

@test "restore puts the file back with the permissions it had" {
  local payload="$TEST_TMP/let"
  printf 'the original bytes\n' > "$payload"; chmod 755 "$payload"
  AUTO_RESPONSE=1 DRY_RUN=0 handle_finding "HARD|malware_path|-|$payload perms=755"

  run stat -c '%a' "$payload"
  [ "$output" = "0" ]

  local id; id="$(quarantine_list | cut -f1)"
  run quarantine_restore "$id"
  [ "$status" -eq 0 ]

  run stat -c '%a' "$payload"
  [ "$output" = "755" ]
  run cat "$payload"
  [ "$output" = "the original bytes" ]
}

@test "restore works even if the original was deleted afterwards" {
  local payload="$TEST_TMP/let"
  printf 'content\n' > "$payload"; chmod 700 "$payload"
  AUTO_RESPONSE=1 DRY_RUN=0 handle_finding "HARD|malware_path|-|$payload perms=700"
  rm -f "$payload"

  local id; id="$(quarantine_list | cut -f1)"
  quarantine_restore "$id"
  [ -f "$payload" ]
  run cat "$payload"
  [ "$output" = "content" ]
}

@test "restore records what it did" {
  local payload="$TEST_TMP/let"
  printf 'content\n' > "$payload"; chmod 700 "$payload"
  AUTO_RESPONSE=1 DRY_RUN=0 handle_finding "HARD|malware_path|-|$payload perms=700"
  local id; id="$(quarantine_list | cut -f1)"
  quarantine_restore "$id"

  run jq -esr '[.[] | select(.category == "quarantine_restore")] | length' "$EVENTS_LOG"
  [ "$output" = "1" ]
}

@test "restore refuses an unknown id" {
  run quarantine_restore "20200101_000000_nope_deadbeef"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no such quarantine entry"* ]]
}

@test "restore refuses a metadata file pointing outside an absolute path" {
  # The metadata sidecar sits in a directory only root can write, but a
  # restore that trusts it blindly would be "write anywhere as root".
  local id="20200101_000000_evil_deadbeef"
  printf 'payload\n' > "$QUARANTINE_DIR/$id"
  printf 'original_path: ../../etc/cron.d/backdoor\nperms_before: 755\n' \
    > "$QUARANTINE_DIR/$id.metadata"

  run quarantine_restore "$id"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not absolute"* ]]
  [ ! -e "$TEST_TMP/../../etc/cron.d/backdoor" ]
}

@test "restore refuses when the quarantined copy is missing" {
  local id="20200101_000000_gone_deadbeef"
  printf 'original_path: /tmp/x\nperms_before: 755\n' > "$QUARANTINE_DIR/$id.metadata"
  run quarantine_restore "$id"
  [ "$status" -ne 0 ]
  [[ "$output" == *"quarantined copy does not"* ]]
}
