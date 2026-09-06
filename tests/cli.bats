#!/usr/bin/env bats
# The entry points: cerberus.sh, master.sh, install.sh.

setup() {
  load helper
  cerberus_setup
  fixture ps_args ""
  fixture ps_cpu ""
  fixture crontab_out ""
  fixture systemctl_unit_files ""
  fixture systemctl_units_running ""

  # These tests drive the real entry points, so a full pass runs against the
  # real host: whatever memfd process or listening port the CI runner happens
  # to have would land in events.jsonl alongside what the test set up. Leave
  # only the detector under test enabled.
  cat > "$CERBERUS_CONF_DIR/cerberus.env" <<'EOF'
DETECT_HIGH_CPU=0
DETECT_NEW_LISTENER=0
DETECT_PERSISTENCE=0
DETECT_UPX_NEW=0
DETECT_REVSHELL=0
DETECT_FILELESS=0
DETECT_SETUID=0
DETECT_LOADER=0
EOF
  chmod 600 "$CERBERUS_CONF_DIR/cerberus.env"
}

@test "cerberus.sh version prints the version" {
  run "$REPO_ROOT/cerberus.sh" version
  [ "$status" -eq 0 ]
  [[ "$output" == "eyes-cerberus "* ]]
}

@test "cerberus.sh with an unknown command fails and prints usage" {
  run "$REPO_ROOT/cerberus.sh" not-a-command
  [ "$status" -eq 1 ]
  [[ "$output" == *"Usage:"* ]]
}

@test "dryscan takes no action and writes no events" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"
  chmod 755 "$payload"
  sig malware_paths.txt "$payload"

  run "$REPO_ROOT/cerberus.sh" dryscan
  [ "$status" -eq 0 ]
  [[ "$output" == *"HARD|malware_path"* ]]

  # the whole point of dryscan: the payload is reported, not touched
  run stat -c '%a' "$payload"
  [ "$output" = "755" ]
  [ ! -s "$CERBERUS_STATE_DIR/events.jsonl" ]
  run bash -c "ls -A '$CERBERUS_STATE_DIR/quarantine' | wc -l"
  [ "$output" = "0" ]
}

@test "scan acts on what dryscan only reported" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"
  chmod 755 "$payload"
  sig malware_paths.txt "$payload"

  run "$REPO_ROOT/cerberus.sh" scan
  [ "$status" -eq 0 ]

  run stat -c '%a' "$payload"
  [ "$output" = "0" ]
  run jq -esr '[.[] | select(.category == "malware_path")] | length' \
    "$CERBERUS_STATE_DIR/events.jsonl"
  [ "$output" = "1" ]
}

@test "notify-failure records that the daemon stopped watching" {
  run "$REPO_ROOT/cerberus.sh" notify-failure
  [ "$status" -eq 0 ]
  run jq -er '.severity + "/" + .category' "$CERBERUS_STATE_DIR/events.jsonl"
  [ "$output" = "HARD/daemon_down" ]
}

@test "master.sh digest summarises the events log" {
  mkdir -p "$CERBERUS_STATE_DIR"
  printf '%s\n' \
    "{\"ts\":\"$(date -Iseconds)\",\"severity\":\"HARD\",\"category\":\"c2_beacon\",\"pid\":\"1\",\"detail\":\"x\"}" \
    "{\"ts\":\"$(date -Iseconds)\",\"severity\":\"SOFT\",\"category\":\"high_cpu\",\"pid\":\"2\",\"detail\":\"y\"}" \
    > "$CERBERUS_STATE_DIR/events.jsonl"

  run "$REPO_ROOT/master.sh" digest 1
  [ "$status" -eq 0 ]
  [[ "$output" == *"c2_beacon"* ]]
  [[ "$output" == *"high_cpu"* ]]
}

@test "master.sh reads the same state directory the daemon writes" {
  run "$REPO_ROOT/master.sh" digest 1
  [[ "$output" == *"$CERBERUS_STATE_DIR"* ]]
}

@test "install.sh --dry-run changes nothing on disk" {
  local target="$TEST_TMP/target"
  run "$REPO_ROOT/install.sh" --dry-run \
    --code-dir "$target/opt" --conf-dir "$target/etc" \
    --state-dir "$target/var" --unit-dir "$target/units"
  [ "$status" -eq 0 ]
  [[ "$output" == *"would:"* ]]
  [ ! -d "$target" ]
}

@test "install.sh refuses to run without the source tree next to it" {
  # Copied somewhere on its own, it must not half-install from nothing.
  cp "$REPO_ROOT/install.sh" "$TEST_TMP/install.sh"
  run bash "$TEST_TMP/install.sh" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"run this from the source tree"* ]]
}

@test "dryscan does not seed any baseline or bookkeeping state" {
  # "no action" has to mean no state either: a dry run that seeds the
  # persistence baseline silently declares a possibly-compromised host to be
  # known-good, and the operator was told nothing happened.
  sig malware_md5.txt "00000000000000000000000000000000"
  run "$REPO_ROOT/cerberus.sh" dryscan
  [ "$status" -eq 0 ]

  [ ! -f "$CERBERUS_STATE_DIR/baseline/units" ]
  [ ! -f "$CERBERUS_STATE_DIR/baseline/listeners" ]
  [ ! -f "$CERBERUS_STATE_DIR/cpu_sustain.tsv" ]
  [ ! -f "$CERBERUS_STATE_DIR/seen_loaders" ]
  [ ! -f "$CERBERUS_STATE_DIR/.hashscan_marker" ]
  [ ! -f "$CERBERUS_STATE_DIR/.upxscan_marker" ]
}

@test "a real scan does seed it" {
  # the hash scan only runs when there is something to compare against
  sig malware_md5.txt "00000000000000000000000000000000"
  run "$REPO_ROOT/cerberus.sh" scan
  [ "$status" -eq 0 ]
  [ -f "$CERBERUS_STATE_DIR/.hashscan_marker" ]
}

@test "the daemon refuses to start on a config anyone can rewrite" {
  chmod 666 "$CERBERUS_CONF_DIR/cerberus.env"
  run timeout 10 "$REPO_ROOT/cerberus.sh" run
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to start"* ]]
}

@test "scan refuses on an untrusted config, dryscan warns and continues" {
  local payload="$TEST_TMP/let"
  printf 'payload\n' > "$payload"; chmod 755 "$payload"
  sig malware_paths.txt "$payload"
  chmod 666 "$CERBERUS_CONF_DIR/cerberus.env"

  run "$REPO_ROOT/cerberus.sh" scan
  [ "$status" -ne 0 ]
  run stat -c '%a' "$payload"
  [ "$output" = "755" ]           # nothing was acted on

  run "$REPO_ROOT/cerberus.sh" dryscan
  [ "$status" -eq 0 ]
  [[ "$output" == *"continuing anyway"* ]]
  [[ "$output" == *"HARD|malware_path"* ]]
}

@test "master.sh works when reached through a symlink" {
  # install.sh puts /usr/local/sbin/cerberus -> .../master.sh, so BASH_SOURCE
  # is the symlink and a naive dirname pointed every source and exec at
  # /usr/local/sbin.
  mkdir -p "$TEST_TMP/sbin"
  ln -sfn "$REPO_ROOT/master.sh" "$TEST_TMP/sbin/cerberus"
  run "$TEST_TMP/sbin/cerberus" digest 1
  [ "$status" -eq 0 ]
  [[ "$output" != *"No such file or directory"* ]]
  [[ "$output" != *"unbound variable"* ]]
}

@test "master.sh works through a relative symlink too" {
  mkdir -p "$TEST_TMP/sbin"
  ln -sfn "../../$(basename "$REPO_ROOT")/master.sh" "$TEST_TMP/sbin/rel" 2>/dev/null || true
  ln -sfn "$REPO_ROOT/master.sh" "$TEST_TMP/sbin/a"
  ln -sfn "$TEST_TMP/sbin/a" "$TEST_TMP/sbin/b"     # a chain of them
  run "$TEST_TMP/sbin/b" digest 1
  [ "$status" -eq 0 ]
}
