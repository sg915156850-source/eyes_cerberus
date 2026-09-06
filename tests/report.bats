#!/usr/bin/env bats
# lib/report.sh: the period report.

setup() {
  load helper
  cerberus_setup
  cerberus_load
  VERSION="test"

  now="$(date -Iseconds)"
  old="$(date -d '-30 days' -Iseconds)"
  {
    printf '{"ts":"%s","severity":"HARD","category":"malware_path","pid":"-","detail":"/tmp/let perms=755"}\n' "$now"
    printf '{"ts":"%s","severity":"HARD","category":"c2_beacon","pid":"41","detail":"nc 203.0.113.9 9009"}\n' "$now"
    printf '{"ts":"%s","severity":"SOFT","category":"high_cpu","pid":"42","detail":"sustained 99%%"}\n' "$now"
    printf '{"ts":"%s","severity":"SOFT","category":"ancient","pid":"-","detail":"long ago"}\n' "$old"
  } > "$EVENTS_LOG"
}

@test "json report counts only the requested period" {
  run report 7 json
  [ "$status" -eq 0 ]
  local json; json="$(report 7 json)"
  [ "$(printf '%s' "$json" | jq -r '.total')" = "3" ]
  [ "$(printf '%s' "$json" | jq -r '.by_severity.HARD')" = "2" ]
  [ "$(printf '%s' "$json" | jq -r '.by_severity.SOFT')" = "1" ]
  [ "$(printf '%s' "$json" | jq -r '.by_category.malware_path')" = "1" ]
}

@test "a wider window picks the older event back up" {
  local json; json="$(report 60 json)"
  [ "$(printf '%s' "$json" | jq -r '.total')" = "4" ]
  [ "$(printf '%s' "$json" | jq -r '.by_category.ancient')" = "1" ]
}

@test "timestamps with a UTC offset are parsed, not silently dropped" {
  # date -Iseconds writes "+00:00", which fromdateiso8601 rejects outright.
  # Getting this wrong makes every report come back empty.
  printf '{"ts":"%s","severity":"SOFT","category":"offset_test","pid":"-","detail":"x"}\n' \
    "$(date -d '-1 hour' '+%Y-%m-%dT%H:%M:%S+00:00')" >> "$EVENTS_LOG"
  local json; json="$(report 7 json)"
  [ "$(printf '%s' "$json" | jq -r '.by_category.offset_test')" = "1" ]
}

@test "json report is valid JSON even with no events at all" {
  rm -f "$EVENTS_LOG"
  local json; json="$(report 7 json)"
  run bash -c "printf '%s' '$json' | jq -e ."
  [ "$status" -eq 0 ]
  [ "$(printf '%s' "$json" | jq -r '.total')" = "0" ]
}

@test "html report is self-contained -- no external requests" {
  local html; html="$(report 7 html)"
  [[ "$html" == *"<!doctype html>"* ]]
  # nothing that would make the page fetch anything
  [[ "$html" != *"src=\"http"* ]]
  [[ "$html" != *"href=\"http"* ]]
  [[ "$html" != *"@import"* ]]
}

@test "html report shows the events and the host state" {
  local html; html="$(report 7 html)"
  [[ "$html" == *"malware_path"* ]]
  [[ "$html" == *"c2_beacon"* ]]
  [[ "$html" == *"quarantined"* ]]
  [[ "$html" != *"ancient"* ]]      # outside the window
}

@test "html report escapes attacker-controlled detail" {
  printf '{"ts":"%s","severity":"HARD","category":"c2_beacon","pid":"1","detail":"<img src=x onerror=alert(1)>"}\n' \
    "$(date -Iseconds)" >> "$EVENTS_LOG"
  local html; html="$(report 7 html)"
  [[ "$html" != *"<img src=x"* ]]
  [[ "$html" == *"&lt;img src=x"* ]]
}

@test "an unknown format is refused" {
  run report 7 csv
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown report format"* ]]
}

@test "the report reads state but never writes to it" {
  local before after
  before="$(find "$STATE_DIR" -type f | sort | md5sum)"
  report 7 html >/dev/null
  report 7 json >/dev/null
  after="$(find "$STATE_DIR" -type f | sort | md5sum)"
  [ "$before" = "$after" ]
}
