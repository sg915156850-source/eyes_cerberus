#!/usr/bin/env bats
# lib/respond.sh: a SOFT finding still open from the last pass is not reported
# again; HARD always is.

setup() {
  load helper
  cerberus_setup
  cerberus_load
  export CERBERUS_NOW=1000000
}

teardown() {
  reap ${SPAWNED:-}
}

# pass <finding>... : one daemon pass at $CERBERUS_NOW, the way one_pass runs it.
pass() {
  alert_state_load
  local f
  for f in "$@"; do handle_finding "$f"; done
  alert_state_save
}

events() {
  if [ -f "$EVENTS_LOG" ]; then grep -c . "$EVENTS_LOG"; else echo 0; fi
}

@test "a SOFT finding that stays open is reported once, not every pass" {
  pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1000030 pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1000060 pass "SOFT|persistence|-|new in units: x.service enabled"

  run events
  [ "$output" = "1" ]
  [ -s "$ALERT_STATE_FILE" ]
}

@test "the same listener after a service restart is the same finding" {
  pass "SOFT|new_listener|-|new LISTEN port 8080 users:((\"python\",pid=859,fd=15))"
  CERBERUS_NOW=1000030 \
    pass "SOFT|new_listener|-|new LISTEN port 8080 users:((\"python\",pid=4242,fd=13))"

  run events
  [ "$output" = "1" ]
}

@test "a changing CPU figure does not make a new finding" {
  pass "SOFT|high_cpu|-|sustained 97% CPU over 4 samples: /usr/bin/x --work"
  CERBERUS_NOW=1000030 pass "SOFT|high_cpu|-|sustained 91.5% CPU over 5 samples: /usr/bin/x --work"

  run events
  [ "$output" = "1" ]
}

@test "different findings are each reported" {
  pass "SOFT|new_listener|-|new LISTEN port 8080 users:((\"a\",pid=1,fd=3))" \
       "SOFT|new_listener|-|new LISTEN port 8081 users:((\"b\",pid=2,fd=3))"

  run events
  [ "$output" = "2" ]
}

@test "an open finding is reported again after ALERT_REPEAT_SECONDS, saying since when" {
  ALERT_REPEAT_SECONDS=600
  pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1000300 pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1000600 pass "SOFT|persistence|-|new in units: x.service enabled"

  run events
  [ "$output" = "2" ]
  run jq -sr '.[1].detail' "$EVENTS_LOG"
  [[ "$output" == *"still open, first reported"* ]]
}

@test "a finding that went away and came back is reported at once, as new" {
  pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1005000 pass "SOFT|persistence|-|new in units: x.service enabled"

  run events
  [ "$output" = "2" ]
  run jq -sr '.[1].detail' "$EVENTS_LOG"
  [[ "$output" != *"still open"* ]]
}

@test "what has gone away is dropped from the state, even on a pass with no findings" {
  pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1005000 pass

  run cat "$ALERT_STATE_FILE"
  [ -z "$output" ]
}

@test "the forget window never undercuts the slowest periodic detector" {
  # persistence runs every 10 passes of 30s; forgetting after 10s would have
  # every one of its findings re-sent each time it ran
  ALERT_FORGET_SECONDS=10 SENSOR_INTERVAL=30 PERSISTENCE_EVERY=10
  pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1000300 pass "SOFT|persistence|-|new in units: x.service enabled"

  run events
  [ "$output" = "1" ]
}

@test "HARD findings are never held back" {
  AUTO_RESPONSE=0
  pass "HARD|c2_socket|-|203.0.113.9:9009"
  CERBERUS_NOW=1000030 pass "HARD|c2_socket|-|203.0.113.9:9009"

  run events
  [ "$output" = "2" ]
}

@test "ALERT_REPEAT_SECONDS=0 reports every pass, as v2.1.0 did" {
  ALERT_REPEAT_SECONDS=0
  pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1000030 pass "SOFT|persistence|-|new in units: x.service enabled"
  CERBERUS_NOW=1000060 pass "SOFT|persistence|-|new in units: x.service enabled"

  run events
  [ "$output" = "3" ]
}

@test "a finding carrying shell syntax is stored as text, never evaluated" {
  # argv is attacker-controlled and lands in the state file as the key
  local f="SOFT|revshell|-|reverse-shell shaped argv: \$(touch $TEST_TMP/pwned) \`touch $TEST_TMP/pwned2\` a[\$(id)]	tab"
  pass "$f"
  CERBERUS_NOW=1000030 pass "$f"

  [ ! -e "$TEST_TMP/pwned" ]
  [ ! -e "$TEST_TMP/pwned2" ]
  run events
  [ "$output" = "1" ]
}

@test "a held-back finding takes no fresh forensics snapshot" {
  SPAWNED="$(spawn_idle)"
  pass "SOFT|exe_in_volatile|$SPAWNED|executable under volatile dir: /tmp/x"
  local first; first="$(ls -A "$EVIDENCE_DIR" | wc -l)"
  [ "$first" -ge 1 ]
  CERBERUS_NOW=1000030 pass "SOFT|exe_in_volatile|$SPAWNED|executable under volatile dir: /tmp/x"

  run bash -c "ls -A '$EVIDENCE_DIR' | wc -l"
  [ "$output" = "$first" ]
}
