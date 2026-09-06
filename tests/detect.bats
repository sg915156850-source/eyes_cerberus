#!/usr/bin/env bats
# lib/detect.sh: each detector, and the HARD/SOFT boundary between them.

setup() {
  load helper
  cerberus_setup
  cerberus_load
}

teardown() {
  reap ${SPAWNED:-}
}

# --- malware_path ----------------------------------------------------------

@test "malware_path: an executable payload at a known path is HARD" {
  local payload="$TEST_TMP/let"
  printf '#!/bin/sh\n' > "$payload"
  chmod 755 "$payload"
  sig malware_paths.txt "$payload"

  run detect_malware_paths
  [ "${#lines[@]}" -eq 1 ]
  [[ "$output" == "HARD|malware_path|-|$payload perms=755" ]]
}

@test "malware_path: an already neutralised payload (000) is not re-reported" {
  local payload="$TEST_TMP/let"
  printf '#!/bin/sh\n' > "$payload"
  chmod 000 "$payload"
  sig malware_paths.txt "$payload"

  run detect_malware_paths
  [ -z "$output" ]
}

@test "malware_path: a path that does not exist produces nothing" {
  sig malware_paths.txt "$TEST_TMP/absent"
  run detect_malware_paths
  [ -z "$output" ]
}

# --- malware_hash ----------------------------------------------------------

@test "malware_hash: a file whose md5 is known is HARD" {
  local payload="$TEST_TMP/dropper"
  printf 'malicious\n' > "$payload"
  chmod 700 "$payload"
  local md5; md5="$(md5sum "$payload" | cut -d' ' -f1)"
  sig malware_md5.txt "$md5"

  # _SUSPECT_DIRS is the scan scope; point it at the sandbox.
  _SUSPECT_DIRS=("$TEST_TMP")
  run detect_malware_hashes
  [[ "$output" == *"HARD|malware_hash|-|$payload md5=$md5"* ]]
}

@test "malware_hash: an unknown hash in the same directory is ignored" {
  printf 'harmless\n' > "$TEST_TMP/ok"
  chmod 700 "$TEST_TMP/ok"
  sig malware_md5.txt "00000000000000000000000000000000"

  _SUSPECT_DIRS=("$TEST_TMP")
  run detect_malware_hashes
  [ -z "$output" ]
}

# --- c2 --------------------------------------------------------------------

@test "c2_beacon: nc to a known C2 address is HARD" {
  sig c2_ips.txt "203.0.113.9"
  sig c2_ports.txt "9009"
  fixture ps_args "  4242 nc 203.0.113.9 9009"

  run detect_c2
  [[ "$output" == *"HARD|c2_beacon|4242|"* ]]
  [[ "$output" == *"-> C2 203.0.113.9"* ]]
}

@test "c2_beacon: nc to a suspicious port on an unknown address is still HARD" {
  sig c2_ips.txt "203.0.113.9"
  sig c2_ports.txt "9009"
  fixture ps_args "  4243 nc 198.51.100.7 9009"

  run detect_c2
  [[ "$output" == *"HARD|c2_beacon|4243|"* ]]
  [[ "$output" == *"suspicious port 9009"* ]]
}

@test "c2_beacon: an ordinary process is not flagged just for naming an IP" {
  sig c2_ips.txt "203.0.113.9"
  sig c2_ports.txt "9009"
  # curl is not nc/ncat/socat: argv matching is restricted on purpose.
  fixture ps_args "  4244 curl https://203.0.113.9/"

  run detect_c2
  [ -z "$output" ]
}

@test "c2_socket: an established socket to a C2 address is HARD whoever opened it" {
  sig c2_ips.txt "203.0.113.9"
  sig c2_ports.txt "9009"
  fixture ps_args ""
  fixture ss_established \
    'ESTAB 0 0 10.0.0.2:44120 203.0.113.9:9009 users:(("python3",pid=8123,fd=5))'

  run detect_c2
  [[ "$output" == *"HARD|c2_socket|8123|"* ]]
  [[ "$output" == *"203.0.113.9"* ]]
}

# --- miner -----------------------------------------------------------------

@test "miner: miner-like argv without CPU load is SOFT, not killed" {
  SPAWNED="$(spawn_idle)"
  sig miner_patterns.txt "xmrig"
  fixture ps_args "  $SPAWNED xmrig --url pool.example:3333"
  fixture ps_cpu  "$SPAWNED xmrig 90.0"

  run detect_miner
  [[ "$output" == "SOFT|miner|$SPAWNED|"* ]]
  [[ "$output" != *"HARD"* ]]
}

@test "miner: miner-like argv on a CPU-hot process is HARD" {
  SPAWNED="$(spawn_busy)"
  sig miner_patterns.txt "xmrig"
  fixture ps_args "  $SPAWNED xmrig --url pool.example:3333"
  fixture ps_cpu  "$SPAWNED xmrig 99.0"
  CPU_THRESHOLD=1     # the process is real, so its /proc stat really does move

  run detect_miner
  [[ "$output" == "HARD|miner|$SPAWNED|"* ]]
}

@test "miner: no miner patterns configured means no findings" {
  : > "$CERBERUS_CONF_DIR/signatures/miner_patterns.txt"
  fixture ps_args "  1 xmrig --url pool.example:3333"
  run detect_miner
  [ -z "$output" ]
}

# --- high_cpu --------------------------------------------------------------

@test "high_cpu: reports only after CPU_SUSTAIN_SAMPLES consecutive passes" {
  SPAWNED="$(spawn_busy)"
  fixture ps_cpu "$SPAWNED burner 99.0"
  fixture ps_p   "burner burner --spin"
  CPU_THRESHOLD=1
  CPU_SUSTAIN_SAMPLES=3

  run detect_high_cpu; [ -z "$output" ]
  run detect_high_cpu; [ -z "$output" ]
  run detect_high_cpu
  [[ "$output" == "SOFT|high_cpu|$SPAWNED|"* ]]

  # and only once -- a sustained hog must not alert every 30 seconds forever
  run detect_high_cpu
  [ -z "$output" ]
}

@test "high_cpu: a whitelisted process is never reported" {
  SPAWNED="$(spawn_busy)"
  printf 'burner\n' > "$CERBERUS_CONF_DIR/whitelist.txt"
  fixture ps_cpu "$SPAWNED burner 99.0"
  CPU_THRESHOLD=1
  CPU_SUSTAIN_SAMPLES=1

  run detect_high_cpu
  [ -z "$output" ]
}

@test "high_cpu: disabled by DETECT_HIGH_CPU=0" {
  SPAWNED="$(spawn_busy)"
  fixture ps_cpu "$SPAWNED burner 99.0"
  CPU_THRESHOLD=1
  CPU_SUSTAIN_SAMPLES=1
  DETECT_HIGH_CPU=0

  run detect_high_cpu
  [ -z "$output" ]
}

# --- new_listener ----------------------------------------------------------

@test "new_listener: a port absent from the baseline is SOFT" {
  printf '22\n' > "$STATE_DIR/baseline/listeners"
  fixture ss_listen 'LISTEN 0 4096 0.0.0.0:22   0.0.0.0:*' \
                    'LISTEN 0 4096 0.0.0.0:4444 0.0.0.0:*'
  fixture ss_listen_pid 'LISTEN 0 4096 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=99,fd=3))'

  run detect_new_listener
  [[ "$output" == *"SOFT|new_listener|-|new LISTEN port 4444"* ]]
  [[ "$output" != *"port 22"* ]]
}

@test "new_listener: the first run seeds the baseline instead of alerting" {
  rm -f "$STATE_DIR/baseline/listeners"
  fixture ss_listen 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*'

  run detect_new_listener
  [ -z "$output" ]
  run cat "$STATE_DIR/baseline/listeners"
  [ "$output" = "22" ]
}

# --- upx -------------------------------------------------------------------

@test "upx_new: a UPX-packed file in a volatile directory is SOFT" {
  local f="$TEST_TMP/packed"
  printf 'ELF junk UPX! more junk\n' > "$f"
  chmod 700 "$f"
  _SUSPECT_DIRS=("$TEST_TMP")

  run detect_upx_new
  [[ "$output" == *"SOFT|upx_new|-|UPX-packed executable: $f"* ]]
}

@test "upx_new: an ordinary executable is not flagged" {
  local f="$TEST_TMP/plain"
  printf '#!/bin/sh\necho hello\n' > "$f"
  chmod 700 "$f"
  _SUSPECT_DIRS=("$TEST_TMP")

  run detect_upx_new
  [ -z "$output" ]
}
