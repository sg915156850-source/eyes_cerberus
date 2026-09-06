# shellcheck shell=bash
#===============================================================================
# Shared test setup.
#
# Every test gets its own config and state directory (via CERBERUS_CONF_DIR /
# CERBERUS_STATE_DIR) and a PATH full of shims, so nothing here reads the real
# host, needs root, or leaves anything behind. If a test ever touches /etc,
# /var or the real process table, that is a bug in the test.
#===============================================================================

REPO_ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
export REPO_ROOT

# cerberus_setup : private conf + state, shimmed PATH. Call from setup().
cerberus_setup() {
  TEST_TMP="${BATS_TEST_TMPDIR:-$(mktemp -d)}"
  export TEST_TMP
  export CERBERUS_CONF_DIR="$TEST_TMP/etc"
  export CERBERUS_STATE_DIR="$TEST_TMP/state"
  export SHIM_DIR="$TEST_TMP/bin"
  export FIXTURE_DIR="$TEST_TMP/fixtures"
  mkdir -p "$CERBERUS_CONF_DIR/signatures" "$SHIM_DIR" "$FIXTURE_DIR"
  : > "$CERBERUS_CONF_DIR/whitelist.txt"
  _make_shims
  export PATH="$SHIM_DIR:$PATH"
}

# cerberus_load : source the library exactly as cerberus.sh does.
cerberus_load() {
  # shellcheck source=../lib/common.sh
  source "$REPO_ROOT/lib/common.sh"
  # shellcheck source=../lib/forensics.sh
  source "$REPO_ROOT/lib/forensics.sh"
  # shellcheck source=../lib/baseline.sh
  source "$REPO_ROOT/lib/baseline.sh"
  # shellcheck source=../lib/detect.sh
  source "$REPO_ROOT/lib/detect.sh"
  # shellcheck source=../lib/respond.sh
  source "$REPO_ROOT/lib/respond.sh"
  # shellcheck source=../lib/sigupdate.sh
  source "$REPO_ROOT/lib/sigupdate.sh"
  # shellcheck source=../lib/report.sh
  source "$REPO_ROOT/lib/report.sh"
}

# sig <file> <line>... : write a signature file the daemon will read.
sig() {
  local f="$CERBERUS_CONF_DIR/signatures/$1"; shift
  printf '%s\n' "$@" > "$f"
}

# fixture <name> <line>... : canned output for one of the shims below.
fixture() {
  local f="$FIXTURE_DIR/$1"; shift
  printf '%s\n' "$@" > "$f"
}

# calls <tool> : everything that tool was invoked with, one line per call.
calls() {
  cat "$FIXTURE_DIR/$1.calls" 2>/dev/null || true
}

_write_shim() {
  local name="$1"
  cat > "$SHIM_DIR/$name"
  chmod +x "$SHIM_DIR/$name"
}

_make_shims() {
  _write_shim ps <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FIXTURE_DIR/ps.calls"
case " $* " in
  *" -p "*) f=ps_p ;;
  *pcpu*)   f=ps_cpu ;;
  *args*)   f=ps_args ;;
  *)        f=ps_other ;;
esac
[ -f "$FIXTURE_DIR/$f" ] && cat "$FIXTURE_DIR/$f"
exit 0
EOF

  _write_shim ss <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FIXTURE_DIR/ss.calls"
case "$*" in
  *"state established"*) f=ss_established ;;
  *-tlnpH*)              f=ss_listen_pid ;;
  *-tlnH*)               f=ss_listen ;;
  *)                     f=ss_all ;;
esac
[ -f "$FIXTURE_DIR/$f" ] && cat "$FIXTURE_DIR/$f"
exit 0
EOF

  # -C is the "does this rule exist" probe. Default answer: no, so the caller
  # goes on to add it and the test can assert on the -A calls.
  _write_shim iptables <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FIXTURE_DIR/iptables.calls"
case "${1:-}" in
  -C) exit "${IPTABLES_CHECK_RC:-1}" ;;
  -S) [ -f "$FIXTURE_DIR/iptables_S" ] && cat "$FIXTURE_DIR/iptables_S"; exit 0 ;;
esac
exit 0
EOF

  _write_shim systemctl <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FIXTURE_DIR/systemctl.calls"
case "$*" in
  *list-unit-files*) f=systemctl_unit_files ;;
  *list-units*)      f=systemctl_units_running ;;
  *)                 f=systemctl_other ;;
esac
[ -f "$FIXTURE_DIR/$f" ] && cat "$FIXTURE_DIR/$f"
exit 0
EOF

  _write_shim crontab <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FIXTURE_DIR/crontab.calls"
[ -f "$FIXTURE_DIR/crontab_out" ] && cat "$FIXTURE_DIR/crontab_out"
exit 0
EOF
}
# spawn_idle : a real process that uses no CPU. Prints its pid.
# spawn_busy : a real process that pegs a core. Prints its pid.
#
# Both exist because the CPU heuristics read /proc/<pid>/stat directly -- that
# is the whole point of the instantaneous measurement, and no shim can fake it.
# Every descriptor is detached: a background job still holding the capture pipe
# makes bats wait forever for output that was written long ago.
spawn_idle() {
  # shellcheck disable=SC2217  # closing stdin is the point, not an accident
  sleep 300 </dev/null >/dev/null 2>&1 &
  local p=$!
  disown "$p" 2>/dev/null || true    # keeps "Killed" out of the test output
  echo "$p"
}

spawn_busy() {
  bash -c 'while :; do :; done' </dev/null >/dev/null 2>&1 &
  local p=$!
  disown "$p" 2>/dev/null || true
  echo "$p"
}

# reap <pid>... : kill the helpers. No `wait`: it would block on anything a
# test left running by accident.
reap() {
  local p
  for p in "$@"; do
    [ -n "$p" ] || continue
    kill -9 "$p" 2>/dev/null || true
  done
}
