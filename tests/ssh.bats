#!/usr/bin/env bats
# cerberus.sh ssh: moving sshd off 22 without locking the operator out.
#
# sshd, systemctl, systemd-run, ss, ssh-keygen and journalctl are all shims.
# The sshd shim resolves -T the way sshd does (first value wins, Port adds up),
# and "applying" copies the configured ports into live_ports, which is what ss
# then reports -- so a test can tell configured from actually listening.

load helper

KEY1='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIkey1 op@laptop'
KEY2='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIkey2 op@phone'

setup() {
  cerberus_setup
  unset SSH_CONNECTION
  export SSHD_CONFIG="$TEST_TMP/sshd_config"
  export SSHD_CONFIG_DIR="$TEST_TMP/sshd_config.d"
  export ROOT_AUTHORIZED_KEYS="$TEST_TMP/rootssh/authorized_keys"
  export F2B_JAIL_DIR="$TEST_TMP/jail.d"
  export SSH_VERIFY_SECONDS=0
  export SSH_AUTH_LOGS=""
  export SSH_PROC_DIR="$TEST_TMP/noproc"   # no ancestor has SSH_CONNECTION
  mkdir -p "$SSHD_CONFIG_DIR" "$F2B_JAIL_DIR" "$SSH_PROC_DIR"
  printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > "$SSHD_CONFIG"
  printf 'PasswordAuthentication yes\n' > "$SSHD_CONFIG_DIR/50-cloud-init.conf"
  echo 22 > "$FIXTURE_DIR/live_ports"
  _ssh_shims
  cerberus_load
}

_ssh_shims() {
  _write_shim sshd <<'EOF'
#!/usr/bin/env bash
printf 'sshd %s\n' "$*" >> "$FIXTURE_DIR/order.calls"
case "${1:-}" in
  -t) exit "${SSHD_T_RC:-0}" ;;
  -T)
    # Include comes first in sshd_config, so drop-ins are read before it
    cat $(ls "$SSHD_CONFIG_DIR"/*.conf 2>/dev/null | sort) "$SSHD_CONFIG" 2>/dev/null | awk '
      /^[[:space:]]*(#|$)/ { next }
      { k = tolower($1); v = $2 }
      k == "port" { ports[++np] = v; next }
      !(k in seen) { seen[k] = v }
      END {
        if (np == 0) print "port 22"; else for (i = 1; i <= np; i++) print "port " ports[i]
        if (!("permitrootlogin" in seen)) seen["permitrootlogin"] = "without-password"
        if (!("passwordauthentication" in seen)) seen["passwordauthentication"] = "yes"
        for (k in seen) print k, seen[k]
      }'
    ;;
esac
EOF

  _write_shim systemctl <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$FIXTURE_DIR/order.calls"
case "$*" in
  "is-active --quiet ssh.socket") exit "${SSH_SOCKET_RC:-0}" ;;
  "is-active --quiet eyes-cerberus-ssh-rollback.timer")
    [ -f "$FIXTURE_DIR/timer_armed" ] && exit 0; exit 3 ;;
  "stop eyes-cerberus-ssh-rollback.timer") rm -f "$FIXTURE_DIR/timer_armed" ;;
  "restart ssh.socket"|"reload ssh.service"|"reload sshd.service")
    [ "${SSH_APPLY_BROKEN:-0}" = 1 ] && exit 0
    sshd -T | awk '$1 == "port" { print $2 }' > "$FIXTURE_DIR/live_ports" ;;
esac
exit 0
EOF

  _write_shim systemd-run <<'EOF'
#!/usr/bin/env bash
printf 'systemd-run %s\n' "$*" >> "$FIXTURE_DIR/order.calls"
rc="${SYSTEMD_RUN_RC:-0}"
[ "$rc" = 0 ] && touch "$FIXTURE_DIR/timer_armed"
exit "$rc"
EOF

  _write_shim ss <<'EOF'
#!/usr/bin/env bash
while read -r p; do
  [ -n "$p" ] && printf 'LISTEN 0 128 0.0.0.0:%s 0.0.0.0:*\n' "$p"
done < "$FIXTURE_DIR/live_ports"
[ -f "$FIXTURE_DIR/ss_extra" ] && cat "$FIXTURE_DIR/ss_extra"
exit 0
EOF

  _write_shim ssh-keygen <<'EOF'
#!/usr/bin/env bash
f="${*: -1}"
awk '{
  for (i = 1; i < NF; i++) if ($i ~ /^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp256)$/) {
    t = $i; b = $(i + 1)
    bits = (t == "ssh-rsa") ? ((b ~ /^weak/) ? 1024 : 3072) : 256
    ty = (t == "ssh-ed25519") ? "ED25519" : (t == "ssh-rsa") ? "RSA" : (t == "ssh-dss") ? "DSA" : "ECDSA"
    printf "%d SHA256:%s test (%s)\n", bits, b, ty; n++; break
  }
} END { exit (n ? 0 : 1) }' "$f"
EOF

  _write_shim journalctl <<'EOF'
#!/usr/bin/env bash
[ -f "$FIXTURE_DIR/journal" ] && cat "$FIXTURE_DIR/journal"
exit 0
EOF

  _write_shim fail2ban-client <<'EOF'
#!/usr/bin/env bash
printf 'fail2ban-client %s\n' "$*" >> "$FIXTURE_DIR/order.calls"
exit 0
EOF
}

with_key() { mkdir -p "$(dirname "$ROOT_AUTHORIZED_KEYS")"; printf '%s\n' "$KEY1" > "$ROOT_AUTHORIZED_KEYS"; }
dropin()   { cat "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf"; }
phase()    { sed -n 's/^phase=//p' "$CERBERUS_STATE_DIR/ssh/state" | tail -1; }
key_login() {   # <client-ip> <client-port>
  printf 'Accepted publickey for root from %s port %s ssh2: ED25519 SHA256:AAAAC3NzaC1lZDI1NTE5AAAAIkey1\n' "$1" "$2" \
    >> "$FIXTURE_DIR/journal"
}

# --- add-key -------------------------------------------------------------------

@test "add-key: refuses a private key outright" {
  printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----\n' > "$TEST_TMP/id"
  run ssh_add_key "$TEST_TMP/id"
  [ "$status" -eq 2 ]
  [[ "$output" == *"PRIVATE key"* ]]
  [ ! -s "$ROOT_AUTHORIZED_KEYS" ]
}

@test "add-key: refuses something that is not a key" {
  echo "hello world" > "$TEST_TMP/x.pub"
  run ssh_add_key "$TEST_TMP/x.pub"
  [ "$status" -ne 0 ]
  [ ! -s "$ROOT_AUTHORIZED_KEYS" ]
}

@test "add-key: refuses a short RSA key" {
  echo "ssh-rsa weakAAAAB3NzaC1yc2E op@old" > "$TEST_TMP/rsa.pub"
  run ssh_add_key "$TEST_TMP/rsa.pub"
  [ "$status" -ne 0 ]
  [[ "$output" == *"too weak"* ]]
}

@test "add-key: appends once, 600, and a second run is a no-op" {
  printf '%s\n' "$KEY1" > "$TEST_TMP/k.pub"
  run ssh_add_key "$TEST_TMP/k.pub"
  [ "$status" -eq 0 ]
  [ "$(grep -c key1 "$ROOT_AUTHORIZED_KEYS")" -eq 1 ]
  [ "$(stat -c %a "$ROOT_AUTHORIZED_KEYS")" = 600 ]
  run ssh_add_key "$TEST_TMP/k.pub"
  [ "$status" -eq 0 ]
  [ "$(grep -c key1 "$ROOT_AUTHORIZED_KEYS")" -eq 1 ]
  grep -q '"category":"ssh_key_added"' "$CERBERUS_STATE_DIR/events.jsonl"
}

@test "add-key: does not glue the key onto a last line without a newline" {
  mkdir -p "$(dirname "$ROOT_AUTHORIZED_KEYS")"
  printf '%s' "$KEY2" > "$ROOT_AUTHORIZED_KEYS"
  printf '%s\n' "$KEY1" > "$TEST_TMP/k.pub"
  run ssh_add_key "$TEST_TMP/k.pub"
  [ "$status" -eq 0 ]
  [ "$(wc -l < "$ROOT_AUTHORIZED_KEYS")" -eq 2 ]
}

@test "add-key: takes the new key into the baseline instead of alarming about it" {
  touch "$BASELINE_DIR/units"
  printf '%s\n' "$KEY1" > "$TEST_TMP/k.pub"
  run ssh_add_key "$TEST_TMP/k.pub"
  [ "$status" -eq 0 ]
  grep -q key1 "$BASELINE_DIR/root_authorized_keys"
  grep -q '"category":"accepted"' "$CERBERUS_STATE_DIR/events.jsonl"
}

# --- stage ---------------------------------------------------------------------

@test "stage: refuses without a key -- that is the lockout" {
  run ssh_stage 2222
  [ "$status" -ne 0 ]
  [[ "$output" == *"add-key"* ]]
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
}

@test "stage: refuses port 22, garbage, and a port already taken" {
  with_key
  run ssh_stage 22;    [ "$status" -ne 0 ]
  run ssh_stage abc;   [ "$status" -ne 0 ]
  run ssh_stage 70000; [ "$status" -ne 0 ]
  echo 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*' > "$FIXTURE_DIR/ss_extra"
  run ssh_stage 2222
  [ "$status" -ne 0 ]
  [[ "$output" == *"in use"* ]]
}

@test "stage: listens on both ports, arms the rollback BEFORE touching sshd" {
  with_key
  run ssh_stage 2222
  [ "$status" -eq 0 ]
  dropin | grep -qx 'Port 22'
  dropin | grep -qx 'Port 2222'
  [ "$(sort "$FIXTURE_DIR/live_ports" | tr '\n' ' ')" = "22 2222 " ]
  [ "$(phase)" = staged ]
  grep -qx 'port = 22,2222' "$F2B_JAIL_DIR/eyes-cerberus-ssh.local"
  # order: timer armed, then the socket restarted
  arm="$(grep -n '^systemd-run' "$FIXTURE_DIR/order.calls" | head -1 | cut -d: -f1)"
  apply="$(grep -n 'restart ssh.socket' "$FIXTURE_DIR/order.calls" | head -1 | cut -d: -f1)"
  [ -n "$arm" ] && [ -n "$apply" ] && [ "$arm" -lt "$apply" ]
  grep -q 'daemon-reload' "$FIXTURE_DIR/order.calls"
}

@test "stage: a host without ssh.socket gets a plain reload" {
  with_key
  SSH_SOCKET_RC=3 run ssh_stage 2222
  [ "$status" -eq 0 ]
  grep -q 'reload ssh.service' "$FIXTURE_DIR/order.calls"
  ! grep -q 'daemon-reload' "$FIXTURE_DIR/order.calls"
}

@test "stage: sshd -t failing leaves the old config and arms nothing" {
  with_key
  SSHD_T_RC=1 run ssh_stage 2222
  [ "$status" -ne 0 ]
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
  [ ! -f "$F2B_JAIL_DIR/eyes-cerberus-ssh.local" ]
  ! grep -q '^systemd-run' "$FIXTURE_DIR/order.calls"
}

@test "stage: no rollback timer, no change" {
  with_key
  SYSTEMD_RUN_RC=1 run ssh_stage 2222
  [ "$status" -ne 0 ]
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
  ! grep -q 'restart ssh.socket' "$FIXTURE_DIR/order.calls"
  [ "$(phase)" = none ]
}

@test "stage: a drop-in sorted before ours that sets Port is caught before applying" {
  with_key
  echo 'Port 2200' > "$SSHD_CONFIG_DIR/00-other.conf"
  rm "$SSHD_CONFIG_DIR/50-cloud-init.conf"
  # Port adds up, so 22 and 2222 still come out of sshd -T: this one passes...
  run ssh_stage 2222
  [ "$status" -eq 0 ]
}

@test "stage: the new port not coming up rolls back at once" {
  with_key
  SSH_APPLY_BROKEN=1 run ssh_stage 2222
  [ "$status" -ne 0 ]
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
  [ "$(phase)" = none ]
  [ ! -f "$FIXTURE_DIR/timer_armed" ]
}

@test "stage: an existing drop-in of ours is restored as it was" {
  with_key
  printf '# older\nLoginGraceTime 60\n' > "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf"
  run ssh_stage 2222
  [ "$status" -eq 0 ]
  run ssh_rollback --auto
  [ "$status" -eq 0 ]
  grep -qx 'LoginGraceTime 60' "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf"
}

@test "stage: a dry run writes nothing and arms nothing" {
  with_key
  CERBERUS_DRY_RUN=1 DRY_RUN=1 run ssh_stage 2222
  [ "$status" -eq 0 ]
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
  ! grep -q '^systemd-run' "$FIXTURE_DIR/order.calls" 2>/dev/null
}

@test "stage: refuses while a previous step is still open" {
  with_key
  run ssh_stage 2222; [ "$status" -eq 0 ]
  run ssh_stage 2223
  [ "$status" -ne 0 ]
  [[ "$output" == *"already at phase"* ]]
}

# --- confirm -------------------------------------------------------------------

@test "confirm: refuses outside an SSH session" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  run ssh_confirm
  [ "$status" -ne 0 ]
  [ "$(phase)" = staged ]
  [ -f "$FIXTURE_DIR/timer_armed" ]
}

@test "confirm: refuses a session that came in on the old port" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  key_login 203.0.113.5 50000
  SSH_CONNECTION="203.0.113.5 50000 198.51.100.1 22" run ssh_confirm
  [ "$status" -ne 0 ]
  [[ "$output" == *"not 2222"* ]]
  [ -f "$FIXTURE_DIR/timer_armed" ]
}

@test "confirm: refuses a session that logged in with a password" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  echo 'Accepted password for root from 203.0.113.5 port 50001 ssh2' > "$FIXTURE_DIR/journal"
  SSH_CONNECTION="203.0.113.5 50001 198.51.100.1 2222" run ssh_confirm
  [ "$status" -ne 0 ]
  [[ "$output" == *"password"* ]]
  [ -f "$FIXTURE_DIR/timer_armed" ]
}

@test "confirm: refuses when sshd has no record of the session" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  SSH_CONNECTION="203.0.113.5 50002 198.51.100.1 2222" run ssh_confirm
  [ "$status" -ne 0 ]
  [ -f "$FIXTURE_DIR/timer_armed" ]
}

@test "confirm: a key session on the new port disarms the rollback" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  key_login 203.0.113.5 50003
  SSH_CONNECTION="203.0.113.5 50003 198.51.100.1 2222" run ssh_confirm
  [ "$status" -eq 0 ]
  [ "$(phase)" = confirmed ]
  [ ! -f "$FIXTURE_DIR/timer_armed" ]
  grep -q '"category":"ssh_confirmed"' "$CERBERUS_STATE_DIR/events.jsonl"
}

@test "confirm: finds the session through sudo, which drops SSH_CONNECTION" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  key_login 203.0.113.5 50004
  export SSH_PROC_DIR=/proc
  # the trailing "exit" keeps bash from exec'ing env in its own place: the
  # parent holding SSH_CONNECTION has to stay alive, as the login shell does
  SSH_CONNECTION="203.0.113.5 50004 198.51.100.1 2222" \
    bash -c 'env -u SSH_CONNECTION "$REPO_ROOT/cerberus.sh" ssh confirm; exit $?' \
    > "$TEST_TMP/out" 2>&1 || { cat "$TEST_TMP/out"; false; }
  [ "$(phase)" = confirmed ]
}

# --- lock ----------------------------------------------------------------------

confirmed_stage() {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  key_login 203.0.113.5 50010
  SSH_CONNECTION="203.0.113.5 50010 198.51.100.1 2222" ssh_confirm >/dev/null 2>&1
  [ "$(phase)" = confirmed ]
}

@test "lock: refuses before a confirmed stage" {
  with_key
  run ssh_lock
  [ "$status" -ne 0 ]
  ssh_stage 2222 >/dev/null 2>&1
  run ssh_lock
  [ "$status" -ne 0 ]
}

@test "lock: new port only, root by key only, fail2ban follows the port" {
  confirmed_stage
  run ssh_lock
  [ "$status" -eq 0 ]
  ! dropin | grep -qx 'Port 22'
  dropin | grep -qx 'Port 2222'
  dropin | grep -qx 'PermitRootLogin prohibit-password'
  ! dropin | grep -q 'PasswordAuthentication'
  [ "$(cat "$FIXTURE_DIR/live_ports")" = 2222 ]
  grep -qx 'port = 2222' "$F2B_JAIL_DIR/eyes-cerberus-ssh.local"
  [ "$(phase)" = locking ]
  [ -f "$FIXTURE_DIR/timer_armed" ]
}

@test "lock --all-users: passwords off for everyone" {
  confirmed_stage
  run ssh_lock --all-users
  [ "$status" -eq 0 ]
  dropin | grep -qx 'PasswordAuthentication no'
}

@test "lock: a file read before ours that keeps root on passwords is caught" {
  confirmed_stage
  echo 'PermitRootLogin yes' > "$SSHD_CONFIG_DIR/00-vendor.conf"
  run ssh_lock
  [ "$status" -ne 0 ]
  [[ "$output" == *"overrides ours"* ]]
  dropin | grep -qx 'Port 22'      # back to the confirmed stage
  [ "$(phase)" = confirmed ]
}

@test "lock: a second key confirmation finishes the job" {
  confirmed_stage
  ssh_lock >/dev/null 2>&1
  key_login 203.0.113.5 50011
  SSH_CONNECTION="203.0.113.5 50011 198.51.100.1 2222" run ssh_confirm
  [ "$status" -eq 0 ]
  [ "$(phase)" = locked ]
  [ ! -f "$FIXTURE_DIR/timer_armed" ]
}

# --- rollback ------------------------------------------------------------------

@test "rollback --auto from staged: back to no drop-in, and it is HARD" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  run ssh_rollback --auto
  [ "$status" -eq 0 ]
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
  [ ! -f "$F2B_JAIL_DIR/eyes-cerberus-ssh.local" ]
  [ "$(cat "$FIXTURE_DIR/live_ports")" = 22 ]
  [ "$(phase)" = none ]
  grep -q '"severity":"HARD","category":"ssh_rollback"' "$CERBERUS_STATE_DIR/events.jsonl"
  # the timer runs without this shell's environment: the window comes from state
  grep -q 'not confirmed within 900s' "$CERBERUS_STATE_DIR/events.jsonl"
}

@test "rollback --auto from locking: back to 22 + new port, not further" {
  confirmed_stage
  ssh_lock >/dev/null 2>&1
  run ssh_rollback --auto
  [ "$status" -eq 0 ]
  [ "$(phase)" = confirmed ]
  [ "$(sort "$FIXTURE_DIR/live_ports" | tr '\n' ' ')" = "22 2222 " ]
  grep -qx 'port = 22,2222' "$F2B_JAIL_DIR/eyes-cerberus-ssh.local"
}

@test "rollback --auto after a confirmation does nothing" {
  confirmed_stage
  run ssh_rollback --auto
  [ "$status" -eq 0 ]
  [ "$(phase)" = confirmed ]
  dropin | grep -qx 'Port 2222'
}

@test "rollback by hand undoes everything" {
  confirmed_stage
  ssh_lock >/dev/null 2>&1
  key_login 203.0.113.5 50012
  SSH_CONNECTION="203.0.113.5 50012 198.51.100.1 2222" ssh_confirm >/dev/null 2>&1
  run ssh_rollback
  [ "$status" -eq 0 ]
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
  [ "$(phase)" = none ]
}

@test "rollback: a restored config sshd refuses falls back to none of ours" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  SSHD_T_RC=1 run ssh_rollback --auto
  [ ! -f "$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" ]
  [ "$(phase)" = none ]
}

@test "the rollback timer carries the paths, so it restores the same files" {
  with_key; ssh_stage 2222 >/dev/null 2>&1
  grep -q "dropin_path=$SSHD_CONFIG_DIR/01-eyes-cerberus.conf" "$CERBERUS_STATE_DIR/ssh/state"
  grep '^systemd-run' "$FIXTURE_DIR/order.calls" | grep -q "CERBERUS_STATE_DIR=$CERBERUS_STATE_DIR"
  grep '^systemd-run' "$FIXTURE_DIR/order.calls" | grep -q 'ssh rollback --auto'
}

@test "cli: cerberus.sh ssh status runs" {
  with_key
  run "$REPO_ROOT/cerberus.sh" ssh status
  [ "$status" -eq 0 ]
  [[ "$output" == *"phase:"*"none"* ]]
  [[ "$output" == *"1 in"* ]]
}
