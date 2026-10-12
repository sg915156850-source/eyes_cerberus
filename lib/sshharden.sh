#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/sshharden.sh
# `cerberus.sh ssh ...`: take sshd off port 22 and stop root password logins
# without locking the operator out of the host.
#
# The order is the whole point:
#
#   add-key   put a public key into root's authorized_keys
#   stage     sshd listens on 22 AND the new port; nothing is taken away yet
#   confirm   run from a NEW session that got in with a key on the new port
#   lock      new port only, root may no longer log in with a password
#   confirm   again, from another new key session on the new port
#
# Every step that changes sshd first arms a transient systemd timer that puts
# the previous configuration back after SSH_CONFIRM_SECONDS. Only `confirm`
# disarms it, and only a session that demonstrably logged in with a key on the
# new port may run it. An operator who cannot get in does nothing, and the host
# restores itself. Without systemd-run there is no such safety net, so the
# steps refuse to change anything.
#
# Changes are made through one drop-in, $SSH_DROPIN, named to sort first:
# sshd takes the FIRST value it reads for most directives, and Ubuntu cloud
# images ship 50-cloud-init.conf with "PasswordAuthentication yes".
# Sourced after lib/common.sh and lib/baseline.sh.
#===============================================================================

SSH_DROPIN="${SSH_DROPIN:-$SSHD_CONFIG_DIR/01-eyes-cerberus.conf}"
SSH_AUTH_KEYS="${SSH_AUTH_KEYS:-$ROOT_AUTHORIZED_KEYS}"
F2B_JAIL_DIR="${F2B_JAIL_DIR:-/etc/fail2ban/jail.d}"
SSH_F2B_DROPIN="${SSH_F2B_DROPIN:-$F2B_JAIL_DIR/eyes-cerberus-ssh.local}"
SSH_CONFIRM_SECONDS="${SSH_CONFIRM_SECONDS:-900}"
SSH_VERIFY_SECONDS="${SSH_VERIFY_SECONDS:-10}"
SSH_AUTH_LOGS="${SSH_AUTH_LOGS-/var/log/auth.log /var/log/secure}"
SSH_ROLLBACK_UNIT="eyes-cerberus-ssh-rollback"
SSH_PROC_DIR="${SSH_PROC_DIR:-/proc}"

_ssh_dir() { printf '%s/ssh' "$STATE_DIR"; }

# --- state: key=value lines, read with sed, never sourced -------------------
_ssh_get() {
  local f; f="$(_ssh_dir)/state"
  [ -f "$f" ] || return 0
  sed -n "s/^$1=//p" "$f" | tail -1
}

# _ssh_set <key> <value> [<key> <value>...]
_ssh_set() {
  local d f tmp; d="$(_ssh_dir)"; f="$d/state"
  mkdir -p "$d" && chmod 700 "$d"
  tmp="$(mktemp "$d/.state.XXXXXX")" || return 1
  [ -f "$f" ] && cp "$f" "$tmp"
  while [ $# -ge 2 ]; do
    sed -i "/^$1=/d" "$tmp"
    printf '%s=%s\n' "$1" "$2" >> "$tmp"
    shift 2
  done
  mv -f "$tmp" "$f"
}

# --- keys ---------------------------------------------------------------------
# _ssh_key_fp <line> : "bits SHA256:... comment (TYPE)" for one public key line.
_ssh_key_fp() {
  local tmp out rc
  tmp="$(mktemp)" || return 1
  printf '%s\n' "$1" > "$tmp"
  out="$(ssh-keygen -l -f "$tmp" 2>/dev/null)"; rc=$?
  rm -f "$tmp"
  [ "$rc" -eq 0 ] && [ -n "$out" ] || return 1
  printf '%s\n' "$out" | head -1
}

# _ssh_key_blob <line> : the base64 key material, the field after the key type.
# Options in front of the type ("from=...") are skipped.
_ssh_key_blob() {
  local w prev=""
  for w in $1; do
    case "$prev" in
      ssh-*|ecdsa-*|sk-*) printf '%s\n' "$w"; return 0 ;;
    esac
    prev="$w"
  done
  return 1
}

# _ssh_count_keys : how many keys sshd would accept from $SSH_AUTH_KEYS.
_ssh_count_keys() {
  [ -s "$SSH_AUTH_KEYS" ] || { echo 0; return 0; }
  ssh-keygen -l -f "$SSH_AUTH_KEYS" 2>/dev/null | grep -c 'SHA256:' || true
}

ssh_add_key() {
  local src="${1:-}" input line fp bits blob added=0 bad=0
  [ -n "$src" ] || { err "usage: cerberus.sh ssh add-key <file.pub|->"; return 2; }
  require_tool ssh-keygen || return 1
  if [ "$src" = "-" ]; then
    input="$(cat)"
  else
    [ -r "$src" ] || { err "cannot read $src"; return 2; }
    input="$(cat "$src")"
  fi
  case "$input" in
    *"PRIVATE KEY"*)
      err "this is a PRIVATE key. It never leaves your computer -- pass the .pub file"
      return 2 ;;
  esac

  while IFS= read -r line; do
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    if ! fp="$(_ssh_key_fp "$line")"; then
      err "not a public key: ${line:0:40}..."
      bad=1; continue
    fi
    bits="${fp%% *}"
    case "$fp" in
      *"(DSA)")
        err "DSA keys are refused by current OpenSSH: $fp"; bad=1; continue ;;
      *"(RSA)")
        if [ "$bits" -lt 2048 ] 2>/dev/null; then
          err "RSA key of $bits bits is too weak, use ed25519: $fp"; bad=1; continue
        fi ;;
    esac
    blob="$(_ssh_key_blob "$line")" || { err "cannot parse: ${line:0:40}..."; bad=1; continue; }
    if [ -f "$SSH_AUTH_KEYS" ] && grep -qF " $blob" "$SSH_AUTH_KEYS"; then
      info "already present: $fp"
      continue
    fi
    if ! state_writable; then
      log DRY "would add to $SSH_AUTH_KEYS: $fp"
      continue
    fi
    mkdir -p "$(dirname "$SSH_AUTH_KEYS")"
    chmod 700 "$(dirname "$SSH_AUTH_KEYS")"
    # a file without a final newline would glue our key onto its last line
    if [ -s "$SSH_AUTH_KEYS" ] && [ -n "$(tail -c1 "$SSH_AUTH_KEYS")" ]; then
      printf '\n' >> "$SSH_AUTH_KEYS"
    fi
    printf '%s\n' "$line" >> "$SSH_AUTH_KEYS"
    chmod 600 "$SSH_AUTH_KEYS"
    added=$((added + 1))
    emit_event SOFT ssh_key_added "-" "key added to $SSH_AUTH_KEYS: $fp"
  done <<< "$input"

  if [ "$added" -gt 0 ]; then
    baseline_accept_category root_authorized_keys "$added key(s) added by 'cerberus.sh ssh add-key'"
  fi
  [ "$bad" = 0 ]
}

# --- sshd ---------------------------------------------------------------------
_ssh_sshd() {
  local b; b="$(command -v sshd 2>/dev/null || true)"
  [ -n "$b" ] || { [ -x /usr/sbin/sshd ] && b=/usr/sbin/sshd; }
  [ -n "$b" ] || { err "sshd not found"; return 127; }
  "$b" "$@"
}

# _ssh_effective <directive> : its value(s) as sshd itself resolves them.
_ssh_effective() {
  _ssh_sshd -T 2>/dev/null | awk -v k="$1" 'tolower($1) == k { $1 = ""; sub(/^ /, ""); print }'
}

_ssh_valid_port() {
  case "${1:-}" in
    ''|*[!0-9]*) err "port must be a number, got '${1:-}'"; return 1 ;;
  esac
  if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then err "port $1 is out of range"; return 1; fi
  if [ "$1" = 22 ]; then err "the point is to leave port 22; pick another"; return 1; fi
  return 0
}

# No `producer | grep -q` anywhere in this file: under pipefail the producer's
# SIGPIPE, after grep -q has already matched and exited, turns a match into 141.
_ssh_listening() {
  local ports
  ports="$(ss -tlnH 2>/dev/null | awk '{print $4}')" || true
  grep -qE "[:.]$1\$" <<<"$ports"
}

# _ssh_wait_listen <port> : the port is listening within SSH_VERIFY_SECONDS.
_ssh_wait_listen() {
  local i=0
  while :; do
    _ssh_listening "$1" && return 0
    [ "$i" -ge "$SSH_VERIFY_SECONDS" ] && return 1
    sleep 1; i=$((i + 1))
  done
}

_ssh_socket_activated() {
  systemctl is-active --quiet ssh.socket 2>/dev/null
}

# _ssh_apply : make the running sshd pick up the configuration.
_ssh_apply() {
  if _ssh_socket_activated; then
    # Ubuntu 22.10+: the listening ports belong to ssh.socket, generated from
    # sshd_config at daemon-reload. Reloading ssh.service alone keeps the old
    # ports. Restarting the socket restarts ssh.service, whose KillMode=process
    # leaves every open session alone.
    systemctl daemon-reload && systemctl restart ssh.socket
  else
    systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
  fi
}

_ssh_reload_f2b() {
  [ -n "$(_ssh_get f2b_path)" ] || return 0
  command -v fail2ban-client >/dev/null 2>&1 || return 0
  fail2ban-client reload sshd >/dev/null 2>&1 || warn "fail2ban did not reload the sshd jail"
}

# _ssh_firewall_warn <port> : a closed INPUT policy with no rule for the port
# means the new port is unreachable. The rollback would catch it; saying so
# up front saves the operator fifteen minutes.
_ssh_firewall_warn() {
  local port="$1" rules
  if command -v iptables >/dev/null 2>&1; then
    rules="$(iptables -S INPUT 2>/dev/null)" || true
    if grep -qE '^-P INPUT (DROP|REJECT)' <<<"$rules" && \
       ! grep -qE -- "--dport $port( |$)" <<<"$rules"; then
      warn "INPUT policy drops by default and no rule opens port $port -- open it first"
    fi
  fi
  if command -v ufw >/dev/null 2>&1; then
    rules="$(ufw status 2>/dev/null)" || true   # not root, or not set up: no output
    if grep -q '^Status: active' <<<"$rules"; then
      grep -qE "^$port(/tcp)? " <<<"$rules" || \
        warn "ufw is active and has no rule for $port -- run: ufw allow $port/tcp"
    fi
  fi
  info "a firewall at the hosting provider is invisible from here: if port $port is closed there, the new session will not connect and the change rolls back by itself"
}

# --- drop-ins and snapshots ---------------------------------------------------
_ssh_write_dropin() {
  local phase="$1"; shift
  {
    printf '# Managed by eyes-cerberus: cerberus.sh ssh (%s). Do not edit by hand;\n' "$phase"
    printf '# undo with: cerberus.sh ssh rollback\n'
    printf '%s\n' "$@"
  } > "$SSH_DROPIN.tmp" && chmod 644 "$SSH_DROPIN.tmp" && mv -f "$SSH_DROPIN.tmp" "$SSH_DROPIN"
}

_ssh_write_f2b() {
  local path; path="$(_ssh_get f2b_path)"
  [ -n "$path" ] || return 0
  printf '# Managed by eyes-cerberus: cerberus.sh ssh\n[sshd]\nport = %s\n' "$1" > "$path"
}

# _ssh_snapshot <name> : remember the drop-ins as they are now.
_ssh_snapshot() {
  local d kind path; d="$(_ssh_dir)"
  mkdir -p "$d" && chmod 700 "$d"
  for kind in dropin f2b; do
    path="$(_ssh_get "${kind}_path")"
    rm -f "$d/$1.$kind" "$d/$1.$kind.absent"
    [ -n "$path" ] || continue
    if [ -f "$path" ]; then
      cp -p "$path" "$d/$1.$kind" || return 1
    else
      : > "$d/$1.$kind.absent"
    fi
  done
}

# _ssh_restore <name> : put the drop-ins back as _ssh_snapshot found them.
_ssh_restore() {
  local d kind path; d="$(_ssh_dir)"
  for kind in dropin f2b; do
    path="$(_ssh_get "${kind}_path")"
    [ -n "$path" ] || continue
    if [ -f "$d/$1.$kind.absent" ]; then
      rm -f "$path"
    elif [ -f "$d/$1.$kind" ]; then
      cp -p "$d/$1.$kind" "$path"
    fi
  done
}

# --- the safety net -------------------------------------------------------------
_ssh_arm_rollback() {
  require_tool systemd-run || { err "no systemd-run: no automatic rollback, so no change"; return 1; }
  systemctl stop "$SSH_ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$SSH_ROLLBACK_UNIT.timer" "$SSH_ROLLBACK_UNIT.service" >/dev/null 2>&1 || true
  if ! systemd-run --quiet --unit="$SSH_ROLLBACK_UNIT" \
        --on-active="${SSH_CONFIRM_SECONDS}s" --timer-property=AccuracySec=1s \
        --setenv=CERBERUS_LAYOUT="$CERBERUS_LAYOUT" \
        --setenv=CERBERUS_CONF_DIR="$ETC_DIR" \
        --setenv=CERBERUS_STATE_DIR="$STATE_DIR" \
        "$CERBERUS_ROOT/cerberus.sh" ssh rollback --auto; then
    err "could not arm the rollback timer"
    return 1
  fi
  systemctl is-active --quiet "$SSH_ROLLBACK_UNIT.timer" || {
    err "the rollback timer did not start"; return 1; }
  _ssh_set deadline "$(( $(date +%s) + SSH_CONFIRM_SECONDS ))" window "$SSH_CONFIRM_SECONDS"
}

_ssh_disarm_rollback() {
  systemctl stop "$SSH_ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true
  _ssh_set deadline ""
}

# _ssh_after_change <port> : the daemon's own detectors would report this change
# as new persistence and a new listener. It was made here, on purpose, so
# record it rather than alarm about it.
_ssh_after_change() {
  baseline_accept_category sshd_config "changed by 'cerberus.sh ssh' ($(_ssh_get phase))"
  if [ -n "${1:-}" ] && [ -f "$BASELINE_DIR/listeners" ] && state_writable; then
    grep -qxF "$1" "$BASELINE_DIR/listeners" || printf '%s\n' "$1" >> "$BASELINE_DIR/listeners"
  fi
}

# --- who is running this ---------------------------------------------------------
# _ssh_session_conn : SSH_CONNECTION of the session this command runs in. sudo
# drops it from the environment; the login shell above us still has it.
_ssh_session_conn() {
  if [ -n "${SSH_CONNECTION:-}" ]; then
    printf '%s\n' "$SSH_CONNECTION"; return 0
  fi
  local pid="$$" val
  while [ -n "$pid" ] && [ "$pid" -gt 1 ] 2>/dev/null; do
    val="$(tr '\0' '\n' < "$SSH_PROC_DIR/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -1)"
    [ -n "$val" ] && { printf '%s\n' "$val"; return 0; }
    pid="$(awk '/^PPid:/ {print $2}' "$SSH_PROC_DIR/$pid/status" 2>/dev/null)"
  done
  return 1
}

# _ssh_auth_line <client-ip> <client-port> <since-epoch> : sshd's "Accepted ..."
# line for that connection.
_ssh_auth_line() {
  local pat=" from $1 port $2 " out="" f
  if command -v journalctl >/dev/null 2>&1; then
    out="$(journalctl -q --no-pager -o cat --since "@$3" -t sshd -t sshd-session 2>/dev/null \
      | grep -F "$pat" | grep -E '^Accepted ' | tail -1)"
  fi
  if [ -z "$out" ]; then
    for f in $SSH_AUTH_LOGS; do
      [ -r "$f" ] || continue
      out="$(tail -n 20000 "$f" | grep -F "$pat" | grep -oE 'Accepted [a-z-]+ for .*' | tail -1)"
      [ -n "$out" ] && break
    done
  fi
  printf '%s\n' "$out"
}

# --- commands -------------------------------------------------------------------
ssh_status() {
  local phase port n
  phase="$(_ssh_get phase)"; port="$(_ssh_get port)"
  echo "phase:            ${phase:-none}${port:+ (new port $port)}"
  if systemctl is-active --quiet "$SSH_ROLLBACK_UNIT.timer" 2>/dev/null; then
    local dl; dl="$(_ssh_get deadline)"
    echo "rollback:         ARMED, in $(( ${dl:-0} - $(date +%s) ))s unless confirmed"
  fi
  echo "listening ports:  $(_ssh_effective port | tr '\n' ' ')"
  echo "PermitRootLogin:  $(_ssh_effective permitrootlogin)"
  echo "PasswordAuth:     $(_ssh_effective passwordauthentication)"
  n="$(_ssh_count_keys)"
  echo "keys:             $n in $SSH_AUTH_KEYS"
  [ -f "$SSH_F2B_DROPIN" ] && echo "fail2ban sshd:    port = $(sed -n 's/^port = //p' "$SSH_F2B_DROPIN")"
  return 0
}

# _ssh_prepare_paths : record where this run writes, so a rollback started by the
# timer -- with none of this shell's environment -- restores the same files.
_ssh_prepare_paths() {
  local f2b=""
  [ -d "$(dirname "$SSH_F2B_DROPIN")" ] && f2b="$SSH_F2B_DROPIN"
  _ssh_set dropin_path "$SSH_DROPIN" f2b_path "$f2b"
}

ssh_stage() {
  local port="${1:-}" phase
  _ssh_valid_port "$port" || return 2
  phase="$(_ssh_get phase)"
  if [ -n "$phase" ] && [ "$phase" != none ]; then
    err "already at phase '$phase' -- confirm, lock or roll back first (cerberus.sh ssh status)"
    return 1
  fi
  if _ssh_listening "$port"; then
    err "port $port is already in use"; return 1
  fi
  local n; n="$(_ssh_count_keys)"
  if [ "${n:-0}" -lt 1 ]; then
    err "no usable key in $SSH_AUTH_KEYS -- run 'cerberus.sh ssh add-key <file.pub>' first"
    return 1
  fi
  _ssh_firewall_warn "$port"

  if ! state_writable; then
    log DRY "would write $SSH_DROPIN with: Port 22, Port $port"
    log DRY "would arm a ${SSH_CONFIRM_SECONDS}s rollback, then reload sshd"
    return 0
  fi

  _ssh_prepare_paths
  _ssh_snapshot orig || { err "could not save the current configuration"; return 1; }
  _ssh_write_dropin stage "Port 22" "Port $port"
  _ssh_write_f2b "22,$port"
  if ! _ssh_sshd -t; then
    _ssh_restore orig
    err "sshd -t rejects the new configuration; nothing changed"
    return 1
  fi
  local ports; ports=" $(_ssh_effective port | sort -u | tr '\n' ' ')"
  case "$ports" in *" 22 "*) ;; *) ports="!$ports" ;; esac
  case "$ports" in *" $port "*) ;; *) ports="!$ports" ;; esac
  if [ "${ports:0:1}" = "!" ]; then
    _ssh_restore orig
    err "sshd would listen on '${ports##*!}', not on 22 and $port -- another config file overrides ours; nothing changed"
    return 1
  fi
  _ssh_set phase staged port "$port" since "$(date +%s)"
  if ! _ssh_arm_rollback; then
    _ssh_restore orig; _ssh_set phase none
    return 1
  fi
  if ! _ssh_apply || ! _ssh_wait_listen "$port" || ! _ssh_wait_listen 22; then
    err "sshd is not listening on both 22 and $port -- rolling back now"
    ssh_rollback --now
    return 1
  fi
  _ssh_reload_f2b
  _ssh_after_change "$port"
  emit_event SOFT ssh_staged "-" \
    "sshd listens on 22 and $port; rolls back in ${SSH_CONFIRM_SECONDS}s unless confirmed from a key session on $port"
  cat <<EOF

sshd now listens on 22 AND $port. Keep this session open.

Within $(( SSH_CONFIRM_SECONDS / 60 )) minutes, from your own computer:
    ssh -p $port -i <your private key> root@<this server>
and in THAT new session run:
    $CERBERUS_ROOT/cerberus.sh ssh confirm

If you cannot get in, do nothing: the previous configuration comes back by itself.
EOF
}

ssh_confirm() {
  local phase port conn cip cport sport acc fp
  phase="$(_ssh_get phase)"; port="$(_ssh_get port)"
  case "$phase" in
    staged|locking) ;;
    *) err "nothing to confirm (phase: ${phase:-none})"; return 1 ;;
  esac
  if ! conn="$(_ssh_session_conn)"; then
    err "this is not an SSH session -- run it from the new session you opened on port $port"
    return 1
  fi
  read -r cip cport _ sport <<< "$conn"
  if [ "$sport" != "$port" ]; then
    err "this session came in on port $sport, not $port. Open a new one with 'ssh -p $port' and confirm from there"
    return 1
  fi
  acc="$(_ssh_auth_line "$cip" "$cport" "$(_ssh_get since)")"
  case "$acc" in
    "Accepted publickey "*) ;;
    "")
      err "no sshd record of how this session logged in (looked for 'Accepted ... from $cip port $cport')"
      return 1 ;;
    *)
      err "this session logged in with '$(printf '%s' "$acc" | awk '{print $2}')', not a key -- the key is what is being proven"
      return 1 ;;
  esac
  fp="$(printf '%s' "$acc" | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | head -1)"

  _ssh_disarm_rollback
  if [ "$phase" = staged ]; then
    _ssh_set phase confirmed key "$fp"
    emit_event SOFT ssh_confirmed "-" \
      "key ${fp:-?} gets in on port $port from $cip; port 22 and passwords stay until 'cerberus.sh ssh lock'"
    cat <<EOF
Confirmed: key login on port $port works. Rollback disarmed.
Port 22 and root password login still work. Next, from this session:
    $CERBERUS_ROOT/cerberus.sh ssh lock
EOF
  else
    _ssh_set phase locked key "$fp"
    emit_event SOFT ssh_locked "-" \
      "sshd only on port $port, root logs in with a key only (confirmed with ${fp:-?} from $cip)"
    echo "Confirmed: sshd is on port $port only and root logs in with a key only. Done."
  fi
}

ssh_lock() {
  local all=0 phase port
  [ "${1:-}" = "--all-users" ] && all=1
  phase="$(_ssh_get phase)"; port="$(_ssh_get port)"
  if [ "$phase" != confirmed ]; then
    err "lock comes after a confirmed stage (phase: ${phase:-none})"
    return 1
  fi
  local n; n="$(_ssh_count_keys)"
  if [ "${n:-0}" -lt 1 ]; then
    err "no usable key left in $SSH_AUTH_KEYS -- not taking passwords away"
    return 1
  fi
  # No MaxAuthTries here: an agent holding several keys offers them one by one,
  # and a low limit locks out exactly the operator this is meant to protect.
  local lines=("Port $port" "PermitRootLogin prohibit-password" "LoginGraceTime 30")
  [ "$all" = 1 ] && lines+=("PasswordAuthentication no" "KbdInteractiveAuthentication no")

  if ! state_writable; then
    log DRY "would write $SSH_DROPIN with: ${lines[*]}"
    return 0
  fi

  _ssh_snapshot confirmed || { err "could not save the current configuration"; return 1; }
  _ssh_write_dropin lock "${lines[@]}"
  _ssh_write_f2b "$port"
  if ! _ssh_sshd -t; then
    _ssh_restore confirmed
    err "sshd -t rejects the new configuration; nothing changed"
    return 1
  fi
  # Another file read before ours, or a Match block, could still win. Ask sshd
  # what it will actually do rather than trust the file we wrote.
  local prl ports
  prl="$(_ssh_effective permitrootlogin)"
  ports="$(_ssh_effective port | sort -u | tr '\n' ' ')"
  if [ "$ports" != "$port " ] || { [ "$prl" != prohibit-password ] && [ "$prl" != without-password ]; }; then
    _ssh_restore confirmed
    err "sshd would resolve this to ports '$ports' and PermitRootLogin '$prl' -- another config file overrides ours; nothing changed"
    return 1
  fi
  _ssh_set phase locking since "$(date +%s)"
  if ! _ssh_arm_rollback; then
    _ssh_restore confirmed; _ssh_set phase confirmed
    return 1
  fi
  if ! _ssh_apply || ! _ssh_wait_listen "$port"; then
    err "sshd is not listening on $port -- rolling back now"
    ssh_rollback --now
    return 1
  fi
  _ssh_listening 22 && warn "something still listens on 22 -- check: ss -tlnp 'sport = :22'"
  _ssh_reload_f2b
  _ssh_after_change
  emit_event SOFT ssh_locking "-" \
    "sshd only on $port, root by key only; rolls back in ${SSH_CONFIRM_SECONDS}s unless confirmed"
  cat <<EOF

sshd now listens on $port only; root may log in with a key only. Keep this session open.

Within $(( SSH_CONFIRM_SECONDS / 60 )) minutes open ANOTHER new session:
    ssh -p $port -i <your private key> root@<this server>
and run there:
    $CERBERUS_ROOT/cerberus.sh ssh confirm

Remember to update your own ~/.ssh/config (Port $port, IdentityFile) and any
tool that connects here, VS Code Remote-SSH included.
EOF
}

# ssh_rollback [--auto|--now] : put back the configuration from before the step
# that is waiting for confirmation. --auto is the timer; after a confirmation
# it has nothing to do. With no flag, an operator undoes everything.
ssh_rollback() {
  local mode phase target newphase
  case "${1:-}" in
    "")     mode=manual ;;
    --auto) mode=auto ;;
    --now)  mode=now ;;
    *) err "usage: cerberus.sh ssh rollback"; return 2 ;;
  esac
  phase="$(_ssh_get phase)"
  case "$phase" in
    staged)  target=orig;      newphase=none ;;
    locking) target=confirmed; newphase=confirmed ;;
    confirmed|locked)
      if [ "$mode" != manual ]; then
        info "ssh rollback: phase is '$phase', already confirmed -- nothing to do"
        return 0
      fi
      target=orig; newphase=none ;;
    *)
      [ "$mode" = manual ] || return 0
      err "nothing to roll back (phase: ${phase:-none})"; return 1 ;;
  esac

  _ssh_restore "$target"
  if ! _ssh_sshd -t; then
    # The snapshot was a configuration sshd ran with; failing now means
    # something else changed underneath. A config sshd refuses is the one
    # outcome worse than any of ours, so fall back to none of ours at all.
    err "the restored configuration does not pass sshd -t -- removing the eyes-cerberus drop-ins entirely"
    _ssh_restore orig
    _ssh_sshd -t || rm -f "$(_ssh_get dropin_path)"
    newphase=none
  fi
  _ssh_set phase "$newphase"
  [ "$newphase" = none ] && _ssh_set port ""
  [ "$mode" = auto ] || _ssh_disarm_rollback
  _ssh_set deadline ""
  _ssh_apply || err "sshd did not reload after the rollback -- check: systemctl status ssh"
  _ssh_reload_f2b
  _ssh_after_change

  case "$mode" in
    auto)
      emit_event HARD ssh_rollback "-" \
        "phase '$phase' was not confirmed within $(_ssh_get window)s: sshd configuration restored to before it" ;;
    *)
      emit_event SOFT ssh_rollback "-" "phase '$phase' rolled back ($mode): sshd configuration restored" ;;
  esac
}

cmd_ssh() {
  local sub="${1:-status}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    status)   ssh_status ;;
    add-key)  ssh_add_key "$@" ;;
    stage)    ssh_stage "$@" ;;
    confirm)  ssh_confirm ;;
    lock)     ssh_lock "$@" ;;
    rollback) ssh_rollback "$@" ;;
    *)
      err "usage: cerberus.sh ssh {status|add-key <file.pub|->|stage <port>|confirm|lock [--all-users]|rollback}"
      return 2 ;;
  esac
}
