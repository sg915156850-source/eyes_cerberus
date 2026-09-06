#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/baseline.sh
# Snapshot and diff the host persistence surface. Additions since the recorded
# baseline are reported as SOFT|persistence findings (alert-only). Removals are
# ignored on purpose (cleanup is not a threat signal).
# Sourced after lib/common.sh.
#===============================================================================

# Every host path this module reads is overridable so the tests can point it at
# a sandbox. On a real host these are the defaults and nothing sets them.
LD_PRELOAD_FILE="${LD_PRELOAD_FILE:-/etc/ld.so.preload}"
PASSWD_FILE="${PASSWD_FILE:-/etc/passwd}"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers}"
SUDOERS_DIR="${SUDOERS_DIR:-/etc/sudoers.d}"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_CONFIG_DIR="${SSHD_CONFIG_DIR:-/etc/ssh/sshd_config.d}"
PAM_DIR="${PAM_DIR:-/etc/pam.d}"

# Where a newly-appeared setuid binary is worth knowing about. Deliberately not
# the whole filesystem: a full find(1) every cycle is too expensive, and new
# setuid files under /usr/bin come from package upgrades, which is noise. These
# are the places a fresh setuid root shell actually shows up.
SETUID_DIRS="${SETUID_DIRS:-/tmp /var/tmp /dev/shm /home /root /opt /srv /usr/local}"

# Sources we watch. Each becomes one file under state/baseline/.
_baseline_capture() {
  local dst="$1"
  mkdir -p "$dst"

  crontab -l 2>/dev/null | grep -vE '^\s*(#|$)' | sort > "$dst/crontab" || true

  {
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
      [ -d "$d" ] || continue
      find "$d" -maxdepth 1 -type f -printf '%p\n' 2>/dev/null
    done
    [ -f /etc/crontab ] && grep -vE '^\s*(#|$)' /etc/crontab
  } | sort > "$dst/cron_system" || true

  systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
    | awk '{print $1, $2}' | sort > "$dst/units" || true

  systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null \
    | awk '{print $1}' | sort > "$dst/units_running" || true

  cat /root/.ssh/authorized_keys 2>/dev/null | sort > "$dst/root_authorized_keys" || true

  for f in /root/.bashrc /root/.profile /root/.bash_profile; do
    [ -f "$f" ] && sha256sum "$f" 2>/dev/null
  done | sort > "$dst/root_shell_rc" || true

  # Accounts. The login-relevant fields only, so a password hash rotation in
  # /etc/shadow does not read as a new user, but uid 0 appearing on a second
  # account does.
  cut -d: -f1,3,4,6,7 "$PASSWD_FILE" 2>/dev/null | sort > "$dst/accounts" || true

  # sudo rules, with the file they came from -- a dropped-in file under
  # sudoers.d is the quiet way to keep root.
  {
    [ -f "$SUDOERS_FILE" ] && \
      grep -vE '^[[:space:]]*(#|$)' "$SUDOERS_FILE" 2>/dev/null | sed "s|^|$SUDOERS_FILE: |"
    if [ -d "$SUDOERS_DIR" ]; then
      for f in "$SUDOERS_DIR"/*; do
        [ -f "$f" ] || continue
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | sed "s|^|$f: |"
      done
    fi
  } | sort > "$dst/sudoers" || true

  # sshd: the effective directives, not a hash, so the finding names what
  # changed (PermitRootLogin yes, an added AuthorizedKeysFile, ...).
  {
    [ -f "$SSHD_CONFIG" ] && grep -vE '^[[:space:]]*(#|$)' "$SSHD_CONFIG" 2>/dev/null
    if [ -d "$SSHD_CONFIG_DIR" ]; then
      for f in "$SSHD_CONFIG_DIR"/*.conf; do
        [ -f "$f" ] || continue
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null
      done
    fi
  } | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//' | sort \
    > "$dst/sshd_config" || true

  # PAM is a supported place to load an arbitrary .so at every authentication.
  if [ -d "$PAM_DIR" ]; then
    find "$PAM_DIR" -maxdepth 1 -type f -exec sha256sum {} + 2>/dev/null | sort \
      > "$dst/pam" || true
  else
    : > "$dst/pam"
  fi

  # New setuid/setgid binaries in the directories that matter.
  if [ "${DETECT_SETUID:-1}" = "1" ]; then
    # shellcheck disable=SC2086  # SETUID_DIRS is a space-separated list on purpose
    find $SETUID_DIRS -xdev \( -perm -4000 -o -perm -2000 \) -type f \
      -printf '%M %u %p\n' 2>/dev/null | sort > "$dst/setuid" || true
  else
    : > "$dst/setuid"
  fi

  # `ls -1 /etc/ld.so.preload && cat ... > file` used to print the path on
  # stdout whenever the file existed. _baseline_capture's stdout is the
  # detector's finding stream, so on a host that actually has an ld.so.preload
  # -- the case this check exists for -- that bare path was parsed as a
  # finding, with the path itself landing in the severity field.
  if [ -f "$LD_PRELOAD_FILE" ]; then
    cat "$LD_PRELOAD_FILE" 2>/dev/null > "$dst/ld_preload" || : > "$dst/ld_preload"
  else
    : > "$dst/ld_preload"
  fi
}

# baseline_build : (re)create the reference snapshot. Call after a known-good
# review, or on first run.
baseline_build() {
  _baseline_capture "$BASELINE_DIR"
  # also seed the listener baseline used by detect_new_listener
  if command -v ss >/dev/null 2>&1; then
    ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u \
      | grep -E '^[0-9]+$' > "$BASELINE_DIR/listeners" || true
  fi
  info "baseline rebuilt at $BASELINE_DIR"
}

# baseline_diff : print SOFT|persistence findings for every line that is present
# now but absent from the baseline. No-op (and self-seeding) if no baseline yet.
baseline_diff() {
  if [ ! -f "$BASELINE_DIR/units" ]; then
    baseline_build
    return 0
  fi
  local cur; cur="$(mktemp -d)"
  _baseline_capture "$cur"

  local name
  for name in crontab cron_system units units_running root_authorized_keys \
              root_shell_rc ld_preload accounts sudoers sshd_config pam setuid; do
    [ -f "$cur/$name" ] || continue
    [ -f "$BASELINE_DIR/$name" ] || touch "$BASELINE_DIR/$name"
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      grep -qxF "$line" "$BASELINE_DIR/$name" || \
        echo "SOFT|persistence|-|new in ${name}: ${line}"
    done < <(comm -13 <(sort "$BASELINE_DIR/$name") <(sort "$cur/$name"))
  done

  rm -rf "$cur"
}
