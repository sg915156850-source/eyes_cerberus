#!/usr/bin/env bats
# packaging/build-deb.sh: what the maintainer scripts do to the unit on
# install, upgrade and removal.
#
# The scripts are taken out of a freshly built .deb and run with their fixed
# paths (/run/systemd/system, /etc/eyes-cerberus, /var/lib/eyes-cerberus)
# pointed into the test directory, and with a systemctl shim that remembers
# whether the unit is enabled.

setup() {
  command -v dpkg-deb >/dev/null 2>&1 || skip "dpkg-deb not installed"
  load helper
  cerberus_setup

  "$REPO_ROOT/packaging/build-deb.sh" "$TEST_TMP/dist" >/dev/null
  dpkg-deb -e "$TEST_TMP"/dist/*.deb "$TEST_TMP/control"

  mkdir -p "$TEST_TMP/run-systemd" "$TEST_TMP/etc-ec" "$TEST_TMP/var-ec"
  : > "$TEST_TMP/etc-ec/cerberus.env.example"
  local s
  for s in preinst postinst prerm postrm; do
    [ -f "$TEST_TMP/control/$s" ] || continue
    sed -e "s|/run/systemd/system|$TEST_TMP/run-systemd|g" \
        -e "s|/etc/eyes-cerberus|$TEST_TMP/etc-ec|g" \
        -e "s|/var/lib/eyes-cerberus|$TEST_TMP/var-ec|g" \
        "$TEST_TMP/control/$s" > "$TEST_TMP/$s"
  done

  # chown root:root is right on a real install and impossible for the
  # unprivileged user CI runs as.
  printf '#!/bin/sh\nexit 0\n' > "$SHIM_DIR/chown"
  chmod +x "$SHIM_DIR/chown"

  _write_shim systemctl <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FIXTURE_DIR/systemctl.calls"
st="$FIXTURE_DIR/unit_enabled"
case "$*" in
  *is-enabled*) [ "$(cat "$st" 2>/dev/null)" = 1 ]; exit ;;
  *disable*)    echo 0 > "$st" ;;
  *enable*)     echo 1 > "$st" ;;
esac
exit 0
EOF
}

unit_enabled() { echo "$1" > "$FIXTURE_DIR/unit_enabled"; }

@test "prerm upgrade stops the daemon and leaves it enabled" {
  unit_enabled 1
  run sh "$TEST_TMP/prerm" upgrade 9.9.9
  [ "$status" -eq 0 ]
  [[ "$(calls systemctl)" == *"stop eyes-cerberus.service"* ]]
  [[ "$(calls systemctl)" != *"disable"* ]]
}

@test "prerm remove stops and disables the daemon" {
  unit_enabled 1
  run sh "$TEST_TMP/prerm" remove
  [ "$status" -eq 0 ]
  [[ "$(calls systemctl)" == *"disable --now eyes-cerberus.service"* ]]
}

@test "an upgrade through dpkg keeps an enabled daemon running" {
  # dpkg runs prerm upgrade, unpacks, then postinst configure <old-version>.
  # prerm used to 'disable --now' unconditionally, so postinst found the unit
  # disabled and every 'dpkg -i' of a new version left the host unwatched.
  unit_enabled 1
  run sh "$TEST_TMP/prerm" upgrade 9.9.9
  [ "$status" -eq 0 ]
  run sh "$TEST_TMP/postinst" configure 2.1.2
  [ "$status" -eq 0 ]
  [[ "$(calls systemctl)" == *"start eyes-cerberus.service"* ]]
  [ "$(cat "$FIXTURE_DIR/unit_enabled")" = 1 ]
  [[ "$output" != *"not started"* ]]
}

@test "postinst on upgrade leaves a disabled daemon alone" {
  unit_enabled 0
  run sh "$TEST_TMP/postinst" configure 2.1.2
  [ "$status" -eq 0 ]
  [[ "$(calls systemctl)" != *"start eyes-cerberus.service"* ]]
  [[ "$output" == *"not started"* ]]
}

@test "postinst on a first install starts nothing" {
  unit_enabled 1
  run sh "$TEST_TMP/postinst" configure
  [ "$status" -eq 0 ]
  [[ "$(calls systemctl)" != *"start eyes-cerberus.service"* ]]
  [[ "$output" == *"not started"* ]]
  [ -f "$TEST_TMP/etc-ec/cerberus.env" ]
}

@test "postinst after an upgrade from 2.1.1 says the old prerm disabled it" {
  # dpkg runs the old package's prerm, so this upgrade cannot be fixed from
  # the new package; the operator at least has to be told.
  command -v dpkg >/dev/null 2>&1 || skip "dpkg not installed"
  unit_enabled 0
  run sh "$TEST_TMP/postinst" configure 2.1.1
  [ "$status" -eq 0 ]
  [[ "$output" == *"systemctl enable --now eyes-cerberus.service"* ]]
  [[ "$output" == *"disabled the daemon"* ]]
}
