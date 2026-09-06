#!/usr/bin/env bats
# lib/sigupdate.sh: fetching a signature bundle, and refusing to.

setup() {
  load helper
  cerberus_setup
  cerberus_load

  BUNDLE_SRC="$TEST_TMP/bundle"
  mkdir -p "$BUNDLE_SRC"
  printf '# feed\n203.0.113.10\n203.0.113.11\n' > "$BUNDLE_SRC/c2_ips.txt"
  printf '# feed\nxmrig\nkdevtmpfsi\n'          > "$BUNDLE_SRC/miner_patterns.txt"
  tar -czf "$TEST_TMP/bundle.tar.gz" -C "$BUNDLE_SRC" .
  BUNDLE_SHA="$(sha256sum "$TEST_TMP/bundle.tar.gz" | cut -d' ' -f1)"

  # curl shim: serves the local bundle for any URL, records what was asked for
  cat > "$SHIM_DIR/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FIXTURE_DIR/curl.calls"
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    http*|https*) url="$1" ;;
  esac
  shift
done
case "$url" in
  *digest*) printf '%s\n' "${CURL_DIGEST_BODY:-}" ;;
  *)
    [ -n "${CURL_FAIL:-}" ] && exit 22
    if [ -n "$out" ]; then cp "$CURL_SERVE" "$out"; else cat "$CURL_SERVE"; fi ;;
esac
exit 0
EOF
  chmod +x "$SHIM_DIR/curl"
  export CURL_SERVE="$TEST_TMP/bundle.tar.gz"

  sig c2_ips.txt "198.51.100.1"
}

@test "a bundle with a matching digest is installed" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$BUNDLE_SHA"

  run sig_update
  [ "$status" -eq 0 ]

  run read_sig c2_ips.txt
  [[ "$output" == *"203.0.113.10"* ]]
  [[ "$output" != *"198.51.100.1"* ]]     # replaced, not merged
}

@test "the previous signature set is kept for rollback" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$BUNDLE_SHA"
  sig_update
  run cat "$SIG_DIR.prev/c2_ips.txt"
  [[ "$output" == *"198.51.100.1"* ]]
}

@test "a digest mismatch is refused and changes nothing" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="0000000000000000000000000000000000000000000000000000000000000000"

  run sig_update
  [ "$status" -ne 0 ]
  [[ "$output" == *"digest mismatch"* ]]

  run read_sig c2_ips.txt
  [ "$output" = "198.51.100.1" ]
}

@test "no digest at all is refused -- there is no unverified path" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256=""
  run sig_update
  [ "$status" -ne 0 ]
  [[ "$output" == *"not installed unverified"* ]]
}

@test "the digest may be fetched from a URL" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="https://example.invalid/digest.txt"
  export CURL_DIGEST_BODY="$BUNDLE_SHA  sigs.tar.gz"

  run sig_update
  [ "$status" -eq 0 ]
  run read_sig c2_ips.txt
  [[ "$output" == *"203.0.113.10"* ]]
}

@test "a bundle carrying anything but signature files is refused" {
  mkdir -p "$TEST_TMP/evil"
  printf '203.0.113.10\n' > "$TEST_TMP/evil/c2_ips.txt"
  printf '#!/bin/sh\n' > "$TEST_TMP/evil/postinst.sh"
  tar -czf "$TEST_TMP/evil.tar.gz" -C "$TEST_TMP/evil" .
  export CURL_SERVE="$TEST_TMP/evil.tar.gz"
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$(sha256sum "$TEST_TMP/evil.tar.gz" | cut -d' ' -f1)"

  run sig_update
  [ "$status" -ne 0 ]
  [[ "$output" == *"non-signature file"* ]]
  run read_sig c2_ips.txt
  [ "$output" = "198.51.100.1" ]
}

@test "a bundle with subdirectories is refused" {
  mkdir -p "$TEST_TMP/nested/sub"
  printf '203.0.113.10\n' > "$TEST_TMP/nested/c2_ips.txt"
  printf 'x\n' > "$TEST_TMP/nested/sub/other.txt"
  tar -czf "$TEST_TMP/nested.tar.gz" -C "$TEST_TMP/nested" .
  export CURL_SERVE="$TEST_TMP/nested.tar.gz"
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$(sha256sum "$TEST_TMP/nested.tar.gz" | cut -d' ' -f1)"

  run sig_update
  [ "$status" -ne 0 ]
  [[ "$output" == *"directories"* ]]
}

@test "local additions survive an update" {
  printf '# mine\n198.51.100.77\n' > "$SIG_DIR/c2_ips.txt.local"
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$BUNDLE_SHA"

  run sig_update
  [ "$status" -eq 0 ]
  run read_sig c2_ips.txt
  [[ "$output" == *"203.0.113.10"* ]]     # from the bundle
  [[ "$output" == *"198.51.100.77"* ]]    # kept from the operator's file
}

@test "--dry-run reports what would change and installs nothing" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$BUNDLE_SHA"

  run sig_update --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"would install"* ]]
  run read_sig c2_ips.txt
  [ "$output" = "198.51.100.1" ]
}

@test "a download failure leaves the signatures alone" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$BUNDLE_SHA"
  export CURL_FAIL=1

  run sig_update
  [ "$status" -ne 0 ]
  run read_sig c2_ips.txt
  [ "$output" = "198.51.100.1" ]
}

@test "no SIGNATURE_URL is a clear error, not a silent no-op" {
  SIGNATURE_URL=""
  run sig_update
  [ "$status" -ne 0 ]
  [[ "$output" == *"SIGNATURE_URL is not set"* ]]
}

@test "an installed update is recorded as an event" {
  SIGNATURE_URL="https://example.invalid/sigs.tar.gz"
  SIGNATURE_SHA256="$BUNDLE_SHA"
  sig_update
  run jq -esr '[.[] | select(.category == "signatures_updated")] | length' "$EVENTS_LOG"
  [ "$output" = "1" ]
}
