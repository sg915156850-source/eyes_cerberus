#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/sigupdate.sh
# Fetch a signature bundle and swap it in atomically.
#
# The signatures shipped with this repository describe one host's incident.
# This is how a host that has never met that dropper gets useful indicators:
# point SIGNATURE_URL at a bundle, run `cerberus.sh update-sigs` from cron, and
# the daemon picks the new files up on its next pass without a restart.
#
# What a bundle is: a tar.gz of *.txt signature files, nothing else, plus a
# SHA-256 published separately. The daemon will not install a bundle whose
# digest is not known-good -- this file decides what a root process kills.
# Sourced after lib/common.sh.
#===============================================================================

# Files the operator maintains by hand. They are never replaced by an update;
# a bundle can only add entries to them via the .local convention below.
_LOCAL_SUFFIX=".local"

# sig_update [--dry-run]
#
# SIGNATURE_URL       bundle location (https). Required.
# SIGNATURE_SHA256    expected digest of the bundle, or the URL of a file
#                     containing it. Required -- there is no unverified path.
sig_update() {
  local url="${SIGNATURE_URL:-}"
  local want="${SIGNATURE_SHA256:-}"
  if [ -z "$url" ]; then
    err "SIGNATURE_URL is not set; nothing to update from"
    return 1
  fi
  if [ -z "$want" ]; then
    err "SIGNATURE_SHA256 is not set. A signature bundle decides what a root"
    err "process kills and quarantines -- it is not installed unverified."
    return 1
  fi
  require_tool curl || return 1
  require_tool tar   || return 1

  local work rc
  work="$(mktemp -d)" || { err "mktemp failed"; return 1; }
  # Cleanup is explicit rather than a RETURN trap: that trap also fires when a
  # nested call returns, so the scratch directory disappeared under the very
  # function still using it.
  _sig_update_into "$work" "$@"
  rc=$?
  rm -rf "$work"
  return "$rc"
}

# _sig_update_into <workdir> [--dry-run] : the body of sig_update. Every exit
# path just returns; the caller owns the scratch directory.
_sig_update_into() {
  local work="$1"; shift
  local dry=0
  [ "${1:-}" = "--dry-run" ] && dry=1

  local url="${SIGNATURE_URL:-}"
  local want="${SIGNATURE_SHA256:-}"

  # The digest may be given inline or as a URL to fetch it from.
  case "$want" in
    http://*|https://*)
      want="$(curl -fsSL --max-time 30 "$want" 2>/dev/null | tr -d '[:space:]' | cut -c1-64)"
      [ -n "$want" ] || { err "could not fetch the expected digest"; return 1; }
      ;;
  esac
  if ! printf '%s' "$want" | grep -qE '^[0-9a-fA-F]{64}$'; then
    err "SIGNATURE_SHA256 is not a sha256 digest"
    return 1
  fi

  info "fetching signature bundle from $url"
  if ! curl -fsSL --max-time 60 -o "$work/bundle.tar.gz" "$url"; then
    err "download failed"
    return 1
  fi

  local got
  got="$(sha256sum "$work/bundle.tar.gz" | cut -d' ' -f1)"
  if [ "$got" != "$(printf '%s' "$want" | tr 'A-F' 'a-f')" ]; then
    err "digest mismatch: expected $want, got $got -- refusing to install"
    return 1
  fi
  info "digest verified"

  mkdir -p "$work/new"
  if ! tar -xzf "$work/bundle.tar.gz" -C "$work/new" 2>/dev/null; then
    err "bundle did not extract"
    return 1
  fi

  # A bundle contains signature files and nothing else. No paths, no
  # subdirectories, no surprises: this is unpacked by root.
  local f base
  local -a incoming=()
  while IFS= read -r f; do
    base="$(basename "$f")"
    case "$base" in
      *.txt) ;;
      *) err "bundle contains a non-signature file: $base"; return 1 ;;
    esac
    incoming+=("$f")
  done < <(find "$work/new" -mindepth 1 -maxdepth 1 -type f | sort)

  if [ "${#incoming[@]}" -eq 0 ]; then
    err "bundle contains no signature files"
    return 1
  fi
  if [ "$(find "$work/new" -mindepth 1 -type d | wc -l)" != "0" ]; then
    err "bundle contains directories; expected a flat set of .txt files"
    return 1
  fi

  if [ "$dry" = "1" ]; then
    info "would install ${#incoming[@]} signature files into $SIG_DIR:"
    for f in "${incoming[@]}"; do
      printf '  %s (%s entries)\n' "$(basename "$f")" \
        "$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null || echo 0)" >&2
    done
    return 0
  fi

  # Keep the previous set so a bad bundle can be rolled back by hand, and so
  # the swap is a rename rather than a window with no signatures at all.
  local backup="$SIG_DIR.prev"
  rm -rf "$backup"
  cp -a "$SIG_DIR" "$backup" 2>/dev/null || true

  for f in "${incoming[@]}"; do
    base="$(basename "$f")"
    install -m 0640 -o root -g root "$f" "$SIG_DIR/$base" 2>/dev/null \
      || install -m 0640 "$f" "$SIG_DIR/$base" \
      || { err "failed installing $base"; return 1; }
  done

  # Operator additions live in <name>.local and are appended after the bundle,
  # so an update never silently drops an indicator someone added by hand.
  local merged=0
  for f in "$SIG_DIR"/*"$_LOCAL_SUFFIX"; do
    [ -f "$f" ] || continue
    base="$(basename "$f" "$_LOCAL_SUFFIX")"
    [ -f "$SIG_DIR/$base" ] || continue
    printf '\n# --- local additions (%s) ---\n' "$(basename "$f")" >> "$SIG_DIR/$base"
    cat "$f" >> "$SIG_DIR/$base"
    merged=$(( merged + 1 ))
  done

  emit_event SOFT signatures_updated "-" \
    "installed ${#incoming[@]} signature files from $url (sha256 $got)${merged:+, merged $merged local files}"
  info "signatures updated; previous set kept at $backup"
  return 0
}
