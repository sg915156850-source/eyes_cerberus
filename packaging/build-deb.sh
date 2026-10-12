#!/usr/bin/env bash
#===============================================================================
# Build a .deb from the source tree. Needs only dpkg-deb.
#   ./packaging/build-deb.sh [outdir]
# Version is read from cerberus.sh, so it cannot drift from what the daemon
# reports.
#===============================================================================
set -euo pipefail

SRC="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
OUT="${1:-$SRC/dist}"

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb not found" >&2; exit 1; }

VERSION="$(sed -n 's/^VERSION="\([0-9.]*\)"/\1/p' "$SRC/cerberus.sh" | head -1)"
[ -n "$VERSION" ] || { echo "could not read VERSION from cerberus.sh" >&2; exit 1; }

PKG="eyes-cerberus"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
# mktemp gives 0700; the package root must be world-readable like any other.
chmod 755 "$BUILD"

CODE="$BUILD/opt/eyes-cerberus"
CONF="$BUILD/etc/eyes-cerberus"
UNITS="$BUILD/lib/systemd/system"
mkdir -p "$CODE" "$CONF/signatures" "$UNITS" "$BUILD/DEBIAN" "$BUILD/usr/local/sbin"

# --- payload ---------------------------------------------------------------
# Same explicit list as install.sh: no state/, no .git, no ir/experimental,
# no tests.
for item in cerberus.sh master.sh lib ir/quick_response.sh ir/emergency_remediation.sh ir/docker; do
  [ -e "$SRC/$item" ] || continue
  mkdir -p "$CODE/$(dirname "$item")"
  cp -a "$SRC/$item" "$CODE/$(dirname "$item")/"
done
for doc in README.md CHANGELOG.md KNOWN_THREATS.md SECURITY.md LICENSE ROADMAP.md; do
  [ -f "$SRC/$doc" ] && cp -a "$SRC/$doc" "$CODE/"
done
cp -a "$SRC"/etc/signatures/*.txt "$CONF/signatures/"
cp -a "$SRC/etc/whitelist.txt"          "$CONF/whitelist.txt"
cp -a "$SRC/etc/cerberus.env.example"   "$CONF/cerberus.env.example"
cp -a "$SRC"/systemd/*.service "$UNITS/"
ln -sfn /opt/eyes-cerberus/master.sh "$BUILD/usr/local/sbin/cerberus"

chmod 755 "$CODE/cerberus.sh" "$CODE/master.sh"
chmod 750 "$CONF" "$CONF/signatures"
chmod 640 "$CONF"/signatures/*.txt "$CONF/whitelist.txt" "$CONF/cerberus.env.example"

INSTALLED_SIZE="$(du -sk "$BUILD" | cut -f1)"

# --- metadata --------------------------------------------------------------
cat > "$BUILD/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: admin
Priority: optional
Architecture: all
Depends: bash (>= 4.4), coreutils, procps, iproute2, iptables
Installed-Size: $INSTALLED_SIZE
Maintainer: Eyes Cerberus <245840742+sg915156850-source@users.noreply.github.com>
Homepage: https://github.com/sg915156850-source/eyes_cerberus
Description: Host defense daemon for a single Linux server
 A supervised daemon that watches processes, sockets and persistence points
 for a known dropper family and a set of lower-confidence heuristics, and
 responds in tiers: high-confidence signatures are auto-contained, heuristics
 only alert. No agent-server split, no runtime dependencies beyond the base
 system.
 .
 Not an antivirus, not an EDR, and not a substitute for patching and least
 privilege.
EOF

# Signatures and thresholds are meant to be edited in place; dpkg must ask
# rather than overwrite on upgrade.
{
  echo /etc/eyes-cerberus/whitelist.txt
  for f in "$SRC"/etc/signatures/*.txt; do
    echo "/etc/eyes-cerberus/signatures/$(basename "$f")"
  done
} > "$BUILD/DEBIAN/conffiles"

cat > "$BUILD/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
STATE=/var/lib/eyes-cerberus
CONF=/etc/eyes-cerberus

mkdir -p "$STATE/evidence" "$STATE/quarantine" "$STATE/baseline"
chown -R root:root "$STATE"
chmod 750 "$STATE"
chmod 700 "$STATE/evidence" "$STATE/quarantine"

# cerberus.env is sourced as bash by a root process: root-only, always.
if [ ! -e "$CONF/cerberus.env" ]; then
  cp "$CONF/cerberus.env.example" "$CONF/cerberus.env"
  echo "eyes-cerberus: created $CONF/cerberus.env -- review it before starting"
fi
chown root:root "$CONF/cerberus.env"
chmod 600 "$CONF/cerberus.env"

UNIT=eyes-cerberus.service
started=0
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  # $2 is the version being upgraded from; empty on a first install, which
  # stays not started until the operator has reviewed the config. On an
  # upgrade prerm only stopped the daemon and left the enablement alone, so
  # is-enabled still says what the operator had chosen.
  case "$1" in
    configure|abort-upgrade)
      if [ -n "${2:-}" ] && systemctl is-enabled --quiet "$UNIT" 2>/dev/null; then
        if systemctl start "$UNIT"; then
          started=1
        else
          echo "eyes-cerberus: $UNIT did not start -- see: journalctl -u $UNIT" >&2
        fi
      fi
      ;;
  esac
fi

if [ "$started" = 0 ]; then
  # A 2.1.1-or-older prerm ran 'disable --now' on every upgrade, and dpkg runs
  # the old package's prerm, so an upgrade from one of those always lands here.
  if [ "$1" = configure ] && [ -n "${2:-}" ] && \
     dpkg --compare-versions "$2" le 2.1.1 2>/dev/null; then
    echo "eyes-cerberus: the $2 package disabled the daemon while upgrading;" \
         "if it was running, re-enable it: systemctl enable --now $UNIT"
  fi
  cat <<'MSG'
eyes-cerberus installed but not started. Review the config, then:
    /opt/eyes-cerberus/cerberus.sh dryscan
    systemctl enable --now eyes-cerberus.service
MSG
fi
exit 0
EOF

# Debian policy: only a removal takes the daemon down for good. On an upgrade
# the old code is stopped before dpkg replaces it and the enablement is left
# alone, so postinst can see it and start the new code. Disabling here on
# every call left the host unwatched after each 'dpkg -i' of a new version.
cat > "$BUILD/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
UNIT=eyes-cerberus.service
[ -d /run/systemd/system ] || exit 0
case "$1" in
  remove)
    systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
    ;;
  upgrade|failed-upgrade)
    systemctl stop "$UNIT" >/dev/null 2>&1 || true
    ;;
esac
exit 0
EOF

cat > "$BUILD/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
  # Evidence and quarantine are the record of an incident; only purge removes
  # them, and even then say so.
  echo "eyes-cerberus: purging /etc/eyes-cerberus and /var/lib/eyes-cerberus"
  rm -rf /etc/eyes-cerberus /var/lib/eyes-cerberus
fi
exit 0
EOF

chmod 755 "$BUILD/DEBIAN/postinst" "$BUILD/DEBIAN/prerm" "$BUILD/DEBIAN/postrm"

mkdir -p "$OUT"
DEB="$OUT/${PKG}_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$BUILD" "$DEB" >/dev/null
echo "$DEB"
