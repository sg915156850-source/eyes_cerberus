#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - host defense daemon
#
#   cerberus.sh run     Supervised sensor loop (this is what systemd runs).
#   cerberus.sh scan    One detector pass, print findings, then act on them.
#   cerberus.sh dryscan One detector pass, print findings, take NO action.
#   cerberus.sh baseline Rebuild the persistence baseline from current state.
#   cerberus.sh quarantine [list|restore <id>]
#                       Review contained files, or undo a containment.
#   cerberus.sh update-sigs [--dry-run]
#                       Fetch a verified signature bundle.
#
# Design notes:
#   * No `set -e`. A detector that exits non-zero (e.g. grep with no match) must
#     never kill the loop. Risky calls are guarded via run_action() / `|| true`.
#   * Detectors (lib/detect.sh) emit  SEVERITY|CATEGORY|PID|DETAIL  lines.
#   * Responder (lib/respond.sh) is tiered: HARD may auto-act, SOFT alerts only.
#   * All config lives in etc/cerberus.env (see etc/cerberus.env.example).
#===============================================================================
set -uo pipefail

_self="${BASH_SOURCE[0]}"
_dir="$(cd -P "$(dirname "$_self")" >/dev/null 2>&1 && pwd)"

# shellcheck source=lib/common.sh
source "$_dir/lib/common.sh"
# shellcheck source=lib/forensics.sh
source "$_dir/lib/forensics.sh"
# shellcheck source=lib/baseline.sh
source "$_dir/lib/baseline.sh"
# shellcheck source=lib/detect.sh
source "$_dir/lib/detect.sh"
# shellcheck source=lib/respond.sh
source "$_dir/lib/respond.sh"
# shellcheck source=lib/sigupdate.sh
source "$_dir/lib/sigupdate.sh"
# shellcheck source=lib/report.sh
source "$_dir/lib/report.sh"

VERSION="2.1.0"

one_pass() {
  local act="$1"   # act | noact
  local findings
  findings="$(run_all_detectors)"
  if [ -z "$findings" ]; then
    [ "$act" = "noact" ] && echo "(no findings)"
    return 0
  fi
  local line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ "$act" = "noact" ]; then
      printf '%s\n' "$line"
    else
      printf '%s\n' "$line" >&2
      handle_finding "$line"
    fi
  done <<< "$findings"
}

cmd_run() {
  info "Eyes Cerberus v$VERSION starting (interval=${SENSOR_INTERVAL}s, auto_response=${AUTO_RESPONSE}, dry_run=${DRY_RUN}, notify=${NOTIFY_METHOD})"
  # A daemon running on a config anyone can rewrite is worse than no daemon:
  # the host looks defended and is not.
  check_config_perms || { err "refusing to start"; exit 1; }
  apply_c2_firewall
  baseline_diff >/dev/null 2>&1 || true   # seed baseline on first ever run
  trap 'info "Eyes Cerberus stopping"; exit 0' TERM INT
  export CERBERUS_PASS=0
  local hb_every=$(( 3600 / (SENSOR_INTERVAL > 0 ? SENSOR_INTERVAL : 30) ))
  [ "$hb_every" -lt 1 ] && hb_every=1
  local conf_every="${PERSISTENCE_EVERY:-10}"
  while true; do
    # The startup check is not enough on its own: permissions can be loosened
    # while the daemon runs. Re-checking costs a handful of stat calls. On
    # failure the daemon keeps watching and reporting but stops acting --
    # exiting would leave the host unwatched, and acting on a config someone
    # else can rewrite is how the responder gets pointed at a real service.
    if [ "$AUTO_RESPONSE" = "1" ] && [ $(( CERBERUS_PASS % conf_every )) -eq 0 ]; then
      if ! check_config_perms; then
        AUTO_RESPONSE=0
        emit_event HARD config_untrusted "-" \
          "config or signatures became writable by someone other than root -- auto-response disabled for this run"
      fi
    fi
    one_pass act || warn "detector pass returned $?"
    rotate_logs
    CERBERUS_PASS=$(( CERBERUS_PASS + 1 ))
    if [ $(( CERBERUS_PASS % hb_every )) -eq 0 ]; then
      local ev=0; [ -f "$EVENTS_LOG" ] && ev="$(wc -l < "$EVENTS_LOG" | tr -d ' ')"
      info "heartbeat: ${CERBERUS_PASS} passes, ${ev} events total"
    fi
    sleep "$SENSOR_INTERVAL" &
    wait $!
  done
}

# Invoked by eyes-cerberus-failure.service (OnFailure=). One notification, and
# an event in the log so a later digest shows the gap was noticed.
cmd_notify_failure() {
  local since=""
  since="$(systemctl show -p ExecMainExitTimestamp --value eyes-cerberus.service 2>/dev/null || true)"
  emit_event HARD daemon_down "-" \
    "eyes-cerberus.service entered a failed state${since:+ at $since} -- host is no longer being watched"
}

cmd_quarantine() {
  case "${1:-list}" in
    list|"")
      if ! quarantine_list; then
        echo "(quarantine is empty)"
        return 0
      fi
      ;;
    restore)
      shift
      [ $# -ge 1 ] || { err "usage: cerberus.sh quarantine restore <id>"; return 2; }
      quarantine_restore "$1"
      ;;
    *)
      err "usage: cerberus.sh quarantine [list|restore <id>]"
      return 2
      ;;
  esac
}

case "${1:-run}" in
  run)      cmd_run ;;
  scan)     check_config_perms || { err "refusing to act on an untrusted config"; exit 1; }
            info "manual scan"; one_pass act ;;
  # dryscan takes no action, so a bad config cannot be turned against the host
  # here -- say so and carry on, since this is the command you reach for while
  # fixing exactly that kind of problem.
  dryscan)  check_config_perms || warn "continuing anyway: dryscan changes nothing"
            CERBERUS_DRY_RUN=1 DRY_RUN=1 one_pass noact ;;
  baseline) baseline_build ;;
  notify-failure) cmd_notify_failure ;;
  quarantine) shift; cmd_quarantine "$@" ;;
  update-sigs) shift; sig_update "$@" ;;
  report) shift; report "${1:-7}" "${2:-html}" ;;
  version|-v|--version) echo "eyes-cerberus $VERSION" ;;
  *)
    cat <<EOF
Eyes Cerberus v$VERSION
Usage: $0 {run|scan|dryscan|baseline|version}
  run       supervised sensor loop (systemd entrypoint)
  scan      one pass: detect + respond
  dryscan   one pass: detect + print only, no action
  baseline  rebuild persistence baseline from current host state
  notify-failure  emit a "daemon is down" alert (used by OnFailure=)
  quarantine [list|restore <id>]
            review what was contained, or put a file back
  update-sigs [--dry-run]
            fetch and verify a signature bundle (SIGNATURE_URL/SIGNATURE_SHA256)
  report [days] [html|json]
            period report over events.jsonl, on stdout
EOF
    exit 1 ;;
esac
