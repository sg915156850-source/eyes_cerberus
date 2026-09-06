# Changelog

## 2.1.0 — 2026-09-06

v2.0 was one host's tool: the install path was baked into the systemd unit,
there were no tests, and the signatures described a single incident. This
release makes it installable, testable and useful on a machine that never met
that dropper.

### Added
- `install.sh` / `uninstall.sh` and a `.deb` (`make deb`). Code in
  `/opt/eyes-cerberus`, config in `/etc/eyes-cerberus`, state in
  `/var/lib/eyes-cerberus`. Idempotent; an upgrade never overwrites an edited
  signature file, whitelist or `cerberus.env`, and carries an older repo-local
  `state/` across.
- Two layouts, chosen automatically: a checkout keeps config and state beside
  the code, an installed copy uses the FHS paths. `CERBERUS_LAYOUT`,
  `CERBERUS_CONF_DIR` and `CERBERUS_STATE_DIR` override it.
- `Makefile` (`lint test check install uninstall deb`) and a `bats` suite of
  141 tests that run as an ordinary user against shimmed `ps`/`ss`/`iptables`/
  `systemctl`/`crontab` and never touches the host.
- CI: lint and tests on Ubuntu, the suite again in Debian 12, Ubuntu 24.04 and
  AlmaLinux 9, a `.deb` built and installed into a clean Debian with the layout
  and permissions asserted, and `install.sh` → upgrade → `uninstall.sh` on a
  real runner.
- `OnFailure=eyes-cerberus-failure.service` and `cerberus.sh notify-failure`:
  a `daemon_down` alert when the unit gives up. A host defense daemon cannot
  report its own death, and killing it is the first thing an attacker with root
  arranges.
- Detectors that are not tied to the March 2026 incident, all SOFT:
  `revshell` (argv shaped like a reverse shell), `fileless` (a process running
  from `/memfd:`, previously dropped silently), `loader` (a cron entry or unit
  that downloads code and runs it, reported once per distinct line).
- The persistence baseline also watches accounts in `/etc/passwd`, `sudoers`
  and `sudoers.d`, the effective `sshd_config`, `/etc/pam.d`, and new
  setuid/setgid files under `SETUID_DIRS`.
- `quarantine list` / `restore <id>`: undo a containment from the metadata
  sidecar, restoring the file and its original permissions. Response without a
  way back is why people set `AUTO_RESPONSE=0` after one false positive and
  never turn it on again.
- `update-sigs`: fetch a signature bundle and install it only against a
  matching SHA-256, keeping the previous set for rollback and re-appending
  local `<name>.txt.local` additions.
- `report [days] [html|json]`: a period report as one self-contained HTML page
  (nothing fetched from anywhere) or as JSON.
- `malware_sha256.txt` matched alongside `malware_md5.txt`.
- Built-in rotation for `events.jsonl` and `cerberus.log` (`LOG_MAX_BYTES`,
  `LOG_KEEP`).
- `SECURITY.md` states what counts as a vulnerability in a root daemon that
  kills processes, and how to report one.

### Fixed
- `emit_event` shelled out to `python3` on every event — an undeclared
  dependency — with a `sed` fallback that escaped neither newlines nor control
  characters. Since the detail field is built from process argv, an attacker
  decided whether `events.jsonl` stayed parseable. Now pure bash.
- The `ld.so.preload` capture printed the path on stdout, which is the
  detector's finding stream, so on a host that actually had one the path was
  parsed as a finding.
- `utime`/`stime` were read by splitting the whole `/proc/<pid>/stat` line, so
  a process named `(evil) proc` shifted every field the CPU maths depends on.
- The CPU sustain counter was keyed by pid alone, so a new process on a
  recycled pid inherited the previous one's history. Now pid + start time.
- `DRY_RUN` still wrote a `.metadata` file into the quarantine directory.
- `ls /proc | grep` in the process loops, where a hostile filename could
  word-split into the caller's loop.

### Changed
- The daemon refuses to start when anything under the config directory is
  writable by group or other, or is not owned by root: `cerberus.env` is
  sourced as bash by a root process, so write access to it is root access.
  `dryscan` warns instead, since it takes no action and is the command you
  reach for while fixing this.
- The unit drops the hardcoded path and everything root does not need
  (`NoNewPrivileges`, an explicit `CapabilityBoundingSet`, restricted address
  families, kernel and cgroup protections). `ProtectSystem`, `ProtectHome` and
  `PrivateTmp` are deliberately absent, with the reason recorded in the unit:
  each would blind a detector or turn containment into a no-op.
- `common.sh`'s `run()` renamed `run_action()` — it shadowed bats' `run` and
  would collide with any script sourcing the library.
- `master.sh` sources `lib/common.sh` instead of assuming the checkout layout.
- `ir/honeypot.sh` moved to `ir/experimental/`, excluded from packages, with a
  README on why deception code is a separate decision.

## 2.0.0 — 2026-08-30

Full rewrite. The v1 layout did not run: the systemd unit was `Type=oneshot` and
its `nohup` workers had been dead for weeks, and `set -euo pipefail` made the
detect loops abort on the first `grep` with no match.

### Added
- `cerberus.sh` — single supervised daemon (`run | scan | dryscan | baseline`).
- `lib/` modules: `common`, `detect`, `respond`, `forensics`, `baseline`.
- Tiered response: **HARD** (auto kill + quarantine + iptables) vs **SOFT**
  (evidence + alert only, never touches the process).
- `state/events.jsonl` structured event log; `notify()` with `log` / `telegram` /
  `webhook` / `email` backends; `master.sh digest`.
- Data-driven signatures in `etc/signatures/` (hashes, C2 IPs/ports, miner
  patterns, dropper paths) — editable live, no restart.
- Persistence-surface baseline + diff (`crontab`, `/etc/cron.*`, systemd units,
  `authorized_keys`, shell rc, `ld.so.preload`).
- `systemd/eyes-cerberus.service` — `Type=simple`, `Restart=always`.
- New `README.md`, `KNOWN_THREATS.md`.

### Changed
- CPU detection is now instantaneous, sustained over N passes, whitelist-guarded,
  and **SOFT only** — it will not kill (`unattended-upgrade`, `fwupd`, `pg_dump`,
  other projects' services were all being SIGKILLed by v1).
- `master.sh` is now a thin wrapper over `systemctl` + the events log.
- `emergency_remediation.sh`, `quick_response.sh`, `honeypot.sh`, Docker
  containment → moved to `ir/` (manual tools, not run by the daemon).

### Removed
- `watcher.sh`, `defense/anti_malware.sh` (merged into `lib/detect.sh`).
- `auto_containment.sh` (superseded by `lib/respond.sh`), `docker_containment_quickstart.sh`.
- `config.cfg`, `defense/defense_config.cfg` references → single `etc/cerberus.env`.
- Incident-specific hardcoding (`NaviomSite`, fixed PIDs, `next-server v15`).
