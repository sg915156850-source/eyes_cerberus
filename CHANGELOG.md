# Changelog

## 2.1.2 — 2026-10-12

The first install on a second host, from a clean checkout with `install.sh`,
turned up two defects that the first host had hidden, and a handful of places
where the documentation promised more than the code does. It also carries
the opt-in `cerberus.sh ssh` work that sat under Unreleased.

### Fixed
- **`cerberus status` said "unit not installed" for a running daemon, on
  about every other call.** `have_unit` was `systemctl list-unit-files | grep
  -q`: grep exits on the first match, systemctl gets SIGPIPE writing the rest,
  and under `pipefail` the pipeline reports 141. The same false negative made
  `cerberus start` run `cerberus.sh run` in the foreground instead of asking
  systemd. The listing is now read whole, then matched.
- The same `producer | grep -q` shape, in every other place it occurred:
  `is_whitelisted` (a hit near the top of a long `whitelist.txt` read as a
  miss), the port and firewall probes of `cerberus.sh ssh`, the per-process
  argv checks of `c2`, `miner` and `loader`, the digest check of
  `update-sigs`, and `ir/docker/containment.sh`. A test now fails if the
  pattern comes back.
- **Upgrading the `.deb` with `dpkg -i` left the daemon stopped and
  disabled.** `prerm` ran `systemctl disable --now` whatever it was called
  for. It now follows Debian policy: `remove` stops and disables, `upgrade`
  only stops, and `postinst` starts the new code again when the unit is
  enabled. A first install still starts nothing. dpkg runs the *old*
  package's `prerm`, so the upgrade from 2.1.1 itself still ends disabled;
  `postinst` says so, and `systemctl enable --now eyes-cerberus.service` once
  after it is needed.
- **`high_cpu` and `miner` never saw a process with a space in its name**
  (`npm exec vite p`, `tmux: server`). `ps -o pid,comm,pcpu` was split on
  whitespace, so a word of the name was read as the CPU figure, and such a
  process never made the CPU shortlist: a CPU-hot miner with a spaced name was
  only ever SOFT. `pcpu` now comes before `comm`, and `comm` is the rest of the
  line.
- `whitelist.txt` stripped every space from an entry, so a name with a space
  in it could never be whitelisted. Entries are now trimmed only at the ends.

### Added

The host this grew up on takes about 3 500 failed SSH logins a day from ~200
addresses, root still logs in with a password, and fail2ban's 5-in-10-minutes
threshold misses the slow, spread-out attempts that make up most of them. Phase
12 starts with the change that removes the actual risk. Opt-in: nothing below
runs until `cerberus.sh ssh` is invoked.

- **`cerberus.sh ssh`**: `add-key`, `stage <port>`, `confirm`, `lock
  [--all-users]`, `rollback`, `status`. Moves sshd off port 22 and root off
  passwords in two confirmed steps. Every step that changes sshd arms a
  systemd timer first and restores the previous step unless `confirm` is run
  from a new session that logged in with a key on the new port. Checked against
  `sshd -T` before applying; socket-activated sshd (Ubuntu 22.10+) is handled;
  fail2ban's `sshd` jail follows the port. Verified end to end against a real
  systemd + socket-activated OpenSSH 9.6 (Ubuntu 24.04): open sessions survive,
  root password logins are refused after `lock`, and an unconfirmed `stage` or
  `lock` is undone by the timer.
- `baseline_accept_category`: a change made by Eyes Cerberus itself (a key, the
  sshd drop-in) is taken into that one baseline category with an `accepted`
  event, instead of coming back as a `persistence` finding.

### Changed
- The `whitelist.txt` header said it exempted processes from the "CPU/miner
  heuristics". `miner` has never read it, deliberately: a whitelisted name
  would be the cheapest disguise for a miner. The header and the README now
  say `high_cpu` only.
- The README listed an `egress` detector and a `DETECT_EGRESS` switch that
  were never implemented. Both are gone from the README, `cerberus.env.example`
  and the defaults; a leftover `DETECT_EGRESS=` line in an existing
  `cerberus.env` is harmless.
- The `root_authorized_keys` baseline category reads `ROOT_AUTHORIZED_KEYS`
  (default `/root/.ssh/authorized_keys`), so tests no longer read the real file.

## 2.1.1 — 2026-10-10

A week of a live v2.1.0 daemon on a busy multi-project host: ~390 000 events,
not one of them HARD, all of them the same ~110 findings repeated every 30
seconds. The log rotated real history away in under two days, and a push
backend would have been muted by its owner long before anything real arrived.

### Fixed
- **Categories added after the baseline was taken were reported in full on
  every pass, forever.** v2.1.0 added `accounts`, `sudoers`, `sshd_config`,
  `pam` and `setuid` to the persistence snapshot. On a host whose baseline came
  from v2.0, `baseline_diff` created an empty reference for each and never
  filled it, so every account, every PAM file and every sshd directive read as
  "new" on every pass. `baseline_build` now writes `baseline/.categories`; a
  category the baseline never captured is recorded once from the current state,
  with one `baseline_seeded` event saying it was not diffed. Pre-manifest
  baselines are migrated: an empty `accounts`/`sudoers`/`sshd_config`/`pam`
  reference is taken as never captured (no host has none of those), while an
  empty crontab, `authorized_keys`, `ld.so.preload` or `setuid` is not -- a
  first entry there is exactly the finding.
- The same code path `touch`ed the missing reference even under a dry run.

### Changed
- **A SOFT finding that stays open is reported once, not every pass.** It is
  reported when it first appears, again every `ALERT_REPEAT_SECONDS` (default
  one day) while it stays open with "still open, first reported ...", and at
  once if it was gone for `ALERT_FORGET_SECONDS` (default one hour, never less
  than three persistence cycles) and came back. PIDs, fds and CPU figures are
  not part of a finding's identity, so a restarted service or a fluctuating
  load is the same finding. A held-back finding takes no fresh forensics
  snapshot either. HARD findings are never held back.
  `ALERT_REPEAT_SECONDS=0` restores the v2.1.0 behaviour. State lives in
  `alert_state.tsv`; `dryscan` neither reads nor writes it.
- The hourly heartbeat reports how many findings are open.

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
- Incident-specific hardcoding (a hardcoded incident project path, fixed PIDs,
  `next-server v15`).
