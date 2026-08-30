# Changelog

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
