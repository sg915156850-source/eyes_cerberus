# 👁️ Eyes Cerberus

**Host defense daemon for a single Linux server.** One supervised process that
watches for the malware family seen on this box in the March–April 2026 incident
(a compromised app spawning a UPX-packed ELF backdoor at `/let` that beaconed to
`nc <c2> 9009`), plus a set of lower-confidence heuristics — and responds in
tiers: high-confidence signatures are auto-contained, heuristics only alert.

> **Not** an antivirus, not an EDR, not a replacement for hardening. It is a
> narrow, auditable safety net with a bias against touching legitimate processes.

---

## Why this rewrite (v2.0)

The v1 scripts did not actually protect anything:

| v1 problem | v2 fix |
|---|---|
| `systemd` unit was `Type=oneshot`; it launched `nohup` workers and exited, so nothing supervised or restarted them. They had been dead for weeks. | `Type=simple` + `Restart=always`. systemd owns the real process. |
| `set -euo pipefail` + `grep` with no match → script aborts silently mid-loop. | No `set -e`. Risky calls guarded; the loop cannot die on an empty match. |
| Auto-kill on "CPU > 60%" using the `ps` **lifetime average** → it SIGKILLed `unattended-upgrade`, `fwupd`, `pg_dump`, other projects' services. | CPU is a **SOFT** signal: instantaneous sampling, sustained over N passes, whitelist-guarded, **never kills**. |
| Two overlapping detect engines, 3 more half-wired response scripts, two config files (one absent). | One daemon, one config, data-driven signature files. |
| "Alerts" went only to a logfile nobody reads. | Structured `events.jsonl` + `notify()` (log / Telegram / webhook / email) + `master.sh digest`. |
| iptables rules lost on reboot. | Daemon re-applies C2 DROP rules on every start. |

---

## Architecture

```
                        systemd (Restart=always)
                                  │
                          cerberus.sh run
                                  │
                 ┌────────────────┴───────────────┐
                 │   sensor loop, every 30s        │
                 │                                 │
   lib/detect.sh │  run_all_detectors ──► findings │  SEVERITY|CATEGORY|PID|DETAIL
                 │        │                        │
   lib/respond.sh│        ▼                        │
                 │  handle_finding                 │
                 │   ├─ lib/forensics.sh  (always) │──► state/evidence/
                 │   ├─ emit_event + notify()      │──► state/events.jsonl
                 │   └─ HARD only, if AUTO_RESPONSE:│
                 │        kill ─ quarantine ─ iptables
                 └─────────────────────────────────┘
                                  │
         lib/baseline.sh  ── persistence snapshot/diff ──► state/baseline/
```

### Repository layout

```
cerberus.sh              daemon: run | scan | dryscan | baseline
master.sh                control wrapper over systemd + events log
lib/
  common.sh              config load, log(), notify(), run() (dry-run-aware), signature helpers
  detect.sh              all detectors -> SEVERITY|CATEGORY|PID|DETAIL lines
  respond.sh             tiered responder; idempotent C2 firewall; quarantine
  forensics.sh           non-destructive evidence capture (per-PID / per-file)
  baseline.sh            persistence-surface snapshot + diff
etc/
  cerberus.env.example   copy to cerberus.env and edit (cerberus.env is git-ignored)
  whitelist.txt          process names exempt from CPU/miner heuristics
  signatures/            malware_md5, c2_ips, c2_ports, miner_patterns, malware_paths
systemd/eyes-cerberus.service
ir/                      MANUAL incident-response tools (not run by the daemon)
  quick_response.sh  emergency_remediation.sh  honeypot.sh  docker/
state/                   runtime (git-ignored): events.jsonl, evidence/, quarantine/, baseline/
```

---

## Detections

### HARD — auto-contained when `AUTO_RESPONSE=1`

| Category | Trigger | Response |
|---|---|---|
| `malware_path` | file at a path in `signatures/malware_paths.txt`, perms ≠ `000` | quarantine copy, `chmod 000` original (not deleted), kill anything executing it |
| `malware_hash` | file under `/tmp /var/tmp /dev/shm` or `/root/*/.next/standalone` matching `signatures/malware_md5.txt` | quarantine + `chmod 000` |
| `malware_proc` | a process whose exe is in a volatile dir **and** matches a known hash | kill + quarantine the binary |
| `c2_beacon` | `nc`/`ncat`/`socat` argv contains a known C2 IP or suspicious port | re-apply C2 firewall + kill |
| `c2_socket` | an established outbound socket to a known C2 IP (any client) | re-apply C2 firewall + kill |
| `miner` | argv matches `signatures/miner_patterns.txt` **and** instantaneous CPU over threshold | kill + quarantine the binary |

### SOFT — evidence + alert only, process/file untouched

| Category | Trigger |
|---|---|
| `high_cpu` | non-whitelisted process over `CPU_THRESHOLD` on `CPU_SUSTAIN_SAMPLES` consecutive passes (instantaneous CPU, not `ps` average) |
| `miner` | miner-like argv but **not** CPU-hot |
| `exe_in_volatile` / `deleted_exe` | process running from `/tmp`,`/dev/shm`,… or from an unlinked binary whose origin was a volatile dir (package upgrades under `/usr` are ignored) |
| `new_listener` | a listening TCP port absent from `state/baseline/listeners` |
| `persistence` | additions vs `state/baseline/` in: root crontab, `/etc/cron.*`, systemd unit files, running services, `/root/.ssh/authorized_keys`, root shell rc files, `/etc/ld.so.preload` (checked every `PERSISTENCE_EVERY` passes) |
| `upx_new` | a newly-appeared UPX-packed executable in a world-writable dir |
| `egress` | new outbound connection to a non-whitelisted external IP (**off by default**, noisy) |

Out of scope by design: the `/root/.botnet_c2` and `/root/.sys_test_*` markers on
this host are known security-test artifacts; the daemon does not scan top-level
`/root` dotfiles.

---

## Install

```bash
cd /root/projects/eyes_cerberus
cp etc/cerberus.env.example etc/cerberus.env      # edit thresholds / notify
./cerberus.sh dryscan                             # sanity check: prints findings, no action

sudo cp systemd/eyes-cerberus.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now eyes-cerberus.service
./master.sh status
```

Optional daily digest (writes nothing external, just to the journal):

```cron
0 9 * * *  /root/projects/eyes_cerberus/master.sh digest 1 | systemd-cat -t cerberus-digest
```

iptables rules are re-applied by the daemon on every start. If you also want them
to survive a reboot before the daemon comes up, install `netfilter-persistent`
and `netfilter-persistent save` — that step is left to you.

---

## Operating it

```bash
./master.sh status         # daemon + firewall + dropper-paths + recent events
./master.sh scan           # one detect+respond pass right now
./master.sh dryscan        # one pass, print findings, take NO action
./master.sh digest 7       # summarise events.jsonl for the last 7 days
./master.sh logs 200       # journalctl -u eyes-cerberus
./master.sh baseline       # rebuild the persistence baseline — do this ONLY after
                           # reviewing the current host state as known-good
```

After a legitimate change (new service, new cron job, new listening port) you
will get one `persistence` / `new_listener` alert, then run `./master.sh baseline`
to re-baseline.

### Configuration (`etc/cerberus.env`)

| Key | Default | Meaning |
|---|---|---|
| `SENSOR_INTERVAL` | `30` | seconds between passes |
| `CPU_THRESHOLD` | `85` | percent (per core) for the `high_cpu` heuristic |
| `CPU_SUSTAIN_SAMPLES` | `4` | consecutive over-threshold passes before alerting |
| `AUTO_RESPONSE` | `1` | `0` = alert-only for everything (HARD still logs + notifies) |
| `BLOCK_C2_PORTS` | `0` | also DROP outbound to `c2_ports.txt` (affects all hosts — opt-in) |
| `DRY_RUN` | `0` | `1` = never kill/chmod/iptables, only log with `[DRY]` |
| `NOTIFY_METHOD` | `log` | `log` \| `telegram` \| `webhook` \| `email` |
| `NOTIFY_MIN_SEVERITY` | `SOFT` | `HARD` to mute SOFT notifications (still recorded) |
| `DETECT_*` | `1` | toggle individual SOFT detectors |

Signatures are plain text, one entry per line, `#` comments — edit and the daemon
picks them up on the next pass (no restart needed).

---

## Incident-response tools (`ir/`, manual)

Not started by the daemon. Run by hand during a live incident.

- `ir/quick_response.sh {status|stop|block|evidence|quarantine|scan}` — quick actions.
- `ir/emergency_remediation.sh` — guided full response (prompts before acting).
- `ir/honeypot.sh` — decoy service + connection logging (optional, noisy).
- `ir/docker/` — Docker-based sample isolation (`CONTAINMENT_STRATEGY.md`, `containment.sh`).

---

## Verifying a change

```bash
bash -n cerberus.sh lib/*.sh master.sh          # syntax
./cerberus.sh dryscan                           # detectors run, zero actions
printf '#!/bin/sh\n' > /tmp/let; chmod 755 /tmp/let
./cerberus.sh scan                              # -> HARD/malware_path: /tmp/let chmod 000 + quarantined
ls state/quarantine state/evidence; cat state/events.jsonl
sudo systemctl restart eyes-cerberus && ./master.sh status
sudo kill -9 "$(systemctl show -p MainPID --value eyes-cerberus)"
sleep 6 && systemctl is-active eyes-cerberus    # -> active (restarted)
```

---

## Disclaimer

Defensive use, on hosts you own or administer. It contains threats (kills
processes, blocks IPs) but never deletes files — originals are `chmod 000` for
forensics. It does not guarantee protection and is not a substitute for patching,
least privilege, and backups.
