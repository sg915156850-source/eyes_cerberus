# Known threats

Indicators this host has actually seen, and what Cerberus does about each.
Signature files under `etc/signatures/` are the machine-readable source of truth;
this file is the human context.

## Incident: `/let` dropper + `nc` C2 beacon (2026-03 → 2026-04)

A compromised application (`/root/NaviomSite/server-deploy/site`, a Next.js build)
was spawning a UPX-packed ELF backdoor. Behaviour observed:

- payload written to `/let` (and attempted at `/var/let`, `/dev/let`, `/dev/shm/let`,
  `/etc/let`, `/tmp/let`), made executable, run as root;
- outbound `nc <c2-ip> 9009` beacons;
- consistent with a crypto-miner dropper.

### Indicators

| Type | Value | Signature file |
|---|---|---|
| MD5 | `ac65b89c09bbb53406dad3d42915c231` — `/let`, UPX-packed ELF | `malware_md5.txt` |
| Path | `/let` `/var/let` `/dev/let` `/dev/shm/let` `/etc/let` `/tmp/let` | `malware_paths.txt` |
| C2 IP | `107.175.89.136` | `c2_ips.txt` |
| C2 IP | `87.121.84.56` | `c2_ips.txt` |
| Port | `9009` (beacon), plus common backdoor ports `4444 5555 14444` | `c2_ports.txt` |

### Cerberus response

- `107.175.89.136` and `87.121.84.56` are DROP-ed (OUTPUT + INPUT) on every daemon
  start — see `iptables -S`.
- A file at any known path with perms ≠ `000`, or any file/running binary matching
  the known hash → **HARD**: quarantined to `state/quarantine/`, original `chmod 000`
  (kept for forensics), any process executing it killed.
- `nc`/`socat` to a known C2 IP/port, or any established socket to a known C2 IP →
  **HARD**: firewall re-applied + process killed.

## Adding a new indicator

Append to the relevant file in `etc/signatures/` (one per line, `#` for comments).
No restart needed — the next sensor pass reads it. Record the context here.
