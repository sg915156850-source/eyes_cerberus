# Security policy

Eyes Cerberus runs as a root daemon on the host it protects. It kills
processes, changes file permissions and edits firewall rules. A defect here is
not an inconvenience — it is either a way to take the host down or a way to
gain root on it. Reports are welcome.

## Reporting

Email **sg915156850@gmail.com** with `[cerberus]` in the subject. Please do not
open a public issue for anything in the "In scope" list below.

Include what you have: affected version (`./cerberus.sh version`), affected
file and line, how to reproduce, and what an attacker gets out of it. A rough
report that is correct beats a polished one that is not.

Expect an acknowledgement within a few days. This is a one-person project, not
a vendor with an on-call rotation — timelines below are intentions, not an SLA.

| Stage | Target |
|---|---|
| Acknowledgement | 3 days |
| Assessment, in or out of scope | 7 days |
| Fix for an in-scope issue | depends on severity, communicated in the assessment |

## In scope

- **Privilege escalation into the daemon.** Anything that lets a non-root user
  influence what the root daemon executes: writable config or signature files,
  unsafe expansion of attacker-controlled process arguments, a path in
  `state/` that a local user can pre-create or replace with a symlink.
- **Response abuse.** Making the daemon kill or neutralise a process or file it
  should not — for example, crafting an argv or a filename that gets a
  legitimate service classified as HARD.
- **Detection bypass that the design does not already admit.** The daemon is
  explicitly signature- and heuristic-based, so "a renamed binary is not
  matched by hash" is documented behaviour, not a vulnerability. "A process
  that the `c2_socket` detector structurally cannot see" is one.
- **Evidence tampering.** A local user corrupting or forging
  `state/events.jsonl` or the quarantine metadata.
- **Secret disclosure.** Anything that copies `etc/cerberus.env` (it may hold a
  Telegram token) or captured `/proc/<pid>/environ` content somewhere
  world-readable.

## Out of scope

- Missing detections for malware families the signatures do not describe. Add
  the indicator to `etc/signatures/` — that is the documented way to extend
  coverage.
- False positives from the SOFT heuristics. They are alert-only by design;
  report them as ordinary issues.
- Anything requiring root on the host to begin with. Root can stop the daemon;
  that is not a bypass, it is the threat model.
- `ir/experimental/` — unsupported, not run by the daemon, see
  `ir/experimental/README.md`.

## Hardening notes for operators

- Keep `etc/cerberus.env` and `etc/signatures/` writable by root only. The
  daemon refuses to start otherwise: the config is sourced as bash by a root
  process, so write access to it is root access.
- Run `./cerberus.sh dryscan` after every signature or threshold change. It
  runs every detector and takes no action.
- Set `AUTO_RESPONSE=0` while tuning on a host you cannot afford to disrupt.
  HARD findings still collect forensics and notify.
- Evidence and quarantine live on the host being defended. An attacker who
  keeps root can destroy both — copy `state/` off the box if it matters.

## Known limitations

This is a narrow safety net, not an antivirus, not an EDR, and not a substitute
for patching, least privilege and backups. It does not delete malware
(originals are `chmod 000` and kept for forensics) and it does not guarantee
protection.
