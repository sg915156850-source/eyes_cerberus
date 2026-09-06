# `ir/experimental/` — unsupported, read before running

Nothing in this directory is run by the daemon, referenced by `master.sh`, or
included in a built package. It is kept for reference and is excluded from
tests, lint gating and releases.

## Why these are separated

`honeypot.sh` stands up a decoy service and logs what connects to it. Its own
header already says "EDUCATIONAL/RESEARCH PURPOSES ONLY" and "consult legal
counsel before deploying counter-measures", and that caution is the reason it
sits here rather than next to the incident-response tooling.

Passive logging of connections to a service on your own host is ordinary
defensive work. The problem is the part of the file that exists to *mislead*
whoever connects. Two concrete risks:

- **Jurisdiction.** Active deception and anything adjacent to "hack-back" is
  treated very differently across legal systems. Some read it as
  unauthorised access in its own right.
- **Third parties.** An attacker usually arrives from a machine that is itself
  compromised — someone else's. Anything you do back lands on a victim, not on
  the attacker.

Neither risk is theoretical enough to keep this in the default install of a
tool that might be deployed on someone else's server.

## If you run it anyway

- Only on a host you own, with no third-party traffic reaching it.
- Never on a machine covered by a customer contract or an SLA.
- Get legal advice first if you are in any doubt — the file says the same.

The rest of `ir/` (`quick_response.sh`, `emergency_remediation.sh`, `docker/`)
is supported and carries none of this.
