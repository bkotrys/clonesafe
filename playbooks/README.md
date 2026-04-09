# Playbooks

Hands-on runbooks for what to do if you got hit (or might have been hit) by a malicious repo. Every playbook here was written from a real incident — they're not theory.

## Read these in order if you just got hit

1. **[`i-just-ran-it.md`](i-just-ran-it.md)** — first 30 minutes. Contain the threat.
2. **[`wallet-drain-procedure.md`](wallet-drain-procedure.md)** — if you have any crypto. Do this before anything else in Phase 2.
3. **[`github-audit.md`](github-audit.md)** — rotate GitHub credentials, audit the security log, check for unauthorized activity.
4. **[`rotation-checklist.md`](rotation-checklist.md)** — the master list of credentials to rotate across every service.
5. **[`forensic-scan.md`](forensic-scan.md)** — read-only deep scan of the compromised machine to find any persistence or keyloggers.
6. **[`90-day-monitoring.md`](90-day-monitoring.md)** — long-term watchlist for slow-burn fraud detection.

## When to use which

| You just ran a suspicious `npm install` | Start with `i-just-ran-it.md` |
| You ran something days ago, only realized now | Skip Phase 1, start with `wallet-drain-procedure.md` |
| You think you might be at risk but not sure | Run `clonesafe vet-repo` on the repo first; only use these if verdict is WARN or BLOCK |
| You want to audit credentials as a routine exercise | `rotation-checklist.md` is a standalone hygiene guide |
| You want to harden against a future attack | `forensic-scan.md` shows what to check; `90-day-monitoring.md` establishes the habit |

## Contributing

If you went through an incident and found gaps in these playbooks — add them. Open a PR. The goal is for these to become the canonical answer when a victim searches "I ran a malicious npm install what do I do."

## Planned additions

- `pesel-freeze.md` — Polish identity freeze walkthrough with screenshots
- `time-machine-restore.md` — how to safely restore from pre-incident backup
- `pcap-analysis.md` — if you captured network traffic during the incident, how to analyze it
- `responsible-disclosure.md` — how to notify impersonated brands without over-sharing
- `talk-to-your-employer.md` — what to tell (and not tell) your employer if the incident happened on a work machine or involves work accounts
