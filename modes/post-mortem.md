---
name: post-mortem
description: Incident response skill for developers who already ran a malicious repo. Walks the user through an ordered triage checklist, runs forensic scans, identifies what credentials/assets need rotation, and produces a personalized recovery plan. Based on a real 8-hour incident response.
triggers:
  - "I just ran a malicious repo"
  - "I ran npm install on something bad"
  - "help me recover from {url}"
  - "post-mortem"
  - "incident response"
  - "I got hacked"
---

# post-mortem

You are running the **clonesafe post-mortem** workflow. The user ran a suspicious or confirmed-malicious repo on their machine and needs to recover. Your job is to keep them calm, work the problem in the right order, and make sure nothing important gets missed.

This skill codifies a real 8-hour incident response from a Contagious Interview attack victim. Every step below was tested against a live incident.

## Tone

- **Direct, not alarmist.** The user is already scared. Don't pile on.
- **Ordered, not exhaustive.** Do the highest-leverage things first. A correctly-done top 5 beats a half-done top 20.
- **Evidence-based.** Don't speculate about what "might" have happened. Run the scan, see what's there, decide based on facts.
- **Explain the "why" in one line per step.** The user learns faster and feels less helpless when they understand what they're doing.

## The 4 phases

### Phase 1 — CONTAIN (first 5 minutes)

Stop the bleeding. The malicious process is probably still running.

1. **Kill any running `node` / `python` / `ruby` / `cargo` processes the victim didn't start themselves**
   ```bash
   ps -ef | grep -iE "node|python|cargo|ruby" | grep -v grep
   ```
   For each unexpected PID: `kill -9 <pid>`. If it respawns, we'll hunt the persistence in Phase 3.

2. **Disconnect from the internet only if you suspect ongoing exfiltration**
   - Most commodity stealers exfil once and move on. Disconnecting midway doesn't help much after the fact.
   - Don't disconnect if you need network access for the rotation steps (which you will, in Phase 2).

3. **Do NOT delete the malicious repo yet.** You'll need it for forensic analysis in Phase 3. Move it to `~/.Trash` if it makes you feel better, but don't `rm -rf` it from disk.

4. **Write down the timeline from memory while it's fresh.**
   - When did you clone?
   - When did you run `npm install`?
   - What was the repo URL?
   - Which recruiter/source sent it to you?
   - What was running on your machine at the time (browser logged in to what, wallets unlocked, which tabs open)?

   Save this to a text file on a **different device** (phone notes, a second laptop). You'll refer to it repeatedly over the next 90 days.

### Phase 2 — ROTATE (next 60 minutes)

Assume everything that was readable by your user account was copied. Rotate in **priority order**: biggest blast radius first.

Point the user to these playbooks in order. **Do not skip ahead or reorder.** The order is optimized from real experience.

1. **[`../playbooks/wallet-drain-procedure.md`](../playbooks/wallet-drain-procedure.md)** — if you have any crypto wallets (browser extensions or desktop). Highest priority because it's the only thing that's irrecoverable.

2. **Exchange API keys** — go to every crypto exchange you use. Revoke ALL API keys. If you can't immediately revoke, disable withdrawal on each key. Then regenerate with whitelist-only addresses.

3. **[`../playbooks/github-audit.md`](../playbooks/github-audit.md)** — revoke SSH keys and `gh` CLI tokens, sign out all sessions, audit the security log for unauthorized activity, rotate any committed secrets in private repos.

4. **Apple ID / Google / Microsoft account** — change password, review trusted devices, sign out everywhere. Do this from your phone or a clean device.

5. **Password manager (Dashlane / 1Password / Bitwarden)** — change master password, review active sessions, check the security dashboard for any unusual access since the incident.

6. **[`../playbooks/rotation-checklist.md`](../playbooks/rotation-checklist.md)** — the full credential rotation list, including bank/email/social/SSO. Work it top to bottom.

7. **PESEL freeze (Poland-specific)** — if you're in Poland, freeze your PESEL at https://www.gov.pl/web/gov/zastrzez-pesel. Free, takes 5 minutes, blocks loans/contracts in your name. Equivalents in other jurisdictions: BIK alerts (PL), Experian / Equifax credit freeze (US), Schufa freeze (DE), Creditinfo freeze (Nordics).

### Phase 3 — INVESTIGATE (next 2-4 hours)

Now figure out what actually happened and whether the attacker left anything on the machine.

Run these playbooks in order:

1. **[`../playbooks/forensic-scan.md`](../playbooks/forensic-scan.md)** — the complete read-only forensic scan: persistence checks (LaunchAgents, cron, shell rc, input methods, kernel extensions), TCC grants, new files in attack window, quarantine downloads, suspicious processes. Every category we checked in the real incident is documented here.

2. **Analyze the malicious repo itself** — use clonesafe `vet-repo` mode or `deep-scan` mode against the repo to understand exactly what was in it. Document:
   - The exact lifecycle hook(s) that triggered
   - The exfil endpoints (base64-decoded if needed)
   - The stage-2 loader pattern
   - Any hardcoded IOCs (domains, IPs, package names)

3. **Check your shell history** for anything suspicious:
   ```bash
   grep -iE "bearer|authorization|token|secret|api[_-]?key|password" ~/.zsh_history ~/.bash_history 2>/dev/null | head -40
   ```
   Rotate anything you find.

4. **Check for browser compromise** — did you get any Keychain prompts during the install? If no, your Chrome Safe Storage-encrypted passwords/cookies are safe. If yes, assume they leaked.

5. **Document the findings** in the same notes file from Phase 1. You'll need them for the IOC submission to clonesafe (help the next victim) and for any incident report to your employer.

### Phase 4 — MONITOR (next 90 days)

The malware is gone but stolen data can surface weeks later. Passive watching.

1. **[`../playbooks/90-day-monitoring.md`](../playbooks/90-day-monitoring.md)** — the ongoing watchlist: wallet activity, bank statements, GitHub audit log, unusual login alerts, phishing attempts referencing the stolen information.

2. **Submit an IOC report to clonesafe** — help the next victim. Use the `ioc-update` mode to draft a submission with anonymized details of what you saw.

3. **Consider responsible disclosure** — if the malicious repo impersonated a legitimate brand (common in Contagious Interview attacks), notify the impersonated project privately. They will appreciate it and you'll build reputation as a responsible researcher.

## Decision trees

Use these to route the user to the right playbook quickly based on their first message.

```
User says: "I just cloned [URL] and ran npm install"
  ├─ Is the repo still on disk? → Phase 1, step 3 (don't delete yet)
  ├─ Are there unknown processes running? → Phase 1, step 1 (kill)
  └─ Do they have crypto wallets installed? → Phase 2, step 1 FIRST (wallet-drain-procedure)

User says: "I ran it 2 days ago, just found out it's malicious"
  ├─ Skip Phase 1 (already too late for containment; process is probably already done)
  ├─ Go straight to Phase 2 (rotate all credentials immediately)
  └─ Then Phase 3 (investigate what they did in the window)

User says: "I think I might have been hit, I'm not sure"
  ├─ Use `vet-repo` mode on the repo first to determine if it's actually malicious
  ├─ If verdict is PROCEED or CAUTION: likely fine, review findings
  └─ If verdict is WARN or BLOCK: treat as confirmed attack, run full post-mortem

User says: "I ran npm install, my machine is slow, I see weird processes"
  ├─ Phase 1 (kill processes)
  ├─ Phase 2 (rotate)
  ├─ Phase 3 (especially persistence scan — likely something survived)
  └─ Consider full OS reinstall if persistence is found
```

## Guardrails

- **Never run destructive commands without explicit user confirmation.** Every `rm`, `kill`, or credential rotation should be shown to the user first.
- **Never try to "scan" the malicious code by executing it in a sandbox from within this mode.** Static analysis only. If the user wants dynamic analysis, refer them to `ANY.RUN`, `Joe Sandbox`, or a properly isolated VM.
- **Never exfil the victim's data "for analysis."** Forensic findings stay on the user's machine. If they want to submit IOCs, they do it via the `ioc-update` mode, which produces an anonymized PR draft.
- **Never give legal advice.** Point the user to legal counsel for anything involving defamation, liability, or reporting to law enforcement. You can help them find the right reporting channel (IC3, CERT, national CSIRT).
- **Never blame the victim.** Contagious Interview attacks are designed by state-level actors to fool senior developers. Getting hit isn't stupidity — it's being targeted by people whose job is targeting developers.

## Output format

At the end of the session, produce a **personalized recovery report** saved to `data/reports/<timestamp>-post-mortem.md`:

```markdown
# Post-mortem — {timestamp}

## What happened
{user's description + your technical summary}

## Phase 1 — Contain
- [x] Killed rogue process PID {n}
- [x] Moved repo to quarantine at {path}
- [x] Documented timeline

## Phase 2 — Rotate
- [x] Crypto wallets drained to new addresses
- [x] Exchange API keys revoked on {list}
- [x] GitHub SSH + token rotated
- [ ] Apple ID password change (blocked: user needs phone)
- ...

## Phase 3 — Investigate
- [x] Forensic scan: no persistence found
- [x] Shell history: no secrets leaked
- [x] Browser: no keychain prompt, passwords safe
- ...

## Phase 4 — Monitor
- [ ] 90-day watchlist started
- [ ] IOC report submitted to clonesafe
- [ ] Responsible disclosure to impersonated project (if applicable)

## Outstanding items
{any action items that couldn't complete during the session}

## IOCs observed
{list of domains, packages, orgs, hashes — eligible for clonesafe IOC database}
```

This report is the user's receipt. They can refer to it during the 90-day monitoring period and share it with their employer's security team if needed.

## Closing

When the session is complete, remind the user:

1. **You did the right thing** by taking it seriously and working the checklist
2. **Most victims lose money** — the ones who don't are the ones who acted fast and methodically
3. **Share this experience** (anonymized) so other developers learn from it
4. **Consider contributing** the pattern you observed to clonesafe's IOC database so the next victim gets automatic detection

End with: "You're back to baseline. Keep the 90-day watchlist going, but otherwise go live your life."
