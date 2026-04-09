---
detector: repo-metadata
applies-to: GitHub API responses
risk-family: trust-signals
---

# Detector: repo metadata

Signals derived from GitHub API responses — cheap to fetch, useful for flagging newly-minted throwaway repos without looking at source.

## Rules

### RM-001 — repo created <30 days before scan
**Risk:** 🟠 HIGH
**Matches:** `created_at` is within 30 days of scan time.

**Why suspicious:** throwaway attack repos are typically created days or weeks before being handed to a victim. Real projects accumulate history over months or years.

**False positives:** genuinely new projects (early-stage startups, hackathon output, personal side projects). Weight should scale with other signals — a new repo with a busy commit history is less suspicious than a new repo with one squashed commit.

**Weight:** +10 (new). +20 if <7 days.

---

### RM-002 — org/user account <30 days old
**Risk:** 🔴 HIGH
**Matches:** Owner's account `created_at` is within 30 days.

**Why suspicious:** attack operators create disposable GitHub orgs. Legitimate companies rarely hand out code challenges to candidates within 30 days of creating their GitHub presence.

**False positives:** new users who just joined GitHub.

**Weight:** +15 (org). +8 (user account).

---

### RM-003 — single contributor
**Risk:** 🟡 MEDIUM
**Matches:** `contributors_count == 1`.

**Why suspicious:** attack repos have a single author (the operator). Real open-source projects accumulate contributors.

**False positives:** solo dev projects, early-stage repos. Combined with other signals, this becomes meaningful.

**Weight:** +8

---

### RM-004 — zero stars despite being public
**Risk:** 🟡 MEDIUM
**Matches:** `stargazers_count == 0` AND repo age >30 days.

**Why suspicious:** any public repo older than a month without a single star is unusual.

**False positives:** many — private projects that happen to be public, hobby repos, internal tooling.

**Weight:** +5

---

### RM-005 — single squashed commit
**Risk:** 🟡 MEDIUM
**Matches:** default branch has exactly 1 commit in its history.

**Why suspicious:** attack repos are often force-pushed or re-initialized to hide history. Real projects have iterative commits.

**False positives:** fresh repos, squash-merge policy projects. Check age.

**Weight:** +5

---

### RM-006 — no LICENSE file
**Risk:** 🟡 MEDIUM
**Matches:** No license detected via GitHub API.

**Why suspicious:** professional open-source projects almost always declare a license. Missing license = either sloppy or deliberately gray.

**False positives:** internal projects, early WIP. Weight low.

**Weight:** +2

---

### RM-007 — no .gitignore AND has package.json
**Risk:** 🟡 MEDIUM
**Matches:** package.json exists at root but no .gitignore.

**Why suspicious:** any Node.js project with a .gitignore-missing is either brand new or set up carelessly.

**Weight:** +2

---

### RM-008 — archived or disabled repo being handed out as a take-home
**Risk:** 🟠 HIGH
**Matches:** `archived: true` OR `disabled: true`.

**Why suspicious:** a recruiter handing out an archived/disabled repo is either sloppy or specifically routing around GitHub's security controls.

**Weight:** +15

---

### RM-009 — README vs. reality mismatch
**Risk:** 🟡 MEDIUM (requires fetching README + other files)
**Matches:** README claims one thing (project maturity, contributor count, production deployment) but repo state contradicts it.

Examples:
- README says "deployed to production, serving 10k users" but repo created 5 days ago
- README has contributor badges but the repo has 1 contributor
- README references features whose code doesn't exist
- README is copied from another well-known project (stylometry check)

**Why suspicious:** attackers often plagiarize READMEs from real projects to look legitimate.

**Weight:** +8

---

### RM-010 — very small or very recent stars pattern
**Risk:** 🟡 MEDIUM
**Matches:** stars count is small (1-5) but all stars appeared within the same 24-hour window close to the repo's creation or close to "now".

**Why suspicious:** fake engagement rings add stars in batches. Legitimate stars accumulate over time.

**Weight:** +8 (requires stargazer timestamp fetch)

---

### RM-011 — owner listed in clonesafe IOC database
**Risk:** 🔴 CRITICAL
**Matches:** `{owner}` appears in `iocs/github-orgs.json`.

**Weight:** +40

---

### RM-012 — no releases but claims to be a library
**Risk:** 🟡 LOW
**Matches:** 0 releases and package.json says `"main": "..."` or `"bin": "..."` intended for publication.

**Why suspicious:** real libraries publish releases.

**Weight:** +3

---

### RM-013 — suspicious commit author patterns
**Risk:** 🟡 MEDIUM
**Matches:** All commits authored by generic email (`user@example.com`, `root@localhost`) or a single throwaway email.

**Weight:** +5

---

### RM-014 — repo is a shallow fork with modifications
**Risk:** 🟠 HIGH
**Matches:** `fork: true` AND the divergence from the parent includes new package.json scripts or new source files.

**Why suspicious:** a common trick is to fork a legitimate repo and add a single malicious commit. The project "looks" legitimate (inherited history, stars, forks from upstream) but the attacker-added commits contain the payload.

**False positives:** many legitimate forks exist. Check what the modifications actually do.

**Weight:** +15

---

## Scoring summary

| Rule | Weight |
|---|---|
| RM-001 new repo (<30d) | +10 / +20 (<7d) |
| RM-002 new account (<30d) | +15 (org) / +8 (user) |
| RM-003 single contributor | +8 |
| RM-004 0 stars | +5 |
| RM-005 single squashed commit | +5 |
| RM-006 no LICENSE | +2 |
| RM-007 no .gitignore | +2 |
| RM-008 archived/disabled | +15 |
| RM-009 README mismatch | +8 |
| RM-010 batch stars | +8 |
| RM-011 IOC org match | +40 |
| RM-012 no releases for lib | +3 |
| RM-013 sus commit authors | +5 |
| RM-014 suspicious fork | +15 |

These signals rarely trigger BLOCK on their own (except RM-011). They add weight to support detector findings and bump WARN → BLOCK when stacked.
