# WARNING — Malicious Samples

This directory contains **captured malware samples and synthetic attack fixtures** for defensive research, detection training, and regression testing.

## Rules

1. **Do NOT execute any code in this directory.** No `node`, no `npm install`, no `python`, no `cargo build`. Static reading only.

2. **Do NOT copy sample files into other directories** without clearly marking them as test fixtures. The patterns in these files can trigger security tools, confuse LLMs, and — if re-armed — cause real harm.

3. **Sample code has been DISARMED** so it cannot execute even if run by accident:
   - `require()` calls are commented out
   - Base64-encoded URLs are broken with `[DEFANGED]` markers
   - Auto-execution calls are removed
   - Each sample directory contains `.npmrc` with `ignore-scripts=true` to block npm lifecycle hooks

4. **The disarming is a safety measure, not a guarantee.** Don't test it. Treat every file here as if it's armed.

5. **Do NOT re-arm the samples** (uncomment requires, fix base64 strings, add execution calls) unless you are operating in a fully isolated sandbox (disposable VM, no network, no credentials on disk).

## What's here

| Directory | Type | Contents |
|---|---|---|
| `contagious-interview-001/` | Real incident (anonymized, defanged) | Captured npm `prepare` hook + exfil + RCE code from an April 2026 Contagious Interview attack |
| `prompt-injection-test/` | Synthetic test fixture | Deliberately-crafted prompt injection attempts for clonesafe's PI detector regression tests |

## If you're adding a new sample

See [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for the full process. Key requirements:
- Remove all real victim PII (names, addresses, wallet addresses, PESEL, etc.)
- DISARM all executable code (comment out requires, break encoded URLs, remove auto-exec)
- Add `.npmrc` with `ignore-scripts=true` in the sample directory
- Add a `README.md` explaining what the sample is and what it demonstrates
- Do NOT include real attacker credentials that could be misused (API keys, tokens, passwords)
- DO include attacker infrastructure identifiers (domains, IPs) — these help defenders block them
