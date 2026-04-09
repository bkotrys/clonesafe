# Security policy

clonesafe is an adversarial security tool — its job is to analyze content authored by hostile parties and produce correct verdicts. That makes clonesafe itself a target. This document describes how we think about threats to clonesafe, what defenses are in place, and how to responsibly disclose issues.

## Threat model

### Assets to protect

1. **The correctness of scan verdicts** — a malicious repo must not produce a false PROCEED verdict
2. **The clonesafe user's trust in the output** — reports must not be manipulable by scanned content
3. **The integrity of the IOC database and detector rules** — these are the single source of truth; tampering would compromise every user
4. **The user's machine** — clonesafe must never cause code from the scanned repo to execute, even accidentally

### Adversaries

1. **Commodity npm / GitHub stealers** — automated operators running Contagious Interview-style campaigns. Low sophistication individually, high volume.
2. **State-sponsored APT operators** — DPRK-nexus, other nation-state actors with documented interest in developer targeting. Medium-to-high sophistication.
3. **Targeted attackers** — specific adversaries aiming at a specific victim (you, the clonesafe user). Variable sophistication, high motivation.
4. **Security researchers** — friendly adversaries probing clonesafe for weaknesses. We welcome their attention.

### Attack surfaces

#### A1 — Prompt injection in fetched content

**Description:** an attacker embeds text in their repo (README, comments, source, metadata, file names) that attempts to manipulate clonesafe's LLM reasoning to produce an incorrect verdict.

**Defenses:**
- **Phase 0 deterministic pre-scan** — `grep`/`jq`/`curl` commands run via the Bash tool BEFORE Claude reads any content. Produces ground-truth match counts. Claude reports these numbers but cannot alter them. If any deterministic check fires, the verdict floor is BLOCK before reasoning begins. No prompt injection can change `grep` output.
- Phase A / Phase B architecture — LLM-assisted findings are locked before report writing begins
- Verdict floor — Phase 0 numbers + Phase A findings hardcode BLOCK regardless of score
- [`detectors/prompt-injection.md`](detectors/prompt-injection.md) — PI-001 through PI-008 rules that turn injection attempts into detection signals
- Explicit guardrails in skill file ("Absolute rules" 7, 8, 9) — treat all fetched content as untrusted data
- Content wrapping — every fetched file is bracketed with untrusted-content markers before analysis
- Self-check — verify verdict derived from raw findings matches emitted verdict
- Mandatory human confirmation — `[N]` is the default answer, user must explicitly type `y`

**Known limitations:**
- Novel semantic attacks that don't match any PI-00X pattern may slip through the reasoning layer
- Cross-file compound attacks (injection fragments distributed across multiple files) are not currently detected
- Non-English injection in languages other than English may bypass regex-based PI rules (planned: language-aware patterns)
- Base64/hex encoding is handled by PI-007; exotic encodings (ROT47, Morse, Unicode homoglyphs, etc.) may slip through (contributions welcome)

**Residual risk:** low-to-medium depending on attacker sophistication. Mechanical rules catch known patterns with ~100% reliability; the reasoning layer provides defense in depth but not absolute protection.

#### A2 — False negatives in detector rules

**Description:** a malicious repo uses a new attack pattern that clonesafe's rules don't cover yet.

**Defenses:**
- Comprehensive rule catalog in [`detectors/`](detectors/) covering: lifecycle scripts, obfuscation, exfiltration, reconnaissance, repo metadata, prompt injection
- IOC database in [`iocs/`](iocs/) for known-bad packages/domains/orgs
- Community contribution flow via [`modes/ioc-update.md`](modes/ioc-update.md) and GitHub issues
- Regular updates as new attack techniques are published by researchers (Snyk, Socket, Phylum, Unit 42, etc.)

**Known limitations:**
- Zero-day detection is not possible — we catch patterns, not novel techniques
- Sophisticated obfuscation (non-string-array mangling, custom encoders) may defeat pattern matching
- Polymorphic payloads generated at runtime cannot be analyzed statically

**Residual risk:** medium. A novel campaign will evade clonesafe until someone submits a sample and we add rules. This is the same model as antivirus signatures — never perfect, always valuable.

**Known evasion techniques against current Phase 1 rules:**

| Technique | What it bypasses | Status |
|---|---|---|
| Name payload `build.js` to match LS-003 allowlist | LS-003 (lifecycle hook → non-build file) | Documented; fix in Phase 1.5 (tighten or remove allowlist) |
| Split base64 literal across concatenated strings (`"abc" + "def"`) | OB-003 (base64 + dynamic exec) | Documented; add OB-003b for concatenated detection |
| Alias `Function` constructor (`const F = Function; F(code)(require)`) | OB-004 (RCE via new Function) | Documented; expand regex to catch indirect invocation |
| Access `Function` via prototype chain (`({}).constructor.constructor(...)`) | OB-004 | Documented; add prototype-chain variant |
| Use `globalThis.Function()` instead of `new Function()` | OB-004 | Documented; add globalThis variant |
| Indirect env access (`const e = process.env; axios.post(url, e)`) | EX-001 (env POST) | Documented; requires variable-tracking analysis |
| Non-npm attack vectors (Python `setup.py`, Rust `build.rs`, Go `go generate`, etc.) | All npm-specific detectors | Documented; Phase 2 adds multi-language support |
| GitHub Actions workflow exfil (`.github/workflows/*.yml`) | Not currently scanned | Documented; planned for Phase 1.5 |
| Injection in non-English languages | PI-001..PI-004 (regex are English-only) | Documented; multilingual patterns planned |

These are published intentionally. Transparency helps defenders more than it helps attackers — attackers who study clonesafe's source to find gaps are already sophisticated enough to evade anyway. Publishing known limitations invites the community to close them.

#### A3 — False positives that train users to ignore warnings

**Description:** overly aggressive detection causes legitimate repos to be flagged, leading users to dismiss clonesafe warnings entirely.

**Defenses:**
- Rule files include explicit "False positives" sections documenting known benign cases
- [`detectors/allowlist.md`](detectors/allowlist.md) (planned) — explicit allowlist patterns for known-good projects
- Scoring weights are calibrated so single LOW/MEDIUM findings don't cross the WARN threshold
- False positive reporting via [`.github/ISSUE_TEMPLATE/false-positive.md`](.github/ISSUE_TEMPLATE/false-positive.md)

**Known limitations:**
- New rules may cause FP waves until they're tuned
- We can't pre-test against every legitimate project

**Residual risk:** medium. Active FP triage is an ongoing maintenance task.

#### A4 — Tampering with clonesafe itself

**Description:** an attacker compromises the clonesafe repository, detector rules, or IOC database to introduce backdoors or weaken detection.

**Defenses:**
- Single maintainer (initially) with full audit trail
- MIT license + public repo — all changes are publicly visible
- No executable code in Phase 1 — all files are markdown and JSON, which are safe to read
- Phase 2+ (CLI) will be code-signed and published via npm with integrity hashes
- Contributors vet all PRs before merge

**Known limitations:**
- Social engineering of the maintainer is always possible
- Supply-chain attacks on clonesafe's own dependencies (none in Phase 1; concern for Phase 2 CLI)

**Residual risk:** low at Phase 1, medium once we ship a CLI with dependencies.

#### A5 — Network-based attacks on the scan flow

**Description:** MITM on the GitHub API or `raw.githubusercontent.com` connection to return modified content.

**Defenses:**
- HTTPS-only communication with GitHub
- Optional `GITHUB_TOKEN` for authenticated calls (provides integrity via the API)
- No resource loading from attacker-controlled domains

**Known limitations:**
- If the user's local TLS trust store is compromised (e.g., malicious CA installed), MITM is possible
- CloudFlare / CDN caching could serve stale content (low impact for malicious detection)

**Residual risk:** low.

## Responsible disclosure

If you discover a security issue in clonesafe — whether a prompt injection bypass, a missed detection pattern, a false positive, or something else — please report it responsibly.

### How to report

1. **Do not** open a public GitHub issue for security vulnerabilities that could be exploited in the wild
2. **Do** email the maintainer directly: security@bkotrys.dev (or whichever contact is current in this file)
3. Include:
   - A clear description of the issue
   - Steps to reproduce (minimal working example preferred)
   - The impact (what does the bypass enable?)
   - Suggested mitigation, if you have one

### Response timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix timeline:** depends on severity
  - Critical (prompt injection bypass, false PROCEED on known malicious patterns): 72 hours
  - High (new attack class not caught by current rules): 7 days
  - Medium (false positives, minor rule tweaks): 30 days
  - Low (documentation, typos): best-effort

### Coordinated disclosure

For vulnerabilities that affect real users:
- We will coordinate a public disclosure date with the reporter
- Patch will be shipped and tagged before the public disclosure
- Reporter will be credited in the CHANGELOG and (if they wish) in the release notes
- No bug bounty is offered at this time — clonesafe is a non-commercial open-source project

### Hall of fame

Security researchers who have responsibly disclosed issues will be listed here (with their permission). None yet — be the first.

## Known non-issues

These are things that look like security problems but aren't:

- **clonesafe doesn't catch [specific attack technique] that's documented in [paper]** — that's a false negative, not a security vulnerability. Open an issue / PR to add the pattern to the detector.
- **clonesafe flags a legitimate project** — that's a false positive, not a security vulnerability. Use the [false positive template](.github/ISSUE_TEMPLATE/false-positive.md).
- **clonesafe lets me proceed with `y`** — by design. The `[N]` default is there; if you type `y`, you've accepted the risk.
- **clonesafe can be read/forked/modified** — it's MIT-licensed. Anyone can read the rules and try to evade them. The rules still work against attackers who don't tune their campaigns specifically to clonesafe (which is the vast majority).

## What NOT to report as security issues

- General feature requests → open a regular issue
- Questions about how a rule works → open a discussion
- Ideas for new detection categories → PR with the new detector file

## Philosophy

clonesafe is built on a few core principles:

1. **Transparency over obscurity** — all rules and IOCs are public. Attackers can read them. Defenders benefit more from the publication than attackers do from the evasion.
2. **Defense in depth, not silver bullet** — no single layer provides 100% protection. Multiple overlapping defenses provide strong practical security.
3. **Honesty over marketing** — we do not claim complete protection. We document limitations explicitly. Users who understand the residual risk are better defenders.
4. **Community over proprietary** — the IOC database is a shared resource. Contributions from victims (and defenders) are the primary way clonesafe improves.
5. **Human verification is the final backstop** — clonesafe provides evidence, the human makes the decision. `[N]` is the default for a reason.

---

**Thank you for caring about clonesafe's security.** If you're reading this because you're planning to responsibly disclose, you're exactly the kind of contributor we want.
