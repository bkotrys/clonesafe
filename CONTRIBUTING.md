# Contributing to clonesafe

Thanks for wanting to make clonesafe stronger. Every new sample and every new rule catches attacks for the next developer who almost got hit.

## Ways to contribute

### 1. Submit a malicious sample

Did you get hit by (or narrowly avoid) a suspicious repo? Share the pattern so clonesafe can detect it.

**How:**
1. Open an [IOC submission issue](.github/ISSUE_TEMPLATE/ioc-submission.md)
2. Include: the original repo URL (if still live), the specific lines/patterns that were malicious, which `detectors/` rules matched (or didn't), and any IOCs (domains, package names, hashes)
3. If you're comfortable, open a PR adding:
   - An anonymized sample to `samples/<campaign-name>/`
   - New IOCs to the relevant `iocs/*.json`
   - A new detector rule to `detectors/` if an existing one didn't catch it

**What we need in a good sample:**
- `package.json` (verbatim, public data)
- The minimal code snippet that triggers the attack (can be a few lines)
- A plain-English `analysis.md` explaining what it does
- A `verdict.md` showing what clonesafe reported (or should report)

### 2. Report a false positive

clonesafe should never block a legit project. If it does, that's a bug worth fixing.

**How:**
1. Open a [false positive issue](.github/ISSUE_TEMPLATE/false-positive.md)
2. Include: the legit repo URL, the rule that triggered, and why it's a false positive
3. If you have a fix, PR the rule refinement

### 3. Add a new detector rule

New attack patterns emerge constantly. Add a rule when you see something clonesafe doesn't catch.

**How:**
1. Add your rule to the appropriate file in `detectors/` (or create a new one)
2. Include: rule name, risk level, what it matches (regex/AST/substring), why it's suspicious, a real-world example, false-positive notes
3. Add at least one sample to `samples/` that triggers the rule
4. Open a PR with both changes

### 4. Expand IOC databases

If you see a new malicious npm package, GitHub org, or exfil domain, add it.

**How:**
1. Edit the relevant `iocs/*.json` file
2. Each entry should include: the identifier, first-seen date, source (CISA/FBI/Unit42/your own research), and a one-line description
3. PR with a descriptive title (`iocs: add Contagious Interview domain cluster (2026-04)`)

## Code of Conduct

Be kind. Don't dox. Don't publish private PII. Don't submit samples containing real victim data without consent (anonymize PESEL, wallet addresses, real names, etc.).

## What we won't accept

- Rules that require running the scanned code
- Rules that call external services beyond `api.github.com` and `raw.githubusercontent.com`
- IOCs based on nationality, name origin, or accent — those are both ineffective and discriminatory
- Samples that include real victim PII
- Anything that would make clonesafe itself require network calls or auth

## Attribution

Contributors are credited in `CONTRIBUTORS.md` (coming soon). If you contribute a significant detector or case study, you're welcome to add yourself via PR.

## Questions

Open a [discussion](https://github.com/bkotrys/clonesafe/discussions) or reach out to [@bkotrys](https://github.com/bkotrys) directly.
