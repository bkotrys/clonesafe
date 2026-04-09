# Sample 002 — Prompt Injection Test Bait

**Purpose:** Synthetic test sample for the clonesafe prompt-injection detector.
**Type:** Deliberately-crafted injection attempts. Not a real incident.
**Status:** Test fixture.

---

## Why this exists

This sample is **not a captured attack**. It's a synthetic set of files containing every canonical prompt injection pattern documented in [`../../detectors/prompt-injection.md`](../../detectors/prompt-injection.md) (rules PI-001 through PI-008).

Its purpose is to verify that clonesafe's PI detectors work correctly: if you run `vet-repo` or `deep-scan` against this sample, every single PI rule should fire and the verdict should be locked at 🔴 BLOCK via the verdict floor.

**This is defensive tooling.** The injections here are hand-crafted from publicly-documented research (Simon Willison's prompt injection corpus, Lakera's Gandalf challenge, academic papers on LLM jailbreaking, Trojan Source CVE-2021-42574, and the GlassWorm supply chain attack writeup). None of them are "real" attacks — they're educational examples.

## Files in this sample

- [`README-with-injections.md`](README-with-injections.md) — a README containing examples of PI-001 through PI-006 (natural-language injections)
- [`package.json`](package.json) — a package.json with injections in the `name`, `description`, and `scripts` fields (PI-001, PI-003, PI-004)
- [`comment-injection.js`](comment-injection.js) — JavaScript source file with injection attempts in comments (PI-001, PI-002, PI-003)
- [`unicode-trojan.js`](unicode-trojan.js) — demonstrates PI-008 with hidden Unicode characters
- [`encoded-injection.md`](encoded-injection.md) — base64-encoded injection strings (PI-007)

## What clonesafe should output on this sample

All 8 PI rule families should fire. The expected verdict:

```
╭─ clonesafe verdict — prompt-injection-test ───────────╮
│  Risk: 🔴 BLOCK    Score: >300 (exact depends on      │
│  rule caps)                                           │
│                                                       │
│  🚨 CRITICAL (Prompt injection)                       │
│  • PI-001: instruction-override phrases detected      │
│  • PI-002: role/system impersonation detected         │
│  • PI-003: trust-claim forgery detected               │
│  • PI-004: output manipulation directives detected    │
│  • PI-005: tool-call impersonation detected           │
│  • PI-007: base64-encoded injection detected          │
│  • PI-008: hidden Unicode characters detected         │
│                                                       │
│  🟡 MEDIUM                                            │
│  • PI-006: out-of-context LLM references              │
│                                                       │
│  Verdict floor: LOCKED AT BLOCK via PI-001, PI-002,   │
│  PI-003, PI-004 (each independently sufficient)       │
╰───────────────────────────────────────────────────────╯
```

**If clonesafe does NOT produce a BLOCK verdict on this sample, there is a bug in the PI detector.** Either the rules are missing a pattern, the skill file isn't loading the detector, or the verdict floor isn't firing correctly. All three are immediate ship-blockers.

## How to use this sample for regression testing

1. Run `vet-repo` or `deep-scan` against this directory
2. Verify every PI-001 through PI-008 rule fires (except possibly PI-008 depending on your terminal's Unicode handling)
3. Verify the verdict is 🔴 BLOCK
4. Verify the verdict floor explanation mentions PI-001..PI-004
5. Verify the report quotes the matched content in fenced code blocks (not paraphrased in natural language)

## Responsible note

The injections in this directory are deliberately contained in clearly-marked test files. They are not in any file that would be loaded by a runtime, installed by a package manager, or processed by any tool other than clonesafe's static scanner. None of the "malicious" instructions are actually malicious — they target a scanner, not a system.

**Do not copy these files outside the `samples/prompt-injection-test/` directory** without clearly documenting that they are test fixtures. Injection strings in the wrong context can confuse other tools.

**Do not use these as templates for real attacks.** clonesafe is a defensive tool. If you're studying this sample to learn how to bypass scanners, you're using it wrong.
