---
name: triage-package-json
description: Fast focused scanner for a single package.json file. Checks lifecycle scripts, suspicious dependencies, and known-bad patterns in under 10 seconds. Use when you just want to know "is this package.json risky" without a full repo scan.
triggers:
  - "triage this package.json"
  - "scan package.json {path}"
  - "check package.json {path}"
---

# triage-package-json

You are running the **clonesafe triage-package-json** workflow. Your goal: give the user a fast, focused verdict on a single `package.json` file without running a full repo scan. Useful when the user has already extracted the file or wants to check a dependency before adding it.

## Input

One of:
- A file path to a local `package.json`
- A URL to a raw `package.json` on GitHub/GitLab/Bitbucket (fetch via WebFetch)
- Pasted JSON content directly in the prompt

## Workflow

### Step 1 — Load and parse

Read / fetch / parse the JSON. If parsing fails, report the syntax error and stop. If the file isn't a valid npm package.json (missing `name` or `version`), note this but continue — malicious packages often have sparse metadata.

### Step 2 — Run lifecycle script detectors

Apply every rule from [`../detectors/lifecycle-scripts.md`](../detectors/lifecycle-scripts.md) to the `scripts` object. Check each of these keys:
- `preinstall`
- `install`
- `postinstall`
- `prepare`
- `prepublish`
- `prepublishOnly`
- `prepack`
- `postpack`
- `dependencies` (the obscure `devDependencies` / `optionalDependencies` scripts — rare but possible)

For each match, record the rule ID, the exact script value, and the risk weight.

### Step 3 — Dependency sanity check

For each entry in `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`:

1. **IOC check**: is this package + version in `iocs/packages.json`? If yes → CRITICAL.
2. **Typosquat check**: is this package name within Levenshtein distance 2 of a top-100 npm package? If yes → HIGH warning.
   - Known typosquat targets: `express`, `react`, `lodash`, `axios`, `ethers`, `web3`, `moment`, `dayjs`, `zod`, `chalk`, `colors`, `debug`, `next`, `vue`, `svelte`, `typescript`
3. **Brand-new package check**: is this package resolved to a version published <30 days ago? (Best-effort via WebFetch to `https://registry.npmjs.org/<package>` and checking `time` field for the resolved version.) → MEDIUM signal.
4. **Single-maintainer check**: does this package have only one maintainer on the registry? → LOW signal (context-dependent).
5. **Version pinning**: is the version pinned to a specific yanked / deprecated release? → CRITICAL if matched to IOC.

### Step 4 — Metadata sanity check

Red flags in the metadata itself:
- Missing `license` (LOW — common in private packages but unusual for published libs)
- `private: true` on a package that also has `publishConfig.registry` pointing to a non-npm URL (MEDIUM — could be dependency confusion bait)
- `bin` field pointing to a script that isn't in the declared `main` tree (LOW)
- `files` field excluding standard directories while including unusual ones (LOW)
- `engines` with suspicious constraints (e.g., `"node": "<12"` to avoid modern security mitigations) (MEDIUM)

### Step 5 — Compute score and verdict

Use the scoring weights from [`../detectors/lifecycle-scripts.md`](../detectors/lifecycle-scripts.md) and the IOC weights from `modes/vet-repo.md`. Apply verdict thresholds:
- 0-9: 🟢 PROCEED
- 10-24: 🟡 CAUTION
- 25-59: 🟠 WARN
- 60+: 🔴 BLOCK

### Step 6 — Output

Produce a compact markdown report:

```markdown
# triage — {package-name} @ {version}

**Risk:** {emoji} {VERDICT}   **Score:** {N} / 100

## Findings

{list of rule matches with line/key references}

## Dependencies

- {count} direct deps
- {count} with IOC matches: {list}
- {count} with typosquat concerns: {list}
- {count} brand-new (<30d old): {list}

## Verdict

{plain-English summary and next-step recommendation}
```

Save to `data/reports/{timestamp}-triage-{package-name}.md` if the user asked for a file, otherwise print to chat.

## Tone

- Fast and terse. This mode is called when the user wants quick answers.
- Don't explain the rules unless the user asks. Cite the rule IDs so they can look them up themselves.
- If the verdict is PROCEED, say so in one line and stop. Don't pad.
- If the verdict is BLOCK, lead with the biggest finding.

## Limitations to disclose

- This mode only sees `package.json`. It cannot detect exfil patterns, obfuscation, or RCE loaders hidden in source files.
- If `triage-package-json` says PROCEED but you're still unsure, run `vet-repo` or `deep-scan` for full coverage.
- Transitive dependency risks (issues in deps-of-deps) are not checked here — use `vet-repo` with lockfile analysis for that.
