# Detectors

This directory contains the **rule catalog** clonesafe applies during `vet-repo`. Each file groups related rules by attack family.

## Current detectors

| File | Family | What it catches |
|---|---|---|
| [`lifecycle-scripts.md`](lifecycle-scripts.md) | install-time execution | Malicious `preinstall`/`postinstall`/`prepare` hooks that launch servers, backgrounding daemons, make network calls, or use base64-encoded commands |
| [`obfuscation.md`](obfuscation.md) | code opacity | javascript-obfuscator output, string-array shuffles, base64+eval chains, dynamic `new Function`, hex-encoded identifiers |
| [`exfil-patterns.md`](exfil-patterns.md) | data exfiltration | `axios.post(process.env)`, SSH key reads, browser/wallet profile paths, decoded exfil URLs, Discord/Telegram webhooks |
| [`recon-patterns.md`](recon-patterns.md) | reconnaissance | OS branching for credential paths, CI detection, anti-debug, `.env` scanning, docker/k8s config reads |
| [`repo-metadata.md`](repo-metadata.md) | trust signals | Repo age, account age, contributor count, fork manipulation, commit history shape, license presence |
| [`prompt-injection.md`](prompt-injection.md) | adversarial scanner manipulation | Text that tries to manipulate clonesafe itself — instruction overrides, role impersonation, trust forgery, output directives, Trojan Source / GlassWorm invisible Unicode |
| [`git-level.md`](git-level.md) | git config exploitation | `.gitattributes` smudge/clean filter RCE, `.gitmodules` submodule URL injection, path traversal, suspicious binary files in repo tree |
| [`lockfile-anomalies.md`](lockfile-anomalies.md) | dependency integrity | Non-registry resolved URLs in lockfiles, `git+ssh://` dependencies, missing integrity hashes, IOC version cross-reference |
| [`dep-confusion.md`](dep-confusion.md) | dependency trust | Typosquats of popular packages (Levenshtein distance), scope confusion, brand-new packages, IOC package exact matches |

## Rule format

Every rule has:

- **ID** (e.g. `LS-001`) — unique within its detector file
- **Risk** — 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW
- **Matches** — concrete regex/AST pattern Claude applies
- **Why suspicious** — one-paragraph rationale
- **Real-world example** — known campaign or package
- **False positives** — legit code that might trip the rule
- **Weight** — numeric score contribution

## How to add a rule

1. Pick the right detector file (or create a new one)
2. Assign the next ID in sequence
3. Write the rule using the format above
4. Add the weight to the scoring summary table at the bottom of the file
5. Add at least one sample to `samples/` that triggers the rule
6. Open a PR with both changes

## Planned detectors

- `python.md` — Python-specific: `setup.py` execution, `install_requires`, `entry_points`
- `rust.md` — Rust-specific: `build.rs`, `[build-dependencies]`
- `go.md` — Go-specific: `go generate` directives, unusual imports
