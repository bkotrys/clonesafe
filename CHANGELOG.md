# Changelog

All notable changes to clonesafe will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and clonesafe adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — pnpm + bun lockfile coverage
- D13 (non-registry resolved URL) and D14 (git+ssh dependency) now scan `pnpm-lock.yaml` (pnpm v6+ schema with `resolution: {tarball: …}`) and `bun.lock` (text format) in addition to `package-lock.json` and `yarn.lock`.
- New informational check D14b: probes `bun.lockb` (binary) via HTTP HEAD and flags presence; binary content remains unscannable so no verdict floor is raised.
- `cli/lib/github.js` now fetches `pnpm-lock.yaml` and `bun.lock` as core lockfile paths.
- `cli/lib/checks.js` D13 ports the pnpm `tarball:` regex; lockfile collection in `runAllChecks` includes the new formats.
- `detectors/lockfile-anomalies.md` LF-001/LF-002/LF-003 documented per-format with a coverage matrix (npm/yarn/pnpm/bun.lock supported; `bun.lockb` flag-only). False-positive list expanded with `codeload.github.com` (commit-pinned GitHub tarballs) and `cdn.sheetjs.com` (xlsx canonical distribution post-2023 npm exit) — both still surface as WARN by design.
- Fixed a latent `grep -c … || echo 0` pattern in the Phase 0 spec that would have double-emitted `0\n0` and broken arithmetic when run with the new lockfile loop.

### Added — Phase 1.5: New Detectors + IOC Expansion
- `detectors/git-level.md` — 7 rules (GL-001..GL-007) for `.gitattributes` smudge/clean filter RCE, submodule URL injection, path traversal, suspicious binaries, custom merge drivers
- `detectors/lockfile-anomalies.md` — 6 rules (LF-001..LF-006) for non-registry resolved URLs, `git+ssh://` deps, missing integrity hashes, IOC version cross-ref, suspicious tarball domains
- `detectors/dep-confusion.md` — 6 rules (DC-001..DC-006) for typosquats (Levenshtein distance), scope confusion, brand-new packages, IOC package exact matches
- 6 new deterministic checks in `scripts/phase0.sh` (D11-D16): gitattributes filters, gitmodules injection, lockfile non-registry URLs, lockfile git+ssh, IOC package deps, typosquat detection
- Expanded `iocs/packages.json` with 12 new entries: ua-parser-js, colors.js, faker, event-stream, flatmap-stream, chalk-next, chalk-new, debug-js, debug-sync, noblox.js-rpc, noblox.js-proxy, noblox.js-api
- Expanded `iocs/domains.json` with citationsherbe.at (ua-parser-js C2), pipedream exfil endpoint, pipedream pattern IOC
- Updated `modes/vet-repo.md` with D11-D16 checks and new detector mappings

### Added — Phase 2: Standalone Node CLI
- `npx clonesafe <url>` — zero-dependency Node.js CLI (requires Node 18+)
- `cli/index.js` — entry point with `--json`, `--quiet`, `--no-color` flags
- `cli/lib/url-parser.js` — GitHub URL parsing (full URLs, owner/repo shorthand, branch refs)
- `cli/lib/github.js` — GitHub API + raw file fetching with `GITHUB_TOKEN` support and rate limit handling
- `cli/lib/checks.js` — all D1-D16 deterministic checks ported from bash to JavaScript
- `cli/lib/detectors.js` — all 9 detector files encoded as JS objects (~70 rules with regex patterns and weights)
- `cli/lib/iocs.js` — IOC database loading and cross-reference (packages, domains, orgs, hashes via SHA-256)
- `cli/lib/scoring.js` — score computation, verdict thresholds (0-9 PROCEED, 10-24 CAUTION, 25-59 WARN, 60+ BLOCK), verdict floor
- `cli/lib/reporter.js` — formatted terminal output with ANSI colors + JSON output mode
- `cli/lib/utils.js` — Levenshtein distance, SHA-256, hook extraction, top-200 npm package list, known scopes list
- `package.json` — npm package config with `bin` field for `npx` support
- Exit code 0 for PROCEED/CAUTION, 1 for WARN/BLOCK (CI-friendly)

## [0.1.0] — 2026-04-09

### Added
- Phase 1 scaffold: Claude Code workflow, modes, detectors, IOCs, samples
- `modes/vet-repo.md` — main pre-clone scanner skill
- `modes/post-mortem.md` — incident response skill for users who already ran something bad
- `modes/triage-package-json.md`, `modes/deep-scan.md` — focused scanners
- `detectors/` — lifecycle-scripts, obfuscation, exfil-patterns, repo-metadata, recon-patterns rule catalogs
- `iocs/packages.json`, `iocs/domains.json`, `iocs/github-orgs.json` — starter IOC databases
- `samples/contagious-interview-001/` — canonical case study: anonymized writeup of the April 8, 2026 Contagious Interview attack that inspired clonesafe
- `playbooks/i-just-ran-it.md` — immediate incident response checklist
- `playbooks/forensic-scan.md`, `playbooks/rotation-checklist.md`, `playbooks/wallet-drain-procedure.md`
- README, LICENSE (MIT), CONTRIBUTING, issue templates, FUNDING

## [0.0.0] — 2026-04-08

Initial commit. clonesafe started after a real Contagious Interview take-home attack was intercepted and analyzed.
