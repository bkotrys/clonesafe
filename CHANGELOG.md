# Changelog

All notable changes to clonesafe will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and clonesafe adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-05-01

### Added — transitive + new-ecosystem detectors
- D15b: lockfile transitive IOC scan. `extractLockfileDeps()` + `checkD15Transitive()` walk `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and `bun.lock` and match every resolved package (not just direct deps) against `iocs/packages.json`. BLOCK floor on any hit.
- D21 (Ruby): `Gemfile` and `extconf.rb` shell-out / network detection. BLOCK floor. Restricted to install-time entry points — `Rakefile` and `.gemspec` are intentionally excluded because they only run on developer invocation.
- D22 (PHP): `composer.json` `post-install-cmd` / `post-update-cmd` (and other install-time hooks) shelling out to `curl`/`wget`/`sh`/`bash`/`nohup`/`eval`/`python`/`node`. BLOCK floor.
- D23: known-bad / spam-correlated TLD detector (`.zip`, `.cam`, `.icu`, `.top`, `.click`, `.buzz`, `.work`, `.gq`, `.tk`, `.ml`, `.cf`). WARN floor.

### Added — repo-history + provenance signals
- GH-FORCE-PUSH: detects force-pushes on the default branch via the GitHub Activity API (`/repos/{o}/{r}/activity?activity_type=force_push`). Tiered: 3+ events in the last 30 days = MEDIUM/+5, 8+ events = HIGH/+20.
- GH-UNSIGNED: surfaces when <20% of recent commits on the default branch are signed. Informational, weight 0.
- PROV-DOWNGRADE / PROV-NONE: opt-in npm provenance check via `--provenance`. `cli/lib/provenance.js` queries `https://registry.npmjs.org/{pkg}` for each direct dep and inspects `versions[v].dist.attestations`. PROV-DOWNGRADE (a published version had SLSA attestations and a newer one from the same publisher does not) = CRITICAL / +50 / blockAlone. PROV-NONE is informational, weight 0.

### Added — operational features
- `--diff` flag: differential scan. `cli/lib/cache.js` writes per-repo finding fingerprints (sha1 of `ruleId|file|match`) to `data/cache/{owner}__{repo}.json` (gitignored). On rescan, only new/removed findings are surfaced.
- `action.yml`: composite GitHub Action at the repo root. Runs clonesafe via `npx`, posts the verdict and JSON report to the PR step summary, and fails the job above a configurable `fail-on` threshold (default `WARN`).
- `scripts/pre-commit.sh`: pre-commit hook that re-vets any new GitHub URL added to staged lockfiles (`package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `bun.lock`). Skips quietly when neither `clonesafe` nor `npx` is on `PATH`.
- `tests/calibrate.js` (`npm run calibrate`): asserts a curated list of high-traffic public repos returns PROCEED or CAUTION. Current list of 14 (express, react, vue, svelte, angular, node, husky, puppeteer, lerna, tokio, requests, flask, rails, laravel) all pass on Node 22 + Docker.

### Hardened — sandbox
- `--sandbox` extract-in-container: `runHarnessOnTarball()` mounts the GitHub tarball into the container as raw compressed bytes only. Extraction happens inside the container's tmpfs `/work` via `tar --no-same-owner --no-same-permissions --strip-components=1`. The host filesystem never sees decompressed source.
- `scripts/sandbox/Dockerfile`: `FROM` line pinned to a sha256 digest.
- `install-and-trace.sh`: openat(O_WRONLY|O_CREAT) outside the install allowlist (`/work`, `/tmp`, `/trace`, `/proc/self`, `~/.npm/`, `~/.cache/`) is now reported as `fsEscapeWrites` and classifies as MALICIOUS in `classifyReport()`.

### Changed
- Bumped to **0.3.0**.
- Typosquat reconciliation: DC-001 (`detectors.js`) and D16 (`checks.js`) now share a single `findTyposquats()` helper in `utils.js`. Variant-suffix and hand-curated allowlists (`TYPOSQUAT_ALLOWLIST`, `SCOPE_ALLOWLIST`) live in `utils.js`; DC-001 carries `cap: 30` so a wide-monorepo dep tree can't dominate the score on its own.
- DC-004 (scope confusion) Levenshtein distance threshold tightened from 2 to 1, plus the shared `SCOPE_ALLOWLIST` is consulted before flagging.
- D13 and LF-001 now skip `codeload.github.com/{owner}/...` URLs when the scanned repo's owner matches — a legit monorepo-internal commit pin should not surface as a non-registry-URL anomaly.
- `cli/lib/github.js` `resolveToken()`: if `GITHUB_TOKEN` is unset, runs `gh auth token` once and uses that, then caches it for the rest of the process.

## [0.2.0] — 2026-05-01

### Added — multi-ecosystem detectors
- D17 (`setup.py` shell-out / network at import time): BLOCK floor.
- D18 (`pyproject.toml` non-standard build backend): WARN floor; allowlists setuptools/hatchling/poetry-core/flit_core/pdm/maturin/scikit-build-core/mesonpy.
- D19 (`build.rs` with `Command::new` / `reqwest::` / `ureq::` / `tokio::net` / `std::net`): BLOCK floor.
- D20 (Go `//go:generate` shelling out to sh/bash/curl/wget/python/node/eval): WARN floor.
- `cli/lib/github.js` now fetches `setup.py`, `pyproject.toml`, `build.rs`, `go.mod`, plus common Go entry files (`main.go`, `gen.go`, `tools.go`, `generate.go`).

### Added — test suite + CI
- `tests/run.js`: zero-dependency `node:test` runner over 11 synthetic fixtures covering every D-code that has a verdict-floor effect, plus two clean baselines (npm + multi-ecosystem). All 12 cases pass on Node 18/20/22.
- `npm test` script (added to `package.json`).
- `.github/workflows/ci.yml`: matrix syntax check + static suite on Node 18/20/22; separate sandbox job that builds the harness image and runs `npm run test:docker`.

### Added — Docker sandbox install harness
- `scripts/sandbox/Dockerfile`: minimal `node:22-alpine` image with `strace`, non-root user, separated `/work` + `/trace` mountpoints.
- `scripts/sandbox/install-and-trace.sh`: runs `npm install --ignore-scripts=false` under `strace -f -e trace=network,process,openat`; emits a JSON anomaly report (DNS attempts, connect/sendto, shell/curl spawns, `~/.ssh` reads, `/proc/<pid>/environ` reads).
- `cli/lib/sandbox.js`: spawns the container with `--network=none --cap-drop=ALL --read-only --pids-limit=256 --memory=512m --security-opt=no-new-privileges`, parses the report, classifies as CLEAN / SUSPICIOUS / MALICIOUS.
- `tests/sandbox.js`: gracefully skips when Docker is unavailable; otherwise asserts `clean-npm` classifies CLEAN and `lifecycle-backgrounding` produces process-spawn anomalies.
- `--sandbox` flag on `clonesafe`: opt-in; downloads tarball via GitHub API, runs the harness, folds classification into the verdict (MALICIOUS → BLOCK; SUSPICIOUS → at least CAUTION; the existing static floor cannot be downgraded).
- `modes/sandbox-install.md`: explains threat model, why `--network=none`, when to use vs not.

### Changed — README/CHANGELOG implementation gap
- Bumped to **0.2.0** (Phase 1.5 + Phase 2 + pnpm/bun lockfile coverage).
- README Prerequisites now distinguishes between standalone CLI (Node 18+, optionally Docker) and the Claude Code workflow (python3/curl/grep).
- README "What it detects" lockfile bullet now scopes to npm/yarn/pnpm/bun.
- Verified-test-results table extends past D10 and adds n8n-io/n8n as a real-world WARN case.
- Roadmap adds Phase 2.5 (this release) and consolidates browser extension as Phase 4.
- FAQ "pip/cargo/go" answer updated from "Phase 2+ will add" to "Phase 2.5 added (D17–D20)".
- LF-001 detector downgraded from CRITICAL/blockAlone to HIGH so it agrees with D13's WARN floor (previously LF-001 = +50/BLOCK while D13 = WARN; same finding pulled in two directions).
- LF-001 regex now covers all four lockfile formats; `appliesTo: 'lockfile'` in `runDetectors` now iterates `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` (was only npm + yarn).

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
