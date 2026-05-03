# clonesafe roadmap

Living document. Last updated 2026-05-03.

This roadmap is grounded in research across four streams: a current-capability inventory of v0.3.0, the 2026 competitive landscape (Socket, Snyk, Aikido, Phylum, GuardDog, OpenSSF Scorecard, OSV, GitHub native, Semgrep SSC), the 2024-2026 threat landscape (Shai-Hulud, tj-actions, axios npm, polyfill, xz, DPRK Contagious Interview, slopsquatting, .pth wheels, audio steganography), and developer-experience research on what makes security tooling adopted vs. uninstalled.

## Strategic position

clonesafe's defensible wedge is **pre-clone, repo-level triage**. No major commercial competitor scans before `git clone` hits disk. GitHub's March 2026 launch of Dependabot malware alerts (npm) closes the *post-install / known-bad-on-disk* gap, which strengthens — not weakens — clonesafe's wedge: the rest of the ecosystem now handles "alert me when something I already use turned bad," leaving the **acquisition-time threat model** to clonesafe.

Two adjacent wedges are also uncontested and deserve roadmap weight:
1. **Pre-install gate**: 2026 attacks (Shai-Hulud worm, axios compromise, Trivy/LiteLLM/Telnyx wave) repeatedly proved that the install moment is the highest-value interception point. A `clonesafe install` shim that gates `npm/pnpm/yarn/pip install` against the IOC DB before postinstall scripts run is high leverage.
2. **AI-assistant integration**: Cursor / Claude Code / Aider routinely suggest package names. A vetting hook at suggest-time prevents slopsquatted and DPRK-family names from ever reaching `package.json`.

Everything below is sized against this positioning. Detection breadth catches up to Socket/Aikido; DX catches up to gitleaks/trivy; trust catches up to Sigstore-era expectations.

---

## v0.4 — High-ROI detection breadth (next minor)

The v0.3.0 inventory shows clonesafe is strong on lifecycle/obfuscation/exfil/git-level static rules and weak on three things: known-bad lookup, repo-health signals, and ecosystem coverage outside npm. v0.4 closes ~70% of the coverage gap with paid tools at low engineering cost.

### Detection
- **OSV.dev + OpenSSF Malicious Packages lookup** — query OSV by ecosystem+package+version, surface GHSA-MAL IDs as findings. Closes the "known-bad" gap clonesafe currently re-discovers from scratch. Free API, stable IDs.
- **OpenSSF Scorecard-style Phase 0 probes** — `Maintained`, `Code-Review`, `Branch-Protection`, `Signed-Releases`, `Dangerous-Workflow`, `Pinned-Dependencies`. Cheap, deterministic, no LLM cost. DPRK lure repos consistently score very low here.
- **Package age / cool-down gate** — configurable `--min-age=48h` flag; warn on any direct dep published within window. Aikido's default; pure heuristic; defangs ~80% of fresh-publish attacks at zero detection cost.
- **Starjacking detector** — parse `package.json` `repository.url`, resolve via API, flag mismatched name / unrelated owner / repo uniqueness across registry.
- **Recruiter-lure repo heuristic (DPRK)** — combo signal: repo age <30d + single contributor + README mentions "coding assignment"/"take-home"/"interview" + recent npm deps + Google-Doc-instruction reference. Hard-block when triggered together.
- **Hidden-Unicode / bidi / homoglyph scanner** — Trojan-Source class plus DPRK obfuscation tactic. Already partly covered by PI-008; promote to standalone detector across all source files, not just READMEs.
- **README / docs prompt-injection scanner** — extend PI-001..004 coverage to all docs, CONTRIBUTING, issues, `.cursor/mcp.json`, `.cursorrules`. Critical for AI-assisted-coding users.
- **Action SHA-pinning auditor** — parse `.github/workflows/*.yml`; flag non-SHA refs for non-`actions/*` orgs; check against a new `iocs/actions-bad-shas.json` (tj-actions/changed-files, reviewdog/action-setup, etc.).
- **Secrets scan over fetched tarball** — light gitleaks-style regex+entropy pass. A repo-level scanner without a secrets pass looks incomplete to anyone who has used GitGuardian.

### Ecosystem completion
- **Python**: `.pth` enumeration in wheels (litellm-class), `setup.py` exec scan, `pyproject.toml` build-system audit.
- **Rust**: `build.rs` content scan (network/process exec calls), unpinned dep range warnings.
- **Go**: top-level `func init()` grep across module zip, module-proxy-vs-tag SHA mismatch (boltdb-class).
- **VS Code repos**: `.vscode/tasks.json` with `runOn: "folderOpen"` auto-execute hooks (DPRK TTP).
- **Container**: Dockerfile `FROM` mutable tag warnings, `curl | sh` patterns in `RUN`.

### IOC expansion
- `iocs/dprk-families.json` — known DPRK package name patterns (HexEval loader, BeaverTail/InvisibleFerret/OtterCookie indicators).
- `iocs/worm-signatures.json` — Shai-Hulud/Sha1-Hulud strings, `bundle.js` postinstall pattern, `webhook.site`/`*.workers.dev` exfil endpoints.
- `iocs/actions-bad-shas.json` — known-compromised GitHub Action SHAs.
- IOC files documented as **OSV-format-exportable** so others can consume.

---

## v0.5 — DX, integration, and rule-pack maturity

v0.4 buys detection breadth. v0.5 makes findings *actionable* and gets clonesafe out of the Action-log void.

### Reporting & integration
- **SARIF 2.1.0 output** (`--sarif`) with stable `partialFingerprints` per finding so suppression survives across runs. Required for GitHub Security tab; without it, findings live in CI logs.
- **CycloneDX 1.6 + SPDX 2.3 SBOM export** — both formats; Syft-style "one scan, both files" pattern. Procurement and compliance flows accept either.
- **`.clonesafe-baseline.json` + `.clonesafe-ignore`** — baseline grandfathers existing findings; ignore file requires `reason` + `expires` fields (force re-evaluation, not permanent ignores). Essential for adoption in mature codebases.
- **Plain-English finding explanations** — every detector gets a one-sentence "why this is exploitable," a `file:line` deep link, and a concrete remediation (specific version pin, removal command, alternate package). The biggest single failure mode of competitors is "pattern matched, no actionable guidance."
- **CI templates** — drop-in YAML for GitLab CI, Bitbucket Pipelines, CircleCI, Jenkins. Not novel; just removes friction.

### Rule packs
- **GuardDog rule import** (`--rules guarddog`) — DataDog GuardDog's Semgrep+YARA rules are MIT-licensed, cover npm/PyPI/Go/RubyGems/GitHub Actions/VS Code, and have the best F1 score (0.93) of any open static tool. Wrapping clonesafe's detectors with this baseline 5–10x's coverage with one integration.
- **YARA rule support** for binary blobs and steganography heuristics (Telnyx WAV-class).
- **User-extensible rule format** — drop-in TOML/YAML for custom org rules (gitleaks pattern), instead of forcing fork-and-PR.

### Detection deepening
- **Version-diff signals** — "this release added a `postinstall`/network call/install-time fetch that the previous version didn't." Computable from registry metadata alone; one of Socket's marquee differentiators.
- **Maintainer-takeover heuristics** — publisher-ID delta across versions, publish-cadence anomaly, provenance regression (had OIDC, now using token), publish hour vs. prior history.
- **Slopsquatting feed** — pull from Lasso/Snyk/Socket lists and public LLM-hallucination corpora; cross-reference low-age + low-DL + name-on-corpus.
- **npm/PyPI/Go provenance & SLSA attestation verification** — promote the existing `--provenance` flag from "is provenance present" to "does the signed builder identity match the source repo and produce a reproducible build."

---

## v1.0 — Distribution, trust, and governance

v0.4/v0.5 build the product. v1.0 is when clonesafe earns the right to be installed in CI on someone else's repo.

### Distribution
- **Single static binary** for macOS / Linux / Windows. Today, `npx --package=clonesafe@0.3.0` drags in Node.js — itself a supply-chain liability for a security tool. Options: Bun `--compile`, Deno compile, or rewriting the hot path in Go/Rust. The Node dependency must end before v1.0 ships.
- **Homebrew formula** (`brew install clonesafe`) — table stakes for macOS devs.
- **Docker image** (`ghcr.io/.../clonesafe:1.0.0`, distroless, multi-arch).
- **Reproducible builds + Sigstore-signed releases** — clonesafe scanning malicious packages while shipping unsigned releases is a credibility problem.
- `apt`, `scoop`, `winget` packages.

### Trust & governance
- **Public IOC revocation log** — every IOC retraction, with reason and timestamp. The trust signal that separates community feeds from black-box ones.
- **Community IOC submission flow** — PR-based, with required evidence fields (sample hash, distribution channel, observed behavior, attribution).
- **Public detector-rule discussion** — gitleaks-style open ruleset evolution; rules live in a single directory with PR review.
- **`SECURITY.md` + responsible disclosure policy** — non-negotiable for a tool with CI repo-read access.
- **Published FP / FN benchmarks** — quarterly run against a public corpus; results checked in, transparently maintained.
- **Public IOC feed export** in OSV format so downstream tools (Semgrep SSC, OSV-Scanner) can consume clonesafe findings as a contributing member of the ecosystem, not just a consumer.

### Performance budget (enforced by CI)
- Pre-commit hook: <500ms total, <200ms target.
- Pre-clone scan: <5s.
- CI incremental: <30s; full: <2min.
- Differential / cached scans first-class (already exists via `--diff`; needs to become the default in CI mode).
- Embedded IOC DB for offline / air-gapped operation; `--offline` flag skips API enrichment.

---

## v2.0+ — Adjacent wedges

Speculative; sequenced after v1.0 ships and adoption signal is clear.

- **`clonesafe install` shim** — wrap `npm`/`pnpm`/`yarn`/`pip`/`uv`/`poetry`/`cargo`/`go get` to gate against IOC DB before postinstall scripts run. Aikido Safe Chain is the precedent; this is the highest-leverage 2026 surface given the worm wave. Probably the single most valuable post-v1.0 feature.
- **MCP server for AI assistants** — Cursor / Claude Code / Aider call `clonesafe vet-package <name>` before writing into a manifest. Uncontested space. Could ship as a Claude Code plugin natively.
- **VS Code / JetBrains / Zed extensions** — inline annotations on `package.json` and lockfiles, Quick Fix actions for known-bad version pins, hover cards with finding details. Catching up to Snyk/GitGuardian/Socket on the IDE surface.
- **Browser extension on github.com** — annotate "Code → Download ZIP" / "Use this template" / repo headers with cached verdicts from the IOC DB. Low complexity, viral demo potential, drives top-of-funnel awareness.
- **Reachability / call-graph filtering** — Endor Labs-style pruning of WARN findings to those actually invoked at runtime. Lower priority for pre-clone (you can't reach what you haven't cloned), but valuable for `/deep-scan`.
- **Cross-platform sandbox** — current strace harness is Linux-only. Phylum's MIT-licensed Birdcage offers cross-platform FS+network deny; could be vendored for macOS/Windows parity.
- **Hosted scan-share URLs** — `clonesafe share` produces a signed URL on a thin SaaS so report links can be DM'd in code review. Pure CLI is fine for power users; shareable URLs multiply organic spread.
- **Slack/Discord bot** — only on BLOCK, never CAUTION/WARN. Severity-filtered by default; uniformly noisy bots get muted within a week.

---

## Crosscutting concerns

These run alongside every release, not as a single milestone.

- **Calibration discipline**: every new detector lands with at least one positive fixture, two negative fixtures (false-positive guards), and an entry in `tests/calibrate.js`. The April 2026 calibration round (rails/rails, GH-FORCE-PUSH false positives) is the model.
- **Detector lineage**: each rule documents its source (incident, threat report, academic paper, GuardDog import) and last-validated date. Rules without a recent validation get pruned or downgraded.
- **Threat-feed subscriptions**: Socket, Phylum, Checkmarx Zero, ReversingLabs, JFrog, Snyk Vuln DB, Sonatype OSSindex, Datadog Security Labs, Microsoft Threat Intel, Unit 42, Mandiant, StepSecurity advisories, ESET DeceptiveDevelopment tracking, Kaspersky Securelist. IOC harvest from these is a recurring chore, not a one-shot project.
- **AI-assistant safety**: clonesafe's own LLM-assisted Phase A is itself a prompt-injection target. Maintain and test the README-injection defense regularly; assume every fetched README is hostile.

---

## Out of scope (explicitly)

- **CVE / vulnerability database matching** beyond surfacing GHSA-MAL IDs. clonesafe is a malicious-package detector, not an SCA tool. Snyk/OSV-Scanner already do this well; competing on it dilutes the wedge.
- **Runtime EDR / endpoint protection.** CrowdStrike and SentinelOne own this surface; clonesafe is prevention, not response.
- **Enterprise ASPM dashboards** (Apiiro / Legit / Arnica territory). Stay CLI-first; integrate via SARIF/SBOM into whatever ASPM the org already runs.
- **Generic SAST.** Semgrep / CodeQL territory. clonesafe's static analysis exists to catch supply-chain attacks specifically.

---

## Sequencing summary

| Track | v0.4 | v0.5 | v1.0 | v2.0+ |
|---|---|---|---|---|
| Detection | OSV lookup, Scorecard probes, age gate, starjacking, recruiter-lure, hidden-Unicode, prompt-injection, action SHA, secrets scan, .pth/build.rs/init/tasks.json, container | GuardDog rules, YARA, version-diff, maintainer takeover, slopsquatting, attestation verification | FP/FN benchmark publication | Reachability, cross-platform sandbox |
| Integration | — | SARIF, CycloneDX, SPDX, baseline/ignore, CI templates | Single binary, Homebrew, Docker, signed releases | npm/pip shim, MCP server, IDE extensions, browser extension |
| Trust | DPRK + worm + bad-action-SHA IOC files, OSV-format export | User-extensible rules | Public revocation log, community IOC PRs, SECURITY.md, public feed | Hosted share URLs |
| Performance | — | Diff-by-default in CI mode | <500ms pre-commit, <5s pre-clone, offline mode | — |

The v0.4 list alone closes roughly two-thirds of the parity gap with Socket and Aikido at low engineering cost, while preserving the slash-command CLI shape that makes clonesafe distinct.
