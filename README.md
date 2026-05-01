# clonesafe

> **Vet a GitHub repo *before* you `git clone` it.**
> Catches malicious `prepare`/`postinstall` hooks, obfuscated exfil, known-bad dependencies, and suspicious repo metadata — all without ever touching your disk.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/built%20with-Claude%20Code-8A2BE2)](https://claude.com/claude-code)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#zero-dependencies)

---

## Why this exists

A developer receives a take-home coding challenge from what looks like a legitimate recruiter. The repo is professional — clean structure, realistic dependencies, a README with screenshots, a small product demo. Nothing unusual.

They run `npm install`. Within minutes, a malicious background Node process exfiltrates their environment variables and starts stage-2 remote code execution against a serverless endpoint. The attack is caught, the process is killed, and hours of incident response follow.

This is not a one-off incident. It's a **documented, multi-year, state-sponsored campaign** tracked publicly as:
- [**Contagious Interview**](https://unit42.paloaltonetworks.com/) (Unit 42 / Palo Alto Networks)
- [**DEV#POPPER**](https://www.securonix.com/blog/) (Securonix)
- [**DeceptiveDevelopment**](https://www.welivesecurity.com/) (ESET)

Thousands of developers are targeted every month — especially in Web3, crypto, AI, and DeFi. The repos look real. The recruiters look real. The only thing that stops you is scanning the code **before** you run it.

**No tool existed to do that. So we built one.**

📖 **Full technical analysis:** [`samples/contagious-interview-001/`](samples/contagious-interview-001/)
📖 **If you've already been hit:** [`playbooks/i-just-ran-it.md`](playbooks/i-just-ran-it.md)

---

## Quick start

clonesafe is a [Claude Code](https://claude.com/claude-code) project.

### Prerequisites

clonesafe ships in two flavors. Pick whichever fits your workflow:

**Standalone CLI (`npx clonesafe`)** — zero-dependency Node.js CLI
- **Node.js ≥ 18** — that's it. No `npm install`, no native deps.
- Optional: **Docker** — only required for `--sandbox` mode (opt-in dynamic install analysis)
- Optional: **GITHUB_TOKEN** env var to lift the GitHub API rate limit from 60 to 5,000/hr

**Claude Code workflow** — richer LLM-assisted analysis via `/vet-repo`
- **[Claude Code](https://claude.com/claude-code)** — the runtime that executes clonesafe's skill files
- **python3**, **curl**, **grep** — used by `scripts/phase0.sh` for deterministic checks (pre-installed on macOS/Linux)
- Optional: **jq** — if installed, some Phase 0 steps run faster

### Install and run

```bash
git clone https://github.com/bkotrys/clonesafe.git
cd clonesafe
claude
```

Then in Claude Code:

```
vet this repo: https://github.com/example-org/example-repo
```

Claude reads the `modes/vet-repo.md` skill and runs the full scan using only the GitHub API and raw file fetches — **no `git clone`, no `npm install`, no code execution on your machine**.

You get a report like this:

```
╭─ clonesafe verdict ──────────────────────────────────────╮
│  Repo:     [REDACTED-ORG]/[REDACTED-REPO]                │
│  Risk:     🔴 BLOCK                                      │
│  Score:    433 / 100                                     │
│                                                          │
│  🚨 CRITICAL                                             │
│  • package.json:10 — `prepare` hook launches `node       │
│    server` in background via nohup (mixed Win/Unix).     │
│    Signature: commodity crypto-stealer, npm supply.      │
│  • routes/api/auth.js:4 — base64-encoded external URL    │
│    decoded at runtime + axios.post(url, process.env).    │
│  • routes/api/auth.js:14 — `new Function("require",      │
│    code)(require)` — remote code execution vector.       │
│                                                          │
│  🟠 STRONG WARNING                                       │
│  • Org created 11 days before you cloned it.             │
│  • Repo has 0 stars, 1 commit, 1 contributor.            │
│                                                          │
│  Matches 2 IOCs in the clonesafe database:               │
│  - exfil endpoint pattern: *-six.vercel.app              │
│  - prepare-hook signature: start /b ... || nohup ... &   │
│                                                          │
│  Proceed with clone?   [N]o / [y]es, I know what I'm     │
│  doing / [s]how detail                                   │
╰──────────────────────────────────────────────────────────╯
```

If you proceed, clonesafe performs the actual `git clone` into a path you choose. If you don't, nothing touches your disk.

### Standalone CLI (no Claude Code needed)

```bash
npx clonesafe https://github.com/example-org/example-repo
```

Or install globally:

```bash
npm install -g clonesafe
clonesafe https://github.com/example-org/example-repo
```

Shorthand:

```bash
clonesafe owner/repo
```

Options:
- `--json` — structured JSON output (pipe to `jq` or parse programmatically)
- `--quiet` — no output, exit code only (0 = safe, 1 = block/warn)
- `--no-color` — disable ANSI colors
- `--sandbox` — opt-in: download the tarball, extract it inside a locked-down Docker container, run `npm install` under `strace`, fold runtime anomalies into the verdict. Requires Docker.
- `--provenance` — query the npm registry for each direct dep and flag publisher-token-hijack signals (a previously-attested package whose newer version from the same publisher dropped attestations).
- `--diff` — differential scan: cache finding fingerprints in `data/cache/` and surface only new/removed findings on rescan.
- `GITHUB_TOKEN` env var — increases GitHub API rate limit from 60 to 5,000 requests/hour. If unset, clonesafe falls back to `gh auth token` once per run.

The CLI runs the same D1-D23 deterministic checks and all 70+ detector rules as the Claude Code workflow, but without the LLM-assisted Phase A reasoning. It's faster and fully deterministic — ideal for CI pipelines, pre-commit hooks, and automated scanning.

### GitHub Action

`action.yml` ships at the repo root as a composite action. Drop it into a workflow:

```yaml
- uses: bkotrys/clonesafe@v0.3.0
  with:
    url: ${{ github.event.pull_request.head.repo.full_name }}@${{ github.event.pull_request.head.sha }}
    fail-on: WARN          # PROCEED | CAUTION | WARN | BLOCK
    sandbox: 'false'       # set 'true' to also run the install harness
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

The action posts the verdict and JSON report to the PR step summary and fails the job when the verdict meets or exceeds `fail-on`. With no `url` input on a `pull_request` event it scans the PR head repo at the head SHA. A complementary `scripts/pre-commit.sh` re-vets any new GitHub URL added to staged lockfiles before the commit lands.

---

## What it detects

### 🔴 Hard fails (any one → BLOCK)
- **Lifecycle script abuse**: `prepare`/`postinstall`/`preinstall`/`install` scripts that launch servers, background-daemonize (`nohup`, `&`, `start /b`), mix Windows/Unix syntax, or make network calls.
- **Base64 + dynamic execution**: `Buffer.from(X, 'base64').toString()` piped into `new Function(...)` or `eval(...)`.
- **Environment exfiltration**: `axios.post` / `fetch` / `got` with `process.env` as the body.
- **Known-bad dependencies — direct AND transitive**: packages matching the clonesafe IOC database, whether they appear in `package.json` directly (D15) or buried inside `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `bun.lock` (D15b).
- **Known-bad GitHub orgs**: orgs tagged in `iocs/github-orgs.json` as campaign infrastructure.
- **`.gitattributes` filter RCE**: smudge/clean filters that execute commands on `git checkout` (CVE-2024-32002).
- **Submodule injection**: `.gitmodules` with `ext::`, `file://`, shell metacharacters, or path traversal.
- **Lockfile manipulation**: non-registry resolved URLs, `git+ssh://` deps redirecting installs to attacker tarballs. Covers `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and `bun.lock` (text). Binary `bun.lockb` is flagged on presence (D14b) but cannot be grepped.
- **Multi-ecosystem install-time shell-out**: Python `setup.py` / `pyproject.toml` (D17/D18), Rust `build.rs` (D19), Ruby `Gemfile` and `extconf.rb` (D21), PHP `composer.json` install hooks (D22).
- **npm provenance downgrade** (`--provenance`): a published version had SLSA attestations and a newer one from the same publisher does not — a publisher-token-hijack signal (PROV-DOWNGRADE).

### 🟠 Strong warnings (raise score)
- **Obfuscation signatures**: javascript-obfuscator output (`_0x[a-f0-9]+` names), reversed/shuffled string arrays, hex-encoded identifiers.
- **OS-specific exfil paths**: references to `~/.ssh`, `~/Library/Application Support/Google/Chrome`, wallet extension IDs, MetaMask/Phantom paths, Local Extension Settings.
- **Dynamic execution primitives**: `new Function`, `eval`, `vm.runInNewContext`, `child_process.exec` with non-literal strings.
- **Repo metadata red flags**: org/repo created <30 days, 0-1 contributors, single squashed commit, missing LICENSE/.gitignore, suspiciously thin history vs. claimed product maturity.
- **Repo-history anomalies**: high force-push rate on the default branch via the GitHub Activity API (GH-FORCE-PUSH; tiered MEDIUM at 3+ events / HIGH at 8+ events in the last 30 days).
- **Known-bad TLDs**: URLs hosted under `.zip` / `.cam` / `.icu` / `.top` / `.click` / `.buzz` / `.work` / `.gq` / `.tk` / `.ml` / `.cf` (D23).
- **Go `//go:generate` shelling out** to `sh`/`bash`/`curl`/`wget`/`python`/`node`/`eval` (D20).

### 🟡 Soft signals (scored, surfaced in report)
- Lockfile anomalies (non-registry URLs, version pins to yanked releases)
- README claims inconsistent with actual repo state
- Mixed package managers
- Dependencies with versions resolved to brand-new packages (<30 days old)
- npm provenance gap on direct deps (PROV-NONE — informational, weight 0)
- Low signed-commit ratio on the default branch (GH-UNSIGNED — informational)

**Full rule catalog:** [`detectors/`](detectors/)

---

## How it works (no magic)

clonesafe never executes the code it's analyzing by default. The static path uses only:

1. **GitHub REST API** — for repo metadata, org age, contributor count, file listing, and force-push activity
2. **`raw.githubusercontent.com`** — for fetching specific files (package.json, lockfiles, entry points, suspicious paths)
3. **Static pattern matching** — regex, substring, and AST shape rules from [`detectors/`](detectors/)
4. **IOC database lookup** — [`iocs/`](iocs/) JSON files for known-bad packages/domains/orgs
5. **Claude Code's reasoning** — to chain the signals into a coherent verdict, explain the findings in English, and suggest next steps

Three opt-in flags extend that surface:

- **`--provenance`** — additionally calls `https://registry.npmjs.org/{pkg}` for each direct dep to check for SLSA attestation downgrades.
- **`--sandbox`** — downloads the GitHub tarball as raw compressed bytes, mounts it into a Docker container, and runs `npm install` under `strace` with `--network=none` and full cap-drop. Extraction happens inside the container; the host never sees decompressed source. The static verdict floor cannot be downgraded by sandbox results.
- **`--diff`** — caches per-repo finding fingerprints in `data/cache/` (gitignored) and surfaces only new/removed findings on rescan.

**No telemetry. No account.** Default-mode network egress is limited to `api.github.com` and `raw.githubusercontent.com`. `--provenance` adds `registry.npmjs.org`; `--sandbox` requires Docker.

Everything runs locally via Claude Code. Your scan history is stored in `data/tracker.tsv` and `data/reports/` — both gitignored.

## Zero dependencies

<a name="zero-dependencies"></a>

clonesafe has **no package.json**. No `npm install`. No `node_modules`. No supply chain.

The entire tool is markdown skill files + JSON data + one shell script. The runtime is Claude Code (which you already have) + `python3`, `curl`, and `grep` (which your OS already has).

```
Total executable code: scripts/phase0.sh (bash) + cli/ (Node.js)
Total dependencies:    0
Total npm packages:    0
Install command:       git clone && cd && claude   (or: npx clonesafe <url>)
```

This is a deliberate architectural choice. A security tool with a dependency tree is a security tool with an attack surface. clonesafe has neither.

---

## What makes this different

| | clonesafe | npm audit | Snyk / Socket.dev | Docker sandbox |
|---|---|---|---|---|
| **When it runs** | Before clone | After install | After install | After clone |
| **What it scans** | Any GitHub repo | Published npm packages | Published packages | Any repo |
| **Catches custom repos** | Yes | No | No | Yes |
| **Catches lifecycle hooks** | Yes (deterministic) | No | Partially | Yes (behavioral) |
| **Catches prompt injection** | Yes | N/A | N/A | N/A |
| **Requires install** | No | Yes (npm) | Yes (CLI + account) | Yes (Docker) |
| **Requires network** | GitHub API only | npm registry | Vendor API | Full network |
| **Code execution** | Never | During install | During install | In sandbox |
| **Dependencies** | 0 | npm ecosystem | Vendor SDK | Docker + images |
| **Cost** | Free | Free | Freemium | Free |
| **LLM-assisted analysis** | Yes (Phase A) | No | Some | No |
| **Deterministic checks** | Yes (Phase 0) | Yes | Yes | Yes |

**clonesafe is the only tool that scans arbitrary repos before clone, with zero dependencies, zero code execution, and deterministic checks that can't be prompt-injected.**

---

## Verified test results

Phase 0 deterministic checks have been tested against:

| Repo | Type | Expected | D-checks | Floor | Result |
|---|---|---|---|---|---|
| `expressjs/express` | Known safe, popular | All zeros | All 0 | NONE | ✅ |
| `facebook/react` | Known safe, popular | All zeros | All 0 | NONE | ✅ |
| `typicode/husky` | Legit lifecycle hooks | All zeros | All 0 | NONE | ✅ no FP |
| `puppeteer/puppeteer` | Legit postinstall | All zeros | All 0 | NONE | ✅ no FP |
| `tokio-rs/tokio` | Rust (no npm) | D19 may fire on `build.rs` | depends | varies | ✅ graceful |
| `n8n-io/n8n` | High-profile pnpm monorepo | D13 fires on private tarballs | D13=2 | WARN | ✅ |
| Contagious Interview sample | Real attack (defanged) | D1,D2,D3,D5,D6,D7 fire | 6 hits | **BLOCK** | ✅ |
| Prompt injection bait | Synthetic PI test | D8 fires | D8=12 | **BLOCK** | ✅ |
| Nonexistent repo | Edge case | No files | All 0 | NONE | ✅ graceful |

The full set of deterministic checks is now **D1–D23** (lifecycle abuse, base64+exec, env exfil, IOC domains, PI, hidden Unicode, sensitive paths, gitattributes RCE, gitmodules injection, lockfile anomalies, direct + transitive IOC packages, typosquats, Python `setup.py` / `pyproject.toml`, Rust `build.rs`, Go `//go:generate`, Ruby `Gemfile`/`extconf.rb`, PHP `composer.json` install hooks, known-bad TLDs). See [`tests/`](tests/) for the synthetic-fixture suite and [`tests/calibrate.js`](tests/calibrate.js) for the false-positive baseline (14 high-traffic public repos must return PROCEED or CAUTION).

---

## Prompt injection resistance

clonesafe reads attacker-controlled content — so attackers will try to manipulate it. Our defense:

```
Phase 0 (grep/python3)  →  ground-truth numbers  →  VERDICT FLOOR (deterministic, unjailable)
Phase A (Claude)         →  rich findings         →  SCORE (LLM-assisted, best-effort)
Phase B (Claude)         →  report                →  OUTPUT (cannot lower verdict below floor)
```

**Key insight:** Phase 0 runs real shell commands (`grep`, `python3`) before Claude reads any content. These produce numbers Claude reports but **cannot alter** — `grep` doesn't hallucinate. If `grep` finds `nohup` in a `prepare` hook, the verdict is BLOCK before the LLM even starts.

On top of Phase 0:
- **8 prompt-injection detector rules** (PI-001..PI-008) — injection attempts become detection signals that *increase* the BLOCK score
- **Verdict floor** — any PI-001..PI-004 match hardcodes BLOCK regardless of score
- **Mandatory human confirmation** — default is always `[N] No`

**Honest limitation:** no LLM-based tool can guarantee 100% PI resistance. Phase 0's deterministic checks are fully resistant for codified patterns; the LLM layer is best-effort. We document known limitations and update rules as new techniques emerge.

**Full threat model, known evasion techniques, and responsible disclosure:** [`SECURITY.md`](SECURITY.md)

---

## Use cases

- **Take-home interview challenges** — the exact attack clonesafe was built to stop
- **Any repo a stranger sent you** on Discord/Telegram/LinkedIn/email
- **Unfamiliar dependencies** — vet a transitive dep before adding it
- **Your own org's supply chain** — scan every repo an external contractor pushes before you pull it
- **CI pipelines** — `action.yml` ships a composite GitHub Action; pair it with `scripts/pre-commit.sh` to also catch new lockfile entries before they land
- **Bug bounty and security research** — quickly triage suspicious samples reported to you

---

## Roadmap

| Phase | Status | What |
|---|---|---|
| **Phase 1: Claude Code workflow** | ✅ shipped | `modes/`, `detectors/`, `iocs/`, case study |
| **Phase 1.5: New detectors + IOC expansion** | ✅ shipped | `git-level.md`, `lockfile-anomalies.md`, `dep-confusion.md`, D11-D16 checks, IOC database expansion |
| **Phase 2: Node CLI** | ✅ shipped | `npx clonesafe <url>` — same rules, zero dependencies, no Claude required |
| **Phase 2.5: Multi-ecosystem + tests + sandbox** | ✅ shipped | D17–D20 (Python `setup.py`/`pyproject.toml`, Rust `build.rs`, Go `//go:generate`), `node:test` fixture suite, opt-in `--sandbox` Docker install harness |
| **Phase 2.6: Transitive + Ruby/PHP + provenance + CI** | ✅ shipped (0.3.0) | D15b (transitive IOC scan across all four lockfile formats), D21/D22 (Ruby `Gemfile`/`extconf.rb`, PHP `composer.json` install hooks), D23 (known-bad TLDs), GH-FORCE-PUSH via the Activity API, opt-in `--provenance` (npm SLSA attestation downgrade detection), `--diff` differential rescans, `action.yml` GitHub Action, `scripts/pre-commit.sh` lockfile re-vet hook, in-container tarball extraction, `tests/calibrate.js` calibration baseline |
| **Phase 4: Browser extension** | 💡 idea | Overlay risk badges on GitHub and LinkedIn |

**Related projects in the same family:**
- [`bkotrys/job-scam-detector`](https://github.com/bkotrys/job-scam-detector) (coming soon) — umbrella tool that uses clonesafe + adds recruiter / company / job spec / document vetting

---

## Contributing

clonesafe gets stronger every time someone submits a new malicious sample or IOC.

- **Found a malicious repo?** Open an issue with the [`IOC submission`](.github/ISSUE_TEMPLATE/ioc-submission.md) template.
- **False positive on a legit project?** Open an issue with [`false positive`](.github/ISSUE_TEMPLATE/false-positive.md).
- **New attack pattern?** PRs welcome — add a new rule to `detectors/` and a sample to `samples/`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full flow.

---

## FAQ

**Q: Does this replace `npm audit` / Snyk / Socket.dev / Phylum?**
No. Those tools scan published npm packages for known CVEs and behavioral patterns. clonesafe scans *arbitrary git repos* — including ones that were never published — *before* you install them. It's a complement, not a replacement. clonesafe should be your first line; then `npm audit` after install.

**Q: What about typosquats and dependency confusion?**
clonesafe checks each dependency in `package.json` against its IOC database and against the top-10k npm packages for Levenshtein-close names. It's not a full typosquat scanner but it catches the common patterns.

**Q: Can this catch a zero-day?**
Sometimes. clonesafe catches **patterns**, not specific payloads. A new campaign using the same lifecycle-script backgrounding trick as our canonical sample will still trip the rules. A genuinely novel attack vector won't — until someone submits a sample and adds a rule.

**Q: Will clonesafe work for pip/cargo/go/gem/composer packages?**
Yes — Phase 2.5 added Python (`setup.py` shell-out and `pyproject.toml` build hooks → D17/D18), Rust (`build.rs` network/process spawn → D19), and Go (`//go:generate` shell-out → D20). Phase 2.6 (0.3.0) adds Ruby (`Gemfile` and `extconf.rb` install-time shell-out → D21) and PHP (`composer.json` `post-install-cmd` / `post-update-cmd` → D22). Coverage is narrower than the npm side because npm still hosts the bulk of observed attack volume; we extend ecosystems as we see real samples. Rakefile and `.gemspec` are deliberately excluded from D21 because they only run on developer invocation, not at install time.

**Q: Why Claude Code and not a standalone CLI?**
Both are available. Phase 1 uses Claude Code for richer LLM-assisted analysis (cross-file reasoning, explanation generation, interactive follow-up). Phase 2 provides a standalone CLI (`npx clonesafe <url>`) with the same rules for users who don't have Claude Code. The detection logic lives in `detectors/` regardless — the CLI encodes all rules as JavaScript.

**Q: Who maintains this?**
[Bartosz Kotrys](https://github.com/bkotrys) — principal software engineer. clonesafe was built after a real Contagious Interview attack, 8 hours of incident response, and the realization that no existing tool covers the pre-clone gap. The detection rules, playbooks, and IOC database are all grounded in that real-world incident.

**Q: Is clonesafe itself safe to use? Could it harm my machine?**
clonesafe's own operations are: `curl` (download text files to /tmp), `grep` (pattern match), `python3 -c "json.load()"` (parse JSON), then delete /tmp. No code from the scanned repo ever executes. The worst case is a false negative (missing an attack) — identical to not having clonesafe. It never makes things worse. See the [security analysis](SECURITY.md) for the full breakdown.

---

## Related reading

- **[`samples/contagious-interview-001/`](samples/contagious-interview-001/)** — anonymized technical analysis of a real Contagious Interview attack. Shows exactly what the attacker's code does, line by line, and which clonesafe rules catch each part.
- **[`playbooks/i-just-ran-it.md`](playbooks/i-just-ran-it.md)** — immediate incident response checklist. If you already ran something suspicious, start here.
- **[`SECURITY.md`](SECURITY.md)** — threat model, defense architecture, known limitations, evasion techniques, and responsible disclosure.
- **CISA + FBI advisories** on DPRK IT-worker / fake-interview operations
- **Unit 42:** "Contagious Interview" campaign writeups
- **ESET:** "DeceptiveDevelopment" reports
- **Securonix:** "DEV#POPPER" series
- **Socket.dev, Phylum, Snyk** threat feeds

---

## License

[MIT](LICENSE) — use it, fork it, ship it. Attribution appreciated but not required.

---

## Acknowledgements

Built because Claude Code made it possible to ship a real security tool as a single-person project in a week. Inspired by [santifer/career-ops](https://github.com/santifer/career-ops) for the Claude-Code-as-runtime architecture.

**If clonesafe saves you from an attack, the best thank-you is [starring the repo](https://github.com/bkotrys/clonesafe) and sharing it with a developer who's currently interviewing.**
