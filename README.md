# clonesafe

> **Vet a GitHub repo *before* you `git clone` it.**
> Catches malicious `prepare`/`postinstall` hooks, obfuscated exfil, known-bad dependencies, and suspicious repo metadata — all without ever touching your disk.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/built%20with-Claude%20Code-8A2BE2)](https://claude.com/claude-code)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#zero-dependencies)

---

## Why this exists

In April 2026, a developer received a take-home coding challenge from what appeared to be a legitimate recruiter. The repo looked professional — clean structure, realistic dependencies (axios, express, mongoose, ethers, socket.io, pokersolver), a README with screenshots. A small Web3 Texas Hold'em game. Nothing unusual.

They ran `npm install`. Within ten minutes, a malicious background Node process had exfiltrated their environment variables and was running stage-2 remote code execution against a `*.vercel.app` endpoint. The attack was caught, the process was killed, and 8 hours of incident response followed.

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

- **[Claude Code](https://claude.com/claude-code)** — the runtime that executes clonesafe's skill files
- **python3** — used by Phase 0 deterministic checks to parse JSON (comes pre-installed on macOS and most Linux distros)
- **curl** — used to fetch files from `raw.githubusercontent.com` (pre-installed on macOS/Linux)
- **grep** — used by Phase 0 deterministic pattern matching (pre-installed on macOS/Linux)

Optional (improves experience but not required):
- **jq** — if installed, some checks run faster. Install via `brew install jq` (macOS) or `apt install jq` (Debian/Ubuntu)

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
- `GITHUB_TOKEN` env var — increases GitHub API rate limit from 60 to 5,000 requests/hour

The CLI runs the same D1-D16 deterministic checks and all 70+ detector rules as the Claude Code workflow, but without the LLM-assisted Phase A reasoning. It's faster and fully deterministic — ideal for CI pipelines, pre-commit hooks, and automated scanning.

---

## What it detects

### 🔴 Hard fails (any one → BLOCK)
- **Lifecycle script abuse**: `prepare`/`postinstall`/`preinstall`/`install` scripts that launch servers, background-daemonize (`nohup`, `&`, `start /b`), mix Windows/Unix syntax, or make network calls.
- **Base64 + dynamic execution**: `Buffer.from(X, 'base64').toString()` piped into `new Function(...)` or `eval(...)`.
- **Environment exfiltration**: `axios.post` / `fetch` / `got` with `process.env` as the body.
- **Known-bad dependencies**: packages matching the clonesafe IOC database (axios 1.14.1, plain-crypto-js 4.2.x, etc.).
- **Known-bad GitHub orgs**: orgs tagged in `iocs/github-orgs.json` as campaign infrastructure.
- **`.gitattributes` filter RCE**: smudge/clean filters that execute commands on `git checkout` (CVE-2024-32002).
- **Submodule injection**: `.gitmodules` with `ext::`, `file://`, shell metacharacters, or path traversal.
- **Lockfile manipulation**: non-registry resolved URLs, `git+ssh://` deps redirecting `npm install` to attacker tarballs.

### 🟠 Strong warnings (raise score)
- **Obfuscation signatures**: javascript-obfuscator output (`_0x[a-f0-9]+` names), reversed/shuffled string arrays, hex-encoded identifiers.
- **OS-specific exfil paths**: references to `~/.ssh`, `~/Library/Application Support/Google/Chrome`, wallet extension IDs, MetaMask/Phantom paths, Local Extension Settings.
- **Dynamic execution primitives**: `new Function`, `eval`, `vm.runInNewContext`, `child_process.exec` with non-literal strings.
- **Repo metadata red flags**: org/repo created <30 days, 0-1 contributors, single squashed commit, missing LICENSE/.gitignore, suspiciously thin history vs. claimed product maturity.

### 🟡 Soft signals (scored, surfaced in report)
- Lockfile anomalies (non-registry URLs, version pins to yanked releases)
- README claims inconsistent with actual repo state
- Mixed package managers
- Dependencies with versions resolved to brand-new packages (<30 days old)

**Full rule catalog:** [`detectors/`](detectors/)

---

## How it works (no magic)

clonesafe never executes the code it's analyzing. It uses only:

1. **GitHub REST API** — for repo metadata, org age, contributor count, file listing
2. **`raw.githubusercontent.com`** — for fetching specific files (package.json, lockfiles, entry points, suspicious paths)
3. **Static pattern matching** — regex, substring, and AST shape rules from [`detectors/`](detectors/)
4. **IOC database lookup** — [`iocs/`](iocs/) JSON files for known-bad packages/domains/orgs
5. **Claude Code's reasoning** — to chain the signals into a coherent verdict, explain the findings in English, and suggest next steps

**No sandbox. No Docker. No VM. No telemetry. No account. No internet calls except to `api.github.com` and `raw.githubusercontent.com`.**

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

| Repo | Type | Expected | D1-D10 | Floor | Result |
|---|---|---|---|---|---|
| `expressjs/express` | Known safe, popular | All zeros | All 0 | NONE | ✅ |
| `facebook/react` | Known safe, popular | All zeros | All 0 | NONE | ✅ |
| `typicode/husky` | Legit lifecycle hooks | All zeros | All 0 | NONE | ✅ no FP |
| `puppeteer/puppeteer` | Legit postinstall | All zeros | All 0 | NONE | ✅ no FP |
| `tokio-rs/tokio` | Rust (no npm) | All zeros | All 0 | NONE | ✅ graceful |
| Contagious Interview sample | Real attack (defanged) | D1,D2,D3,D5,D6,D7 fire | 6 hits | **BLOCK** | ✅ |
| Prompt injection bait | Synthetic PI test | D8 fires | D8=12 | **BLOCK** | ✅ |
| Nonexistent repo | Edge case | No files | All 0 | NONE | ✅ graceful |

**Zero false positives. Zero false negatives. Clean edge case handling.**

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
- **CI pipelines** — eventually, a GitHub Action wrapper ([roadmap](#roadmap))
- **Bug bounty and security research** — quickly triage suspicious samples reported to you

---

## Roadmap

| Phase | Status | What |
|---|---|---|
| **Phase 1: Claude Code workflow** | ✅ shipped | `modes/`, `detectors/`, `iocs/`, case study |
| **Phase 1.5: New detectors + IOC expansion** | ✅ shipped | `git-level.md`, `lockfile-anomalies.md`, `dep-confusion.md`, D11-D16 checks, IOC database expansion |
| **Phase 2: Node CLI** | ✅ shipped | `npx clonesafe <url>` — same rules, zero dependencies, no Claude required |
| **Phase 3: GitHub Action + pre-commit hook** | 📋 planned | CI-time scanning, `baitcheck/scan@v1` |
| **Phase 4: Sandbox-as-a-service** | 💡 idea | Hosted Docker runner for `npm install` behavioral analysis |
| **Phase 5: Browser extension** | 💡 idea | Overlay risk badges on GitHub and LinkedIn |

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

**Q: Will clonesafe work for pip/cargo/go packages?**
Phase 1 is npm-focused because that's where ~95% of the current attack volume lives. Phase 2+ will add Python (`setup.py`, `pyproject.toml`), Rust (`build.rs`), Go (`go.mod` + `go generate`), Ruby (Gemfile + `postinstall`).

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
