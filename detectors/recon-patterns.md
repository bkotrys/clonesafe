---
detector: recon-patterns
applies-to: "*.js, *.ts, *.mjs, *.cjs, *.py"
risk-family: reconnaissance-and-targeting
---

# Detector: reconnaissance and targeting

Before exfiltration, stealers often fingerprint the victim's environment to decide what to steal. These rules catch the recon and targeting code.

## Rules

### RC-001 — `process.platform` branching
**Risk:** 🟠 HIGH
**Matches:** Code that branches on `process.platform === 'darwin' / 'win32' / 'linux'` and reads different files per OS.

Pattern:
```js
if (process.platform === 'darwin') {
  const x = fs.readFileSync(os.homedir() + '/Library/...');
} else if (process.platform === 'win32') {
  const y = fs.readFileSync(os.homedir() + '/AppData/...');
}
```

**Why suspicious:** legitimate cross-platform code branches on OS for file paths in application config. Malicious code branches on OS to find OS-specific credential/wallet storage.

**False positives:** lots of legitimate cross-platform libraries do this. The signal strength comes from *what* gets read in each branch — combine with EX-004/EX-005.

**Weight:** +10 standalone, +25 when combined with exfil targets

---

### RC-002 — hostname / username fingerprinting
**Risk:** 🟡 MEDIUM
**Matches:** Reading `os.hostname()`, `os.userInfo()`, `require('os').userInfo()`, `process.env.USER`, `process.env.USERNAME`.

**Why suspicious:** used to identify the victim machine and tag exfiltrated data with a unique ID.

**False positives:** many legitimate uses. Weight low unless combined with network exfil.

**Weight:** +5

---

### RC-003 — IP geolocation lookup
**Risk:** 🟡 MEDIUM
**Matches:** HTTP calls to IP geolocation services: `ipify.org`, `ip-api.com`, `ipinfo.io`, `geoip.com`, `ipapi.co`, `api.ipify.org`.

**Why suspicious:** targeted campaigns geofence execution to specific countries. Also used to identify high-value victims.

**False positives:** legitimate analytics, user personalization.

**Weight:** +5 (or +15 if combined with conditional execution)

---

### RC-004 — CI/sandbox detection
**Risk:** 🟠 HIGH
**Matches:** Code checking for presence of CI environment variables and exiting if found.

Patterns:
```js
process\.env\.CI
process\.env\.GITHUB_ACTIONS
process\.env\.CIRCLECI
process\.env\.GITLAB_CI
process\.env\.BUILDKITE
```
Combined with early return / process.exit.

**Why suspicious:** malware tries not to execute in CI/CD environments because those are often instrumented for detection.

**False positives:** build scripts that genuinely need to behave differently in CI.

**Weight:** +15

---

### RC-005 — anti-debug checks
**Risk:** 🟠 HIGH
**Matches:** Detection of debuggers, Node.js inspect mode, or performance-based timing anti-debug.

Patterns:
```js
process\.execArgv.*inspect
process\.debugPort
Date\.now\(\)\s*-\s*start\s*>\s*\d+\s*\?\s*.*return
```

**Why suspicious:** legitimate code doesn't detect debuggers.

**Weight:** +15

---

### RC-006 — sleep / delay before main logic
**Risk:** 🟡 MEDIUM
**Matches:** `setTimeout` / `await new Promise(r => setTimeout(r, N))` where N > 30000 at the start of execution, before any useful work.

**Why suspicious:** delayed execution helps evade sandbox analysis (most sandboxes watch for ~1 minute then conclude the file is benign).

**False positives:** legitimate rate-limiting, debouncing.

**Weight:** +8

---

### RC-007 — user-agent spoofing
**Risk:** 🟡 MEDIUM
**Matches:** HTTP requests with hardcoded browser user-agent strings.

Pattern:
```
['"]User-Agent['"].*Mozilla/5\.0
```

**Why suspicious:** malware fakes a browser UA so its traffic blends with legitimate web browsing. Legitimate code either uses no UA or a descriptive one (`axios/1.0`, `my-app/2.0`).

**False positives:** scrapers legitimately spoof UAs.

**Weight:** +5

---

### RC-008 — check for specific software presence
**Risk:** 🟡 MEDIUM
**Matches:** Enumeration of installed software — checking for Chrome, Brave, Firefox, MetaMask, etc.

Example patterns:
```js
fs\.existsSync\s*\(\s*['"][^'"]*Chrome[^'"]*['"]
fs\.accessSync\s*\(\s*[^)]*Brave
fs\.statSync\s*\(\s*[^)]*Library/Application Support/[^)]*
```

**Why suspicious:** the recon phase before targeted exfiltration.

**Weight:** +15

---

### RC-009 — reading docker / kubernetes config
**Risk:** 🟠 HIGH
**Matches:** Reading `~/.docker/config.json`, `~/.kube/config`, kubeconfig paths.

**Why suspicious:** enterprise credentials worth their own weight class.

**Weight:** +25

---

### RC-010 — scanning for `.env` files
**Risk:** 🟠 HIGH
**Matches:** Code that walks directories looking for `.env` or `.env.*` files outside the package's own directory.

Patterns:
```
glob\s*\(\s*['"].*\.env
readdir.*\.env
find.*\.env
```

**Why suspicious:** stealing env files from other projects on the dev's machine.

**Weight:** +25

---

## Scoring summary

| Rule | Weight |
|---|---|
| RC-001 platform branching | +10 / +25 with exfil |
| RC-002 hostname/user | +5 |
| RC-003 IP geo | +5 / +15 conditional |
| RC-004 CI detection | +15 |
| RC-005 anti-debug | +15 |
| RC-006 sleep delay | +8 |
| RC-007 UA spoofing | +5 |
| RC-008 software presence | +15 |
| RC-009 docker/k8s config | +25 |
| RC-010 .env scanning | +25 |
