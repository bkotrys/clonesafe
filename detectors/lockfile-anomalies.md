---
detector: lockfile-anomalies
applies-to: "package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock"
risk-family: dependency-integrity
---

# Detector: lockfile anomalies

Lockfiles pin exact dependency versions and resolve URLs. Manipulated lockfiles can redirect installs to attacker-controlled tarballs, pin known-bad versions, or inject dependencies that bypass `package.json` review. These rules catch lockfile states that deviate from normal registry resolution.

**Per-format coverage:**
| Lockfile | LF-001 | LF-002 | LF-003 | LF-004 | LF-005 | LF-006 |
|---|---|---|---|---|---|---|
| `package-lock.json` (npm v2/v3) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (v3-only field) |
| `yarn.lock` (Yarn v1) | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| `pnpm-lock.yaml` (pnpm v6+) | ✓ | ✓ | ✓ | ✓ | ✓ | — (no equivalent flag) |
| `bun.lock` (text) | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| `bun.lockb` (binary) | flag-presence-only — clonesafe cannot grep binary lockfiles |

## Rules

### LF-001 — non-registry resolved URL
**Risk:** 🔴 CRITICAL
**Matches:** Any resolved-tarball URL in `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, or `bun.lock` that does NOT point to `registry.npmjs.org` or `registry.yarnpkg.com`.

Each lockfile format encodes the resolved URL differently — apply the regex appropriate to the format:

**package-lock.json (npm v2/v3) and bun.lock:**
```
"resolved"\s*:\s*"(?!https://registry\.npmjs\.org/)(?!https://registry\.yarnpkg\.com/)[^"]*"
```

**yarn.lock:**
```
resolved\s+"(?!https://registry\.npmjs\.org/)(?!https://registry\.yarnpkg\.com/)[^"]*"
```

**pnpm-lock.yaml (pnpm v6+):** pnpm omits the tarball key when the URL matches its default registry, so simply *any* `tarball:` line whose URL isn't an npm/yarn registry is a hit:
```
(^|[{,[:space:]])tarball:\s*(?!https?://(registry\.npmjs\.org|registry\.yarnpkg\.com)/)https?://[^\s,}]+
```

A pnpm-lock entry typically looks like one of:
```yaml
'/some-pkg@1.2.3':
  resolution: {integrity: sha512-...}                      # default registry — NOT a hit
'wa-sqlite@https://codeload.github.com/.../tar.gz/abc123':
  resolution: {tarball: https://codeload.github.com/..., integrity: sha512-...}   # hit
```

**bun.lockb** is a binary file. clonesafe cannot grep it; flag presence and note that LF-001 is skipped for that file.

**Why suspicious:** the npm and yarn registries are the canonical sources. A resolved URL pointing anywhere else — GitHub raw URLs, personal servers, S3 buckets, Vercel deployments — means the dependency was explicitly redirected. This is the primary mechanism for lockfile injection attacks.

**Real-world example:** the Codecov supply chain attack (2021) involved modifying a CI script, but lockfile manipulation is the npm-native equivalent — an attacker with repo write access changes resolved URLs to serve backdoored tarballs.

**False positives:** private registries (Artifactory, Nexus, Verdaccio, GitHub Packages) use custom URLs; some legitimate packages are distributed only via vendor CDNs or GitHub releases (e.g. `xlsx` from `cdn.sheetjs.com` after sheetjs left npm in 2023, or `wa-sqlite` pinned to a commit on `codeload.github.com`). Check if the domain looks like a legitimate registry or a known vendor CDN:
```
registry\.npmjs\.org
registry\.yarnpkg\.com
npm\.pkg\.github\.com
.*\.jfrog\.io
.*\.artifactoryonline\.com
codeload\.github\.com           # github source tarballs (commit-pinned)
cdn\.sheetjs\.com               # sheetjs official distribution (post-2023 npm exit)
```
Even when the URL is benign, the WARN floor still fires so the user reviews each one — the rule is conservative on purpose.

---

### LF-002 — git+ssh dependency URL
**Risk:** 🔴 CRITICAL
**Matches:** Any lockfile entry (any of `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`) with `git+ssh://` or `git+https://` as the resolved protocol.

Regex (format-independent):
```
git\+ssh://
git\+https://
```

For pnpm-lock.yaml, this typically appears as `resolution: {type: git, repo: git+ssh://..., commit: ...}` or as a key like `<pkg>@git+ssh://...:<commit>`. The bare-protocol regex catches all variants.

**Why suspicious:** `git+ssh://` dependencies bypass the npm registry entirely, pulling code directly from a git repo. The resolved content isn't checksummed against the registry. An attacker who controls the git repo can push arbitrary changes that `npm install` will silently pull.

**Real-world example:** dependency confusion attacks where internal package names collide with public ones, and lockfiles pin `git+ssh://` URLs to attacker repos.

**False positives:** some projects legitimately use git dependencies for pre-release versions or monorepo cross-references. Check if the git URL points to the same org as the project.

---

### LF-003 — missing or unusual integrity hash
**Risk:** 🟠 HIGH
**Matches:** Lockfile entries where:
1. A resolved URL is present but `integrity` is missing entirely, OR
2. `integrity` uses an algorithm other than `sha512` (e.g., `sha1-`, `md5-`), OR
3. `integrity` field is empty string

**package-lock.json (v2/v3) — missing integrity:**
```
"resolved"\s*:\s*"[^"]+",?\s*\n\s*(?!"integrity")
```

**Weak hash (any JSON-style lockfile):**
```
"integrity"\s*:\s*"(sha1-|md5-)"
```

**pnpm-lock.yaml — missing integrity:** every package block under `packages:` should have `resolution: {integrity: sha512-...}` (registry default) or both `tarball:` and `integrity:` keys (non-default). A `resolution:` block with neither integrity field is a hit:
```
resolution:\s*\{(?![^}]*integrity)[^}]*\}
```

**pnpm weak hash:**
```
integrity:\s*(sha1-|md5-)
```

**Why suspicious:** npm/pnpm/yarn use SHA-512 integrity hashes to verify downloaded tarballs match what was published. Missing or weak integrity hashes mean the package manager can't verify the tarball hasn't been tampered with. A lockfile with missing integrity was either generated by very old tooling or deliberately stripped.

**False positives:** npm v5 lockfiles (lockfileVersion 1) may use sha1. pnpm `link:` / `file:` / `workspace:` resolutions correctly omit integrity (local sources). Old projects that haven't regenerated their lockfile. Check `lockfileVersion` and the resolution `type` before flagging.

---

### LF-004 — dependency version matches known-bad IOC
**Risk:** 🟠 HIGH
**Matches:** Any dependency name + version combination in the lockfile that matches an entry in `iocs/packages.json`.

This is a cross-reference check, not a regex check. For each entry in `iocs/packages.json`, check if the lockfile contains a dependency with that name at one of the flagged versions.

**Why suspicious:** the IOC database contains confirmed malicious package versions. A lockfile pinning one of these versions means the project will install known malware on `npm install`.

**Real-world example:** axios 1.14.1 (2026 compromise), ua-parser-js 0.7.29 (2021), event-stream 3.3.6 (2018).

**False positives:** none. IOC matches are confirmed malicious.

---

### LF-005 — tarball URL from suspicious domain
**Risk:** 🟠 HIGH
**Matches:** `resolved` URL whose domain matches `iocs/domains.json` entries or known-suspicious hosting patterns.

Suspicious domain patterns:
```
.*\.vercel\.app
.*\.netlify\.app
.*\.glitch\.me
.*\.repl\.co
.*\.ngrok\.io
.*\.herokuapp\.com
.*\.workers\.dev
\d+\.\d+\.\d+\.\d+              # raw IP addresses
```

Also cross-reference against `iocs/domains.json` entries and pattern IOCs.

**Why suspicious:** legitimate npm packages are hosted on the npm registry. Tarballs from free hosting platforms or raw IPs are attacker infrastructure.

**False positives:** some companies host internal registries on custom domains. Check if the domain pattern matches a known registry.

---

### LF-006 — unexpected `hasInstallScript` flag
**Risk:** 🟡 MEDIUM
**Matches:** `package-lock.json` v3 entries with `"hasInstallScript": true` on packages that are not typically expected to have install scripts.

Known packages that legitimately have install scripts:
```
esbuild
sharp
canvas
sqlite3
bcrypt
node-sass
puppeteer
electron
phantomjs
node-gyp
prebuild-install
```

Flag any `hasInstallScript: true` entry whose package name is NOT in the allowlist above.

**Why suspicious:** `hasInstallScript` is a lockfile v3 field that explicitly marks packages with lifecycle scripts. This is a convenient audit point — if an unexpected package gained install scripts between versions, it may have been compromised.

**Real-world example:** the ua-parser-js compromise added a `postinstall` script to a package that previously had none. If the lockfile had been audited for `hasInstallScript` changes, the compromise would have been immediately visible.

**False positives:** native module packages legitimately need install scripts for compilation. The allowlist reduces noise.

---

## Scoring summary

| Rule | Weight |
|---|---|
| LF-001 non-registry URL | +50 |
| LF-002 git+ssh URL | +45 |
| LF-003 missing/weak integrity | +30 |
| LF-004 IOC version match | +25 |
| LF-005 suspicious domain tarball | +30 |
| LF-006 unexpected install script | +15 |

A single LF-001 or LF-002 hit should BLOCK on its own.
