---
detector: dep-confusion
applies-to: "package.json"
risk-family: dependency-trust
---

# Detector: dependency confusion and typosquatting

Attackers publish packages with names designed to be mistaken for legitimate ones — typosquats, scope impersonations, and namespace confusion. These rules catch dependencies that look like deception rather than legitimate choices.

## Rules

### DC-001 — typosquat of popular package
**Risk:** 🟠 HIGH
**Matches:** Any dependency name within Levenshtein distance 1-2 of a top-500 npm package name.

Examples of known typosquat patterns:
```
expresss         → express (double s)
loadash          → lodash (added a)
axois            → axios (transposed letters)
ract             → react (dropped e)
chalck           → chalk (added c)
requets          → request (transposed letters)
underscoer       → underscore (transposed letters)
momnet           → moment (transposed letters)
babael           → babel (transposed letters)
```

The check requires a hardcoded list of top npm package names (maintained in the CLI's `utils.js`) and a Levenshtein distance function. Flag any dependency where:
- `levenshtein(depName, topPackageName) <= 2` AND
- `depName` is not itself in the top-500 list (avoid flagging legitimate packages)

**Why suspicious:** typosquatting is the most common npm supply chain attack vector by volume. Attackers publish packages with common misspellings and wait for developers to install the wrong one. The malicious package often has identical functionality plus a hidden payload.

**Real-world example:** `crossenv` (typosquat of `cross-env`, 2017), `lodahs` / `lodashs` (typosquats of `lodash`, 2018), the September 2024 Chalk+Debug attack wave (`chalk-next`, `debug-js`).

**False positives:** legitimate packages that happen to have similar names. The top-500 allowlist prevents self-flagging. Weight is +30 to allow stacking with other signals rather than blocking alone.

---

### DC-002 — brand-new npm package (<30 days old)
**Risk:** 🟡 MEDIUM
**Matches:** A dependency whose first publish date on the npm registry is fewer than 30 days ago.

Check via npm registry API: `https://registry.npmjs.org/<package-name>` → `time.created` field.

**Why suspicious:** newly-published packages have no track record. Many supply chain attacks involve publishing a new malicious package and quickly getting it into victims' dependency trees (via PR, social engineering, or typosquat installation).

**Note:** this check requires a live npm registry API call. In the Claude Code workflow (Phase A), Claude can make this call. In the CLI (Phase 2), this runs behind a `--deep` flag to avoid rate-limiting the npm registry.

**Real-world example:** `plain-crypto-js` (2026) was published specifically as a malicious dependency for the compromised axios versions. It was <1 day old when victims installed it.

**False positives:** many — every legitimate new package starts at 0 days old. Weight is low (+15) and this never blocks alone. It's a stacking signal.

---

### DC-003 — single-maintainer critical dependency
**Risk:** 🟡 MEDIUM
**Matches:** A dependency listed in `dependencies` (not `devDependencies`) that has only one npm maintainer.

Check via npm registry API: `https://registry.npmjs.org/<package-name>` → `maintainers` array length.

**Why suspicious:** single-maintainer packages are the highest-risk targets for account takeover. If the one maintainer's credentials are compromised, there's no second pair of eyes on published versions.

**Note:** like DC-002, requires a live npm registry API call. Runs behind `--deep` flag in the CLI.

**Real-world example:** ua-parser-js had limited maintainers when compromised in 2021. The event-stream incident (2018) involved a single maintainer who transferred ownership to an attacker.

**False positives:** most npm packages have a single maintainer. Weight is very low (+10). This is an informational signal, not a blocker.

---

### DC-004 — scope confusion
**Risk:** 🟠 HIGH
**Matches:** A scoped dependency (`@org/pkg`) where `org` is within Levenshtein distance 1-2 of a well-known npm scope.

Well-known scopes to check against:
```
@angular
@babel
@types
@aws-sdk
@google-cloud
@azure
@nestjs
@react-native
@storybook
@testing-library
@emotion
@mui
@chakra-ui
@prisma
@trpc
@tanstack
@sveltejs
@nuxtjs
@vue
@vitejs
@rollup
@esbuild
@typescript-eslint
@eslint
@octokit
@vercel
```

Examples of scope confusion:
```
@angulr/core       → @angular/core
@bable/core        → @babel/core
@tpyes/node        → @types/node
@awssdk/client-s3  → @aws-sdk/client-s3
```

**Why suspicious:** scope typosquatting targets enterprise developers who may not notice a misspelled scope prefix. The malicious package under the fake scope can mirror the legitimate package's API while exfiltrating data.

**Real-world example:** multiple scope confusion attacks documented by Socket.dev and Phylum research teams targeting `@types/` and `@babel/` scopes.

**False positives:** legitimate scopes that happen to be short and similar. The known-scopes list is authoritative.

---

### DC-005 — unscoped package shadowing a scoped one
**Risk:** 🟠 HIGH
**Matches:** A dependency that is an unscoped package whose name matches the basename of a well-known scoped package.

Examples:
```
tinycolor          → should be @ctrl/tinycolor
client-s3          → should be @aws-sdk/client-s3
eslint-plugin      → should be @eslint/eslint-plugin
```

Check: if `depName` (without scope) matches the basename portion of any package in the top scoped packages list, flag it.

**Why suspicious:** unscoped packages that shadow scoped ones exploit the npm resolution algorithm. If a developer forgets the scope, they get the attacker's package instead.

**Real-world example:** `@ctrl/tinycolor` had its unscoped variant registered by attackers in 2024.

**False positives:** some legitimate packages predate the scoped versions. Check npm publish dates — if the unscoped version was published significantly after the scoped one, it's likely malicious.

---

### DC-006 — IOC package exact match
**Risk:** 🔴 CRITICAL
**Matches:** Any dependency name that matches an entry in `iocs/packages.json`, regardless of version.

This is a direct lookup — no fuzzy matching. Check both `dependencies` and `devDependencies`.

For version-specific IOCs (like `axios` which is only malicious at specific versions), check the version range against the IOC's `versions` array. If the range could resolve to a known-bad version, flag it.

**Why suspicious:** the IOC database contains confirmed malicious packages. Any dependency matching an IOC identifier is either the malicious package itself or a legitimate package at a compromised version.

**Real-world example:** `plain-crypto-js` (2026), `ua-parser-js` at version 0.7.29 (2021), `event-stream` at version 3.3.6 (2018).

**False positives:** for packages like `axios` that have both clean and compromised versions, only flag if the version range includes the known-bad versions. `axios@^1.7.0` is safe; `axios@1.14.1` is not.

---

## Scoring summary

| Rule | Weight |
|---|---|
| DC-001 typosquat (Levenshtein 1-2) | +30 |
| DC-002 brand-new package (<30d) | +15 |
| DC-003 single maintainer | +10 |
| DC-004 scope confusion | +25 |
| DC-005 unscoped shadowing scoped | +25 |
| DC-006 IOC exact match | +50 |

DC-006 should BLOCK on its own. All others are stacking signals — individually they raise the score but don't trigger BLOCK without corroboration.
