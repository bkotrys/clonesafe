---
detector: obfuscation
applies-to: "*.js, *.ts, *.mjs, *.cjs"
risk-family: code-opacity
---

# Detector: obfuscation

Malicious code in a "looks legitimate" repo is almost always obfuscated to pass casual human review. Legitimate projects are not obfuscated (bundlers minify, but minification is different from obfuscation — minified code still reads linearly).

## Rules

### OB-001 — javascript-obfuscator signature
**Risk:** 🔴 CRITICAL
**Matches:** files containing identifiers of the form `_0x[a-f0-9]{4,6}` in significant count.

Regex:
```
_0x[a-f0-9]{4,6}
```
Threshold: **>10 unique matches in a single file** → CRITICAL. 5-10 matches → HIGH. <5 → flag but don't block.

**Why suspicious:** `_0x` is the default naming convention of [javascript-obfuscator](https://obfuscator.io/), used by 95%+ of commodity npm-stealer malware.

**Real-world example:** ua-parser-js incident (2021), noblox.js fork attacks, multiple Contagious Interview loader files.

**False positives:** very rare in source repos. Bundled/minified dist files might use short hex names but usually with a different prefix.

---

### OB-002 — string array shuffle pattern
**Risk:** 🔴 CRITICAL
**Matches:** A large array of short encoded strings at the top of a file, followed by a shuffle/rotate function.

Patterns to grep for:
```
var\s+_0x[a-f0-9]+\s*=\s*\[
\(function\s*\(\s*_0x[a-f0-9]+\s*,\s*_0x[a-f0-9]+\s*\)
```

Plus: a line containing an array of 20+ base64-ish strings like `['\x6e\x6f\x64\x65', '\x72\x65\x71\x75', ...]`.

**Why suspicious:** this is the javascript-obfuscator "string array encoding" mode. Its sole purpose is to obscure readable strings (URLs, function names, API endpoints).

**False positives:** none in source repos.

---

### OB-003 — base64 literal + dynamic execution
**Risk:** 🔴 CRITICAL
**Matches:** Any file containing a base64 literal longer than 40 characters within 20 lines of `new Function`, `eval`, `vm.runInNewContext`, or `vm.runInThisContext`.

Patterns:
```
Buffer\.from\(['"][A-Za-z0-9+/=]{40,}['"]\s*,\s*['"]base64['"]\)
atob\(['"][A-Za-z0-9+/=]{40,}['"]\)
```

If found, check the next ~20 lines for:
```
new\s+Function\s*\(
\beval\s*\(
vm\.runIn(New|This)Context
```

**Why suspicious:** this is the canonical "download-decode-execute" stage-2 loader pattern. The Contagious Interview sample 001 incident used this exact pattern: `const AUTH_API = Buffer.from(authKey, "base64").toString()` followed by `new Function("require", code)(require)`.

**Real-world example:** Contagious Interview sample 001 (`routes/api/auth.js`), numerous axios/plain-crypto-js droppers.

**False positives:** template engines sometimes use `new Function` for compiled templates — but they don't combine it with base64 literals. Build tools might base64-encode inlined assets but don't pass them to `new Function`.

---

### OB-004 — remote code execution via new Function
**Risk:** 🔴 CRITICAL
**Matches:** `new Function(...)` where the argument is a variable (not a literal) **AND** earlier in the function there's an HTTP fetch.

Shape to match:
```js
const {data} = await axios.get(X);        // or fetch, or got, or any HTTP client
// ... (any lines)
new Function('require', data)(require);   // or similar invocation
```

**Why suspicious:** this is remote code execution. The runtime downloads code and runs it immediately. No legitimate library does this.

**Real-world example:** Contagious Interview sample 001. Many RATs.

**False positives:** none.

---

### OB-005 — hex-encoded property access
**Risk:** 🟠 HIGH
**Matches:** Heavy use of `["\x66\x65\x74\x63\x68"]` style property access.

Regex:
```
\[\s*['"](?:\\x[0-9a-f]{2}){3,}['"]\s*\]
```

**Why suspicious:** obfuscators hide function names like `fetch`, `exec`, `require` this way.

**False positives:** extremely rare. Occasional edge-case test files.

---

### OB-006 — unicode-escaped identifiers
**Risk:** 🟠 HIGH
**Matches:** Identifiers using `\u00XX` escapes where readable ASCII would suffice.

Regex:
```
\\u00[0-9a-f]{2}
```
in a non-string context (i.e., in variable/function names or property access).

**Why suspicious:** another obfuscator trick for hiding identifiers.

**False positives:** legitimate code with non-ASCII identifiers (rare in JS/TS).

---

### OB-007 — large base64 string in source
**Risk:** 🟡 MEDIUM
**Matches:** any string literal longer than 500 base64 characters.

**Why suspicious:** embedded payloads are often multi-KB base64 blobs. Legitimate use is rare outside of inlined images in web code (SVG data URIs).

**False positives:** inlined fonts, SVGs, PDF stamps, WebAssembly modules. Check context.

---

### OB-008 — eval with concatenated string
**Risk:** 🟠 HIGH
**Matches:** `eval(X + Y)` or `eval('...' + variable + '...')`.

**Why suspicious:** building an eval argument dynamically almost always hides intent.

**False positives:** some dev tools use eval in debug paths.

---

### OB-009 — `Function` constructor with dynamic body
**Risk:** 🟠 HIGH
**Matches:** `new Function(varA, varB)` where either argument is a variable.

**Why suspicious:** same risk as `eval`. Legitimate template engines use `new Function` but with literal bodies.

---

### OB-010 — `require` of a dynamically-constructed path
**Risk:** 🟠 HIGH
**Matches:** `require(X + Y)` where X/Y are variables, especially decoded strings.

Regex:
```
require\s*\(\s*[a-zA-Z_]\w*\s*\+
require\s*\(\s*Buffer\.from\(
require\s*\(\s*atob\(
```

**Why suspicious:** hides what's being loaded. Legitimate dynamic requires use allowlists and paths like `require('./lang/' + locale)`.

**False positives:** i18n loaders, plugin systems. Check if the dynamic part is bounded by a literal prefix/suffix.

---

## Scoring summary

| Rule | Weight |
|---|---|
| OB-001 _0x names (>10) | +30 |
| OB-001 _0x names (5-10) | +15 |
| OB-002 string array shuffle | +35 |
| OB-003 base64 + exec | +50 |
| OB-004 RCE via new Function | +50 |
| OB-005 hex property access | +20 |
| OB-006 unicode identifiers | +15 |
| OB-007 large base64 | +8 |
| OB-008 eval concat | +20 |
| OB-009 dynamic new Function | +20 |
| OB-010 dynamic require | +15 |

A single OB-003 or OB-004 hit should BLOCK on its own.
