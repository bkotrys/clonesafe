---
detector: git-level
applies-to: ".gitattributes, .gitmodules, repo file listing"
risk-family: git-config-exploitation
---

# Detector: git-level exploits

Git itself provides mechanisms that execute arbitrary commands on checkout, merge, and archive. These rules catch abuse of `.gitattributes` filters, `.gitmodules` submodule injection, and suspicious binaries in the repo tree.

## Rules

### GL-001 — smudge/clean filter RCE in `.gitattributes`
**Risk:** 🔴 CRITICAL
**Matches:** `.gitattributes` file containing `filter=` directives. When a repo defines a custom smudge or clean filter, `git checkout` runs the specified command on every matching file. An attacker who controls `.gitattributes` can execute arbitrary code on clone.

Regex (applied to `.gitattributes` content):
```
filter\s*=\s*\S+
```

Cross-check: if the filter name is one of the well-known safe filters (`lfs`, `git-crypt`), do **not** flag. Flag everything else.

Safe filter allowlist:
```
^(lfs|git-crypt|crypt)$
```

**Why suspicious:** `.gitattributes` filters execute during `git checkout`, which happens automatically after `git clone`. This is a direct RCE vector that runs before the developer has a chance to inspect the code. CVE-2022-39253, CVE-2024-32002, and related vulnerabilities all exploit this mechanism.

**Real-world example:** CVE-2024-32002 — a crafted repo with `.gitattributes` and symlinks could execute arbitrary code during `git clone`. Multiple proof-of-concept exploits demonstrated filter-based RCE.

**False positives:** Git LFS (`filter=lfs`) and git-crypt (`filter=git-crypt`) are legitimate. Any other filter name in a repo you don't control is suspicious.

---

### GL-002 — `.gitattributes` export-ignore on security-relevant files
**Risk:** 🟠 HIGH
**Matches:** `export-ignore` applied to files that a reviewer would want to see — especially `.gitmodules`, `.github/`, security files, or source files.

Patterns:
```
\.gitmodules\s+export-ignore
\.github\s+export-ignore
security\s+export-ignore
```

**Why suspicious:** `export-ignore` hides files from `git archive` exports. An attacker can hide malicious `.gitmodules` or workflow files so they don't appear in GitHub's source download but are present in the actual repo.

**False positives:** legitimate projects use `export-ignore` for test fixtures, docs, CI configs. Flag only when applied to security-relevant paths.

---

### GL-003 — submodule URL injection
**Risk:** 🔴 CRITICAL
**Matches:** `.gitmodules` containing URLs with shell metacharacters, option injection (`--`), or dangerous protocols.

Regex patterns (applied to `.gitmodules` content):
```
url\s*=\s*.*ext::
url\s*=\s*.*file://
url\s*=\s*.*\$\(
url\s*=\s*.*`
url\s*=\s*.*--upload-pack
url\s*=\s*.*--config
```

**Why suspicious:** the `ext::` protocol in git allows arbitrary command execution. `file://` can access local repos for symlink attacks. Shell metacharacters (`$(...)`, backticks) in URLs can execute commands when git processes the submodule. `--upload-pack` and `--config` injection allows passing arbitrary git options.

**Real-world example:** CVE-2022-39253 — local clone optimization could be abused via crafted `.gitmodules`. CVE-2024-32002 — symlinked submodule paths combined with hooks for RCE on clone.

**False positives:** none for `ext::` or shell metacharacters. `file://` is extremely rare in legitimate submodules.

---

### GL-004 — submodule path traversal
**Risk:** 🔴 CRITICAL
**Matches:** `.gitmodules` with `path` values containing `..` (parent directory traversal) or absolute paths.

Regex patterns:
```
path\s*=\s*.*\.\.
path\s*=\s*\/
```

**Why suspicious:** path traversal in submodule definitions can place files outside the expected repo directory, potentially overwriting system files or placing hooks in `.git/hooks/`. This is the core mechanism of CVE-2024-32002.

**Real-world example:** CVE-2024-32002 — crafted submodule paths with case-insensitive filesystem tricks allowed writing to `.git/hooks/`, achieving RCE on clone.

**False positives:** none. Legitimate submodules use relative paths within the repo.

---

### GL-005 — submodule pointing to suspicious host
**Risk:** 🟠 HIGH
**Matches:** `.gitmodules` URL pointing to a non-standard host — raw IPs, non-GitHub/GitLab/Bitbucket hosts, or known IOC domains.

Patterns:
```
url\s*=\s*https?://\d+\.\d+\.\d+\.\d+
url\s*=\s*.*\.vercel\.app
url\s*=\s*.*\.netlify\.app
url\s*=\s*.*\.ngrok\.io
url\s*=\s*.*\.glitch\.me
url\s*=\s*.*\.repl\.co
```

Also cross-reference the URL domain against `iocs/domains.json`.

Allowlist of trusted hosts:
```
github\.com
gitlab\.com
bitbucket\.org
```

**Why suspicious:** legitimate submodules point to well-known git hosting platforms. Submodules from raw IPs or throwaway hosting suggest attacker-controlled infrastructure.

**False positives:** self-hosted GitLab/Gitea instances use custom domains. Check if the URL looks like a git hosting service (has `/owner/repo.git` structure).

---

### GL-006 — binary executables in repo
**Risk:** 🟡 MEDIUM
**Matches:** files with executable/binary extensions in the repo's root or source directories.

Extensions to flag (from GitHub API contents listing or file fetching):
```
\.(exe|dll|so|dylib|bin|msi|dmg|app|deb|rpm|bat|cmd|ps1|vbs|wsf|scr|com|pif)$
```

**Why suspicious:** source repos should contain source code, not compiled binaries. Binaries can contain anything and can't be statically analyzed. Their presence in a repo is a red flag — especially in an npm project.

**Real-world example:** some Contagious Interview variants include precompiled binaries as "build artifacts" that the lifecycle script executes directly.

**False positives:** legitimate native module repos (e.g., sharp, canvas) include prebuilt binaries for distribution. Electron apps may include platform-specific binaries. Check if the package's stated purpose involves native code.

---

### GL-007 — custom merge driver in `.gitattributes`
**Risk:** 🟠 HIGH
**Matches:** `.gitattributes` defining a custom merge driver.

Regex:
```
merge\s*=\s*(?!binary|union|text)\S+
```

**Why suspicious:** custom merge drivers execute commands during `git merge`. Like smudge/clean filters, they're a code execution vector controlled by the repo author.

**Real-world example:** theoretical but documented in git security advisories. Same mechanism as filter exploits.

**False positives:** `merge=binary` and `merge=union` are built-in and safe. Any other merge driver name in a third-party repo is suspicious.

---

## Scoring summary

| Rule | Weight |
|---|---|
| GL-001 smudge/clean filter | +50 |
| GL-002 export-ignore abuse | +20 |
| GL-003 submodule URL injection | +50 |
| GL-004 submodule path traversal | +50 |
| GL-005 suspicious submodule host | +25 |
| GL-006 binary executables | +10 |
| GL-007 custom merge driver | +25 |

Any GL-001, GL-003, or GL-004 hit should BLOCK on its own.
