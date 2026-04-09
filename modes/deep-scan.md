---
name: deep-scan
description: Slow, thorough scan that reads every source file in a locally-cloned repo. Use when vet-repo flags something and you want definitive answers, or when you want to audit a repo that's already on disk.
triggers:
  - "deep scan {path}"
  - "deep-scan this repo"
  - "audit {path} thoroughly"
---

# deep-scan

You are running the **clonesafe deep-scan** workflow. Unlike `vet-repo` (which fetches via API before cloning), `deep-scan` operates on a repo that's already on disk. Its job is to walk every file and apply every detector rule, producing a definitive audit.

## When to use deep-scan vs vet-repo

| Situation | Use |
|---|---|
| You haven't cloned yet | `vet-repo` |
| You just cloned and want to verify before `npm install` | `deep-scan` |
| `vet-repo` flagged something and you want confirmation | `deep-scan` |
| You want to audit a dependency already in your `node_modules` | `deep-scan` |
| You want to re-audit an existing project against new detection rules | `deep-scan` |

## Absolute rules

1. **Read-only.** Deep-scan never modifies, deletes, or executes anything in the target directory.
2. **No `npm install`, no `node`, no `python`, no build tools.** Static analysis only.
3. **No external network calls** except for IOC database reads (local JSON) and optional registry lookups for dependency version dates.
4. **Skip `node_modules/` by default** unless the user explicitly asks to include it. Deps are the concern of `vet-repo` at install time.
5. **Always save a report** to `data/reports/{timestamp}-deep-scan-{repo-name}.md`.

## Workflow

### Step 1 — Validate target

The user provides a path. Verify:
- The path exists
- It's a directory
- It contains at least one of: `package.json`, `.git/`, `pyproject.toml`, `Cargo.toml`, `go.mod`
- If none of the above, warn the user this doesn't look like a code repo

### Step 2 — Inventory

Walk the directory tree (excluding `node_modules/`, `.git/objects/`, `dist/`, `build/`, `.next/`, `.cache/`, `coverage/`):

```
find {path} -type f \
  -not -path "*/node_modules/*" \
  -not -path "*/.git/objects/*" \
  -not -path "*/dist/*" \
  -not -path "*/build/*" \
  -not -path "*/.next/*"
```

Count files by extension. Report the inventory up front so the user knows the scan scope.

### Step 3 — Apply detectors to each relevant file

- **`package.json` files (all of them, including nested)** → `detectors/lifecycle-scripts.md`
- **`*.js`, `*.ts`, `*.mjs`, `*.cjs`, `*.jsx`, `*.tsx`** → `detectors/obfuscation.md`, `detectors/exfil-patterns.md`, `detectors/recon-patterns.md`
- **`*.py`** → `detectors/exfil-patterns.md` (Python-aware), `detectors/recon-patterns.md`
- **`*.sh`, `*.bash`, `*.zsh`** → shell script heuristics (curl-pipe-bash, base64 decode, etc.)
- **`.gitattributes`, `.gitmodules`** → git-level detectors (planned: `detectors/git-level.md`)
- **`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`** → lockfile IOC checks

For each file, record:
- Path
- Size
- Number of lines
- List of rule hits with line numbers

### Step 4 — Cross-reference IOCs

For each file, grep for any string in `iocs/domains.json`. Compute SHA256 for small files and compare against `iocs/hashes.json`. For `package.json` files, check every dep+version against `iocs/packages.json`.

### Step 5 — Build call graph (optional, slow)

If the user asked for a thorough scan:

1. Parse each `package.json`'s `scripts`
2. Trace what each script executes → which file, which args
3. For each referenced file, recursively trace its `require()` / `import` statements
4. Flag any path that goes from a lifecycle hook → to a file → to exfil patterns, as a "full kill chain" finding

This is slower but catches multi-file malicious flows.

### Step 6 — Entry points analysis

Identify all possible entry points:
- `package.json` → `main`, `module`, `bin`, `scripts.*`
- `pyproject.toml` → `[project.scripts]`, `entry_points`
- `Cargo.toml` → `[[bin]]`, `build = "build.rs"`
- `Dockerfile` → `ENTRYPOINT`, `CMD`
- `.github/workflows/*.yml` → action invocations

For each entry point, trace what it loads at startup. This is where Contagious Interview-style attacks hide (the payload runs as soon as the app starts).

### Step 7 — Compute score

Same weight table as `vet-repo`. Apply verdict thresholds.

### Step 8 — Full report

```markdown
# deep-scan — {repo name or path}

**Scanned:** {timestamp}
**Path:** {abs path}
**Files scanned:** {n} (excluded {m})
**Risk:** {emoji} {VERDICT}   **Score:** {N} / 100

## Inventory

- package.json: {count}
- JS/TS files: {count}
- Python files: {count}
- Shell scripts: {count}
- Other: {count}

## Critical findings

{list — each with file:line, rule ID, matched snippet}

## Strong warnings

{list}

## Other findings

{list}

## Entry points traced

- {list of entry points and what they execute at load time}

## IOC matches

{list}

## Dependencies flagged

{list of suspicious deps from package.json / pyproject.toml / Cargo.toml}

## Clean files

{count of files scanned that had zero findings}

## What you should do

{action guidance based on verdict}
```

## Tone

- Be thorough but not verbose. Show the evidence, not the reasoning.
- If everything is clean, say so clearly: "Deep scan found nothing. Repo looks safe."
- Never give a false "clean" verdict if the scan hit limits (too large, timeout, permission errors). Say what didn't get scanned.

## Performance considerations

- Deep-scan can take minutes on large repos (e.g., monorepos with 1000+ files). Give progress updates every 50 files.
- If the repo is >10k files, ask the user to narrow scope (specific directories) or use `triage-package-json` instead.
- Cache parsed IOC JSON files in memory — reload only if they've been modified.

## Edge cases

- **Minified / bundled files** — treat as opaque. Flag them as "minified" and note they couldn't be fully analyzed.
- **Binary files** — skip unless the user requests. Compute hash and check IOCs.
- **Symlinks** — do not follow by default (can escape the target directory).
- **Huge files (>1 MB)** — grep for critical patterns only; don't parse fully.
- **Git submodules** — note their presence, recurse only if the user asks.

## Limitations

Even deep-scan is static analysis only. It will NOT catch:
- Runtime-only behavior (code that only runs under specific conditions)
- Polymorphic / packed malware (requires dynamic analysis)
- Supply-chain attacks in transitive deps not yet in the IOC database
- Behavior of native compiled modules (`.node`, `.so`, `.dylib`, `.dll`)

For those, use a real sandbox (ANY.RUN, Joe Sandbox, a proper VM).
