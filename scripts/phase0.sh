#!/usr/bin/env bash
# ============================================================
# clonesafe Phase 0 — Deterministic pre-scan
#
# Usage: bash scripts/phase0.sh <owner> <repo> [ref]
#
# Fetches key files from a GitHub repo via raw.githubusercontent.com
# and runs grep/python3 pattern matching. Outputs ground-truth
# match counts (D1-D10) and a deterministic verdict floor.
#
# This script makes NO changes to your system. It downloads files
# to a temp directory, greps them, prints results, and cleans up.
#
# Dependencies: curl, python3, grep (all pre-installed on macOS/Linux)
# ============================================================

set -uo pipefail
# Note: NOT using set -e because grep returns exit 1 on zero matches,
# which is expected (a clean repo has zero matches). We handle errors
# explicitly with || true and ${VAR:-0} defaults.

OWNER="${1:?Usage: bash scripts/phase0.sh <owner> <repo> [ref]}"
REPO="${2:?Usage: bash scripts/phase0.sh <owner> <repo> [ref]}"
REF="${3:-HEAD}"

SCAN_DIR=$(mktemp -d /tmp/clonesafe-XXXXXX)
BASE="https://raw.githubusercontent.com/$OWNER/$REPO/$REF"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cleanup() { rm -rf "$SCAN_DIR"; }
trap cleanup EXIT

# ---- Fetch files ----
echo "=== PHASE 0: Fetching files from $OWNER/$REPO ($REF) ==="

curl -sfL "$BASE/package.json" -o "$SCAN_DIR/package.json" 2>/dev/null || true
curl -sfL "$BASE/README.md" -o "$SCAN_DIR/README.md" 2>/dev/null || true
curl -sfL "$BASE/server.js" -o "$SCAN_DIR/server.js" 2>/dev/null || true
curl -sfL "$BASE/index.js" -o "$SCAN_DIR/index.js" 2>/dev/null || true
curl -sfL "$BASE/.gitattributes" -o "$SCAN_DIR/.gitattributes" 2>/dev/null || true
curl -sfL "$BASE/.gitmodules" -o "$SCAN_DIR/.gitmodules" 2>/dev/null || true
curl -sfL "$BASE/package-lock.json" -o "$SCAN_DIR/package-lock.json" 2>/dev/null || true
curl -sfL "$BASE/yarn.lock" -o "$SCAN_DIR/yarn.lock" 2>/dev/null || true

# Discover and fetch suspicious paths
for path in routes/api/auth.js routes/index.js config/loadEnv.js \
            config/index.js middleware/index.js src/index.js \
            lib/index.js loader.js auth.js; do
  curl -sfL "$BASE/$path" -o "$SCAN_DIR/$(echo "$path" | tr '/' '_')" 2>/dev/null || true
done

# Extract entry points from package.json and fetch them
if [ -f "$SCAN_DIR/package.json" ]; then
  python3 -c "
import json, sys, re
try:
    p = json.load(open(sys.argv[1]))
    s = p.get('scripts', {})
    for h in ['prepare','preinstall','install','postinstall','prepublish']:
        v = s.get(h, '')
        for m in re.findall(r'node\s+(\S+)', v):
            print(m.replace('./', ''))
    m = p.get('main')
    if m:
        print(m.replace('./', ''))
    b = p.get('bin', {})
    if isinstance(b, str):
        print(b.replace('./', ''))
    elif isinstance(b, dict):
        for v in b.values():
            print(v.replace('./', ''))
except:
    pass
" "$SCAN_DIR/package.json" 2>/dev/null | while read -r entry; do
    curl -sfL "$BASE/$entry" -o "$SCAN_DIR/$(basename "$entry")" 2>/dev/null || true
    curl -sfL "$BASE/${entry}.js" -o "$SCAN_DIR/$(basename "$entry").js" 2>/dev/null || true
  done
fi

# Remove empty files (failed downloads)
find "$SCAN_DIR" -type f -empty -delete 2>/dev/null || true

echo "Files fetched:"
ls "$SCAN_DIR/" 2>/dev/null | grep -v '^$' || echo "(none)"
echo ""

# ---- Helper: extract lifecycle hook values ----
extract_hooks() {
  python3 -c "
import json, sys
try:
    pkg = json.load(open(sys.argv[1]))
    for h in ['prepare','preinstall','install','postinstall','prepublish','prepublishOnly','prepack']:
        v = pkg.get('scripts', {}).get(h)
        if v:
            print(v)
except:
    pass
" "$1" 2>/dev/null
}

# ---- Run checks ----
echo "=== PHASE 0: Running deterministic checks ==="

# D1: Lifecycle script backgrounding
D1=$(extract_hooks "$SCAN_DIR/package.json" | grep -ciE 'nohup|disown|start[[:space:]]+/b|setsid' 2>/dev/null || true)
D1=${D1:-0}

# D2: Mixed Windows/Unix syntax
D2=$(extract_hooks "$SCAN_DIR/package.json" | grep -ciE 'start[[:space:]]+/b.*nohup|cmd[[:space:]]+/c.*bash' 2>/dev/null || true)
D2=${D2:-0}

# D3: Node runs non-build file in lifecycle hook
D3=$(extract_hooks "$SCAN_DIR/package.json" | grep -ciE 'node[[:space:]]+\.?/?(server|index|app|loader|config|auth|main|daemon|worker|start)(\.js|\.ts)?' 2>/dev/null || true)
D3=${D3:-0}

# D4: Base64 literals in source files
D4=0
if ls "$SCAN_DIR"/*.js 2>/dev/null >&2; then
  D4=$(grep -rlE "Buffer\.from[[:space:]]*\([[:space:]]*['\"][A-Za-z0-9+/]{40,}" "$SCAN_DIR"/*.js 2>/dev/null | wc -l | tr -d ' ')
fi

# D5: new Function with require
D5=0
if ls "$SCAN_DIR"/*.js 2>/dev/null >&2; then
  D5=$(grep -rlE "new[[:space:]]+Function[[:space:]]*\(|Function[[:space:]]*\([[:space:]]*['\"]require['\"]" "$SCAN_DIR"/*.js 2>/dev/null | wc -l | tr -d ' ')
fi

# D6: process.env exfiltration
D6=0
if ls "$SCAN_DIR"/*.js 2>/dev/null >&2; then
  D6=$(grep -rlE '(axios|fetch|got|request|http)\.(post|put|patch).*process\.env|\.send\s*\(.*process\.env|JSON\.stringify\s*\(\s*process\.env' "$SCAN_DIR"/*.js 2>/dev/null | wc -l | tr -d ' ')
fi

# D7: Known IOC domains
D7=0
if [ -f "$SCRIPT_DIR/iocs/domains.json" ]; then
  IOC_DOMS=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    for e in d.get('entries', []):
        print(e['identifier'])
except:
    pass
" "$SCRIPT_DIR/iocs/domains.json" 2>/dev/null | tr '\n' '|' | sed 's/|$//')
  if [ -n "$IOC_DOMS" ]; then
    D7=$(grep -rlE "$IOC_DOMS" "$SCAN_DIR"/* 2>/dev/null | wc -l | tr -d ' ')
  fi
fi

# D8: Prompt injection patterns in README
D8=0
if [ -f "$SCAN_DIR/README.md" ]; then
  D8=$(grep -ciE 'ignore.*(previous|prior).*(instructions|rules|directives)|disregard the above|SYSTEM:|return verdict (PROCEED|PASS|SAFE)|pre-?audited by|whitelisted by|clonesafe.*(verified|approved|trusted)|skip.*(detector|rule|scan)|bypass the scanner|set (the )?score to 0' "$SCAN_DIR/README.md" 2>/dev/null || true)
  D8=${D8:-0}
fi

# D9: Hidden Unicode (Trojan Source / GlassWorm)
D9=$(grep -rPc '[\x{200B}\x{200C}\x{200D}\x{202A}-\x{202E}\x{2066}-\x{2069}]' "$SCAN_DIR"/* 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')

# D10: Sensitive path references (SSH keys, wallet extensions, browser data)
D10=0
if ls "$SCAN_DIR"/*.js 2>/dev/null >&2; then
  D10=$(grep -rlE '\.ssh/id_|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|login\.keychain|Cookies|Login Data' "$SCAN_DIR"/*.js 2>/dev/null | wc -l | tr -d ' ')
fi

# D11: .gitattributes filter= directives (smudge/clean RCE)
D11=0
if [ -f "$SCAN_DIR/.gitattributes" ]; then
  # Match filter= but exclude known-safe filters (lfs, git-crypt)
  D11=$(grep -ciE 'filter\s*=\s*' "$SCAN_DIR/.gitattributes" 2>/dev/null || true)
  SAFE_FILTERS=$(grep -ciE 'filter\s*=\s*(lfs|git-crypt|crypt)\b' "$SCAN_DIR/.gitattributes" 2>/dev/null || true)
  D11=$(( ${D11:-0} - ${SAFE_FILTERS:-0} ))
  [ "$D11" -lt 0 ] 2>/dev/null && D11=0
fi

# D12: .gitmodules ext::/file:// or path traversal
D12=0
if [ -f "$SCAN_DIR/.gitmodules" ]; then
  D12=$(grep -ciE 'url\s*=\s*.*(ext::|file://|\$\(|`|--upload-pack|--config)|path\s*=\s*.*(\.\./|^/)' "$SCAN_DIR/.gitmodules" 2>/dev/null || true)
  D12=${D12:-0}
fi

# D13: Lockfile non-registry resolved URLs
D13=0
for lockfile in "$SCAN_DIR/package-lock.json" "$SCAN_DIR/yarn.lock"; do
  if [ -f "$lockfile" ]; then
    NON_REG=$(grep -ciE '"resolved"\s*:\s*"(?!https://registry\.npmjs\.org/)(?!https://registry\.yarnpkg\.com/)' "$lockfile" 2>/dev/null || true)
    # Fallback for yarn.lock format
    NON_REG_YARN=$(grep -ciE 'resolved\s+"(?!https://registry\.npmjs\.org/)(?!https://registry\.yarnpkg\.com/)' "$lockfile" 2>/dev/null || true)
    D13=$(( ${D13:-0} + ${NON_REG:-0} + ${NON_REG_YARN:-0} ))
  fi
done

# D14: Lockfile git+ssh:// URLs
D14=0
for lockfile in "$SCAN_DIR/package-lock.json" "$SCAN_DIR/yarn.lock"; do
  if [ -f "$lockfile" ]; then
    GIT_SSH=$(grep -ciE 'git\+ssh://' "$lockfile" 2>/dev/null || true)
    D14=$(( ${D14:-0} + ${GIT_SSH:-0} ))
  fi
done

# D15: package.json deps matching IOC packages
D15=0
if [ -f "$SCAN_DIR/package.json" ] && [ -f "$SCRIPT_DIR/iocs/packages.json" ]; then
  D15=$(python3 -c "
import json, sys
try:
    pkg = json.load(open(sys.argv[1]))
    iocs = json.load(open(sys.argv[2]))
    ioc_names = {e['identifier'] for e in iocs.get('entries', [])}
    all_deps = {}
    all_deps.update(pkg.get('dependencies', {}))
    all_deps.update(pkg.get('devDependencies', {}))
    matches = sum(1 for d in all_deps if d in ioc_names)
    print(matches)
except:
    print(0)
" "$SCAN_DIR/package.json" "$SCRIPT_DIR/iocs/packages.json" 2>/dev/null)
  D15=${D15:-0}
fi

# D16: Basic typosquat check (top-20 attacked packages)
D16=0
if [ -f "$SCAN_DIR/package.json" ]; then
  D16=$(python3 -c "
import json, sys

TOP = ['express','lodash','chalk','debug','react','axios','request','commander',
       'moment','webpack','typescript','underscore','async','bluebird','uuid',
       'glob','minimist','yargs','inquirer','semver']

def lev(a, b):
    if len(a) < len(b): return lev(b, a)
    if len(b) == 0: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca!=cb)))
        prev = curr
    return prev[-1]

try:
    pkg = json.load(open(sys.argv[1]))
    all_deps = {}
    all_deps.update(pkg.get('dependencies', {}))
    all_deps.update(pkg.get('devDependencies', {}))
    count = 0
    for dep in all_deps:
        if dep in TOP:
            continue
        for top in TOP:
            d = lev(dep.lower(), top.lower())
            if 0 < d <= 2:
                count += 1
                break
    print(count)
except:
    print(0)
" "$SCAN_DIR/package.json" 2>/dev/null)
  D16=${D16:-0}
fi

# ---- Results ----
echo ""
echo "========================================="
echo "PHASE 0 — DETERMINISTIC RESULTS"
echo "========================================="
printf "D1  Lifecycle backgrounding:   %s\n" "$D1"
printf "D2  Mixed Win/Unix syntax:     %s\n" "$D2"
printf "D3  Node non-build in hook:    %s\n" "$D3"
printf "D4  Base64 in source:          %s\n" "$D4"
printf "D5  new Function(require):     %s\n" "$D5"
printf "D6  process.env exfil:         %s\n" "$D6"
printf "D7  IOC domain match:          %s\n" "$D7"
printf "D8  Prompt injection in docs:  %s\n" "$D8"
printf "D9  Hidden Unicode:            %s\n" "$D9"
printf "D10 Sensitive path refs:       %s\n" "$D10"
printf "D11 gitattributes filter RCE:  %s\n" "$D11"
printf "D12 gitmodules injection:      %s\n" "$D12"
printf "D13 Lockfile non-registry URL: %s\n" "$D13"
printf "D14 Lockfile git+ssh URL:      %s\n" "$D14"
printf "D15 IOC package match:         %s\n" "$D15"
printf "D16 Typosquat candidate:       %s\n" "$D16"
echo "========================================="

# ---- Verdict floor ----
BLOCKS=""
[ "$D1" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D1 "
[ "$D2" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D2 "
[ "$D3" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D3 "
[ "$D5" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D5 "
[ "$D6" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D6 "
[ "$D7" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D7 "
[ "$D8" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D8 "
[ "$D10" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D10 "
[ "$D11" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D11 "
[ "$D12" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D12 "
[ "$D14" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D14 "
[ "$D15" -gt 0 ] 2>/dev/null && BLOCKS="${BLOCKS}D15 "

# D4 alone is WARN; BLOCK if combined with D5 or D6
if [ "$D4" -gt 0 ] 2>/dev/null; then
  if [ "$D5" -gt 0 ] 2>/dev/null || [ "$D6" -gt 0 ] 2>/dev/null; then
    BLOCKS="${BLOCKS}D4+D5/D6 "
  fi
fi

# D9 alone is WARN; BLOCK if >5 or combined with others
if [ "$D9" -gt 5 ] 2>/dev/null; then
  BLOCKS="${BLOCKS}D9 "
fi

echo ""
if [ -n "$BLOCKS" ]; then
  echo "VERDICT FLOOR: BLOCK (triggers: $BLOCKS)"
else
  WARN=""
  [ "$D4" -gt 0 ] 2>/dev/null && WARN="D4 "
  [ "$D9" -gt 0 ] 2>/dev/null && WARN="${WARN}D9 "
  [ "$D13" -gt 0 ] 2>/dev/null && WARN="${WARN}D13 "
  [ "$D16" -gt 0 ] 2>/dev/null && WARN="${WARN}D16 "
  if [ -n "$WARN" ]; then
    echo "VERDICT FLOOR: WARN (soft signals: $WARN)"
  else
    echo "VERDICT FLOOR: NONE — no deterministic triggers"
  fi
fi
echo "========================================="
