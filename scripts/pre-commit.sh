#!/usr/bin/env bash
# Pre-commit hook that re-vets any GitHub repo URL referenced in newly-added
# lockfile entries before the commit lands.
#
# Install:
#   ln -s ../../scripts/pre-commit.sh .git/hooks/pre-commit
#
# Skips quietly if `clonesafe` (or `npx clonesafe`) isn't on PATH so it
# doesn't break developers who don't have it installed yet.

set -euo pipefail
IFS=$'\n\t'

if ! command -v clonesafe >/dev/null 2>&1 && ! command -v npx >/dev/null 2>&1; then
  exit 0
fi

# Find unique github URLs added to staged lockfiles. We anchor the URL
# regex with strict character classes (no period or other token-adjacent
# chars allowed at the end) and use a word-boundary so a maliciously
# crafted lockfile entry can't slide a sibling URL through (e.g.
# `github.com/aws/aws-sdk-js.evil` previously matched as a single token).
LOCKFILES='package-lock.json yarn.lock pnpm-lock.yaml bun.lock'
URLS_RAW=$(git diff --cached --unified=0 -- $LOCKFILES 2>/dev/null \
  | grep -E '^\+' \
  | grep -oE 'https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+\b' \
  | sort -u || true)

if [ -z "$URLS_RAW" ]; then
  exit 0
fi

# Use the safer base-command form: an array, so quoting is preserved when
# we append the URL.
if command -v clonesafe >/dev/null 2>&1; then
  CMD=(clonesafe)
else
  CMD=(npx -y -p clonesafe -- clonesafe)
fi

failed=0
# while-read instead of `for x in $URLS` so any whitespace/newline shenanigans
# in URLs (which our regex already refuses) are still handled correctly.
while IFS= read -r url; do
  [ -z "$url" ] && continue
  # Final defense in depth: re-validate against the same anchored shape
  # before invoking clonesafe with it.
  if ! printf '%s' "$url" | grep -qE '^https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+$'; then
    echo "clonesafe: refusing malformed URL: $url" >&2
    continue
  fi
  echo "clonesafe: vetting newly referenced $url"
  if ! "${CMD[@]}" -- "$url" --quiet --no-color; then
    echo "  → BLOCK/WARN — see 'clonesafe $url' for details" >&2
    failed=1
  fi
done <<< "$URLS_RAW"

if [ "$failed" -ne 0 ]; then
  echo "" >&2
  echo "Pre-commit blocked. Re-run with --no-verify only after manual review." >&2
  exit 1
fi
