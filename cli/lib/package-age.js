'use strict';

// Package-age cool-down gate.
//
// Many supply-chain attacks (Shai-Hulud waves, axios 2026, lottie-player,
// recurring DPRK pushes) are caught by registry takedowns within hours to
// days. A "your direct deps must be at least N hours old" gate is a free,
// pure-heuristic defense that defangs a large fraction of fresh-publish
// attacks. Aikido's Safe Chain ships with a 48h default; we follow suit.
//
// Currently npm-only. PyPI / RubyGems support is a future addition; the
// extractDeps shape is generic so the helper signature won't change.

const VERSION = require('../../package.json').version;

const REGISTRY_BASE = 'https://registry.npmjs.org';
const REQUEST_TIMEOUT_MS = 5000;
const CONCURRENCY = 6;

function parseDuration(spec) {
  if (typeof spec === 'number') return spec;
  if (!spec) return 0;
  const m = String(spec).match(/^(\d+)\s*(s|m|h|d|w)?$/i);
  if (!m) return 0;
  const n = parseInt(m[1], 10);
  const unit = (m[2] || 'h').toLowerCase();
  const mult = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[unit];
  return n * mult * 1000;
}

async function fetchPackumentTime(name) {
  const url = `${REGISTRY_BASE}/${encodeURIComponent(name).replace(/^%40/, '@').replace(/%2F/g, '/')}`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': `clonesafe/${VERSION}`,
        // Slimmer payload — `time` is the only field we need.
        'Accept': 'application/vnd.npm.install-v1+json'
      },
      signal: ctrl.signal
    });
    if (!res.ok) return null;
    const body = await res.json();
    return body && body.time ? body.time : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// `deps` is the all-deps map from extractDeps. `minAge` is a duration
// string (e.g. '48h', '7d') or millisecond number. Returns findings.
async function checkAges(deps, minAgeSpec) {
  const minMs = parseDuration(minAgeSpec);
  if (!minMs) return [];

  const names = Object.keys(deps || {});
  if (names.length === 0) return [];

  const findings = [];
  const now = Date.now();
  // Naive bounded-parallel pool.
  for (let i = 0; i < names.length; i += CONCURRENCY) {
    const slice = names.slice(i, i + CONCURRENCY);
    const times = await Promise.all(slice.map(fetchPackumentTime));
    for (let j = 0; j < slice.length; j++) {
      const name = slice[j];
      const time = times[j];
      if (!time) continue;
      const wantedRaw = String(deps[name] || '').replace(/^[\^~>=<\s]+/, '');
      // If the requested range resolves to a specific version with a
      // timestamp, prefer that; else fall back to `created` (first publish).
      let publishedAt = time[wantedRaw] || time.created;
      if (!publishedAt) continue;
      const ageMs = now - new Date(publishedAt).getTime();
      if (ageMs < minMs) {
        const ageHours = Math.floor(ageMs / 3600000);
        findings.push({
          ruleId: 'AGE-001',
          risk: 'HIGH',
          weight: 25,
          match: `${name}@${wantedRaw || '*'} (${ageHours}h old)`,
          explanation: `Direct dependency ${name}@${wantedRaw || '*'} was published ${ageHours}h ago — below your --min-age cool-down`
        });
      }
    }
  }
  return findings;
}

module.exports = { checkAges, parseDuration };
