'use strict';

// Per-repo verdict + finding-fingerprint cache used by --diff.
// Lives at data/cache/{owner}__{repo}.json (gitignored).

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const CACHE_DIR = path.resolve(__dirname, '..', '..', 'data', 'cache');

function key(owner, repo) {
  // Lossy character substitution can collide (`foo/bar.baz` and `foo/bar_baz`
  // both → `foo__bar_baz`). Mix in a SHA-256 prefix of the original tuple so
  // every distinct (owner, repo) pair gets a distinct cache file even when
  // their sanitized forms coincide.
  const safe = `${owner}__${repo}`.toLowerCase().replace(/[^a-z0-9_-]/g, '_');
  const tag = crypto.createHash('sha256').update(`${owner}/${repo}`).digest('hex').slice(0, 8);
  return `${safe}-${tag}`;
}

function fingerprintFinding(f) {
  // A finding's identity is its rule + file + match. Counts/weights can
  // shift between runs as detectors evolve; we don't want every clonesafe
  // upgrade to be reported as "new findings."
  // Full SHA-256 — earlier prototypes used a 12-hex-char SHA-1 prefix
  // (~48 bits) which is collision-attackable in principle. The cost of
  // the longer hash is trivial (~32 hex chars per finding in the cache).
  const id = `${f.ruleId || f.iocId || ''}|${f.file || ''}|${f.match || ''}`;
  return crypto.createHash('sha256').update(id).digest('hex');
}

function sanitizeForReport(s) {
  // Defensive: truncate and strip characters that would break out of the
  // GitHub Actions Markdown step-summary fenced JSON block (the entire
  // finding flows through there via reporter.js / action.yml).
  return String(s == null ? '' : s).slice(0, 500).replace(/`/g, '​`');
}

function load(owner, repo) {
  try {
    const file = path.join(CACHE_DIR, `${key(owner, repo)}.json`);
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    // Trust nothing on disk. The cache file lives at a user-writable path,
    // so any process running as the same uid can poison it.
    if (!parsed || typeof parsed !== 'object') return null;
    if (!Array.isArray(parsed.fingerprints)) return null;
    parsed.fingerprints = parsed.fingerprints
      .filter(p => p && typeof p === 'object' && typeof p.fp === 'string' && p.fp.length === 64)
      .map(p => ({
        fp: p.fp,
        ruleId: typeof p.ruleId === 'string' ? sanitizeForReport(p.ruleId) : '',
        match: typeof p.match === 'string' ? sanitizeForReport(p.match) : ''
      }));
    if (typeof parsed.verdict !== 'string') parsed.verdict = '';
    if (typeof parsed.timestamp !== 'string') parsed.timestamp = '';
    return parsed;
  } catch {
    return null;
  }
}

function save(owner, repo, verdict, findings) {
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    const file = path.join(CACHE_DIR, `${key(owner, repo)}.json`);
    const data = {
      timestamp: new Date().toISOString(),
      verdict,
      fingerprints: findings.map(f => ({ fp: fingerprintFinding(f), ruleId: f.ruleId || f.iocId, match: f.match }))
    };
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch {
    // Cache is best-effort. A read-only filesystem just disables --diff.
  }
}

/**
 * Compare current findings against a cached prior run.
 * Returns { added: [...], removed: [...], unchanged: [...] }.
 */
function diff(prior, currentFindings) {
  if (!prior || !prior.fingerprints) return null;
  const priorMap = new Map(prior.fingerprints.map(p => [p.fp, p]));
  const currentMap = new Map(currentFindings.map(f => [fingerprintFinding(f), f]));

  const added = [];
  const removed = [];
  const unchanged = [];
  for (const [fp, f] of currentMap) {
    if (priorMap.has(fp)) unchanged.push(f);
    else added.push(f);
  }
  for (const [fp, p] of priorMap) {
    if (!currentMap.has(fp)) removed.push(p);
  }
  return { added, removed, unchanged, priorTimestamp: prior.timestamp, priorVerdict: prior.verdict };
}

module.exports = { load, save, diff };
