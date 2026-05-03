'use strict';

// Baseline + ignore management.
//
// .clonesafe-baseline.json — finding-level suppression. Each entry is a
// stable fingerprint produced by sarif.fingerprint() plus optional
// `reason` and `expires` (ISO date) fields. Findings whose fingerprint
// matches an unexpired baseline entry are filtered before the verdict
// is computed, so existing tech debt doesn't keep failing CI.
//
// .clonesafe-ignore — path-based exclusion (gitignore-style). Untouched
// here; this module deliberately keeps finding-level suppression separate
// to avoid overloading the path-exclusion file.

const fs = require('node:fs');
const path = require('node:path');
const sarif = require('./sarif');

const BASELINE_FILENAME = '.clonesafe-baseline.json';

function load(cwd) {
  const p = path.resolve(cwd || process.cwd(), BASELINE_FILENAME);
  try {
    const txt = fs.readFileSync(p, 'utf8');
    const parsed = JSON.parse(txt);
    return Array.isArray(parsed.entries) ? parsed : { entries: [] };
  } catch {
    return null;
  }
}

function isExpired(entry) {
  if (!entry || !entry.expires) return false;
  const t = Date.parse(entry.expires);
  if (Number.isNaN(t)) return false;
  return t < Date.now();
}

function makeFilter(baseline) {
  if (!baseline || !Array.isArray(baseline.entries)) return () => false;
  const allowed = new Set(
    baseline.entries
      .filter(e => e && e.fingerprint && !isExpired(e))
      .map(e => e.fingerprint)
  );
  return (finding) => allowed.has(sarif.fingerprint(finding));
}

function applyToResult(result, baseline) {
  const filter = makeFilter(baseline);
  if (!baseline) return { result, suppressed: 0 };
  let suppressed = 0;
  const findings = (result.findings || []).filter(f => {
    if (filter(f)) { suppressed++; return false; }
    return true;
  });
  const iocFindings = (result.iocFindings || []).filter(f => {
    if (filter(f)) { suppressed++; return false; }
    return true;
  });
  return { result: { ...result, findings, iocFindings }, suppressed };
}

function writeBaseline(result, cwd) {
  const all = [...(result.findings || []), ...(result.iocFindings || [])];
  const entries = all.map(f => ({
    fingerprint: sarif.fingerprint(f),
    ruleId: f.ruleId || f.iocId || 'UNKNOWN',
    file: f.file || null,
    detail: f.detail || f.explanation || '',
    reason: 'baseline (auto-captured)',
    expires: null
  }));
  const out = {
    $schema: 'https://clonesafe.dev/schemas/baseline.v1.json',
    generated: new Date().toISOString(),
    note: 'Findings present at baseline capture. Future scans won\'t fail on these. Replace `reason` + set `expires` to force re-evaluation.',
    entries
  };
  const p = path.resolve(cwd || process.cwd(), BASELINE_FILENAME);
  fs.writeFileSync(p, JSON.stringify(out, null, 2) + '\n');
  return p;
}

module.exports = { load, applyToResult, writeBaseline, BASELINE_FILENAME };
