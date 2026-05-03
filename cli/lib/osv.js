'use strict';

// OSV.dev / OpenSSF Malicious Packages lookup.
//
// OSV ingests the OpenSSF malicious-packages feed, so a successful
// `querybatch` lookup against api.osv.dev returns GHSA-MAL-* IDs alongside
// regular CVEs. We surface only the malware advisories — known-bad CVEs
// are out of scope (clonesafe is a malicious-package detector, not an SCA).
//
// Free public API, no auth required, generous rate limits. Conservative
// timeout + concurrency limit to keep `vet-repo` snappy.

const VERSION = require('../../package.json').version;

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const REQUEST_TIMEOUT_MS = 8000;
const MAX_BATCH = 100;

function ecoFromManifest(manifestKey) {
  switch (manifestKey) {
    case 'npm': return 'npm';
    case 'pypi': return 'PyPI';
    case 'rubygems': return 'RubyGems';
    case 'cargo': return 'crates.io';
    case 'go': return 'Go';
    case 'composer': return 'Packagist';
    case 'maven': return 'Maven';
    default: return null;
  }
}

function buildQueries(deps) {
  const out = [];
  for (const { name, version, ecosystem } of deps) {
    const eco = ecoFromManifest(ecosystem);
    if (!eco || !name) continue;
    const q = { package: { name, ecosystem: eco } };
    if (version) q.version = String(version).replace(/^[\^~>=<\s]+/, '');
    out.push(q);
  }
  return out;
}

async function postJson(url, body) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `clonesafe/${VERSION}`
      },
      body: JSON.stringify(body),
      signal: ctrl.signal
    });
    if (!res.ok) throw new Error(`OSV ${res.status} ${res.statusText}`);
    return res.json();
  } finally {
    clearTimeout(t);
  }
}

// queryDeps takes [{ name, version, ecosystem }, ...] and returns
// findings: [{ ruleId, risk, weight, file, match, explanation, ghsa, ecosystem }].
async function queryDeps(deps) {
  const queries = buildQueries(deps);
  if (queries.length === 0) return [];

  const findings = [];
  for (let i = 0; i < queries.length; i += MAX_BATCH) {
    const slice = queries.slice(i, i + MAX_BATCH);
    let resp;
    try {
      resp = await postJson(OSV_BATCH_URL, { queries: slice });
    } catch (err) {
      // OSV unreachable — surface a single low-severity advisory note,
      // never silently swallow a network failure.
      findings.push({
        ruleId: 'OSV-ERR',
        risk: 'LOW',
        weight: 0,
        match: 'osv.dev unreachable',
        explanation: `OSV lookup failed: ${err.message}`
      });
      return findings;
    }
    const results = (resp && resp.results) || [];
    for (let j = 0; j < results.length; j++) {
      const dep = deps[i + j];
      const vulns = (results[j] && results[j].vulns) || [];
      for (const v of vulns) {
        if (!v.id) continue;
        const isMalware = v.id.startsWith('MAL-') || v.id.startsWith('GHSA-MAL-') || /malware|malicious/i.test(v.summary || '');
        if (!isMalware) continue;
        findings.push({
          ruleId: 'OSV-MAL',
          ghsa: v.id,
          ecosystem: dep.ecosystem,
          risk: 'CRITICAL',
          weight: 50,
          match: `${dep.name}@${dep.version || '*'} → ${v.id}`,
          explanation: `${dep.name}@${dep.version || '*'} matches ${v.id}: ${v.summary || 'OpenSSF malicious-packages advisory'}`
        });
      }
    }
  }
  return findings;
}

module.exports = { queryDeps, ecoFromManifest };
