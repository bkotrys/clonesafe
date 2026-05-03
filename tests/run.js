#!/usr/bin/env node
'use strict';

// Zero-dependency test runner for clonesafe's deterministic checks.
// Loads each fixture directory as a virtual file Map and asserts which
// D-codes fire and what verdict floor is computed.
//
// Run: npm test  (or: node tests/run.js)

const fs = require('fs');
const path = require('path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

const { runAllChecks, computeVerdictFloor } = require('../cli/lib/checks');
const { runDetectors } = require('../cli/lib/detectors');
const { loadIOCs } = require('../cli/lib/iocs');

const FIXTURES_DIR = path.join(__dirname, 'fixtures');

function loadFixture(dir) {
  const files = new Map();
  const root = path.join(FIXTURES_DIR, dir);
  function walk(rel) {
    const abs = path.join(root, rel);
    for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
      const next = rel ? path.posix.join(rel, ent.name) : ent.name;
      if (ent.isDirectory()) walk(next);
      else if (ent.isFile()) files.set(next, fs.readFileSync(path.join(abs, ent.name), 'utf8'));
    }
  }
  walk('');
  return files;
}

function runFixture(name, metadata = {}) {
  const files = loadFixture(name);
  const iocDB = loadIOCs();
  const checks = runAllChecks(files, iocDB, metadata);
  const floor = computeVerdictFloor(checks);
  const findings = runDetectors(files, metadata);
  return { files, checks, floor, findings };
}

// ─── Cases ──────────────────────────────────────────────────────────
//
// Each case asserts:
//   • which D-codes must be > 0 (mustFire)
//   • which D-codes must be 0 (mustNotFire)
//   • the verdict floor (BLOCK / WARN / NONE)
//   • optionally: detector ruleIds that must appear in findings

const CASES = [
  {
    name: 'clean-npm',
    floor: 'NONE',
    mustFire: [],
    mustNotFire: ['D1', 'D2', 'D3', 'D5', 'D6', 'D8', 'D11', 'D12', 'D13', 'D14', 'D17', 'D18', 'D19', 'D20']
  },
  {
    name: 'lifecycle-backgrounding',
    floor: 'BLOCK',
    mustFire: ['D1', 'D2'],
    mustNotFire: []
  },
  {
    name: 'env-exfil-source',
    floor: 'BLOCK',
    mustFire: ['D4', 'D5', 'D6'],
    mustNotFire: []
  },
  {
    name: 'lockfile-non-registry-pnpm',
    floor: 'WARN',
    mustFire: ['D13'],
    mustNotFire: ['D14']
  },
  {
    name: 'lockfile-git-ssh-yarn',
    floor: 'BLOCK',
    mustFire: ['D14'],
    mustNotFire: []
  },
  {
    name: 'python-setup-shellout',
    floor: 'BLOCK',
    mustFire: ['D17'],
    mustNotFire: ['D18', 'D19', 'D20']
  },
  {
    name: 'python-pyproject-custom-backend',
    floor: 'WARN',
    mustFire: ['D18'],
    mustNotFire: ['D17', 'D19', 'D20']
  },
  {
    name: 'rust-buildrs-network',
    floor: 'BLOCK',
    mustFire: ['D19'],
    mustNotFire: ['D17', 'D18', 'D20']
  },
  {
    name: 'go-generate-curl',
    floor: 'WARN',
    mustFire: ['D20'],
    mustNotFire: ['D17', 'D18', 'D19']
  },
  {
    name: 'prompt-injection-readme',
    floor: 'BLOCK',
    mustFire: ['D8'],
    mustNotFire: []
  },
  {
    name: 'clean-multi-ecosystem',
    floor: 'NONE',
    mustFire: [],
    mustNotFire: ['D17', 'D18', 'D19', 'D20']
  },
  {
    name: 'sandbox-clean-empty',
    floor: 'NONE',
    mustFire: [],
    mustNotFire: ['D1', 'D2', 'D3', 'D5', 'D6', 'D17', 'D18', 'D19', 'D20']
  },
  {
    name: 'sandbox-malicious-hook',
    floor: 'BLOCK',
    mustFire: ['D1'],
    mustNotFire: []
  },
  // ── v0.4 detector fixtures ───────────────────────────────────────
  {
    name: 'gha-known-bad-sha',
    floor: 'BLOCK',
    mustFire: ['D24'],
    mustNotFire: ['D24u']
  },
  {
    name: 'gha-unpinned-tag',
    floor: 'WARN',
    mustFire: ['D24u'],
    mustNotFire: ['D24']
  },
  {
    name: 'vscode-task-folderopen',
    floor: 'WARN',
    mustFire: ['D26'],
    mustNotFire: []
  },
  {
    name: 'dockerfile-mutable-tag',
    floor: 'WARN',
    mustFire: ['D27'],
    mustNotFire: []
  },
  {
    name: 'go-init-network',
    floor: 'WARN',
    mustFire: ['D28'],
    mustNotFire: ['D20']
  },
  {
    name: 'worm-shai-hulud',
    floor: 'BLOCK',
    mustFire: ['D29'],
    mustNotFire: []
  },
  {
    name: 'dprk-hexeval',
    floor: 'BLOCK',
    mustFire: ['D30'],
    mustNotFire: []
  },
  {
    name: 'secret-leaked-aws',
    floor: 'WARN',
    mustFire: ['D31'],
    mustNotFire: []
  },
  {
    name: 'python-pth-file',
    floor: 'BLOCK',
    mustFire: ['D32'],
    mustNotFire: []
  },
  {
    name: 'docs-prompt-injection',
    floor: 'WARN',
    mustFire: ['D25'],
    mustNotFire: ['D8']
  },
  {
    name: 'starjack-popular',
    floor: 'BLOCK',
    mustFire: ['D33'],
    mustNotFire: [],
    metadata: { owner: 'attacker', repo: 'lure-react' }
  },
  {
    name: 'recruiter-lure-combo',
    floor: 'BLOCK',
    mustFire: ['D34'],
    mustNotFire: [],
    metadata: {
      owner: 'fly-by-night',
      repo: 'frontend-takehome',
      repoMeta: { created_at: new Date(Date.now() - 5 * 86400000).toISOString() },
      ownerMeta: { created_at: new Date(Date.now() - 10 * 86400000).toISOString(), type: 'User' },
      contributors: [{ login: 'fly-by-night' }]
    }
  }
];

for (const c of CASES) {
  test(`fixture: ${c.name}`, () => {
    const { checks, floor } = runFixture(c.name, c.metadata || {});
    for (const code of c.mustFire) {
      assert.ok(checks[code] > 0, `expected ${code} > 0 in ${c.name}, got ${code}=${checks[code]} (all: ${JSON.stringify(checks)})`);
    }
    for (const code of c.mustNotFire) {
      assert.equal(checks[code], 0, `expected ${code} === 0 in ${c.name}, got ${code}=${checks[code]}`);
    }
    assert.equal(floor.floor, c.floor, `expected floor=${c.floor} in ${c.name}, got ${floor.floor} (triggers: ${floor.triggers.join(',')})`);
  });
}

// Sanity: detectors module still loads and runs on every fixture without throwing.
test('runDetectors smoke test across all fixtures', () => {
  for (const c of CASES) {
    const { findings } = runFixture(c.name, c.metadata || {});
    assert.ok(Array.isArray(findings), `findings should be array for ${c.name}`);
  }
});

// ── unit tests for v0.5 modules ──────────────────────────────────────

test('sarif: emits 2.1.0 doc with stable fingerprints', () => {
  const sarif = require('../cli/lib/sarif');
  const result = {
    owner: 'foo', repo: 'bar', verdict: 'WARN', score: 30,
    verdictFloor: 'WARN', floorTriggers: ['D24u'],
    findings: [{ ruleId: 'D24u', detector: 'workflows', risk: 'HIGH', weight: 25, file: '.github/workflows/ci.yml', line: 5, match: 'codecov/codecov-action@v4', detail: 'unpinned' }],
    iocFindings: []
  };
  const doc = sarif.emit(result);
  assert.equal(doc.version, '2.1.0');
  assert.equal(doc.runs.length, 1);
  assert.equal(doc.runs[0].results.length, 1);
  const fp1 = doc.runs[0].results[0].partialFingerprints.detectorHash;
  // Same input → same fingerprint.
  const doc2 = sarif.emit(result);
  assert.equal(fp1, doc2.runs[0].results[0].partialFingerprints.detectorHash);
  assert.equal(fp1.length, 32);
});

test('sbom: cyclonedx + spdx structures are well-formed', () => {
  const sbom = require('../cli/lib/sbom');
  const deps = [{ name: 'react', version: '18.0.0', ecosystem: 'npm' }];
  const cdx = sbom.emitCycloneDX({ owner: 'foo', repo: 'bar', ref: 'main', deps, findings: [] });
  assert.equal(cdx.bomFormat, 'CycloneDX');
  assert.equal(cdx.specVersion, '1.6');
  assert.equal(cdx.components[0].purl, 'pkg:npm/react@18.0.0');
  const spdx = sbom.emitSPDX({ owner: 'foo', repo: 'bar', ref: 'main', deps });
  assert.equal(spdx.spdxVersion, 'SPDX-2.3');
  assert.equal(spdx.packages.length, 2); // root + 1 dep
  assert.equal(spdx.relationships[0].relationshipType, 'DEPENDS_ON');
});

test('baseline: applyToResult drops fingerprints, recomputes verdict', () => {
  const baseline = require('../cli/lib/baseline');
  const sarif = require('../cli/lib/sarif');
  const finding = { ruleId: 'D24u', detector: 'workflows', risk: 'HIGH', weight: 25, file: '.github/workflows/ci.yml', match: 'codecov/codecov-action@v4', detail: 'unpinned' };
  const fp = sarif.fingerprint(finding);
  const result = { findings: [finding], iocFindings: [] };
  const baselineDoc = { entries: [{ fingerprint: fp, reason: 'grandfathered' }] };
  const out = baseline.applyToResult(result, baselineDoc);
  assert.equal(out.suppressed, 1);
  assert.equal(out.result.findings.length, 0);
});

test('baseline: expired entries do not suppress', () => {
  const baseline = require('../cli/lib/baseline');
  const sarif = require('../cli/lib/sarif');
  const finding = { ruleId: 'D24u', file: 'a.yml', match: 'foo', detail: 'd' };
  const fp = sarif.fingerprint(finding);
  const result = { findings: [finding], iocFindings: [] };
  const expired = { entries: [{ fingerprint: fp, expires: '2020-01-01' }] };
  const out = baseline.applyToResult(result, expired);
  assert.equal(out.suppressed, 0);
  assert.equal(out.result.findings.length, 1);
});

test('rules: guarddog-lite pack loads and applies', () => {
  const rules = require('../cli/lib/rules');
  const pack = rules.resolvePack('guarddog');
  assert.equal(pack.name, 'guarddog-lite');
  assert.ok(Array.isArray(pack.rules) && pack.rules.length > 0);
  // Synthetic Python file that should match GD-PY-EXEC-AT-IMPORT.
  const files = new Map([['mod.py', 'import os\nos.system("echo pwned")\n']]);
  const findings = rules.applyExtraRules(files, pack);
  assert.ok(findings.some(f => f.ruleId === 'GD-PY-EXEC-AT-IMPORT'),
    `expected GD-PY-EXEC-AT-IMPORT to fire, got: ${findings.map(f => f.ruleId).join(',')}`);
});

test('rules: applies_to filters by extension', () => {
  const rules = require('../cli/lib/rules');
  const pack = {
    name: 'test',
    rules: [{ id: 'JS-ONLY', risk: 'HIGH', weight: 10, applies_to: '*.js', regex: 'evil' }]
  };
  const files = new Map([['a.py', 'evil'], ['b.js', 'evil']]);
  const findings = rules.applyExtraRules(files, pack);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'b.js');
});

test('package-age: parses duration formats', () => {
  const pa = require('../cli/lib/package-age');
  assert.equal(pa.parseDuration('48h'), 48 * 3600 * 1000);
  assert.equal(pa.parseDuration('7d'), 7 * 86400 * 1000);
  assert.equal(pa.parseDuration('2w'), 14 * 86400 * 1000);
  assert.equal(pa.parseDuration(''), 0);
  assert.equal(pa.parseDuration('garbage'), 0);
});

test('utils: extractMultiEcosystemDeps covers npm/pypi/rubygems/composer', () => {
  const { extractMultiEcosystemDeps } = require('../cli/lib/utils');
  const files = new Map([
    ['package.json', '{"dependencies":{"react":"^18.0.0"}}'],
    ['pyproject.toml', '[project]\ndependencies = [\n  "requests>=2.31.0",\n]'],
    ['Gemfile', "gem 'rails', '~> 7.0'\n"],
    ['composer.json', '{"require":{"php":">=8.1","monolog/monolog":"^3.0"}}']
  ]);
  const deps = extractMultiEcosystemDeps(files);
  const ecos = new Set(deps.map(d => d.ecosystem));
  assert.ok(ecos.has('npm'));
  assert.ok(ecos.has('pypi'));
  assert.ok(ecos.has('rubygems'));
  assert.ok(ecos.has('composer'));
  // php pseudo-dep should be filtered out
  assert.ok(!deps.some(d => d.name === 'php'));
});

test('osv: ecosystem mapping is correct', () => {
  const osv = require('../cli/lib/osv');
  assert.equal(osv.ecoFromManifest('npm'), 'npm');
  assert.equal(osv.ecoFromManifest('pypi'), 'PyPI');
  assert.equal(osv.ecoFromManifest('rubygems'), 'RubyGems');
  assert.equal(osv.ecoFromManifest('cargo'), 'crates.io');
  assert.equal(osv.ecoFromManifest('go'), 'Go');
  assert.equal(osv.ecoFromManifest('composer'), 'Packagist');
  assert.equal(osv.ecoFromManifest('unknown-eco'), null);
});

test('remediation: returns concrete fix for known rule IDs', () => {
  const { getRemediation } = require('../cli/lib/remediation');
  assert.ok(getRemediation('LS-004'), 'LS-004 should have remediation');
  assert.ok(getRemediation('D29'), 'D29 (worm) should have remediation');
  assert.ok(getRemediation('OSV-MAL'), 'OSV-MAL should have remediation');
  assert.equal(getRemediation('NEVER-DEFINED'), null);
});
