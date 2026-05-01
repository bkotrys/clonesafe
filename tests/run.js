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

function runFixture(name) {
  const files = loadFixture(name);
  const iocDB = loadIOCs();
  const checks = runAllChecks(files, iocDB);
  const floor = computeVerdictFloor(checks);
  const findings = runDetectors(files, {});
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
  }
];

for (const c of CASES) {
  test(`fixture: ${c.name}`, () => {
    const { checks, floor } = runFixture(c.name);
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
    const { findings } = runFixture(c.name);
    assert.ok(Array.isArray(findings), `findings should be array for ${c.name}`);
  }
});
