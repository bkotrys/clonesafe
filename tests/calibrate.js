#!/usr/bin/env node
'use strict';

// Calibration test: scan a curated list of clean, high-traffic repos and
// assert every one returns PROCEED or CAUTION (i.e. no false-positive
// WARN/BLOCK on widely-used legitimate code). Skips gracefully without a
// GitHub token to avoid noisy rate-limit failures in CI.
//
// Run: npm run calibrate    (or: node tests/calibrate.js)

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');

const REPOS = [
  // Core JS ecosystem
  'expressjs/express',
  'facebook/react',
  'vuejs/vue',
  'sveltejs/svelte',
  'angular/angular',
  'nodejs/node',
  // Lifecycle-script-heavy but legitimate
  'typicode/husky',
  'puppeteer/puppeteer',
  'lerna/lerna',
  // Other ecosystems
  'tokio-rs/tokio',           // Rust — exercises D19
  'psf/requests',             // Python — exercises D17/D18
  'pallets/flask',
  'rails/rails',              // Ruby — exercises D21
  'laravel/laravel'           // PHP — exercises D22
];

// Resolve a token once at the test-suite level. We export it into the env
// so each scan child inherits it without spawning gh repeatedly (which
// would consume our gh-side rate limit).
function resolveToken() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  const r = spawnSync('gh', ['auth', 'token'], { encoding: 'utf8', timeout: 1500, stdio: ['ignore', 'pipe', 'ignore'] });
  if (r.status === 0 && r.stdout) {
    const tok = r.stdout.trim();
    if (tok.length > 10) return tok;
  }
  return null;
}

const TOKEN = resolveToken();
if (!TOKEN) {
  console.log('# SKIP: no GITHUB_TOKEN and no `gh auth token` — calibration needs an auth\'d API quota.');
  process.exit(0);
}

function scan(slug) {
  const r = spawnSync('node', ['cli/index.js', slug, '--json', '--no-color'], {
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, GITHUB_TOKEN: TOKEN }
  });
  if (r.error) throw r.error;
  // CLI exits non-zero on WARN/BLOCK; that's expected, parse stdout regardless.
  try {
    return JSON.parse(r.stdout);
  } catch {
    return null;
  }
}

for (const slug of REPOS) {
  test(`calibration: ${slug} returns PROCEED or CAUTION`, { timeout: 90_000 }, () => {
    const result = scan(slug);
    assert.ok(result, `failed to scan ${slug}`);
    const acceptable = ['PROCEED', 'CAUTION'];
    if (!acceptable.includes(result.verdict)) {
      const findings = (result.findings || []).map(f => `${f.ruleId} ${f.match || ''}`).join('\n  - ');
      assert.fail(
        `${slug} returned ${result.verdict} (score ${result.score}) — calibration baseline is "no false-positive WARN/BLOCK on top-50 clean repos".\nFindings:\n  - ${findings}`
      );
    }
  });
}
