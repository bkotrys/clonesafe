#!/usr/bin/env node
'use strict';

// Docker-based test harness. Builds the sandbox image (if needed) and
// runs `npm install` for two representative fixtures inside it:
//
//   • clean-npm                   — a vanilla install. Should produce ZERO
//                                   network/SSH/proc-env anomalies under
//                                   --network=none.
//   • lifecycle-backgrounding     — has a malicious `prepare` hook that
//                                   tries to background a server. Under
//                                   --network=none the fetch will fail,
//                                   but strace must show the spawn attempt.
//
// If Docker is unavailable on the host we SKIP rather than fail — the
// static suite already covers correctness; this is the install-time guard
// rail. CI sets `needs: test` on the sandbox job and only runs it on
// runners with Docker.

const path = require('node:path');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runHarness, classifyReport, dockerAvailable } = require('../cli/lib/sandbox');

const FIXTURES = path.join(__dirname, 'fixtures');

if (!dockerAvailable()) {
  console.log('# SKIP: docker not available — install-time anomaly tests skipped.');
  console.log('# The static fixture suite (npm test) already covers detector correctness.');
  process.exit(0);
}

// Note: we use dependency-free fixtures for the sandbox tests because under
// --network=none any project with deps fails the registry resolution step
// before lifecycle scripts get a chance to run. The static suite covers the
// dependency-bearing fixtures; the sandbox suite covers install-time dynamic
// behavior.

test('sandbox: dependency-free install is CLEAN', { timeout: 180_000 }, () => {
  const report = runHarness(path.join(FIXTURES, 'sandbox-clean-empty'), { timeoutSec: 60 });
  const { verdict, reasons } = classifyReport(report);
  assert.equal(verdict, 'CLEAN', `expected CLEAN, got ${verdict} (${reasons.join(', ')}) — full: ${JSON.stringify(report)}`);
});

test('sandbox: malicious preinstall hook is detected as MALICIOUS', { timeout: 180_000 }, () => {
  const report = runHarness(path.join(FIXTURES, 'sandbox-malicious-hook'), { timeoutSec: 60 });
  const { verdict, reasons } = classifyReport(report);
  // The preinstall hook reads /proc/1/environ and ~/.ssh; either signal
  // alone is enough to escalate to MALICIOUS in our classifier.
  assert.equal(verdict, 'MALICIOUS', `expected MALICIOUS, got ${verdict} (${reasons.join(', ')}) — full: ${JSON.stringify(report)}`);
});
