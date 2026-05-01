#!/usr/bin/env node
'use strict';

const { parse } = require('./lib/url-parser');
const { fetchRepoMeta, fetchOwnerMeta, fetchContributors, fetchCommits, fetchAllFiles, downloadTarball } = require('./lib/github');
const { runAllChecks, computeVerdictFloor } = require('./lib/checks');
const { runDetectors } = require('./lib/detectors');
const { loadIOCs, checkPackageIOCs, checkDomainIOCs, checkOrgIOCs, checkHashIOCs } = require('./lib/iocs');
const { computeVerdict } = require('./lib/scoring');
const { formatVerdict, formatJSON, printProgress, clearProgress } = require('./lib/reporter');
const { extractDeps } = require('./lib/utils');
const { checkProvenance } = require('./lib/provenance');
const { checkGitHistory } = require('./lib/git-history');
const cache = require('./lib/cache');
const sandbox = require('./lib/sandbox');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const pkg = require('../package.json');

// ─── Argument parsing ───────────────────────────────────────────────

const args = process.argv.slice(2);
const flags = {
  json: args.includes('--json'),
  quiet: args.includes('--quiet'),
  noColor: args.includes('--no-color'),
  sandbox: args.includes('--sandbox'),
  provenance: args.includes('--provenance'),
  diff: args.includes('--diff'),
  help: args.includes('--help') || args.includes('-h'),
  version: args.includes('--version') || args.includes('-v')
};
const positional = args.filter(a => !a.startsWith('--') && !a.startsWith('-'));

if (flags.version) {
  console.log(`clonesafe ${pkg.version}`);
  process.exit(0);
}

if (flags.help || positional.length === 0) {
  console.log(`
  ${pkg.name} v${pkg.version}
  Pre-clone GitHub repo scanner

  Usage:
    clonesafe <github-url>          Scan a repo before cloning
    clonesafe owner/repo            Shorthand format

  Options:
    --json       Output structured JSON instead of formatted report
    --quiet      No output, exit code only (0 = safe, 1 = warn/block)
    --no-color   Disable ANSI colors
    --sandbox    Opt-in: after the static scan, materialize the repo into a
                 locked-down Docker container (no network, dropped caps,
                 read-only fs) and run \`npm install\` under strace, then
                 fold the captured anomalies (DNS attempts, shell/curl
                 spawns, ~/.ssh reads, /proc/<pid>/environ reads, fs-escape
                 writes outside /work) into the verdict. WARNING: this DOES
                 execute install-time code from the target repo — only use
                 when you would have cloned it anyway. Tarball is fetched
                 to host as raw bytes; extraction happens INSIDE the
                 container so the host never sees decompressed source.
                 Requires Docker on PATH.
    --provenance Query npm registry for each direct dep. Flags packages
                 that previously had SLSA provenance attestations and
                 then lost them in a newer version (publisher-token
                 hijack signal). Adds ~3-8s of network latency.
    --diff       Differential scan: compare against the cached findings
                 from a prior scan of this repo and surface only what's
                 new or removed. Cache lives in data/cache/ (gitignored).
    --help, -h   Show this help
    --version    Show version

  Environment:
    GITHUB_TOKEN   GitHub personal access token (increases API rate limit)
    NO_COLOR       Disable colors (standard)

  Examples:
    clonesafe https://github.com/expressjs/express
    clonesafe facebook/react
    clonesafe https://github.com/suspicious-org/take-home-test --json

  Exit codes:
    0   PROCEED or CAUTION — repo appears safe
    1   WARN or BLOCK — repo has suspicious patterns
`);
  process.exit(0);
}

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  const urlArg = positional[0];

  // Parse URL
  let parsed;
  try {
    parsed = parse(urlArg);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(2);
  }

  const { owner, repo, ref } = parsed;

  if (!flags.quiet && !flags.json) {
    console.log(`\n  clonesafe v${pkg.version} — scanning ${owner}/${repo}${ref !== 'HEAD' ? ` (${ref})` : ''}\n`);
  }

  // Load IOC databases
  printProgress('Loading IOC databases...');
  const iocDB = loadIOCs();

  // Fetch repo metadata
  printProgress('Fetching repo metadata...');
  const repoMeta = await fetchRepoMeta(owner, repo);
  if (!repoMeta) {
    clearProgress();
    console.error(`Error: Repository ${owner}/${repo} not found or is private.`);
    process.exit(2);
  }

  // Fetch additional metadata in parallel
  printProgress('Fetching owner, contributors, commits...');
  const [ownerMeta, contributors, commits] = await Promise.all([
    fetchOwnerMeta(owner),
    fetchContributors(owner, repo),
    fetchCommits(owner, repo)
  ]);

  // Fetch files
  printProgress('Fetching source files...');
  const actualRef = ref === 'HEAD' ? repoMeta.default_branch || 'main' : ref;
  const files = await fetchAllFiles(owner, repo, actualRef);

  clearProgress();

  if (!flags.quiet && !flags.json) {
    console.log(`  Fetched ${files.size} file${files.size !== 1 ? 's' : ''} for analysis`);
  }

  // Phase 0: Deterministic checks
  printProgress('Running deterministic checks (D1-D16)...');
  const checkResults = runAllChecks(files, iocDB, { owner });
  const floor = computeVerdictFloor(checkResults);

  // Phase A: Detector rules
  printProgress('Running detector rules...');
  const metadata = { repoMeta, ownerMeta, contributors, commits, owner, repo };
  const findings = runDetectors(files, metadata);

  // IOC cross-reference
  printProgress('Cross-referencing IOC databases...');
  const iocFindings = [];
  const pkgJson = files.get('package.json');
  if (pkgJson) {
    const deps = extractDeps(pkgJson);
    iocFindings.push(...checkPackageIOCs(deps.all, iocDB));
  }
  iocFindings.push(...checkDomainIOCs(files, iocDB));
  iocFindings.push(...checkOrgIOCs(owner, iocDB));
  iocFindings.push(...checkHashIOCs(files, iocDB));

  // Git-history anomalies (force-push, orphaned tags, signature ratio).
  // Cheap (3 API calls), so always run.
  printProgress('Checking git-history signals...');
  const ghToken = process.env.GITHUB_TOKEN;
  const historyFindings = await checkGitHistory(owner, repo, actualRef, ghToken);
  findings.push(...historyFindings);

  // Optional: npm provenance check (--provenance flag).
  let provenanceFindings = [];
  if (flags.provenance && pkgJson) {
    printProgress('Checking npm provenance for direct deps...');
    try {
      const deps = extractDeps(pkgJson);
      provenanceFindings = await checkProvenance(deps.all);
      findings.push(...provenanceFindings);
    } catch (err) {
      provenanceFindings = [{ error: err.message }];
    }
  }

  // Phase B: Scoring and verdict
  printProgress('Computing verdict...');
  const verdict = computeVerdict(floor, findings, iocFindings);

  clearProgress();

  // Optional Phase D: Docker sandbox install
  let sandboxResult = null;
  if (flags.sandbox) {
    try {
      sandboxResult = await runSandboxPhase(owner, repo, actualRef, flags);
      if (sandboxResult && sandboxResult.classification && sandboxResult.classification.verdict === 'MALICIOUS') {
        // Sandbox-detected anomaly is BLOCK-equivalent.
        verdict.verdict = 'BLOCK';
      } else if (sandboxResult && sandboxResult.classification && sandboxResult.classification.verdict === 'SUSPICIOUS' && verdict.verdict === 'PROCEED') {
        verdict.verdict = 'CAUTION';
      }
    } catch (err) {
      sandboxResult = { error: err.message };
    }
  }

  // Differential scan: compare against the prior cached run, if any.
  let diffResult = null;
  if (flags.diff) {
    const prior = cache.load(owner, repo);
    if (prior) diffResult = cache.diff(prior, [...findings, ...iocFindings]);
  }
  cache.save(owner, repo, verdict.verdict, [...findings, ...iocFindings]);

  // Build result object
  const result = {
    owner,
    repo,
    ref: actualRef,
    verdict: verdict.verdict,
    score: verdict.score,
    verdictFloor: verdict.verdictFloor,
    floorTriggers: verdict.floorTriggers,
    checks: checkResults,
    findings,
    iocFindings,
    sandbox: sandboxResult,
    diff: diffResult
  };

  // Output
  if (flags.json) {
    console.log(formatJSON(result));
  } else if (!flags.quiet) {
    console.log(formatVerdict(result, flags.noColor));
  }

  // Exit code
  const exitCode = (verdict.verdict === 'PROCEED' || verdict.verdict === 'CAUTION') ? 0 : 1;
  process.exit(exitCode);
}

async function runSandboxPhase(owner, repo, ref, flags) {
  if (!sandbox.dockerAvailable()) {
    return { error: 'docker not available on PATH; skipping --sandbox phase' };
  }
  if (!flags.quiet && !flags.json) {
    console.log('  [sandbox] Docker harness enabled — install will run inside locked-down container.');
  }
  // We download the tarball to a host temp dir as raw bytes (NOT extracted)
  // and hand it to the sandbox harness, which extracts inside the container.
  // This means the host never sees decompressed source from the target repo —
  // a tarball with malicious symlinks (zip-slip) can only escape to the
  // container's tmpfs, not the host filesystem.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clonesafe-sb-'));
  const tarPath = path.join(tmp, 'repo.tar.gz');
  try {
    printProgress('  [sandbox] downloading repo tarball...');
    await downloadTarball(owner, repo, ref, tarPath);
    clearProgress();
    printProgress('  [sandbox] extracting + running npm install under strace inside container...');
    const report = sandbox.runHarnessOnTarball(tarPath, { timeoutSec: 90 });
    clearProgress();
    if (report.status === 'skipped') return { skipped: report.reason || 'skipped' };
    const classification = sandbox.classifyReport(report);
    return { report, classification };
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

main().catch(err => {
  clearProgress();
  console.error(`\nError: ${err.message}`);
  if (err.message.includes('rate limit')) {
    process.exit(3);
  }
  process.exit(2);
});
