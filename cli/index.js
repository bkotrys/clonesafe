#!/usr/bin/env node
'use strict';

const { parse } = require('./lib/url-parser');
const { fetchRepoMeta, fetchOwnerMeta, fetchContributors, fetchCommits, fetchAllFiles } = require('./lib/github');
const { runAllChecks, computeVerdictFloor } = require('./lib/checks');
const { runDetectors } = require('./lib/detectors');
const { loadIOCs, checkPackageIOCs, checkDomainIOCs, checkOrgIOCs, checkHashIOCs } = require('./lib/iocs');
const { computeVerdict } = require('./lib/scoring');
const { formatVerdict, formatJSON, printProgress, clearProgress } = require('./lib/reporter');
const { extractDeps } = require('./lib/utils');
const pkg = require('../package.json');

// ─── Argument parsing ───────────────────────────────────────────────

const args = process.argv.slice(2);
const flags = {
  json: args.includes('--json'),
  quiet: args.includes('--quiet'),
  noColor: args.includes('--no-color'),
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
  const checkResults = runAllChecks(files, iocDB);
  const floor = computeVerdictFloor(checkResults);

  // Phase A: Detector rules
  printProgress('Running detector rules...');
  const metadata = { repoMeta, ownerMeta, contributors, commits };
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

  // Phase B: Scoring and verdict
  printProgress('Computing verdict...');
  const verdict = computeVerdict(floor, findings, iocFindings);

  clearProgress();

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
    iocFindings
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

main().catch(err => {
  clearProgress();
  console.error(`\nError: ${err.message}`);
  if (err.message.includes('rate limit')) {
    process.exit(3);
  }
  process.exit(2);
});
