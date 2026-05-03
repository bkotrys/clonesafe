'use strict';

// OpenSSF Scorecard-style probes, derived from data clonesafe already
// fetches (repoMeta, ownerMeta, contributors, commits, workflow files).
// Probes that would require additional API calls (Branch-Protection,
// Signed-Releases) are gated behind --scorecard so the default scan stays
// at the same cost.
//
// Output shape mirrors the detector findings shape so they fold into the
// scoring pipeline without special-casing.

function probeMaintained({ commits, repoMeta }) {
  if (!Array.isArray(commits) || commits.length === 0) return null;
  const last = commits[0] && (commits[0].commit?.author?.date || commits[0].commit?.committer?.date);
  if (!last) return null;
  const ageDays = (Date.now() - new Date(last).getTime()) / 86400000;
  if (ageDays > 365) {
    return {
      ruleId: 'SC-MAINTAINED',
      risk: 'MEDIUM',
      weight: 8,
      match: `last commit ${Math.floor(ageDays)} days ago`,
      explanation: 'Repository appears unmaintained (>1 year since last commit). Combine with other signals before adopting.'
    };
  }
  return null;
}

function probeCodeReview({ commits }) {
  // Heuristic: in healthy repos, recent commits are merge commits or land
  // via PR. We can't see PR review counts cheaply, but a long string of
  // direct-to-default-branch commits with no merge structure is suspicious.
  if (!Array.isArray(commits) || commits.length < 5) return null;
  const merged = commits.filter(c => c && c.parents && c.parents.length > 1).length;
  if (merged === 0) {
    return {
      ruleId: 'SC-CODE-REVIEW',
      risk: 'LOW',
      weight: 3,
      match: '0 merge commits in last 10',
      explanation: 'Recent commits land directly on the default branch — no PR/review trail visible.'
    };
  }
  return null;
}

function probeDangerousWorkflow(files) {
  const findings = [];
  for (const [path, content] of files) {
    if (!/^\.github\/workflows\/.+\.ya?ml$/i.test(path)) continue;
    // pull_request_target + explicit checkout of PR head ref is the classic
    // "execute attacker code with a write-token" pattern.
    if (/pull_request_target/.test(content) &&
        /actions\/checkout@/.test(content) &&
        /(?:ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}|head\.repo\.fork)/i.test(content)) {
      findings.push({
        ruleId: 'SC-DANGEROUS-WORKFLOW',
        risk: 'HIGH',
        weight: 25,
        file: path,
        match: 'pull_request_target + checkout PR head',
        explanation: 'Workflow runs with the base-repo write token but checks out arbitrary PR-head code — Coinbase/tj-actions class.'
      });
    }
    // ${{ github.event... }} interpolation directly inside a `run:` block
    // is a script-injection sink.
    const runRe = /^\s*run:\s*\|?[\s\S]*?\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)/gm;
    if (runRe.test(content)) {
      findings.push({
        ruleId: 'SC-WORKFLOW-INJECTION',
        risk: 'HIGH',
        weight: 25,
        file: path,
        match: 'github.event.* interpolated into run:',
        explanation: 'PR-controlled github.event.* is concatenated into a shell `run:` block — script-injection sink.'
      });
    }
  }
  return findings;
}

function probeNoLicense({ repoMeta }) {
  if (repoMeta && !repoMeta.license) {
    return {
      ruleId: 'SC-NO-LICENSE',
      risk: 'LOW',
      weight: 2,
      match: 'no license',
      explanation: 'Repository has no LICENSE — adopting it carries unclear legal terms. Not a malware signal alone.'
    };
  }
  return null;
}

function runProbes({ files, repoMeta, ownerMeta, contributors, commits }) {
  const out = [];
  const m = probeMaintained({ commits, repoMeta });
  if (m) out.push(m);
  const cr = probeCodeReview({ commits });
  if (cr) out.push(cr);
  out.push(...probeDangerousWorkflow(files));
  // SC-NO-LICENSE overlaps with RM-006; skip to avoid double-counting in
  // default scans. Re-enable when --scorecard explicitly requested.
  return out;
}

module.exports = { runProbes };
