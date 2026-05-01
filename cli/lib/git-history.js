'use strict';

// Repo-history anomaly detection via the GitHub REST API only.
//
// Three signals:
//   GH-FORCE-PUSH   the default branch was force-pushed within the lookback
//                   window. Activity API surfaces this as an `activity_type`
//                   of force_push. Strong signal: legit projects rarely do
//                   this on main.
//   GH-TAG-FORCED   the repo's most recent tag points at a commit that is
//                   no longer reachable from the default branch (the tag
//                   was created, then the branch was rewritten under it).
//   GH-UNSIGNED     >50% of commits on the default branch in the last
//                   month are unsigned, despite required_signatures being
//                   off. Info-only — many legit repos don't sign.

async function ghJson(token, path) {
  const headers = {
    'User-Agent': 'clonesafe',
    'Accept': 'application/vnd.github.v3+json'
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  try {
    const res = await fetch(`https://api.github.com${path}`, { headers });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function checkGitHistory(owner, repo, defaultBranch, token) {
  const findings = [];

  // 1. Activity API — list recent force-pushes on the default branch.
  // Returns 200 with [] on a clean repo, 404 on private repos w/o auth.
  // Calibration runs against legit projects (express, husky, etc.) revealed
  // that 1-4 force-pushes/30d on master is common practice (release-prep
  // squashes, accidental commit reverts). The signal only escalates above
  // a noise threshold — and even at HIGH it's MEDIUM-weight, never enough
  // alone to push past CAUTION.
  // defaultBranch is attacker-controllable repo metadata — encode it before
  // splicing into the API path. Without this, a branch literally named
  // `?activity_type=push&` could break out of the query string.
  const branch = encodeURIComponent(defaultBranch);
  const activity = await ghJson(token, `/repos/${owner}/${repo}/activity?activity_type=force_push&ref=refs/heads/${branch}&per_page=20`);
  if (Array.isArray(activity)) {
    const n = activity.length;
    if (n >= 8) {
      findings.push({
        ruleId: 'GH-FORCE-PUSH',
        detector: 'git-history',
        risk: 'HIGH',
        weight: 20,
        match: `${n} force-push events on ${defaultBranch} in last 30d`,
        detail: 'unusually high force-push rate on default branch — frequent history rewrites obscure attacker tampering and warrant manual review'
      });
    } else if (n >= 3) {
      findings.push({
        ruleId: 'GH-FORCE-PUSH',
        detector: 'git-history',
        risk: 'MEDIUM',
        weight: 5,
        match: `${n} force-push events on ${defaultBranch} in last 30d`,
        detail: 'moderate force-push activity on default branch — informational, common during release prep'
      });
    }
  }

  // 2. (Removed) Tag-vs-branch reachability via /compare?status=diverged
  // produced too many false positives on legitimate release-branch
  // workflows (React, Vue, etc. tag commits sit on release branches that
  // aren't strict ancestors of main). Force-push detection via the
  // Activity API above is the more reliable signal for the same threat.

  // 3. Recent commit signature ratio.
  const commits = await ghJson(token, `/repos/${owner}/${repo}/commits?sha=${branch}&per_page=20`);
  if (Array.isArray(commits) && commits.length >= 10) {
    const verified = commits.filter(c => c.commit && c.commit.verification && c.commit.verification.verified).length;
    const ratio = verified / commits.length;
    if (ratio < 0.2 && commits.length >= 15) {
      // Info-only at weight=0 — many real repos don't sign. Surfaces in
      // the JSON output for ops dashboards but doesn't move the score.
      findings.push({
        ruleId: 'GH-UNSIGNED',
        detector: 'git-history',
        risk: 'LOW',
        weight: 0,
        match: `${verified}/${commits.length} recent commits signed`,
        detail: 'most commits on the default branch are unsigned — informational signal, often benign'
      });
    }
  }

  return findings;
}

module.exports = { checkGitHistory };
