'use strict';

// Plain-English remediation hints keyed by rule/finding ID. Used by the
// reporter to give every finding a concrete next step. Missing entries
// gracefully fall back to the rule's `detail` text — no rule is required
// to have a remediation, but every BLOCK-class rule should.

const REMEDIATION = {
  // Lifecycle scripts (LS-*)
  'LS-001': 'Remove the backgrounded process from your install/postinstall script. Lifecycle scripts must complete synchronously and exit; dropping a daemon is a malware pattern.',
  'LS-002': 'Mixing cmd/bash in one script is a sandbox-evasion pattern. Replace with a single, platform-specific script (use cross-env / npm run-script if you need both).',
  'LS-003': 'Lifecycle scripts must not invoke runtime entry points. Move the install logic into a dedicated install-time script that does not re-import your runtime code.',
  'LS-004': 'Network calls inside install hooks are how supply-chain attacks deliver second-stage payloads. Remove curl/wget/fetch from your scripts.',
  'LS-005': 'Encoded payloads in install scripts are almost always malicious. Replace with plain commands or remove entirely.',

  // Obfuscation (OB-*)
  'OB-003': 'Source files combining base64 literals with eval/new Function are decode-and-execute payloads. Replace with explicit, readable code.',
  'OB-004': 'HTTP fetch + new Function("require", ...) is a remote-code-execution pattern. Remove this code.',

  // Exfil (EX-*)
  'EX-001': 'POSTing process.env is credential exfiltration. Audit who introduced this and revoke any tokens that may have been live in CI.',
  'EX-002': 'Reading SSH private keys from Node code is rarely legitimate. If this is for tooling, move it out of an installed package and into an explicit user script.',
  'EX-003': 'Reading browser/wallet profile paths is malware behavior. Remove the file and revoke any keys that may have been on the affected machine.',
  'EX-004': 'Hardcoded Discord/Telegram webhook URLs are exfil endpoints. Rotate any tokens, revoke the webhook, and treat the install machine as compromised until inspected.',

  // Git-level (GL-*)
  'GL-001': 'A custom .gitattributes filter executes at checkout time. Replace with `filter=lfs` or remove the directive.',
  'GL-003': 'Submodule URL injection is RCE-equivalent. Use a plain HTTPS URL with no shell-meta characters.',
  'GL-004': 'Submodule path traversal lets an attacker drop files outside the working tree. Use a plain in-tree path.',

  // Lockfile (LF-*)
  'LF-001': 'Non-registry resolved URLs in your lockfile point at attacker-controlled tarballs. Re-resolve from the official registry (`npm ci` after deleting the lockfile, or pin to the registry copy).',
  'LF-002': 'git+ssh dependencies in lockfiles are how attackers smuggle in private-repo payloads. Replace with a registry version.',

  // Dependency confusion (DC-*)
  'DC-001': 'This dependency name is one Levenshtein step from a popular package. Verify the maintainer and the registry URL before installing.',
  'DC-004': 'Scope is one character off a known org. Either you have a typo, or someone is squatting. Verify against the legitimate scope.',
  'DC-006': 'Direct match against the malicious-package IOC database. Do not install. Audit your lockfile for other matches.',

  // Phase-0 deterministic (D*)
  'D24': 'A workflow uses a known-malicious GitHub Action ref (CVE-2025-30066 class). Pin all third-party actions to a known-good 40-char SHA, never to mutable tags.',
  'D24u': 'Pin third-party actions by 40-char commit SHA. `actions/*` and `github/*` are first-party and may be tag-pinned. Use Dependabot or Renovate to keep SHAs updated.',
  'D25': 'Prompt-injection text in docs targets AI coding assistants and AI-assisted reviewers. Remove the injection lines or wrap them with a clear "EXAMPLE — DO NOT EXECUTE" marker.',
  'D26': 'A VS Code task is configured to auto-execute on folder open. Change `runOptions.runOn` to `default` (manual) or remove the task entirely.',
  'D27': 'Dockerfile uses a mutable base-image tag (or pipes curl into shell). Pin base images by SHA digest and replace `curl | sh` with a verified-checksum download.',
  'D28': 'A Go init() function makes network or process calls. Move that work into an explicitly-called function so import alone does not run it.',
  'D29': 'File contains a known supply-chain worm signature (Shai-Hulud / GlassWorm class). Treat the host as compromised; rotate npm/GitHub/cloud credentials.',
  'D30': 'File matches a DPRK Contagious Interview content signature. Stop, rotate any credentials that touched the machine, and report to your security team.',
  'D31': 'A live API key / private key is committed to source. Rotate the key immediately, then remove the secret from git history (BFG / git-filter-repo).',
  'D32': 'A `.pth` file in the source tree auto-executes Python at every interpreter startup. Remove it unless you have a documented, audited reason.',
  'D33': 'package.json declares a popular package name but `repository.url` points elsewhere — classic starjacking. Verify the package against the npm registry and the legitimate repo.',
  'D34': 'Multiple recruiter-lure indicators present (interview language + brand-new repo + brand-new owner + single contributor). Treat as DPRK Contagious Interview lure; do not run code.',

  // OSV / age / scorecard
  'OSV-MAL': 'OpenSSF malicious-packages advisory match. Remove the dependency and pin to a known-good version. Audit any production deploys that may have shipped this.',
  'AGE-001': 'Direct dependency was published more recently than your --min-age cool-down. Wait for community vetting, or pin to an older known-good version.',
  'SC-DANGEROUS-WORKFLOW': 'pull_request_target + checkout-PR-head executes attacker code with the base-repo write token. Use `pull_request` (no token) or guard with a permission-restricted approval gate.',
  'SC-WORKFLOW-INJECTION': 'PR-controlled github.event.* values are interpolated into a shell `run:` block. Move the value into an env var so the shell sees a literal, not concatenated.',
  'SC-MAINTAINED': 'Repo appears unmaintained. Combine with security signals before adopting; if you adopt, vendor and audit it.',
  'SC-CODE-REVIEW': 'Recent commits land directly on the default branch with no merge structure. Limited safety net against insider/compromised-maintainer pushes.'
};

function getRemediation(ruleId) {
  if (!ruleId) return null;
  return REMEDIATION[ruleId] || null;
}

module.exports = { getRemediation, REMEDIATION };
