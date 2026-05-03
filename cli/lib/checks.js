'use strict';

const { extractHooks, extractDeps, findTyposquats } = require('./utils');

// D1: Lifecycle script backgrounding
function checkD1(pkgJson) {
  if (!pkgJson) return 0;
  const hooks = extractHooks(pkgJson);
  return hooks.filter(([, v]) =>
    /\bnohup\b/i.test(v) || /\bdisown\b/i.test(v) ||
    /&\s*$/.test(v) || /\bstart\s+\/b\b/i.test(v) || /\bsetsid\b/i.test(v)
  ).length;
}

// D2: Mixed Windows/Unix syntax
function checkD2(pkgJson) {
  if (!pkgJson) return 0;
  const hooks = extractHooks(pkgJson);
  return hooks.filter(([, v]) =>
    /start\s+\/b.*nohup/i.test(v) || /cmd\s+\/c.*bash/i.test(v)
  ).length;
}

// D3: Node runs non-build file in lifecycle hook
function checkD3(pkgJson) {
  if (!pkgJson) return 0;
  const hooks = extractHooks(pkgJson);
  return hooks.filter(([, v]) =>
    /node\s+\.?\/?(?:server|index|app|loader|config|auth|main|daemon|worker|start)(?:\.js|\.ts)?/i.test(v)
  ).length;
}

// D4: Base64 literals in source files
function checkD4(jsFiles) {
  let count = 0;
  for (const [, content] of jsFiles) {
    if (/Buffer\.from\s*\(\s*['"][A-Za-z0-9+/]{40,}/m.test(content)) count++;
  }
  return count;
}

// D5: new Function with require
function checkD5(jsFiles) {
  let count = 0;
  for (const [, content] of jsFiles) {
    if (/new\s+Function\s*\(|Function\s*\(\s*['"]require['"]/m.test(content)) count++;
  }
  return count;
}

// D6: process.env exfiltration
function checkD6(jsFiles) {
  let count = 0;
  for (const [, content] of jsFiles) {
    if (/(axios|fetch|got|request|http)\.(post|put|patch).*process\.env|\.send\s*\(.*process\.env|JSON\.stringify\s*\(\s*process\.env/m.test(content)) count++;
  }
  return count;
}

// D7: Known IOC domains
function checkD7(allFiles, iocDomains) {
  const entries = iocDomains.entries || [];
  if (entries.length === 0) return 0;
  let count = 0;
  const domainStrings = entries.map(e => e.identifier);
  for (const [, content] of allFiles) {
    for (const domain of domainStrings) {
      if (content.includes(domain)) { count++; break; }
    }
  }
  return count;
}

// D8: Prompt injection patterns in README
function checkD8(readme) {
  if (!readme) return 0;
  const patterns = [
    /ignore.*(previous|prior).*(instructions|rules|directives)/i,
    /disregard the above/i,
    /SYSTEM:/,
    /return verdict (PROCEED|PASS|SAFE)/i,
    /pre-?audited by/i,
    /whitelisted by/i,
    /clonesafe.*(verified|approved|trusted)/i,
    /skip.*(detector|rule|scan)/i,
    /bypass the scanner/i,
    /set (the )?score to 0/i
  ];
  let count = 0;
  for (const pat of patterns) {
    const matches = readme.match(new RegExp(pat.source, 'gi'));
    if (matches) count += matches.length;
  }
  return count;
}

// D9: Hidden Unicode (Trojan Source / GlassWorm)
function checkD9(allFiles) {
  let count = 0;
  const re = /[\u200B\u200C\u200D\u202A-\u202E\u2066-\u2069]/g;
  for (const [, content] of allFiles) {
    const matches = content.match(re);
    if (matches) count += matches.length;
  }
  return count;
}

// D10: Sensitive path references
function checkD10(jsFiles) {
  let count = 0;
  const re = /\.ssh\/id_|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|login\.keychain|Cookies|Login Data/;
  for (const [, content] of jsFiles) {
    if (re.test(content)) count++;
  }
  return count;
}

// D11: .gitattributes filter= directives (smudge/clean RCE)
function checkD11(gitattributes) {
  if (!gitattributes) return 0;
  const allFilters = (gitattributes.match(/filter\s*=\s*\S+/gi) || []).length;
  const safeFilters = (gitattributes.match(/filter\s*=\s*(lfs|git-crypt|crypt)\b/gi) || []).length;
  return Math.max(0, allFilters - safeFilters);
}

// D12: .gitmodules ext::/file:// or path traversal
function checkD12(gitmodules) {
  if (!gitmodules) return 0;
  const urlInjection = (gitmodules.match(/url\s*=\s*.*(ext::|file:\/\/|\$\(|`|--upload-pack|--config)/gi) || []).length;
  const pathTraversal = (gitmodules.match(/path\s*=\s*.*\.\.\//gi) || []).length;
  return urlInjection + pathTraversal;
}

// D13: Lockfile non-registry resolved URLs
// Supports: package-lock.json (npm v2/v3), bun.lock (npm-compatible JSON-ish),
//           yarn.lock (Yarn v1 syntax), pnpm-lock.yaml (pnpm v6+ YAML)
function checkD13(lockfiles, owner) {
  // codeload.github.com URLs from the SAME org as the scanned repo are
  // normal monorepo-internal pins (e.g. angular pulling angular/domino).
  // Different-org codeload URLs remain anomalies.
  const sameOrgCodeload = owner
    ? new RegExp(`^https://codeload\\.github\\.com/${owner.toLowerCase()}/`, 'i')
    : null;
  const isRegistryUrl = (url) =>
    !!url && (url.startsWith('https://registry.npmjs.org/') ||
              url.startsWith('https://registry.yarnpkg.com/') ||
              (sameOrgCodeload && sameOrgCodeload.test(url)));

  let count = 0;
  for (const content of lockfiles) {
    // package-lock.json / bun.lock JSON shape: "resolved": "<url>"
    for (const m of content.matchAll(/"resolved"\s*:\s*"([^"]*)"/g)) {
      if (m[1] && /^https?:\/\//.test(m[1]) && !isRegistryUrl(m[1])) count++;
    }
    // yarn.lock shape: resolved "<url>"
    for (const m of content.matchAll(/^\s*resolved\s+"([^"]*)"/gm)) {
      if (m[1] && /^https?:\/\//.test(m[1]) && !isRegistryUrl(m[1])) count++;
    }
    // pnpm-lock.yaml shape: tarball: <url>  (inline inside resolution: {...} or as a multi-line key).
    // pnpm only emits an explicit `tarball:` when the URL deviates from its default registry,
    // so any non-registry hit is a finding.
    for (const m of content.matchAll(/(?:^|[{,\s])tarball:\s*(https?:\/\/[^\s,}]+)/g)) {
      if (!isRegistryUrl(m[1])) count++;
    }
  }
  return count;
}

// D14: Lockfile git+ssh:// URLs
function checkD14(lockfiles) {
  let count = 0;
  for (const content of lockfiles) {
    const matches = content.match(/git\+ssh:\/\//g) || [];
    count += matches.length;
  }
  return count;
}

// D15: package.json deps matching IOC packages.
//
// Mirrors `checkPackageIOCs` in iocs.js: a name match alone is NOT enough.
// IOC entries pin specific malicious versions (e.g. axios@1.14.1); the
// canonical name remains a legitimate dep at every other version. Without
// the version check, any project depending on axios at all would BLOCK.
function checkD15(pkgJson, iocPackages) {
  if (!pkgJson) return 0;
  const deps = extractDeps(pkgJson);
  const byName = new Map();
  for (const e of (iocPackages.entries || [])) byName.set(e.identifier, e);
  let count = 0;
  for (const [dep, version] of Object.entries(deps.all)) {
    const entry = byName.get(dep);
    if (!entry) continue;
    if ((entry.versions || []).includes('*')) { count++; continue; }
    const clean = (typeof version === 'string' ? version : '').replace(/^[\^~>=<\s]+/, '');
    if ((entry.versions || []).includes(clean)) count++;
  }
  return count;
}

// Lockfile name → list of {name, version} entries it declares. Used by D15
// for transitive IOC matching and exposed for any future check that needs
// to walk the closure rather than just direct deps.
// Cap on lockfile size before regex evaluation. The yarn-lock and package-lock
// regexes have nested quantifiers that can backtrack badly on adversarial
// inputs; a 5 MB lockfile easily covers every real project we'd scan and
// shuts the door on a 50 MB attacker-supplied lockfile dragging the regex
// engine into seconds of CPU.
const LOCKFILE_SIZE_LIMIT = 5 * 1024 * 1024;

function extractLockfileDeps(lockfileText, format) {
  const out = [];
  if (!lockfileText) return out;
  if (lockfileText.length > LOCKFILE_SIZE_LIMIT) return out;
  if (format === 'package-lock') {
    // npm v2/v3 lockfile: top-level "packages" map keyed by node_modules path.
    // Each entry has name (sometimes implicit from key) + version.
    const m = lockfileText.match(/"packages"\s*:\s*\{([\s\S]*?)\n\s*\}\s*(?:,|\n\s*\})/);
    if (m) {
      const body = m[1];
      // Match "node_modules/<name>": { ..."version": "<v>" ... } sections.
      const re = /"(?:node_modules\/)?((?:@[^"/]+\/)?[^"/]+)"\s*:\s*\{[^}]*?"version"\s*:\s*"([^"]+)"/g;
      let mm;
      while ((mm = re.exec(body)) !== null) {
        if (mm[1] && !mm[1].startsWith('node_modules')) out.push({ name: mm[1], version: mm[2] });
      }
    }
    // Also: legacy v1 "dependencies" tree.
    const re2 = /"((?:@[^"/]+\/)?[a-z0-9_.-]+)"\s*:\s*\{\s*"version"\s*:\s*"([^"]+)"/gi;
    let mm;
    while ((mm = re2.exec(lockfileText)) !== null) {
      out.push({ name: mm[1], version: mm[2] });
    }
  } else if (format === 'yarn') {
    // yarn.lock v1: each block starts with `"<name>@<range>", "<name>@<range>":`
    // followed by `  version "<v>"`.
    const re = /^\s*"?((?:@[^@/"]+\/)?[a-z0-9_.-]+)@[^"]+"?:\s*\n(?:\s+\w+\s+["[][^\n]*\n)*\s+version\s+"([^"]+)"/gim;
    let mm;
    while ((mm = re.exec(lockfileText)) !== null) {
      out.push({ name: mm[1], version: mm[2] });
    }
  } else if (format === 'pnpm') {
    // pnpm v6+ keys packages as `/name@version:` or `/name@version(peer)`.
    const re = /^\s*\/((?:@[^@/]+\/)?[a-z0-9_.-]+)@([0-9][^:(\s]*)/gim;
    let mm;
    while ((mm = re.exec(lockfileText)) !== null) {
      out.push({ name: mm[1], version: mm[2] });
    }
  } else if (format === 'bun') {
    // bun.lock text format mirrors package-lock.json shape.
    const re = /"((?:@[^"/]+\/)?[a-z0-9_.-]+)"\s*:\s*\{[^}]*?"version"\s*:\s*"([^"]+)"/gi;
    let mm;
    while ((mm = re.exec(lockfileText)) !== null) {
      out.push({ name: mm[1], version: mm[2] });
    }
  }
  return out;
}

// D15b: scan TRANSITIVE deps from lockfiles against the IOC database.
// Direct-dep matching lives in iocs.js; this function returns counts for
// the verdict-floor layer. Severity stays at BLOCK for any IOC match
// (transitive or direct — a malicious package buried in the closure runs
// the same code as a direct dep).
function checkD15Transitive(files, iocPackages) {
  const entries = (iocPackages && iocPackages.entries) || [];
  if (entries.length === 0) return 0;
  const iocByName = new Map();
  for (const e of entries) iocByName.set(e.identifier, e);

  const seen = new Set(); // dedupe across lockfiles
  let count = 0;
  const lockfiles = [
    ['package-lock.json', 'package-lock'],
    ['yarn.lock', 'yarn'],
    ['pnpm-lock.yaml', 'pnpm'],
    ['bun.lock', 'bun']
  ];
  for (const [name, format] of lockfiles) {
    if (!files.has(name)) continue;
    const deps = extractLockfileDeps(files.get(name), format);
    for (const { name: depName, version } of deps) {
      const entry = iocByName.get(depName);
      if (!entry) continue;
      const key = `${depName}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (entry.versions.includes('*')) { count++; continue; }
      const clean = (version || '').replace(/^[\^~>=<\s]+/, '');
      if (entry.versions.includes(clean)) count++;
    }
  }
  return count;
}

// D21 (Ruby): Gemfile / extconf.rb shell-out at install time.
// Bundler runs extconf.rb on `gem install` for native extensions; arbitrary
// system() / backtick / IO.popen there is the Ruby analogue of npm's
// preinstall hook. We require the function-call form (paren or backtick)
// because the bare word "system" appears in many legit Gemfile comments
// (e.g. "for system gems", "system Ruby", "build system").
function checkD21(files) {
  let count = 0;
  for (const [path, content] of files) {
    // Rakefile and .gemspec do NOT run at `bundle install` / `gem install`
    // time — they execute only when the developer runs rake / gem build.
    // Restrict D21 to the actual install-time entry points.
    const isRuby = path === 'Gemfile' || path.endsWith('extconf.rb');
    if (!isRuby) continue;
    // Strip Ruby comments so "# build system" / "= use the system gem" don't false-match.
    const stripped = content.split('\n').map(l => l.replace(/(^|\s)#.*$/, '$1')).join('\n');
    if (/\b(?:system|exec|spawn|Kernel\.(?:system|exec))\s*\(\s*['"]/.test(stripped)) { count++; continue; }
    if (/`[^`\n]*\$|`[^`\n]*\b(curl|wget|sh|bash|nohup|eval|python|node)\b[^`\n]*`/.test(stripped)) { count++; continue; }
    if (/%x\s*[\{\(\[][^\}\)\]]*\b(curl|wget|sh|bash|eval|python|node)\b/.test(stripped)) { count++; continue; }
    if (/\b(?:IO\.popen|Open3\.(?:popen|capture|pipeline))\s*\(/.test(stripped)) { count++; continue; }
    if (/\b(?:Net::HTTP\.(?:get|post)|URI\.open|open\s*\(\s*['"]https?:)/.test(stripped)) { count++; continue; }
  }
  return count;
}

// D22 (PHP): composer.json post-install-cmd / post-update-cmd that shells
// out. Composer scripts can shell-execute via "@php" plus arbitrary
// commands; check for shell-tool prefixes.
function checkD22(files) {
  const composer = files.get('composer.json');
  if (!composer) return 0;
  let pkg;
  try { pkg = JSON.parse(composer); } catch { return 0; }
  const scripts = pkg.scripts || {};
  const hookNames = ['post-install-cmd', 'post-update-cmd', 'pre-install-cmd', 'pre-update-cmd', 'post-autoload-dump', 'post-create-project-cmd', 'post-package-install', 'post-package-update'];
  let count = 0;
  for (const hook of hookNames) {
    const v = scripts[hook];
    if (!v) continue;
    const arr = Array.isArray(v) ? v : [v];
    for (const cmd of arr) {
      if (typeof cmd !== 'string') continue;
      // @php / @composer / @ are namespaced refs; flag bare shell tools.
      if (/(^|[\s|;&])(curl|wget|sh|bash|nohup|eval|python|python3|node)\b/i.test(cmd) ||
          /\|\s*(?:sh|bash)\b/.test(cmd) ||
          /(^|\s)\.\/[^\s]+/.test(cmd)) count++;
    }
  }
  return count;
}

// D23: Known-bad / spam-correlated TLDs in URLs.
// Threat-feed correlation of these TLDs with malware/spam is high enough
// to surface a WARN, but legit content does occur (.xyz hosts a long tail
// of indie projects), so we never auto-BLOCK.
const KNOWN_BAD_TLDS = ['.zip', '.cam', '.icu', '.top', '.click', '.buzz', '.work', '.gq', '.tk', '.ml', '.cf'];
function checkD23(files) {
  let count = 0;
  const tldRe = new RegExp(
    'https?:\\/\\/[a-z0-9.-]+(' +
    KNOWN_BAD_TLDS.map(t => t.replace('.', '\\.')).join('|') +
    ')(?=[\\/:"\\s\\)\\]\\?]|$)',
    'gi'
  );
  for (const [, content] of files) {
    const m = content.match(tldRe);
    if (m) count += m.length;
  }
  return count;
}

// D17: Python setup.py shell-out / network fetch at install time
// Modern setup.py should be inert: any os.system / subprocess / urlretrieve at import
// scope means arbitrary code runs on `pip install`.
function checkD17(files) {
  const setupPy = files.get('setup.py');
  if (!setupPy) return 0;
  const re = /\b(os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_call|check_output)|urllib\.request\.urlretrieve|urllib\.request\.urlopen|urlopen|urlretrieve|requests\.(?:get|post)|httpx\.(?:get|post))\s*\(/;
  return re.test(setupPy) ? 1 : 0;
}

// D18: pyproject.toml non-standard build backend
// Standard backends are inert; a custom backend pointing at local code can run on pip install.
function checkD18(files) {
  const pyproject = files.get('pyproject.toml');
  if (!pyproject) return 0;
  const m = pyproject.match(/^\s*build-backend\s*=\s*"([^"]+)"/m);
  if (!m) return 0;
  const backend = m[1];
  const knownSafe = [
    'setuptools.build_meta', 'setuptools.build_meta:__legacy__',
    'hatchling.build', 'poetry.core.masonry.api', 'poetry_core.masonry.api',
    'flit_core.buildapi', 'pdm.backend', 'pdm_backend', 'pdm.pep517.api',
    'maturin', 'scikit_build_core.build', 'mesonpy'
  ];
  return knownSafe.includes(backend) ? 0 : 1;
}

// D19: Rust build.rs with network or shell-out
// build.rs runs on `cargo build`. Network/process activity at build time is the
// Rust analogue of an npm postinstall hook.
function checkD19(files) {
  const buildRs = files.get('build.rs');
  if (!buildRs) return 0;
  const re = /\b(std::process::Command|Command::new|reqwest::|ureq::|curl::|hyper::Client|tokio::net|std::net::TcpStream)\b/;
  return re.test(buildRs) ? 1 : 0;
}

// D20: Go //go:generate shelling out to non-go tooling
// Legitimate uses are typically `go run`, `go tool`, `stringer`, `mockgen`, etc.
// Anything piping to sh/bash/curl/wget/eval is the Go analogue of a malicious
// install hook.
function checkD20(files) {
  let count = 0;
  for (const [path, content] of files) {
    if (!path.endsWith('.go')) continue;
    const re = /^\s*\/\/\s*go:generate\s+(?:sh\b|bash\b|curl\b|wget\b|python\b|python3\b|node\b|eval\b|.*\|\s*(?:sh|bash))/gm;
    const m = content.match(re);
    if (m) count += m.length;
  }
  return count;
}

// D16: Basic typosquat check (delegates to shared findTyposquats helper).
function checkD16(pkgJson) {
  if (!pkgJson) return 0;
  const deps = extractDeps(pkgJson);
  return findTyposquats(deps.all).length;
}

// ───────────────────────────────────────────────────────────────────
// v0.4 detectors (D24–D34)
// ───────────────────────────────────────────────────────────────────

// GitHub Actions audit shared parser. Returns { bad, unpinned } counts so
// callers can route each into a different verdict floor. `bad` covers
// known-malicious commit SHAs and tj-actions-style poisoned-tag matches;
// `unpinned` covers third-party actions referenced by mutable tag instead
// of a 40-char commit SHA.
function auditWorkflowUses(files, iocActions) {
  const badShas = new Set(((iocActions && iocActions.entries) || [])
    .map(e => (e.identifier || '').toLowerCase()));
  const tagBlocks = (iocActions && iocActions.tag_blocklist) || [];
  let bad = 0;
  let unpinned = 0;
  for (const [path, content] of files) {
    if (!/^\.github\/workflows\/.+\.ya?ml$/i.test(path)) continue;
    const re = /^\s*-?\s*uses:\s*['"]?([^@\s'"#]+)@([^\s'"#]+)/gm;
    let m;
    while ((m = re.exec(content)) !== null) {
      const action = m[1];
      const ref = m[2];
      if (action.startsWith('./') || action.startsWith('../')) continue;
      const trustedOrgs = /^(actions|github|docker|aws-actions|azure|google-github-actions)\//i;
      const isSha = /^[0-9a-f]{40}$/i.test(ref);
      let isBad = false;
      if (isSha && badShas.has(ref.toLowerCase())) isBad = true;
      if (!isBad) {
        for (const block of tagBlocks) {
          if (action === block.action) {
            try {
              if (new RegExp(block.ref_pattern).test(ref)) { isBad = true; break; }
            } catch { /* invalid regex in IOC → skip */ }
          }
        }
      }
      if (isBad) { bad++; continue; }
      if (!trustedOrgs.test(action) && !isSha) unpinned++;
    }
  }
  return { bad, unpinned };
}

// D24: known-malicious GitHub Actions ref (SHA or tag-blocklist match) → BLOCK.
function checkD24(files, iocActions) {
  return auditWorkflowUses(files, iocActions).bad;
}

// D24u: unpinned third-party action references → WARN (common bad practice).
function checkD24u(files, iocActions) {
  return auditWorkflowUses(files, iocActions).unpinned;
}

// D25: Prompt-injection patterns in docs/issues/AI-config files (extension
// of D8). README is already covered by D8; this catches CONTRIBUTING.md,
// .cursorrules, .cursor/mcp.json, docs/* etc.
function checkD25(files) {
  const patterns = [
    /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|preceding)\s+(?:instructions?|directives?|rules?|prompts?)/i,
    /disregard\s+(?:the\s+|any\s+|all\s+)?(?:above|previous|prior|foregoing)/i,
    /\boverride\s+the\s+(?:rules?|scoring|verdict|detector)/i,
    /(?:you are|you're)\s+now\s+(?:a|an|operating as)/i,
    /SYSTEM:|<\|im_start\|>|<\|system\|>|\[INST\]/,
    /clonesafe[\s-]*(?:verified|approved|whitelist|trust|audit)/i,
    /(?:return|set|give)\s+(?:the\s+)?(?:verdict|score|result)\s+(?:to\s+|of\s+)?(?:0|zero|PASS|SAFE|PROCEED|CLEAN)/i,
    /skip\s+(?:the\s+|any\s+|all\s+)?(?:detector|rule|scan|check)/i,
    /bypass\s+(?:the\s+)?(?:scanner|detector|rule|check)/i
  ];
  let count = 0;
  for (const [p, content] of files) {
    // README.md is D8's domain — don't double-count.
    if (p === 'README.md') continue;
    const isDocLike = /\.(md|mdx|mdc|rst|txt)$/i.test(p) ||
      p === 'CONTRIBUTING.md' || p === '.cursorrules' ||
      p.startsWith('.cursor/') || p.startsWith('docs/');
    if (!isDocLike) continue;
    for (const pat of patterns) {
      if (pat.test(content)) { count++; break; }
    }
  }
  return count;
}

// D26: VS Code tasks.json auto-execute hooks. `runOn: "folderOpen"` on
// any task is a known DPRK Contagious Interview TTP.
function checkD26(files) {
  const t = files.get('.vscode/tasks.json');
  if (!t) return 0;
  let parsed;
  try {
    // VS Code permits // and /* */ comments in tasks.json. Strip them
    // before parsing, otherwise legit task files raise a SyntaxError.
    const stripped = t
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:\\])\/\/.*$/gm, '$1')
      .replace(/,\s*([}\]])/g, '$1');
    parsed = JSON.parse(stripped);
  } catch { return 0; }
  const tasks = (parsed && parsed.tasks) || [];
  let count = 0;
  for (const task of tasks) {
    const runOptions = task && task.runOptions;
    if (runOptions && /folderOpen/i.test(runOptions.runOn || '')) count++;
  }
  return count;
}

// D27: Dockerfile / docker-compose with mutable `FROM` tags or `curl | sh`
// patterns in `RUN` instructions.
function checkD27(files) {
  let count = 0;
  for (const [p, content] of files) {
    const isDockerfile = /(?:^|\/)Dockerfile(?:\.[^/]+)?$/i.test(p);
    const isCompose = /docker-compose(?:\.[^/]+)?\.ya?ml$/i.test(p);
    if (!isDockerfile && !isCompose) continue;

    if (isDockerfile) {
      // FROM image:TAG with no @sha256:... pin and a mutable-looking tag.
      // `latest` is the canonical bad tag, but version aliases like `1`, `lts`,
      // `stable`, `slim` move too. Pinned-by-digest (image@sha256:...) is OK.
      // The image-name char class excludes `:` so `node:20-alpine` correctly
      // splits image=`node` tag=`20-alpine` (a specific version that shouldn't
      // trigger). `scratch` is a meta-image with no upstream and is exempt.
      for (const m of content.matchAll(/^\s*FROM\s+([^\s#@:]+)(?::([^\s#@]+))?(@sha256:[a-f0-9]+)?/gim)) {
        const image = (m[1] || '').toLowerCase();
        const tag = m[2] || '';
        const digest = m[3] || '';
        if (digest) continue;
        if (image === 'scratch') continue;
        if (!tag) { count++; continue; } // no tag = `latest`
        if (/^(latest|lts|stable|slim|alpine|edge|main|master|nightly|rolling)$/i.test(tag)) count++;
      }
      // RUN ... curl|sh / wget|sh — the canonical install-script footgun.
      for (const m of content.matchAll(/^\s*RUN\s+[^\n]*/gim)) {
        const line = m[0];
        if (/\b(curl|wget)\b[^|]*\|\s*(?:sh|bash)\b/.test(line)) count++;
      }
    }
    if (isCompose) {
      // image: foo:latest / image: foo  → mutable.
      for (const m of content.matchAll(/^\s*image:\s*([^\s#]+)/gm)) {
        const ref = m[1];
        if (/@sha256:[a-f0-9]+/.test(ref)) continue;
        if (!/:[^/]+$/.test(ref)) { count++; continue; }
        const tag = ref.split(':').pop();
        if (/^(latest|lts|stable|slim|alpine|edge|main|master|nightly|rolling)$/i.test(tag)) count++;
      }
    }
  }
  return count;
}

// D28: Go `init()` functions with network/process calls. `init()` runs
// implicitly at package import time, so `init()` + net/http or os/exec
// is the Go analogue of a postinstall script.
function checkD28(files) {
  let count = 0;
  for (const [p, content] of files) {
    if (!p.endsWith('.go')) continue;
    // Find each top-level func init() body.
    // We use a non-greedy match up to the first close-brace at column 0,
    // which in idiomatic Go always terminates a top-level function.
    const re = /^func\s+init\s*\(\s*\)\s*\{([\s\S]*?)^\}/gm;
    let m;
    while ((m = re.exec(content)) !== null) {
      const body = m[1];
      if (/\b(?:exec\.Command|os\/exec|http\.(?:Get|Post)|net\.Dial|http\.NewRequest|net\/http|os\.Setenv)\b/.test(body)) count++;
    }
  }
  return count;
}

// D29: Self-replicating worm signatures (Shai-Hulud, Sha1-Hulud, GlassWorm).
function checkD29(files, iocWorms) {
  const entries = (iocWorms && iocWorms.entries) || [];
  if (entries.length === 0) return 0;
  let count = 0;
  for (const entry of entries) {
    let re;
    try { re = new RegExp(entry.pattern, 'i'); } catch { continue; }
    for (const [, content] of files) {
      if (re.test(content)) { count++; break; }
    }
  }
  return count;
}

// D30: DPRK content signatures — HexEval loaders, family-name strings,
// DPRK-specific exfil endpoints.
function checkD30(files, iocDprk) {
  const sigs = (iocDprk && iocDprk.content_signatures) || [];
  if (sigs.length === 0) return 0;
  let count = 0;
  for (const sig of sigs) {
    let re;
    try { re = new RegExp(sig.pattern); } catch { continue; }
    for (const [, content] of files) {
      if (re.test(content)) { count++; break; }
    }
  }
  return count;
}

// D31: Secrets / API-key strings (gitleaks-lite). Catches the common,
// high-confidence shapes; intentionally conservative to avoid drowning
// in entropy-driven FPs.
function checkD31(files) {
  const SECRET_PATTERNS = [
    // AWS access keys.
    /\bAKIA[0-9A-Z]{16}\b/,
    // GitHub tokens (classic + fine-grained + app installation).
    /\bghp_[A-Za-z0-9]{36}\b/,
    /\bgho_[A-Za-z0-9]{36}\b/,
    /\bghu_[A-Za-z0-9]{36}\b/,
    /\bghs_[A-Za-z0-9]{36}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{82}\b/,
    // Slack tokens.
    /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
    // Google API key.
    /\bAIza[0-9A-Za-z_-]{35}\b/,
    // Stripe live keys.
    /\bsk_live_[0-9A-Za-z]{24,}\b/,
    // npm tokens.
    /\bnpm_[A-Za-z0-9]{36}\b/,
    // OpenAI keys.
    /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/,
    // Anthropic keys.
    /\bsk-ant-(?:api|sid)\d+-[A-Za-z0-9_-]{40,}\b/,
    // Generic PEM private keys.
    /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/
  ];
  let count = 0;
  for (const [p, content] of files) {
    // Skip lockfiles and minified bundles — too noisy, mostly FPs.
    if (/^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$/.test(p)) continue;
    if (/\.min\.(?:js|css)$/.test(p)) continue;
    for (const pat of SECRET_PATTERNS) {
      if (pat.test(content)) { count++; break; }
    }
  }
  return count;
}

// D32: Python `.pth` file presence. .pth files placed in site-packages
// auto-execute lines starting with `import` at every Python startup,
// regardless of whether the package is imported. Even one such file is
// a strong supply-chain risk signal (LiteLLM 2026-03 incident). For a
// repo-level scan, we flag any committed `.pth` file.
function checkD32(files) {
  let count = 0;
  for (const [p] of files) {
    if (/\.pth$/.test(p)) count++;
  }
  return count;
}

// D33: Starjacking — package.json declares a `repository.url` that
// points at a different GitHub owner/repo than the one we're scanning,
// AND the package name is on the popular-packages list (heuristic for
// "claiming to be a popular thing while living somewhere else").
function checkD33(pkgJson, ctxOwner, ctxRepo) {
  if (!pkgJson || !ctxOwner || !ctxRepo) return 0;
  let pkg;
  try { pkg = JSON.parse(pkgJson); } catch { return 0; }
  const repoUrl = pkg.repository && (pkg.repository.url || (typeof pkg.repository === 'string' ? pkg.repository : ''));
  if (!repoUrl) return 0;
  const m = repoUrl.match(/github\.com[/:]([^/]+)\/([^/.]+)(?:\.git)?/i);
  if (!m) return 0;
  const declOwner = m[1].toLowerCase();
  const declRepo = m[2].toLowerCase();
  const sameRepo = (declOwner === ctxOwner.toLowerCase()) && (declRepo === ctxRepo.toLowerCase());
  if (sameRepo) return 0;
  // Different owner/repo than we're scanning → potential starjack.
  // Require pkg.name to be on the popular list to keep this BLOCK-floor.
  const { TOP_PACKAGES } = require('./utils');
  const name = (pkg.name || '').toLowerCase();
  if (TOP_PACKAGES.includes(name)) return 1;
  // Lower-confidence variant: name claimed but not popular — still WARN-worthy.
  return name ? 0 : 0;
}

// D34: Recruiter-lure heuristic — combo signal. Fires when a repo
// has multiple lure indicators at once: README mentions an interview
// task, repo is brand-new, owner is brand-new, single contributor,
// suspicious package set. Each of these alone is a benign signal,
// but the combination is highly characteristic of DPRK Contagious
// Interview lure repos.
function checkD34(files, iocDprk, repoMeta, ownerMeta, contributors) {
  if (!iocDprk) return 0;
  const lures = (iocDprk.lure_indicators || []);
  const readme = files.get('README.md') || '';
  let lureScore = 0;
  for (const ind of lures) {
    let re;
    try { re = new RegExp(ind.pattern, 'i'); } catch { continue; }
    if (re.test(readme)) lureScore++;
  }
  if (lureScore === 0) return 0;
  // Combine with repo signals.
  const ageDays = repoMeta && repoMeta.created_at
    ? (Date.now() - new Date(repoMeta.created_at).getTime()) / 86400000
    : null;
  const ownerAgeDays = ownerMeta && ownerMeta.created_at
    ? (Date.now() - new Date(ownerMeta.created_at).getTime()) / 86400000
    : null;
  const contribCount = Array.isArray(contributors) ? contributors.length : null;
  let combo = lureScore;
  if (ageDays !== null && ageDays < 30) combo++;
  if (ownerAgeDays !== null && ownerAgeDays < 30) combo++;
  if (contribCount !== null && contribCount <= 1) combo++;
  // Only escalate to a count when at least 3 of the 4 dimensions agree.
  return combo >= 3 ? 1 : 0;
}

function runAllChecks(files, iocDB, { owner, repo, repoMeta, ownerMeta, contributors } = {}) {
  const pkgJson = files.get('package.json') || null;
  const readme = files.get('README.md') || null;
  const gitattributes = files.get('.gitattributes') || null;
  const gitmodules = files.get('.gitmodules') || null;

  // Collect JS files
  const jsFiles = new Map();
  for (const [path, content] of files) {
    if (path.endsWith('.js') || path.endsWith('.ts') || path.endsWith('.mjs') || path.endsWith('.cjs')) {
      jsFiles.set(path, content);
    }
  }

  // Collect lockfiles (text formats only — bun.lockb binary is intentionally skipped)
  const lockfiles = [];
  for (const name of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock']) {
    if (files.has(name)) lockfiles.push(files.get(name));
  }

  return {
    D1: checkD1(pkgJson),
    D2: checkD2(pkgJson),
    D3: checkD3(pkgJson),
    D4: checkD4(jsFiles),
    D5: checkD5(jsFiles),
    D6: checkD6(jsFiles),
    D7: checkD7(files, iocDB.domains),
    D8: checkD8(readme),
    D9: checkD9(files),
    D10: checkD10(jsFiles),
    D11: checkD11(gitattributes),
    D12: checkD12(gitmodules),
    D13: checkD13(lockfiles, owner),
    D14: checkD14(lockfiles),
    D15: checkD15(pkgJson, iocDB.packages),
    D16: checkD16(pkgJson),
    D15b: checkD15Transitive(files, iocDB.packages),
    D17: checkD17(files),
    D18: checkD18(files),
    D19: checkD19(files),
    D20: checkD20(files),
    D21: checkD21(files),
    D22: checkD22(files),
    D23: checkD23(files),
    D24: checkD24(files, iocDB.actions),
    D24u: checkD24u(files, iocDB.actions),
    D25: checkD25(files),
    D26: checkD26(files),
    D27: checkD27(files),
    D28: checkD28(files),
    D29: checkD29(files, iocDB.worms),
    D30: checkD30(files, iocDB.dprk),
    D31: checkD31(files),
    D32: checkD32(files),
    D33: checkD33(pkgJson, owner, repo),
    D34: checkD34(files, iocDB.dprk, repoMeta, ownerMeta, contributors)
  };
}

function computeVerdictFloor(results) {
  const blocks = [];

  if (results.D1 > 0) blocks.push('D1');
  if (results.D2 > 0) blocks.push('D2');
  if (results.D3 > 0) blocks.push('D3');
  if (results.D5 > 0) blocks.push('D5');
  if (results.D6 > 0) blocks.push('D6');
  if (results.D7 > 0) blocks.push('D7');
  if (results.D8 > 0) blocks.push('D8');
  if (results.D10 > 0) blocks.push('D10');
  if (results.D11 > 0) blocks.push('D11');
  if (results.D12 > 0) blocks.push('D12');
  if (results.D14 > 0) blocks.push('D14');
  if (results.D15 > 0) blocks.push('D15');
  if (results.D17 > 0) blocks.push('D17');
  if (results.D19 > 0) blocks.push('D19');
  if (results.D15b > 0) blocks.push('D15b');
  if (results.D21 > 0) blocks.push('D21');
  if (results.D22 > 0) blocks.push('D22');
  // v0.4 BLOCK floors:
  // D29 (worm signature), D30 (DPRK content), D32 (.pth wheel), D33 (starjack popular pkg),
  // D34 (recruiter-lure combo) are all high-confidence.
  if (results.D24 > 0) blocks.push('D24');
  if (results.D29 > 0) blocks.push('D29');
  if (results.D30 > 0) blocks.push('D30');
  if (results.D32 > 0) blocks.push('D32');
  if (results.D33 > 0) blocks.push('D33');
  if (results.D34 > 0) blocks.push('D34');

  // D4 alone is WARN; BLOCK if combined with D5 or D6
  if (results.D4 > 0 && (results.D5 > 0 || results.D6 > 0)) {
    blocks.push('D4+D5/D6');
  }

  // D9 > 5 is BLOCK, D9 alone is WARN
  if (results.D9 > 5) blocks.push('D9');

  if (blocks.length > 0) {
    return { floor: 'BLOCK', triggers: blocks };
  }

  const warns = [];
  if (results.D4 > 0) warns.push('D4');
  if (results.D9 > 0) warns.push('D9');
  if (results.D13 > 0) warns.push('D13');
  if (results.D16 > 0) warns.push('D16');
  if (results.D18 > 0) warns.push('D18');
  if (results.D20 > 0) warns.push('D20');
  if (results.D23 > 0) warns.push('D23');
  // v0.4 WARN floors:
  // D24 (unpinned/known-bad action) — common, so WARN not BLOCK except when
  //                                   the bad-SHA list matches (handled by
  //                                   detector dedicated rule below).
  // D25 (prompt injection in non-README docs) — single doc finding alone.
  // D26 (vscode auto-execute task) — could be legit, surface but don't BLOCK.
  // D27 (Dockerfile mutable tags / curl|sh) — common bad practice; WARN.
  // D28 (Go init network/process) — could be legit; combine with other signals.
  // D31 (committed secret) — leaks not malware; WARN, escalate via score.
  if (results.D24u > 0) warns.push('D24u');
  if (results.D25 > 0) warns.push('D25');
  if (results.D26 > 0) warns.push('D26');
  if (results.D27 > 0) warns.push('D27');
  if (results.D28 > 0) warns.push('D28');
  if (results.D31 > 0) warns.push('D31');

  if (warns.length > 0) {
    return { floor: 'WARN', triggers: warns };
  }

  return { floor: 'NONE', triggers: [] };
}

module.exports = { runAllChecks, computeVerdictFloor };
