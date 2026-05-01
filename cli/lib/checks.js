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

function runAllChecks(files, iocDB, { owner } = {}) {
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
    D23: checkD23(files)
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

  if (warns.length > 0) {
    return { floor: 'WARN', triggers: warns };
  }

  return { floor: 'NONE', triggers: [] };
}

module.exports = { runAllChecks, computeVerdictFloor };
