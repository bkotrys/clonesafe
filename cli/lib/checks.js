'use strict';

const { extractHooks, extractDeps, levenshtein, TOP_PACKAGES } = require('./utils');

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
function checkD13(lockfiles) {
  let count = 0;
  for (const content of lockfiles) {
    // package-lock.json format
    const resolvedMatches = content.match(/"resolved"\s*:\s*"([^"]*)"/g) || [];
    for (const m of resolvedMatches) {
      const url = m.match(/"resolved"\s*:\s*"([^"]*)"/)?.[1] || '';
      if (url && !url.startsWith('https://registry.npmjs.org/') && !url.startsWith('https://registry.yarnpkg.com/')) {
        count++;
      }
    }
    // yarn.lock format
    const yarnMatches = content.match(/resolved\s+"([^"]*)"/g) || [];
    for (const m of yarnMatches) {
      const url = m.match(/resolved\s+"([^"]*)"/)?.[1] || '';
      if (url && !url.startsWith('https://registry.npmjs.org/') && !url.startsWith('https://registry.yarnpkg.com/')) {
        count++;
      }
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

// D15: package.json deps matching IOC packages
function checkD15(pkgJson, iocPackages) {
  if (!pkgJson) return 0;
  const deps = extractDeps(pkgJson);
  const iocNames = new Set((iocPackages.entries || []).map(e => e.identifier));
  let count = 0;
  for (const dep of Object.keys(deps.all)) {
    if (iocNames.has(dep)) count++;
  }
  return count;
}

// D16: Basic typosquat check
function checkD16(pkgJson) {
  if (!pkgJson) return 0;
  const deps = extractDeps(pkgJson);
  const top20 = TOP_PACKAGES.slice(0, 20);
  let count = 0;
  for (const dep of Object.keys(deps.all)) {
    if (top20.includes(dep)) continue;
    for (const top of top20) {
      const minLen = Math.min(dep.length, top.length);
      const d = levenshtein(dep.toLowerCase(), top.toLowerCase());
      if (d === 1 && minLen >= 3) { count++; break; }
      if (d === 2 && minLen >= 6) { count++; break; }
    }
  }
  return count;
}

function runAllChecks(files, iocDB) {
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

  // Collect lockfiles
  const lockfiles = [];
  for (const name of ['package-lock.json', 'yarn.lock']) {
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
    D13: checkD13(lockfiles),
    D14: checkD14(lockfiles),
    D15: checkD15(pkgJson, iocDB.packages),
    D16: checkD16(pkgJson)
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

  if (warns.length > 0) {
    return { floor: 'WARN', triggers: warns };
  }

  return { floor: 'NONE', triggers: [] };
}

module.exports = { runAllChecks, computeVerdictFloor };
