'use strict';

const { extractHooks, extractDeps, levenshtein, findTyposquats, SCOPE_ALLOWLIST, TOP_PACKAGES, KNOWN_SCOPES } = require('./utils');

// ─── Rule definitions ────────────────────────────────────────────────
// Each rule: { id, detector, risk, weight, blockAlone, cap, appliesTo, check(content, ctx) → matches[] }
// check returns array of { file, line?, match, detail }

function matchRegexLines(content, pattern, file) {
  const results = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      results.push({ file, line: i + 1, match: lines[i].trim().slice(0, 120) });
    }
  }
  return results;
}

function countRegexMatches(content, pattern) {
  const m = content.match(pattern);
  return m ? m.length : 0;
}

// ─── Lifecycle Scripts (LS) ──────────────────────────────────────────

const LS_RULES = [
  {
    id: 'LS-001', detector: 'lifecycle-scripts', risk: 'CRITICAL', weight: 40, blockAlone: true,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (/\bnohup\b|\bdisown\b|&\s*$|\bstart\s+\/b\b|\bsetsid\b/i.test(val)) {
          results.push({ file: 'package.json', match: `${name}: ${val}`, detail: 'background launch in lifecycle hook' });
        }
      }
      return results;
    }
  },
  {
    id: 'LS-002', detector: 'lifecycle-scripts', risk: 'CRITICAL', weight: 40, blockAlone: true,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (/start\s+\/b.*nohup|cmd\s+\/c.*bash|powershell.*\|\|\s*bash/i.test(val)) {
          results.push({ file: 'package.json', match: `${name}: ${val}`, detail: 'mixed Windows/Unix syntax' });
        }
      }
      return results;
    }
  },
  {
    id: 'LS-003', detector: 'lifecycle-scripts', risk: 'CRITICAL', weight: 40, blockAlone: true,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (/node\s+\.?\/?(?:server|index|app|loader|config|auth|main|daemon|worker|start)(?:\.js|\.ts)?/i.test(val)) {
          results.push({ file: 'package.json', match: `${name}: ${val}`, detail: 'node runs non-build file in lifecycle hook' });
        }
      }
      return results;
    }
  },
  {
    id: 'LS-004', detector: 'lifecycle-scripts', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (/\b(curl|wget)\b.*\||curl\s.*https?:\/\/|wget\s.*https?:\/\/|node\s+-e\s+['"].*fetch\(|\beval\(.*curl|\.\s*\|\s*bash/i.test(val)) {
          results.push({ file: 'package.json', match: `${name}: ${val}`, detail: 'network call in lifecycle hook' });
        }
      }
      return results;
    }
  },
  {
    id: 'LS-005', detector: 'lifecycle-scripts', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (/base64\s+-d|echo\s+['"]?[A-Za-z0-9+/]{40,}=?=?['"]?\s*\|\s*base64|printf.*\\x[0-9a-f]|node\s+-e\s+['"].*Buffer\.from\(['"][A-Za-z0-9+/]{40,}/i.test(val)) {
          results.push({ file: 'package.json', match: `${name}: ${val}`, detail: 'base64/hex encoded command in lifecycle hook' });
        }
      }
      return results;
    }
  },
  {
    id: 'LS-006', detector: 'lifecycle-scripts', risk: 'HIGH', weight: 5,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (/\$HOME\b|\$USER\b|\$PATH\b|\$\{[A-Z_]+\}/i.test(val)) {
          results.push({ file: 'package.json', match: `${name}: ${val}`, detail: 'env var read in lifecycle hook' });
        }
      }
      return results;
    }
  },
  {
    id: 'LS-007', detector: 'lifecycle-scripts', risk: 'HIGH', weight: 20,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (/sh\s+-c\s+['"]?\$|bash\s+-c\s+['"]?\$|eval\s+\$/i.test(val)) {
          results.push({ file: 'package.json', match: `${name}: ${val}`, detail: 'dynamic shell invocation in lifecycle hook' });
        }
      }
      return results;
    }
  },
  {
    id: 'LS-010', detector: 'lifecycle-scripts', risk: 'MEDIUM', weight: 5,
    appliesTo: 'package.json',
    check(content) {
      const hooks = extractHooks(content);
      const results = [];
      for (const [name, val] of hooks) {
        if (val.length > 200) {
          results.push({ file: 'package.json', match: `${name}: (${val.length} chars)`, detail: 'unusually long lifecycle script' });
        }
      }
      return results;
    }
  }
];

// ─── Obfuscation (OB) ───────────────────────────────────────────────

const OB_RULES = [
  {
    id: 'OB-001', detector: 'obfuscation', risk: 'CRITICAL', weight: 30, blockAlone: false,
    appliesTo: '*.js',
    check(content, ctx) {
      const matches = content.match(/_0x[a-f0-9]{4,6}/g) || [];
      const unique = new Set(matches);
      if (unique.size > 10) return [{ file: ctx.file, match: `${unique.size} unique _0x identifiers`, detail: 'javascript-obfuscator signature (>10)' }];
      if (unique.size >= 5) return [{ file: ctx.file, match: `${unique.size} unique _0x identifiers`, detail: 'javascript-obfuscator signature (5-10)' }];
      return [];
    },
    dynamicWeight(matches) {
      if (!matches[0]) return 0;
      const count = parseInt(matches[0].match.match(/(\d+)/)?.[1] || '0');
      return count > 10 ? 30 : 15;
    }
  },
  {
    id: 'OB-002', detector: 'obfuscation', risk: 'CRITICAL', weight: 35, blockAlone: false,
    appliesTo: '*.js',
    check(content, ctx) {
      if (/var\s+_0x[a-f0-9]+\s*=\s*\[/.test(content) || /\(function\s*\(\s*_0x[a-f0-9]+\s*,\s*_0x[a-f0-9]+\s*\)/.test(content)) {
        return [{ file: ctx.file, match: 'string array shuffle pattern', detail: 'javascript-obfuscator string array encoding' }];
      }
      return [];
    }
  },
  {
    id: 'OB-003', detector: 'obfuscation', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '*.js',
    check(content, ctx) {
      const hasBase64 = /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*,\s*['"]base64['"]\)|atob\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*\)/.test(content);
      const hasExec = /new\s+Function\s*\(|\beval\s*\(|vm\.runIn(?:New|This)Context/.test(content);
      if (hasBase64 && hasExec) {
        return [{ file: ctx.file, match: 'base64 literal + dynamic execution', detail: 'base64 decode-and-execute pattern' }];
      }
      return [];
    }
  },
  {
    id: 'OB-004', detector: 'obfuscation', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '*.js',
    check(content, ctx) {
      const hasHTTP = /(axios|fetch|got|request|http)\.(get|post|put)\s*\(/.test(content);
      const hasNewFunc = /new\s+Function\s*\(\s*['"]require['"]/.test(content);
      if (hasHTTP && hasNewFunc) {
        return [{ file: ctx.file, match: 'HTTP fetch + new Function("require", ...)', detail: 'remote code execution via new Function' }];
      }
      return [];
    }
  },
  {
    id: 'OB-005', detector: 'obfuscation', risk: 'HIGH', weight: 20,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /\[\s*['"](?:\\x[0-9a-f]{2}){3,}['"]\s*\]/, ctx.file)
        .map(m => ({ ...m, detail: 'hex-encoded property access' }));
    }
  },
  {
    id: 'OB-008', detector: 'obfuscation', risk: 'HIGH', weight: 20,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /eval\s*\([^)]*\+/, ctx.file)
        .map(m => ({ ...m, detail: 'eval with concatenated string' }));
    }
  },
  {
    id: 'OB-010', detector: 'obfuscation', risk: 'HIGH', weight: 15,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /require\s*\(\s*[a-zA-Z_]\w*\s*\+|require\s*\(\s*Buffer\.from\(|require\s*\(\s*atob\(/, ctx.file)
        .map(m => ({ ...m, detail: 'require of dynamically-constructed path' }));
    }
  }
];

// ─── Exfil Patterns (EX) ────────────────────────────────────────────

const EX_RULES = [
  {
    id: 'EX-001', detector: 'exfil-patterns', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /axios\.post\s*\([^)]*process\.env|fetch\s*\([^,]*,\s*\{[^}]*body:\s*JSON\.stringify\s*\(\s*process\.env|got\.post\s*\([^)]*process\.env|\.send\s*\(\s*process\.env|\.write\s*\(\s*JSON\.stringify\s*\(\s*process\.env/, ctx.file)
        .map(m => ({ ...m, detail: 'HTTP POST with process.env body' }));
    }
  },
  {
    id: 'EX-002', detector: 'exfil-patterns', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '*.js',
    check(content, ctx) {
      const hasDecodedURL = /Buffer\.from\s*\([^,]+,\s*['"]base64['"]\)\.toString\(\)|atob\s*\(/.test(content);
      const hasHTTPPost = /axios\.post|fetch\s*\(|got\.post|request\.post/.test(content);
      if (hasDecodedURL && hasHTTPPost) {
        return [{ file: ctx.file, match: 'decoded URL used as exfil endpoint', detail: 'base64-decoded URL + HTTP client' }];
      }
      return [];
    }
  },
  {
    id: 'EX-003', detector: 'exfil-patterns', risk: 'CRITICAL', weight: 45, blockAlone: true,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)|BEGIN\s+(?:OPENSSH|RSA|DSA|EC)\s+PRIVATE\s+KEY|os\.homedir\(\).*\.ssh|path\.join\([^)]*['"]\.ssh['"]/, ctx.file)
        .map(m => ({ ...m, detail: 'reading SSH private keys' }));
    }
  },
  {
    id: 'EX-004', detector: 'exfil-patterns', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /Library\/Application Support\/Google\/Chrome|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|dmkamcknogkgcdfhhbddcghachkejeap|Login Data|cookies\.sqlite|logins\.json|key4\.db/, ctx.file)
        .map(m => ({ ...m, detail: 'reading browser profile / wallet data' }));
    }
  },
  {
    id: 'EX-005', detector: 'exfil-patterns', risk: 'HIGH', weight: 25,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /\.npmrc|\.yarnrc|\.pypirc|\.docker\/config\.json|\.aws\/credentials|\.config\/gcloud|\.kube\/config|\.netrc|authorized_keys/, ctx.file)
        .map(m => ({ ...m, detail: 'reading developer config / credential files' }));
    }
  },
  {
    id: 'EX-008', detector: 'exfil-patterns', risk: 'HIGH', weight: 15,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /\.(zsh|bash|mysql|psql|sqlite|python)_history/, ctx.file)
        .map(m => ({ ...m, detail: 'reading shell history' }));
    }
  },
  {
    id: 'EX-010', detector: 'exfil-patterns', risk: 'HIGH', weight: 20,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /os\.homedir\(\)\s*\+|process\.env\.HOME|glob\s*\(\s*['"]~|walk(?:Sync)?\s*\([^)]*home/, ctx.file)
        .map(m => ({ ...m, detail: 'bulk file read from user home directory' }));
    }
  },
  {
    id: 'EX-012', detector: 'exfil-patterns', risk: 'HIGH', weight: 30,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+|api\.telegram\.org\/bot\d+:[A-Za-z0-9_-]+\/sendMessage/, ctx.file)
        .map(m => ({ ...m, detail: 'hardcoded Discord/Telegram webhook exfil' }));
    }
  }
];

// ─── Recon Patterns (RC) ────────────────────────────────────────────

const RC_RULES = [
  {
    id: 'RC-001', detector: 'recon-patterns', risk: 'HIGH', weight: 10,
    appliesTo: '*.js',
    check(content, ctx) {
      if (/process\.platform\s*===?\s*['"](?:darwin|win32|linux)['"]/.test(content)) {
        // Higher weight if combined with exfil paths
        const hasExfil = /Library\/Application Support|AppData|\.ssh|\.config/.test(content);
        return [{ file: ctx.file, match: 'process.platform branching', detail: 'OS-specific branching' + (hasExfil ? ' with credential paths' : ''), weight: hasExfil ? 25 : 10 }];
      }
      return [];
    }
  },
  {
    id: 'RC-004', detector: 'recon-patterns', risk: 'HIGH', weight: 15,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /process\.env\.CI\b|process\.env\.GITHUB_ACTIONS|process\.env\.CIRCLECI|process\.env\.GITLAB_CI/, ctx.file)
        .map(m => ({ ...m, detail: 'CI/sandbox detection' }));
    }
  },
  {
    id: 'RC-005', detector: 'recon-patterns', risk: 'HIGH', weight: 15,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /process\.execArgv.*inspect|process\.debugPort/, ctx.file)
        .map(m => ({ ...m, detail: 'anti-debug checks' }));
    }
  },
  {
    id: 'RC-009', detector: 'recon-patterns', risk: 'HIGH', weight: 25,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /\.docker\/config\.json|\.kube\/config|kubeconfig/, ctx.file)
        .map(m => ({ ...m, detail: 'reading docker/kubernetes config' }));
    }
  },
  {
    id: 'RC-010', detector: 'recon-patterns', risk: 'HIGH', weight: 25,
    appliesTo: '*.js',
    check(content, ctx) {
      return matchRegexLines(content, /glob\s*\(\s*['"].*\.env|readdir.*\.env|find.*\.env/, ctx.file)
        .map(m => ({ ...m, detail: 'scanning for .env files' }));
    }
  }
];

// ─── Prompt Injection (PI) ──────────────────────────────────────────

const PI_RULES = [
  {
    id: 'PI-001', detector: 'prompt-injection', risk: 'CRITICAL', weight: 50, blockAlone: true, cap: 150,
    appliesTo: '*',
    check(content, ctx) {
      const patterns = [
        /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|preceding)\s+(?:instructions?|directives?|rules?|prompts?)/i,
        /disregard\s+(?:the\s+|any\s+|all\s+)?(?:above|previous|prior|foregoing)/i,
        /forget\s+(?:the\s+|your\s+|all\s+)?(?:instructions?|rules?|guidelines?|system prompt)/i,
        /\boverride\s+the\s+(?:rules?|scoring|verdict|detector)/i,
        /reset\s+(?:your|the)\s+(?:instructions?|system|context|behavior)/i,
        /(?:you are|you're)\s+now\s+(?:a|an|operating as)/i,
        /pretend\s+(?:to be|you are|you're)/i,
        /from\s+now\s+on,?\s+(?:you|your|this)/i
      ];
      const results = [];
      for (const pat of patterns) {
        const m = content.match(new RegExp(pat.source, 'gi'));
        if (m) results.push({ file: ctx.file, match: m[0].slice(0, 100), detail: 'instruction-override phrase' });
      }
      return results;
    }
  },
  {
    id: 'PI-002', detector: 'prompt-injection', risk: 'CRITICAL', weight: 50, blockAlone: true, cap: 150,
    appliesTo: '*',
    check(content, ctx) {
      const patterns = [
        /^\s*(?:SYSTEM|ASSISTANT|USER|HUMAN):\s/m,
        /<\|(?:im_start|im_end|start_header_id|end_header_id|begin_of_text|end_of_text|eot_id)\|?>/,
        /\[INST\]/,
        /\[\/INST\]/,
        /<\|system\|>/,
        /<\|assistant\|>/,
        /<\|user\|>/
      ];
      const results = [];
      const seen = new Set();
      for (const pat of patterns) {
        if (pat.test(content) && !seen.has(pat.source)) {
          seen.add(pat.source);
          results.push({ file: ctx.file, match: content.match(pat)?.[0]?.slice(0, 80) || pat.source, detail: 'role/conversation impersonation' });
        }
      }
      return results;
    }
  },
  {
    id: 'PI-003', detector: 'prompt-injection', risk: 'CRITICAL', weight: 50, blockAlone: true, cap: 150,
    appliesTo: '*',
    check(content, ctx) {
      const patterns = [
        /clonesafe[\s-]*(?:verified|approved|whitelist|trust|audit)/i,
        /this\s+(?:repo|repository|package|project)\s+(?:has been\s+|is\s+)?(?:pre-?)?audit(?:ed)?/i,
        /trust(?:ed)?\s+by\s+(?:clonesafe|the maintainer|the author|security)/i,
        /whitelist(?:ed)?\s+(?:by|in)\s+(?:clonesafe|the scanner|security)/i,
        /safe to clone,?\s*verified/i,
        /cleared by\s+(?:clonesafe|snyk|socket|phylum|security)/i
      ];
      const results = [];
      for (const pat of patterns) {
        if (pat.test(content)) {
          results.push({ file: ctx.file, match: content.match(pat)?.[0]?.slice(0, 100) || '', detail: 'trust/authority impersonation' });
        }
      }
      return results;
    }
  },
  {
    id: 'PI-004', detector: 'prompt-injection', risk: 'CRITICAL', weight: 50, blockAlone: true, cap: 150,
    appliesTo: '*',
    check(content, ctx) {
      const patterns = [
        /return\s+(?:verdict\s+|a verdict of\s+|score\s+|result\s+)?(?:PROCEED|PASS|SAFE|CLEAN|OK)/i,
        /(?:set|make|give)\s+(?:the\s+)?(?:score|verdict|result)\s+(?:to\s+|of\s+)?(?:0|zero|PASS|SAFE|PROCEED)/i,
        /(?:do not|don't|never)\s+(?:flag|report|block|warn)(?:\s+this|\s+about)?/i,
        /skip\s+(?:the\s+|any\s+|all\s+)?(?:detector|rule|scan|check|analysis|review)/i,
        /bypass\s+(?:the\s+)?(?:scanner|detector|rule|check)/i
      ];
      const results = [];
      for (const pat of patterns) {
        if (pat.test(content)) {
          results.push({ file: ctx.file, match: content.match(pat)?.[0]?.slice(0, 100) || '', detail: 'output manipulation directive' });
        }
      }
      return results;
    }
  },
  {
    id: 'PI-008', detector: 'prompt-injection', risk: 'HIGH', weight: 40, cap: 100,
    appliesTo: '*',
    check(content, ctx) {
      const charClasses = [
        { name: 'bidi-override', re: /[\u202A-\u202E]/ },
        { name: 'bidi-isolate', re: /[\u2066-\u2069]/ },
        { name: 'zero-width', re: /[\u200B\u200C\u200D]/ },
        { name: 'BOM-mid-file', re: /(?!^)\uFEFF/ }
      ];
      const results = [];
      for (const cls of charClasses) {
        if (cls.re.test(content)) {
          results.push({ file: ctx.file, match: `hidden Unicode: ${cls.name}`, detail: `Trojan Source / GlassWorm: ${cls.name} characters` });
        }
      }
      return results;
    }
  }
];

// ─── Git-Level (GL) ─────────────────────────────────────────────────

const GL_RULES = [
  {
    id: 'GL-001', detector: 'git-level', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '.gitattributes',
    check(content, ctx) {
      const allFilters = content.match(/filter\s*=\s*(\S+)/gi) || [];
      const results = [];
      for (const f of allFilters) {
        const name = f.match(/filter\s*=\s*(\S+)/i)?.[1] || '';
        if (!/^(lfs|git-crypt|crypt)$/i.test(name)) {
          results.push({ file: '.gitattributes', match: f, detail: `smudge/clean filter RCE: filter=${name}` });
        }
      }
      return results;
    }
  },
  {
    id: 'GL-002', detector: 'git-level', risk: 'HIGH', weight: 20,
    appliesTo: '.gitattributes',
    check(content, ctx) {
      return matchRegexLines(content, /(?:\.gitmodules|\.github|security)\s+export-ignore/i, '.gitattributes')
        .map(m => ({ ...m, detail: 'export-ignore on security-relevant path' }));
    }
  },
  {
    id: 'GL-003', detector: 'git-level', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '.gitmodules',
    check(content, ctx) {
      return matchRegexLines(content, /url\s*=\s*.*(ext::|file:\/\/|\$\(|`|--upload-pack|--config)/i, '.gitmodules')
        .map(m => ({ ...m, detail: 'submodule URL injection' }));
    }
  },
  {
    id: 'GL-004', detector: 'git-level', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: '.gitmodules',
    check(content, ctx) {
      return matchRegexLines(content, /path\s*=\s*.*(?:\.\.|^\/)/i, '.gitmodules')
        .map(m => ({ ...m, detail: 'submodule path traversal' }));
    }
  },
  {
    id: 'GL-005', detector: 'git-level', risk: 'HIGH', weight: 25,
    appliesTo: '.gitmodules',
    check(content, ctx) {
      return matchRegexLines(content, /url\s*=\s*https?:\/\/\d+\.\d+\.\d+\.\d+|url\s*=\s*.*\.(?:vercel\.app|netlify\.app|ngrok\.io|glitch\.me|repl\.co)/i, '.gitmodules')
        .map(m => ({ ...m, detail: 'submodule pointing to suspicious host' }));
    }
  },
  {
    id: 'GL-007', detector: 'git-level', risk: 'HIGH', weight: 25,
    appliesTo: '.gitattributes',
    check(content, ctx) {
      const matches = content.match(/merge\s*=\s*(?!binary|union|text)\S+/gi) || [];
      return matches.map(m => ({ file: '.gitattributes', match: m, detail: 'custom merge driver' }));
    }
  }
];

// ─── Lockfile Anomalies (LF) ────────────────────────────────────────

const LF_RULES = [
  {
    id: 'LF-001', detector: 'lockfile-anomalies', risk: 'HIGH', weight: 30, cap: 30,
    appliesTo: 'lockfile',
    check(content, ctx) {
      const results = [];
      // codeload.github.com tarballs from the SAME org as the repo being
      // scanned are normal monorepo-internal references (e.g. angular pulling
      // its own angular/domino fork). Different-org codeload URLs remain
      // anomalies because they're how an attacker would point a lockfile
      // at their own commit-pinned tarball.
      const sameOrgCodeload = ctx.owner
        ? new RegExp(`^https://codeload\\.github\\.com/${ctx.owner.toLowerCase()}/`, 'i')
        : null;
      const isAllowlisted = (url) =>
        !url ||
        url.startsWith('https://registry.npmjs.org/') ||
        url.startsWith('https://registry.yarnpkg.com/') ||
        url.startsWith('https://npm.pkg.github.com/') ||
        /\.jfrog\.io/.test(url) ||
        /\.artifactoryonline\.com/.test(url) ||
        (sameOrgCodeload && sameOrgCodeload.test(url));
      // package-lock.json / bun.lock JSON shape: "resolved": "<url>"
      for (const m of content.matchAll(/"resolved"\s*:\s*"([^"]*)"/g)) {
        if (m[1] && /^https?:\/\//.test(m[1]) && !isAllowlisted(m[1])) {
          results.push({ file: ctx.file, match: m[1].slice(0, 120), detail: 'non-registry resolved URL in lockfile' });
        }
      }
      // yarn.lock format: resolved "<url>"
      for (const m of content.matchAll(/^\s*resolved\s+"([^"]*)"/gm)) {
        if (m[1] && /^https?:\/\//.test(m[1]) && !isAllowlisted(m[1])) {
          results.push({ file: ctx.file, match: m[1].slice(0, 120), detail: 'non-registry resolved URL in lockfile' });
        }
      }
      // pnpm-lock.yaml: tarball: <url>
      for (const m of content.matchAll(/(?:^|[{,\s])tarball:\s*(https?:\/\/[^\s,}]+)/g)) {
        if (!isAllowlisted(m[1])) {
          results.push({ file: ctx.file, match: m[1].slice(0, 120), detail: 'non-registry tarball URL in lockfile' });
        }
      }
      return results;
    }
  },
  {
    id: 'LF-002', detector: 'lockfile-anomalies', risk: 'CRITICAL', weight: 45, blockAlone: true,
    appliesTo: 'lockfile',
    check(content, ctx) {
      return matchRegexLines(content, /git\+ssh:\/\//, ctx.file)
        .map(m => ({ ...m, detail: 'git+ssh dependency URL in lockfile' }));
    }
  },
  {
    id: 'LF-003', detector: 'lockfile-anomalies', risk: 'HIGH', weight: 30,
    appliesTo: 'lockfile',
    check(content, ctx) {
      const results = [];
      if (/"integrity"\s*:\s*"(sha1-|md5-)"/.test(content)) {
        results.push({ file: ctx.file, match: 'weak integrity hash algorithm', detail: 'lockfile uses sha1/md5 instead of sha512' });
      }
      return results;
    }
  },
  {
    id: 'LF-005', detector: 'lockfile-anomalies', risk: 'HIGH', weight: 30,
    appliesTo: 'lockfile',
    check(content, ctx) {
      return matchRegexLines(content, /https?:\/\/(?:\d+\.\d+\.\d+\.\d+|[^"]*\.(?:vercel\.app|netlify\.app|glitch\.me|repl\.co|ngrok\.io|herokuapp\.com|workers\.dev))/, ctx.file)
        .map(m => ({ ...m, detail: 'tarball URL from suspicious domain' }));
    }
  }
];

// ─── Dependency Confusion (DC) ──────────────────────────────────────

const DC_RULES = [
  {
    id: 'DC-001', detector: 'dep-confusion', risk: 'HIGH', weight: 30,
    appliesTo: 'package.json',
    check(content) {
      const deps = extractDeps(content);
      // Use full TOP_PACKAGES list here (broader than D16's top-20) — DC-001
      // contributes to the score, not the verdict floor, so wider coverage
      // is fine. Shared helper guarantees DC-001 and D16 never disagree on
      // overlapping inputs.
      return findTyposquats(deps.all, { includeAll: true })
        .map(({ dep, top, distance }) => ({
          file: 'package.json',
          match: `"${dep}" ~ "${top}" (distance ${distance})`,
          detail: 'typosquat of popular package'
        }));
    }
  },
  {
    id: 'DC-004', detector: 'dep-confusion', risk: 'HIGH', weight: 25, cap: 25,
    appliesTo: 'package.json',
    check(content) {
      const deps = extractDeps(content);
      const results = [];
      const seen = new Set();
      for (const dep of Object.keys(deps.all)) {
        if (!dep.startsWith('@')) continue;
        const scope = dep.split('/')[0];
        if (seen.has(scope)) continue;
        seen.add(scope);
        if (SCOPE_ALLOWLIST.has(scope)) continue;
        for (const known of KNOWN_SCOPES) {
          if (scope === known) break; // exact match — legit
          const d = levenshtein(scope.toLowerCase(), known.toLowerCase());
          // Distance-1 on scopes is the right threshold (e.g. @bable vs @babel).
          // Distance-2 produced too many FPs across legit-but-similarly-named
          // orgs (@bazel vs @babel, @vue vs @mui).
          if (d === 1) {
            results.push({ file: 'package.json', match: `"${dep}" scope ~ "${known}" (distance ${d})`, detail: 'scope confusion' });
            break;
          }
        }
      }
      return results;
    }
  },
  {
    id: 'DC-006', detector: 'dep-confusion', risk: 'CRITICAL', weight: 50, blockAlone: true,
    appliesTo: 'package.json',
    check(content, ctx) {
      // Handled by IOC cross-reference, but included here for completeness
      return []; // iocs.js handles this
    }
  }
];

// ─── Repo Metadata (RM) ─────────────────────────────────────────────

const RM_RULES = [
  {
    id: 'RM-001', detector: 'repo-metadata', risk: 'HIGH', weight: 10,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (!ctx.repoMeta?.created_at) return [];
      const age = (Date.now() - new Date(ctx.repoMeta.created_at).getTime()) / (1000 * 60 * 60 * 24);
      if (age < 7) return [{ match: `repo created ${Math.floor(age)} days ago`, detail: 'repo created <7 days ago', weight: 20 }];
      if (age < 30) return [{ match: `repo created ${Math.floor(age)} days ago`, detail: 'repo created <30 days ago' }];
      return [];
    }
  },
  {
    id: 'RM-002', detector: 'repo-metadata', risk: 'HIGH', weight: 15,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (!ctx.ownerMeta?.created_at) return [];
      const age = (Date.now() - new Date(ctx.ownerMeta.created_at).getTime()) / (1000 * 60 * 60 * 24);
      if (age < 30) {
        const isOrg = ctx.ownerMeta.type === 'Organization';
        return [{
          match: `owner account created ${Math.floor(age)} days ago`,
          detail: `${isOrg ? 'org' : 'user'} account <30 days old`,
          weight: isOrg ? 15 : 8
        }];
      }
      return [];
    }
  },
  {
    id: 'RM-003', detector: 'repo-metadata', risk: 'MEDIUM', weight: 8,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (ctx.contributors && ctx.contributors.length === 1) {
        return [{ match: 'single contributor', detail: 'repo has only 1 contributor' }];
      }
      return [];
    }
  },
  {
    id: 'RM-004', detector: 'repo-metadata', risk: 'MEDIUM', weight: 5,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (!ctx.repoMeta) return [];
      const age = (Date.now() - new Date(ctx.repoMeta.created_at).getTime()) / (1000 * 60 * 60 * 24);
      if (ctx.repoMeta.stargazers_count === 0 && age > 30) {
        return [{ match: '0 stars', detail: 'zero stars despite being public for >30 days' }];
      }
      return [];
    }
  },
  {
    id: 'RM-005', detector: 'repo-metadata', risk: 'MEDIUM', weight: 5,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (ctx.commits && ctx.commits.length === 1) {
        return [{ match: '1 commit', detail: 'single squashed commit in history' }];
      }
      return [];
    }
  },
  {
    id: 'RM-006', detector: 'repo-metadata', risk: 'MEDIUM', weight: 2,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (ctx.repoMeta && !ctx.repoMeta.license) {
        return [{ match: 'no license', detail: 'no LICENSE file detected' }];
      }
      return [];
    }
  },
  {
    id: 'RM-008', detector: 'repo-metadata', risk: 'HIGH', weight: 15,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (ctx.repoMeta?.archived || ctx.repoMeta?.disabled) {
        return [{ match: ctx.repoMeta.archived ? 'archived' : 'disabled', detail: 'repo is archived or disabled' }];
      }
      return [];
    }
  },
  {
    id: 'RM-014', detector: 'repo-metadata', risk: 'HIGH', weight: 15,
    appliesTo: 'metadata',
    check(_, ctx) {
      if (ctx.repoMeta?.fork) {
        return [{ match: 'fork', detail: 'repo is a fork — check for malicious modifications' }];
      }
      return [];
    }
  }
];

// ─── All Rules ──────────────────────────────────────────────────────

const ALL_RULES = [...LS_RULES, ...OB_RULES, ...EX_RULES, ...RC_RULES, ...PI_RULES, ...GL_RULES, ...LF_RULES, ...DC_RULES, ...RM_RULES];

function runDetectors(files, metadata) {
  const findings = [];

  for (const rule of ALL_RULES) {
    // Determine which files this rule applies to
    let targets = [];

    if (rule.appliesTo === 'metadata') {
      targets = [['__metadata__', '']];
    } else if (rule.appliesTo === 'package.json') {
      if (files.has('package.json')) targets = [['package.json', files.get('package.json')]];
    } else if (rule.appliesTo === '.gitattributes') {
      if (files.has('.gitattributes')) targets = [['.gitattributes', files.get('.gitattributes')]];
    } else if (rule.appliesTo === '.gitmodules') {
      if (files.has('.gitmodules')) targets = [['.gitmodules', files.get('.gitmodules')]];
    } else if (rule.appliesTo === 'lockfile') {
      for (const name of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock']) {
        if (files.has(name)) targets.push([name, files.get(name)]);
      }
    } else if (rule.appliesTo === '*.js') {
      for (const [path, content] of files) {
        if (/\.(js|ts|mjs|cjs)$/.test(path)) targets.push([path, content]);
      }
    } else if (rule.appliesTo === '*') {
      targets = [...files.entries()];
    }

    for (const [filePath, content] of targets) {
      const ctx = { file: filePath, ...metadata };
      try {
        const matches = rule.check(content, ctx);
        for (const m of matches) {
          let weight = m.weight || rule.weight;
          if (rule.dynamicWeight) weight = rule.dynamicWeight(matches);

          // Apply cap
          const existingForRule = findings.filter(f => f.ruleId === rule.id);
          const existingWeight = existingForRule.reduce((s, f) => s + f.weight, 0);
          if (rule.cap && existingWeight >= rule.cap) continue;
          if (rule.cap) weight = Math.min(weight, rule.cap - existingWeight);

          findings.push({
            ruleId: rule.id,
            detector: rule.detector,
            risk: rule.risk,
            weight,
            blockAlone: rule.blockAlone || false,
            file: m.file || filePath,
            line: m.line,
            match: m.match,
            detail: m.detail
          });
        }
      } catch {
        // Rule execution error — skip silently
      }
    }
  }

  return findings;
}

module.exports = { runDetectors, ALL_RULES };
