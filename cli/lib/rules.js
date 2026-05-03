'use strict';

// User-extensible detector rules.
//
// Two entry points:
//
// 1. `--rules <path>` — load a JSON file with a `rules` array. Each rule:
//    { id, risk, weight, applies_to, regex, detail, [block_alone], [cap] }
//    `applies_to` is one of: '*', '*.js', '*.py', 'package.json',
//    a literal filename, or a glob ending in `*`.
//
// 2. `--rules guarddog` — load the bundled detectors/guarddog-lite.json
//    pack. Hand-ported subset of DataDog GuardDog's highest-signal
//    regex rules, MIT-licensed.
//
// Findings produced here use the same shape runDetectors emits, so they
// fold into the verdict pipeline without special-casing.

const fs = require('node:fs');
const path = require('node:path');

const RISK_DEFAULTS = { CRITICAL: 50, HIGH: 25, MEDIUM: 10, LOW: 3 };

function loadFile(filePath) {
  const txt = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(txt);
}

function resolvePack(spec) {
  if (!spec) return null;
  if (spec === 'guarddog' || spec === 'guarddog-lite') {
    const p = path.resolve(__dirname, '..', '..', 'detectors', 'guarddog-lite.json');
    return loadFile(p);
  }
  if (fs.existsSync(spec)) return loadFile(spec);
  throw new Error(`--rules: ${spec} is neither a known pack nor an existing file`);
}

function appliesTo(rule, filePath) {
  const a = rule.applies_to || rule.appliesTo || '*';
  if (a === '*') return true;
  if (a === filePath) return true;
  if (a.startsWith('*.')) return filePath.endsWith(a.slice(1));
  if (a.endsWith('/*')) return filePath.startsWith(a.slice(0, -1));
  return false;
}

function applyExtraRules(files, pack) {
  if (!pack || !Array.isArray(pack.rules)) return [];
  const findings = [];
  for (const rule of pack.rules) {
    let re;
    try { re = new RegExp(rule.regex, rule.flags || ''); } catch { continue; }
    const weight = typeof rule.weight === 'number' ? rule.weight : (RISK_DEFAULTS[rule.risk] || 10);
    let used = 0;
    for (const [filePath, content] of files) {
      if (!appliesTo(rule, filePath)) continue;
      const m = content.match(re);
      if (!m) continue;
      if (rule.cap && used >= rule.cap) break;
      used += weight;
      findings.push({
        ruleId: rule.id,
        detector: pack.name || 'user-rules',
        risk: rule.risk || 'HIGH',
        weight,
        blockAlone: !!(rule.block_alone || rule.blockAlone),
        file: filePath,
        match: m[0].slice(0, 120),
        detail: rule.detail || rule.id
      });
    }
  }
  return findings;
}

module.exports = { resolvePack, applyExtraRules };
