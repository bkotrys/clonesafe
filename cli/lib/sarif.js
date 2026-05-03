'use strict';

// SARIF 2.1.0 emitter for clonesafe findings.
//
// Drives the GitHub Code Scanning UI when uploaded via
// github/codeql-action/upload-sarif. `partialFingerprints.detectorHash`
// is stable across runs so suppression and "fixed in PR X" tracking
// survive line-number drift.

const crypto = require('crypto');
const VERSION = require('../../package.json').version;

const RISK_TO_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };

function fingerprint(f) {
  // Stable identifier independent of source line numbers.
  const seed = `${f.ruleId || f.iocId || ''}|${f.detector || ''}|${f.file || ''}|${f.match || ''}`;
  return crypto.createHash('sha256').update(seed).digest('hex').slice(0, 32);
}

function ruleEntries(allFindings) {
  const seen = new Map();
  for (const f of allFindings) {
    const id = f.ruleId || f.iocId || 'UNKNOWN';
    if (seen.has(id)) continue;
    seen.set(id, {
      id,
      name: id.replace(/[-_]/g, ' '),
      shortDescription: { text: f.detail || f.explanation || id },
      fullDescription: { text: f.explanation || f.detail || id },
      defaultConfiguration: { level: RISK_TO_LEVEL[f.risk] || 'warning' },
      properties: { tags: ['supply-chain', 'security', f.detector || 'clonesafe'] }
    });
  }
  return Array.from(seen.values());
}

function resultEntry(f) {
  const ruleId = f.ruleId || f.iocId || 'UNKNOWN';
  const level = RISK_TO_LEVEL[f.risk] || 'warning';
  const message = { text: f.explanation || f.detail || `${ruleId} matched ${f.match || ''}`.trim() };
  const out = {
    ruleId,
    level,
    message,
    partialFingerprints: { detectorHash: fingerprint(f) }
  };
  if (f.file) {
    out.locations = [{
      physicalLocation: {
        artifactLocation: { uri: f.file },
        region: f.line ? { startLine: f.line } : undefined
      }
    }];
  }
  return out;
}

function emit(result) {
  const all = [...(result.findings || []), ...(result.iocFindings || [])];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'clonesafe',
          version: VERSION,
          informationUri: 'https://github.com/bkotrys/clonesafe',
          rules: ruleEntries(all)
        }
      },
      results: all.map(resultEntry),
      properties: {
        verdict: result.verdict,
        score: result.score,
        verdictFloor: result.verdictFloor,
        floorTriggers: result.floorTriggers
      }
    }]
  };
}

module.exports = { emit, fingerprint };
