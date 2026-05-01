'use strict';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

const colors = {
  red: (s) => useColor ? `\x1b[31m${s}\x1b[0m` : s,
  yellow: (s) => useColor ? `\x1b[33m${s}\x1b[0m` : s,
  green: (s) => useColor ? `\x1b[32m${s}\x1b[0m` : s,
  cyan: (s) => useColor ? `\x1b[36m${s}\x1b[0m` : s,
  bold: (s) => useColor ? `\x1b[1m${s}\x1b[0m` : s,
  dim: (s) => useColor ? `\x1b[2m${s}\x1b[0m` : s
};

const VERDICT_STYLES = {
  PROCEED: { icon: '\u{1F7E2}', color: colors.green, label: 'PROCEED' },
  CAUTION: { icon: '\u{1F7E1}', color: colors.yellow, label: 'CAUTION' },
  WARN: { icon: '\u{1F7E0}', color: colors.yellow, label: 'WARN' },
  BLOCK: { icon: '\u{1F534}', color: colors.red, label: 'BLOCK' }
};

function formatVerdict(result, noColor) {
  const style = VERDICT_STYLES[result.verdict];
  const colorFn = noColor ? (s) => s : style.color;
  const boldFn = noColor ? (s) => s : colors.bold;
  const dimFn = noColor ? (s) => s : colors.dim;
  const cyanFn = noColor ? (s) => s : colors.cyan;

  const W = 60;
  const hline = '+' + '-'.repeat(W) + '+';
  const pad = (s, w) => {
    const clean = s.replace(/\x1b\[[0-9;]*m/g, '');
    return s + ' '.repeat(Math.max(0, w - clean.length));
  };
  const row = (s) => '|  ' + pad(s, W - 4) + '  |';

  const lines = [];
  lines.push('');
  lines.push(hline.replace('--', '- clonesafe verdict ').replace(/--(?=-+\+$)/, ' -'));
  lines.push(row(`${boldFn(result.owner + '/' + result.repo)}`));
  lines.push(row(`Risk:  ${colorFn(style.icon + ' ' + style.label)}   Score: ${result.score}`));
  lines.push(row(''));

  // Deterministic checks summary
  if (result.verdictFloor !== 'NONE') {
    lines.push(row(`${boldFn('Deterministic floor:')} ${colorFn(result.verdictFloor)} (${result.floorTriggers.join(', ')})`));
    lines.push(row(''));
  }

  // Group findings by risk
  const allFindings = [...result.findings, ...result.iocFindings];
  const critical = allFindings.filter(f => f.risk === 'CRITICAL');
  const high = allFindings.filter(f => f.risk === 'HIGH');
  const medium = allFindings.filter(f => f.risk === 'MEDIUM' || f.risk === 'LOW');

  if (critical.length > 0) {
    lines.push(row(colorFn(boldFn('CRITICAL'))));
    for (const f of critical.slice(0, 8)) {
      const loc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '';
      lines.push(row(`  ${f.ruleId || f.iocId || ''} ${f.detail || f.explanation || ''}`));
      if (loc) lines.push(row(`    ${dimFn(loc)} ${dimFn('(+' + f.weight + ')')}`));
    }
    if (critical.length > 8) lines.push(row(dimFn(`  ... and ${critical.length - 8} more CRITICAL findings`)));
    lines.push(row(''));
  }

  if (high.length > 0) {
    lines.push(row(cyanFn(boldFn('HIGH'))));
    for (const f of high.slice(0, 5)) {
      const loc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '';
      lines.push(row(`  ${f.ruleId || f.iocId || ''} ${f.detail || f.explanation || ''}`));
      if (loc) lines.push(row(`    ${dimFn(loc)} ${dimFn('(+' + f.weight + ')')}`));
    }
    if (high.length > 5) lines.push(row(dimFn(`  ... and ${high.length - 5} more HIGH findings`)));
    lines.push(row(''));
  }

  if (medium.length > 0) {
    lines.push(row(`${boldFn('MEDIUM/LOW')} (${medium.length} finding${medium.length > 1 ? 's' : ''})`));
    for (const f of medium.slice(0, 3)) {
      lines.push(row(`  ${f.ruleId || ''} ${f.detail || ''}`));
    }
    if (medium.length > 3) lines.push(row(dimFn(`  ... and ${medium.length - 3} more`)));
    lines.push(row(''));
  }

  if (allFindings.length === 0) {
    lines.push(row(colors.green('No suspicious patterns detected.')));
    lines.push(row(''));
  }

  // Diff summary (only when --diff was used and we had a prior cached run).
  if (result.diff) {
    const d = result.diff;
    lines.push(row(`${boldFn('Diff vs prior scan')} (${(d.priorTimestamp || '?').slice(0, 10)}, was ${d.priorVerdict || '?'})`));
    if (d.added.length === 0 && d.removed.length === 0) {
      lines.push(row(dimFn('  no change in findings')));
    } else {
      if (d.added.length > 0) lines.push(row(colors.yellow(`  + ${d.added.length} new finding${d.added.length > 1 ? 's' : ''}`)));
      if (d.removed.length > 0) lines.push(row(colors.green(`  - ${d.removed.length} resolved`)));
    }
    lines.push(row(''));
  }

  // Sandbox phase summary (only when --sandbox was used)
  if (result.sandbox) {
    if (result.sandbox.error) {
      lines.push(row(`${boldFn('Sandbox:')} skipped — ${result.sandbox.error}`));
    } else if (result.sandbox.skipped) {
      lines.push(row(`${boldFn('Sandbox:')} skipped — ${result.sandbox.skipped}`));
    } else {
      const c = result.sandbox.classification || {};
      const fn = c.verdict === 'MALICIOUS' ? colors.red : c.verdict === 'SUSPICIOUS' ? colors.yellow : colors.green;
      lines.push(row(`${boldFn('Sandbox install:')} ${(noColor ? (s) => s : fn)(c.verdict || '?')}`));
      if (c.reasons && c.reasons.length) {
        lines.push(row(dimFn(`  signals: ${c.reasons.join(' | ')}`)));
      }
    }
    lines.push(row(''));
  }

  // Deterministic check results
  lines.push(row(dimFn(`D1-D20 check results: ${formatCheckSummary(result.checks)}`)));

  lines.push(hline);
  lines.push('');

  return lines.join('\n');
}

function formatCheckSummary(checks) {
  if (!checks) return 'N/A';
  const fired = Object.entries(checks).filter(([, v]) => v > 0);
  if (fired.length === 0) return 'all clear';
  return fired.map(([k, v]) => `${k}=${v}`).join(' ');
}

function formatJSON(result) {
  return JSON.stringify({
    version: require('../../package.json').version,
    timestamp: new Date().toISOString(),
    repo: `${result.owner}/${result.repo}`,
    verdict: result.verdict,
    score: result.score,
    verdictFloor: result.verdictFloor,
    floorTriggers: result.floorTriggers,
    checks: result.checks,
    findings: result.findings.map(f => ({
      ruleId: f.ruleId,
      detector: f.detector,
      risk: f.risk,
      weight: f.weight,
      file: f.file,
      line: f.line,
      match: f.match,
      detail: f.detail
    })),
    iocFindings: result.iocFindings.map(f => ({
      ruleId: f.ruleId,
      iocId: f.iocId,
      risk: f.risk,
      weight: f.weight,
      match: f.match,
      explanation: f.explanation,
      campaign: f.campaign
    }))
  }, null, 2);
}

function printProgress(msg) {
  if (process.stderr.isTTY) {
    process.stderr.write(`\r\x1b[K${colors.dim('  ' + msg)}`);
  }
}

function clearProgress() {
  if (process.stderr.isTTY) {
    process.stderr.write('\r\x1b[K');
  }
}

module.exports = { formatVerdict, formatJSON, printProgress, clearProgress };
