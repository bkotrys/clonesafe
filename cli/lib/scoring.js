'use strict';

const THRESHOLDS = {
  PROCEED: 9,
  CAUTION: 24,
  WARN: 59
  // 60+ = BLOCK
};

const VERDICT_ORDER = ['PROCEED', 'CAUTION', 'WARN', 'BLOCK'];

function verdictFromScore(score) {
  if (score <= THRESHOLDS.PROCEED) return 'PROCEED';
  if (score <= THRESHOLDS.CAUTION) return 'CAUTION';
  if (score <= THRESHOLDS.WARN) return 'WARN';
  return 'BLOCK';
}

function maxVerdict(a, b) {
  return VERDICT_ORDER.indexOf(a) >= VERDICT_ORDER.indexOf(b) ? a : b;
}

function computeVerdict(checkResults, findings, iocFindings) {
  const { floor: deterministicFloor, triggers: floorTriggers } = checkResults;

  // Sum weights from detector findings
  const detectorScore = findings.reduce((sum, f) => sum + f.weight, 0);

  // Sum weights from IOC findings
  const iocScore = iocFindings.reduce((sum, f) => sum + f.weight, 0);

  const totalScore = detectorScore + iocScore;
  const scoreVerdict = verdictFromScore(totalScore);

  // Check if any single finding triggers BLOCK on its own
  let findingFloor = 'PROCEED';
  const blockFindings = findings.filter(f => f.blockAlone && f.weight > 0);
  if (blockFindings.length > 0) findingFloor = 'BLOCK';

  // IOC matches always BLOCK
  const criticalIOCs = iocFindings.filter(f => f.risk === 'CRITICAL');
  if (criticalIOCs.length > 0) findingFloor = 'BLOCK';

  // Deterministic floor from D1-D16
  const dFloor = deterministicFloor === 'NONE' ? 'PROCEED' : deterministicFloor;

  // Final verdict is the maximum of all floors and score-based verdict
  const verdict = maxVerdict(maxVerdict(scoreVerdict, dFloor), findingFloor);

  return {
    score: totalScore,
    verdict,
    verdictFloor: deterministicFloor,
    floorTriggers,
    findingFloor: findingFloor !== 'PROCEED' ? findingFloor : null,
    detectorScore,
    iocScore,
    findingCount: findings.length + iocFindings.length
  };
}

module.exports = { computeVerdict, THRESHOLDS, verdictFromScore };
