'use strict';

const fs = require('fs');
const path = require('path');
const { sha256 } = require('./utils');

function loadIOCs() {
  const base = path.resolve(__dirname, '../../iocs');
  const load = (file) => {
    try {
      return JSON.parse(fs.readFileSync(path.join(base, file), 'utf8'));
    } catch {
      return { entries: [] };
    }
  };
  return {
    packages: load('packages.json'),
    domains: load('domains.json'),
    orgs: load('github-orgs.json'),
    hashes: load('hashes.json')
  };
}

function checkPackageIOCs(allDeps, iocDB) {
  const findings = [];
  const entries = iocDB.packages.entries || [];

  for (const entry of entries) {
    const depVersion = allDeps[entry.identifier];
    if (!depVersion) continue;

    // Wildcard versions — package is entirely malicious
    if (entry.versions.includes('*')) {
      findings.push({
        ruleId: 'IOC-PKG',
        iocId: entry.id,
        risk: 'CRITICAL',
        weight: 50,
        match: `${entry.identifier}@${depVersion}`,
        explanation: `Dependency "${entry.identifier}" matches IOC ${entry.id}: ${entry.description}`,
        campaign: entry.campaign
      });
      continue;
    }

    // Check if the version range could match a known-bad version
    const cleanVersion = depVersion.replace(/^[\^~>=<\s]+/, '');
    if (entry.versions.includes(cleanVersion)) {
      findings.push({
        ruleId: 'IOC-PKG',
        iocId: entry.id,
        risk: 'CRITICAL',
        weight: 50,
        match: `${entry.identifier}@${depVersion} (known-bad: ${entry.versions.join(', ')})`,
        explanation: `Dependency "${entry.identifier}" at version "${depVersion}" matches IOC ${entry.id}: ${entry.description}`,
        campaign: entry.campaign
      });
    }
  }

  return findings;
}

function checkDomainIOCs(files, iocDB) {
  const findings = [];
  const entries = iocDB.domains.entries || [];
  const patterns = iocDB.domains.pattern_iocs || [];

  for (const [filePath, content] of files) {
    // Check exact domain matches
    for (const entry of entries) {
      if (content.includes(entry.identifier)) {
        findings.push({
          ruleId: 'IOC-DOMAIN',
          iocId: entry.id,
          risk: 'CRITICAL',
          weight: 50,
          file: filePath,
          match: entry.identifier,
          explanation: `File "${filePath}" references IOC domain ${entry.identifier}: ${entry.description}`,
          campaign: entry.campaign
        });
      }
    }

    // Check pattern IOCs
    for (const pat of patterns) {
      try {
        const re = new RegExp(pat.pattern, 'gm');
        const matches = content.match(re);
        if (matches) {
          findings.push({
            ruleId: 'IOC-DOMAIN-PAT',
            iocId: pat.id,
            risk: 'HIGH',
            weight: 30,
            file: filePath,
            match: matches[0],
            explanation: `File "${filePath}" matches domain pattern ${pat.id}: ${pat.description}`
          });
        }
      } catch {
        // Invalid regex in IOC — skip
      }
    }
  }

  return findings;
}

function checkOrgIOCs(owner, iocDB) {
  const findings = [];
  const entries = iocDB.orgs.entries || [];

  for (const entry of entries) {
    if (owner.toLowerCase() === entry.identifier.toLowerCase()) {
      findings.push({
        ruleId: 'IOC-ORG',
        iocId: entry.id,
        risk: 'CRITICAL',
        weight: 40,
        match: owner,
        explanation: `Repository owner "${owner}" matches IOC org ${entry.id}: ${entry.description}`,
        campaign: entry.campaign
      });
    }
  }

  return findings;
}

function checkHashIOCs(files, iocDB) {
  const findings = [];
  const entries = iocDB.hashes.entries || [];
  if (entries.length === 0) return findings;

  const hashSet = new Set(entries.map(e => e.identifier.toLowerCase()));

  for (const [filePath, content] of files) {
    const hash = sha256(content);
    if (hashSet.has(hash)) {
      const entry = entries.find(e => e.identifier.toLowerCase() === hash);
      findings.push({
        ruleId: 'IOC-HASH',
        iocId: entry.id,
        risk: 'CRITICAL',
        weight: 50,
        file: filePath,
        match: hash,
        explanation: `File "${filePath}" has SHA256 matching IOC ${entry.id}: ${entry.description}`,
        campaign: entry.campaign
      });
    }
  }

  return findings;
}

module.exports = {
  loadIOCs,
  checkPackageIOCs,
  checkDomainIOCs,
  checkOrgIOCs,
  checkHashIOCs
};
