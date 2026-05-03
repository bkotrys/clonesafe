'use strict';

// CycloneDX 1.6 + SPDX 2.3 SBOM emitters.
//
// SBOM here is intentionally narrow: it's an inventory of the dependency
// closure clonesafe observed (npm, pypi, rubygems, composer), with risk
// flags pulled from clonesafe findings. It is NOT a full BOM of every
// transitive native dep — that's the job of syft/cyclonedx-cli, not a
// supply-chain scanner.

const crypto = require('crypto');
const VERSION = require('../../package.json').version;

function purl({ name, version, ecosystem }) {
  const eco = {
    npm: 'npm',
    pypi: 'pypi',
    rubygems: 'gem',
    composer: 'composer',
    cargo: 'cargo',
    go: 'golang'
  }[ecosystem] || ecosystem;
  const cleanVersion = version ? String(version).replace(/^[\^~>=<\s]+/, '') : '';
  return `pkg:${eco}/${name}${cleanVersion ? '@' + cleanVersion : ''}`;
}

function emitCycloneDX({ owner, repo, ref, deps, findings }) {
  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;
  // Dedupe by purl — CycloneDX requires bom-ref uniqueness within a doc.
  const seen = new Set();
  const components = [];
  for (const d of deps) {
    const ref = purl(d);
    if (seen.has(ref)) continue;
    seen.add(ref);
    components.push({
      'bom-ref': ref,
      type: 'library',
      name: d.name,
      version: d.version || 'unknown',
      purl: ref
    });
  }
  const vulnerabilities = (findings || [])
    .filter(f => f.ghsa || (f.ruleId === 'OSV-MAL'))
    .map(f => ({
      id: f.ghsa,
      source: { name: 'OSV' },
      ratings: [{ severity: 'critical' }],
      affects: f.match ? [{ ref: `pkg:npm/${(f.match.split('@')[0] || '').trim()}` }] : []
    }));
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'clonesafe', name: 'clonesafe', version: VERSION }],
      component: {
        type: 'application',
        name: `${owner}/${repo}`,
        version: ref || 'HEAD',
        'bom-ref': `pkg:github/${owner}/${repo}@${ref || 'HEAD'}`
      }
    },
    components,
    vulnerabilities
  };
}

function emitSPDX({ owner, repo, ref, deps }) {
  const ts = new Date().toISOString();
  const docNs = `https://clonesafe.dev/spdx/${owner}/${repo}/${ref || 'HEAD'}-${Date.now()}`;
  const root = `SPDXRef-Package-${owner}-${repo}`;
  const packages = [
    {
      SPDXID: root,
      name: `${owner}/${repo}`,
      versionInfo: ref || 'HEAD',
      downloadLocation: `https://github.com/${owner}/${repo}`,
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION'
    },
    ...deps.map(d => ({
      SPDXID: `SPDXRef-${d.ecosystem}-${(d.name || '').replace(/[^A-Za-z0-9.-]/g, '-')}-${(d.version || 'unknown').replace(/[^A-Za-z0-9.-]/g, '-')}`,
      name: d.name,
      versionInfo: d.version || 'unknown',
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: purl(d) }]
    }))
  ];
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${owner}/${repo}-clonesafe-sbom`,
    documentNamespace: docNs,
    creationInfo: {
      created: ts,
      creators: [`Tool: clonesafe-${VERSION}`]
    },
    documentDescribes: [root],
    packages,
    relationships: deps.map(d => ({
      spdxElementId: root,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: `SPDXRef-${d.ecosystem}-${(d.name || '').replace(/[^A-Za-z0-9.-]/g, '-')}-${(d.version || 'unknown').replace(/[^A-Za-z0-9.-]/g, '-')}`
    }))
  };
}

module.exports = { emitCycloneDX, emitSPDX, purl };
