'use strict';

// npm provenance check.
//
// For each direct dep: query the public npm registry and inspect
// `versions[v].dist.attestations`. Two findings:
//
//   PROV-NONE     latest version has no attestations (info-only — most
//                 published packages don't have provenance yet)
//   PROV-DOWNGRADE  some prior version had attestations and a newer one
//                   from the same publisher does not. This is the
//                   load-bearing signal: it's how a hijacked publisher
//                   token gets used to ship an unsigned malicious build.
//
// Costs: one HTTPS request per direct dep, parallelized. We cap to
// MAX_DEPS to keep total wall-clock bounded.

const MAX_DEPS = 30;
const REGISTRY = 'https://registry.npmjs.org';

function registryUrl(name) {
  // npm scoped names are `@scope/pkg`. The encoded path keeps the leading
  // `@` literal but encodes the slash; we rebuild it explicitly rather
  // than the previous `replace('%40','@')` round-trip, which a future
  // maintainer could plausibly extend to `replace('%2F','/')` and
  // accidentally introduce a path-traversal SSRF.
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash < 0) return null; // malformed scoped name
    return `${REGISTRY}/@${encodeURIComponent(name.slice(1, slash))}/${encodeURIComponent(name.slice(slash + 1))}`;
  }
  return `${REGISTRY}/${encodeURIComponent(name)}`;
}

async function fetchPackage(name, { signal } = {}) {
  // npm registry is permissive on unauthenticated read — no token needed.
  const url = registryUrl(name);
  if (!url) return { _err: 'malformed package name' };
  try {
    const res = await fetch(url, { signal, headers: { 'User-Agent': 'clonesafe' } });
    if (!res.ok) return { _err: `registry returned ${res.status}` };
    return await res.json();
  } catch (err) {
    return { _err: err.message || 'fetch error' };
  }
}

/**
 * Run provenance checks against every direct dep in package.json.
 * Returns an array of findings:
 *   { ruleId, risk, weight, package, version, detail }
 *
 * The function is best-effort: on network error or registry shape
 * surprises, it returns whatever it computed and skips the broken entry.
 * Callers should treat absence of findings as "no provenance signal" —
 * not "verified clean."
 */
async function checkProvenance(deps, { timeoutMs = 8000, maxDeps = MAX_DEPS } = {}) {
  const findings = [];
  const names = Object.keys(deps).filter(n => !n.startsWith('@types/')).slice(0, maxDeps);
  if (names.length === 0) return findings;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);

  const metas = await Promise.allSettled(names.map(n => fetchPackage(n, { signal: ctrl.signal })));
  clearTimeout(timer);

  for (let i = 0; i < names.length; i++) {
    const r = metas[i];
    if (r.status !== 'fulfilled' || !r.value) continue;
    const meta = r.value;
    if (meta._err) {
      // Surface a PROV-ERROR finding (info-only) so consumers can tell
      // "registry was unreachable" apart from "registry said clean."
      // Otherwise a 429 would silently inflate confidence.
      findings.push({
        ruleId: 'PROV-ERROR', detector: 'provenance', risk: 'LOW', weight: 0,
        package: names[i],
        match: `${names[i]}: provenance check failed (${meta._err})`,
        detail: 'could not query npm registry — provenance status unknown'
      });
      continue;
    }
    const versions = meta.versions || {};
    const time = meta.time || {};
    const sortedVersions = Object.keys(versions).sort((a, b) => new Date(time[a] || 0) - new Date(time[b] || 0));
    if (sortedVersions.length === 0) continue;

    const latest = (meta['dist-tags'] && meta['dist-tags'].latest) || sortedVersions[sortedVersions.length - 1];
    const latestMeta = versions[latest] || {};
    const hasLatest = !!(latestMeta.dist && latestMeta.dist.attestations);

    // Downgrade detection: walk versions in time order, look for any
    // truthy → falsy transition by the same publisher.
    let prevHad = false;
    let prevPublisher = null;
    let downgradeFromVersion = null;
    let downgradeToVersion = null;
    for (const v of sortedVersions) {
      const vm = versions[v] || {};
      const has = !!(vm.dist && vm.dist.attestations);
      const pub = (vm._npmUser && vm._npmUser.name) || null;
      if (prevHad && !has && pub && prevPublisher && pub === prevPublisher) {
        downgradeFromVersion = downgradeToVersion = null;
        // Record the first such transition; further transitions strengthen but
        // don't add new finding rows — one signal per package is enough.
        downgradeFromVersion = sortedVersions[sortedVersions.indexOf(v) - 1];
        downgradeToVersion = v;
        break;
      }
      prevHad = has;
      if (pub) prevPublisher = pub;
    }

    if (downgradeToVersion) {
      findings.push({
        ruleId: 'PROV-DOWNGRADE',
        detector: 'provenance',
        risk: 'CRITICAL',
        weight: 50,
        blockAlone: true,
        package: names[i],
        match: `${names[i]}: provenance disappeared at v${downgradeToVersion} (last seen at v${downgradeFromVersion})`,
        detail: 'package previously had provenance attestations but a newer version from the same publisher does not — possible publisher-token hijack'
      });
    } else if (!hasLatest) {
      // Info-only — most packages still ship without provenance. We surface
      // it at LOW so report consumers see the gap without inflating the
      // score for benign cases.
      findings.push({
        ruleId: 'PROV-NONE',
        detector: 'provenance',
        risk: 'LOW',
        weight: 0,
        package: names[i],
        match: `${names[i]}@${latest} has no npm provenance`,
        detail: 'no SLSA attestations — common for older or community packages'
      });
    }
  }
  return findings;
}

module.exports = { checkProvenance };
