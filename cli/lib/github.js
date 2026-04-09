'use strict';

const VERSION = require('../../package.json').version;

function headers() {
  const h = {
    'User-Agent': `clonesafe/${VERSION}`,
    'Accept': 'application/vnd.github.v3+json'
  };
  if (process.env.GITHUB_TOKEN) {
    h['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return h;
}

async function apiFetch(path) {
  const url = `https://api.github.com${path}`;
  const res = await fetch(url, { headers: headers() });

  if (res.status === 403) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    if (remaining === '0') {
      const reset = res.headers.get('x-ratelimit-reset');
      const resetDate = reset ? new Date(parseInt(reset) * 1000).toLocaleTimeString() : 'soon';
      throw new Error(
        `GitHub API rate limit exceeded. Resets at ${resetDate}.\n` +
        'Set GITHUB_TOKEN env var to increase your limit:\n' +
        '  export GITHUB_TOKEN=ghp_your_token_here'
      );
    }
  }

  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GitHub API error: ${res.status} ${res.statusText} for ${path}`);
  return res.json();
}

async function fetchRepoMeta(owner, repo) {
  return apiFetch(`/repos/${owner}/${repo}`);
}

async function fetchOwnerMeta(owner) {
  // Try org first, fall back to user
  const org = await apiFetch(`/orgs/${owner}`);
  if (org) return { ...org, type: 'Organization' };
  const user = await apiFetch(`/users/${owner}`);
  if (user) return { ...user, type: 'User' };
  return null;
}

async function fetchContributors(owner, repo) {
  return apiFetch(`/repos/${owner}/${repo}/contributors?per_page=5`);
}

async function fetchCommits(owner, repo) {
  return apiFetch(`/repos/${owner}/${repo}/commits?per_page=10`);
}

async function fetchContents(owner, repo, ref) {
  return apiFetch(`/repos/${owner}/${repo}/contents?ref=${ref}`);
}

async function fetchRawFile(owner, repo, ref, path) {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${path}`;
  try {
    const res = await fetch(url, { headers: { 'User-Agent': `clonesafe/${VERSION}` } });
    if (!res.ok) return null;
    return res.text();
  } catch {
    return null;
  }
}

async function fetchMultipleRaw(owner, repo, ref, paths) {
  const results = new Map();
  const settled = await Promise.allSettled(
    paths.map(async (p) => {
      const content = await fetchRawFile(owner, repo, ref, p);
      if (content !== null) results.set(p, content);
    })
  );
  return results;
}

async function fetchAllFiles(owner, repo, ref) {
  const files = new Map();

  // Core files to always fetch
  const corePaths = [
    'package.json', 'README.md', 'server.js', 'index.js',
    '.gitattributes', '.gitmodules',
    'package-lock.json', 'yarn.lock'
  ];

  // Suspicious paths to probe
  const probePaths = [
    'routes/api/auth.js', 'routes/index.js', 'config/loadEnv.js',
    'config/index.js', 'middleware/index.js', 'src/index.js',
    'lib/index.js', 'loader.js', 'auth.js'
  ];

  const allPaths = [...corePaths, ...probePaths];
  const fetched = await fetchMultipleRaw(owner, repo, ref, allPaths);
  for (const [p, content] of fetched) {
    files.set(p, content);
  }

  // Discover entry points from package.json
  const pkgJson = files.get('package.json');
  if (pkgJson) {
    try {
      const pkg = JSON.parse(pkgJson);
      const entryPaths = new Set();

      // Extract from lifecycle hooks
      const scripts = pkg.scripts || {};
      for (const hook of ['prepare', 'preinstall', 'install', 'postinstall', 'prepublish']) {
        const v = scripts[hook] || '';
        const nodeMatches = v.matchAll(/node\s+(\S+)/g);
        for (const m of nodeMatches) {
          entryPaths.add(m[1].replace(/^\.\//, ''));
        }
      }

      // Main entry
      if (pkg.main) entryPaths.add(pkg.main.replace(/^\.\//, ''));

      // Bin entries
      if (typeof pkg.bin === 'string') {
        entryPaths.add(pkg.bin.replace(/^\.\//, ''));
      } else if (typeof pkg.bin === 'object') {
        for (const v of Object.values(pkg.bin)) {
          entryPaths.add(v.replace(/^\.\//, ''));
        }
      }

      // Fetch discovered entries
      const newPaths = [...entryPaths].filter(p => !files.has(p));
      if (newPaths.length > 0) {
        // Also try with .js extension
        const withExt = newPaths.flatMap(p => p.endsWith('.js') ? [p] : [p, p + '.js']);
        const extra = await fetchMultipleRaw(owner, repo, ref, withExt);
        for (const [p, content] of extra) {
          files.set(p, content);
        }
      }
    } catch {
      // package.json parse error — continue with what we have
    }
  }

  return files;
}

module.exports = {
  fetchRepoMeta,
  fetchOwnerMeta,
  fetchContributors,
  fetchCommits,
  fetchContents,
  fetchRawFile,
  fetchMultipleRaw,
  fetchAllFiles
};
