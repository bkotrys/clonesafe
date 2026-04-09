'use strict';

function parse(urlString) {
  if (!urlString) throw new Error('No URL provided');

  // Handle shorthand owner/repo format
  if (/^[a-zA-Z0-9_-]+\/[a-zA-Z0-9._-]+$/.test(urlString)) {
    const [owner, repo] = urlString.split('/');
    return { owner, repo, ref: 'HEAD' };
  }

  let url;
  try {
    url = new URL(urlString);
  } catch {
    throw new Error(`Invalid URL: ${urlString}`);
  }

  if (url.hostname !== 'github.com') {
    throw new Error(`Only GitHub URLs are supported. Got: ${url.hostname}`);
  }

  const parts = url.pathname.replace(/^\//, '').replace(/\.git$/, '').split('/');

  if (parts.length < 2 || !parts[0] || !parts[1]) {
    throw new Error(`Could not extract owner/repo from: ${urlString}`);
  }

  const owner = parts[0];
  const repo = parts[1];
  let ref = 'HEAD';

  // github.com/owner/repo/tree/branch-name
  if (parts[2] === 'tree' && parts[3]) {
    ref = parts.slice(3).join('/');
  }
  // github.com/owner/repo/commit/sha
  if (parts[2] === 'commit' && parts[3]) {
    ref = parts[3];
  }

  return { owner, repo, ref };
}

module.exports = { parse };
