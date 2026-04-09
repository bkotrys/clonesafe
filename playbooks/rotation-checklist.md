# Credential rotation checklist

> **Priority:** HIGH. Work this after the wallet drain and GitHub audit.
>
> **Time budget:** 30-90 minutes depending on how many accounts you have.

This is the master list of credentials to rotate after a machine compromise. Work it top-to-bottom. Skip anything that doesn't apply to you.

For each item, the assumption is the same: **the attacker had your user-level access for N minutes and could read any file you could read**. Assume anything that was in a file, an environment variable, or an active session is potentially copied.

---

## 🔴 Tier 1 — Rotate FIRST (after wallet drain + GitHub)

### Apple ID / iCloud
- [ ] Go to https://account.apple.com → Sign-In and Security → **Change password**
- [ ] Review **Trusted Devices** → remove any device you don't recognize
- [ ] Review **Trusted Phone Numbers**
- [ ] Review **App-Specific Passwords** → revoke any you don't actively use
- [ ] Check **Sign-in activity** for unknown locations

### Google account
- [ ] Go to https://myaccount.google.com → Security
- [ ] Change password
- [ ] Review **Your devices** → sign out any you don't recognize
- [ ] Review **Third-party apps with account access** → revoke anything unnecessary
- [ ] Review **Recent security activity**
- [ ] Enable 2FA (hardware key preferred)
- [ ] Generate new backup codes
- [ ] Check Google Photos for leaked screenshots of anything sensitive (many victims discover they had password screenshots synced)

### Microsoft account (if applicable)
- [ ] https://account.microsoft.com/security → change password, review sessions, review app permissions

### Password manager (Dashlane / 1Password / Bitwarden / LastPass / Keeper)
- [ ] Change the **master password** — use a new, strong, unique phrase
- [ ] Review **active sessions / devices** → revoke anything unknown
- [ ] Check the **security dashboard** for any unusual access since the incident
- [ ] Review **recently accessed items** — anything the attacker might have read
- [ ] Rotate any password that's marked as "compromised" or "reused" in the dashboard

---

## 🟠 Tier 2 — Rotate within 2 hours

### Exchange API keys (if you have any)
For every crypto exchange you use:
- [ ] Log in → API management
- [ ] **Delete all existing API keys**
- [ ] Regenerate with:
  - Read-only by default
  - Withdrawal disabled unless absolutely necessary
  - IP whitelist enabled
  - Specific permissions (spot-trading only, no futures, no withdrawal)

Exchanges to check: Binance, Coinbase, Kraken, Bybit, KuCoin, OKX, Bitstamp, Bitget, Gate.io, Bitfinex, Huobi, HTX, MEXC, HitBTC, Crypto.com, Revolut Crypto, Uphold, Wealthsimple Crypto.

### Email accounts used on the compromised machine
For each email account (Gmail, Outlook, Proton, Fastmail, etc.):
- [ ] Change password
- [ ] Sign out of all sessions
- [ ] Review forwarding rules — attackers often set up auto-forwards to exfiltrate password resets
- [ ] Review filters — attackers hide password-reset emails with filters that auto-delete them
- [ ] Review "connected apps" / "IMAP clients" / "POP clients"
- [ ] Check sent folder for anything you didn't send
- [ ] Check trash folder for anything the attacker deleted
- [ ] Enable 2FA if not already (hardware key preferred)

### Bank accounts + financial services
- [ ] Log in to each bank online — change password
- [ ] Review recent transactions for unauthorized activity
- [ ] Check for new payees / beneficiaries you didn't add
- [ ] Check for new standing orders / direct debits
- [ ] Check card statements (credit cards, debit cards)
- [ ] If Polish: Millennium, PKO BP, mBank, Santander Polska, ING, Pekao, Alior, BNP Paribas, Citi Handlowy
- [ ] If EU: Revolut, N26, Wise, bunq
- [ ] Consider temporarily freezing cards you don't need

### Payment processors
- [ ] PayPal → Settings → Login → change password, review devices
- [ ] Stripe (if you're a merchant) → rotate API keys
- [ ] Square / Block (if applicable)
- [ ] Apple Pay / Google Pay — review transaction history

---

## 🟡 Tier 3 — Rotate within 24 hours

### SSO provider (Okta / Auth0 / OneLogin / Azure AD / Google Workspace admin)
If you're an admin or power user of any SSO:
- [ ] Rotate your own credentials
- [ ] Review active sessions for unusual locations
- [ ] Check audit log for any admin actions you didn't take
- [ ] Rotate any service accounts you manage

### Developer tool accounts
- [ ] GitLab — same flow as GitHub: tokens, SSH keys, sessions, audit log
- [ ] Bitbucket — ditto
- [ ] Codeberg, Gitea, sourcehut — ditto
- [ ] npm, PyPI, RubyGems, crates.io, pub.dev, Hex — rotate access tokens (attackers use these to publish malicious packages to your name)
- [ ] Docker Hub, GitHub Container Registry, GHCR — rotate access tokens
- [ ] Cloudflare — API tokens, global API key
- [ ] AWS — access keys (root + IAM users). Use `aws iam delete-access-key` then create new
- [ ] GCP — service account keys in `~/.config/gcloud`
- [ ] Azure — CLI tokens in `~/.azure`
- [ ] DigitalOcean — API tokens
- [ ] Vercel, Netlify, Render, Fly.io, Railway — dashboard tokens
- [ ] Heroku — API tokens
- [ ] Supabase, PlanetScale, Neon, Turso, Railway DB — connection strings + API keys
- [ ] Sentry, Datadog, Honeycomb, Grafana, Logtail — API keys
- [ ] OpenAI, Anthropic, Google AI Studio, Hugging Face — API keys (attackers use these to rack up bills on your account)

### Communication tools
- [ ] Slack — password change, active sessions review, review connected apps
- [ ] Discord — password change, review authorized apps, 2FA
- [ ] Telegram — active sessions review (Settings → Devices)
- [ ] WhatsApp — linked devices review
- [ ] Signal — linked devices (primary lives on your phone, so laptop-side compromise doesn't expose the chat DB unless you had Signal Desktop)
- [ ] Matrix / Element — sessions
- [ ] Zoom — password, signed-in devices
- [ ] Microsoft Teams — password, signed-in devices

### Social media
- [ ] X (Twitter) — password, sessions, connected apps
- [ ] LinkedIn — password, sessions, connected apps — **critical** since your job search may be happening here
- [ ] Facebook / Instagram — password, sessions
- [ ] Reddit — password, sessions, apps
- [ ] YouTube (via Google) — already handled in Google account rotation

---

## 🟢 Tier 4 — Monitor and rotate on need

### Subscription services
These are lower priority but worth cycling through over the next week:
- [ ] Netflix, Spotify, Apple Music, YouTube Premium, Disney+
- [ ] Dropbox, Box, Mega, pCloud — especially if you stored sensitive files there
- [ ] Notion, Obsidian Sync, Logseq Sync — if you keep work notes here
- [ ] Figma, Miro, Canva
- [ ] Linear, Jira, Asana, Trello, ClickUp, Basecamp
- [ ] Typefully, Buffer, Hypefury (social scheduling)

### Government / identity
- [ ] **Polish PESEL freeze** — https://www.gov.pl/web/gov/zastrzez-pesel (free, 5 minutes)
- [ ] **BIK credit monitoring alerts** — https://www.bik.pl (Poland)
- [ ] **Experian / Equifax / TransUnion credit freeze** (US) — free at each bureau's website
- [ ] **Schufa Kontakt** (Germany)
- [ ] **Creditinfo** (Nordics)
- [ ] Mobile carrier: add a port-out PIN (prevents SIM-swap). Call customer service and ask for "port protection" or "number transfer PIN"
- [ ] Government e-services: mObywatel (Polish), Estonian e-ID, etc. — review sessions if applicable

### Physical / hardware
- [ ] If you have smart locks, security cameras, smart home — review access logs for anything unexpected
- [ ] If you have a hardware wallet — verify it hasn't been tampered with (seal, physical inspection)
- [ ] Yubikey / Titan Key — review which services they're registered with, deregister + re-register on critical services if paranoid

---

## After you've completed this checklist

You've rotated:
- ✅ Crypto wallets (from `wallet-drain-procedure.md`)
- ✅ GitHub credentials (from `github-audit.md`)
- ✅ Tier 1: Apple ID, Google, Microsoft, password manager
- ✅ Tier 2: Exchange APIs, email, banks, payment processors
- ✅ Tier 3: SSO, dev tools, communication, social
- ✅ Tier 4: Subscriptions, identity monitoring, hardware

Now go to [`forensic-scan.md`](forensic-scan.md) to investigate what's actually on the compromised machine.

---

## Red flags during rotation

If during the rotation process you notice ANY of the following, escalate to "incident worse than expected":

- You discover login attempts from unfamiliar locations BEFORE the incident date — indicates a longer-running compromise
- Password reset emails arriving for services you didn't attempt to reset — means your email is compromised
- 2FA codes arriving that you didn't request — attacker is actively attempting account takeover
- Your new passwords "don't work" immediately after you set them — session hijacking in progress
- SSH keys you just revoked showing as still active after 5 minutes — possible GitHub session issue, contact GitHub support
- Unexpected SIM service issues — possible SIM-swap attempt, contact carrier immediately

If any of these happen, pause the rotation, take your phone, and call your bank + mobile carrier fraud lines. Escalate to local law enforcement if warranted.
