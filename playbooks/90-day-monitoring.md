# 90-day monitoring watchlist

> **Priority:** ONGOING. Set up in the first 24 hours after the incident. Check on the cadence below for 90 days.
>
> **Time budget:** 15 minutes to set up, 5-10 minutes weekly to maintain.

The malicious code is gone. The credentials are rotated. The forensic scan is clean. **But stolen data can surface weeks or months later** — in phishing attempts, unauthorized account activity, slow-burn identity fraud, or attempted credential reuse on services you forgot to rotate.

This playbook is about passive watching, not active defense. It's designed to minimize your cognitive load while maximizing detection of follow-on abuse.

---

## Daily (first 7 days)

You're still in the reactive phase. Check these daily for the first week:

- [ ] **Wallet activity** — open your NEW wallet addresses on Etherscan / Solscan / BscScan / block explorers. Verify only the transactions you expect.
- [ ] **Old wallet addresses** — check that nothing moves out. If anything moves, the attacker has leveraged an unrevoked approval; go back to revoke.cash and revoke all remaining approvals.
- [ ] **Exchange accounts** — log into each exchange you use. Check recent trades, deposits, withdrawals, login history.
- [ ] **Email inbox** — look for password reset emails for services you don't use, "new sign-in from..." alerts, 2FA codes you didn't request.
- [ ] **Bank + card statements** — check for any transactions you don't recognize. Any amount, even $1 (often a test charge).
- [ ] **Phone SMS** — unexpected 2FA codes, "your number is being transferred" alerts, billing notifications from your carrier.

---

## Weekly (weeks 2-12)

You're in the watching phase. Drop to weekly checks.

### Sunday morning routine (15 minutes)

1. **GitHub security log** — https://github.com/settings/security-log
   - Filter: last 7 days
   - Look for any event you didn't perform

2. **Email forwarding + filters** — re-verify no new forwarding rules or filters on your email accounts. Attackers sometimes set these up on a delay.
   - Gmail: https://mail.google.com/mail/u/0/#settings/fwdandpop
   - Gmail: https://mail.google.com/mail/u/0/#settings/filters

3. **Password manager security dashboard** — Dashlane / 1Password / Bitwarden all have security dashboards showing:
   - Reused passwords
   - Compromised passwords (from breach databases)
   - Weak passwords
   - Unusual access

4. **Crypto wallet activity** — check new wallets (expecting only your own TXs) and old wallets (expecting zero activity).

5. **Bank statements** — scan the last week's transactions across all accounts.

6. **Apple ID / Google / Microsoft** — check active sessions and recent login activity.

7. **Exchange accounts** — verify no unauthorized activity, no new API keys created, no new withdrawal addresses whitelisted.

---

## Monthly (months 1-3)

Broader sweep on the 1st of each month.

### Identity monitoring

- **BIK credit monitoring (Poland)** — https://www.bik.pl — check for any new credit applications. Alerts should fire if your PESEL was frozen per `rotation-checklist.md`, but verify.
- **Experian / Equifax / TransUnion (US)** — pull your free credit report and scan for unauthorized accounts.
- **Schufa (Germany)** — request a free copy annually; check between incidents.
- **Country-specific credit bureaus** elsewhere.

### Domain / subdomain monitoring

If you have any personal or company domains, check that:
- DNS hasn't been tampered with
- No new subdomains created
- No unexpected certificate issuance in CT logs (use crt.sh)
- Registrar account hasn't been accessed

### Dark web monitoring (free tier)

- https://haveibeenpwned.com — enter every email you've used, see if new breaches have surfaced
- https://dehashed.com (paid) or Troy Hunt's free alerts at HIBP
- DeHashed, Constella, IntelX, Snusbase — paid tier but cover corporate / exchange breaches

### Review all the accounts in `rotation-checklist.md`

- Did you miss any?
- Are any showing unusual login patterns?
- Any new "authorized apps" in your OAuth grants across services?

---

## What to watch for — red flags

The following events suggest the attacker is still benefiting from the stolen data:

### Phishing attempts referencing stolen context

- Emails/messages that mention specific details only the attacker would know (your full name + the specific company you were "interviewing" with, your wallet addresses, your project names from the leaked repo access)
- Impersonation attempts: fake "Ledger support", fake "Apple security team", fake "GitHub abuse review"
- Increased spam volume to addresses only used for specific services (indicates data was sold to spam lists)

### Account takeover attempts

- "Someone tried to sign in from a new location" alerts — attacker attempting credential reuse elsewhere
- Password reset emails you didn't initiate
- 2FA codes you didn't request
- "Your password was changed" notifications

### Follow-on fraud

- Unusual transactions on bank statements
- New credit card applications (catch via credit monitoring)
- New phone lines opened in your name (catch via credit monitoring)
- Tax refund already claimed (catch via your national tax authority's online portal)

### Wallet activity

- Old wallet addresses receive unexpected deposits — suspicious, attacker might be "testing" if you're still watching
- Unexpected NFT airdrops on old addresses — attacker trying to bait you into signing malicious transactions
- Any movement from old addresses that you didn't initiate — means seed phrase was compromised, even funds you thought you moved are at risk (unlikely but possible if you left dust)

---

## When to escalate

If during the 90-day window you observe ANY of:

1. **Active account takeover** — someone is actively logging into your accounts
2. **Unauthorized transactions** — real money moved without your consent
3. **Identity theft in progress** — credit applications, loans, tax fraud
4. **Persistent threats** — your machine continues to show signs of compromise after the forensic scan was clean

...then:

- **File a report** with your local cybercrime unit. IC3 (US), CERT.PL (Poland), Action Fraud (UK), etc.
- **Notify affected financial institutions** immediately — they have fraud response teams
- **Consider professional incident response** — if you're a high-value target or this is a workplace incident, engage a professional DFIR firm
- **Reconsider OS reinstall** if you haven't already done one

---

## What to stop worrying about after 90 days

If nothing has happened in 90 days:

- The commodity crypto-stealer part of the attack has clearly moved on. Commodity attackers don't hold onto stale data.
- Your credentials are rotated.
- Your machine is clean.
- Any follow-on abuse would have shown up by now.

**You can relax.** Keep using unique passwords, keep 2FA enabled, keep your password manager updated, and check your bank statements monthly like every responsible adult. That's enough.

The only things to continue long-term:

- PESEL freeze stays on until you explicitly need credit (then lift for 24h, then refreeze)
- Credit monitoring continues passively
- Be hyper-aware of phishing impersonating Ledger / Apple / GitHub / your bank forever — this is just good practice
- Keep the anonymized case study of your incident. You may want to share it at some point to help other devs.

---

## Emotional note

Incident response is exhausting. The days after an attack feel disproportionately scary — every weird email, every slow-loading webpage, every unfamiliar notification feels like the attacker striking again.

Most of these are noise. Your amygdala is pattern-matching everywhere because it just got burned. That's normal. It will fade.

The single best predictor of "did you fully recover" is: did you do the rotation checklist thoroughly and on time. If you did, you're 99% safe. The remaining 1% is monitoring, and this playbook handles that.

You did the right thing by taking it seriously. Now take a break, sleep on it, and come back to normal life. You are not broken. Your machine is not haunted. The attacker is on to the next victim.
