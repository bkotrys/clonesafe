# GitHub audit + credential rotation

> **Priority:** HIGH. Do this immediately after the wallet drain in [`wallet-drain-procedure.md`](wallet-drain-procedure.md).
>
> **Time budget:** 15-30 minutes.

Your `~/.ssh/id_*` private keys and `~/.config/gh/hosts.yml` GitHub CLI token were readable by the malicious process. Assume they were copied. Rotate and audit.

---

## Step 1 — Revoke the old credentials (from a clean device or your phone)

Open https://github.com/settings in a browser **on your phone or a clean device**. Ideal: a device that was never near the compromised machine.

### 1a. SSH keys
- Go to https://github.com/settings/keys
- Find every SSH key you currently have registered. For each, click "Delete"
- Even keys you "don't use anymore" — delete them. If the attacker has your disk, they have all of them.
- **Note:** this will break any CI/CD systems or other machines using the same key. You'll regenerate later.

### 1b. GPG keys
- Go to https://github.com/settings/keys (same page, scroll down)
- Review and delete any GPG keys whose corresponding private keys were on the compromised machine (check `~/.gnupg/` on the affected machine)

### 1c. Personal Access Tokens (classic + fine-grained)
- Go to https://github.com/settings/tokens
- Delete every token. All of them.
- Also check https://github.com/settings/tokens?type=beta for fine-grained tokens

### 1d. OAuth applications
- Go to https://github.com/settings/applications
- Look for "Authorized OAuth Apps" tab
- Find "GitHub CLI" — revoke it. This invalidates the token in your `hosts.yml`.
- Revoke any other OAuth apps you don't recognize or don't need

### 1e. Active sessions
- Go to https://github.com/settings/sessions
- "Sign out of all other sessions" — this invalidates any stolen session cookies

### 1f. Change your GitHub password
- Go to https://github.com/settings/security
- Change the password (use your password manager to generate a strong one)
- Enable 2FA if you haven't already (use a hardware key or TOTP, NOT SMS)

### 1g. Recovery codes
- Regenerate 2FA recovery codes at https://github.com/settings/security — invalidates old ones
- Store the new ones in your password manager, not as a text file on disk

---

## Step 2 — Audit the security log for unauthorized activity

Go to https://github.com/settings/security-log

Filter by date: everything since the incident. Look for these event types as red flags:

| Event | What it means | Action |
|---|---|---|
| `public_key.create` | New SSH key added | If not you, attacker has your account — revoke immediately |
| `personal_access_token.create` | New PAT created | Same — revoke |
| `oauth_authorization.create` | New OAuth app authorized | Same |
| `repo.transfer` | Repo ownership changed | Transfer it back, investigate |
| `repo.add_member` | Collaborator added | Remove, investigate |
| `org.invite_member` | Someone invited to your org | Revoke invite |
| `user.login` from unfamiliar IP/location | Session hijack | Sign out all, change password |
| `user.changed_email` | Email changed | Change it back, lock down account |
| `user.two_factor_disabled` | 2FA turned off | Re-enable immediately |
| `repo.access` from unfamiliar user | Private repo access | Investigate who |

If you find ANY of these from a session you didn't make: treat it as a confirmed account compromise and follow GitHub's account recovery flow: https://github.com/contact

---

## Step 3 — Audit per-repo activity

For each of your important repos, especially any private ones with committed secrets:

1. Go to `https://github.com/<owner>/<repo>/activity`
2. Filter by date since the incident
3. Look for commits, force-pushes, branch creations, tag creations, releases you didn't make
4. Check `https://github.com/<owner>/<repo>/settings/keys` — deploy keys
5. Check `https://github.com/<owner>/<repo>/settings/hooks` — webhooks
6. Check `https://github.com/<owner>/<repo>/settings/secrets/actions` — GitHub Actions secrets (the attacker can't read these via a leaked CLI token, but they can exfiltrate them if they can push to a branch that workflows run on)

On the command line from a clean environment:
```bash
git log --since="<incident date>" --all
git reflog  # catches force-pushes
```

Every entry should be yours. If not, revert and investigate.

---

## Step 4 — Org-level audit (if you own any organizations)

For each org:

1. Go to `https://github.com/organizations/<org>/settings/audit-log`
2. Same filters and red flags as personal account
3. Check `https://github.com/organizations/<org>/people` — members list
4. Check `https://github.com/organizations/<org>/outside-collaborators`
5. Check `https://github.com/organizations/<org>/settings/applications` — OAuth apps with org access
6. Require 2FA for all org members if not already enabled

---

## Step 5 — Rotate committed secrets in repositories

If any of your private repos contain committed secrets in current OR historical commits, those secrets may have been exfiltrated.

On the compromised machine (or a clean clone from your new SSH key):

```bash
cd ~/codebase/your-repo
git log -p --all 2>/dev/null | grep -iE "(api[_-]?key|secret|token|password|bearer|authorization|aws|mongodb://|postgres://|mysql://|@github\.com/|\.heroku|private[_-]?key|sk_live_|pk_live_)" | head -50
```

For each hit:
- Identify what service the secret belongs to
- Rotate that specific secret on the service
- **Git history cleanup is secondary** — rotating the secret on the real service invalidates the leak, even if the old value is still in git history. Only do a BFG / filter-repo rewrite if the repo is public.

Common places secrets hide:
- `.env`, `.env.production`, `.env.local` (even if gitignored NOW, check if they were ever committed)
- `config/*.yml`, `config/*.json`
- `terraform/*.tfvars`
- `docker-compose.yml` (hardcoded passwords)
- `Dockerfile` (hardcoded build secrets)
- CI/CD workflow files (hardcoded tokens)

---

## Step 6 — Regenerate SSH keys and gh CLI auth on the compromised machine

After you've revoked everything on GitHub, generate new credentials on the (now cleaned) compromised machine.

**Important:** only do this AFTER you've completed the [`forensic-scan.md`](forensic-scan.md) playbook and confirmed the machine has no persistence. If there's a keylogger still running, your new credentials will be stolen during generation.

```bash
# Delete old keys
mv ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.OLD.compromised
mv ~/.ssh/id_ed25519.pub ~/.ssh/id_ed25519.pub.OLD.compromised

# Generate new key
ssh-keygen -t ed25519 -C "your-email@example.com"

# Re-auth gh CLI
gh auth logout
gh auth login
```

Add the new public key to GitHub at https://github.com/settings/keys.

Test:
```bash
ssh -T git@github.com
```

Should respond with "Hi <username>! You've successfully authenticated."

---

## Step 7 — Check GitHub Actions runners

If you self-host any Action runners (`actions-runner/` on a machine you control):

- Check the runner machines for any unexpected activity
- Re-register any runners that were configured using the compromised PAT/token
- Review the runner configurations for any environment variables containing secrets

---

## Step 8 — Notify collaborators

If you share repos with teammates or collaborators:

- Send them a heads-up that your SSH key and tokens were compromised and have been rotated
- Ask them to watch for any suspicious commits attributed to your account in the incident window
- If you have an employer: tell your security team NOW, don't wait

---

## When you've done everything in this playbook

You should have:
- ✅ All old SSH keys, GPG keys, PATs, OAuth apps revoked on GitHub
- ✅ All active sessions signed out, password changed, 2FA re-verified
- ✅ Security log audited with no unknown activity
- ✅ Per-repo activity audited for each important repo
- ✅ Any committed secrets rotated on the real services
- ✅ New SSH key generated and added to GitHub (after forensic scan)
- ✅ `gh auth` re-established with new credentials

Now go to [`rotation-checklist.md`](rotation-checklist.md) for the broader credential rotation.
