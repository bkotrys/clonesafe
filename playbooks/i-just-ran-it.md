# I just ran a malicious repo — first 30 minutes

> **If you're reading this, stop scrolling and start executing.** Every minute counts in the first hour. Do the top items first. Don't read ahead. Don't skip around.

This playbook was written by someone who got hit by a real Contagious Interview attack and did incident response on their own machine for 8 hours. The ordering is from experience, not theory.

---

## Minute 0-5 — CONTAIN

### 1. Stay calm, get your phone

You'll need your phone for 2FA and for reading this from a clean device if you don't want to use the potentially-compromised machine. **Do not use the compromised machine to log in to sensitive accounts for rotation until Phase 2.** Use your phone.

### 2. Kill rogue processes on the compromised machine

Open a terminal (not in your editor — a fresh terminal window) and run:

```bash
ps -ef | grep -iE "node|python|cargo|ruby" | grep -v grep
```

Look for processes you don't recognize. Common signs:
- `node server` / `node ./server` running in the background (you didn't start it)
- `node index.js` in a directory you never cd'd into
- Any process with parent PID `1` (orphaned, detached from terminal) that you didn't create
- Any process whose path includes the malicious repo directory

For each one:

```bash
kill -9 <PID>
```

If it respawns automatically, you have persistence. Don't panic — we'll deal with it in Phase 3. For now, just keep killing and move on.

### 3. Check for network connections to the attacker

```bash
lsof -i -nP 2>/dev/null | grep ESTABLISHED
```

Look for any connection to domains/IPs you don't recognize. Record them. If you see active exfiltration, you can block it with:

```bash
sudo route add -host <IP> 127.0.0.1
```

(macOS — this null-routes the IP. Linux uses `iptables`.) This is temporary and won't survive reboot, but stops exfil right now.

### 4. Do NOT delete the repo yet

You'll need it for forensic analysis. If it makes you feel better, **move** the directory to Trash (macOS) or elsewhere:

```bash
mv ~/path/to/malicious-repo ~/.Trash/
```

But do not empty Trash. Do not `rm -rf`. We'll read the files during Phase 3.

### 5. Write down the timeline on your phone (not this machine)

Open your phone's Notes app. Write:

- **Incident date + time:** (when did you run `npm install`)
- **Repo URL:** (full GitHub URL)
- **Source:** (who sent it — recruiter name, email, Discord handle, LinkedIn profile URL)
- **Your claim on this machine at the time:**
  - Which crypto wallets did you have unlocked or loaded in the browser? (MetaMask, Phantom, Rabby, etc.)
  - Which email accounts were logged in?
  - Which password manager sessions were active?
  - Which SSH / API sessions were active?
  - Were you in a project directory with a `.env` file?
- **What you've noticed that's off:** (weird processes, slow machine, network activity, browser tabs you didn't open)

Keep this note open on your phone. You'll update it throughout the next 8 hours.

---

## Minute 5-30 — STABILIZE

### 6. Block the exfil domain at DNS level (optional but fast)

Edit `/etc/hosts` and null-route any domain you identified:

```bash
sudo nano /etc/hosts
```

Add lines:
```
0.0.0.0  exfil-domain.example.com
```

This prevents any stage-2 payload from phoning home.

### 7. Scan for the most common immediate signals

Look for a `nohup.out` file in the malicious repo directory — if it exists, the prepare hook ran a background server:

```bash
ls -la ~/.Trash/<malicious-repo>/nohup.out 2>/dev/null
cat ~/.Trash/<malicious-repo>/nohup.out 2>/dev/null
```

If it says something like "API Key verified successfully" or any similar "success" message from code you didn't write, that's confirmation the malicious code executed.

### 8. Check for new files in the last 30 minutes outside the repo directory

```bash
find ~ -type f -newermt "30 minutes ago" 2>/dev/null \
  | grep -viE "Cache|Caches|\.log$|Chrome|Safari|Firefox|\.DS_Store|IndexedDB" \
  | head -40
```

Anything new that you didn't create is worth investigating. Record paths in your phone notes.

### 9. Check running `launchd` / startup items

On macOS:
```bash
launchctl list | awk 'NR>1 && $3 !~ /^com\.apple\./' | head -30
ls -la ~/Library/LaunchAgents/
ls -la /Library/LaunchAgents/ /Library/LaunchDaemons/
```

Compare to what you'd expect. Anything you don't recognize is a persistence candidate.

### 10. Decide: phone-first rotation or machine rotation

If your phone is clean and you have access to password managers there, do the rotation from your phone. It's safer than using the potentially-compromised machine.

If you have to use the compromised machine, that's OK — the deep forensic scan that runs later will catch any keylogger. Just don't type your new wallet seed phrases on this machine ever.

---

## After minute 30 — continue with these playbooks in order

You've contained the immediate threat. Now work through the phases methodically. **Do these in order**. The order matters.

1. **[`wallet-drain-procedure.md`](wallet-drain-procedure.md)** — if you have crypto. Highest priority. Only irreversible category of loss.
2. **[`github-audit.md`](github-audit.md)** — revoke SSH keys, tokens, sessions; audit for unauthorized activity
3. **[`rotation-checklist.md`](rotation-checklist.md)** — the full list of credentials to rotate
4. **[`forensic-scan.md`](forensic-scan.md)** — thorough read-only investigation of what's on the machine
5. **[`90-day-monitoring.md`](90-day-monitoring.md)** — ongoing watchlist for slow-burn fraud

---

## If you need help from another human

- **GitHub Abuse:** https://github.com/contact/report-abuse (tag: malware, report the repo)
- **Vercel Abuse:** https://vercel.com/abuse (if the exfil domain is `*.vercel.app`)
- **FBI IC3:** https://www.ic3.gov (US; for Contagious Interview / DPRK-linked incidents)
- **CISA:** https://www.cisa.gov/report (US; especially if you're a federal contractor)
- **CERT.PL:** https://incydent.cert.pl (Poland)
- **National CSIRT:** find yours at https://www.first.org/members/teams/
- **Your employer's security team:** if this happened on a work machine, tell them NOW. Don't wait.

---

## What NOT to do in the first 30 minutes

- ❌ Don't panic-delete everything — you'll need the forensic artifacts
- ❌ Don't post publicly about the specific repo / recruiter yet — anonymize first, wait until investigation is complete
- ❌ Don't restore from backup without reading the forensic-scan playbook first — you might restore into a compromised snapshot
- ❌ Don't skip the crypto wallet drain to "research more" — every minute the attacker has your seed phrase, your funds are at risk
- ❌ Don't reinstall macOS yet — that erases the forensic evidence you need for investigation
- ❌ Don't type your new seed phrase on the compromised machine — use your phone or a clean device
- ❌ Don't rely on antivirus — most commodity Node.js stealers don't trip AV signatures

---

## When you've done everything in this playbook

You should have:
- ✅ Killed any rogue processes
- ✅ Moved the malicious repo to Trash (not deleted)
- ✅ Written the timeline on your phone
- ✅ Identified any active exfil connections
- ✅ Read `nohup.out` or equivalent for confirmation of execution
- ✅ Listed any new files / persistence candidates for the forensic scan

Now go to [`wallet-drain-procedure.md`](wallet-drain-procedure.md) next. Do not skip.
