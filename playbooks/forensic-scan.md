# Forensic scan — what's actually on the compromised machine

> **Priority:** HIGH. Do this after the initial rotation (wallet drain + GitHub + Tier 1 credentials). Before completing the rest of the rotation.
>
> **Time budget:** 1-2 hours.

This playbook is a read-only investigation of the compromised machine. Its goal is to determine:
1. Did the attacker establish persistence? (most important question)
2. Was a keylogger installed?
3. Were any known malicious files dropped?
4. Which files were created or modified during the attack window?
5. Are there active connections to attacker infrastructure?

**Everything in this playbook is read-only.** You will not modify, delete, or execute anything. If you find something bad, you'll document it and decide on remediation separately.

---

## Before you start

- You should have already: killed rogue processes, moved the malicious repo to Trash (not deleted), started credential rotation.
- You need terminal access on the compromised machine.
- Have your phone's notes file open to record findings.
- **Do not** run any commands that look like "cleanup" or "fix" scripts. Read-only only.

---

## macOS — the full scan

### Section 1 — Current process state

Look for anything still running from the attack.

```bash
# All user-owned processes (non-system)
ps -U $(id -u) -o pid,ppid,stat,command | grep -viE "(/System/|/usr/lib|/usr/libexec|/sbin|com\.apple|Google Chrome|iTerm|Claude|Signal|Slack|Discord|Zoom|NordVPN|ssh-agent|Homebrew|-zsh|-bash|ps -U|grep)"

# Any node processes at all
pgrep -lf node

# Any python processes
pgrep -lf python

# Network connections — any active listeners or established outbound
lsof -i -nP 2>/dev/null | grep -iE "LISTEN|ESTABLISHED" | head -30
```

**Red flags:**
- `node` / `python` / `ruby` processes you didn't start
- Listening ports on non-standard ports (not 3000, 5173, 8080, etc.)
- Established connections to unknown IPs or Vercel/Netlify/Glitch subdomains
- Processes with parent PID = 1 (orphaned, detached from your terminal)

### Section 2 — Persistence: user-level launchd

macOS's primary persistence mechanism for user-space malware.

```bash
# User LaunchAgents
ls -la ~/Library/LaunchAgents 2>/dev/null

# System-wide LaunchAgents (all users)
ls -la /Library/LaunchAgents 2>/dev/null

# System LaunchDaemons (run as root)
ls -la /Library/LaunchDaemons 2>/dev/null

# Currently loaded jobs (anything non-Apple)
launchctl list 2>/dev/null | awk 'NR>1 && $3 !~ /^com\.apple\./'
```

Compare each entry against what you'd expect. Google updater, Spotify, NordVPN, ssh-agent, Signal-desktop — all normal. Anything else is a candidate for investigation.

**For each unknown plist:**
```bash
cat "/path/to/unknown.plist"
```
Look at `ProgramArguments` or `Program` — what does it launch? If it points to a binary in a user-writable path, that's suspicious.

### Section 3 — Persistence: login items

```bash
osascript -e 'tell application "System Events" to get the name of every login item' 2>&1
```

Also check:
- System Settings → General → Login Items
- Menu bar for unfamiliar icons

### Section 4 — Persistence: shell startup files

The attacker might have appended malicious commands to your shell rc files.

```bash
# Check for anything in shell configs
for f in ~/.zshenv ~/.zprofile ~/.zshrc ~/.zlogin ~/.profile ~/.bash_profile ~/.bashrc ~/.bash_login; do
  if [ -f "$f" ]; then
    echo "=== $f ==="
    stat -f "%Sm %N" -t "%Y-%m-%d %H:%M" "$f"
    cat "$f"
    echo
  fi
done
```

**Red flags:**
- `curl ... | sh` / `curl ... | bash` lines you didn't add
- `eval $(...)` with a base64 string
- `alias sudo=...` or `alias ssh=...` (command replacement)
- Anything that sources a file in `/tmp` or `/var/tmp`
- New `export PATH=...` with an unusual directory prefix

### Section 5 — Persistence: cron / at / periodic

```bash
# User crontab
crontab -l 2>&1

# At jobs
atq 2>&1

# /etc/periodic directories
ls /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null
```

Default macOS has empty cron and only `999.local` placeholder scripts. Anything else is suspicious.

### Section 6 — Persistence: input method / keyboard layout hijack

A rogue input method or keyboard layout can log every keystroke.

```bash
# Check enabled input sources
defaults read ~/Library/Preferences/com.apple.HIToolbox AppleEnabledInputSources
defaults read ~/Library/Preferences/com.apple.HIToolbox AppleSelectedInputSources
```

Look for anything that isn't a standard Apple keyboard layout or a well-known IME.

### Section 7 — TCC (accessibility / screen recording / input monitoring) grants

Check which apps have been granted sensitive permissions. If any unknown app has Input Monitoring or Accessibility, it's a keylogger candidate.

```bash
# System TCC DB — Input Monitoring, Accessibility, Screen Capture
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value, datetime(last_modified,'unixepoch') FROM access
   WHERE service IN ('kTCCServiceListenEvent','kTCCServicePostEvent','kTCCServiceAccessibility','kTCCServiceScreenCapture')
   ORDER BY last_modified DESC;" 2>&1
```

**Red flag:** any grant added on or after the incident date to an app you don't recognize.

**Legitimate grants you'll probably see:**
- Discord (Input Monitoring) — for push-to-talk
- superwhisper / Krisp / similar (Accessibility) — voice tools
- Chrome / Safari (Screen Capture) — for screen share in meetings
- SteamHelper / Parallels / VMware (various)

### Section 8 — Kernel extensions

Third-party kexts persist across reboots and can do anything in the kernel.

```bash
kextstat 2>/dev/null | grep -v com.apple
```

Common legitimate third-party kexts:
- Lilu, WhateverGreen, VirtualSMC, AppleALC (OpenCore / Hackintosh)
- AMFIPass, RestrictEvents, AirportBrcmFixup (OCLP stack)
- SoftRAID, HighPointIOP (RAID drivers)
- Little Snitch, ReiKey, BlockBlock (Objective-See tools)
- VMware, Parallels, VirtualBox drivers

Anything else is worth investigation.

### Section 9 — New files in the attack window

This catches files dropped by the attacker.

```bash
# Replace the timestamps with your actual incident window
find ~ -type f -newermt "2026-04-08 17:25:00" ! -newermt "2026-04-08 17:45:00" 2>/dev/null \
  | grep -viE "Cache|Caches|WebKit|Chrome|Safari|Firefox|Cookies|IndexedDB|LocalStorage|\.DS_Store|Spotlight|FileProvider|Saved Application State|HTTPStorages|SiteData|Logs?/|\.log$" \
  | head -50
```

Record any unexpected files. Cross-reference with your phone timeline notes.

### Section 10 — Quarantine database (anything downloaded)

macOS records downloads in a SQLite DB.

```bash
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch','localtime'),
          LSQuarantineAgentName, LSQuarantineDataURLString
   FROM LSQuarantineEvent
   WHERE LSQuarantineTimeStamp+978307200 > strftime('%s','<incident-date>')
   ORDER BY LSQuarantineTimeStamp DESC;" 2>&1
```

Review every download since the incident. Anything you don't recognize is a candidate for analysis.

### Section 11 — /tmp and /var/tmp

Common staging areas for stealers:

```bash
find /tmp /private/tmp /var/tmp -type f -newermt "2026-04-08" 2>/dev/null \
  | grep -viE "(\.lock$|\.sock$|com\.apple|tmp\.[a-z0-9]+$)" \
  | head -30
```

**Red flags:**
- `sync[0-9]{7}/` directories (AMOS staging pattern)
- `out.zip`, `data.zip`, `result.zip`, any archive containing browser data names
- `.helper`, `.agent` hidden files (Atomic Stealer backdoor)
- `/Library/Caches/com.apple.act.mond` (axios compromise RAT IOC)

### Section 12 — SSH config tampering

```bash
cat ~/.ssh/config 2>/dev/null
cat ~/.ssh/known_hosts 2>/dev/null | wc -l
stat -f "%Sm %N" -t "%Y-%m-%d %H:%M" ~/.ssh/*
```

**Red flags:**
- `~/.ssh/config` containing `ProxyCommand` or `LocalForward` / `RemoteForward` lines you didn't add
- `~/.ssh/authorized_keys` existing (means someone can SSH in as you)
- Modification times on private key files post-incident (shouldn't change)

### Section 13 — DNS configuration tampering

```bash
# macOS DNS
scutil --dns | grep "nameserver\[" | sort -u
cat /etc/hosts
cat /etc/resolv.conf
```

**Red flags:**
- Unknown DNS servers (if you use NordVPN, `100.64.0.2` is expected; otherwise look for anything non-standard)
- Entries in `/etc/hosts` redirecting github.com, google.com, or any bank/wallet domain
- `resolv.conf` showing non-standard nameservers

### Section 14 — Homebrew / system binaries tampering

```bash
# /usr/local modifications since incident
find /usr/local -maxdepth 4 -type f -newermt "2026-04-08" 2>/dev/null | grep -viE "Cellar|var/log|Caskroom|\.lock" | head

# /Applications modifications
find /Applications ~/Applications -maxdepth 3 -name "*.app" -newermt "2026-04-08" 2>/dev/null
```

App auto-updates (Chrome, Discord, Claude, etc.) are normal. Anything else worth checking.

### Section 15 — Developer credential files

Check which credential files exist on the machine. These were readable by the attacker if present.

```bash
# Check for presence (don't print contents)
for f in ~/.aws/credentials ~/.config/gcloud/credentials.db ~/.azure/credentials \
         ~/.kube/config ~/.docker/config.json ~/.npmrc ~/.yarnrc ~/.pypirc \
         ~/.cargo/credentials ~/.netrc ~/.config/gh/hosts.yml ~/.config/glab-cli/config.yml; do
  if [ -f "$f" ]; then
    stat -f "%Sm %N" -t "%Y-%m-%d %H:%M" "$f"
  fi
done
```

Every file listed should be rotated per [`rotation-checklist.md`](rotation-checklist.md).

### Section 16 — Optional: KnockKnock (Objective-See)

For a second-opinion persistence scan using the industry-standard tool:

1. Download KnockKnock from https://objective-see.org/products/knockknock.html
2. Run it (it's a GUI tool)
3. Export results as JSON
4. Review all "third-party" entries

KnockKnock covers: Authorization Plugins, Launch Items, Login Items, Kernel Extensions, Periodic Scripts, Shell Config Files, Spotlight Importers, Dir. Services Plugins, Dock Tiles Plugins, Extensions and Widgets.

---

## Linux — abbreviated scan

(macOS is the most common target but if you're on Linux, here's the starting point.)

```bash
# Processes
ps aux | head -30
systemctl --user list-units --type=service
systemctl list-units --type=service | grep -v "loaded active running"

# User persistence
ls -la ~/.config/systemd/user/
crontab -l
cat ~/.bashrc ~/.zshrc ~/.profile

# System persistence
ls -la /etc/systemd/system/
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/

# New files
find ~ -type f -newermt "<incident date>" 2>/dev/null | head -50

# Network
ss -tunap 2>/dev/null | grep ESTAB
```

## Windows — abbreviated scan

```powershell
# Processes
Get-Process | Where-Object { $_.Path -notlike "*Windows*" }

# Startup items
Get-CimInstance Win32_StartupCommand
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select TaskName, TaskPath

# Services
Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.StartType -eq 'Automatic'}

# Network
Get-NetTCPConnection | Where-Object State -eq 'Established'

# Recent files
Get-ChildItem -Path $HOME -Recurse -File -ErrorAction SilentlyContinue | `
  Where-Object LastWriteTime -gt "<incident date>" | Select-Object FullName, LastWriteTime
```

Use **Autoruns** from Microsoft Sysinternals for a thorough persistence scan: https://learn.microsoft.com/sysinternals/downloads/autoruns

---

## Recording findings

For each section, record in your phone notes:

```
Section 1 — processes: CLEAN / FOUND: <details>
Section 2 — launchd: CLEAN / FOUND: <paths>
...
```

At the end you'll have a complete forensic ledger of the machine state.

---

## Interpreting results

### If everything is CLEAN

Your attack was "stage-1 only": exfil happened, but the attacker didn't bother installing persistence. This is the most common outcome for commodity crypto-stealer attacks. You're probably in good shape — continue with the credential rotation and 90-day monitoring. **You do NOT need to reinstall the OS** if the forensic scan is clean across the board.

### If you find persistence

Options in order of severity:
1. **Manual removal** — remove the specific artifact (plist, cron entry, file). Requires confidence that you found it all. Risk: missing something.
2. **Restore from pre-incident backup** — if you have Time Machine and the last backup is clean, restore the whole system. Verify the backup is pre-incident.
3. **Full OS reinstall** — the only way to be 100% sure. Takes hours + reconfigure time, but eliminates all persistence risk. Recommended if you found unexpected kexts or kernel-level modifications.

### If you find active connections to attacker infrastructure

- Note the IP / domain
- Block it in `/etc/hosts` or at the router
- Kill the connecting process
- Start the forensic scan over to find the persistence that's creating those connections
- Consider unplugging the network entirely until you've cleaned up

### If you find a keylogger

- Treat every credential you typed on this machine since incident date as compromised (not just the ones in your rotation list)
- Reinstall the OS. No half-measures.
- Change every credential you use day-to-day.

---

## When you're done

You should have:
- ✅ Scanned every persistence category
- ✅ Checked for active connections
- ✅ Checked for new files in the attack window
- ✅ Recorded findings in your phone notes
- ✅ Decided on remediation (clean / manual removal / reinstall)

Now move on to [`90-day-monitoring.md`](90-day-monitoring.md) to set up long-term watching.

Or, if you're also in Poland, [`../playbooks/`](../playbooks/) will include a PESEL freeze guide in a future release.
