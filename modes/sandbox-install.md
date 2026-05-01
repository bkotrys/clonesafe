---
name: sandbox-install
description: Opt-in dynamic install harness — runs `npm install` inside a locked-down Docker container and folds runtime anomalies into the verdict.
trigger: --sandbox flag on `clonesafe`, or `npm run test:docker` for the fixture suite
---

# Sandbox Install Harness

clonesafe is a **static** scanner by default. Phase 0/Phase A/Phase B never execute
code from the target. The sandbox harness is a **separate, opt-in** dynamic phase
for users who would have cloned the repo anyway and want a second layer of
runtime evidence before doing so.

## What it does

1. Pulls a tarball of the repo via `https://api.github.com/repos/{o}/{r}/tarball/{ref}`.
2. Materializes it into a temp directory on the host.
3. Spins up `clonesafe-sandbox:ci` (built from `scripts/sandbox/Dockerfile`):
   - `--network=none`
   - `--cap-drop=ALL`
   - `--security-opt=no-new-privileges`
   - `--read-only` rootfs
   - tmpfs `/work` (128 MB) and `/trace` (8 MB)
   - 256 PIDs, 512 MB memory cap
4. Inside the container, copies the source into `/work` and runs
   `npm install --ignore-scripts=false` under `strace -f -e trace=network,process,openat`.
5. Emits a JSON report with anomaly counts: DNS attempts, network syscalls,
   shell/curl/wget spawns, `~/.ssh/...` reads, `/proc/<pid>/environ` reads.
6. The CLI maps the classification onto the existing verdict ladder:
   - **MALICIOUS** (any DNS / connect / SSH / env reads) → `BLOCK`
   - **SUSPICIOUS** (shell/curl spawns only) → bumps `PROCEED` → `CAUTION`
   - **CLEAN** → no change

## Why `--network=none` and not a recording proxy

A recording proxy lets the install actually exfiltrate. Severing the network
turns every `axios.post(...)` and `curl ...` into a failed `connect()` syscall
that strace logs without leaking. Anomalies are detected as **attempts**, not
successful exfil.

## Why this is opt-in

This phase **does** execute install-time code from the target repo. The
container hardening is good but isolation is never zero-risk. The default
clonesafe path remains static-only. Use `--sandbox` only when:
- you would have cloned and installed the repo anyway, OR
- you are running on disposable CI infrastructure.

## When it's most useful

- The static scan returns CAUTION/WARN and you want a runtime cross-check.
- The repo passes static analysis but feels off (recent org, thin history).
- You're triaging a large batch of suspect repos and want to escalate ones
  that touch network during install.

## When NOT to rely on it

- A scan returning PROCEED + sandbox-CLEAN is **not** proof of safety; an
  attacker can stage stage-2 behind a `postinstall` time-bomb.
- A scan returning BLOCK statically should never be downgraded by a CLEAN
  sandbox run. The verdict floor is one-way.

## Test suite

`npm run test:docker` runs the harness against `tests/fixtures/clean-npm`
(must classify CLEAN) and `tests/fixtures/lifecycle-backgrounding`
(must produce process-spawn anomalies). It SKIPS gracefully if Docker is
unavailable on the host.
