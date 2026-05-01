'use strict';

// Docker-based dynamic install harness.
//
// Architecture:
//   - We build (or reuse) an image from scripts/sandbox/Dockerfile.
//   - For each fixture/repo, we mount its files read-only into /work and
//     copy them into a writable scratch dir inside the container before
//     running `npm install --ignore-scripts=false` under strace.
//   - The container runs with --network=none, --cap-drop=ALL, --read-only,
//     no /tmp tmpfs mount required (image already provides /trace tmpfs in
//     the run command). Any network/process/SSH-path activity in the
//     strace log is logged as an anomaly.
//
// IMPORTANT: this module DOES execute code from the target. It is gated
// behind explicit opt-in (--sandbox flag, scripts/sandbox/Dockerfile must
// be built). The default clonesafe path remains static analysis only.

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const IMAGE = 'clonesafe-sandbox:ci';
const SANDBOX_DIR = path.resolve(__dirname, '..', '..', 'scripts', 'sandbox');

function dockerAvailable() {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  return r.status === 0;
}

function imageExists() {
  const r = spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'ignore' });
  return r.status === 0;
}

function buildImage() {
  const r = spawnSync('docker', ['build', '-t', IMAGE, '-f', path.join(SANDBOX_DIR, 'Dockerfile'), SANDBOX_DIR], {
    stdio: 'inherit'
  });
  if (r.status !== 0) throw new Error(`docker build failed (exit ${r.status})`);
}

function ensureImage() {
  if (!dockerAvailable()) throw new Error('Docker is not available on PATH.');
  if (!imageExists()) buildImage();
}

// Common docker run flags shared by the directory-input and tarball-input
// harness invocations. Centralized so any hardening change applies to both
// codepaths.
function dockerRunFlags(timeoutSec) {
  return [
    'run', '--rm',
    '--network=none',
    '--cap-drop=ALL',
    // strace requires CAP_SYS_PTRACE to follow forks across uids; we keep
    // ALL other caps dropped. Combined with --network=none and read-only
    // root, the worst the install can do inside is exhaust the tmpfs.
    '--cap-add=SYS_PTRACE',
    '--security-opt=no-new-privileges',
    // Some Docker seccomp profiles deny process_vm_readv/process_vm_writev
    // which strace needs. Relax just seccomp; cap drops still apply.
    '--security-opt=seccomp=unconfined',
    '--pids-limit=256',
    '--memory=512m',
    '--read-only',
    '--tmpfs', '/work:rw,size=256m,uid=10001,gid=10001,mode=0755',
    '--tmpfs', '/trace:rw,size=8m,uid=10001,gid=10001,mode=0755',
    // Many install scripts (benign and malicious) shell out and redirect to
    // /tmp. Without a writable /tmp, redirect setup fails and the command
    // never runs — meaning we'd miss the very anomalies we want to detect.
    // Sized small enough that a runaway can't fill the host.
    '--tmpfs', '/tmp:rw,size=32m,uid=10001,gid=10001,mode=1777',
    '-e', `CLONESAFE_TIMEOUT=${timeoutSec}`,
    // Force a complete PATH: node:22-alpine on some hosts spawns the entrypoint
    // with PATH that excludes /bin and /sbin, which means npm's lifecycle
    // scripts can't find `sh` to run `sh -c "..."`.
    '-e', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
  ];
}

/**
 * Run the install harness over a directory containing a package.json.
 * The directory is mounted read-only and copied into the container's
 * tmpfs before install runs. Used by the test fixture suite.
 */
function runHarness(dir, { timeoutSec = 60 } = {}) {
  ensureImage();
  const harnessHost = path.join(SANDBOX_DIR, 'install-and-trace.sh');
  if (!fs.existsSync(harnessHost)) throw new Error(`harness script missing: ${harnessHost}`);

  const args = [
    ...dockerRunFlags(timeoutSec),
    '-v', `${dir}:/src:ro`,
    '-v', `${harnessHost}:/usr/local/bin/install-and-trace.sh:ro`,
    '--entrypoint', '/bin/sh',
    IMAGE,
    '-c',
    'cp -r /src/. /work/ && /usr/local/bin/install-and-trace.sh install'
  ];
  return runAndParse(args);
}

/**
 * Run the install harness against a downloaded GitHub tarball.
 *
 * SECURITY: the tarball is mounted read-only as raw compressed bytes — the
 * host NEVER sees the decompressed source. Extraction happens inside the
 * container's tmpfs `/work` with `--strip-components=1` and `--no-same-owner`
 * so an archive with attacker-controlled symlinks or owners can only affect
 * the ephemeral tmpfs, not the host filesystem.
 *
 * Returns the parsed JSON report (which may have status=skipped if the
 * archive doesn't contain a package.json).
 */
function runHarnessOnTarball(tarPath, { timeoutSec = 90 } = {}) {
  ensureImage();
  const harnessHost = path.join(SANDBOX_DIR, 'install-and-trace.sh');
  if (!fs.existsSync(harnessHost)) throw new Error(`harness script missing: ${harnessHost}`);

  const args = [
    ...dockerRunFlags(timeoutSec),
    '-v', `${tarPath}:/src/repo.tar.gz:ro`,
    '-v', `${harnessHost}:/usr/local/bin/install-and-trace.sh:ro`,
    '--entrypoint', '/bin/sh',
    IMAGE,
    '-c',
    // Extract inside the container only. Hardening applied:
    //   gzip -l decompressed-size guard — refuse > 200 MB to avoid
    //                                     decompression bombs filling tmpfs.
    //   tar -tzf scan refuses any archive with a symlink or hardlink entry
    //                 (type 'l' or 'h') so an attacker can't redirect a
    //                 later openat() to a path the fsEscapeWrites detector
    //                 would otherwise allowlist (e.g. /work/proc -> /proc).
    //   --no-same-owner / --no-same-permissions / --no-acls / --no-xattrs:
    //                 don't trust archived ownership/perms/xattrs.
    //   --strip-components=1   GitHub tarballs nest under a single top-level dir.
    //   --no-overwrite-dir     fail rather than overwrite an existing dir.
    'set -e; cd /work && ' +
    // gzip -l outputs: <compressed> <uncompressed> <ratio> <name>. Pull col 2.
    'sz=$(gzip -l /src/repo.tar.gz 2>/dev/null | awk \'NR==2{print $2}\'); ' +
    'if [ -n "$sz" ] && [ "$sz" -gt 209715200 ]; then ' +
    '  echo "===CLONESAFE_REPORT_START===\\n{\\"status\\":\\"skipped\\",\\"reason\\":\\"tarball decompresses to >200MB\\"}\\n===CLONESAFE_REPORT_END==="; exit 0; ' +
    'fi; ' +
    'if tar -tzf /src/repo.tar.gz 2>/dev/null | head -20000 | grep -qE \'^l|^h\'; then ' +
    '  echo "===CLONESAFE_REPORT_START===\\n{\\"status\\":\\"skipped\\",\\"reason\\":\\"tarball contains symlink/hardlink entries — refusing for safety\\"}\\n===CLONESAFE_REPORT_END==="; exit 0; ' +
    'fi; ' +
    // Alpine's tar is busybox tar — the GNU --no-acls / --no-xattrs /
    // --no-overwrite-dir flags it doesn't recognize would crash extraction.
    // We drop them here. Permissions and ownership are not load-bearing
    // because the container has --read-only rootfs, runs as a fixed
    // non-root uid, and the tmpfs filesystem doesn't propagate xattrs/acls.
    'tar --no-same-owner --no-same-permissions --strip-components=1 -xzf /src/repo.tar.gz && ' +
    '/usr/local/bin/install-and-trace.sh install'
  ];
  return runAndParse(args);
}

function runAndParse(args) {
  const r = spawnSync('docker', args, { encoding: 'utf8' });
  if (r.error) throw r.error;
  const lastJson = extractLastJson(r.stdout || '');
  if (!lastJson) {
    const stderr = (r.stderr || '').slice(-2000);
    throw new Error(`could not parse sandbox report. exit=${r.status}\nstdout tail:\n${(r.stdout || '').slice(-2000)}\nstderr tail:\n${stderr}`);
  }
  lastJson._dockerExit = r.status;
  return lastJson;
}

function extractLastJson(text) {
  // The harness wraps its JSON report in ===CLONESAFE_REPORT_START===/END===
  // markers because strace samples that we embed in the report contain
  // literal {} braces (e.g. "{nlmsg_len=20, ...}") which break naive
  // brace-balancing parsers.
  const m = text.match(/===CLONESAFE_REPORT_START===\s*([\s\S]*?)\s*===CLONESAFE_REPORT_END===/);
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch (err) {
    return { _parseError: err.message, _payload: m[1].slice(0, 500) };
  }
}

/**
 * Classify a sandbox report into a verdict contribution. Returns:
 *   { verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS', reasons: string[] }
 *
 * The harness runs with --network=none, so any network/DNS attempt during
 * install is by definition the install reaching out somewhere it cannot.
 * Process spawns of sh/bash/curl/wget/python during a vanilla `npm install`
 * are also strong signals — npm itself doesn't need them.
 */
function classifyReport(report) {
  const reasons = [];
  if (!report || typeof report !== 'object') return { verdict: 'CLEAN', reasons: ['no-report'] };
  const a = report.anomalies || {};
  if ((a.dnsAttempts || 0) > 0) reasons.push(`dns: ${a.dnsAttempts}`);
  if ((a.networkSyscalls || 0) > 0) reasons.push(`net: ${a.networkSyscalls}`);
  if ((a.shellOrFetchSpawns || 0) > 0) reasons.push(`shell/fetch spawn: ${a.shellOrFetchSpawns}`);
  if ((a.sshPathReads || 0) > 0) reasons.push(`ssh path read: ${a.sshPathReads}`);
  if ((a.procEnvReads || 0) > 0) reasons.push(`/proc/*/environ read: ${a.procEnvReads}`);
  if ((a.fsEscapeWrites || 0) > 0) reasons.push(`fs-escape writes: ${a.fsEscapeWrites}`);

  // SSH-key reads or process-env reads at install time are unambiguous credential
  // theft fingerprints — escalate straight to MALICIOUS. Shell/curl/wget/nohup
  // spawns at install time are not normal for vanilla `npm install` and warrant
  // SUSPICIOUS.
  //
  // Bare networkSyscalls/dnsAttempts are reported but NOT used to classify.
  // npm reads /etc/resolv.conf at startup and may attempt loopback connections
  // (update notifier, etc.) even on dependency-free projects under
  // --network=none. Treating those as anomalies makes every benign install
  // look suspicious. The load-bearing dynamic signals are credential reads
  // and lifecycle-time shell spawns.
  let verdict = 'CLEAN';
  if ((a.sshPathReads || 0) > 0 || (a.procEnvReads || 0) > 0 || (a.fsEscapeWrites || 0) > 0) {
    verdict = 'MALICIOUS';
  } else if ((a.shellOrFetchSpawns || 0) > 0) {
    verdict = 'SUSPICIOUS';
  }
  return { verdict, reasons };
}

module.exports = { runHarness, runHarnessOnTarball, classifyReport, ensureImage, dockerAvailable, IMAGE };
