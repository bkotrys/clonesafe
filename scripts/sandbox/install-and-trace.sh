#!/bin/sh
# install-and-trace.sh — runs an `npm install` (or skip) under strace and
# emits a JSON anomaly report to stdout.
#
# Inputs:
#   $1   "install" or "noop". install runs `npm install --ignore-scripts=false`.
#        noop just lists files (used to baseline the image).
#
# Environment:
#   CLONESAFE_TIMEOUT   wall-clock timeout in seconds (default 60)
#
# The container is started by the host with --network=none and read-only
# /work so any "anomaly" recorded here is the install actually trying to
# escape the sandbox.

set -eu

# Alpine ships /bin/sh + /bin/busybox-symlinked utilities under /bin and /sbin.
# Some Docker runtimes spawn the entrypoint with a PATH missing /bin, which
# means npm's child processes can't find `sh` to run lifecycle scripts. Force
# a complete PATH so lifecycle behavior is actually exercised.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

MODE="${1:-install}"
TIMEOUT="${CLONESAFE_TIMEOUT:-60}"
TRACE=/trace/strace.log
REPORT=/trace/report.json

cd /work

# Always emit a stub report so the harness can read it even on failure.
printf '%s\n' '{"status":"starting"}' > "$REPORT"

run_install() {
  # We trace network syscalls + process spawns + file writes. -f follows forks
  # so npm's child processes (lifecycle hooks!) are captured. We keep the npm
  # output in a separate file but tee strace's own stderr too in case it failed
  # to attach (usually a seccomp/ptrace permissions issue).
  strace -f -e trace=network,process,openat -o "$TRACE" -- \
    timeout "$TIMEOUT" npm install --ignore-scripts=false --no-audit --no-fund \
    >/trace/npm.out 2>/trace/npm.err
}

if [ "$MODE" = "install" ]; then
  if [ ! -f package.json ]; then
    printf '%s\n' '{"status":"skipped","reason":"no package.json"}' > "$REPORT"
    echo '===CLONESAFE_REPORT_START==='
cat "$REPORT"
echo
echo '===CLONESAFE_REPORT_END==='
    exit 0
  fi
  if run_install; then
    INSTALL_STATUS="ok"
  else
    INSTALL_STATUS="failed"
  fi
else
  : > "$TRACE"
  INSTALL_STATUS="noop"
fi

# Anomalies of interest (egress, process spawns, suspicious paths).
# --network=none means any successful connect() is by definition impossible,
# but the *attempt* is itself a signal — record it.
# Real off-host egress only — loopback (127.0.0.1, ::1) and netlink/AF_UNIX
# don't count because npm's update notifier and a few alpine init bits hit
# them on every install regardless of network=none. We require an explicit
# AF_INET/AF_INET6 connect() to a non-loopback address.
NET_ATTEMPTS=$(grep -E 'connect\(.*sa_family=AF_INET' "$TRACE" 2>/dev/null \
  | grep -vE 'inet_addr\("127\.|inet_pton\(AF_INET6, "::1"' \
  | wc -l 2>/dev/null || true)
DNS_ATTEMPTS=$(grep -cE '"/etc/resolv\.conf"' "$TRACE" 2>/dev/null || true)

# Filesystem writes outside the install's expected sandbox. We allow:
#   /work/**         (the install target)
#   /tmp/**          (scratch — already on tmpfs and gone at exit)
#   /trace/**        (our own report)
#   /home/sb/.npm/** (npm cache, used unavoidably)
#   /proc/self/**    (process self-state)
# Anything else (e.g. /home/sb/.bashrc, /home/sb/.config, /etc, /root)
# being opened with O_WRONLY|O_CREAT is a strong fingerprint for an
# install-time persistence/credential-tampering attempt.
FS_ESCAPE_WRITES=$(grep -E 'openat\([^)]*O_(WRONLY|RDWR)' "$TRACE" 2>/dev/null \
  | grep -vE '"/(work|tmp|trace|dev|proc/self)' \
  | grep -vE '"/home/sb/\.(npm|cache)/' \
  | grep -E '"/[^"]+"' \
  | wc -l 2>/dev/null || true)
PROC_SPAWNS=$(grep -cE '\bexecve\(' "$TRACE" 2>/dev/null || true)
SH_SPAWNS=$(grep -cE 'execve\("[^"]*/(sh|bash|dash|ash|zsh|python|python3|curl|wget|nc|ncat|nohup|setsid|disown)"' "$TRACE" 2>/dev/null || true)
# Use grep -F-style fixed patterns where possible to dodge ERE escaping subtleties
# in BusyBox grep. Both signals are very specific path substrings.
SSH_PATHS=$(grep -cE '\.ssh/' "$TRACE" 2>/dev/null || true)
ENV_READS=$(grep -cE '/proc/[0-9]+/environ' "$TRACE" 2>/dev/null || true)

# Default any empty/non-numeric to 0.
for v in NET_ATTEMPTS DNS_ATTEMPTS PROC_SPAWNS SH_SPAWNS SSH_PATHS ENV_READS FS_ESCAPE_WRITES; do
  case "$(eval "echo \$$v")" in
    ''|*[!0-9]*) eval "$v=0" ;;
  esac
done

TRACE_LINES=0
if [ -f "$TRACE" ]; then
  TRACE_LINES=$(wc -l < "$TRACE" 2>/dev/null || echo 0)
fi
case "$TRACE_LINES" in ''|*[!0-9]*) TRACE_LINES=0 ;; esac

# For debugging, write a redacted trace excerpt to /trace/samples.txt that
# the host-side harness can fetch on demand. We intentionally do NOT embed
# strace lines in the JSON report because they contain non-JSON-safe escape
# sequences (\x00, \xff, etc.) emitted by strace itself.
{
  echo '--- shell/fetch spawns ---'
  grep -E 'execve\("[^"]*/(sh|bash|dash|ash|zsh|python|python3|curl|wget|nc|ncat|nohup|setsid|disown|cat)"' "$TRACE" 2>/dev/null | head -8
  echo '--- ssh path reads ---'
  grep -E '\.ssh/' "$TRACE" 2>/dev/null | head -4
  echo '--- /proc/<pid>/environ reads ---'
  grep -E '/proc/[0-9]+/environ' "$TRACE" 2>/dev/null | head -4
} > /trace/samples.txt 2>/dev/null || true

cat > "$REPORT" <<EOF
{
  "status": "${INSTALL_STATUS}",
  "mode": "${MODE}",
  "timeoutSec": ${TIMEOUT},
  "traceLines": ${TRACE_LINES},
  "anomalies": {
    "networkSyscalls": ${NET_ATTEMPTS},
    "dnsAttempts": ${DNS_ATTEMPTS},
    "processSpawns": ${PROC_SPAWNS},
    "shellOrFetchSpawns": ${SH_SPAWNS},
    "sshPathReads": ${SSH_PATHS},
    "procEnvReads": ${ENV_READS},
    "fsEscapeWrites": ${FS_ESCAPE_WRITES}
  }
}
EOF

echo '===CLONESAFE_REPORT_START==='
cat "$REPORT"
echo
echo '===CLONESAFE_REPORT_END==='
