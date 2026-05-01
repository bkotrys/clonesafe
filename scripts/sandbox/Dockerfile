# Minimal Alpine image used by clonesafe's `--sandbox` mode and by the
# `npm run test:docker` harness. The image deliberately ships no compilers or
# extra tools — anything an `npm install` lifecycle script needs to do, it
# must do with what's here. We add `strace` so the harness can record the
# syscall timeline of the install for anomaly detection.
# Pinned to digest so a poisoned base image can't silently change the
# install-time analysis surface. Update by running:
#   docker pull node:22-alpine && \
#   docker inspect --format='{{index .RepoDigests 0}}' node:22-alpine
FROM node:22-alpine@sha256:8ea2348b068a9544dae7317b4f3aafcdc032df1647bb7d768a05a5cad1a7683f

RUN apk add --no-cache strace ca-certificates jq python3 \
 && addgroup -g 10001 sb && adduser -D -u 10001 -G sb sb \
 && mkdir -p /work /trace && chown sb:sb /work /trace \
 # npm's lifecycle-script PATH on this image excludes /bin, so a plain
 # `sh -c "..."` from package.json fails with ENOENT. Symlink the busybox
 # core utilities into a directory npm DOES search (/usr/local/bin) so
 # lifecycle hooks behave like they would on a developer's machine.
 && for tool in sh cat echo true nohup setsid; do \
      [ -e /usr/local/bin/$tool ] || ln -s /bin/$tool /usr/local/bin/$tool 2>/dev/null || true; \
    done

USER sb
WORKDIR /work

# node:22-alpine's default PATH for non-root users excludes /bin and /sbin,
# which means npm's lifecycle scripts can't find `sh` to run `sh -c "..."`.
# Force a complete PATH so `npm install --ignore-scripts=false` actually
# exercises lifecycle hooks.
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Default entrypoint is the harness script, mounted at /usr/local/bin/install-and-trace.sh.
ENTRYPOINT ["/usr/local/bin/install-and-trace.sh"]
