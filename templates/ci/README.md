# clonesafe CI templates

Drop-in pipeline configurations for the major non-GitHub CI providers.

| File | Provider |
|---|---|
| `gitlab-ci.yml` | GitLab CI/CD |
| `bitbucket-pipelines.yml` | Bitbucket Pipelines |
| `circleci-config.yml` | CircleCI |
| `Jenkinsfile` | Jenkins (declarative pipeline) |

GitHub Actions users should use the bundled action at the repo root
(`action.yml`) — see the README for usage.

## Configuration

All four templates honour two environment variables:

- `CLONESAFE_VERSION` (default `0.4.0`) — npm version to install.
- `CLONESAFE_FAIL_ON` (default `WARN`) — fail the build at this verdict
  level or higher (`PROCEED` / `CAUTION` / `WARN` / `BLOCK`).

## What each template does

1. Resolves the repo slug and commit SHA from CI-provided env vars.
2. Runs `clonesafe <owner/repo>@<sha> --json` and writes `clonesafe-report.json`.
3. Reads the verdict and exits non-zero when it meets or exceeds the
   `CLONESAFE_FAIL_ON` threshold.
4. Archives the JSON report as a build artifact for triage.

The scan runs against the GitHub-hosted source via the GitHub API (no
clone), so even forks, private repos with read access, or specific
historical commits work.
