# calcom-arm64

Unofficial **linux/arm64** builds of [Cal.com](https://github.com/calcom/cal.com) from the official
[calcom/docker](https://github.com/calcom/docker) Dockerfile, unchanged, built on GitHub's arm64 runners and
published to `ghcr.io/jphein/calcom-arm64:<cal.com version>`. The official image is amd64-only; this exists so a
self-hosted instance can run on a Graviton box. Same runtime contract as the official image (placeholder URL
replaced at container start by `scripts/replace-placeholder.sh`). No code changes, no secrets: the build args are
the Dockerfile's defaults.

Build: `.github/workflows/build.yml` (workflow_dispatch with the calcom/docker tag to build).
