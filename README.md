# calcom-arm64

Unofficial **linux/arm64** builds of [Cal.com](https://github.com/calcom/cal.com) from the official
[calcom/docker](https://github.com/calcom/docker) Dockerfile, unchanged, built on GitHub's arm64 runners and
published to `ghcr.io/jphein/calcom-arm64:<cal.com version>`. The official image is amd64-only; this exists so a
self-hosted instance can run on a Graviton box. Same runtime contract as the official image (placeholder URL
replaced at container start by `scripts/replace-placeholder.sh`). No code changes, no secrets: the build args are
the Dockerfile's defaults.

Build: `.github/workflows/build.yml` (workflow_dispatch with the calcom/docker tag to build).

Since 2026-11-10 the workflow also prunes build-only trees at the end of the `builder-two` stage (every `node_modules/vite`, `vitest` and `vite-node` copy, `apps/web/.next/standalone`, `packages/platform/examples/base/node_modules`) and purges `openssh-client` from the runner. Nothing served changes (`next start` reads `.next`, never `standalone`; no shipped code requires vite), the image loses ~700 MB, and the KEV gate carries no allow line any more: a vite or ssh copy that returns fails the build.
