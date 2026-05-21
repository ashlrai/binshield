# Contributing to BinShield

Thank you for your interest in contributing.

## Prerequisites

- **Node.js** >= 20
- **pnpm** 10.28.2 — install via Corepack:
  ```bash
  corepack enable
  ```

## Setup

```bash
git clone https://github.com/ashlrai/binshield.git
cd binshield
pnpm install
cp .env.example .env.local  # fill in credentials as needed
```

Most frontend and API work runs in demo-fallback mode and does not require
real credentials. The worker and advisory sync need Supabase + xAI keys.

## Monorepo Layout

| Path | Description |
|------|-------------|
| `apps/web` | Next.js 15 App Router frontend (Vercel) |
| `apps/api` | Hono API server (Railway) |
| `apps/worker` | Analysis worker daemon (Railway) |
| `apps/github-action` | GitHub Action for CI scanning |
| `apps/video` | Remotion demo video project |
| `packages/analysis-types` | Shared TypeScript types and sample data |
| `packages/risk-engine` | Deterministic risk scoring |
| `packages/config` | Environment configuration |
| `packages/ui` | Shared UI components |
| `packages/cli` | CLI tooling |

## Validation Gate

**All three of these must pass before every commit:**

```bash
pnpm typecheck   # TypeScript check across all packages
pnpm test        # Run all tests
pnpm build       # Build all packages
```

CI enforces this on every PR.

## Running Individual Services

```bash
# Frontend
pnpm --filter @binshield/web dev

# API
pnpm --filter @binshield/api dev

# Worker (pick a mode)
BINSHIELD_WORKER_MODE=cli    pnpm --filter @binshield/worker dev   # one-shot
BINSHIELD_WORKER_MODE=daemon pnpm --filter @binshield/worker dev   # polling loop
BINSHIELD_WORKER_MODE=feed   pnpm --filter @binshield/worker dev   # npm registry feed
BINSHIELD_WORKER_MODE=crawl  pnpm --filter @binshield/worker dev   # proactive discovery
```

## GitHub Action Changes

`apps/github-action` is distributed as a compiled bundle. After modifying any
source under `apps/github-action/src/`, rebuild and commit the dist:

```bash
pnpm --filter @binshield/github-action build
git add apps/github-action/dist/
git commit -m "chore(action): rebuild dist"
```

CI runs a freshness check and will fail if `dist/` is stale.

## PR Process

1. Branch from `main` with a descriptive name (`feat/…`, `fix/…`, `chore/…`).
2. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
   messages (`feat:`, `fix:`, `chore:`, `docs:`, `perf:`, `refactor:`).
3. Keep PRs focused — one logical change per PR.
4. Fill out the pull request template completely.
5. Ensure CI is green before requesting review.

## Code Conventions

- **No Tailwind** — use CSS classes in `globals.css` with CSS variables
  (`--bg`, `--accent`, `--text`, etc.). Fonts: JetBrains Mono + Instrument Sans.
- **API auth** — all endpoints authenticate via `x-binshield-api-key` header
  or `Authorization: Bearer <token>`.
- **Supabase** — the worker and API use the service role key (bypasses RLS).
  Never expose the service role key client-side.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.
