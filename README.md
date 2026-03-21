# BinShield

BinShield is an npm-first supply-chain binary scanner. This repo contains the public search app, SaaS API, analysis worker, GitHub Action, and shared analysis/risk packages in one monorepo.

## Workspace Layout

- `apps/web`: Next.js app for the public database and authenticated dashboard
- `apps/api`: Hono API for package search, scan submission, org workflows, API keys, and billing stubs
- `apps/worker`: analysis orchestration, package acquisition, binary extraction, fingerprinting, and provider adapters
- `apps/github-action`: GitHub Action that discovers npm targets, queries the API, and enforces policy
- `packages/analysis-types`: shared domain schema, seeded demo corpus, and route contracts
- `packages/risk-engine`: deterministic risk scoring and aggregation helpers
- `packages/config`: shared environment parsing and product constants
- `supabase/migrations`: initial schema and RLS foundations

## Planned Runtime Stack

- Web: Next.js 15 App Router
- API: Hono on Node
- Database/Auth: Supabase Postgres/Auth
- Queue: BullMQ-compatible queue interface
- Workers: Ghidra headless runners plus LLM classification

## Getting Started

1. Install dependencies with `pnpm install`.
2. Copy env examples for each app.
3. Run `pnpm dev` for the web app and `pnpm --filter @binshield/api dev` for the API.
4. Run `pnpm test` for shared package coverage.

## Demo Mode

The repo intentionally ships with a polished fallback path so product work can continue before live infrastructure is wired:

- the web app can render from the seeded analysis corpus when the API is unavailable
- the API can run against its local repository mode when Supabase is not configured
- the worker can analyze the bundled fixture package when live providers are unavailable

This keeps the package-intelligence surface, dashboard shell, and CI integration demonstrable even before production credentials are connected.
