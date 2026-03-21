# BinShield

BinShield is an npm-first supply-chain binary scanner. This repo contains the public search app, SaaS API, analysis worker, GitHub Action, and shared analysis/risk packages in one monorepo.

## Workspace Layout

- `apps/web`: Next.js app for the public database and authenticated dashboard
- `apps/api`: Hono API for package search, scan submission, and org/repo workflows
- `apps/worker`: analysis orchestration and provider adapters
- `apps/github-action`: GitHub Action that queries the API and enforces scan policy
- `packages/analysis-types`: shared domain schema, mock data helpers, and route contracts
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

The worker and API include a local sample mode so the repo remains usable before external infrastructure is connected.
