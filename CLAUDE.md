# BinShield — Claude Code Instructions

## What This Project Is

BinShield is a supply chain binary security platform. It decompiles native package binaries (.node, .so, .dylib, .wasm) from npm packages, classifies their behavior with AI (xAI Grok), and surfaces risk scores for security teams.

**Live at:** https://binshield.dev
**API:** https://api.binshield.dev (or https://binshieldapi-production.up.railway.app)

## Workspace Layout

```
apps/web          — Next.js 15 App Router frontend (Vercel)
apps/api          — Hono API server (Railway)
apps/worker       — Analysis worker daemon (Railway)
apps/github-action — GitHub Action for CI scanning
apps/video        — Remotion demo video project
packages/analysis-types — Shared TypeScript types and sample data
packages/risk-engine    — Deterministic risk scoring
packages/config         — Environment configuration
packages/ui             — Shared UI components
```

## Key Commands

```bash
pnpm install          # Install all dependencies
pnpm dev              # Start web app dev server
pnpm build            # Build all packages
pnpm test             # Run all tests
pnpm typecheck        # TypeScript check all packages

# Individual services
pnpm --filter @binshield/web dev
pnpm --filter @binshield/api dev
BINSHIELD_WORKER_MODE=daemon pnpm --filter @binshield/worker dev
BINSHIELD_WORKER_MODE=feed pnpm --filter @binshield/worker dev
BINSHIELD_WORKER_MODE=crawl pnpm --filter @binshield/worker dev
```

## Tech Stack

- **Frontend:** Next.js 15, React 19, CSS (no Tailwind)
- **API:** Hono on Node.js
- **Database:** Supabase (PostgreSQL + Auth + RLS)
- **AI Classification:** xAI grok-4-1-fast-reasoning
- **Binary Analysis:** Ghidra Docker containers + heuristic fallback
- **Billing:** Stripe (test mode)
- **Deployment:** Vercel (web) + Railway (API + worker)

## Architecture

1. User/Action submits scan → API writes job to Supabase `analysis_jobs`
2. Worker daemon polls `analysis_jobs` → claims job → downloads package → extracts binaries
3. Worker runs decompilation (Ghidra or heuristic) → YARA pattern matching → AI classification (Grok)
4. Worker writes results to `packages`, `analyses`, `binaries` tables
5. Feed follower tails npm registry changes feed → discovers new native packages → queues scans
6. Crawler proactively discovers and seeds popular native packages for analysis
7. Advisory sync aggregates vulnerability data from OSV, NVD, and GitHub Security Advisories
8. API serves results, advisories, feed events, lockfile scans, and compliance reports → Web/Action displays them

## Key Files

- `packages/analysis-types/src/index.ts` — All domain types (PackageAnalysis, BinaryAnalysis, etc.)
- `packages/risk-engine/src/index.ts` — Deterministic scoring algorithm
- `apps/api/src/app.ts` — All API routes (31 endpoints)
- `apps/api/src/lib/repository.ts` — Supabase + local repository implementations
- `apps/api/src/lib/advisory-service.ts` — OSV/NVD/GitHub advisory aggregation
- `apps/api/src/lib/middleware.ts` — Quota enforcement, feature gates, usage tracking
- `apps/api/src/lib/compliance-reports.ts` — SOC 2/ISO 27001/EU CRA report generation
- `apps/worker/src/pipeline.ts` — Analysis orchestration
- `apps/worker/src/providers.ts` — Decompiler + classifier provider chain
- `apps/worker/src/discovery.ts` — Native binary detection in package tarballs
- `apps/worker/src/crawler.ts` — Proactive package discovery and seeding
- `apps/worker/src/lockfile-scanner.ts` — Lockfile parsing and dependency extraction
- `apps/worker/src/feed-follower.ts` — npm registry changes feed tailer
- `apps/worker/src/yara-scanner.ts` — YARA rule matching on extracted binaries
- `apps/worker/src/native-indicators.ts` — Heuristic native binary detection
- `apps/web/src/lib/site-data.ts` — Web data layer (live API + demo fallback)

## Conventions

- No Tailwind — use CSS classes in `globals.css`
- Design tokens via CSS variables (`--bg`, `--accent`, `--text`, etc.)
- Fonts: JetBrains Mono (display/code) + Instrument Sans (body)
- All API auth via `x-binshield-api-key` header or `Authorization: Bearer`
- Supabase uses service role key for worker/API (bypasses RLS)
- Worker supports four modes: `cli` (one-shot), `daemon` (polling), `feed` (registry changes tailer), `crawl` (proactive package discovery)
- CORS is restricted to production origins (`binshield.dev` + `publicAppUrl`); falls back to `*` in local dev
- Global error handler catches unhandled exceptions and returns structured JSON errors

## Validation Gate

Before any commit, ensure:
```bash
pnpm typecheck  # Must pass
pnpm test       # Must pass (28 tests)
pnpm build      # Must pass
```
