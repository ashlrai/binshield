# Claude Code Handoff

This document is the current handoff state for `ashlrai/binshield` as of commit `9102e0c` on `main`.

Use this file as the first-stop source of truth before making infra or product changes.

## Repo State

- Repo: `https://github.com/ashlrai/binshield`
- Current branch: `main`
- Latest commits:
  - `9102e0c` `Deepen package intelligence and action reporting`
  - `c25436b` `Build launch-ready BinShield SaaS tranche`
  - `6aaedea` `Remove generated tsbuildinfo artifact`

## What Is Already Built

### Web app

Location: `apps/web`

Implemented:
- Public homepage, package browser, search, package detail, and dedicated binary detail route
- Authenticated dashboard shells for overview, billing, settings, and watchlists
- Security-native package intelligence presentation:
  - package-level signals
  - grouped findings by severity
  - version timeline
  - version drift narrative
  - binary evidence cards
  - dedicated binary evidence detail pages
- Live-or-demo data access:
  - uses API when `BINSHIELD_API_BASE_URL` / `NEXT_PUBLIC_BINSHIELD_API_BASE_URL` is set
  - falls back to seeded corpus when API is unavailable

Important routes:
- `/`
- `/packages`
- `/packages/[name]`
- `/packages/[name]/binaries/[binaryId]`
- `/search`
- `/dashboard`
- `/dashboard/billing`
- `/dashboard/settings`
- `/dashboard/watchlists`

Key files:
- `apps/web/src/lib/site-data.ts`
- `apps/web/src/app/packages/[name]/page.tsx`
- `apps/web/src/app/packages/[name]/binaries/[binaryId]/page.tsx`
- `apps/web/src/app/globals.css`

### API

Location: `apps/api`

Implemented:
- Hono API
- Public package endpoints
- Authenticated org-scoped routes
- Local repository fallback mode
- Supabase-ready repository abstraction
- API-key auth middleware
- Billing checkout/webhook stubs

Implemented route families:
- `/health`
- `/packages/search`
- `/packages/:ecosystem/:name`
- `/packages/:ecosystem/:name/versions/:version`
- `/packages/:ecosystem/:name/diff`
- `/scans/packages`
- `/scans/:id`
- `/orgs/:orgId`
- `/orgs/:orgId/repos`
- `/orgs/:orgId/watchlists`
- `/orgs/:orgId/watchlists/:watchlistId/packages`
- `/orgs/:orgId/subscription`
- `/orgs/:orgId/api-keys`
- `/billing/checkout`
- `/billing/webhook`

Key files:
- `apps/api/src/app.ts`
- `apps/api/src/lib/repository.ts`
- `apps/api/src/lib/auth.ts`
- `apps/api/src/lib/env.ts`

### Worker

Location: `apps/worker`

Implemented:
- Package acquisition coordinator
- Local directory source
- Registry acquisition path via `npm pack`
- Binary extraction from package trees
- Fingerprinting and binary candidate detection
- Provider-backed decompiler/classifier chain
- In-memory cache and job store
- Fixture-backed local runtime for demo mode

Current provider behavior:
- There is a real worker architecture
- There are fallback providers/local heuristics
- This is ready for real Ghidra + LLM provider wiring, but those live integrations are not fully wired yet

Key files:
- `apps/worker/src/pipeline.ts`
- `apps/worker/src/package-source.ts`
- `apps/worker/src/extractor.ts`
- `apps/worker/src/fingerprint.ts`
- `apps/worker/src/providers.ts`
- `apps/worker/src/job-store.ts`

### GitHub Action

Location: `apps/github-action`

Implemented:
- npm dependency discovery from `package-lock.json` / `npm-shrinkwrap.json`
- native-only or all-dependencies scan modes
- API polling with timeout/backoff
- summary and PR-comment modes
- security-native result formatting with evidence cues and remediation guidance
- clear warnings when PR comments cannot be posted due to missing `github-token` or non-PR workflows

Key files:
- `apps/github-action/src/discovery.ts`
- `apps/github-action/src/client.ts`
- `apps/github-action/src/report.ts`
- `apps/github-action/src/github.ts`
- `apps/github-action/src/index.ts`

### Shared packages

Location: `packages/*`

Implemented:
- Shared contracts/types for analyses, jobs, orgs, watchlists, entitlements, subscriptions, alerts, action summaries
- Deterministic risk scoring
- Seeded launch corpus used by demo mode

Current seeded corpus includes:
- `bcrypt` with multiple versions
- `sharp` with multiple versions
- `sqlite3`
- `canvas` with multiple binaries
- `argon2`

Important helpers:
- `getSamplePackageHistory`
- `getSamplePackageDiff`
- `getSampleActionSummaries`

Key files:
- `packages/analysis-types/src/index.ts`
- `packages/risk-engine/src/index.ts`
- `packages/config/src/index.ts`

## What Is Real vs Fallback

### Real enough to build on directly

- Web app routing and product IA
- API route surface
- Worker orchestration structure
- GitHub Action discovery/polling/reporting
- Shared types and seed corpus
- Migration baseline under `supabase/migrations`

### Still fallback/demo-oriented

- Web data can run entirely from seeded corpus
- API can run entirely from local in-memory/local repository mode
- Worker can run entirely from fixture package and local heuristics
- Billing checkout/webhook behavior is scaffolded, not production-complete
- Live Supabase persistence/auth is not the default active path yet
- Live Stripe wiring is not complete
- Real Ghidra container execution and live LLM classification are not fully wired end-to-end

## What Claude Code Should Probably Own Next

You said Claude Code will handle Supabase and Stripe. The highest-value Claude work is:

1. Supabase persistence/auth
- replace fallback/local repository mode with live Supabase-backed persistence where intended
- wire auth/organization membership/RLS behavior end-to-end
- connect dashboard/org routes to real data

2. Stripe
- wire real checkout/session creation
- webhook verification and subscription state updates
- plan entitlements from Stripe state rather than demo stubs

3. Worker live provider integrations
- real Ghidra execution path
- real LLM provider adapter
- persistent job/results storage instead of fallback-only runtime assumptions

4. API/worker persistence contract
- queued scans should persist and complete through the live data layer
- dashboard and action polling should read real job state

## Areas To Avoid Re-Doing

Claude should avoid re-solving these unless necessary:

- Package-intelligence UX structure in `apps/web`
- GitHub Action lockfile discovery from scratch
- Risk scoring model scaffolding in `packages/risk-engine`
- Shared type system in `packages/analysis-types` unless new infra needs contract additions

The app already has a strong fallback/demo product layer. Infra work should preserve that where possible instead of deleting it.

## Known Current Truths / Caveats

- `docs/launch-checklist.md` is partially stale. Some listed items are already substantially implemented in scaffolded form:
  - GitHub Action lockfile discovery is done
  - worker is no longer purely simulated
  - seeded public corpus is broader than the earliest scaffold
- `apps/web/src/lib/data.ts` still exists as an old leftover helper and is not the main active data path. The active web data path is `apps/web/src/lib/site-data.ts`.
- The API local repository uses seeded/demo org concepts like `org_demo` in places. If Claude normalizes org identity, it should do so carefully and keep tests aligned.
- The repo currently builds cleanly, but some generated local files such as `.next` and `tsbuildinfo` may appear during development. Avoid committing generated artifacts.

## Validation Status

These passed before this handoff document was added:

- `pnpm typecheck`
- `pnpm test`
- `pnpm build`

If Claude makes infra changes, those three commands should remain the minimum regression gate.

## Useful Commands

- Web dev: `pnpm --filter @binshield/web dev`
- API dev: `pnpm --filter @binshield/api dev`
- Worker local run: `pnpm --filter @binshield/worker dev`
- Action tests: `pnpm --filter @binshield/github-action test`
- Full validation:
  - `pnpm typecheck`
  - `pnpm test`
  - `pnpm build`

## Recommended Starting Reads For Claude

1. `docs/CLAUDE_CODE_HANDOFF.md`
2. `README.md`
3. `docs/architecture.md`
4. `apps/api/src/lib/repository.ts`
5. `apps/worker/src/pipeline.ts`
6. `apps/web/src/lib/site-data.ts`
7. `packages/analysis-types/src/index.ts`

## Short Summary

BinShield is no longer just a scaffold. It already has:
- a meaningful package-intelligence product surface
- a real API shape
- a real worker architecture
- a useful GitHub Action
- a broader seeded corpus for demo mode

What it needs next is not another product rewrite. It needs live infrastructure wiring and persistence/auth/billing completion layered onto the current product and contract structure.
