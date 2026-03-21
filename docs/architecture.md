# BinShield Architecture

## Core Services

- `apps/web` provides the marketing site, public package database, and authenticated SaaS pages.
- `apps/api` exposes public search/package endpoints plus authenticated scan, repo, watchlist, API key, and billing-adjacent workflows.
- `apps/worker` is the analysis orchestration layer. It now handles package acquisition, binary extraction, fingerprinting, job tracking, cache hooks, and provider-backed decompilation/classification with local fallbacks.
- `apps/github-action` is the CI entrypoint that discovers npm lockfile targets, submits scans, polls results, and enforces a risk threshold.

## Data Flow

1. A user or GitHub Action submits a package/version to the API.
2. The API returns a cached result immediately or a queued job id.
3. The worker acquires the package, extracts binaries, fingerprints artifacts, decompiles them through a provider chain, classifies behaviors, then stores normalized package and binary analysis results.
4. The web app reshapes those contracts into package-intelligence investigation views, while the GitHub Action converts them into CI-facing summaries.

## Current Implementation Notes

- The repo supports a deliberate fallback mode: local API repository storage, seeded package data in the web app, and a fixture-backed worker path keep the product usable before live infrastructure is connected.
- Shared risk logic is deterministic and tested in `packages/risk-engine`.
- Supabase schema and RLS foundations are in `supabase/migrations`.
