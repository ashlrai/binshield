# BinShield Architecture

## Core Services

- `apps/web` provides the marketing site, public package database, and authenticated SaaS pages.
- `apps/api` exposes public search/package endpoints plus authenticated scan/repo workflows.
- `apps/worker` is the analysis orchestration layer. It currently runs in simulated mode and is structured so real extraction, Ghidra, queue, and Claude adapters can replace the stubs without changing contracts.
- `apps/github-action` is the CI entrypoint that submits scans and enforces a risk threshold.

## Data Flow

1. A user or GitHub Action submits a package/version to the API.
2. The API returns a cached result immediately or a queued job id.
3. The worker extracts binaries, decompiles them with Ghidra, classifies behaviors through the LLM provider, then stores normalized package/binary analysis results.
4. The web app and GitHub Action consume the same response contracts from `@binshield/analysis-types`.

## Current Implementation Notes

- The repo uses an in-memory API store and simulated worker analysis so the codebase is runnable before Supabase, Redis, Ghidra, and LLM credentials are connected.
- Shared risk logic is deterministic and tested in `packages/risk-engine`.
- Supabase schema and RLS foundations are in `supabase/migrations`.
