# Changelog

All notable changes to BinShield are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Install-script analysis engine (npm + PyPI).** A second analysis path
  alongside native-binary decompilation. It inspects `package.json` lifecycle
  hooks (preinstall/install/postinstall/prepare) and the JavaScript they run,
  and PyPI `setup.py` / `pyproject.toml` code — the vector used by
  supply-chain worms such as Shai-Hulud. Heuristic detection plus an AI
  (Grok) classification pass, with a deterministic heuristic floor.
- **Threat taxonomy** for install-script risks: install hooks, script
  injection, environment/credential theft, dependency confusion, wipers,
  reverse shells, remote code execution, and obfuscation.
- **Known-malware feed.** Scanned packages are cross-referenced against OSV's
  malicious-package advisories (`MAL-*`); a confirmed match forces a critical
  verdict. Advisories are now typed as `vulnerability` vs `malware`.
- **Proactive alert loop.** When a malicious or high-risk package is found, it
  is matched against org watchlists and previously scanned lockfiles, and
  affected orgs are alerted via email / Slack / webhook with per-package
  deduplication.
- PyPI package acquisition via the PyPI source-distribution API.
- Discovery and the npm registry feed follower now surface install-script
  packages, not only packages shipping native binaries.

### Fixed

- The alert recorder previously wrote columns that did not exist on the
  `email_alerts` table, so every alert insert failed silently. Alerts now use
  a dedicated `alerts` ledger with a unique dedup index.

## [0.1.0] - 2026-05-15

### Added

- Initial BinShield monorepo: web app (Next.js), API (Hono), analysis worker,
  and a GitHub Action for CI scanning.
- Native binary analysis pipeline: extraction, Ghidra Docker decompilation
  with a heuristic fallback, YARA scanning, and AI behavior classification.
- Deterministic risk-scoring engine and shared analysis types.
- Supabase persistence with row-level security; CycloneDX SBOM export.
- Vulnerability advisory aggregation from OSV, NVD, and GitHub Security
  Advisories.
- Lockfile scanning, proactive package discovery/crawler, npm registry feed
  follower, and SOC 2 / ISO 27001 / EU CRA compliance report generation.
- Stripe billing, organization quotas, and feature gating.

### Changed

- Rebranded to Ashlr AI; migrated AI classification to xAI `grok-4.3`.

[Unreleased]: https://github.com/ashlrai/binshield/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ashlrai/binshield/releases/tag/v0.1.0
