# BinShield — Supply Chain Binary Scanner

## Product Requirements Document

**Version:** 1.0
**Date:** 2026-03-21
**Author:** Mason Wyatt / Ashlr AI
**Status:** Draft

---

## 1. Vision

BinShield is a supply chain security platform that decompiles and AI-analyzes the compiled binary blobs inside npm/PyPI packages — the `.node` files, Python C extensions, WASM modules, and pre-built binaries that every other security tool ignores. Socket, Snyk, and Phylum analyze source code and metadata. BinShield looks inside the actual machine code.

**One-liner:** "Snyk for binaries — we decompile your dependencies so attackers can't hide in compiled code."

---

## 2. Problem

### The Gap Nobody Fills

When you `npm install bcrypt`, you get a pre-compiled `.node` binary. When you `pip install cryptography`, you get a compiled C extension. These binaries:

- Are **not analyzed by any existing SCA tool** (Snyk, Socket, npm audit all check source/metadata only)
- Can contain **hidden malware, backdoors, data exfiltration, or supply chain attacks**
- Ship in **99.8% of npm malware** (Q4 2025 data)
- Are responsible for ~45% of enterprise security incidents via supply chain attacks

Nobody decompiles these binaries to check what they actually do. Security teams trust that the compiled binary matches the published source — but that trust is unverified.

### Who Feels This Pain

1. **DevSecOps engineers** at mid-market SaaS companies (200-2000 employees) who need to vet dependencies before production
2. **Compliance-driven organizations** (fintech, healthcare, government) needing binary-level SBOMs for SOC 2 / ISO 27001 / EU Cyber Resilience Act
3. **Open-source maintainers** who want to prove their published binaries match their source code
4. **AppSec teams** who currently have zero visibility into what native dependencies actually execute

---

## 3. Solution

### Three-Layer Product

#### Layer 1: Free Public Database (Adoption Engine)
Pre-computed Ghidra + AI analysis of the top 1,000 npm/PyPI packages that ship native binaries. Searchable web interface showing:
- What system calls each binary makes (network, filesystem, process, crypto)
- AI-generated plain-English summary of binary behavior
- Risk score (0-100) based on behavioral patterns
- Version-over-version diff showing when binary behavior changes

#### Layer 2: CI/CD GitHub Action (Conversion Engine)
A GitHub Action that runs on PR/push:
1. Scans `node_modules` or `site-packages` for native binaries
2. Checks the free database first (instant results for known packages)
3. For unknown packages: runs Ghidra headless decompilation + Claude analysis on-demand
4. Posts a PR comment with findings: PASS / WARN / FAIL
5. Blocks merge on FAIL (configurable)

#### Layer 3: Dashboard & API (Revenue Engine)
Web dashboard for teams:
- Risk scores across all repos and dependencies
- Binary diff alerts when a package update changes binary behavior
- SBOM export with binary-level detail (CycloneDX / SPDX format)
- Compliance reports for auditors
- API for programmatic access and custom integrations

---

## 4. Architecture

### Core Pipeline

```
Binary Input (from npm/PyPI/upload)
    │
    ▼
┌─────────────────────┐
│  Binary Extraction   │  Identify .node, .so, .dylib, .dll, .wasm files
│  (npm pack / pip)    │  in package archives
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Ghidra Headless     │  Decompile binary to pseudo-C
│  (Docker container)  │  Extract: functions, strings, imports, syscalls
│  analyzeHeadless     │  Output: decompiled source + function list + call graph
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  AI Analysis Layer   │  Claude/Grok analyzes decompiled output
│  (Structured output) │  Classifies: network calls, file I/O, crypto ops,
│                      │  obfuscation, data exfiltration patterns
│                      │  Generates: risk score, behavior summary, findings
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Results Database    │  Store analysis results per package@version
│  (Supabase/Postgres) │  Enable: search, diff, alerts, API
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Distribution Layer  │  Web UI, GitHub Action, API, PR comments
│  (Next.js + API)     │
└─────────────────────┘
```

### Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Frontend | Next.js 15+ / React / Tailwind | Ashlr's core stack |
| Backend API | Next.js API routes or Express | Depends on complexity |
| Database | Supabase (PostgreSQL + Auth + RLS) | Ashlr's standard |
| Binary Analysis | Ghidra 11.3 headless mode in Docker | Free, scriptable, multi-arch |
| AI Layer | Claude API (primary), Grok (fallback) | Ashlr's standard LLM stack |
| Job Queue | BullMQ + Redis or Supabase Edge Functions | Async analysis jobs |
| CI/CD Integration | GitHub Action (TypeScript) | Primary distribution channel |
| Auth | Supabase Auth | Standard |
| Billing | Stripe | Standard |
| Hosting | Vercel (web) + Railway or Fly.io (Ghidra workers) | Ghidra needs CPU-heavy containers |

### Infrastructure Considerations

- **Ghidra headless is CPU-intensive** — each binary analysis takes 30s-5min depending on size
- **Worker pool** — run N Docker containers with Ghidra pre-loaded, process jobs from queue
- **Caching** — once a package@version is analyzed, cache forever (immutable). Only re-analyze on new version publish.
- **File size limits** — start with 10MB max binary size, expand later
- **Rate limiting** — per-user and per-org limits on on-demand analysis

---

## 5. Features — MVP (Phase 1, 6-8 weeks)

### P0 — Must Have

| Feature | Description |
|---------|-------------|
| **Binary extraction** | Given an npm package name + version, download and extract all native binaries (.node, .so, .dylib, .wasm) |
| **Ghidra decompilation** | Headless Ghidra script that decompiles a binary and outputs: pseudo-C, function list, string table, import table, syscall list |
| **AI analysis** | Claude prompt that takes decompiled output and produces: behavior classification (network/file/crypto/process), risk score (0-100), plain-English summary, specific findings with severity |
| **Results database** | Store analysis results keyed by ecosystem/package/version/binary. Queryable via API. |
| **Public web UI** | Search by package name. View analysis results: summary, risk score, function list, AI explanation, raw decompiled snippets |
| **GitHub Action** | Runs on PR. Scans package.json/lockfile for native dependencies. Queries database. Posts PR comment with results. Configurable fail threshold. |
| **Pre-computed database** | Analyze top 200 npm packages with native binaries on launch. Expand to 1,000 within first month. |

### P1 — Should Have

| Feature | Description |
|---------|-------------|
| **Binary diff** | Compare analysis between two versions of the same package. Highlight behavioral changes. AI-explain what changed. |
| **Alerts** | Email/Slack notification when a watched package publishes a new version with changed binary behavior |
| **PyPI support** | Extend extraction pipeline to Python wheels with C extensions |
| **Dashboard** | Org-level view: all repos, all native dependencies, aggregate risk score, compliance status |
| **API** | REST API for programmatic access. Token-based auth. Rate limited. |

### P2 — Nice to Have

| Feature | Description |
|---------|-------------|
| **SBOM export** | Generate CycloneDX or SPDX SBOM with binary-level components |
| **Compliance reports** | SOC 2 / ISO 27001 evidence documents |
| **GitLab CI integration** | Extend beyond GitHub |
| **Custom binary upload** | Users upload their own binaries for analysis (not just packages) |
| **Team features** | Shared annotations, comments on findings, audit log |

---

## 6. AI Analysis Prompt Design

The AI layer is the core differentiator. The prompt must produce structured, actionable output.

### Input to AI

```
Package: {name}@{version}
Binary: {filename} ({architecture}, {format})
File size: {bytes}

Decompiled functions ({count}):
{function_name_list}

Import table:
{imported_functions}

String table (filtered):
{interesting_strings — URLs, IPs, paths, commands}

Decompiled source (top functions by complexity):
{pseudo_c_output}
```

### Expected Output (Structured JSON)

```json
{
  "risk_score": 35,
  "risk_level": "medium",
  "summary": "This binary implements bcrypt password hashing using native C. It makes no network calls and only accesses memory. The crypto implementation uses standard OpenSSL routines. No suspicious behavior detected.",
  "behaviors": {
    "network": { "detected": false, "details": [] },
    "filesystem": { "detected": true, "details": ["Reads /dev/urandom for entropy"] },
    "process": { "detected": false, "details": [] },
    "crypto": { "detected": true, "details": ["Uses OpenSSL EVP_* functions for bcrypt"] },
    "obfuscation": { "detected": false, "details": [] },
    "data_exfiltration": { "detected": false, "details": [] }
  },
  "findings": [
    {
      "severity": "info",
      "title": "Entropy source access",
      "description": "Binary reads from /dev/urandom — expected for cryptographic operations.",
      "location": "function_0x4A32",
      "recommendation": "No action needed — standard crypto entropy source."
    }
  ],
  "source_match_confidence": "high",
  "explanation": "This is a standard bcrypt native addon..."
}
```

---

## 7. GitHub Action Spec

### Usage

```yaml
# .github/workflows/binary-check.yml
name: Binary Dependency Check
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield-action@v1
        with:
          api-key: ${{ secrets.BINSHIELD_API_KEY }}
          fail-on: high  # fail PR if any HIGH risk findings
          # Options: critical, high, medium, low, never
```

### PR Comment Output

```markdown
## BinShield — Binary Dependency Scan

**3 native binaries found** in 2 packages

| Package | Binary | Risk | Summary |
|---------|--------|------|---------|
| bcrypt@5.1.1 | bcrypt_lib.node | LOW (12) | Standard bcrypt implementation, no network/suspicious calls |
| sharp@0.33.2 | sharp-linux-x64.node | LOW (8) | Image processing via libvips, expected filesystem access |
| sqlite3@5.1.7 | sqlite3.node | LOW (5) | SQLite engine, no network calls |

All binaries passed analysis. No suspicious behavior detected.

---
*Powered by [BinShield](https://binshield.dev) — Binary supply chain security*
```

---

## 8. Data Model

### Core Tables

```sql
-- Packages we've analyzed
packages (
  id uuid PRIMARY KEY,
  ecosystem text NOT NULL,         -- 'npm', 'pypi'
  name text NOT NULL,
  latest_analyzed_version text,
  total_versions_analyzed int,
  created_at timestamptz,
  UNIQUE(ecosystem, name)
)

-- Specific version analyses
analyses (
  id uuid PRIMARY KEY,
  package_id uuid REFERENCES packages,
  version text NOT NULL,
  status text NOT NULL,            -- 'queued', 'analyzing', 'complete', 'failed'
  risk_score int,                  -- 0-100
  risk_level text,                 -- 'critical', 'high', 'medium', 'low', 'none'
  summary text,
  behaviors jsonb,                 -- structured behavior classification
  findings jsonb,                  -- array of finding objects
  binary_count int,
  total_binary_size bigint,
  ghidra_version text,
  ai_model text,
  analysis_duration_ms int,
  created_at timestamptz,
  UNIQUE(package_id, version)
)

-- Individual binary files within a package version
binaries (
  id uuid PRIMARY KEY,
  analysis_id uuid REFERENCES analyses,
  filename text NOT NULL,
  architecture text,               -- 'x86_64', 'arm64', etc.
  format text,                     -- 'ELF', 'PE', 'Mach-O', 'WASM'
  file_size bigint,
  function_count int,
  import_count int,
  risk_score int,
  decompiled_preview text,         -- first N lines of decompiled output
  ai_explanation text,
  behaviors jsonb,
  findings jsonb,
  created_at timestamptz
)

-- User organizations and repos being monitored
organizations (
  id uuid PRIMARY KEY,
  name text,
  plan text DEFAULT 'free',        -- 'free', 'pro', 'team', 'enterprise'
  stripe_customer_id text,
  created_at timestamptz
)

-- Repos connected for CI scanning
repos (
  id uuid PRIMARY KEY,
  org_id uuid REFERENCES organizations,
  github_repo text NOT NULL,       -- 'owner/repo'
  last_scan_at timestamptz,
  native_dep_count int,
  aggregate_risk_score int,
  created_at timestamptz
)

-- Alert subscriptions
alerts (
  id uuid PRIMARY KEY,
  org_id uuid REFERENCES organizations,
  package_id uuid REFERENCES packages,
  channel text NOT NULL,           -- 'email', 'slack', 'webhook'
  destination text NOT NULL,       -- email address, webhook URL, etc.
  created_at timestamptz
)
```

---

## 9. Pricing

| Tier | Price | Includes |
|------|-------|---------|
| **Free** | $0 | Public database access, 3 repos, 50 on-demand scans/month, community support |
| **Pro** | $149/mo | Unlimited repos, unlimited scans, binary diff alerts, API access, email support |
| **Team** | $499/mo | Everything in Pro + dashboard, SBOM export, Slack alerts, 5 seats |
| **Enterprise** | Custom ($2K-10K/mo) | Everything in Team + SSO, compliance reports, SLA, dedicated support, unlimited seats |

### Usage-Based Add-on
- On-demand analysis API: $0.50 per binary (for packages not in the public database)
- Billed monthly, included in Pro+ tiers up to limits

---

## 10. Go-to-Market

### Launch Sequence

**Week 1-2: Build the database**
- Identify top 200 npm packages with native binaries (bcrypt, sharp, sqlite3, canvas, etc.)
- Run Ghidra + Claude analysis pipeline on all of them
- Store results, verify quality

**Week 3-4: Build the web UI + GitHub Action**
- Public searchable database website
- GitHub Action that queries the database
- Landing page with value prop

**Week 5-6: Soft launch**
- Publish 3-5 blog posts analyzing interesting findings in popular packages
- Submit GitHub Action to marketplace
- Post to Hacker News, Reddit r/netsec, r/node
- DM 20 DevSecOps engineers on LinkedIn

**Week 7-8: Iterate + paid launch**
- Incorporate feedback from soft launch users
- Enable billing (Stripe)
- Begin outreach to compliance-driven companies

### Distribution Channels

| Channel | Expected Impact |
|---------|----------------|
| Free public database | Viral in security community — "look what we found in bcrypt" |
| GitHub Action marketplace | Organic discovery by DevSecOps engineers |
| Blog content | SEO + social sharing for interesting binary analysis findings |
| LinkedIn outreach | Direct to CISOs and VP Eng at mid-market companies |
| DevSecOps newsletters | tl;dr sec, This Week in Security, DevSecOps Weekly |
| Conference talks | BSides, OWASP chapter meetings, local security meetups |

### First 10 Customers Playbook

1. Publish free database — build awareness
2. Write "We decompiled the top 100 npm native packages — here's what we found" blog post
3. Identify 50 companies that have publicly discussed supply chain security concerns
4. Cold outreach: "We found [specific finding] in a package your repo uses. Here's the free report. Want us to scan everything?"
5. Offer 30-day free Pro trial to first 20 signups

---

## 11. Competitive Positioning

| Competitor | What They Do | What They Miss |
|-----------|-------------|---------------|
| **Socket.dev** ($65M raised) | Analyzes package install scripts, source behavior | Doesn't decompile native binaries |
| **Snyk** ($300M+ revenue) | SCA + SAST, CVE database | Source-level only, no binary analysis |
| **Phylum** (acquired by Veracode) | ML-based package risk scoring | Package metadata, not binary decompilation |
| **npm audit** | Known CVE matching | Only checks advisory database |
| **Endor Labs** | Reachability analysis | Source-level function analysis only |
| **ReversingLabs** | Enterprise binary analysis | $500K+ enterprise pricing, not developer-focused |

**BinShield's unique position:** The only tool that actually decompiles the machine code inside your dependencies and tells you what it does.

---

## 12. Success Metrics

### MVP Launch (Week 8)

| Metric | Target |
|--------|--------|
| Packages in public database | 500+ |
| GitHub Action installs | 100+ |
| Website unique visitors | 5,000+ |
| Free signups | 200+ |
| Blog post views | 10,000+ |

### Month 3

| Metric | Target |
|--------|--------|
| Packages analyzed | 2,000+ |
| Paying customers | 10+ |
| MRR | $2,000+ |
| GitHub Action installs | 500+ |

### Month 6

| Metric | Target |
|--------|--------|
| Packages analyzed | 5,000+ |
| Paying customers | 50+ |
| MRR | $10,000+ |
| Enterprise pipeline | 3+ conversations |

### Month 12

| Metric | Target |
|--------|--------|
| ARR | $100K-$400K |
| Packages analyzed | 10,000+ |
| Free users | 5,000+ |
| Paying customers | 200+ |

---

## 13. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Ghidra decompilation quality varies by architecture | Some binaries produce poor/incomplete output | Start with x86_64 Linux only (most common). Add architectures incrementally. Show confidence scores. |
| AI false positives | Users lose trust if benign binaries flagged as threats | Conservative risk scoring. Human review of first 200 analyses. Feedback mechanism. |
| Socket/Snyk adds binary analysis | Competitive pressure from well-funded incumbents | Move fast, build data moat. By the time they copy, we have 10,000+ analyzed packages and version history they'd need years to replicate. |
| Compute costs for Ghidra at scale | Margin pressure | Aggressive caching (immutable package versions = analyze once). Batch processing during off-peak. Start with spot instances. |
| Legal: decompiling packages | IP/license concerns | Packages are published for public consumption. Decompilation for security analysis is fair use. Consult attorney before launch. |
| Small team burnout | 3 people building infra + product + GTM | Phase aggressively. MVP is database + GitHub Action + landing page. Everything else is Phase 2+. |

---

## 14. Open Questions

1. **Name:** BinShield is a working title. Other options: BinLens, DeepDep, BinaryGuard, PackageScope. Need to check domain availability.
2. **PyPI priority:** Should MVP include Python packages or focus exclusively on npm first?
3. **Self-hosted option:** Will enterprise customers need an on-prem version?
4. **Ghidra vs alternatives:** Should we evaluate Binary Ninja's headless mode as an alternative/supplement to Ghidra? (License cost vs analysis quality tradeoff)
5. **Legal review:** Need attorney sign-off on decompiling published packages for security analysis before launch.

---

## 15. Reference Materials

### Existing Ashlr Assets to Leverage
- Security audit protocol: `~/Desktop/documentation project/04-operations/security/`
- Binary supply chain audit example: `~/Desktop/Evero BI/.security/binary-supply-chain-audit-2026-03-18.md`
- Audit report template: `~/Desktop/Evero BI/.security/audit-report-template.md`
- Ghidra headless scripting docs: https://github.com/NationalSecurityAgency/ghidra
- Ghidra headless scripts collection: https://github.com/galoget/ghidra-headless-scripts

### Market Research Sources
- Software supply chain security market: $5.53B (2025), 12.8% CAGR to $10.1B by 2030
- Malware analysis market: $6.94B (2025), 28% CAGR
- 99.8% of npm malware uses native/compiled components (Q4 2025)
- Socket.dev: $65M raised (a16z), analyzes source not binaries
- EU Cyber Resilience Act: mandates binary-level security documentation
- Biden EO: requires machine-readable SBOMs from federal software suppliers

### Key Open-Source Tools
- Ghidra headless mode: `analyzeHeadless` CLI
- Sekiryu: Ghidra headless toolkit (https://github.com/20urc3/Sekiryu)
- pyghidra-mcp: Headless Ghidra MCP server
- GhidrAssist: LLM extension for Ghidra
- LLM4Decompile: Specialized decompilation LLM
