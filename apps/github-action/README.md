# BinShield Supply Chain Scanner

**Catch malicious install-script worms and AI-classify native binaries before they reach production.**

BinShield is the only CI scanner that looks *inside* the machine code your dependencies execute. It catches two classes of threat that `npm audit` misses entirely:

- **Install-script worms** — packages with `preinstall`/`postinstall` scripts that run arbitrary code at install time (the `node-ipc`, `event-source-polyfill`, and `xz-utils` attack pattern)
- **Malicious native binaries** — `.node` / `.so` / `.dylib` files that ship compiled malware disguised as normal addons

Results appear as a workflow summary, PR comment, SARIF code-scanning alerts, or all three.

## Installable today

```yaml
# Before a v1 tag is published, reference @main:
uses: ashlrai/binshield/apps/github-action@main

# Once the v1 tag is cut:
uses: ashlrai/binshield/apps/github-action@v1
```

## Quick Start

```yaml
name: Dependency Security Scan
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield/apps/github-action@main
        with:
          fail-on: high
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

Add `api-key: ${{ secrets.BINSHIELD_API_KEY }}` (free at [binshield.dev](https://binshield.dev)) to unlock higher rate limits and proactive alerting.

## What It Detects

| Threat class | Signal | Example packages |
|---|---|---|
| Install-script worm | `hasInstallScript: true` in lockfile | `node-ipc`, `ua-parser-js` |
| Native addon | `.gypfile: true`, `cpu`/`os` platform constraints | `bcrypt`, `sharp`, `canvas` |
| Binary tool | `bin` field ships an executable | `esbuild`, `vite` |
| Known-malicious | BinShield threat intelligence database | Typosquatters, compromised versions |

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-key` | — | BinShield API key for authenticated scans |
| `github-token` | — | Token for PR comments (`secrets.GITHUB_TOKEN`) |
| `api-base-url` | `https://api.binshield.dev` | Override for self-hosted deployments |
| `working-directory` | `.` | Repo root containing `package.json` and lockfile |
| `scan-mode` | `native-only` | `native-only` or `all-dependencies` (see below) |
| `include-dev-dependencies` | `false` | Include `devDependencies` in the scan |
| `register-dependencies` | `false` | Register deps so your org gets alerted if any are later flagged |
| `fail-on` | `high` | Risk threshold: `critical`, `high`, `medium`, `low`, `never` |
| `comment-mode` | `summary` | `summary`, `pr-comment`, `both`, or `off` |
| `sarif-file` | — | Path to write SARIF 2.1.0 output (enables Security tab integration) |
| `poll-interval-ms` | `1500` | Polling interval while real-time analysis runs |
| `timeout-ms` | `120000` | Max wait time before timing out |
| `max-targets` | `50` | Cap on packages scanned per run |

## Outputs

| Output | Description |
|---|---|
| `total-scanned` | Number of packages scanned |
| `highest-risk` | Highest risk level found: `none`, `low`, `medium`, `high`, `critical` |
| `failed` | `'true'` if the risk threshold was exceeded, `'false'` otherwise |
| `sarif-file` | Absolute path to the SARIF file (set when `sarif-file` input is provided) |

## Scan Modes

**`native-only`** (default): Scans packages with install scripts, `.gyp` build files, platform-specific binary markers (`cpu`/`os` fields), or known native package names. Fast — typically 5–30 packages per repo.

**`all-dependencies`**: Scans every entry in the lockfile. Use for compliance audits or when you want full-graph visibility.

## Risk Levels

| Level | Score | Meaning |
|---|---|---|
| `none` | 0 | No risky signals detected |
| `low` | 1–29 | Expected behaviors only; review optional |
| `medium` | 30–59 | Review-worthy signals present |
| `high` | 60–79 | Multiple risk signals; manual review required |
| `critical` | 80–100 | Severe threat indicators; block until validated |

## GitHub Code Scanning (SARIF)

Surface BinShield findings directly in the **Security > Code scanning** tab:

```yaml
name: BinShield + Code Scanning
on: [pull_request, push]

permissions:
  security-events: write
  contents: read

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: BinShield supply chain scan
        id: binshield
        uses: ashlrai/binshield/apps/github-action@main
        with:
          api-key: ${{ secrets.BINSHIELD_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: high
          sarif-file: binshield.sarif

      - name: Upload to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.binshield.outputs.sarif-file }}
          category: binshield
```

### SARIF severity mapping

| BinShield level | SARIF level |
|---|---|
| `critical`, `high` | `error` |
| `medium` | `warning` |
| `low`, `none` | `note` |

## Proactive Dependency Monitoring

Enable `register-dependencies: true` to record your dependency graph with BinShield. Your organization receives alerts when any registered package is later flagged by the npm registry feed — catching compromised-after-install attacks that point-in-time CI scans cannot detect.

```yaml
- uses: ashlrai/binshield/apps/github-action@main
  with:
    api-key: ${{ secrets.BINSHIELD_API_KEY }}
    register-dependencies: true
    fail-on: high
```

## Example PR Comment

```
## BinShield — Supply Chain Scan

3 native candidates found in 2 packages

| Package        | Risk     | Signals                       |
|----------------|----------|-------------------------------|
| bcrypt@6.0.0   | MEDIUM   | install script, crypto, fs    |
| sharp@0.34.5   | LOW      | platform binary, filesystem   |

All packages passed the HIGH threshold.
```

## Support

- Website: [binshield.dev](https://binshield.dev)
- Issues: [github.com/ashlrai/binshield/issues](https://github.com/ashlrai/binshield/issues)
