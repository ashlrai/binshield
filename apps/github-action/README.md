# BinShield GitHub Action

Scan your npm dependencies for risky native binaries. BinShield decompiles compiled `.node` files, classifies behavior with AI, and blocks threats before they reach production.

**Every `npm install` ships native binaries that no other scanner checks.** BinShield is the first tool that looks inside the machine code your dependencies actually execute.

## Quick Start

```yaml
name: Binary Dependency Check
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield-action@v1
        with:
          fail-on: high
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## What It Does

1. Discovers native dependencies from your `package-lock.json`
2. Submits each to the BinShield API for binary analysis
3. Posts a security report as a PR comment or workflow summary
4. Fails the check if any package exceeds your risk threshold

## Example PR Comment

```
## BinShield -- Binary Dependency Scan

3 native binaries found in 2 packages

| Package        | Risk     | Evidence                    |
|----------------|----------|-----------------------------|
| bcrypt@6.0.0   | MEDIUM   | 10 binaries, crypto, fs     |
| sharp@0.34.5   | LOW      | 1 binary, filesystem        |

All binaries passed the HIGH threshold.
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `api-base-url` | BinShield API URL | `https://binshieldapi-production.up.railway.app` |
| `api-key` | API key for authenticated scans | - |
| `github-token` | Token for PR comments | - |
| `working-directory` | Repo path to inspect | `.` |
| `scan-mode` | `native-only` or `all-dependencies` | `native-only` |
| `fail-on` | Risk threshold: `critical`, `high`, `medium`, `low`, `never` | `high` |
| `comment-mode` | `summary`, `pr-comment`, `both`, `off` | `summary` |
| `include-dev-dependencies` | Scan devDependencies too | `false` |
| `poll-interval-ms` | Polling delay in ms | `1500` |
| `timeout-ms` | Polling timeout in ms | `120000` |
| `max-targets` | Max packages to scan | `50` |

## How Scanning Works

- Discovers native packages from lockfile (heuristic: install scripts, gyp files, known native packages)
- Queries the BinShield public database for instant cached results
- For unknown packages, queues real-time analysis (decompilation + AI classification)
- Polls until results are ready or timeout is reached
- Renders findings with evidence cues and remediation guidance

## Scan Modes

**`native-only`** (default): Only scan packages identified as native binary candidates. Fast, focused on the highest-risk dependencies.

**`all-dependencies`**: Scan every dependency in the lockfile. Use for compliance audits where full coverage is required.

## Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| `none` | 0 | No binaries or behaviors detected |
| `low` | 1-29 | Expected behaviors only |
| `medium` | 30-59 | Review-worthy behaviors present |
| `high` | 60-79 | Multiple risk signals, manual review required |
| `critical` | 80-100 | Severe indicators, block until validated |

## SBOM Export

BinShield generates CycloneDX 1.5 SBOMs with binary-level detail:

```bash
curl https://binshieldapi-production.up.railway.app/packages/npm/bcrypt/versions/6.0.0/sbom
```

## GitHub Code Scanning (SARIF)

BinShield can emit a SARIF 2.1.0 file so findings appear in the **Security > Code scanning** tab on GitHub. Pass the `sarif-file` input and follow up with `github/codeql-action/upload-sarif`:

```yaml
name: BinShield + Code Scanning
on: [pull_request, push]

permissions:
  security-events: write   # required for upload-sarif
  contents: read

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: BinShield binary scan
        id: binshield
        uses: ashlrai/binshield-action@v1
        with:
          api-key: ${{ secrets.BINSHIELD_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: high
          sarif-file: binshield.sarif      # relative to working-directory

      - name: Upload SARIF to GitHub Security tab
        if: always()                        # upload even when the action fails
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.binshield.outputs.sarif-file }}
          category: binshield
```

Once uploaded, every binary and install-script finding surfaces as an alert in **Security > Code scanning alerts** with severity, rule description, and the affected package as the artifact path.

### SARIF severity mapping

| BinShield severity | SARIF level |
|--------------------|-------------|
| `critical`, `high` | `error`     |
| `medium`           | `warning`   |
| `low`, `info`      | `note`      |

## Support

- Website: [binshield.dev](https://binshield.dev)
- Issues: [github.com/ashlrai/binshield/issues](https://github.com/ashlrai/binshield/issues)
