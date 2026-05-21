# @binshield/cli

Zero-dependency CLI for [BinShield](https://binshield.dev) — audit your dependency tree and scan npm packages for binary supply-chain risk. Decompiles native `.node`, `.so`, `.dylib`, and `.wasm` binaries, detects malicious install scripts, and blocks supply-chain worms before they reach production.

**Zero runtime dependencies.** The entire CLI is a single auditable entry point.

## Install

```bash
# One-off (no install required)
npx @binshield/cli audit

# Global
npm install -g @binshield/cli
pnpm add -g @binshield/cli
```

## Commands

### `binshield audit [path]` — flagship

Detect your project's lockfile, scan every dependency, and print an aggregate risk report. This is the primary command for CI and developer workflows.

```bash
binshield audit                           # auto-detect lockfile in cwd
binshield audit ./apps/api                # specific directory
binshield audit --fail-on medium          # exit 2 on medium+ risk
binshield audit --ci                      # plain output for CI logs
binshield audit --json > report.json      # full JSON report
```

Output includes:
- Verdict box: overall risk level + counts by severity
- **Install-script threats highlighted prominently** (BinShield's differentiator)
- Sorted table of risky packages (critical → high → medium → low)
- Remediation guidance

### `binshield scan <ecosystem> <package> [version]`

Deep-scan a single package. Works **without an API key** via the public endpoint.

```bash
binshield scan npm bcrypt 5.1.1
binshield scan npm sharp                  # latest
binshield scan pypi requests 2.31.0
binshield scan npm canvas --fail-on medium
binshield scan npm express --json | jq .riskLevel
```

### `binshield init`

Scaffold a GitHub Actions workflow into `.github/workflows/binshield.yml` in one command.

```bash
binshield init
binshield init --fail-on medium
binshield init --force                    # overwrite existing
```

Then add `BINSHIELD_API_KEY` as a GitHub Actions secret.

### `binshield scan-lockfile [path]`

Submit a specific lockfile. Requires an API key.

```bash
binshield scan-lockfile
binshield scan-lockfile ./apps/api/package-lock.json
```

Supports: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.

### `binshield config [get|set|path]`

Manage persistent settings in `~/.binshield/config.json` (chmod 600).

```bash
binshield config set apiKey bsh_live_xxxxx
binshield config set apiUrl https://api.binshield.dev
binshield config get
binshield config path                     # print config file location
```

### `binshield search <query>`

Search the public package database.

```bash
binshield search sqlite
binshield search native image addon
```

### `binshield login`

Interactive API key prompt (alias for `config set apiKey`).

## Global flags

| Flag | Description |
|------|-------------|
| `--api-key <key>` | API key (overrides env / config file) |
| `--api-url <url>` | Override API base URL |
| `--fail-on <level>` | Exit 2 when risk >= level (`none`\|`low`\|`medium`\|`high`\|`critical`). Default: `high` |
| `--json` | Machine-readable JSON output |
| `--ci` | CI mode: plain output, no spinner, no color |
| `--no-color` | Disable ANSI colors |
| `--quiet`, `-q` | Suppress informational output |
| `--verbose` | Show extra detail (imports, strings, decompiled preview) |
| `-h`, `--help` | Show help (also: `binshield <command> --help`) |
| `-v`, `--version` | Show version |

## Config precedence

```
CLI flag  >  BINSHIELD_API_KEY / BINSHIELD_API_URL env  >  ~/.binshield/config.json  >  default
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `BINSHIELD_API_KEY` | API key |
| `BINSHIELD_API_URL` | API base URL (default: `https://api.binshield.dev`) |
| `NO_COLOR` | Disable ANSI colors ([no-color.org](https://no-color.org)) |
| `FORCE_COLOR` | Force ANSI colors even in non-TTY |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success — risk below threshold |
| `1` | Error (network failure, bad arguments, API error) |
| `2` | Risk at or above `--fail-on` threshold |

## CI integration

```yaml
# .github/workflows/binshield.yml  (or: binshield init)
- name: BinShield supply-chain audit
  run: npx --yes @binshield/cli audit --ci --fail-on high
  env:
    BINSHIELD_API_KEY: ${{ secrets.BINSHIELD_API_KEY }}
```

Or generate it with `binshield init`.

## Why zero dependencies?

A security tool's supply chain should be as small and auditable as possible. `@binshield/cli` ships with:

- Hand-rolled ANSI styling (`style.ts`)
- Hand-rolled Braille-block spinner with graceful TTY/non-TTY degradation (`spinner.ts`)
- Hand-rolled `node:util parseArgs` argument parsing
- Zero runtime npm dependencies

The entire codebase is readable in an afternoon.

## License

MIT
