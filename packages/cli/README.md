# @binshield/cli

Zero-dependency CLI for [BinShield](https://binshield.dev) — scan npm packages and lockfiles for binary supply-chain risk without signing up for the SaaS.

## Install

```bash
# One-off scan (no install required)
npx @binshield/cli scan npm bcrypt 5.1.1

# Global install
npm install -g @binshield/cli

# Or with pnpm / yarn
pnpm add -g @binshield/cli
yarn global add @binshield/cli
```

## Usage

### Scan a package

```bash
# Scan a specific version
binshield scan npm bcrypt 5.1.1

# Scan latest
binshield scan npm sharp

# Other ecosystems
binshield scan pypi requests 2.31.0
binshield scan cargo openssl 0.10.55
```

### Scan a lockfile

Requires an API key ([get one free](https://binshield.dev)).

```bash
# Auto-detect lockfile in current directory
binshield scan-lockfile

# Explicit path
binshield scan-lockfile ./apps/api/package-lock.json
```

Supports: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.

### Search the database

```bash
binshield search sqlite
binshield search native addon
```

### Download an SBOM

```bash
binshield sbom sharp 0.33.2
```

### Save your API key

```bash
binshield login
# prompts for key → saves to ~/.binshield/config.json
```

## Global flags

| Flag | Description |
|------|-------------|
| `--api-url <url>` | Override the API base URL |
| `--api-key <key>` | Pass API key inline (overrides env / config) |
| `--json` | Machine-readable JSON output |
| `--fail-on <level>` | Exit code 2 when risk is at or above this level (default: `high`) |
| `--help`, `-h` | Show help |
| `--version`, `-v` | Show version |

## Environment variables

| Variable | Description |
|----------|-------------|
| `BINSHIELD_API_KEY` | API key (overrides config file) |
| `BINSHIELD_API_URL` | API base URL (default: `https://api.binshield.dev`) |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success — risk below threshold |
| `1` | Error (network, API, bad arguments) |
| `2` | Risk at or above `--fail-on` threshold |

## CI integration

```yaml
# .github/workflows/security.yml
- name: BinShield scan
  run: npx @binshield/cli scan-lockfile --api-key ${{ secrets.BINSHIELD_API_KEY }} --fail-on high
```

## License

MIT
