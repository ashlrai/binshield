/**
 * Help text for all commands — zero dependencies.
 */

import { bold, dim, cyan, green, isColorEnabled } from "./style.js";

const VERSION = "0.2.0";

function indent(lines: string[], spaces = 4): string {
  const pad = " ".repeat(spaces);
  return lines.map((l) => (l ? `${pad}${l}` : "")).join("\n");
}

function cmd(name: string): string {
  return isColorEnabled() ? cyan(name) : name;
}

function flag(name: string): string {
  return isColorEnabled() ? green(name) : name;
}

// ---------------------------------------------------------------------------
// Top-level help
// ---------------------------------------------------------------------------

export function helpRoot(): string {
  return `
${bold("BinShield")} — binary supply-chain security scanner  ${dim(`v${VERSION}`)}
${dim("https://binshield.dev")}

${bold("USAGE")}
  binshield <command> [options]

${bold("COMMANDS")}
  ${cmd("scan")} <ecosystem> <package> [version]
    Scan a single package. Works without an API key (public endpoint).
    Use your key for priority scanning and higher rate limits.

  ${cmd("audit")} [path]
    Audit a project directory: auto-detect the lockfile, scan every
    dependency, and print a risk summary. This is the flagship command.

  ${cmd("scan-lockfile")} [path]
    Submit a specific lockfile for scanning (requires API key).

  ${cmd("init")}
    Scaffold a GitHub Actions workflow that adds BinShield to your CI.

  ${cmd("config")} [get|set|path]
    Manage persistent settings (API key, API URL).

  ${cmd("search")} <query>
    Search the public package database.

  ${cmd("sbom")} <ecosystem> <package> <version>
    Download a CycloneDX SBOM for a package version.

${bold("GLOBAL FLAGS")}
  ${flag("--api-key <key>")}     API key (flag > BINSHIELD_API_KEY env > config file)
  ${flag("--api-url <url>")}     API base URL (default: https://api.binshield.dev)
  ${flag("--fail-on <level>")}   Exit 2 when risk >= level  [none|low|medium|high|critical]
                       Default: high
  ${flag("--json")}              Machine-readable JSON output
  ${flag("--ci")}                CI mode: plain output, strict exit codes (implies --no-color)
  ${flag("--no-color")}          Disable ANSI colors
  ${flag("--quiet")}             Suppress informational output
  ${flag("--verbose")}           Show extra detail (imports, strings, decompiled preview)
  ${flag("-h, --help")}          Show help (per-command: binshield scan --help)
  ${flag("-v, --version")}       Show version

${bold("ENV VARS")}
  BINSHIELD_API_KEY    API key
  BINSHIELD_API_URL    API base URL
  NO_COLOR             Disable ANSI colors (per no-color.org)
  FORCE_COLOR          Force ANSI colors even in non-TTY

${bold("EXIT CODES")}
  0   Success — scan complete, risk below threshold
  1   Error (network failure, bad arguments, API error)
  2   Risk at or above --fail-on threshold

${bold("EXAMPLES")}
${indent([
  "binshield scan npm bcrypt 5.1.1",
  "binshield scan npm sharp",
  "binshield audit",
  "binshield audit ./my-app",
  "binshield scan-lockfile ./package-lock.json --fail-on medium",
  "binshield init",
  "binshield config set apiKey bsh_live_xxxxx",
  "binshield config get",
])}

Run ${cyan("binshield <command> --help")} for command-specific help.
`;
}

// ---------------------------------------------------------------------------
// Per-command help
// ---------------------------------------------------------------------------

export function helpScan(): string {
  return `
${bold("binshield scan")} — scan a single package for binary supply-chain risk

${bold("USAGE")}
  binshield scan <ecosystem> <package> [version] [flags]

${bold("ARGUMENTS")}
  ecosystem   Package ecosystem: ${dim("npm")} | ${dim("pypi")} | ${dim("cargo")}
  package     Package name
  version     Version to scan (default: latest)

${bold("FLAGS")}
  ${flag("--fail-on <level>")}   Exit 2 when risk >= level  [none|low|medium|high|critical]  (default: high)
  ${flag("--json")}              JSON output
  ${flag("--verbose")}           Show imports, strings, and decompiled preview
  ${flag("--api-key <key>")}     API key for priority scanning
  ${flag("--no-color")}          Plain output

${bold("NOTES")}
  Works without an API key using the anonymous public endpoint.
  Authenticated requests get faster analysis and higher rate limits.
  Install-script threats are shown prominently — this is BinShield's
  primary differentiator against supply-chain worms.

${bold("EXAMPLES")}
${indent([
  "binshield scan npm bcrypt 5.1.1",
  "binshield scan npm sharp",
  "binshield scan pypi requests 2.31.0",
  "binshield scan npm canvas --fail-on medium",
  "binshield scan npm express --json | jq .riskLevel",
])}
`;
}

export function helpAudit(): string {
  return `
${bold("binshield audit")} — audit your project's dependency tree

${bold("USAGE")}
  binshield audit [path] [flags]

${bold("ARGUMENTS")}
  path   Project directory to scan (default: current directory)
         BinShield will auto-detect: package-lock.json, yarn.lock,
         pnpm-lock.yaml, requirements.txt, Cargo.lock

${bold("FLAGS")}
  ${flag("--fail-on <level>")}   Exit 2 when any package risk >= level  (default: high)
  ${flag("--json")}              JSON output (full lockfile scan result)
  ${flag("--ci")}                CI mode: plain output, strict exit codes
  ${flag("--api-key <key>")}     API key (required for authenticated scans)
  ${flag("--no-color")}          Plain output
  ${flag("--quiet")}             Summary only, no per-package table

${bold("OUTPUT")}
  - Counts by risk level (critical / high / medium / low / clean)
  - Install-script threats prominently highlighted
  - Table of risky packages sorted critical → high → medium → low
  - Remediation guidance

${bold("EXAMPLES")}
${indent([
  "binshield audit",
  "binshield audit ./apps/api",
  "binshield audit --fail-on medium",
  "binshield audit --ci --fail-on high",
  "binshield audit --json > report.json",
])}
`;
}

export function helpScanLockfile(): string {
  return `
${bold("binshield scan-lockfile")} — submit a lockfile for scanning

${bold("USAGE")}
  binshield scan-lockfile [path] [flags]

${bold("ARGUMENTS")}
  path   Path to lockfile (default: auto-detect in current directory)
         Supported: package-lock.json, yarn.lock, pnpm-lock.yaml

${bold("FLAGS")}
  ${flag("--fail-on <level>")}   Exit 2 when any package risk >= level  (default: high)
  ${flag("--json")}              JSON output
  ${flag("--api-key <key>")}     API key (required)
  ${flag("--no-color")}          Plain output

${bold("NOTES")}
  Requires an API key. Get one free at https://binshield.dev
  Use ${cyan("binshield config set apiKey <key>")} to save it persistently.

${bold("EXAMPLES")}
${indent([
  "binshield scan-lockfile",
  "binshield scan-lockfile ./package-lock.json",
  "binshield scan-lockfile --fail-on medium --json",
])}
`;
}

export function helpInit(): string {
  return `
${bold("binshield init")} — scaffold BinShield into your GitHub CI

${bold("USAGE")}
  binshield init [flags]

${bold("WHAT IT DOES")}
  Creates .github/workflows/binshield.yml in the current project.
  The workflow runs ${cyan("binshield audit --ci")} on every push and pull request,
  blocking merges when supply-chain risk is detected.

${bold("FLAGS")}
  ${flag("--fail-on <level>")}   Risk threshold for the workflow  (default: high)
  ${flag("--force")}             Overwrite existing workflow file

${bold("NEXT STEPS")}
  1. Add your API key as a GitHub secret named BINSHIELD_API_KEY
  2. Commit and push .github/workflows/binshield.yml
  3. Open a PR to see BinShield in action

  Get an API key: https://binshield.dev/settings/api-keys

${bold("EXAMPLES")}
${indent([
  "binshield init",
  "binshield init --fail-on medium",
  "binshield init --force",
])}
`;
}

export function helpConfig(): string {
  return `
${bold("binshield config")} — manage persistent CLI settings

${bold("USAGE")}
  binshield config get              Show current config
  binshield config set <key> <val>  Set a config value
  binshield config path             Show config file path

${bold("KEYS")}
  apiKey    BinShield API key
  apiUrl    API base URL (default: https://api.binshield.dev)

${bold("NOTES")}
  Config is stored in ~/.binshield/config.json (chmod 600).
  CLI flags and environment variables take precedence over config file:
    CLI flag > BINSHIELD_API_KEY env var > config file

${bold("EXAMPLES")}
${indent([
  "binshield config get",
  "binshield config set apiKey bsh_live_xxxxx",
  "binshield config set apiUrl https://api.binshield.dev",
  "binshield config path",
])}
`;
}

export function helpSearch(): string {
  return `
${bold("binshield search")} — search the package database

${bold("USAGE")}
  binshield search <query> [flags]

${bold("FLAGS")}
  ${flag("--json")}   JSON output

${bold("EXAMPLES")}
${indent([
  "binshield search sqlite",
  "binshield search native image",
  "binshield search bcrypt --json",
])}
`;
}

export { VERSION };
