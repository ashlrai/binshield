#!/usr/bin/env node
/**
 * BinShield CLI — binary supply-chain security scanner
 * Zero runtime dependencies.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { createInterface } from "node:readline";
import { resolve, basename, dirname } from "node:path";
import { parseArgs } from "node:util";
import { homedir } from "node:os";

import { BinShieldClient, ApiError, type RiskLevel } from "./api.js";
import {
  readConfig,
  writeConfig,
  resolveApiKey,
  resolveApiUrl,
  CONFIG_FILE,
} from "./config.js";
import {
  renderAnalysis,
  renderAuditReport,
  renderLockfileScan,
  renderSearchResults,
  formatPollStatus,
  printError,
  printSuccess,
  printInfo,
  friendlyApiError,
} from "./render.js";
import { Spinner } from "./spinner.js";
import {
  setColorEnabled,
  isColorEnabled,
  bold,
  dim,
  cyan,
} from "./style.js";
import {
  helpRoot,
  helpScan,
  helpAudit,
  helpScanLockfile,
  helpInit,
  helpConfig,
  helpSearch,
  helpAuditNames,
  VERSION,
} from "./help.js";
import {
  parseLockfile,
  auditLockfileNames,
} from "@binshield/package-intelligence";

// ---------------------------------------------------------------------------
// Risk ordering
// ---------------------------------------------------------------------------

const RISK_ORDER: Record<string, number> = {
  none: 0, low: 1, medium: 2, high: 3, critical: 4,
};

function riskAtOrAbove(level: RiskLevel, threshold: RiskLevel): boolean {
  return (RISK_ORDER[level] ?? 0) >= (RISK_ORDER[threshold] ?? 3);
}

function riskAnyAbove(
  packages: Array<{ riskLevel: RiskLevel }>,
  threshold: RiskLevel,
): boolean {
  return packages.some((p) => riskAtOrAbove(p.riskLevel, threshold));
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

/**
 * Split args into positionals (before the first '--' flag) and flag tokens.
 * This lets parseArgs see only flags while we handle positionals manually.
 */
function splitArgs(args: string[]): { positionals: string[]; flagArgs: string[] } {
  const positionals: string[] = [];
  const flagArgs: string[] = [];
  let inFlags = false;

  for (const arg of args) {
    if (!inFlags && arg.startsWith("-")) inFlags = true;
    if (inFlags) {
      flagArgs.push(arg);
    } else {
      positionals.push(arg);
    }
  }

  return { positionals, flagArgs };
}

function parseFlags(args: string[]) {
  try {
    return parseArgs({
      args,
      options: {
        help:       { type: "boolean", short: "h" },
        version:    { type: "boolean", short: "v" },
        json:       { type: "boolean" },
        ci:         { type: "boolean" },
        "no-color": { type: "boolean" },
        quiet:      { type: "boolean", short: "q" },
        verbose:    { type: "boolean" },
        "fail-on":  { type: "string" },
        "api-url":  { type: "string" },
        "api-key":  { type: "string" },
        force:      { type: "boolean" },
        ecosystem:  { type: "string" },
      },
      strict: false,
      allowPositionals: true,
    });
  } catch {
    return { values: {} as Record<string, string | boolean | string[] | undefined> };
  }
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

const rawArgs = process.argv.slice(2);
const { positionals, flagArgs } = splitArgs(rawArgs);
const command = positionals[0]?.toLowerCase();
const parsed = parseFlags(flagArgs);
const flags = parsed.values;

// Apply color / CI mode before any output
if (flags["no-color"] || flags["ci"]) {
  setColorEnabled(false);
}

async function main(): Promise<void> {
  // --version / -v
  if (!command || command === "--version" || flags.version) {
    if (flags.version || command === "--version") {
      process.stdout.write(`@binshield/cli ${VERSION}\n`);
      return;
    }
    // No command — show help
    process.stdout.write(helpRoot());
    return;
  }

  // --help / -h: if there's a real command, let that handler respond
  if (command === "--help" || (flags.help && !command)) {
    process.stdout.write(helpRoot());
    return;
  }

  switch (command) {
    case "scan":          return handleScan();
    case "audit":         return handleAudit();
    case "scan-lockfile": return handleScanLockfile();
    case "audit-names":   return handleAuditNames();
    case "init":          return handleInit();
    case "config":        return handleConfig();
    case "search":        return handleSearch();
    case "sbom":          return handleSbom();
    case "login":         return handleLogin();  // alias for config set apiKey
    default:
      printError(`Unknown command: ${command}`);
      process.stderr.write(`\nRun ${isColorEnabled() ? cyan("binshield --help") : "binshield --help"} to see available commands.\n`);
      process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------

function makeClient(requireKey = false): BinShieldClient {
  const apiKey = resolveApiKey(flags["api-key"] as string | undefined);
  const apiUrl = resolveApiUrl(flags["api-url"] as string | undefined);

  if (requireKey && !apiKey) {
    printError(
      "An API key is required for this command.\n" +
      "  Run: binshield config set apiKey <your-key>\n" +
      "  Or:  export BINSHIELD_API_KEY=<your-key>\n" +
      "  Get a free key at https://binshield.dev",
    );
    process.exit(1);
  }

  return new BinShieldClient({ baseUrl: apiUrl, apiKey });
}

const renderOpts = () => ({
  json: Boolean(flags.json),
  quiet: Boolean(flags.quiet),
  verbose: Boolean(flags.verbose),
});

// ---------------------------------------------------------------------------
// scan <ecosystem> <package> [version]
// ---------------------------------------------------------------------------

async function handleScan(): Promise<void> {
  if (flags.help) {
    process.stdout.write(helpScan());
    return;
  }

  // Parse: scan <ecosystem> <package> [version]
  // Also accepts legacy: scan bcrypt@5.1.1 (inferred npm)
  let ecosystem: string;
  let packageName: string;
  let version: string;

  const arg1 = positionals[1];
  const arg2 = positionals[2];
  const arg3 = positionals[3];

  if (!arg1) {
    printError("Package argument required.");
    process.stderr.write(helpScan());
    process.exitCode = 1;
    return;
  }

  // Detect @-notation for legacy compat: scan bcrypt@5.1.1
  const atIdx = arg1.lastIndexOf("@");
  if (!arg2 && atIdx > 0) {
    ecosystem = (flags.ecosystem as string | undefined) ?? "npm";
    packageName = arg1.slice(0, atIdx);
    version = arg1.slice(atIdx + 1);
  } else if (arg2) {
    ecosystem = arg1;
    packageName = arg2;
    version = arg3 ?? "latest";
  } else {
    ecosystem = (flags.ecosystem as string | undefined) ?? "npm";
    packageName = arg1;
    version = "latest";
  }

  const failOn = ((flags["fail-on"] as string | undefined) ?? "high") as RiskLevel;
  const client = makeClient(false);
  const spinner = new Spinner();

  try {
    spinner.start(`Scanning ${ecosystem}/${packageName}@${version}`);

    // Use authenticated endpoint if key is present, else public
    let job;
    if (client.apiKey) {
      job = await client.scan(ecosystem, packageName, version);
    } else {
      try {
        job = await client.scanPublic(ecosystem, packageName, version);
      } catch (pubErr) {
        // If public endpoint 404s (no /public/scan), fall back to authenticated
        if (pubErr instanceof ApiError && pubErr.kind === "not_found") {
          job = await client.scan(ecosystem, packageName, version);
        } else {
          throw pubErr;
        }
      }
    }

    spinner.update(`Analyzing ${packageName}@${version}  ${dim(`[${job.id.slice(0, 8)}]`)}`);

    const analysis = await client.waitForResult(job, {
      timeoutMs: 180_000,
      onPoll: (updated) => {
        spinner.update(formatPollStatus(updated));
      },
    });

    spinner.stop();
    renderAnalysis(analysis, renderOpts());

    if (riskAtOrAbove(analysis.riskLevel, failOn)) {
      if (!flags.json) {
        printError(`Risk level "${analysis.riskLevel}" meets the --fail-on threshold "${failOn}"`);
      }
      process.exitCode = 2;
    }
  } catch (err) {
    spinner.stop();
    printError(friendlyApiError(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// audit [path] — THE flagship
// ---------------------------------------------------------------------------

const LOCKFILE_CANDIDATES = [
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "pnpm-lock.yml",
  "requirements.txt",
  "Cargo.lock",
];

function detectLockfile(dir: string): string | undefined {
  for (const name of LOCKFILE_CANDIDATES) {
    const p = resolve(dir, name);
    if (existsSync(p)) return p;
  }
  return undefined;
}

async function handleAudit(): Promise<void> {
  if (flags.help) {
    process.stdout.write(helpAudit());
    return;
  }

  const targetDir = resolve(process.cwd(), positionals[1] ?? ".");
  const lockfilePath = detectLockfile(targetDir);

  if (!lockfilePath) {
    printError(
      `No lockfile found in ${targetDir}\n` +
      `  Supported: ${LOCKFILE_CANDIDATES.join(", ")}\n` +
      "  Pass a path: binshield audit ./path/to/project",
    );
    process.exitCode = 1;
    return;
  }

  const client = makeClient(true);

  let content: string;
  try {
    content = readFileSync(lockfilePath, "utf-8");
  } catch (err) {
    printError(`Cannot read lockfile: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
    return;
  }

  const filename = basename(lockfilePath);
  const failOn = ((flags["fail-on"] as string | undefined) ?? "high") as RiskLevel;
  const spinner = new Spinner();

  if (!flags.quiet && !flags.json) {
    printInfo(`Found ${filename} in ${targetDir}`);
  }

  try {
    spinner.start(`Submitting lockfile: ${filename}`);
    const job = await client.scanLockfile(filename, content);
    spinner.update(`Scanning dependencies  ${dim(`[${job.id.slice(0, 8)}]`)}`);

    const result = await client.waitForLockfileResult(job, {
      timeoutMs: 180_000,
      onPoll: (status) => {
        spinner.update(`Analyzing dependencies  ${dim(status)}`);
      },
    });

    spinner.stop();
    renderAuditReport(result, { ...renderOpts() });

    if (riskAnyAbove(result.packages ?? [], failOn)) {
      if (!flags.json) {
        printError(`Dependency tree contains packages at or above --fail-on threshold "${failOn}"`);
      }
      process.exitCode = 2;
    }
  } catch (err) {
    spinner.stop();
    printError(friendlyApiError(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// scan-lockfile [path]
// ---------------------------------------------------------------------------

async function handleScanLockfile(): Promise<void> {
  if (flags.help) {
    process.stdout.write(helpScanLockfile());
    return;
  }

  let lockfilePath = positionals[1];

  if (!lockfilePath) {
    const found = detectLockfile(process.cwd());
    if (!found) {
      printError(
        "No lockfile found in current directory.\n" +
        `  Supported: ${LOCKFILE_CANDIDATES.join(", ")}\n` +
        "  Pass a path: binshield scan-lockfile ./package-lock.json",
      );
      process.exitCode = 1;
      return;
    }
    lockfilePath = found;
  } else {
    lockfilePath = resolve(process.cwd(), lockfilePath);
  }

  if (!existsSync(lockfilePath)) {
    printError(`Lockfile not found: ${lockfilePath}`);
    process.exitCode = 1;
    return;
  }

  const client = makeClient(true);

  let content: string;
  try {
    content = readFileSync(lockfilePath, "utf-8");
  } catch (err) {
    printError(`Cannot read lockfile: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
    return;
  }

  const filename = basename(lockfilePath);
  const failOn = ((flags["fail-on"] as string | undefined) ?? "high") as RiskLevel;
  const spinner = new Spinner();

  try {
    spinner.start(`Submitting lockfile scan: ${filename}`);
    const job = await client.scanLockfile(filename, content);
    spinner.update(`Scan queued  ${dim(`[${job.id.slice(0, 8)}]`)}`);

    const result = await client.waitForLockfileResult(job, {
      timeoutMs: 180_000,
      onPoll: (status) => {
        spinner.update(`Lockfile scan  ${dim(status)}`);
      },
    });

    spinner.stop();
    renderLockfileScan(result, renderOpts());

    if (riskAnyAbove(result.packages ?? [], failOn)) {
      if (!flags.json) {
        printError(`Lockfile contains packages at or above --fail-on threshold "${failOn}"`);
      }
      process.exitCode = 2;
    }
  } catch (err) {
    spinner.stop();
    printError(friendlyApiError(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// init — scaffold GitHub Actions workflow
// ---------------------------------------------------------------------------

const WORKFLOW_TEMPLATE = (failOn: string) => `# BinShield — binary supply-chain security
# Scaffolded by: binshield init
# Docs: https://binshield.dev/docs/github-actions

name: BinShield Security Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

permissions:
  contents: read

jobs:
  binshield:
    name: Supply-chain audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run BinShield audit
        run: npx --yes @binshield/cli audit --ci --fail-on ${failOn}
        env:
          BINSHIELD_API_KEY: \${{ secrets.BINSHIELD_API_KEY }}
`;

async function handleInit(): Promise<void> {
  if (flags.help) {
    process.stdout.write(helpInit());
    return;
  }

  const failOn = (flags["fail-on"] as string | undefined) ?? "high";
  const workflowDir = resolve(process.cwd(), ".github", "workflows");
  const workflowFile = resolve(workflowDir, "binshield.yml");

  if (existsSync(workflowFile) && !flags.force) {
    printError(
      `${workflowFile} already exists.\n  Use --force to overwrite.`,
    );
    process.exitCode = 1;
    return;
  }

  try {
    mkdirSync(workflowDir, { recursive: true });
    writeFileSync(workflowFile, WORKFLOW_TEMPLATE(failOn), "utf-8");
  } catch (err) {
    printError(`Failed to write workflow: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
    return;
  }

  if (!flags.json) {
    printSuccess(`Created ${workflowFile}`);
    process.stdout.write(`
${bold("Next steps:")}

  1. Add your API key as a GitHub Actions secret:
     ${dim("Settings → Secrets → New repository secret")}
     ${dim("Name: BINSHIELD_API_KEY")}
     ${dim("Value: <your key from https://binshield.dev/settings/api-keys>")}

  2. Commit and push the workflow:
     ${dim("git add .github/workflows/binshield.yml")}
     ${dim("git commit -m 'ci: add BinShield supply-chain scan'")}
     ${dim("git push")}

  3. Open a pull request to see BinShield check your dependencies.

`);
  } else {
    process.stdout.write(
      JSON.stringify({ created: workflowFile, failOn }, null, 2) + "\n",
    );
  }
}

// ---------------------------------------------------------------------------
// config [get|set|path]
// ---------------------------------------------------------------------------

async function handleConfig(): Promise<void> {
  if (flags.help) {
    process.stdout.write(helpConfig());
    return;
  }

  const sub = positionals[1]?.toLowerCase();

  switch (sub) {
    case "path": {
      process.stdout.write(`${CONFIG_FILE}\n`);
      return;
    }

    case "get":
    case undefined: {
      const cfg = readConfig();
      if (flags.json) {
        // Never print the actual key in JSON — show a redacted preview
        const safe = {
          apiKey: cfg.apiKey ? `${cfg.apiKey.slice(0, 8)}...` : undefined,
          apiUrl: cfg.apiUrl,
          configFile: CONFIG_FILE,
          source: {
            apiKey: resolveApiKey() ? "resolved" : "not set",
            apiUrl: resolveApiUrl(),
          },
        };
        process.stdout.write(JSON.stringify(safe, null, 2) + "\n");
      } else {
        const resolvedKey = resolveApiKey(flags["api-key"] as string | undefined);
        const resolvedUrl = resolveApiUrl(flags["api-url"] as string | undefined);
        process.stdout.write(`
  ${bold("Config file:")}  ${CONFIG_FILE}

  ${bold("apiKey")}   ${resolvedKey ? dim(resolvedKey.slice(0, 8) + "...") : dim("(not set)")}
  ${bold("apiUrl")}   ${resolvedUrl}

  ${dim("Precedence: --api-key flag > BINSHIELD_API_KEY env > config file > default")}
`);
      }
      return;
    }

    case "set": {
      const key = positionals[2];
      const val = positionals[3];

      if (!key || !val) {
        printError("Usage: binshield config set <key> <value>\n  Keys: apiKey, apiUrl");
        process.exitCode = 1;
        return;
      }

      if (key !== "apiKey" && key !== "apiUrl") {
        printError(`Unknown config key: ${key}\n  Valid keys: apiKey, apiUrl`);
        process.exitCode = 1;
        return;
      }

      const existing = readConfig();
      writeConfig({ ...existing, [key]: val });

      if (!flags.json) {
        if (key === "apiKey") {
          printSuccess(`apiKey saved to ${CONFIG_FILE} (${val.slice(0, 8)}...)`);
        } else {
          printSuccess(`${key} set to ${val}`);
        }
      } else {
        process.stdout.write(JSON.stringify({ ok: true, key, configFile: CONFIG_FILE }, null, 2) + "\n");
      }
      return;
    }

    default:
      printError(`Unknown config subcommand: ${sub}\n  Usage: binshield config [get|set|path]`);
      process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// login — interactive API key save (alias for config set apiKey)
// ---------------------------------------------------------------------------

async function handleLogin(): Promise<void> {
  const envKey = process.env.BINSHIELD_API_KEY;
  if (envKey) {
    printSuccess("BINSHIELD_API_KEY environment variable is already set and takes precedence over the config file.");
  }

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const ask = (q: string): Promise<string> =>
    new Promise((res) => rl.question(q, (a) => res(a.trim())));

  try {
    const apiKey = await ask("  API key: ");
    if (!apiKey) {
      printError("No API key provided.");
      process.exitCode = 1;
      return;
    }
    const existing = readConfig();
    writeConfig({ ...existing, apiKey });
    printSuccess(`API key saved to ${CONFIG_FILE}`);
  } finally {
    rl.close();
  }
}

// ---------------------------------------------------------------------------
// search <query>
// ---------------------------------------------------------------------------

async function handleSearch(): Promise<void> {
  if (flags.help) {
    process.stdout.write(helpSearch());
    return;
  }

  const query = positionals.slice(1).join(" ").trim();
  if (!query) {
    printError("Usage: binshield search <query>");
    process.exitCode = 1;
    return;
  }

  const client = makeClient(false);

  try {
    const response = await client.search(query);
    renderSearchResults(response.items, response.total, renderOpts());
  } catch (err) {
    printError(friendlyApiError(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// audit-names [path] — typosquat / confusable name detection
// ---------------------------------------------------------------------------

const RISK_LEVEL_ORDER: Record<string, number> = {
  low: 1, medium: 2, high: 3, critical: 4,
};

function riskNameAtOrAbove(level: string, threshold: string): boolean {
  return (RISK_LEVEL_ORDER[level] ?? 0) >= (RISK_LEVEL_ORDER[threshold] ?? 3);
}

async function handleAuditNames(): Promise<void> {
  if (flags.help) {
    process.stdout.write(helpAuditNames());
    return;
  }

  let lockfilePath = positionals[1];

  if (!lockfilePath) {
    const found = detectLockfile(process.cwd());
    if (!found) {
      printError(
        "No lockfile found in current directory.\n" +
        "  Supported: package-lock.json, pnpm-lock.yaml, requirements.txt\n" +
        "  Pass a path: binshield audit-names ./package-lock.json",
      );
      process.exitCode = 1;
      return;
    }
    lockfilePath = found;
  } else {
    lockfilePath = resolve(process.cwd(), lockfilePath);
  }

  if (!existsSync(lockfilePath)) {
    printError(`Lockfile not found: ${lockfilePath}`);
    process.exitCode = 1;
    return;
  }

  let content: string;
  try {
    content = readFileSync(lockfilePath, "utf-8");
  } catch (err) {
    printError(`Cannot read lockfile: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
    return;
  }

  const filename = basename(lockfilePath);
  const failOn = (flags["fail-on"] as string | undefined) ?? "high";

  if (!flags.quiet && !flags.json) {
    printInfo(`Checking package names in ${filename}`);
  }

  const packages = parseLockfile(filename, content);

  if (packages.length === 0) {
    printError(
      `Could not parse any packages from ${filename}.\n` +
      "  Supported formats: package-lock.json (v1/v2), pnpm-lock.yaml, requirements.txt"
    );
    process.exitCode = 1;
    return;
  }

  const result = auditLockfileNames(packages);

  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    process.stdout.write(`\n${bold("Name Intelligence Audit")} — ${dim(filename)}\n\n`);
    process.stdout.write(`  Scanned: ${result.scanned} packages\n`);
    process.stdout.write(`  Risky:   ${result.risky.length}\n`);
    process.stdout.write(`  Clean:   ${result.clean}\n\n`);

    if (result.risky.length > 0) {
      process.stdout.write(`${bold("Risky packages:")}\n\n`);
      for (const r of result.risky) {
        const badge = r.riskLevel === "critical" ? "CRITICAL"
          : r.riskLevel === "high" ? "HIGH    "
          : r.riskLevel === "medium" ? "MEDIUM  "
          : "LOW     ";
        process.stdout.write(`  ${bold(badge)}  ${cyan(r.packageName)}\n`);
        for (const m of r.matches) {
          process.stdout.write(`           ${dim("•")} ${m.reason}\n`);
        }
        process.stdout.write("\n");
      }
    }

    process.stdout.write(`${dim(result.summary)}\n\n`);
  }

  const hasRisky = result.risky.some((r) => riskNameAtOrAbove(r.riskLevel, failOn));
  if (hasRisky) {
    if (!flags.json) {
      printError(`Lockfile contains package names at or above --fail-on threshold "${failOn}"`);
    }
    process.exitCode = 2;
  }
}

// ---------------------------------------------------------------------------
// sbom <ecosystem> <package> <version>
// ---------------------------------------------------------------------------

async function handleSbom(): Promise<void> {
  const ecosystem = positionals[1] ?? (flags.ecosystem as string | undefined) ?? "npm";
  const name = positionals[2] ?? positionals[1];
  const version = positionals[3] ?? positionals[2];

  if (!name || !version) {
    printError("Usage: binshield sbom <ecosystem> <package> <version>");
    process.exitCode = 1;
    return;
  }

  const client = makeClient(false);

  try {
    const sbom = await client.getSbom(ecosystem, name, version);
    process.stdout.write(sbom);
  } catch (err) {
    printError(friendlyApiError(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

main().catch((err) => {
  printError(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
