#!/usr/bin/env node

import { createInterface } from "node:readline";
import { readFileSync, existsSync } from "node:fs";
import { resolve, basename } from "node:path";
import { parseArgs } from "node:util";
import { BinShieldClient } from "./api.js";
import { readConfig, writeConfig, resolveApiKey, resolveApiUrl } from "./config.js";
import {
  printHelp,
  printAnalysis,
  printLockfileScan,
  printSearchResults,
  printError,
  printSuccess,
  Spinner,
  formatPollStatus,
} from "./output.js";
import type { RiskLevel } from "./api.js";

// ---------------------------------------------------------------------------
// Version (kept in sync with package.json manually)
// ---------------------------------------------------------------------------

const VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Risk level ordering
// ---------------------------------------------------------------------------

const RISK_ORDER: Record<string, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function riskAtOrAbove(level: RiskLevel, threshold: RiskLevel): boolean {
  return (RISK_ORDER[level] ?? 0) >= (RISK_ORDER[threshold] ?? 3);
}

// ---------------------------------------------------------------------------
// Arg parsing with node:util parseArgs
// ---------------------------------------------------------------------------

// Strip the command/subcommand tokens before parsing flags so parseArgs
// doesn't choke on positional arguments.
const rawArgs = process.argv.slice(2);

// Identify leading positional tokens (command + optional subcommand args)
// before any '--' flag. We pull them out manually so parseArgs only sees flags.
function splitPositionalsFromFlags(args: string[]): { positionals: string[]; flags: string[] } {
  const positionals: string[] = [];
  const flags: string[] = [];
  let pastFirst = false;

  for (const arg of args) {
    if (arg.startsWith("-")) {
      pastFirst = true;
    }
    if (!pastFirst) {
      positionals.push(arg);
    } else {
      flags.push(arg);
    }
  }

  return { positionals, flags };
}

const { positionals, flags: flagArgs } = splitPositionalsFromFlags(rawArgs);
const command = positionals[0]?.toLowerCase();

function parseFlags(args: string[]) {
  try {
    return parseArgs({
      args,
      options: {
        help:      { type: "boolean", short: "h" },
        version:   { type: "boolean", short: "v" },
        json:      { type: "boolean" },
        "api-url": { type: "string" },
        "api-key": { type: "string" },
        "fail-on": { type: "string" },
        ecosystem: { type: "string" },
      },
      strict: false,
      allowPositionals: true,
    });
  } catch {
    return { values: {} as Record<string, string | boolean | string[] | undefined> };
  }
}

const parsedFlags = parseFlags(flagArgs);
const flagValues = parsedFlags.values;

const jsonMode = (flagValues.json ?? false) as boolean;
const failOnLevel = ((flagValues["fail-on"] ?? "high") as string) as RiskLevel;
const apiUrlFlag = flagValues["api-url"] as string | undefined;
const apiKeyFlag = flagValues["api-key"] as string | undefined;

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  if (!command || command === "--help" || flagValues.help) {
    printHelp();
    return;
  }

  if (command === "--version" || flagValues.version) {
    console.log(`@binshield/cli ${VERSION}`);
    return;
  }

  switch (command) {
    case "scan":
      await handleScan();
      break;
    case "scan-lockfile":
      await handleScanLockfile();
      break;
    case "search":
      await handleSearch();
      break;
    case "sbom":
      await handleSbom();
      break;
    case "login":
      await handleLogin();
      break;
    default:
      printError(`Unknown command: ${command}`);
      printHelp();
      process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Helper: build client from resolved flags
// ---------------------------------------------------------------------------

function makeClient(): BinShieldClient {
  return new BinShieldClient({
    baseUrl: resolveApiUrl(apiUrlFlag),
    apiKey: resolveApiKey(apiKeyFlag),
  });
}

// ---------------------------------------------------------------------------
// scan <ecosystem> <package> [version]
// ---------------------------------------------------------------------------

async function handleScan(): Promise<void> {
  // Accepts two forms:
  //   binshield scan npm bcrypt 5.1.1
  //   binshield scan npm bcrypt
  //   binshield scan bcrypt@5.1.1           (legacy single-arg form)
  //   binshield scan bcrypt                 (legacy, defaults to npm)

  let ecosystem: string;
  let packageName: string;
  let version: string;

  const arg1 = positionals[1];
  const arg2 = positionals[2];
  const arg3 = positionals[3];

  if (!arg1) {
    printError("Usage: binshield scan <ecosystem> <package> [version]");
    printError("       binshield scan npm bcrypt 5.1.1");
    process.exitCode = 1;
    return;
  }

  // Detect legacy @-notation: binshield scan bcrypt@5.1.1
  const atIdx = arg1.lastIndexOf("@");
  if (!arg2 && atIdx > 0) {
    ecosystem = (flagValues.ecosystem as string | undefined) ?? "npm";
    packageName = arg1.slice(0, atIdx);
    version = arg1.slice(atIdx + 1);
  } else if (arg2) {
    // New form: scan <ecosystem> <package> [version]
    ecosystem = arg1;
    packageName = arg2;
    version = arg3 ?? "latest";
  } else {
    // Just a package name — default ecosystem
    ecosystem = (flagValues.ecosystem as string | undefined) ?? "npm";
    packageName = arg1;
    version = "latest";
  }

  if (!packageName) {
    printError("Package name is required.");
    process.exitCode = 1;
    return;
  }

  const client = makeClient();
  const spinner = new Spinner();

  try {
    spinner.start(`Submitting scan for ${ecosystem}/${packageName}@${version}`);
    const job = await client.scan(ecosystem, packageName, version);
    spinner.update(formatPollStatus(job));

    const analysis = await client.waitForResult(job, {
      timeoutMs: 180_000,
      onPoll: (updated) => {
        spinner.update(formatPollStatus(updated));
      },
    });

    spinner.stop();
    printAnalysis(analysis, jsonMode);

    if (riskAtOrAbove(analysis.riskLevel, failOnLevel)) {
      if (!jsonMode) {
        printError(
          `Risk level "${analysis.riskLevel}" meets or exceeds --fail-on threshold "${failOnLevel}"`,
        );
      }
      process.exitCode = 2;
    }
  } catch (err) {
    spinner.stop();
    printError(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// scan-lockfile [path]
// ---------------------------------------------------------------------------

const LOCKFILE_CANDIDATES = [
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
];

async function handleScanLockfile(): Promise<void> {
  let lockfilePath = positionals[1];

  if (!lockfilePath) {
    // Auto-detect in cwd
    const found = LOCKFILE_CANDIDATES.find((name) =>
      existsSync(resolve(process.cwd(), name)),
    );
    if (!found) {
      printError(
        "No lockfile found in current directory. Pass a path explicitly:\n" +
        "  binshield scan-lockfile ./path/to/package-lock.json\n" +
        "  Supported: " + LOCKFILE_CANDIDATES.join(", "),
      );
      process.exitCode = 1;
      return;
    }
    lockfilePath = resolve(process.cwd(), found);
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
    printError(`Failed to read lockfile: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
    return;
  }

  const filename = basename(lockfilePath);
  const client = makeClient();

  if (!client.apiKey) {
    printError(
      "An API key is required for lockfile scanning.\n" +
      "  Set BINSHIELD_API_KEY, pass --api-key, or run: binshield login",
    );
    process.exitCode = 1;
    return;
  }

  const spinner = new Spinner();

  try {
    spinner.start(`Submitting lockfile scan: ${filename}`);
    const job = await client.scanLockfile(filename, content);
    spinner.update(`Scan queued: ${job.id} [${job.status}]`);

    const result = await client.waitForLockfileResult(job, {
      timeoutMs: 180_000,
      onPoll: (status) => {
        spinner.update(`Lockfile scan ${job.id}: ${status}`);
      },
    });

    spinner.stop();
    printLockfileScan(result, jsonMode);

    const hasCritical = (result.criticalRiskCount ?? 0) > 0;
    const hasHigh = (result.highRiskCount ?? 0) > 0;

    if (
      (failOnLevel === "critical" && hasCritical) ||
      (failOnLevel === "high" && (hasCritical || hasHigh)) ||
      (failOnLevel === "medium" &&
        (hasCritical || hasHigh || (result.packages ?? []).some((p) => p.riskLevel === "medium"))) ||
      (failOnLevel === "low" &&
        (result.packages ?? []).some((p) => p.riskLevel !== "none")) ||
      (failOnLevel === "none" && (result.packages ?? []).length > 0)
    ) {
      if (!jsonMode) {
        printError(
          `Lockfile contains packages at or above --fail-on threshold "${failOnLevel}"`,
        );
      }
      process.exitCode = 2;
    }
  } catch (err) {
    spinner.stop();
    printError(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// search <query>
// ---------------------------------------------------------------------------

async function handleSearch(): Promise<void> {
  const query = positionals.slice(1).join(" ");

  if (!query) {
    printError("Usage: binshield search <query>");
    process.exitCode = 1;
    return;
  }

  const client = makeClient();

  try {
    const response = await client.search(query);
    printSearchResults(response.items, jsonMode);
    if (!jsonMode) {
      console.log(`  ${response.total} result(s) found.`);
    }
  } catch (err) {
    printError(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// sbom <package> <version>
// ---------------------------------------------------------------------------

async function handleSbom(): Promise<void> {
  const name = positionals[1];
  const version = positionals[2];

  if (!name || !version) {
    printError("Usage: binshield sbom <package> <version>");
    process.exitCode = 1;
    return;
  }

  const ecosystem = (flagValues.ecosystem as string | undefined) ?? "npm";
  const client = makeClient();

  try {
    const sbom = await client.getSbom(ecosystem, name, version);
    process.stdout.write(sbom);
  } catch (err) {
    printError(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

async function handleLogin(): Promise<void> {
  const envKey = process.env.BINSHIELD_API_KEY;

  if (envKey) {
    printSuccess(
      "BINSHIELD_API_KEY environment variable is already set. It will take precedence over the config file.",
    );
  }

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const ask = (question: string): Promise<string> =>
    new Promise((resolve) => {
      rl.question(question, (answer) => resolve(answer.trim()));
    });

  try {
    const apiKey = await ask("API key: ");

    if (!apiKey) {
      printError("No API key provided.");
      process.exitCode = 1;
      return;
    }

    const existing = readConfig();
    writeConfig({ ...existing, apiKey });
    printSuccess("API key saved to ~/.binshield/config.json");
  } finally {
    rl.close();
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

main().catch((err) => {
  printError(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
