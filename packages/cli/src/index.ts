#!/usr/bin/env node

import { createInterface } from "node:readline";
import { BinShieldClient } from "./api.js";
import { readConfig, writeConfig } from "./config.js";
import {
  printHelp,
  printAnalysis,
  printSearchResults,
  printError,
  printSuccess,
  Spinner,
  formatPollStatus,
} from "./output.js";

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const command = args[0]?.toLowerCase();

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  if (!command || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command === "--version" || command === "-v") {
    console.log("@binshield/cli 0.1.0");
    return;
  }

  switch (command) {
    case "scan":
      await handleScan();
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
// scan <package>@<version>
// ---------------------------------------------------------------------------

async function handleScan(): Promise<void> {
  const target = args[1];

  if (!target) {
    printError("Usage: binshield scan <package>@<version>");
    process.exitCode = 1;
    return;
  }

  // Parse "package@version". Handle scoped packages like @scope/name@version.
  const atIdx = target.lastIndexOf("@");

  if (atIdx <= 0) {
    printError(
      "Invalid format. Expected <package>@<version> (e.g. bcrypt@5.1.1)",
    );
    process.exitCode = 1;
    return;
  }

  const packageName = target.slice(0, atIdx);
  const version = target.slice(atIdx + 1);

  if (!packageName || !version) {
    printError(
      "Invalid format. Expected <package>@<version> (e.g. bcrypt@5.1.1)",
    );
    process.exitCode = 1;
    return;
  }

  // Default to npm ecosystem; could be extended with --ecosystem flag.
  const ecosystem = getFlag("--ecosystem") ?? "npm";

  const client = new BinShieldClient();
  const spinner = new Spinner();

  try {
    spinner.start(`Submitting scan for ${packageName}@${version}`);
    const job = await client.scan(ecosystem, packageName, version);
    spinner.update(formatPollStatus(job));

    const analysis = await client.waitForResult(job, {
      timeoutMs: 180_000,
      onPoll: (updated) => {
        spinner.update(formatPollStatus(updated));
      },
    });

    spinner.stop();
    printAnalysis(analysis);

    // Exit with non-zero if risk is high or critical.
    if (analysis.riskLevel === "high" || analysis.riskLevel === "critical") {
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
  const query = args.slice(1).join(" ");

  if (!query) {
    printError("Usage: binshield search <query>");
    process.exitCode = 1;
    return;
  }

  const client = new BinShieldClient();

  try {
    const response = await client.search(query);
    printSearchResults(response.items);
    console.log(`  ${response.total} result(s) found.`);
  } catch (err) {
    printError(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// sbom <package> <version>
// ---------------------------------------------------------------------------

async function handleSbom(): Promise<void> {
  const name = args[1];
  const version = args[2];

  if (!name || !version) {
    printError("Usage: binshield sbom <package> <version>");
    process.exitCode = 1;
    return;
  }

  const ecosystem = getFlag("--ecosystem") ?? "npm";
  const client = new BinShieldClient();

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
// Helpers
// ---------------------------------------------------------------------------

function getFlag(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

main().catch((err) => {
  printError(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
