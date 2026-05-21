import type {
  PackageAnalysis,
  BinaryAnalysis,
  SearchResult,
  ScanJob,
  RiskLevel,
  LockfileScanResult,
  LockfilePackageResult,
} from "./api.js";

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------

const ESC = "\x1b[";

const RESET = `${ESC}0m`;
const BOLD = `${ESC}1m`;
const DIM = `${ESC}2m`;

const FG_RED = `${ESC}31m`;
const FG_GREEN = `${ESC}32m`;
const FG_YELLOW = `${ESC}33m`;
const FG_CYAN = `${ESC}36m`;
const FG_WHITE = `${ESC}37m`;
const FG_BRIGHT_RED = `${ESC}91m`;

/** Detect whether stdout supports color. */
function supportsColor(): boolean {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR !== undefined) return true;
  if (typeof process.stdout.isTTY === "boolean") return process.stdout.isTTY;
  return false;
}

const COLOR_ENABLED = supportsColor();

function wrap(style: string, text: string): string {
  return COLOR_ENABLED ? `${style}${text}${RESET}` : text;
}

function bold(text: string): string {
  return wrap(BOLD, text);
}

function dim(text: string): string {
  return wrap(DIM, text);
}

// ---------------------------------------------------------------------------
// Risk level colorization
// ---------------------------------------------------------------------------

export function colorRisk(level: RiskLevel): string {
  switch (level) {
    case "none":
      return wrap(FG_GREEN, "none");
    case "low":
      return wrap(FG_GREEN, "low");
    case "medium":
      return wrap(FG_YELLOW, "medium");
    case "high":
      return wrap(FG_RED, "high");
    case "critical":
      return wrap(`${BOLD}${FG_BRIGHT_RED}`, "critical");
    default:
      return level;
  }
}

function riskBadge(level: RiskLevel, score: number): string {
  return `${colorRisk(level)} (${score})`;
}

// ---------------------------------------------------------------------------
// Spinner
// ---------------------------------------------------------------------------

const SPINNER_FRAMES = ["|", "/", "-", "\\"];

export class Spinner {
  private timer: ReturnType<typeof setInterval> | null = null;
  private frame = 0;

  start(message: string): void {
    if (!COLOR_ENABLED) {
      process.stdout.write(`${message}...\n`);
      return;
    }

    process.stdout.write(`${ESC}?25l`); // hide cursor
    this.timer = setInterval(() => {
      const char = SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length];
      process.stdout.write(`\r${wrap(FG_CYAN, char)} ${message}`);
      this.frame++;
    }, 100);
  }

  update(message: string): void {
    if (!COLOR_ENABLED) {
      process.stdout.write(`${message}\n`);
      return;
    }

    const char = SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length];
    process.stdout.write(`\r${wrap(FG_CYAN, char)} ${message}`);
  }

  stop(finalMessage?: string): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    if (COLOR_ENABLED) {
      process.stdout.write(`\r${ESC}K${ESC}?25h`); // clear line, show cursor
    }

    if (finalMessage) {
      process.stdout.write(`${finalMessage}\n`);
    }
  }
}

// ---------------------------------------------------------------------------
// Padding utility
// ---------------------------------------------------------------------------

function pad(text: string, width: number): string {
  if (text.length >= width) return text;
  return text + " ".repeat(width - text.length);
}

// ---------------------------------------------------------------------------
// Scan result display
// ---------------------------------------------------------------------------

export function printAnalysis(analysis: PackageAnalysis, jsonMode = false): void {
  if (jsonMode) {
    console.log(JSON.stringify(analysis, null, 2));
    return;
  }

  const header = `${bold(analysis.packageName)}@${analysis.version}`;
  const divider = "─".repeat(60);

  console.log();
  console.log(divider);
  console.log(`  Package:    ${header}`);
  console.log(`  Ecosystem:  ${analysis.ecosystem}`);
  console.log(`  Risk:       ${riskBadge(analysis.riskLevel, analysis.riskScore)}`);
  console.log(`  Binaries:   ${analysis.binaryCount}`);
  console.log(`  Total size: ${formatBytes(analysis.totalBinarySize)}`);
  console.log(`  Confidence: ${analysis.sourceMatchConfidence}`);

  if (analysis.hasInstallScript) {
    console.log(`  ${wrap(FG_RED, "Install script detected")} — review carefully before installing`);
  }

  console.log(divider);
  console.log();
  console.log(`  ${dim("Summary:")} ${analysis.summary}`);
  console.log();

  if (analysis.binaries.length > 0) {
    console.log(`  ${bold("Binaries")}`);
    console.log();

    for (const bin of analysis.binaries) {
      printBinary(bin);
    }
  }
}

function printBinary(bin: BinaryAnalysis): void {
  console.log(`    ${bold(bin.filename)}`);
  console.log(`      Format:    ${bin.format} / ${bin.architecture}`);
  console.log(`      Size:      ${formatBytes(bin.fileSize)}`);
  console.log(`      Risk:      ${riskBadge(bin.riskLevel, bin.riskScore)}`);
  console.log(`      Functions: ${bin.functionCount}  Imports: ${bin.importCount}`);

  // Behaviors
  const detected = Object.entries(bin.behaviors)
    .filter(([, signal]) => signal.detected)
    .map(([name, signal]) => `${name}: ${signal.details.join("; ")}`);

  if (detected.length > 0) {
    console.log(`      ${dim("Behaviors:")}`);
    for (const b of detected) {
      console.log(`        - ${b}`);
    }
  }

  // Findings — show all, highlighted by severity
  if (bin.findings.length > 0) {
    console.log(`      ${dim("Findings:")}`);
    for (const f of bin.findings) {
      const sevColor =
        f.severity === "critical" || f.severity === "high"
          ? FG_RED
          : f.severity === "medium"
            ? FG_YELLOW
            : FG_WHITE;
      console.log(`        [${wrap(sevColor, f.severity)}] ${f.title}`);
      console.log(`          ${f.description}`);
      if (f.location) {
        console.log(`          ${dim("Location:")} ${f.location}`);
      }
      if (f.recommendation) {
        console.log(`          ${dim("Recommendation:")} ${f.recommendation}`);
      }
    }
  }

  console.log();
}

// ---------------------------------------------------------------------------
// Lockfile scan result display
// ---------------------------------------------------------------------------

export function printLockfileScan(result: LockfileScanResult, jsonMode = false): void {
  if (jsonMode) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const divider = "─".repeat(70);
  console.log();
  console.log(divider);
  console.log(`  Lockfile:  ${bold(result.filename)}`);
  console.log(`  Packages:  ${result.totalPackages}`);

  if (result.criticalRiskCount > 0) {
    console.log(`  Critical:  ${wrap(`${BOLD}${FG_BRIGHT_RED}`, String(result.criticalRiskCount))}`);
  }
  if (result.highRiskCount > 0) {
    console.log(`  High:      ${wrap(FG_RED, String(result.highRiskCount))}`);
  }

  console.log(divider);
  console.log();

  if (!result.packages || result.packages.length === 0) {
    console.log(`  ${dim("No package results yet — scan may still be processing.")}`);
    console.log();
    return;
  }

  // Sort: critical → high → medium → low → none
  const riskOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    none: 4,
  };

  const sorted = [...result.packages].sort(
    (a, b) => (riskOrder[a.riskLevel] ?? 5) - (riskOrder[b.riskLevel] ?? 5),
  );

  // Only print packages with risk > none, or all if everything is none
  const risky = sorted.filter((p) => p.riskLevel !== "none");
  const toPrint = risky.length > 0 ? risky : sorted.slice(0, 20);

  console.log(
    `  ${pad("Package", 35)} ${pad("Version", 15)} ${pad("Risk", 20)} Status`,
  );
  console.log(`  ${"─".repeat(90)}`);

  for (const pkg of toPrint) {
    printLockfilePackage(pkg);
  }

  const omitted = sorted.length - toPrint.length;
  if (omitted > 0) {
    console.log(`  ${dim(`  ... and ${omitted} more package(s) with no risk detected`)}`);
  }

  console.log();
}

function printLockfilePackage(pkg: LockfilePackageResult): void {
  const risk = riskBadge(pkg.riskLevel, pkg.riskScore);
  const riskPlain = `${pkg.riskLevel} (${pkg.riskScore})`;
  const riskPad = " ".repeat(Math.max(0, 20 - riskPlain.length));

  console.log(
    `  ${pad(pkg.packageName, 35)} ${pad(pkg.version, 15)} ${risk}${riskPad} ${pkg.status}`,
  );
}

// ---------------------------------------------------------------------------
// Search results display
// ---------------------------------------------------------------------------

export function printSearchResults(results: SearchResult[], jsonMode = false): void {
  if (jsonMode) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  if (results.length === 0) {
    console.log(dim("  No results found."));
    return;
  }

  // Header
  console.log();
  console.log(
    `  ${pad("Package", 30)} ${pad("Version", 12)} ${pad("Risk", 18)} ${pad("Binaries", 10)} Summary`,
  );
  console.log(`  ${"─".repeat(100)}`);

  for (const r of results) {
    const risk = riskBadge(r.riskLevel, r.riskScore);
    const riskPlain = `${r.riskLevel} (${r.riskScore})`;
    const riskPad = " ".repeat(Math.max(0, 18 - riskPlain.length));

    console.log(
      `  ${pad(r.packageName, 30)} ${pad(r.latestVersion, 12)} ${risk}${riskPad} ${pad(String(r.binaryCount), 10)} ${r.summary}`,
    );
  }

  console.log();
}

// ---------------------------------------------------------------------------
// Poll status display
// ---------------------------------------------------------------------------

export function formatPollStatus(job: ScanJob): string {
  const stage = job.stage ? ` [${job.stage}]` : "";
  return `Scan ${job.id}: ${job.status}${stage}`;
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

export function printHelp(): void {
  console.log(`
${bold("BinShield CLI")} — Binary supply-chain security scanner

${bold("USAGE")}
  binshield <command> [options]

${bold("COMMANDS")}
  scan <ecosystem> <package> [version]
    Submit a package scan and wait for results.
    ecosystem: npm | pypi | cargo | ...
    version:   defaults to "latest"

    Example:
      binshield scan npm bcrypt 5.1.1
      binshield scan npm sharp

  scan-lockfile [path]
    Scan a lockfile for risky dependencies.
    Detects: package-lock.json, yarn.lock, pnpm-lock.yaml
    Auto-detects lockfile in current directory if path is omitted.
    Requires an API key (--api-key or BINSHIELD_API_KEY).

    Example:
      binshield scan-lockfile
      binshield scan-lockfile ./app/package-lock.json

  search <query>
    Search the public package database.

  sbom <package> <version>
    Download SBOM for a package version (CycloneDX).

  login
    Save API key to ~/.binshield/config.json

  --help, -h       Show this help message
  --version, -v    Show version

${bold("GLOBAL FLAGS")}
  --api-url <url>       API base URL (default: https://api.binshield.dev)
  --api-key <key>       API key (overrides env / config file)
  --json                Machine-readable JSON output
  --fail-on <level>     Exit non-zero when risk >= level
                        Levels: none | low | medium | high | critical
                        Default: high

${bold("ENVIRONMENT")}
  BINSHIELD_API_KEY     API key (overrides config file)
  BINSHIELD_API_URL     API base URL

${bold("EXIT CODES")}
  0  Clean / scan complete, risk below threshold
  1  Error (network, API, bad arguments)
  2  Risk at or above --fail-on threshold
`);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function printError(message: string): void {
  console.error(`${wrap(FG_RED, "error:")} ${message}`);
}

export function printSuccess(message: string): void {
  console.log(`${wrap(FG_GREEN, "ok:")} ${message}`);
}
