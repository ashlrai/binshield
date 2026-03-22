import type {
  PackageAnalysis,
  BinaryAnalysis,
  SearchResult,
  ScanJob,
  RiskLevel,
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

    // The interval will pick up the new message on next tick if we
    // just write it in-line now.
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

export function printAnalysis(analysis: PackageAnalysis): void {
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

  // Findings
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
      if (f.recommendation) {
        console.log(`          ${dim("Recommendation:")} ${f.recommendation}`);
      }
    }
  }

  console.log();
}

// ---------------------------------------------------------------------------
// Search results display
// ---------------------------------------------------------------------------

export function printSearchResults(results: SearchResult[]): void {
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
    // Risk badge contains ANSI codes so we can't rely on .length for padding.
    // Use a fixed-width approach for the plain-text portion.
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
${bold("BinShield CLI")} - Binary supply-chain security scanner

${bold("USAGE")}
  binshield <command> [options]

${bold("COMMANDS")}
  scan <package>@<version>       Submit a scan and display results
  search <query>                 Search the public package database
  sbom <package> <version>       Download SBOM for a package version
  login                          Save API key to ~/.binshield/config.json
  --help, -h                     Show this help message
  --version, -v                  Show version

${bold("ENVIRONMENT")}
  BINSHIELD_API_KEY              API key (overrides config file)
  BINSHIELD_API_URL              API base URL (default: https://api.binshield.dev)

${bold("EXAMPLES")}
  binshield scan bcrypt@5.1.1
  binshield search sqlite
  binshield sbom sharp 0.33.2
  binshield login
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
