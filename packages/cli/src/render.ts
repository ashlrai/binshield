/**
 * Rich terminal rendering for BinShield CLI — zero dependencies.
 *
 * All output respects isColorEnabled() from style.ts. Non-TTY / --ci / --no-color
 * environments receive clean plain text.
 */

import type {
  PackageAnalysis,
  BinaryAnalysis,
  ManifestAnalysis,
  ScriptFinding,
  LockfileScanResult,
  LockfilePackageResult,
  SearchResult,
  RiskLevel,
  FindingSeverity,
} from "./api.js";

import {
  bold,
  dim,
  gray,
  green,
  yellow,
  red,
  cyan,
  brightRed,
  boldRed,
  boldGreen,
  boldCyan,
  riskColor,
  riskBadge,
  riskBadgePlain,
  sectionHeader,
  divider,
  box,
  stripAnsi,
  padRight,
  truncate,
  formatBytes,
  isColorEnabled,
} from "./style.js";

// ---------------------------------------------------------------------------
// Severity colorization
// ---------------------------------------------------------------------------

function sevColor(sev: FindingSeverity | string): string {
  switch (sev) {
    case "critical": return boldRed(sev);
    case "high":     return red(sev);
    case "medium":   return yellow(sev);
    case "low":      return cyan(sev);
    default:         return dim(sev);
  }
}

// ---------------------------------------------------------------------------
// Threat category labels
// ---------------------------------------------------------------------------

const THREAT_LABELS: Record<string, string> = {
  installHook:        "Install hook",
  scriptInjection:    "Script injection",
  environmentTheft:   "Environment theft",
  dependencyConfusion:"Dependency confusion",
  wiper:              "Wiper",
  reverseShell:       "Reverse shell",
  remoteCodeExecution:"Remote code execution",
  obfuscation:        "Obfuscation",
  knownMalware:       "Known malware",
};

const BEHAVIOR_LABELS: Record<string, string> = {
  network:         "Network",
  filesystem:      "Filesystem",
  process:         "Process",
  crypto:          "Crypto",
  obfuscation:     "Obfuscation",
  dataExfiltration:"Data exfiltration",
};

// ---------------------------------------------------------------------------
// Verdict box
// ---------------------------------------------------------------------------

function verdictLine(level: RiskLevel, score: number): string {
  const label = `RISK: ${level.toUpperCase()} (${score})`;
  if (!isColorEnabled()) return label;

  switch (level) {
    case "critical": return `${"\x1b[1m\x1b[91m"}${label}${"\x1b[0m"}`;
    case "high":     return `${"\x1b[31m"}${label}${"\x1b[0m"}`;
    case "medium":   return `${"\x1b[33m"}${label}${"\x1b[0m"}`;
    case "low":      return `${"\x1b[34m"}${label}${"\x1b[0m"}`;
    default:         return `${"\x1b[90m"}${label}${"\x1b[0m"}`;
  }
}

function installScriptWarning(): string {
  return isColorEnabled()
    ? `${"\x1b[1m\x1b[91m"}INSTALL SCRIPT DETECTED${"\x1b[0m"} — malicious code can run on npm install`
    : "INSTALL SCRIPT DETECTED — malicious code can run on npm install";
}

// ---------------------------------------------------------------------------
// Package scan output
// ---------------------------------------------------------------------------

export function renderAnalysis(analysis: PackageAnalysis, opts: RenderOpts = {}): void {
  if (opts.json) {
    process.stdout.write(JSON.stringify(analysis, null, 2) + "\n");
    return;
  }

  const w = 64;

  // --- Verdict box --------------------------------------------------------
  const pkg = `${bold(analysis.packageName)}@${analysis.version}`;
  const ecosystem = dim(analysis.ecosystem);
  const verdict = verdictLine(analysis.riskLevel, analysis.riskScore);
  const binLine = `${analysis.binaryCount} ${analysis.binaryCount === 1 ? "binary" : "binaries"}  ${formatBytes(analysis.totalBinarySize)}`;
  const confLine = `Source confidence: ${analysis.sourceMatchConfidence}`;

  const boxLines: string[] = [
    `${pkg}  ${ecosystem}`,
    "",
    verdict,
  ];

  const ma = analysis.manifestAnalysis;
  if (ma?.hasInstallScripts) {
    boxLines.push("");
    boxLines.push(installScriptWarning());
  }

  boxLines.push("");
  boxLines.push(binLine);
  boxLines.push(dim(confLine));

  console.log();
  console.log(box(boxLines, w));
  console.log();

  // --- Summary ------------------------------------------------------------
  console.log(`  ${analysis.summary}`);
  console.log();

  // --- Install script threats (highest priority) --------------------------
  if (ma) {
    renderManifestAnalysis(ma);
  }

  // --- Binaries -----------------------------------------------------------
  if (analysis.binaries.length > 0) {
    console.log(sectionHeader("BINARIES", w));
    for (const bin of analysis.binaries) {
      renderBinary(bin, w);
    }
  }

  // --- Footer link --------------------------------------------------------
  const url = `https://binshield.dev/packages/${analysis.ecosystem}/${analysis.packageName}/${analysis.version}`;
  console.log(`  ${dim("View full report:")} ${url}`);
  console.log();
}

function renderManifestAnalysis(ma: ManifestAnalysis): void {
  const w = 64;

  if (!ma.hasInstallScripts && ma.findings.length === 0 && ma.knownMalwareAdvisoryIds.length === 0) {
    return;
  }

  console.log(sectionHeader("INSTALL SCRIPT ANALYSIS", w));
  console.log();

  // Known malware advisories
  if (ma.knownMalwareMatches && ma.knownMalwareMatches.length > 0) {
    for (const m of ma.knownMalwareMatches) {
      const icon = boldRed("KNOWN MALWARE");
      console.log(`  ${icon}  ${bold(m.advisoryId)}`);
      console.log(`    ${m.summary}`);
      if (m.url) console.log(`    ${dim(m.url)}`);
      console.log();
    }
  } else if (ma.knownMalwareAdvisoryIds.length > 0) {
    for (const id of ma.knownMalwareAdvisoryIds) {
      console.log(`  ${boldRed("KNOWN MALWARE")}  ${bold(id)}`);
    }
    console.log();
  }

  // Detected threat categories
  const detectedThreats = Object.entries(ma.threats)
    .filter(([, signal]) => signal.detected)
    .map(([key]) => key);

  if (detectedThreats.length > 0) {
    console.log(`  ${bold("Detected threats:")}`);
    for (const key of detectedThreats) {
      const label = THREAT_LABELS[key] ?? key;
      const signal = (ma.threats as unknown as Record<string, { detected: boolean; details: string[] }>)[key];
      console.log(`    ${red("•")} ${label}`);
      if (signal?.details && signal.details.length > 0) {
        for (const d of signal.details) {
          console.log(`      ${dim(d)}`);
        }
      }
    }
    console.log();
  }

  // Script findings
  if (ma.findings.length > 0) {
    console.log(`  ${bold("Script findings:")}`);
    for (const f of ma.findings) {
      renderScriptFinding(f);
    }
    console.log();
  }

  // AI explanation
  if (ma.aiExplanation) {
    console.log(`  ${dim("AI analysis:")} ${ma.aiExplanation}`);
    console.log();
  }

  // Lifecycle hooks
  const hooks = Object.keys(ma.lifecycleHooks ?? {});
  if (hooks.length > 0) {
    console.log(`  ${dim("Lifecycle hooks:")} ${hooks.join(", ")}`);
    console.log();
  }
}

function renderScriptFinding(f: ScriptFinding): void {
  const sev = sevColor(f.severity);
  const category = THREAT_LABELS[f.category] ?? f.category;
  console.log(`    [${sev}] ${bold(f.title)}  ${dim(category)}`);
  console.log(`      ${f.description}`);
  if (f.lifecycleHook) {
    console.log(`      ${dim("Hook:")} ${f.lifecycleHook}  ${dim("File:")} ${f.filePath}`);
  } else {
    console.log(`      ${dim("File:")} ${f.filePath}`);
  }
  if (f.evidence) {
    console.log(`      ${dim("Evidence:")} ${truncate(f.evidence, 120)}`);
  }
  console.log(`      ${dim("Fix:")} ${f.recommendation}`);
  console.log();
}

function renderBinary(bin: BinaryAnalysis, w: number): void {
  console.log();
  console.log(`  ${bold(bin.filename)}`);
  console.log(`  ${divider(w - 2)}`);

  const rows: [string, string][] = [
    ["Format",    `${bin.format} / ${bin.architecture}`],
    ["Size",      formatBytes(bin.fileSize)],
    ["Risk",      isColorEnabled() ? riskBadge(bin.riskLevel, bin.riskScore) : riskBadgePlain(bin.riskLevel, bin.riskScore)],
    ["Functions", `${bin.functionCount}   ${dim("Imports:")} ${bin.importCount}`],
  ];

  for (const [k, v] of rows) {
    console.log(`    ${padRight(dim(k + ":"), 18)}${v}`);
  }

  // Behaviors
  const detected = Object.entries(bin.behaviors)
    .filter(([, sig]) => sig.detected)
    .map(([key, sig]) => ({ label: BEHAVIOR_LABELS[key] ?? key, details: sig.details }));

  if (detected.length > 0) {
    console.log();
    console.log(`    ${dim("Behaviors:")}`);
    for (const b of detected) {
      console.log(`      ${cyan("•")} ${b.label}`);
      for (const d of b.details) {
        console.log(`        ${dim(d)}`);
      }
    }
  }

  // Findings
  if (bin.findings.length > 0) {
    console.log();
    console.log(`    ${dim("Findings:")}`);
    for (const f of bin.findings) {
      console.log(`      [${sevColor(f.severity)}] ${bold(f.title)}`);
      console.log(`        ${f.description}`);
      if (f.location) console.log(`        ${dim("Location:")} ${f.location}`);
      if (f.recommendation) console.log(`        ${dim("Fix:")} ${f.recommendation}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Audit / lockfile output
// ---------------------------------------------------------------------------

const RISK_ORDER: Record<RiskLevel, number> = {
  critical: 0, high: 1, medium: 2, low: 3, none: 4,
};

export interface AuditOpts extends RenderOpts {
  topN?: number;
}

export function renderAuditReport(
  result: LockfileScanResult,
  opts: AuditOpts = {},
): void {
  if (opts.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    return;
  }

  const w = 70;
  const pkgs = result.packages ?? [];
  const sorted = [...pkgs].sort(
    (a, b) => (RISK_ORDER[a.riskLevel] ?? 5) - (RISK_ORDER[b.riskLevel] ?? 5),
  );

  const counts: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  for (const p of pkgs) counts[p.riskLevel] = (counts[p.riskLevel] ?? 0) + 1;

  const hasThreats = counts.critical > 0 || counts.high > 0 || counts.medium > 0;
  const installScriptPkgs = pkgs.filter((p) => p.hasInstallScript);

  // --- Summary box -------------------------------------------------------
  const overallRisk: RiskLevel =
    counts.critical > 0 ? "critical"
    : counts.high > 0 ? "high"
    : counts.medium > 0 ? "medium"
    : counts.low > 0 ? "low"
    : "none";

  const boxLines: string[] = [
    `${bold(result.filename)}`,
    "",
    verdictLine(overallRisk, 0).replace(" (0)", ""),
    "",
    `${result.totalPackages} packages scanned`,
  ];

  if (counts.critical > 0) boxLines.push(`${boldRed(String(counts.critical))} critical`);
  if (counts.high > 0)     boxLines.push(`${red(String(counts.high))} high`);
  if (counts.medium > 0)   boxLines.push(`${yellow(String(counts.medium))} medium`);
  if (counts.low > 0)      boxLines.push(`${cyan(String(counts.low))} low`);
  if (counts.none > 0)     boxLines.push(`${gray(String(counts.none))} clean`);

  if (installScriptPkgs.length > 0) {
    boxLines.push("");
    boxLines.push(isColorEnabled()
      ? `${"\x1b[1m\x1b[91m"}${installScriptPkgs.length} install script(s) detected${"\x1b[0m"}`
      : `${installScriptPkgs.length} install script(s) detected`);
  }

  console.log();
  console.log(box(boxLines, w));
  console.log();

  // --- Install script warnings (most important) ---------------------------
  if (installScriptPkgs.length > 0) {
    console.log(sectionHeader("INSTALL SCRIPT THREATS", w));
    console.log();
    for (const p of installScriptPkgs) {
      const risk = isColorEnabled()
        ? riskBadge(p.riskLevel, p.riskScore)
        : riskBadgePlain(p.riskLevel, p.riskScore);
      console.log(`  ${red("!")} ${bold(p.packageName)}@${p.version}  ${risk}`);
    }
    console.log();
    console.log(`  ${dim("Install scripts run arbitrary code during `npm install`.")}`);
    console.log(`  ${dim("Review each package before installing in CI or production.")}`);
    console.log();
  }

  // --- Risky packages table -----------------------------------------------
  const risky = sorted.filter((p) => p.riskLevel !== "none");
  if (risky.length > 0) {
    console.log(sectionHeader("RISKY PACKAGES", w));
    console.log();

    const COL_PKG = 36;
    const COL_VER = 14;
    const COL_RISK = 20;

    const hdr = `  ${padRight(dim("Package"), COL_PKG)}${padRight(dim("Version"), COL_VER)}${padRight(dim("Risk"), COL_RISK)}`;
    console.log(hdr);
    console.log(`  ${divider(w - 2)}`);

    const topN = opts.topN ?? 40;
    const display = risky.slice(0, topN);

    for (const p of display) {
      const name = padRight(truncate(p.packageName, COL_PKG - 1), COL_PKG);
      const ver  = padRight(p.version, COL_VER);
      const risk = isColorEnabled()
        ? riskBadge(p.riskLevel, p.riskScore)
        : riskBadgePlain(p.riskLevel, p.riskScore);
      console.log(`  ${name}${ver}${risk}`);
    }

    if (risky.length > topN) {
      console.log(`\n  ${dim(`... and ${risky.length - topN} more. Use --json for the full list.`)}`);
    }

    console.log();
  }

  // --- Clean summary ------------------------------------------------------
  if (!hasThreats) {
    console.log(`  ${boldGreen("All packages are clean.")}  ${dim("No supply-chain risks detected.")}`);
    console.log();
  } else {
    console.log(`  ${dim("Run")} ${cyan("binshield scan npm <package>")} ${dim("for a deep dive on any package.")}`);
    console.log(`  ${dim("Docs:")} https://binshield.dev/docs`);
    console.log();
  }
}

// ---------------------------------------------------------------------------
// Lockfile scan output (detailed, for scan-lockfile command)
// ---------------------------------------------------------------------------

export function renderLockfileScan(result: LockfileScanResult, opts: RenderOpts = {}): void {
  // Delegates to audit renderer — same layout
  renderAuditReport(result, opts);
}

// ---------------------------------------------------------------------------
// Search results
// ---------------------------------------------------------------------------

export function renderSearchResults(
  results: SearchResult[],
  total: number,
  opts: RenderOpts = {},
): void {
  if (opts.json) {
    process.stdout.write(JSON.stringify({ items: results, total }, null, 2) + "\n");
    return;
  }

  if (results.length === 0) {
    console.log(`\n  ${dim("No results found.")}\n`);
    return;
  }

  const COL_PKG  = 32;
  const COL_VER  = 12;
  const COL_RISK = 22;
  const COL_BINS = 8;

  console.log();
  const hdr = `  ${padRight(dim("Package"), COL_PKG)}${padRight(dim("Version"), COL_VER)}${padRight(dim("Risk"), COL_RISK)}${padRight(dim("Bins"), COL_BINS)}Summary`;
  console.log(hdr);
  console.log(`  ${"─".repeat(90)}`);

  for (const r of results) {
    const name = padRight(truncate(r.packageName, COL_PKG - 1), COL_PKG);
    const ver  = padRight(r.latestVersion, COL_VER);
    const risk = isColorEnabled()
      ? riskBadge(r.riskLevel, r.riskScore)
      : riskBadgePlain(r.riskLevel, r.riskScore);
    // riskBadge already has trailing padding to COL_RISK chars
    const binsStr = padRight(String(r.binaryCount), COL_BINS);
    const summary = truncate(r.summary, 60);

    // For color, riskBadge adds invisible ANSI chars — pad based on plain width
    const riskDisplay = isColorEnabled()
      ? `${risk}${" ".repeat(Math.max(0, COL_RISK - stripAnsi(`${r.riskLevel} (${r.riskScore})`).length - 1))}`
      : padRight(risk, COL_RISK);

    console.log(`  ${name}${ver}${riskDisplay}${binsStr}${summary}`);
  }

  console.log(`\n  ${dim(`${total} result${total !== 1 ? "s" : ""}`)}\n`);
}

// ---------------------------------------------------------------------------
// Poll status line (used by spinner)
// ---------------------------------------------------------------------------

export function formatPollStatus(job: { id: string; status: string; stage?: string }): string {
  const stage = job.stage ? `  ${dim(`[${job.stage}]`)}` : "";
  return `${cyan(job.id.slice(0, 8))}… ${bold(job.status)}${stage}`;
}

// ---------------------------------------------------------------------------
// Error / success output
// ---------------------------------------------------------------------------

export function printError(message: string): void {
  // Zero-dependency error formatting (mirrors the prior @ashlr/cli-common renderError
  // contract: red "error:" prefix + message). Inlined so the published CLI has no
  // out-of-repo file: dependency, which previously broke clean installs / deploys.
  const prefix = isColorEnabled() ? red("error:") : "error:";
  process.stderr.write(`${prefix} ${message}\n`);
}

export function printWarn(message: string): void {
  const prefix = isColorEnabled() ? `${"\x1b[33m"}warn${"\x1b[0m"}` : "warn";
  process.stderr.write(`${prefix}: ${message}\n`);
}

export function printSuccess(message: string): void {
  const prefix = isColorEnabled() ? `${"\x1b[32m"}ok${"\x1b[0m"}` : "ok";
  process.stdout.write(`${prefix}: ${message}\n`);
}

export function printInfo(message: string): void {
  const prefix = isColorEnabled() ? dim("info") : "info";
  process.stderr.write(`${prefix}: ${message}\n`);
}

// ---------------------------------------------------------------------------
// User-friendly API error messages
// ---------------------------------------------------------------------------

export function friendlyApiError(err: unknown): string {
  if (err instanceof Error && err.name === "ApiError") {
    const apiErr = err as unknown as { kind: string; message: string; statusCode?: number };
    switch (apiErr.kind) {
      case "auth":
        return (
          "Authentication failed. Your API key may be invalid or expired.\n" +
          "  Run: binshield config set apiKey <your-key>\n" +
          "  Or:  export BINSHIELD_API_KEY=<your-key>"
        );
      case "not_found":
        return `Package not found. Check the name, version, and ecosystem.\n  ${dim(apiErr.message)}`;
      case "rate_limit":
        return (
          "Rate limit exceeded. Wait a moment and try again.\n" +
          "  Upgrade your plan at https://binshield.dev/pricing for higher limits."
        );
      case "server":
        return `BinShield API error (${apiErr.statusCode ?? "5xx"}). Try again shortly or check https://status.binshield.dev`;
      case "network":
        return `Cannot reach BinShield API. Check your network connection.\n  ${dim(apiErr.message)}`;
      case "timeout":
        return apiErr.message;
      default:
        return apiErr.message;
    }
  }
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Shared options type
// ---------------------------------------------------------------------------

export interface RenderOpts {
  json?: boolean;
  quiet?: boolean;
  verbose?: boolean;
}
