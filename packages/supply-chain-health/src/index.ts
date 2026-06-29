/**
 * Supply-Chain Health Analyzer
 *
 * Scores every package on maintenance signal (commit frequency, release
 * cadence, contributor count, license deprecation) and structural risk
 * (circular dependencies, orphaned dependencies, outdated transitive
 * versions).  Aggregates into a deterministic RiskLevel using fixed
 * thresholds so results are reproducible across runs.
 */

import type { RiskLevel } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Re-export the shared RiskLevel enum so consumers can import from one place
// ---------------------------------------------------------------------------
export type { RiskLevel };

// ---------------------------------------------------------------------------
// Signal types
// ---------------------------------------------------------------------------

/**
 * Raw maintenance + structural signals fetched from registry metadata.
 * All numeric fields are optional — analyzers emit `undefined` when the
 * underlying data is unavailable (e.g. no commit history for a package with
 * no public VCS).
 */
export interface SupplyChainSignals {
  /** Average commits per 90-day rolling window, derived from commit history. */
  commit_velocity_90d: number | undefined;
  /**
   * Average number of days between releases (lower = more actively released).
   * `undefined` when fewer than 2 releases exist.
   */
  release_cadence_days: number | undefined;
  /**
   * Fraction of contributors who left in the last 12 months compared to 12
   * months prior.  0 = no turnover, 1 = complete turnover.
   * `undefined` when contributor history is unavailable.
   */
  contributor_turnover: number | undefined;
  /**
   * Percentile rank of the direct-dependency age distribution for this
   * package (0–100).  A high percentile means dependencies are unusually old.
   * `undefined` when no dependencies are present.
   */
  dependency_age_percentile: number | undefined;
  /** Number of circular dependency pairs detected in the direct-dep graph. */
  circular_dep_count: number;
  /**
   * Number of declared dependencies that appear to have no dependents among
   * the remaining graph ("orphaned" / unused).
   */
  orphaned_dep_count: number;
  /**
   * `true` when the declared SPDX license identifier is deprecated or
   * non-OSI-recognised (e.g. "UNLICENSED", "SEE LICENSE IN LICENSE",
   * deprecated OSI aliases such as "GPL-2.0" without the SPDX + suffix).
   */
  license_deprecated: boolean;
}

// ---------------------------------------------------------------------------
// Per-signal scored finding
// ---------------------------------------------------------------------------

/** Human-readable explanation for a single degraded signal. */
export interface SupplyChainSignalFinding {
  signal: keyof SupplyChainSignals;
  /** Severity contribution of this individual signal. */
  severity: "info" | "low" | "medium" | "high" | "critical";
  /** Observed value (stringified). */
  observed: string;
  /** Threshold that was breached. */
  threshold: string;
  detail: string;
}

// ---------------------------------------------------------------------------
// Aggregate result
// ---------------------------------------------------------------------------

/** Full supply-chain health result for one package@version. */
export interface SupplyChainHealthResult {
  packageName: string;
  version: string;
  ecosystem: "npm" | "pypi";
  /** Raw signal values used to compute the score. */
  signals: SupplyChainSignals;
  /** Detailed per-signal findings for signals that exceeded thresholds. */
  findings: SupplyChainSignalFinding[];
  /**
   * Numeric risk score 0–100 (deterministic — computed from signal weights).
   */
  riskScore: number;
  /** Bucketed risk level derived from riskScore. */
  riskLevel: RiskLevel;
  /** Brief human-readable summary of the health assessment. */
  summary: string;
  /** ISO timestamp when this health check was computed. */
  analyzedAt: string;
}

// ---------------------------------------------------------------------------
// Registry metadata shapes (subset we actually use)
// ---------------------------------------------------------------------------

/** Subset of an npm registry package metadata document. */
export interface NpmRegistryMetadata {
  name: string;
  /** version → dist-tag, publish time */
  time?: Record<string, string>;
  versions?: Record<string, {
    dependencies?: Record<string, string>;
    license?: string | { type: string } | Array<{ type: string }>;
  }>;
  /** contributors list from latest version */
  maintainers?: Array<{ name: string; email?: string }>;
  contributors?: Array<{ name: string; email?: string }>;
  /** Latest dist-tags info */
  "dist-tags"?: Record<string, string>;
  license?: string;
  bugs?: unknown;
  repository?: unknown;
}

/** Subset of a PyPI JSON API package info document. */
export interface PypiRegistryMetadata {
  info: {
    name: string;
    version: string;
    license?: string | null;
    requires_dist?: string[] | null;
    author?: string | null;
    maintainer?: string | null;
  };
  releases?: Record<string, Array<{ upload_time?: string }>>;
  urls?: Array<{ upload_time?: string }>;
}

/** Union metadata type passed to the analyzer. */
export type PackageRegistryMetadata =
  | { ecosystem: "npm"; data: NpmRegistryMetadata }
  | { ecosystem: "pypi"; data: PypiRegistryMetadata };

// ---------------------------------------------------------------------------
// Deprecated / non-standard SPDX license identifiers
// ---------------------------------------------------------------------------

/**
 * SPDX identifiers that are deprecated, non-OSI-approved, or commonly
 * mis-used in the npm/PyPI ecosystem.
 */
const DEPRECATED_LICENSE_IDENTIFIERS = new Set([
  "UNLICENSED",
  "UNLICENSE",
  "SEE LICENSE IN LICENSE",
  "SEE LICENSE IN LICENCE",
  "SEE LICENSE IN LICENSE.md",
  "SEE LICENSE IN LICENSE.txt",
  "GPL-2.0",          // deprecated alias — should be GPL-2.0-only or GPL-2.0-or-later
  "GPL-3.0",          // deprecated alias
  "LGPL-2.0",         // deprecated alias
  "LGPL-2.1",         // deprecated alias
  "LGPL-3.0",         // deprecated alias
  "AGPL-3.0",         // deprecated alias
  "AGPL-1.0",
  "MPL-1.0",
  "MPL-1.1",
  "CDDL-1.0",
  "EPL-1.0",
  "OSL-1.0",
  "OSL-1.1",
  "OSL-2.0",
  "OSL-2.1",
  "OSL-3.0",
  "Artistic-1.0",
  "eCos-2.0",
  "None",
  "",
]);

// ---------------------------------------------------------------------------
// Deterministic scoring thresholds
// ---------------------------------------------------------------------------

/**
 * Scoring weight for each signal when it exceeds its threshold.
 * Weights sum to 100 max across all CRITICAL breaches.
 */
const SIGNAL_WEIGHTS: Record<keyof SupplyChainSignals, number> = {
  commit_velocity_90d:    20,
  release_cadence_days:   15,
  contributor_turnover:   15,
  dependency_age_percentile: 15,
  circular_dep_count:     10,
  orphaned_dep_count:     10,
  license_deprecated:     15,
};

/**
 * Thresholds for individual signal severity levels.
 * Each key is a signal name; the value maps a severity to the threshold that
 * triggers it.  Evaluated from most-severe to least-severe — first match wins.
 */
const THRESHOLDS = {
  commit_velocity_90d: {
    critical: 0,    // zero commits in 90d
    high: 2,        // ≤2 commits per quarter
    medium: 10,     // ≤10 commits per quarter
    low: 20,        // ≤20 commits per quarter
  },
  release_cadence_days: {
    critical: 730,  // >2 years between releases
    high: 365,      // >1 year between releases
    medium: 180,    // >6 months between releases
    low: 90,        // >3 months between releases
  },
  contributor_turnover: {
    critical: 1.0,  // 100% turnover
    high: 0.8,      // ≥80% contributors left
    medium: 0.5,    // ≥50% contributors left
    low: 0.3,       // ≥30% contributors left
  },
  dependency_age_percentile: {
    critical: 95,   // top-5% oldest dependencies
    high: 85,       // top-15% oldest
    medium: 70,     // top-30% oldest
    low: 60,        // top-40% oldest
  },
  circular_dep_count: {
    critical: 5,
    high: 3,
    medium: 1,
    low: 0,         // any circular dep is at least informational — handled separately
  },
  orphaned_dep_count: {
    critical: 10,
    high: 5,
    medium: 2,
    low: 1,
  },
} as const;

// ---------------------------------------------------------------------------
// Score contribution per severity level
// ---------------------------------------------------------------------------
const SEVERITY_SCORE: Record<"critical" | "high" | "medium" | "low" | "info", number> = {
  critical: 1.0,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
  info: 0.1,
};

// ---------------------------------------------------------------------------
// Helper: classify a numeric signal against its thresholds
// ---------------------------------------------------------------------------

type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

function classifyNumeric(
  value: number,
  thresholds: { critical: number; high: number; medium: number; low: number },
  higherIsBetter: boolean
): SeverityLevel {
  const check = (threshold: number) =>
    higherIsBetter ? value <= threshold : value >= threshold;

  if (check(thresholds.critical)) return "critical";
  if (check(thresholds.high)) return "high";
  if (check(thresholds.medium)) return "medium";
  if (check(thresholds.low)) return "low";
  return "info";
}

// ---------------------------------------------------------------------------
// License extraction helpers
// ---------------------------------------------------------------------------

function extractNpmLicense(
  meta: NpmRegistryMetadata,
  version: string
): string | undefined {
  const versionData = meta.versions?.[version];
  if (versionData?.license) {
    if (typeof versionData.license === "string") return versionData.license;
    if (typeof versionData.license === "object" && !Array.isArray(versionData.license)) {
      return (versionData.license as { type: string }).type;
    }
    if (Array.isArray(versionData.license)) {
      return (versionData.license as Array<{ type: string }>)[0]?.type;
    }
  }
  if (typeof meta.license === "string") return meta.license;
  return undefined;
}

function isLicenseDeprecated(licenseId: string | undefined | null): boolean {
  if (licenseId == null) return true; // missing license is treated as deprecated
  const normalized = licenseId.trim().toUpperCase();
  // Check exact match
  if (DEPRECATED_LICENSE_IDENTIFIERS.has(normalized)) return true;
  // Empty / whitespace only
  if (normalized.length === 0) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Release cadence computation (shared between npm + pypi)
// ---------------------------------------------------------------------------

function computeReleaseCadence(timestamps: string[]): number | undefined {
  if (timestamps.length < 2) return undefined;

  const sorted = timestamps
    .map((t) => new Date(t).getTime())
    .filter((ms) => !isNaN(ms))
    .sort((a, b) => a - b);

  if (sorted.length < 2) return undefined;

  const gaps: number[] = [];
  for (let i = 1; i < sorted.length; i++) {
    gaps.push((sorted[i]! - sorted[i - 1]!) / (1000 * 60 * 60 * 24)); // ms → days
  }

  const avg = gaps.reduce((sum, g) => sum + g, 0) / gaps.length;
  return Math.round(avg);
}

// ---------------------------------------------------------------------------
// Dependency graph helpers (static metadata analysis)
// ---------------------------------------------------------------------------

/**
 * Detect circular dependency pairs in a flat dependency map.
 * Uses a simple adjacency check: if package A depends on B and B depends on A,
 * that is one circular pair.  Deep cycles are approximated via DFS.
 */
function detectCircularDeps(
  deps: Record<string, string[]>
): number {
  const visited = new Set<string>();
  const inStack = new Set<string>();
  let cycleCount = 0;

  function dfs(node: string, path: Set<string>): void {
    if (inStack.has(node)) {
      cycleCount++;
      return;
    }
    if (visited.has(node)) return;

    visited.add(node);
    inStack.add(node);

    for (const neighbor of deps[node] ?? []) {
      if (path.has(neighbor)) {
        cycleCount++;
      } else {
        const newPath = new Set(path);
        newPath.add(node);
        dfs(neighbor, newPath);
      }
    }

    inStack.delete(node);
  }

  for (const node of Object.keys(deps)) {
    if (!visited.has(node)) {
      dfs(node, new Set([node]));
    }
  }

  return cycleCount;
}

/**
 * Count orphaned dependencies: packages listed in the dep map that are not
 * transitively referenced by any other package in the map.
 */
function countOrphanedDeps(
  directDeps: string[],
  allDeps: Record<string, string[]>
): number {
  // Build the set of all packages referenced by at least one other dep
  const referenced = new Set<string>();
  for (const dep of directDeps) {
    referenced.add(dep);
  }
  for (const transitive of Object.values(allDeps)) {
    for (const dep of transitive) {
      referenced.add(dep);
    }
  }

  // Orphans are packages in allDeps that are never referenced
  let orphans = 0;
  for (const pkg of Object.keys(allDeps)) {
    if (!referenced.has(pkg)) {
      orphans++;
    }
  }
  return orphans;
}

// ---------------------------------------------------------------------------
// Signal extractor for npm
// ---------------------------------------------------------------------------

function extractNpmSignals(
  meta: NpmRegistryMetadata,
  version: string
): Omit<SupplyChainSignals, "circular_dep_count" | "orphaned_dep_count"> {
  // --- commit_velocity_90d ---
  // npm registry doesn't expose commit history directly; approximate using
  // publish frequency in a 90-day window as a proxy for commit activity.
  let commit_velocity_90d: number | undefined;
  if (meta.time) {
    const now = Date.now();
    const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;
    const recentVersions = Object.entries(meta.time)
      .filter(([key]) => key !== "created" && key !== "modified")
      .filter(([, ts]) => new Date(ts).getTime() >= ninetyDaysAgo);
    commit_velocity_90d = recentVersions.length * 3; // ~3 commits per release as approximation
  }

  // --- release_cadence_days ---
  let release_cadence_days: number | undefined;
  if (meta.time) {
    const publishTimes = Object.entries(meta.time)
      .filter(([key]) => key !== "created" && key !== "modified")
      .map(([, ts]) => ts);
    release_cadence_days = computeReleaseCadence(publishTimes);
  }

  // --- contributor_turnover ---
  // npm doesn't provide contributor history over time — use maintainer count
  // as a proxy (single maintainer = high single-point-of-failure risk).
  let contributor_turnover: number | undefined;
  const maintainerCount = (meta.maintainers ?? []).length;
  if (maintainerCount === 1) {
    contributor_turnover = 0.9; // single maintainer — high bus-factor risk
  } else if (maintainerCount > 1) {
    contributor_turnover = Math.max(0, 1 - Math.min(maintainerCount / 5, 1));
  }

  // --- dependency_age_percentile ---
  // Approximate from the ratio of dependencies that pin exact versions (=x.y.z)
  // vs. semver ranges — exact pins tend to be older dependencies.
  let dependency_age_percentile: number | undefined;
  const versionDeps = meta.versions?.[version]?.dependencies ?? {};
  const depEntries = Object.values(versionDeps);
  if (depEntries.length > 0) {
    const exactPins = depEntries.filter((v) => /^\d+\.\d+\.\d+$/.test(v));
    dependency_age_percentile = Math.round((exactPins.length / depEntries.length) * 100);
  }

  // --- license_deprecated ---
  const licenseId = extractNpmLicense(meta, version);
  const license_deprecated = isLicenseDeprecated(licenseId);

  return {
    commit_velocity_90d,
    release_cadence_days,
    contributor_turnover,
    dependency_age_percentile,
    license_deprecated,
  };
}

// ---------------------------------------------------------------------------
// Signal extractor for PyPI
// ---------------------------------------------------------------------------

function extractPypiSignals(
  meta: PypiRegistryMetadata
): Omit<SupplyChainSignals, "circular_dep_count" | "orphaned_dep_count"> {
  const releases = meta.releases ?? {};

  // --- commit_velocity_90d ---
  // Approximate via uploads in last 90 days
  let commit_velocity_90d: number | undefined;
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;
  const recentUploads = Object.values(releases)
    .flat()
    .filter((f) => f.upload_time && new Date(f.upload_time).getTime() >= ninetyDaysAgo);
  commit_velocity_90d = recentUploads.length * 3; // same proxy as npm

  // --- release_cadence_days ---
  const allUploadTimes = Object.values(releases)
    .map((files) => files[0]?.upload_time)
    .filter((t): t is string => typeof t === "string");
  const release_cadence_days = computeReleaseCadence(allUploadTimes);

  // --- contributor_turnover ---
  // PyPI provides author/maintainer as strings — single maintainer = high risk
  const hasAuthor = !!meta.info.author?.trim();
  const hasMaintainer = !!meta.info.maintainer?.trim();
  let contributor_turnover: number | undefined;
  if (hasAuthor || hasMaintainer) {
    // If only one of them is set, treat as single-maintainer risk
    contributor_turnover = hasAuthor && hasMaintainer ? 0.4 : 0.9;
  }

  // --- dependency_age_percentile ---
  const requiresDist = meta.info.requires_dist ?? [];
  if (requiresDist.length > 0) {
    // Heuristic: packages with many unpinned extras tend to be older
    const hasVersionPins = requiresDist.filter((r) => /==/.test(r));
    dependency_age_percentile = Math.round((hasVersionPins.length / requiresDist.length) * 100);
  } else {
    var dependency_age_percentile: number | undefined = undefined;
  }

  // --- license_deprecated ---
  const license_deprecated = isLicenseDeprecated(meta.info.license);

  return {
    commit_velocity_90d,
    release_cadence_days,
    contributor_turnover,
    dependency_age_percentile,
    license_deprecated,
  };
}

// ---------------------------------------------------------------------------
// Structural risk extractor (works for both ecosystems)
// ---------------------------------------------------------------------------

function extractStructuralSignals(
  directDeps: string[],
  depGraph: Record<string, string[]>
): { circular_dep_count: number; orphaned_dep_count: number } {
  const circular_dep_count = detectCircularDeps(depGraph);
  const orphaned_dep_count = countOrphanedDeps(directDeps, depGraph);
  return { circular_dep_count, orphaned_dep_count };
}

// ---------------------------------------------------------------------------
// Scoring engine
// ---------------------------------------------------------------------------

function scoreSignals(signals: SupplyChainSignals): {
  findings: SupplyChainSignalFinding[];
  riskScore: number;
} {
  const findings: SupplyChainSignalFinding[] = [];
  let weightedScore = 0;

  // --- commit_velocity_90d ---
  if (signals.commit_velocity_90d !== undefined) {
    const severity = classifyNumeric(
      signals.commit_velocity_90d,
      THRESHOLDS.commit_velocity_90d,
      true
    );
    if (severity !== "info" || signals.commit_velocity_90d === 0) {
      findings.push({
        signal: "commit_velocity_90d",
        severity: signals.commit_velocity_90d === 0 ? "critical" : severity,
        observed: String(signals.commit_velocity_90d),
        threshold: `>${THRESHOLDS.commit_velocity_90d.low} commits/90d for healthy`,
        detail:
          signals.commit_velocity_90d === 0
            ? "No commits detected in the last 90 days — package may be abandoned."
            : `Only ${signals.commit_velocity_90d} commits in the last 90 days — low maintenance activity.`,
      });
      const s: SeverityLevel = signals.commit_velocity_90d === 0 ? "critical" : severity;
      weightedScore += SIGNAL_WEIGHTS.commit_velocity_90d * SEVERITY_SCORE[s];
    }
  }

  // --- release_cadence_days ---
  if (signals.release_cadence_days !== undefined) {
    const severity = classifyNumeric(
      signals.release_cadence_days,
      THRESHOLDS.release_cadence_days,
      false
    );
    if (severity !== "info") {
      findings.push({
        signal: "release_cadence_days",
        severity,
        observed: `${signals.release_cadence_days} days`,
        threshold: `<${THRESHOLDS.release_cadence_days.low} days between releases`,
        detail: `Average ${signals.release_cadence_days} days between releases — release cadence is ${severity === "critical" || severity === "high" ? "very" : ""} slow.`,
      });
      weightedScore += SIGNAL_WEIGHTS.release_cadence_days * SEVERITY_SCORE[severity];
    }
  }

  // --- contributor_turnover ---
  if (signals.contributor_turnover !== undefined) {
    const severity = classifyNumeric(
      signals.contributor_turnover,
      THRESHOLDS.contributor_turnover,
      false
    );
    if (severity !== "info") {
      const pct = Math.round(signals.contributor_turnover * 100);
      findings.push({
        signal: "contributor_turnover",
        severity,
        observed: `${pct}%`,
        threshold: `<${Math.round(THRESHOLDS.contributor_turnover.low * 100)}% turnover`,
        detail: `${pct}% contributor turnover — high bus-factor risk.`,
      });
      weightedScore += SIGNAL_WEIGHTS.contributor_turnover * SEVERITY_SCORE[severity];
    }
  }

  // --- dependency_age_percentile ---
  if (signals.dependency_age_percentile !== undefined) {
    const severity = classifyNumeric(
      signals.dependency_age_percentile,
      THRESHOLDS.dependency_age_percentile,
      false
    );
    if (severity !== "info") {
      findings.push({
        signal: "dependency_age_percentile",
        severity,
        observed: `p${signals.dependency_age_percentile}`,
        threshold: `<p${THRESHOLDS.dependency_age_percentile.low} dependency age`,
        detail: `Dependencies are at the ${signals.dependency_age_percentile}th percentile of age — unusually old transitive dependencies detected.`,
      });
      weightedScore += SIGNAL_WEIGHTS.dependency_age_percentile * SEVERITY_SCORE[severity];
    }
  }

  // --- circular_dep_count ---
  if (signals.circular_dep_count > 0) {
    const severity = classifyNumeric(
      signals.circular_dep_count,
      THRESHOLDS.circular_dep_count,
      false
    );
    const effectiveSeverity: SeverityLevel = severity === "info" ? "low" : severity;
    findings.push({
      signal: "circular_dep_count",
      severity: effectiveSeverity,
      observed: String(signals.circular_dep_count),
      threshold: `0 circular dependency pairs`,
      detail: `${signals.circular_dep_count} circular dependency pair${signals.circular_dep_count !== 1 ? "s" : ""} detected — may cause installation failures.`,
    });
    weightedScore += SIGNAL_WEIGHTS.circular_dep_count * SEVERITY_SCORE[effectiveSeverity];
  }

  // --- orphaned_dep_count ---
  if (signals.orphaned_dep_count > 0) {
    const severity = classifyNumeric(
      signals.orphaned_dep_count,
      THRESHOLDS.orphaned_dep_count,
      false
    );
    const effectiveSeverity: SeverityLevel = severity === "info" ? "low" : severity;
    findings.push({
      signal: "orphaned_dep_count",
      severity: effectiveSeverity,
      observed: String(signals.orphaned_dep_count),
      threshold: `0 orphaned dependencies`,
      detail: `${signals.orphaned_dep_count} orphaned (unreferenced) dependenc${signals.orphaned_dep_count !== 1 ? "ies" : "y"} detected — potential dead-weight or build artifact.`,
    });
    weightedScore += SIGNAL_WEIGHTS.orphaned_dep_count * SEVERITY_SCORE[effectiveSeverity];
  }

  // --- license_deprecated ---
  if (signals.license_deprecated) {
    findings.push({
      signal: "license_deprecated",
      severity: "high",
      observed: "deprecated/missing",
      threshold: "valid OSI-approved SPDX identifier",
      detail: "Package uses a deprecated, non-OSI-approved, or missing SPDX license identifier.",
    });
    weightedScore += SIGNAL_WEIGHTS.license_deprecated * SEVERITY_SCORE.high;
  }

  // Normalise to 0–100
  const maxPossibleScore = Object.values(SIGNAL_WEIGHTS).reduce((a, b) => a + b, 0);
  const riskScore = Math.min(100, Math.round((weightedScore / maxPossibleScore) * 100));

  return { findings, riskScore };
}

// ---------------------------------------------------------------------------
// RiskLevel bucketing
// ---------------------------------------------------------------------------

function riskScoreToLevel(score: number): RiskLevel {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  if (score > 0) return "low";
  return "none";
}

// ---------------------------------------------------------------------------
// Summary generator
// ---------------------------------------------------------------------------

function buildSummary(
  packageName: string,
  version: string,
  riskLevel: RiskLevel,
  findings: SupplyChainSignalFinding[]
): string {
  if (findings.length === 0) {
    return `${packageName}@${version} passes all supply-chain health checks — no maintenance or structural risks detected.`;
  }

  const criticalOrHigh = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  );
  if (criticalOrHigh.length > 0) {
    const topSignal = criticalOrHigh[0]!;
    return `${packageName}@${version} has ${riskLevel} supply-chain risk — primary concern: ${topSignal.detail}`;
  }

  return `${packageName}@${version} has ${riskLevel} supply-chain risk across ${findings.length} degraded signal${findings.length !== 1 ? "s" : ""}.`;
}

// ---------------------------------------------------------------------------
// Main analyzer class
// ---------------------------------------------------------------------------

/**
 * Analyzes supply-chain health for a single package version.
 *
 * Usage:
 *   const analyzer = new SupplyChainHealthAnalyzer();
 *   const result = analyzer.analyze({ ecosystem: "npm", data: npmMetadata }, "1.2.3");
 *   result.riskLevel // "none" | "low" | "medium" | "high" | "critical"
 */
export class SupplyChainHealthAnalyzer {
  /**
   * Analyze registry metadata and return a deterministic health result.
   *
   * @param registryMetadata - Parsed registry API response
   * @param version - The specific version string being evaluated
   * @param depGraph - Optional dependency graph for structural analysis.
   *   Keys are package names; values are their direct dependency names.
   * @param directDeps - Optional list of direct dependencies declared by the
   *   package itself (subset of depGraph keys).
   */
  analyze(
    registryMetadata: PackageRegistryMetadata,
    version: string,
    depGraph: Record<string, string[]> = {},
    directDeps: string[] = []
  ): SupplyChainHealthResult {
    // Extract maintenance signals
    let baseSignals: Omit<SupplyChainSignals, "circular_dep_count" | "orphaned_dep_count">;

    if (registryMetadata.ecosystem === "npm") {
      baseSignals = extractNpmSignals(registryMetadata.data, version);
    } else {
      baseSignals = extractPypiSignals(registryMetadata.data);
    }

    // Extract structural signals
    const structuralSignals = extractStructuralSignals(directDeps, depGraph);

    const signals: SupplyChainSignals = {
      ...baseSignals,
      ...structuralSignals,
    };

    const { findings, riskScore } = scoreSignals(signals);
    const riskLevel = riskScoreToLevel(riskScore);

    const packageName =
      registryMetadata.ecosystem === "npm"
        ? registryMetadata.data.name
        : registryMetadata.data.info.name;

    const summary = buildSummary(packageName, version, riskLevel, findings);

    return {
      packageName,
      version,
      ecosystem: registryMetadata.ecosystem,
      signals,
      findings,
      riskScore,
      riskLevel,
      summary,
      analyzedAt: new Date().toISOString(),
    };
  }

  /**
   * Convenience method: fetch npm registry metadata and analyze.
   * In test environments or when network is unavailable, callers should pass
   * pre-fetched metadata to `analyze()` directly.
   */
  static buildNpmMetadata(raw: NpmRegistryMetadata): PackageRegistryMetadata {
    return { ecosystem: "npm", data: raw };
  }

  static buildPypiMetadata(raw: PypiRegistryMetadata): PackageRegistryMetadata {
    return { ecosystem: "pypi", data: raw };
  }
}

// ---------------------------------------------------------------------------
// SupplyChainHealthFinding — entry in the threat taxonomy
// (mirrors the ScriptFinding shape used elsewhere in the codebase)
// ---------------------------------------------------------------------------

export interface SupplyChainHealthFinding {
  /** Which supply-chain signal triggered this finding. */
  signal: keyof SupplyChainSignals;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  /** Observed metric value. */
  observed: string;
  /** Healthy threshold for context. */
  threshold: string;
  recommendation: string;
}

/**
 * Convert a raw SupplyChainSignalFinding to the richer SupplyChainHealthFinding
 * shape used in the threat taxonomy.
 */
export function toHealthFinding(
  raw: SupplyChainSignalFinding
): SupplyChainHealthFinding {
  const titleMap: Record<keyof SupplyChainSignals, string> = {
    commit_velocity_90d: "Low commit velocity",
    release_cadence_days: "Slow release cadence",
    contributor_turnover: "High contributor turnover",
    dependency_age_percentile: "Outdated transitive dependencies",
    circular_dep_count: "Circular dependency detected",
    orphaned_dep_count: "Orphaned dependency detected",
    license_deprecated: "Deprecated or missing license",
  };

  const recommendationMap: Record<keyof SupplyChainSignals, string> = {
    commit_velocity_90d:
      "Evaluate whether the package is actively maintained; consider forks or alternatives.",
    release_cadence_days:
      "Check the project's issue tracker for signs of abandonment and consider alternative packages.",
    contributor_turnover:
      "Assess single-maintainer bus-factor risk and ensure a fork plan is in place.",
    dependency_age_percentile:
      "Audit transitive dependencies for known CVEs and outdated major versions.",
    circular_dep_count:
      "Report the circular dependency to the maintainer; avoid installing until resolved.",
    orphaned_dep_count:
      "Review whether orphaned dependencies can be removed to reduce the attack surface.",
    license_deprecated:
      "Contact the maintainer to update the license to a valid SPDX identifier before using in production.",
  };

  return {
    signal: raw.signal,
    severity: raw.severity,
    title: titleMap[raw.signal],
    description: raw.detail,
    observed: raw.observed,
    threshold: raw.threshold,
    recommendation: recommendationMap[raw.signal],
  };
}

// ---------------------------------------------------------------------------
// Re-export the behavior correlation engine so consumers can import from
// @binshield/supply-chain-health for both health analysis and pattern correlation.
// ---------------------------------------------------------------------------
export {
  ManifestBehaviorCorrelator,
  ATTACK_PROFILES,
  type AttackProfile,
  type BehaviorCorrelationResult,
  type CorrelatorInput,
} from "./manifest-correlator";

// ---------------------------------------------------------------------------
// Re-export named analyzer classes so consumers can use them individually.
// ---------------------------------------------------------------------------
export {
  CommitVelocityAnalyzer,
  ReleaseCadenceAnalyzer,
  ContributorTurnoverAnalyzer,
  DependencyAgeAnalyzer,
  CircularDepDetector,
  OrphanedDepDetector,
  ScoreAggregator,
  type CommitVelocityResult,
  type ReleaseCadenceResult,
  type ContributorTurnoverResult,
  type DependencyAgeResult,
  type CircularDepResult,
  type OrphanedDepResult,
  type AggregatedScore,
  type AggregatorSignals,
} from "./analyzers";
