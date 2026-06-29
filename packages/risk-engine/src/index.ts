import type {
  BehaviorSignal,
  BehaviorSummary,
  BinaryAnalysis,
  Finding,
  FindingSeverity,
  ManifestAnalysis,
  PackageAnalysis,
  RiskLevel,
  ScriptFinding,
  ScriptThreatSummary
} from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Vendor Patch Context — intelligent risk downgrade for patched CVEs
// ---------------------------------------------------------------------------

/**
 * Per-CVE vendor patch context.  When a patched version has been released the
 * risk engine applies a -15 pt penalty to the raw score because the attack
 * surface shrinks as soon as the fix is deployed.
 *
 * daysToFix  – calendar days from CVE disclosure to patch release (0 = same-day).
 * vendorConfidence – how confident we are in the patch data:
 *   "high"   = authoritative vendor advisory (GHSA, NVD confirmed patched)
 *   "medium" = OSV-derived, may be inaccurate for multi-range vulnerabilities
 *   "low"    = inferred or community-reported, treat as provisional
 */
export interface VendorPatchContext {
  cveId: string;
  patchedVersion: string;
  daysToFix: number;
  vendorConfidence: "high" | "medium" | "low";
}

/**
 * Lockfile resolution context.
 *
 * Carries the package version that the lockfile currently pins alongside
 * whatever patched version is available.  The risk engine uses this to decide
 * whether to emit a "Patchable vulnerability" finding instead of a raw
 * CRITICAL/HIGH severity.
 */
export interface LockfileResolutionContext {
  /** The version string that appears in the lockfile today. */
  resolvedVersion: string;
  /** The earliest version that fully remediates the vulnerability. */
  patchedVersion: string;
  /** CVE ID this context belongs to. */
  cveId: string;
  /**
   * True when `resolvedVersion` is still in the vulnerable range and
   * `patchedVersion` is available but has not been pinned in the lockfile.
   */
  isUnpatched: boolean;
}

/**
 * Patch deployment correlation context.
 *
 * Links the patch availability date to ecosystem-wide adoption telemetry.
 * A patch released 90 days ago with < 5 % adoption is treated differently
 * from one released yesterday.
 */
export interface PatchDeploymentContext {
  cveId: string;
  /** ISO date when the patch was first published. */
  patchPublishedAt: string;
  /** Number of calendar days since the patch was published (computed by caller). */
  daysSincePatch: number;
  /**
   * Fraction [0, 1] of the ecosystem that has adopted the patched version,
   * e.g. 0.05 = 5 %.  undefined = unknown / not enough telemetry.
   */
  ecosystemAdoptionRate?: number;
}

// ---------------------------------------------------------------------------
// Patch penalty / adjustment helpers
// ---------------------------------------------------------------------------

/**
 * Compute the vendor-patch risk penalty.
 *
 * Returns a *negative* number (penalty) to be subtracted from the raw score:
 *   - Patch exists, high confidence → -15 pts
 *   - Patch exists, medium confidence → -10 pts
 *   - Patch exists, low confidence  →  -5 pts
 *   - No patch context              →   0 pts
 */
export function vendorPatchPenalty(patches?: VendorPatchContext[]): number {
  if (!patches || patches.length === 0) return 0;

  // Use the best-confidence patch signal available
  const best = patches.reduce<VendorPatchContext | undefined>((acc, p) => {
    if (!acc) return p;
    const rank = { high: 3, medium: 2, low: 1 } as const;
    return rank[p.vendorConfidence] > rank[acc.vendorConfidence] ? p : acc;
  }, undefined);

  if (!best) return 0;

  switch (best.vendorConfidence) {
    case "high":
      return -15;
    case "medium":
      return -10;
    case "low":
      return -5;
  }
}

/**
 * Build a MEDIUM "Patchable-Vulnerability" finding for each lockfile entry
 * where a patch is available but the lockfile has not been updated.
 *
 * The generated findings are MEDIUM rather than the raw CVE severity because
 * the existence of a patch substantially reduces risk compared to an
 * unmitigated vulnerability.
 */
export function buildLockfilePatchableFindings(resolutions?: LockfileResolutionContext[]): Finding[] {
  if (!resolutions || resolutions.length === 0) return [];

  return resolutions
    .filter((r) => r.isUnpatched)
    .map((r) => ({
      severity: "medium" as FindingSeverity,
      title: `Patchable vulnerability: ${r.cveId}`,
      description:
        `Your lockfile resolves to version ${r.resolvedVersion} which is still vulnerable to ${r.cveId}. ` +
        `A patched version (${r.patchedVersion}) is available but has not been applied.`,
      recommendation:
        `Update your lockfile to resolve ${r.cveId.split("-")[0]}/${r.cveId.split("-").slice(1).join("-")} ` +
        `to ${r.patchedVersion} or later and re-lock dependencies.`
    }));
}

/**
 * Compute a patch-deployment urgency modifier [-10, 0].
 *
 * When a patch has been available for a long time but ecosystem adoption
 * remains very low, the vulnerability is still practically exploitable —
 * return 0 (no downgrade).  When the patch is mature and widely adopted,
 * apply an additional -10 to further de-prioritise the finding.
 *
 * Urgency modifiers (applied on top of vendorPatchPenalty):
 *   daysSincePatch < 7                    → 0  (too new to judge)
 *   daysSincePatch >= 7, adoption < 5 %   → 0  (patch exists but not adopted)
 *   daysSincePatch >= 30, adoption >= 25 %→ -5  (gaining traction)
 *   daysSincePatch >= 90, adoption >= 50 %→ -10 (widely deployed)
 */
export function patchDeploymentModifier(deployment?: PatchDeploymentContext): number {
  if (!deployment) return 0;
  const { daysSincePatch, ecosystemAdoptionRate } = deployment;

  if (daysSincePatch < 7) return 0;
  if (ecosystemAdoptionRate == null || ecosystemAdoptionRate < 0.05) return 0;
  if (daysSincePatch >= 90 && ecosystemAdoptionRate >= 0.5) return -10;
  if (daysSincePatch >= 30 && ecosystemAdoptionRate >= 0.25) return -5;
  return 0;
}

const severityWeight: Record<FindingSeverity, number> = {
  info: 2,
  low: 8,
  medium: 18,
  high: 30,
  critical: 45
};

const behaviorWeight: Record<keyof BehaviorSummary, number> = {
  network: 14,
  filesystem: 4,
  process: 12,
  crypto: 3,
  obfuscation: 24,
  dataExfiltration: 28
};

/**
 * Install-script threat weights. Heavier than binary behaviors because
 * install-time RCE / credential theft is the npm/PyPI worm vector — a
 * malicious postinstall hook is strictly worse than, say, a binary that
 * merely touches the filesystem.
 */
const scriptThreatWeight: Record<keyof ScriptThreatSummary, number> = {
  installHook: 6,
  scriptInjection: 24,
  environmentTheft: 34,
  dependencyConfusion: 20,
  wiper: 40,
  reverseShell: 40,
  remoteCodeExecution: 38
};

export function scoreFindings(findings: Finding[]): number {
  return findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
}

export function scoreScriptFindings(findings: ScriptFinding[]): number {
  return findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
}

export function scoreBehaviors(behaviors: BehaviorSummary): number {
  return (Object.entries(behaviors) as [keyof BehaviorSummary, BehaviorSignal][])
    .filter(([, signal]) => signal.detected)
    .reduce((total, [key, signal]) => total + behaviorWeight[key] + Math.min(signal.details.length, 3), 0);
}

export function scoreScriptThreats(threats: ScriptThreatSummary): number {
  return (Object.entries(threats) as [keyof ScriptThreatSummary, BehaviorSignal][])
    .filter(([, signal]) => signal.detected)
    .reduce((total, [key, signal]) => total + scriptThreatWeight[key] + Math.min(signal.details.length, 3), 0);
}

export function normalizeRisk(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 80) {
    return "critical";
  }
  if (score >= 60) {
    return "high";
  }
  if (score >= 30) {
    return "medium";
  }
  if (score > 0) {
    return "low";
  }
  return "none";
}

/**
 * Optional EPSS context passed to scoreBinary / scoreManifest.
 * When epssPercentile > 0.75 the engine boosts the risk score by 15–25 pts
 * to reflect active real-world exploitation rather than theoretical severity.
 *
 * epssPercentile > 0.90 → +25 pt boost ("Exploited in the Wild")
 * epssPercentile > 0.75 → +15 pt boost ("High real-world exploit activity")
 */
export interface EpssContext {
  /** Highest EPSS percentile among all CVEs affecting this package/version [0,1] */
  maxEpssPercentile: number;
}

/**
 * CISA KEV (Known Exploited Vulnerabilities) context.
 *
 * When a package has at least one CVE confirmed by CISA as actively exploited
 * in the wild the risk engine applies a +20 pt boost and emits a dedicated
 * "CVE-Actively-Exploited-In-Wild" CRITICAL finding.
 */
export type ExploitMaturity = "proof-of-concept" | "active-exploitation" | "widespread";

export interface CisaKevContext {
  /**
   * CVE IDs that appear in the CISA KEV catalogue for this package/version,
   * keyed by CVE ID with their maturity score.
   */
  kevMatches: Array<{
    cveId: string;
    firstSeenDate: string; // ISO date, e.g. "2024-03-15"
    exploitMaturity: ExploitMaturity;
  }>;
}

/**
 * Compute the CISA KEV risk boost (0 or 20 pts).
 *
 * Returns 20 when at least one matched CVE has exploit_maturity_score of
 * 'active-exploitation' or 'widespread'. Returns 0 otherwise (includes
 * 'proof-of-concept' and no matches).
 */
export function cisaKevBoost(kev?: CisaKevContext): number {
  if (!kev || kev.kevMatches.length === 0) return 0;
  const hasActive = kev.kevMatches.some(
    (m) => m.exploitMaturity === "active-exploitation" || m.exploitMaturity === "widespread"
  );
  return hasActive ? 20 : 0;
}

/**
 * Build a CRITICAL "CVE-Actively-Exploited-In-Wild" finding for each
 * active-exploitation or widespread KEV match. These findings are injected
 * into the package-level result so they surface in reports and gate checks.
 */
export function buildCisaKevFindings(kev?: CisaKevContext): Finding[] {
  if (!kev || kev.kevMatches.length === 0) return [];

  return kev.kevMatches
    .filter((m) => m.exploitMaturity === "active-exploitation" || m.exploitMaturity === "widespread")
    .map((m) => ({
      severity: "critical" as FindingSeverity,
      title: `CVE-Actively-Exploited-In-Wild: ${m.cveId}`,
      description:
        `${m.cveId} has been confirmed by CISA as actively exploited in the wild ` +
        `(maturity: ${m.exploitMaturity}, CISA KEV date: ${m.firstSeenDate}). ` +
        `Immediate remediation is strongly advised.`,
      recommendation:
        "Upgrade or replace this package immediately. Monitor CISA KEV for patch guidance."
    }));
}

/**
 * Compute the EPSS risk boost (0 | 15 | 25) for a given EPSS context.
 * Returns 0 when no context is provided or percentile is below threshold.
 */
export function epssBoost(epss?: EpssContext): number {
  if (!epss) return 0;
  if (epss.maxEpssPercentile > 0.9) return 25;
  if (epss.maxEpssPercentile > 0.75) return 15;
  return 0;
}

/**
 * Optional behavior-correlation context passed to scoreBinary.
 *
 * When the behavior-correlation analyzer detects a coordinated attack profile
 * (e.g. Injection+Spawn, Exfil+C2, Persistence+Wiper, CryptoStealing) the
 * risk engine applies a flat +10 pt boost to reflect the elevated threat level
 * of multi-technique coordinated attacks versus single-signal detections.
 */
export interface BehaviorCorrelationContext {
  /** True when at least one coordinated attack profile fired with confidence > 0.7. */
  correlatedProfileDetected: boolean;
}

/**
 * Compute the behavior-correlation risk boost (0 or 10).
 * Returns 10 when a coordinated attack profile was detected, 0 otherwise.
 */
export function behaviorCorrelationBoost(correlation?: BehaviorCorrelationContext): number {
  return correlation?.correlatedProfileDetected ? 10 : 0;
}

export function scoreBinary(
  binary: Pick<BinaryAnalysis, "behaviors" | "findings" | "importCount" | "functionCount">,
  epss?: EpssContext,
  kev?: CisaKevContext,
  correlation?: BehaviorCorrelationContext,
  patches?: VendorPatchContext[],
  deployment?: PatchDeploymentContext
) {
  const baseScore =
    scoreFindings(binary.findings) +
    scoreBehaviors(binary.behaviors) +
    Math.min(binary.importCount / 4, 6) +
    Math.min(binary.functionCount / 20, 5);

  const score = normalizeRisk(
    baseScore +
    epssBoost(epss) +
    cisaKevBoost(kev) +
    behaviorCorrelationBoost(correlation) +
    vendorPatchPenalty(patches) +
    patchDeploymentModifier(deployment)
  );

  return {
    riskScore: score,
    riskLevel: riskLevelFromScore(score)
  };
}

/**
 * Score a manifest / install-script analysis. A confirmed known-malware match
 * forces a maximum-severity verdict — a package on a malware advisory must
 * never score "low" just because its visible script happened to look benign.
 *
 * Optional EPSS context boosts the score when the package's CVEs have a high
 * real-world exploit probability (epssPercentile > 0.75 → +15 pts,
 * epssPercentile > 0.90 → +25 pts).
 */
export function scoreManifest(
  manifest: ManifestAnalysis,
  epss?: EpssContext,
  kev?: CisaKevContext,
  patches?: VendorPatchContext[],
  deployment?: PatchDeploymentContext
): { riskScore: number; riskLevel: RiskLevel } {
  if (manifest.knownMalwareAdvisoryIds.length > 0) {
    return { riskScore: 100, riskLevel: "critical" };
  }

  const score = normalizeRisk(
    scoreScriptFindings(manifest.findings) +
    scoreScriptThreats(manifest.threats) +
    epssBoost(epss) +
    cisaKevBoost(kev) +
    vendorPatchPenalty(patches) +
    patchDeploymentModifier(deployment)
  );
  return {
    riskScore: score,
    riskLevel: riskLevelFromScore(score)
  };
}

export function aggregatePackageRisk(binaries: BinaryAnalysis[]) {
  if (binaries.length === 0) {
    return {
      riskScore: 0,
      riskLevel: "none" as RiskLevel
    };
  }

  const maxBinary = Math.max(...binaries.map((binary) => binary.riskScore));
  const averageBinary = binaries.reduce((total, binary) => total + binary.riskScore, 0) / binaries.length;
  const aggregate = normalizeRisk(maxBinary * 0.65 + averageBinary * 0.35);

  return {
    riskScore: aggregate,
    riskLevel: riskLevelFromScore(aggregate)
  };
}

/**
 * Overall package risk combining native-binary analysis with install-script
 * analysis. Uses `max` (not an average) so a clean set of binaries cannot
 * dilute a malicious install script — and vice versa. This is the change that
 * lets a no-binary supply-chain worm score above "none".
 */
export function aggregatePackageRiskWithManifest(
  binaries: BinaryAnalysis[],
  manifest?: ManifestAnalysis
): { riskScore: number; riskLevel: RiskLevel } {
  const binaryAggregate = aggregatePackageRisk(binaries);
  if (!manifest) {
    return binaryAggregate;
  }

  if (manifest.knownMalwareAdvisoryIds.length > 0) {
    return { riskScore: 100, riskLevel: "critical" };
  }

  const manifestScore = scoreManifest(manifest);
  const score = Math.max(binaryAggregate.riskScore, manifestScore.riskScore);
  return {
    riskScore: score,
    riskLevel: riskLevelFromScore(score)
  };
}

export function summarizePackage(analysis: PackageAnalysis): string {
  const behaviors = new Set<string>();
  for (const binary of analysis.binaries) {
    for (const [name, signal] of Object.entries(binary.behaviors) as [keyof BehaviorSummary, BehaviorSignal][]) {
      if (signal.detected) {
        behaviors.add(name);
      }
    }
  }

  if (analysis.manifestAnalysis) {
    for (const [name, signal] of Object.entries(analysis.manifestAnalysis.threats) as [
      keyof ScriptThreatSummary,
      BehaviorSignal
    ][]) {
      if (signal.detected) {
        behaviors.add(name);
      }
    }
  }

  const behaviorText = behaviors.size > 0 ? Array.from(behaviors).join(", ") : "no notable behaviors";
  return `${analysis.packageName}@${analysis.version} exposes ${behaviorText} with overall ${analysis.riskLevel} risk.`;
}
