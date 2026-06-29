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

export function scoreBinary(
  binary: Pick<BinaryAnalysis, "behaviors" | "findings" | "importCount" | "functionCount">,
  epss?: EpssContext,
  kev?: CisaKevContext
) {
  const baseScore =
    scoreFindings(binary.findings) +
    scoreBehaviors(binary.behaviors) +
    Math.min(binary.importCount / 4, 6) +
    Math.min(binary.functionCount / 20, 5);

  const score = normalizeRisk(baseScore + epssBoost(epss) + cisaKevBoost(kev));

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
  kev?: CisaKevContext
): { riskScore: number; riskLevel: RiskLevel } {
  if (manifest.knownMalwareAdvisoryIds.length > 0) {
    return { riskScore: 100, riskLevel: "critical" };
  }

  const score = normalizeRisk(
    scoreScriptFindings(manifest.findings) +
    scoreScriptThreats(manifest.threats) +
    epssBoost(epss) +
    cisaKevBoost(kev)
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
