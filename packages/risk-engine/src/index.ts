import type {
  BehaviorSummary,
  BinaryAnalysis,
  Finding,
  FindingSeverity,
  PackageAnalysis,
  RiskLevel
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

export function scoreFindings(findings: Finding[]): number {
  return findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
}

export function scoreBehaviors(behaviors: BehaviorSummary): number {
  return (Object.entries(behaviors) as [keyof BehaviorSummary, BehaviorSummary[keyof BehaviorSummary]][])
    .filter(([, signal]) => signal.detected)
    .reduce((total, [key, signal]) => total + behaviorWeight[key] + Math.min(signal.details.length, 3), 0);
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

export function scoreBinary(binary: Pick<BinaryAnalysis, "behaviors" | "findings" | "importCount" | "functionCount">) {
  const score = normalizeRisk(
    scoreFindings(binary.findings) +
      scoreBehaviors(binary.behaviors) +
      Math.min(binary.importCount / 4, 6) +
      Math.min(binary.functionCount / 20, 5)
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

export function summarizePackage(analysis: PackageAnalysis): string {
  const behaviors = new Set<string>();
  for (const binary of analysis.binaries) {
    for (const [name, signal] of Object.entries(binary.behaviors) as [keyof BehaviorSummary, BehaviorSummary[keyof BehaviorSummary]][]) {
      if (signal.detected) {
        behaviors.add(name);
      }
    }
  }

  const behaviorText = behaviors.size > 0 ? Array.from(behaviors).join(", ") : "no notable behaviors";
  return `${analysis.packageName}@${analysis.version} exposes ${behaviorText} with overall ${analysis.riskLevel} risk.`;
}
