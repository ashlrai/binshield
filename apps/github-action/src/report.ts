import type { PackageAnalysis, RiskLevel } from "@binshield/analysis-types";

import type { CommentMode, ScanOutcome } from "./types";

const thresholdOrder: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

export function shouldFail(level: RiskLevel, threshold: RiskLevel | "never") {
  if (threshold === "never") {
    return false;
  }

  return thresholdOrder.indexOf(level) >= thresholdOrder.indexOf(threshold);
}

export function renderComment(outcomes: ScanOutcome[]) {
  const rows = outcomes
    .map((outcome) => {
      if (outcome.error) {
        return `| ${outcome.target.name}@${outcome.target.version} | ${outcome.target.path} | ERROR | ${outcome.error} |`;
      }

      const analysis = outcome.analysis as PackageAnalysis;
      return `| ${analysis.packageName}@${analysis.version} | ${outcome.target.path} | ${analysis.riskLevel.toUpperCase()} (${analysis.riskScore}) | ${analysis.summary} |`;
    })
    .join("\n");

  return `## BinShield - Binary Dependency Scan

**${outcomes.length} package analyses completed**

  | Package | Path | Risk | Summary |
  |---------|------|------|---------|
  ${rows}
  `;
}

export function summarize(outcomes: ScanOutcome[]) {
  const successful = outcomes.filter((outcome) => outcome.analysis);
  const failures = outcomes.filter((outcome) => outcome.error);
  const highest = successful.reduce<RiskLevel>((current, outcome) => {
    const next = outcome.analysis?.riskLevel ?? "none";
    return thresholdOrder.indexOf(next) > thresholdOrder.indexOf(current) ? next : current;
  }, "none");

  return {
    successful: successful.length,
    failures: failures.length,
    highest
  };
}

export function shouldPublishComment(commentMode: CommentMode) {
  return commentMode === "pr-comment" || commentMode === "both";
}

export function shouldPublishSummary(commentMode: CommentMode) {
  return commentMode === "summary" || commentMode === "both";
}
