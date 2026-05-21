import type { PackageAnalysis, RiskLevel } from "@binshield/analysis-types";

import type { CommentMode, ScanOutcome } from "./types";

const thresholdOrder: RiskLevel[] = ["none", "low", "medium", "high", "critical"];
const severityOrder: Array<"critical" | "high" | "medium" | "low" | "info"> = ["critical", "high", "medium", "low", "info"];

export function shouldFail(level: RiskLevel, threshold: RiskLevel | "never") {
  if (threshold === "never") {
    return false;
  }

  return thresholdOrder.indexOf(level) >= thresholdOrder.indexOf(threshold);
}

function formatTarget(target: ScanOutcome["target"]) {
  return `${target.name}@${target.version}`;
}

function collectBehaviors(analysis: PackageAnalysis) {
  const behaviors = new Set<string>();

  for (const binary of analysis.binaries) {
    for (const [name, signal] of Object.entries(binary.behaviors)) {
      if (signal.detected) {
        behaviors.add(name);
      }
    }
  }

  return Array.from(behaviors);
}

function collectFindings(analysis: PackageAnalysis) {
  const findings = analysis.binaries.flatMap((binary) =>
    binary.findings.map((finding) => ({
      ...finding,
      binary: binary.filename
    }))
  );

  return findings.sort((a, b) => severityOrder.indexOf(a.severity as (typeof severityOrder)[number]) - severityOrder.indexOf(b.severity as (typeof severityOrder)[number]));
}

/** Install-script / manifest findings, highest severity first. */
function collectScriptFindings(analysis: PackageAnalysis) {
  const findings = analysis.manifestAnalysis?.findings ?? [];
  return [...findings].sort(
    (a, b) =>
      severityOrder.indexOf(a.severity as (typeof severityOrder)[number]) -
      severityOrder.indexOf(b.severity as (typeof severityOrder)[number])
  );
}

function buildEvidenceCue(analysis: PackageAnalysis) {
  const behaviors = collectBehaviors(analysis);
  const findings = collectFindings(analysis);
  const scriptFindings = collectScriptFindings(analysis);
  const binaryNames = analysis.binaries.map((binary) => binary.filename);
  const topFinding = findings[0];
  const topScript = scriptFindings[0];

  const parts = [
    `${analysis.binaryCount} binaries`,
    behaviors.length ? `behaviors: ${behaviors.slice(0, 3).join(", ")}` : "no behavior families detected",
    binaryNames.length ? `artifacts: ${binaryNames.slice(0, 2).join(", ")}` : "no native artifacts recovered"
  ];

  if (analysis.manifestAnalysis?.hasInstallScripts) {
    parts.push("runs install scripts");
  }
  if (topScript) {
    parts.push(`install-script threat: ${topScript.severity.toUpperCase()} ${topScript.category}`);
  }
  if (topFinding) {
    parts.push(`top binary finding: ${topFinding.severity.toUpperCase()} in ${topFinding.binary}`);
  }

  return parts.join(" | ");
}

function buildGuidance(analysis: PackageAnalysis) {
  const findings = collectFindings(analysis);
  const scriptFindings = collectScriptFindings(analysis);
  const topScript = scriptFindings[0];
  const topFinding = findings[0];

  // Install-script threats are install-time RCE — surface their guidance first.
  if (topScript && (topScript.severity === "critical" || topScript.severity === "high")) {
    return topScript.recommendation;
  }

  if (topFinding?.recommendation) {
    return topFinding.recommendation;
  }

  if (topScript?.recommendation) {
    return topScript.recommendation;
  }

  switch (analysis.riskLevel) {
    case "critical":
    case "high":
      return "Block the merge until the binary evidence is reviewed and the behavior is explained.";
    case "medium":
      return "Review the binary evidence before merging and confirm the behavior is expected.";
    case "low":
      return "No immediate action required, but keep the package on watch if it is sensitive.";
    default:
      return "No action required.";
  }
}

function buildPackageLine(outcome: ScanOutcome) {
  if (outcome.error) {
    return {
      packageLabel: formatTarget(outcome.target),
      riskLabel: "ERROR",
      evidence: "scan failed before analysis completed",
      guidance: "Check the BinShield API, worker health, auth token, and workflow connectivity.",
      path: outcome.target.path
    };
  }

  const analysis = outcome.analysis as PackageAnalysis;
  return {
    packageLabel: formatTarget(outcome.target),
    riskLabel: `${analysis.riskLevel.toUpperCase()} (${analysis.riskScore})`,
    evidence: buildEvidenceCue(analysis),
    guidance: buildGuidance(analysis),
    path: outcome.target.path
  };
}

export function renderComment(outcomes: ScanOutcome[]) {
  const successful = outcomes.filter((outcome) => outcome.analysis);
  const failures = outcomes.filter((outcome) => outcome.error);
  const highest = successful.reduce<RiskLevel>((current, outcome) => {
    const next = outcome.analysis?.riskLevel ?? "none";
    return thresholdOrder.indexOf(next) > thresholdOrder.indexOf(current) ? next : current;
  }, "none");

  const rows = outcomes.map((outcome) => buildPackageLine(outcome));
  const riskyRows = rows.filter((row) => row.riskLabel.startsWith("HIGH") || row.riskLabel.startsWith("CRITICAL") || row.riskLabel === "ERROR");

  const rowText = rows
    .map(
      (row) => `| ${row.packageLabel} | ${row.path} | ${row.riskLabel} | ${row.evidence} | ${row.guidance} |`
    )
    .join("\n");

  return `## BinShield - Binary Dependency Scan

Scanned **${outcomes.length}** targets: **${successful.length}** analyzed, **${failures.length}** failed.
Highest observed risk: **${highest.toUpperCase()}**.

### Results

| Package | Path | Risk | Evidence cues | Guidance |
|---------|------|------|---------------|----------|
${rowText}

### What to review

${riskyRows.length ? riskyRows.map((row) => `- ${row.packageLabel}: ${row.evidence}. ${row.guidance}`).join("\n") : "- No high-risk binaries surfaced. Review only if your change set is sensitive or touches security-critical code."}

### Remediation

${riskyRows.length ? riskyRows.map((row) => `- ${row.packageLabel}: ${row.guidance}`).join("\n") : "- No immediate remediation required."}

### Failure handling

${failures.length ? "- One or more targets failed to scan. Check the API, worker health, and token permissions before merging." : "- No scan failures detected."}
`;
}

export function buildFailureMessage(outcomes: ScanOutcome[], threshold: RiskLevel | "never") {
  const messages: string[] = [];

  for (const outcome of outcomes) {
    if (outcome.error) {
      messages.push(`${formatTarget(outcome.target)} failed to scan: ${outcome.error}`);
      continue;
    }

    if (outcome.analysis && shouldFail(outcome.analysis.riskLevel, threshold)) {
      const analysis = outcome.analysis;
      const guidance = buildGuidance(analysis);
      messages.push(`${formatTarget(outcome.target)} exceeded the ${threshold} threshold with ${analysis.riskLevel.toUpperCase()} (${analysis.riskScore}). ${guidance}`);
    }
  }

  return messages.length ? messages.join(" ") : null;
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
