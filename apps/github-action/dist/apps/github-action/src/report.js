const thresholdOrder = ["none", "low", "medium", "high", "critical"];
const severityOrder = ["critical", "high", "medium", "low", "info"];
export function shouldFail(level, threshold) {
    if (threshold === "never") {
        return false;
    }
    return thresholdOrder.indexOf(level) >= thresholdOrder.indexOf(threshold);
}
function formatTarget(target) {
    return `${target.name}@${target.version}`;
}
function collectBehaviors(analysis) {
    const behaviors = new Set();
    for (const binary of analysis.binaries) {
        for (const [name, signal] of Object.entries(binary.behaviors)) {
            if (signal.detected) {
                behaviors.add(name);
            }
        }
    }
    return Array.from(behaviors);
}
function collectFindings(analysis) {
    const findings = analysis.binaries.flatMap((binary) => binary.findings.map((finding) => ({
        ...finding,
        binary: binary.filename
    })));
    return findings.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
}
function buildEvidenceCue(analysis) {
    const behaviors = collectBehaviors(analysis);
    const findings = collectFindings(analysis);
    const binaryNames = analysis.binaries.map((binary) => binary.filename);
    const topFinding = findings[0];
    const parts = [
        `${analysis.binaryCount} binaries`,
        behaviors.length ? `behaviors: ${behaviors.slice(0, 3).join(", ")}` : "no behavior families detected",
        binaryNames.length ? `artifacts: ${binaryNames.slice(0, 2).join(", ")}` : "no native artifacts recovered"
    ];
    if (topFinding) {
        parts.push(`top finding: ${topFinding.severity.toUpperCase()} in ${topFinding.binary}`);
    }
    return parts.join(" | ");
}
function buildGuidance(analysis) {
    const findings = collectFindings(analysis);
    const topFinding = findings[0];
    if (topFinding?.recommendation) {
        return topFinding.recommendation;
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
function buildPackageLine(outcome) {
    if (outcome.error) {
        return {
            packageLabel: formatTarget(outcome.target),
            riskLabel: "ERROR",
            evidence: "scan failed before analysis completed",
            guidance: "Check the BinShield API, worker health, auth token, and workflow connectivity.",
            path: outcome.target.path
        };
    }
    const analysis = outcome.analysis;
    return {
        packageLabel: formatTarget(outcome.target),
        riskLabel: `${analysis.riskLevel.toUpperCase()} (${analysis.riskScore})`,
        evidence: buildEvidenceCue(analysis),
        guidance: buildGuidance(analysis),
        path: outcome.target.path
    };
}
export function renderComment(outcomes) {
    const successful = outcomes.filter((outcome) => outcome.analysis);
    const failures = outcomes.filter((outcome) => outcome.error);
    const highest = successful.reduce((current, outcome) => {
        const next = outcome.analysis?.riskLevel ?? "none";
        return thresholdOrder.indexOf(next) > thresholdOrder.indexOf(current) ? next : current;
    }, "none");
    const rows = outcomes.map((outcome) => buildPackageLine(outcome));
    const riskyRows = rows.filter((row) => row.riskLabel.startsWith("HIGH") || row.riskLabel.startsWith("CRITICAL") || row.riskLabel === "ERROR");
    const rowText = rows
        .map((row) => `| ${row.packageLabel} | ${row.path} | ${row.riskLabel} | ${row.evidence} | ${row.guidance} |`)
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
export function buildFailureMessage(outcomes, threshold) {
    const messages = [];
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
export function summarize(outcomes) {
    const successful = outcomes.filter((outcome) => outcome.analysis);
    const failures = outcomes.filter((outcome) => outcome.error);
    const highest = successful.reduce((current, outcome) => {
        const next = outcome.analysis?.riskLevel ?? "none";
        return thresholdOrder.indexOf(next) > thresholdOrder.indexOf(current) ? next : current;
    }, "none");
    return {
        successful: successful.length,
        failures: failures.length,
        highest
    };
}
export function shouldPublishComment(commentMode) {
    return commentMode === "pr-comment" || commentMode === "both";
}
export function shouldPublishSummary(commentMode) {
    return commentMode === "summary" || commentMode === "both";
}
