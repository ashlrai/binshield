// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------
function severityToLevel(severity) {
    switch (severity) {
        case "critical":
        case "high":
            return "error";
        case "medium":
            return "warning";
        case "low":
        case "info":
        default:
            return "note";
    }
}
// ---------------------------------------------------------------------------
// Rule ID derivation
// A stable, slug-safe identifier built from category + title.
// ---------------------------------------------------------------------------
function toRuleId(prefix, title) {
    const slug = title
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "");
    return `binshield/${prefix}/${slug}`;
}
// ---------------------------------------------------------------------------
// Artifact URI helpers
// Package content is not source code, so we use a package-uri convention that
// GitHub's code-scanning UI will show as a meaningful artifact path.
// ---------------------------------------------------------------------------
function packageUri(packageName, version, binaryFilename) {
    const base = `pkg:npm/${encodeURIComponent(packageName)}@${encodeURIComponent(version)}`;
    return binaryFilename ? `${base}#${binaryFilename}` : base;
}
// ---------------------------------------------------------------------------
// buildSarif
// ---------------------------------------------------------------------------
export function buildSarif(outcomes) {
    const results = [];
    // Rule map keyed by ruleId — collects distinct rules from all findings.
    const rulesMap = new Map();
    function upsertRule(ruleId, title, description, level) {
        if (!rulesMap.has(ruleId)) {
            rulesMap.set(ruleId, {
                id: ruleId,
                name: title,
                shortDescription: { text: title },
                defaultConfiguration: { level },
                helpUri: "https://binshield.dev/docs/findings",
                help: { text: description }
            });
        }
    }
    for (const outcome of outcomes) {
        if (!outcome.analysis) {
            continue;
        }
        const { packageName, version, binaries, manifestAnalysis } = outcome.analysis;
        // Binary findings — one SARIF result per Finding per binary.
        for (const binary of binaries) {
            for (const finding of binary.findings) {
                const ruleId = toRuleId("binary", finding.title);
                const level = severityToLevel(finding.severity);
                upsertRule(ruleId, finding.title, finding.description, level);
                const messageText = [
                    finding.description,
                    finding.recommendation ? `Recommendation: ${finding.recommendation}` : ""
                ]
                    .filter(Boolean)
                    .join(" ");
                results.push({
                    ruleId,
                    level,
                    message: { text: messageText },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: packageUri(packageName, version, binary.filename)
                                }
                            },
                            logicalLocations: [
                                {
                                    name: `${packageName}@${version}/${binary.filename}`,
                                    kind: "module"
                                }
                            ]
                        }
                    ]
                });
            }
        }
        // Install-script findings — one SARIF result per ScriptFinding.
        const scriptFindings = manifestAnalysis?.findings ?? [];
        for (const finding of scriptFindings) {
            const ruleId = toRuleId("script", finding.title);
            const level = severityToLevel(finding.severity);
            upsertRule(ruleId, finding.title, finding.description, level);
            const messageText = [
                finding.description,
                finding.evidence ? `Evidence: ${finding.evidence}` : "",
                finding.recommendation ? `Recommendation: ${finding.recommendation}` : ""
            ]
                .filter(Boolean)
                .join(" ");
            // filePath may be something like "package.json#scripts.postinstall"
            const artifactUri = finding.filePath.startsWith("pkg:")
                ? finding.filePath
                : packageUri(packageName, version, finding.filePath);
            results.push({
                ruleId,
                level,
                message: { text: messageText },
                locations: [
                    {
                        physicalLocation: {
                            artifactLocation: {
                                uri: artifactUri
                            }
                        },
                        logicalLocations: [
                            {
                                name: `${packageName}@${version}/${finding.filePath}`,
                                kind: "module"
                            }
                        ]
                    }
                ]
            });
        }
    }
    return {
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "BinShield",
                        version: "1.0.0",
                        informationUri: "https://binshield.dev",
                        rules: Array.from(rulesMap.values())
                    }
                },
                results
            }
        ]
    };
}
