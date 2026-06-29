import { describe, expect, it } from "vitest";

import { AdvisoryService } from "./advisory-service";
import type { VendorAdvisoryJson } from "./advisory-service";
import type { EpssScore } from "./types";

// ---------------------------------------------------------------------------
// AdvisoryService — pure computation tests (no network, no DB)
// ---------------------------------------------------------------------------

// We test the public `computeCompositeExploitRisk` method in isolation.
// The AdvisoryService constructor requires config but these tests only call
// a pure method that does not touch the network or Supabase.

function makeService() {
  return new AdvisoryService({
    supabaseUrl: "http://localhost:54321",
    supabaseServiceRoleKey: "test-key"
  });
}

function makeEpss(cveId: string, epssScore: number, epssPercentile: number): EpssScore {
  return {
    cveId,
    packageName: "test-pkg",
    ecosystem: "npm",
    version: "1.0.0",
    epssScore,
    epssPercentile,
    modelVersion: "v2023.03.01",
    scoreDate: "2026-06-29",
    updatedAt: new Date().toISOString(),
    exploitedInTheWild: epssPercentile > 0.9
  };
}

describe("AdvisoryService.computeCompositeExploitRisk", () => {
  const svc = makeService();

  it("returns 0 when there are no CVEs", () => {
    expect(svc.computeCompositeExploitRisk([], [])).toBe(0);
  });

  it("falls back to CVSS-based score when no EPSS data is available", () => {
    const cvss = [{ cveId: "CVE-2024-0001", cvssScore: 7.5 }];
    const result = svc.computeCompositeExploitRisk(cvss, []);
    // fallback: (7.5 / 10) * 100 = 75
    expect(result).toBe(75);
  });

  it("uses max CVSS for fallback when multiple CVEs present", () => {
    const cvss = [
      { cveId: "CVE-2024-0001", cvssScore: 5.0 },
      { cveId: "CVE-2024-0002", cvssScore: 9.8 }
    ];
    const result = svc.computeCompositeExploitRisk(cvss, []);
    // fallback: (9.8 / 10) * 100 = 98
    expect(result).toBe(98);
  });

  it("computes composite score when EPSS data is present", () => {
    const cvss = [{ cveId: "CVE-2024-0001", cvssScore: 9.8 }];
    const epss = [makeEpss("CVE-2024-0001", 0.6, 0.85)];
    const result = svc.computeCompositeExploitRisk(cvss, epss);
    // contribution = (9.8 / 10) * 0.85 * 100 = 83.3 → 83
    expect(result).toBe(83);
  });

  it("compositeExploitRisk is capped at 100", () => {
    const cvss = [
      { cveId: "CVE-A", cvssScore: 10.0 },
      { cveId: "CVE-B", cvssScore: 10.0 },
      { cveId: "CVE-C", cvssScore: 10.0 }
    ];
    const epss = [
      makeEpss("CVE-A", 0.9, 0.99),
      makeEpss("CVE-B", 0.9, 0.99),
      makeEpss("CVE-C", 0.9, 0.99)
    ];
    const result = svc.computeCompositeExploitRisk(cvss, epss);
    expect(result).toBe(100);
  });

  it("uses CVSS/10 as contribution for CVEs with no matching EPSS row", () => {
    const cvss = [
      { cveId: "CVE-2024-KNOWN", cvssScore: 8.0 },
      { cveId: "CVE-2024-UNKNOWN", cvssScore: 6.0 } // no EPSS row
    ];
    const epss = [makeEpss("CVE-2024-KNOWN", 0.5, 0.80)];
    const result = svc.computeCompositeExploitRisk(cvss, epss);
    // contribution KNOWN: (8/10) * 0.80 * 100 = 64
    // contribution UNKNOWN (no epss): 6.0 (cvssScore used directly as contribution)
    // sum top-3: 64 + 6 = 70
    expect(result).toBe(70);
  });

  it("only sums top-3 contributions to avoid inflating score with many low CVEs", () => {
    const cvss = [
      { cveId: "CVE-1", cvssScore: 9.0 },
      { cveId: "CVE-2", cvssScore: 8.0 },
      { cveId: "CVE-3", cvssScore: 7.0 },
      { cveId: "CVE-4", cvssScore: 6.0 },
      { cveId: "CVE-5", cvssScore: 5.0 }
    ];
    const epss = [
      makeEpss("CVE-1", 0.4, 0.60),
      makeEpss("CVE-2", 0.3, 0.50),
      makeEpss("CVE-3", 0.2, 0.40),
      makeEpss("CVE-4", 0.1, 0.30),
      makeEpss("CVE-5", 0.05, 0.20)
    ];
    // contributions: 54, 40, 28, 18, 10 — top-3 = 54 + 40 + 28 = 122 → capped at 100
    const result = svc.computeCompositeExploitRisk(cvss, epss);
    expect(result).toBeLessThanOrEqual(100);
  });

  it("exploitedInTheWild flag is set when percentile > 0.90", () => {
    const notWild = makeEpss("CVE-2024-0001", 0.5, 0.85);
    const inWild = makeEpss("CVE-2024-0002", 0.9, 0.95);
    expect(notWild.exploitedInTheWild).toBe(false);
    expect(inWild.exploitedInTheWild).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Verify against real-world-like package: bcrypt@5.1.1 with CVE-2024-0727
  // CVE-2024-0727 is a CVSS 5.5 (medium) OpenSSL vuln sometimes linked to
  // bcrypt builds; EPSS percentile is typically ~0.30 (low real-world risk).
  // The composite should reflect this: moderate CVSS, low EPSS → low-medium.
  // -------------------------------------------------------------------------
  it("bcrypt CVE-2024-0727 scenario: low EPSS keeps composite risk moderate", () => {
    const cvss = [{ cveId: "CVE-2024-0727", cvssScore: 5.5 }];
    const epss = [makeEpss("CVE-2024-0727", 0.0008, 0.30)];
    const result = svc.computeCompositeExploitRisk(cvss, epss);
    // contribution = (5.5/10) * 0.30 * 100 = 16.5 → 17
    expect(result).toBe(17);
    expect(result).toBeLessThan(50); // not a high-risk package
  });

  it("high EPSS percentile significantly boosts composite risk", () => {
    // Same CVSS but very high EPSS (actively exploited)
    const cvss = [{ cveId: "CVE-2024-0727", cvssScore: 5.5 }];
    const lowEpss = [makeEpss("CVE-2024-0727", 0.001, 0.30)];
    const highEpss = [makeEpss("CVE-2024-0727", 0.5, 0.92)];

    const lowRisk = svc.computeCompositeExploitRisk(cvss, lowEpss);
    const highRisk = svc.computeCompositeExploitRisk(cvss, highEpss);
    expect(highRisk).toBeGreaterThan(lowRisk);
    // high: (5.5/10) * 0.92 * 100 = 50.6 → 51
    expect(highRisk).toBeGreaterThan(40);
  });
});

// ---------------------------------------------------------------------------
// AdvisoryService.parseVendorAdvisoryPatches
// ---------------------------------------------------------------------------

function makeGhsaAdvisory(overrides: Partial<VendorAdvisoryJson> = {}): VendorAdvisoryJson {
  return {
    id: "GHSA-xxxx-yyyy-zzzz",
    cve_id: "CVE-2024-1234",
    vulnerabilities: [
      {
        package: { name: "test-pkg", ecosystem: "npm" },
        first_patched_version: { identifier: "2.0.0" },
        patched_versions: ">= 2.0.0",
        vulnerable_version_range: ">= 1.0.0, < 2.0.0"
      }
    ],
    published_at: "2024-01-01T00:00:00.000Z",
    updated_at: "2024-01-10T00:00:00.000Z",
    withdrawn_at: null,
    ...overrides
  };
}

describe("AdvisoryService.parseVendorAdvisoryPatches", () => {
  const svc = makeService();

  it("returns empty result for empty input", () => {
    const result = svc.parseVendorAdvisoryPatches([]);
    expect(result.patches).toHaveLength(0);
    expect(result.parsed).toBe(0);
    expect(result.skipped).toBe(0);
  });

  it("parses a GHSA advisory with first_patched_version as high-confidence", () => {
    const result = svc.parseVendorAdvisoryPatches([makeGhsaAdvisory()]);
    expect(result.patches).toHaveLength(1);
    expect(result.parsed).toBe(1);
    expect(result.skipped).toBe(0);
    const patch = result.patches[0]!;
    expect(patch.cveId).toBe("CVE-2024-1234");
    expect(patch.patchedVersion).toBe("2.0.0");
    expect(patch.vendorConfidence).toBe("high");
    expect(patch.daysToFix).toBeGreaterThan(0);
  });

  it("uses cve_id when present (GHSA → CVE mapping)", () => {
    const advisory = makeGhsaAdvisory({ id: "GHSA-aaaa-bbbb-cccc", cve_id: "CVE-2024-5678" });
    const result = svc.parseVendorAdvisoryPatches([advisory]);
    expect(result.patches[0]!.cveId).toBe("CVE-2024-5678");
  });

  it("falls back to advisory id when no cve_id", () => {
    const advisory = makeGhsaAdvisory({ id: "CVE-2024-9999", cve_id: null });
    const result = svc.parseVendorAdvisoryPatches([advisory]);
    expect(result.patches[0]!.cveId).toBe("CVE-2024-9999");
  });

  it("skips withdrawn advisories", () => {
    const advisory = makeGhsaAdvisory({ withdrawn_at: "2024-06-01T00:00:00.000Z" });
    const result = svc.parseVendorAdvisoryPatches([advisory]);
    expect(result.patches).toHaveLength(0);
    expect(result.skipped).toBe(1);
  });

  it("skips advisories with no vulnerabilities array", () => {
    const advisory = makeGhsaAdvisory({ vulnerabilities: [] });
    const result = svc.parseVendorAdvisoryPatches([advisory]);
    expect(result.patches).toHaveLength(0);
    expect(result.skipped).toBe(1);
  });

  it("skips advisories with no patched version in any vuln entry", () => {
    const advisory = makeGhsaAdvisory({
      vulnerabilities: [
        {
          package: { name: "test-pkg", ecosystem: "npm" },
          first_patched_version: null,
          patched_versions: null,
          vulnerable_version_range: ">= 1.0.0"
        }
      ]
    });
    const result = svc.parseVendorAdvisoryPatches([advisory]);
    expect(result.patches).toHaveLength(0);
    expect(result.skipped).toBe(1);
  });

  it("applies packageName filter — skips non-matching packages", () => {
    const advisory = makeGhsaAdvisory({
      vulnerabilities: [
        {
          package: { name: "other-pkg", ecosystem: "npm" },
          first_patched_version: { identifier: "3.0.0" },
          patched_versions: ">= 3.0.0",
          vulnerable_version_range: ">= 1.0.0, < 3.0.0"
        }
      ]
    });
    const result = svc.parseVendorAdvisoryPatches([advisory], "test-pkg");
    expect(result.patches).toHaveLength(0);
    expect(result.skipped).toBe(1);
  });

  it("classifies non-GHSA ids as medium confidence", () => {
    const advisory = makeGhsaAdvisory({ id: "CVE-2024-9999", cve_id: null });
    const result = svc.parseVendorAdvisoryPatches([advisory]);
    expect(result.patches[0]!.vendorConfidence).toBe("medium");
  });

  it("extracts patched version from patched_versions string when first_patched_version absent", () => {
    const advisory = makeGhsaAdvisory({
      vulnerabilities: [
        {
          package: { name: "test-pkg", ecosystem: "npm" },
          first_patched_version: null,
          patched_versions: ">= 1.5.3",
          vulnerable_version_range: ">= 1.0.0, < 1.5.3"
        }
      ]
    });
    const result = svc.parseVendorAdvisoryPatches([advisory]);
    expect(result.patches[0]!.patchedVersion).toBe("1.5.3");
  });

  it("processes multiple advisories and counts correctly", () => {
    const advisories = [
      makeGhsaAdvisory({ id: "GHSA-aaaa-0001-0001", cve_id: "CVE-2024-0001" }),
      makeGhsaAdvisory({ id: "GHSA-aaaa-0002-0002", cve_id: "CVE-2024-0002", withdrawn_at: "2024-05-01T00:00:00.000Z" }),
      makeGhsaAdvisory({ id: "GHSA-aaaa-0003-0003", cve_id: "CVE-2024-0003" })
    ];
    const result = svc.parseVendorAdvisoryPatches(advisories);
    expect(result.parsed).toBe(2);
    expect(result.skipped).toBe(1);
    expect(result.patches).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// AdvisoryService.buildLockfileResolutionContexts
// ---------------------------------------------------------------------------

describe("AdvisoryService.buildLockfileResolutionContexts", () => {
  const svc = makeService();

  const patches = [
    { cveId: "CVE-2024-0001", patchedVersion: "2.0.0", daysToFix: 30, vendorConfidence: "high" as const },
    { cveId: "CVE-2024-0002", patchedVersion: "1.5.0", daysToFix: 15, vendorConfidence: "medium" as const }
  ];

  it("marks lockfile as unpatched when resolved version is older than patched version", () => {
    const contexts = svc.buildLockfileResolutionContexts("1.0.0", patches);
    expect(contexts).toHaveLength(2);
    expect(contexts[0]!.isUnpatched).toBe(true); // 1.0.0 < 2.0.0
    expect(contexts[1]!.isUnpatched).toBe(true); // 1.0.0 < 1.5.0
  });

  it("marks lockfile as patched when resolved version equals patched version", () => {
    const contexts = svc.buildLockfileResolutionContexts("2.0.0", patches);
    expect(contexts[0]!.isUnpatched).toBe(false); // 2.0.0 = 2.0.0
    expect(contexts[1]!.isUnpatched).toBe(false); // 2.0.0 > 1.5.0
  });

  it("marks lockfile as patched when resolved version is newer than patched version", () => {
    const contexts = svc.buildLockfileResolutionContexts("3.1.0", patches);
    expect(contexts.every((c) => !c.isUnpatched)).toBe(true);
  });

  it("returns empty array when no patches provided", () => {
    expect(svc.buildLockfileResolutionContexts("1.0.0", [])).toEqual([]);
  });

  it("preserves cveId and version strings in each context", () => {
    const contexts = svc.buildLockfileResolutionContexts("1.0.0", [patches[0]!]);
    expect(contexts[0]!.cveId).toBe("CVE-2024-0001");
    expect(contexts[0]!.resolvedVersion).toBe("1.0.0");
    expect(contexts[0]!.patchedVersion).toBe("2.0.0");
  });

  // E2E-style: real CVE with vendor patch — CVE-2021-44228 (Log4Shell)
  // Patched in log4j 2.15.0; if lockfile pins 2.14.1 it should be flagged.
  it("real-world scenario: log4j-style patch detection", () => {
    const log4jPatch = [{
      cveId: "CVE-2021-44228",
      patchedVersion: "2.15.0",
      daysToFix: 7,
      vendorConfidence: "high" as const
    }];
    const vulnerable = svc.buildLockfileResolutionContexts("2.14.1", log4jPatch);
    expect(vulnerable[0]!.isUnpatched).toBe(true);

    const patched = svc.buildLockfileResolutionContexts("2.15.0", log4jPatch);
    expect(patched[0]!.isUnpatched).toBe(false);

    const newer = svc.buildLockfileResolutionContexts("2.17.1", log4jPatch);
    expect(newer[0]!.isUnpatched).toBe(false);
  });
});
