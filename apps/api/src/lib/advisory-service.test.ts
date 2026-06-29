import { describe, expect, it } from "vitest";

import { AdvisoryService } from "./advisory-service";
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
