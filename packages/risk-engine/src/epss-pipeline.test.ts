/**
 * EPSS Severity Override & Real-Time CVE Cross-Reference — pipeline tests
 *
 * Covers:
 *   - CVE lookup misses (empty list, all stale, no kev)
 *   - EPSS percentile boundary cases: 0, 0.39, 0.40, 0.50, 0.75, 0.76, 0.90, 0.91, 0.95, 0.99
 *   - KEV-active vs KEV-inactive modifiers
 *   - aggregatePackageRiskWithEpss score arithmetic
 *   - EpssBoostContext / boost Finding audit fields
 *   - isEpssEntryFresh staleness guard
 *   - selectBestCveEntry selection logic
 *   - buildEpssBoostFinding severity mapping
 */

import { describe, expect, it } from "vitest";
import type { BinaryAnalysis } from "@binshield/analysis-types";
import { emptyBehaviorSummary } from "@binshield/analysis-types";

import {
  aggregatePackageRiskWithEpss,
  buildEpssBoostContext,
  buildEpssBoostFinding,
  isEpssEntryFresh,
  selectBestCveEntry,
  epssPercentileBoost,
  kevBoostForVuln,
  normalizeRisk,
} from "./index";
import type { CveEpssInput } from "./index";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeBinary(riskScore: number): BinaryAnalysis {
  return {
    id: `bin_${riskScore}`,
    filename: "test.node",
    architecture: "x86_64",
    format: "ELF",
    fileSize: 100_000,
    functionCount: 20,
    importCount: 10,
    riskScore,
    riskLevel: "low",
    decompiledPreview: "",
    aiExplanation: "",
    imports: [],
    strings: [],
    behaviors: emptyBehaviorSummary(),
    findings: [],
  };
}

const FRESH_AT = new Date(Date.now() - 1000).toISOString(); // 1 second ago
const STALE_AT = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString(); // 40 days ago

function makeCve(
  cveId: string,
  epss_percentile: number,
  kev_active = false,
  fetchedAt?: string
): CveEpssInput {
  return { cveId, epss_percentile, kev_active, fetchedAt: fetchedAt ?? FRESH_AT };
}

// ---------------------------------------------------------------------------
// 1. isEpssEntryFresh — staleness guard
// ---------------------------------------------------------------------------

describe("isEpssEntryFresh", () => {
  it("returns true when fetchedAt is absent (no staleness info)", () => {
    const entry: CveEpssInput = { cveId: "CVE-2024-0001", epss_percentile: 0.5, kev_active: false };
    expect(isEpssEntryFresh(entry)).toBe(true);
  });

  it("returns true for a freshly fetched entry (1 second ago)", () => {
    expect(isEpssEntryFresh(makeCve("CVE-2024-0001", 0.5, false, FRESH_AT))).toBe(true);
  });

  it("returns false for a stale entry (40 days ago)", () => {
    expect(isEpssEntryFresh(makeCve("CVE-2024-0001", 0.5, false, STALE_AT))).toBe(false);
  });

  it("returns false for an invalid fetchedAt string", () => {
    const entry = makeCve("CVE-2024-0001", 0.5, false, "not-a-date");
    expect(isEpssEntryFresh(entry)).toBe(false);
  });

  it("returns true exactly at the 30-day boundary (not yet stale)", () => {
    const BOUNDARY_AT = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000 + 1000).toISOString();
    expect(isEpssEntryFresh(makeCve("CVE-2024-0001", 0.5, false, BOUNDARY_AT))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 2. selectBestCveEntry — highest-percentile fresh entry
// ---------------------------------------------------------------------------

describe("selectBestCveEntry", () => {
  it("returns undefined for an empty list", () => {
    expect(selectBestCveEntry([])).toBeUndefined();
  });

  it("returns undefined when all entries are stale", () => {
    const cves = [
      makeCve("CVE-2024-0001", 0.95, false, STALE_AT),
      makeCve("CVE-2024-0002", 0.80, false, STALE_AT),
    ];
    expect(selectBestCveEntry(cves)).toBeUndefined();
  });

  it("returns the single fresh entry", () => {
    const cve = makeCve("CVE-2024-0001", 0.72, false, FRESH_AT);
    expect(selectBestCveEntry([cve])?.cveId).toBe("CVE-2024-0001");
  });

  it("returns the highest-percentile entry when multiple are fresh", () => {
    const cves = [
      makeCve("CVE-2024-LOW", 0.30, false, FRESH_AT),
      makeCve("CVE-2024-HIGH", 0.95, false, FRESH_AT),
      makeCve("CVE-2024-MID", 0.60, false, FRESH_AT),
    ];
    expect(selectBestCveEntry(cves)?.cveId).toBe("CVE-2024-HIGH");
  });

  it("ignores stale entries and picks the best fresh one", () => {
    const cves = [
      makeCve("CVE-2024-STALE", 0.99, false, STALE_AT), // stale — ignored
      makeCve("CVE-2024-FRESH", 0.60, false, FRESH_AT),
    ];
    expect(selectBestCveEntry(cves)?.cveId).toBe("CVE-2024-FRESH");
  });
});

// ---------------------------------------------------------------------------
// 3. epssPercentileBoost — boundary cases
// ---------------------------------------------------------------------------

describe("epssPercentileBoost — EPSS percentile boundary cases", () => {
  it("returns 0 for percentile 0 (no exploitation signal)", () => {
    expect(epssPercentileBoost(0)).toBe(0);
  });

  it("returns 0 for percentile 0.39 (below 0.40 threshold)", () => {
    expect(epssPercentileBoost(0.39)).toBe(0);
  });

  it("returns +5 at exactly 0.40 (first boost tier)", () => {
    expect(epssPercentileBoost(0.40)).toBe(5);
  });

  it("returns +5 for percentile 0.50 (mid first tier)", () => {
    expect(epssPercentileBoost(0.50)).toBe(5);
  });

  it("returns +5 for percentile 0.74 (just below second tier)", () => {
    expect(epssPercentileBoost(0.74)).toBe(5);
  });

  it("returns +5 for percentile 0.75 (second tier boundary — exclusive)", () => {
    // epssPercentileBoost uses > 0.75, so 0.75 is still in the 0.40–0.75 band
    expect(epssPercentileBoost(0.75)).toBe(5);
  });

  it("returns +15 for percentile 0.76 (just above 0.75)", () => {
    expect(epssPercentileBoost(0.76)).toBe(15);
  });

  it("returns +15 for percentile 0.90 (second tier boundary — exclusive)", () => {
    // epssPercentileBoost uses > 0.90, so 0.90 is still in the 0.75–0.90 band
    expect(epssPercentileBoost(0.90)).toBe(15);
  });

  it("returns +25 for percentile 0.91 (just above 0.90)", () => {
    expect(epssPercentileBoost(0.91)).toBe(25);
  });

  it("returns +25 for percentile 0.95", () => {
    expect(epssPercentileBoost(0.95)).toBe(25);
  });

  it("returns +25 for percentile 0.99 (near maximum)", () => {
    expect(epssPercentileBoost(0.99)).toBe(25);
  });

  it("returns +25 for percentile 1.0 (maximum)", () => {
    expect(epssPercentileBoost(1.0)).toBe(25);
  });
});

// ---------------------------------------------------------------------------
// 4. aggregatePackageRiskWithEpss — CVE lookup misses
// ---------------------------------------------------------------------------

describe("aggregatePackageRiskWithEpss — CVE lookup misses", () => {
  it("returns base score unchanged when cves list is empty", () => {
    const binaries = [makeBinary(30)];
    const result = aggregatePackageRiskWithEpss(binaries, []);
    expect(result.riskScore).toBe(30);
    expect(result.epss_context).toBeUndefined();
    expect(result.boostFinding).toBeUndefined();
  });

  it("returns base score unchanged when all cves are stale", () => {
    const binaries = [makeBinary(30)];
    const cves = [makeCve("CVE-2024-0001", 0.95, true, STALE_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    expect(result.riskScore).toBe(30);
    expect(result.epss_context).toBeUndefined();
  });

  it("returns base score unchanged when percentile is below all thresholds (< 0.40)", () => {
    const binaries = [makeBinary(20)];
    const cves = [makeCve("CVE-2024-LOWRISK", 0.10, false, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    // epssPercentileBoost(0.10) = 0, kevBoostForVuln(false) = 0 → no boost
    expect(result.riskScore).toBe(20);
    expect(result.boostFinding).toBeUndefined();
  });

  it("returns base score when binaries list is empty (no binaries = 0 risk)", () => {
    const cves = [makeCve("CVE-2024-0001", 0.95, true, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss([], cves);
    // aggregatePackageRisk([]) = 0; 0 + 25 (EPSS) + 20 (KEV) = 45
    expect(result.riskScore).toBe(45);
  });
});

// ---------------------------------------------------------------------------
// 5. aggregatePackageRiskWithEpss — EPSS boost arithmetic
// ---------------------------------------------------------------------------

describe("aggregatePackageRiskWithEpss — boost arithmetic", () => {
  it("applies +5 boost for EPSS percentile in [0.40, 0.75]", () => {
    const binaries = [makeBinary(20)];
    const cves = [makeCve("CVE-2024-MID", 0.50, false, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    expect(result.riskScore).toBe(25); // 20 + 5
    expect(result.epss_context?.epss_boost_pts).toBe(5);
    expect(result.epss_context?.kev_boost_pts).toBe(0);
  });

  it("applies +15 boost for EPSS percentile in (0.75, 0.90]", () => {
    const binaries = [makeBinary(20)];
    const cves = [makeCve("CVE-2024-HIGH", 0.80, false, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    expect(result.riskScore).toBe(35); // 20 + 15
    expect(result.epss_context?.epss_boost_pts).toBe(15);
  });

  it("applies +25 boost for EPSS percentile > 0.90", () => {
    const binaries = [makeBinary(20)];
    const cves = [makeCve("CVE-2024-CRIT", 0.95, false, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    expect(result.riskScore).toBe(45); // 20 + 25
    expect(result.epss_context?.epss_boost_pts).toBe(25);
  });

  it("applies +25 EPSS + +20 KEV boost for KEV-active CVE at 99th percentile", () => {
    const binaries = [makeBinary(20)];
    const cves = [makeCve("CVE-2024-KEV", 0.99, true, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    expect(result.riskScore).toBe(65); // 20 + 25 + 20
    expect(result.epss_context?.epss_boost_pts).toBe(25);
    expect(result.epss_context?.kev_boost_pts).toBe(20);
    expect(result.epss_context?.kev_status).toBe(true);
  });

  it("KEV-inactive CVE at 99th percentile adds only EPSS boost", () => {
    const binaries = [makeBinary(20)];
    const cves = [makeCve("CVE-2024-NOKEV", 0.99, false, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    expect(result.riskScore).toBe(45); // 20 + 25
    expect(result.epss_context?.kev_boost_pts).toBe(0);
    expect(result.epss_context?.kev_status).toBe(false);
  });

  it("clamps combined score to 100", () => {
    const binaries = [makeBinary(80)];
    const cves = [makeCve("CVE-2024-OVERFLOW", 0.99, true, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    // 80 + 25 + 20 = 125 → clamped to 100
    expect(result.riskScore).toBe(100);
    expect(result.riskLevel).toBe("critical");
  });

  it("selects highest-percentile CVE when multiple are provided", () => {
    const binaries = [makeBinary(10)];
    const cves = [
      makeCve("CVE-LOW", 0.20, false, FRESH_AT),
      makeCve("CVE-HIGH", 0.92, true, FRESH_AT),
      makeCve("CVE-MID", 0.55, false, FRESH_AT),
    ];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    // Best = CVE-HIGH at 0.92: epss=25, kev=20 → 10 + 45 = 55
    expect(result.epss_context?.primaryCveId).toBe("CVE-HIGH");
    expect(result.riskScore).toBe(55);
  });
});

// ---------------------------------------------------------------------------
// 6. EpssBoostContext audit fields
// ---------------------------------------------------------------------------

describe("buildEpssBoostContext — audit fields", () => {
  it("includes cveId, percentile, boost_pts, and boost_reason", () => {
    const entry = makeCve("CVE-2024-AUDIT", 0.95, true, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 25, 20);
    expect(ctx.primaryCveId).toBe("CVE-2024-AUDIT");
    expect(ctx.epss_percentile).toBe(0.95);
    expect(ctx.epss_boost_pts).toBe(25);
    expect(ctx.kev_boost_pts).toBe(20);
    expect(ctx.kev_status).toBe(true);
    expect(ctx.boost_reason).toContain("CVE-2024-AUDIT");
    expect(ctx.boost_reason).toContain("CISA KEV");
    expect(typeof ctx.computed_at).toBe("string");
  });

  it("boost_reason contains percentile label", () => {
    const entry = makeCve("CVE-2024-PCT", 0.97, false, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 25, 0);
    expect(ctx.boost_reason).toContain("97th percentile");
  });

  it("boost_reason mentions below-threshold when both boosts are zero", () => {
    const entry = makeCve("CVE-2024-LOW", 0.10, false, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 0, 0);
    expect(ctx.boost_reason).toContain("below boost threshold");
  });
});

// ---------------------------------------------------------------------------
// 7. buildEpssBoostFinding — severity mapping
// ---------------------------------------------------------------------------

describe("buildEpssBoostFinding — severity mapping", () => {
  it("returns critical finding when total boost >= 20", () => {
    const entry = makeCve("CVE-2024-CRIT", 0.95, true, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 25, 20);
    const finding = buildEpssBoostFinding(ctx);
    expect(finding.severity).toBe("critical");
    expect(finding.title).toContain("CVE-2024-CRIT");
  });

  it("returns high finding when total boost is 10–19", () => {
    const entry = makeCve("CVE-2024-HIGH", 0.80, false, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 15, 0);
    const finding = buildEpssBoostFinding(ctx);
    expect(finding.severity).toBe("high");
  });

  it("returns medium finding when total boost is 5–9", () => {
    const entry = makeCve("CVE-2024-MED", 0.50, false, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 5, 0);
    const finding = buildEpssBoostFinding(ctx);
    expect(finding.severity).toBe("medium");
  });

  it("recommendation mentions CISA KEV when kev_status is true", () => {
    const entry = makeCve("CVE-2024-KEV", 0.95, true, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 25, 20);
    const finding = buildEpssBoostFinding(ctx);
    expect(finding.recommendation).toContain("CISA Known Exploited");
  });

  it("recommendation does NOT mention CISA KEV when kev_status is false", () => {
    const entry = makeCve("CVE-2024-NOKEV", 0.95, false, FRESH_AT);
    const ctx = buildEpssBoostContext(entry, 25, 0);
    const finding = buildEpssBoostFinding(ctx);
    expect(finding.recommendation).not.toContain("CISA Known Exploited");
    expect(finding.recommendation).toContain("Monitor");
  });
});

// ---------------------------------------------------------------------------
// 8. riskLevel escalation
// ---------------------------------------------------------------------------

describe("aggregatePackageRiskWithEpss — riskLevel escalation", () => {
  it("escalates low→medium when EPSS boost pushes score past 30", () => {
    const binaries = [makeBinary(20)]; // riskLevel=low
    const cves = [makeCve("CVE-2024-ESC", 0.80, false, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    // 20 + 15 = 35 → medium
    expect(result.riskLevel).toBe("medium");
  });

  it("escalates medium→high when EPSS+KEV boost pushes score past 60", () => {
    const binaries = [makeBinary(30)]; // riskLevel=medium, score=30
    const cves = [makeCve("CVE-2024-ESC2", 0.95, true, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    // 30 + 25 + 20 = 75 → high
    expect(result.riskLevel).toBe("high");
  });

  it("reaches critical when score hits 80+", () => {
    const binaries = [makeBinary(35)];
    const cves = [makeCve("CVE-2024-ESC3", 0.99, true, FRESH_AT)];
    const result = aggregatePackageRiskWithEpss(binaries, cves);
    // 35 + 25 + 20 = 80 → critical
    expect(result.riskLevel).toBe("critical");
  });
});
