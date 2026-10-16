import { describe, expect, it } from "vitest";

import type { Advisory, MalwareDetectionResult } from "@binshield/analysis-types";
import {
  cisaKevBoostPoints,
  correlateEpssWithMalware,
  correlatedSeverityFromScore,
  cvssFloor,
  epssBoostPoints,
  malwareSignalBoostPoints
} from "./epss-correlator";

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    cveId: "CVE-2024-0001",
    title: "Test advisory",
    ...overrides
  };
}

function makeSignal(overrides: Partial<MalwareDetectionResult> = {}): MalwareDetectionResult {
  return {
    analyzerName: "entropy",
    analyzerVersion: "1.0.0",
    detected: true,
    signals: ["high entropy section"],
    confidence: 0.85,
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// 1. cvssFloor — CVSS v3 score → risk floor mapping
// ---------------------------------------------------------------------------

describe("cvssFloor", () => {
  it("returns 0 when cvssV3Score is undefined", () => {
    expect(cvssFloor(undefined)).toBe(0);
  });

  it("returns 0 when cvssV3Score is 0", () => {
    expect(cvssFloor(0)).toBe(0);
  });

  it("returns 5 for low CVSS scores (0.1–3.9)", () => {
    expect(cvssFloor(1.0)).toBe(5);
    expect(cvssFloor(3.9)).toBe(5);
  });

  it("returns 20 for medium CVSS scores (4.0–6.9)", () => {
    expect(cvssFloor(4.0)).toBe(20);
    expect(cvssFloor(6.9)).toBe(20);
  });

  it("returns 40 for high CVSS scores (7.0–8.9)", () => {
    expect(cvssFloor(7.0)).toBe(40);
    expect(cvssFloor(8.9)).toBe(40);
  });

  it("returns 55 for critical CVSS scores (9.0–10.0)", () => {
    expect(cvssFloor(9.0)).toBe(55);
    expect(cvssFloor(10.0)).toBe(55);
  });
});

// ---------------------------------------------------------------------------
// 2. epssBoostPoints — EPSS percentile boost
// ---------------------------------------------------------------------------

describe("epssBoostPoints", () => {
  it("returns 0 when epssPercentile is undefined", () => {
    expect(epssBoostPoints(undefined)).toBe(0);
  });

  it("returns 0 when epssPercentile is below 0.75", () => {
    expect(epssBoostPoints(0)).toBe(0);
    expect(epssBoostPoints(0.50)).toBe(0);
    expect(epssBoostPoints(0.749)).toBe(0);
  });

  it("returns +10 when epssPercentile is in [0.75, 0.90)", () => {
    expect(epssBoostPoints(0.75)).toBe(10);
    expect(epssBoostPoints(0.80)).toBe(10);
    expect(epssBoostPoints(0.899)).toBe(10);
  });

  it("returns +20 when epssPercentile is >= 0.90", () => {
    expect(epssBoostPoints(0.90)).toBe(20);
    expect(epssBoostPoints(0.95)).toBe(20);
    expect(epssBoostPoints(1.0)).toBe(20);
  });
});

// ---------------------------------------------------------------------------
// 3. cisaKevBoostPoints — CISA KEV boost
// ---------------------------------------------------------------------------

describe("cisaKevBoostPoints", () => {
  it("returns 0 when cisaKev is undefined", () => {
    expect(cisaKevBoostPoints(undefined)).toBe(0);
  });

  it("returns 0 when cisaKev is false", () => {
    expect(cisaKevBoostPoints(false)).toBe(0);
  });

  it("returns +15 when cisaKev is true", () => {
    expect(cisaKevBoostPoints(true)).toBe(15);
  });
});

// ---------------------------------------------------------------------------
// 4. malwareSignalBoostPoints — detection confidence boost
// ---------------------------------------------------------------------------

describe("malwareSignalBoostPoints", () => {
  it("returns 0 and empty analyzers when signals is undefined", () => {
    const result = malwareSignalBoostPoints(undefined);
    expect(result.boost).toBe(0);
    expect(result.matchedAnalyzers).toHaveLength(0);
  });

  it("returns 0 and empty analyzers when signals array is empty", () => {
    const result = malwareSignalBoostPoints([]);
    expect(result.boost).toBe(0);
    expect(result.matchedAnalyzers).toHaveLength(0);
  });

  it("returns 0 when no analyzer detected anything", () => {
    const signals = [
      makeSignal({ detected: false, confidence: 0.9 }),
      makeSignal({ analyzerName: "import-table", detected: false, confidence: 0.8 })
    ];
    const result = malwareSignalBoostPoints(signals);
    expect(result.boost).toBe(0);
    expect(result.matchedAnalyzers).toHaveLength(0);
  });

  it("returns +5 for low-confidence detections (avg confidence 0.2–0.49)", () => {
    const signals = [makeSignal({ confidence: 0.3 })];
    const result = malwareSignalBoostPoints(signals);
    expect(result.boost).toBe(5);
    expect(result.matchedAnalyzers).toContain("entropy");
  });

  it("returns +10 for medium-confidence detections (avg confidence 0.5–0.79)", () => {
    const signals = [makeSignal({ confidence: 0.6 })];
    const result = malwareSignalBoostPoints(signals);
    expect(result.boost).toBe(10);
  });

  it("returns +15 for high-confidence detections (avg confidence >= 0.8)", () => {
    const signals = [makeSignal({ confidence: 0.9 })];
    const result = malwareSignalBoostPoints(signals);
    expect(result.boost).toBe(15);
  });

  it("averages confidence across all detected signals", () => {
    // avg = (0.9 + 0.5) / 2 = 0.70 → +10
    const signals = [
      makeSignal({ analyzerName: "entropy", detected: true, confidence: 0.9 }),
      makeSignal({ analyzerName: "import-table", detected: true, confidence: 0.5 })
    ];
    const result = malwareSignalBoostPoints(signals);
    expect(result.boost).toBe(10);
    expect(result.matchedAnalyzers).toContain("entropy");
    expect(result.matchedAnalyzers).toContain("import-table");
  });

  it("only includes detected analyzers in matchedAnalyzers", () => {
    const signals = [
      makeSignal({ analyzerName: "entropy", detected: true, confidence: 0.9 }),
      makeSignal({ analyzerName: "string-literal", detected: false, confidence: 0.1 })
    ];
    const result = malwareSignalBoostPoints(signals);
    expect(result.matchedAnalyzers).toContain("entropy");
    expect(result.matchedAnalyzers).not.toContain("string-literal");
  });
});

// ---------------------------------------------------------------------------
// 5. correlatedSeverityFromScore — score → severity tier
// ---------------------------------------------------------------------------

describe("correlatedSeverityFromScore", () => {
  it("returns none for score 0", () => {
    expect(correlatedSeverityFromScore(0)).toBe("none");
  });

  it("returns low for score 1–29", () => {
    expect(correlatedSeverityFromScore(1)).toBe("low");
    expect(correlatedSeverityFromScore(29)).toBe("low");
  });

  it("returns medium for score 30–59", () => {
    expect(correlatedSeverityFromScore(30)).toBe("medium");
    expect(correlatedSeverityFromScore(59)).toBe("medium");
  });

  it("returns high for score 60–79", () => {
    expect(correlatedSeverityFromScore(60)).toBe("high");
    expect(correlatedSeverityFromScore(79)).toBe("high");
  });

  it("returns critical for score 80–100", () => {
    expect(correlatedSeverityFromScore(80)).toBe("critical");
    expect(correlatedSeverityFromScore(100)).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// 6. correlateEpssWithMalware — integration / end-to-end cases
// ---------------------------------------------------------------------------

describe("correlateEpssWithMalware", () => {
  // --- Test case 1: minimal advisory — no CVSS, no EPSS, no KEV ---
  it("TC01: minimal advisory with no signals scores 0 / none", () => {
    const result = correlateEpssWithMalware(makeAdvisory());
    expect(result.correlatedScore).toBe(0);
    expect(result.correlatedSeverity).toBe("none");
    expect(result.scoreBreakdown.cvssFloor).toBe(0);
    expect(result.scoreBreakdown.epssBoost).toBe(0);
    expect(result.scoreBreakdown.cisaKevBoost).toBe(0);
    expect(result.scoreBreakdown.malwareSignalBoost).toBe(0);
    expect(result.matchedMalwareAnalyzers).toHaveLength(0);
  });

  // --- Test case 2: critical CVSS alone —  55 pts / medium ---
  it("TC02: critical CVSS (9.5) without EPSS or KEV → 55 pts / medium", () => {
    const result = correlateEpssWithMalware(makeAdvisory({ cvssV3Score: 9.5 }));
    expect(result.correlatedScore).toBe(55);
    expect(result.correlatedSeverity).toBe("medium");
    expect(result.scoreBreakdown.cvssFloor).toBe(55);
  });

  // --- Test case 3: high CVSS floor ---
  it("TC03: high CVSS (7.8) → floor 40 / medium", () => {
    const result = correlateEpssWithMalware(makeAdvisory({ cvssV3Score: 7.8 }));
    expect(result.correlatedScore).toBe(40);
    expect(result.correlatedSeverity).toBe("medium");
  });

  // --- Test case 4: high CVSS + high EPSS → escalates to critical ---
  it("TC04: high CVSS (7.0) + EPSS ≥ 0.90 → 40+20=60 / high", () => {
    const result = correlateEpssWithMalware(
      makeAdvisory({ cvssV3Score: 7.0, epssPercentile: 0.92 })
    );
    expect(result.correlatedScore).toBe(60);
    expect(result.correlatedSeverity).toBe("high");
    expect(result.scoreBreakdown.epssBoost).toBe(20);
  });

  // --- Test case 5: KEV-only (no CVSS, no EPSS) ---
  it("TC05: KEV-only advisory (no CVSS, no EPSS) → 15 pts / low", () => {
    const result = correlateEpssWithMalware(makeAdvisory({ cisaKev: true }));
    expect(result.correlatedScore).toBe(15);
    expect(result.correlatedSeverity).toBe("low");
    expect(result.scoreBreakdown.cisaKevBoost).toBe(15);
    expect(result.scoreBreakdown.cvssFloor).toBe(0);
    expect(result.scoreBreakdown.epssBoost).toBe(0);
  });

  // --- Test case 6: high CVSS + EPSS mid-tier boost ---
  it("TC06: high CVSS (8.5) + EPSS 0.75 → 40+10=50 / medium", () => {
    const result = correlateEpssWithMalware(
      makeAdvisory({ cvssV3Score: 8.5, epssPercentile: 0.75 })
    );
    expect(result.correlatedScore).toBe(50);
    expect(result.scoreBreakdown.epssBoost).toBe(10);
  });

  // --- Test case 7: high CVSS + missing EPSS ---
  it("TC07: high CVSS (7.5) + missing EPSS → no EPSS boost applied", () => {
    const result = correlateEpssWithMalware(makeAdvisory({ cvssV3Score: 7.5 }));
    expect(result.scoreBreakdown.epssBoost).toBe(0);
    expect(result.correlatedScore).toBe(40);
  });

  // --- Test case 8: critical CVSS + KEV + high EPSS → capped at 100 ---
  it("TC08: critical CVSS (9.8) + KEV + EPSS 0.95 → 55+15+20=90 / critical", () => {
    const result = correlateEpssWithMalware(
      makeAdvisory({ cvssV3Score: 9.8, epssPercentile: 0.95, cisaKev: true })
    );
    expect(result.correlatedScore).toBe(90);
    expect(result.correlatedSeverity).toBe("critical");
    expect(result.scoreBreakdown.cvssFloor).toBe(55);
    expect(result.scoreBreakdown.epssBoost).toBe(20);
    expect(result.scoreBreakdown.cisaKevBoost).toBe(15);
  });

  // --- Test case 9: all signals combined, capped at 100 ---
  it("TC09: critical CVSS + KEV + high EPSS + high-confidence malware → capped at 100", () => {
    const signals = [makeSignal({ confidence: 0.95 })];
    const result = correlateEpssWithMalware(
      makeAdvisory({ cvssV3Score: 9.8, epssPercentile: 0.95, cisaKev: true }),
      signals
    );
    // 55 + 20 + 15 + 15 = 105 → clamped to 100
    expect(result.correlatedScore).toBe(100);
    expect(result.correlatedSeverity).toBe("critical");
    expect(result.scoreBreakdown.malwareSignalBoost).toBe(15);
    expect(result.matchedMalwareAnalyzers).toContain("entropy");
  });

  // --- Test case 10: high CVSS low EPSS — EPSS below threshold adds nothing ---
  it("TC10: high CVSS (8.0) + low EPSS (0.30) → only floor applies (40 pts)", () => {
    const result = correlateEpssWithMalware(
      makeAdvisory({ cvssV3Score: 8.0, epssPercentile: 0.30 })
    );
    expect(result.correlatedScore).toBe(40);
    expect(result.scoreBreakdown.epssBoost).toBe(0);
  });

  // --- Test case 11: zero CVSS + KEV + high EPSS (CVSSless KEV scenario) ---
  it("TC11: zero CVSS + KEV + EPSS 0.90 → 0+15+20=35 / medium", () => {
    const result = correlateEpssWithMalware(
      makeAdvisory({ cvssV3Score: 0, epssPercentile: 0.90, cisaKev: true })
    );
    expect(result.correlatedScore).toBe(35);
    expect(result.correlatedSeverity).toBe("medium");
  });

  // --- Test case 12: score never goes below 0 ---
  it("TC12: score is floored at 0 (inputs that would produce negative are clamped)", () => {
    // All inputs zero → result must be exactly 0, never negative
    const result = correlateEpssWithMalware(makeAdvisory({ cvssV3Score: 0 }));
    expect(result.correlatedScore).toBeGreaterThanOrEqual(0);
    expect(result.correlatedScore).toBe(0);
  });

  // --- Test case 13: malware signals with no detections produce no boost ---
  it("TC13: malware signals present but all detected=false → no malware boost", () => {
    const signals = [
      makeSignal({ detected: false, confidence: 0.99 }),
      makeSignal({ analyzerName: "import-table", detected: false, confidence: 0.95 })
    ];
    const result = correlateEpssWithMalware(
      makeAdvisory({ cvssV3Score: 7.0 }),
      signals
    );
    expect(result.scoreBreakdown.malwareSignalBoost).toBe(0);
    expect(result.matchedMalwareAnalyzers).toHaveLength(0);
    expect(result.correlatedScore).toBe(40);
  });

  // --- Test case 14: enriched output preserves original advisory fields ---
  it("TC14: EnrichedAdvisory preserves all original Advisory fields", () => {
    const advisory = makeAdvisory({
      cveId: "CVE-2024-99999",
      title: "Critical RCE in libfoo",
      cvssV3Score: 9.1,
      epssPercentile: 0.88,
      cisaKev: true,
      updatedAt: "2024-06-15T00:00:00.000Z"
    });
    const result = correlateEpssWithMalware(advisory);
    expect(result.cveId).toBe("CVE-2024-99999");
    expect(result.title).toBe("Critical RCE in libfoo");
    expect(result.cvssV3Score).toBe(9.1);
    expect(result.epssPercentile).toBe(0.88);
    expect(result.cisaKev).toBe(true);
    expect(result.updatedAt).toBe("2024-06-15T00:00:00.000Z");
    // Also verify enrichment fields are present
    expect(typeof result.correlatedScore).toBe("number");
    expect(typeof result.correlatedAt).toBe("string");
  });

  // --- Test case 15: scoreBreakdown.finalScore === correlatedScore always ---
  it("TC15: scoreBreakdown.finalScore always equals correlatedScore", () => {
    const cases: Advisory[] = [
      makeAdvisory(),
      makeAdvisory({ cvssV3Score: 5.5 }),
      makeAdvisory({ cvssV3Score: 9.9, epssPercentile: 0.99, cisaKev: true }),
      makeAdvisory({ cvssV3Score: 7.0, epssPercentile: 0.50 }),
      makeAdvisory({ cisaKev: true, epssPercentile: 0.76 })
    ];
    for (const advisory of cases) {
      const result = correlateEpssWithMalware(advisory);
      expect(result.scoreBreakdown.finalScore).toBe(result.correlatedScore);
    }
  });
});
