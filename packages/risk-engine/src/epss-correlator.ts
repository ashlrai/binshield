import type {
  Advisory,
  CorrelatedSeverity,
  CorrelationBreakdown,
  EnrichedAdvisory,
  MalwareDetectionResult
} from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// EPSS/CVE Risk Correlation Engine
// ---------------------------------------------------------------------------
//
// Deterministic risk aggregator that combines:
//   1. CVSS v3 base score → risk floor
//   2. EPSS percentile boost
//   3. CISA KEV active-exploitation boost
//   4. Correlated malware-engine detection confidence boost
//
// All scoring is additive; the final result is clamped to [0, 100].

// ---------------------------------------------------------------------------
// CVSS floor mapping
// ---------------------------------------------------------------------------

/**
 * Derive the base risk floor from a CVSS v3 score.
 *
 * CVSSv3 → risk floor:
 *   9.0–10.0  → 55 pts  (critical)
 *   7.0–8.9   → 40 pts  (high)
 *   4.0–6.9   → 20 pts  (medium)
 *   0.1–3.9   → 5  pts  (low)
 *   0 / absent → 0  pts  (none)
 */
export function cvssFloor(cvssV3Score: number | undefined): number {
  if (cvssV3Score == null || cvssV3Score <= 0) return 0;
  if (cvssV3Score >= 9.0) return 55;
  if (cvssV3Score >= 7.0) return 40;
  if (cvssV3Score >= 4.0) return 20;
  return 5;
}

// ---------------------------------------------------------------------------
// EPSS percentile boost
// ---------------------------------------------------------------------------

/**
 * Additional risk points from the EPSS exploitation-probability percentile.
 *
 *   ≥ 0.90 → +20 pts  (very high real-world exploit activity)
 *   ≥ 0.75 → +10 pts  (elevated real-world exploit activity)
 *   < 0.75 → +0  pts
 *
 * When `epssPercentile` is absent or undefined, returns 0.
 */
export function epssBoostPoints(epssPercentile: number | undefined): number {
  if (epssPercentile == null) return 0;
  if (epssPercentile >= 0.9) return 20;
  if (epssPercentile >= 0.75) return 10;
  return 0;
}

// ---------------------------------------------------------------------------
// CISA KEV boost
// ---------------------------------------------------------------------------

/**
 * Additional risk points when the CVE is confirmed in the CISA KEV catalogue.
 *
 *   cisaKev === true → +15 pts  (active exploitation confirmed)
 *   otherwise        → +0  pts
 */
export function cisaKevBoostPoints(cisaKev: boolean | undefined): number {
  return cisaKev === true ? 15 : 0;
}

// ---------------------------------------------------------------------------
// Malware detection signal boost
// ---------------------------------------------------------------------------

/**
 * Derive a risk boost from correlated malware-engine detection results.
 *
 * The boost reflects the average confidence of detectors that positively
 * detected something, scaled to a maximum of +15 pts:
 *
 *   avg_confidence ≥ 0.8 → +15 pts
 *   avg_confidence ≥ 0.5 → +10 pts
 *   avg_confidence ≥ 0.2 → +5  pts
 *   no detections / empty → +0  pts
 *
 * @returns { boost, matchedAnalyzers } where `matchedAnalyzers` is the list
 *   of analyzer names whose `detected` flag is true.
 */
export function malwareSignalBoostPoints(signals: MalwareDetectionResult[] | undefined): {
  boost: number;
  matchedAnalyzers: string[];
} {
  if (!signals || signals.length === 0) return { boost: 0, matchedAnalyzers: [] };

  const detected = signals.filter((s) => s.detected);
  if (detected.length === 0) return { boost: 0, matchedAnalyzers: [] };

  const avgConfidence = detected.reduce((sum, s) => sum + s.confidence, 0) / detected.length;
  const matchedAnalyzers = detected.map((s) => s.analyzerName);

  let boost = 0;
  if (avgConfidence >= 0.8) boost = 15;
  else if (avgConfidence >= 0.5) boost = 10;
  else if (avgConfidence >= 0.2) boost = 5;

  return { boost, matchedAnalyzers };
}

// ---------------------------------------------------------------------------
// Severity tier mapping
// ---------------------------------------------------------------------------

/**
 * Map a composite correlated score [0, 100] to a `CorrelatedSeverity` tier.
 *
 *   80–100 → "critical"
 *   60–79  → "high"
 *   30–59  → "medium"
 *   1–29   → "low"
 *   0      → "none"
 */
export function correlatedSeverityFromScore(score: number): CorrelatedSeverity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  if (score > 0) return "low";
  return "none";
}

// ---------------------------------------------------------------------------
// Main export — correlateEpssWithMalware
// ---------------------------------------------------------------------------

/**
 * Correlate an advisory's CVSS / EPSS / CISA KEV signals with optional
 * malware-engine detection results to produce a deterministic composite
 * risk score [0–100].
 *
 * Algorithm (additive, all terms are non-negative):
 *   1. `cvssFloor(advisory.cvssV3Score)`              → base floor
 *   2. `epssBoostPoints(advisory.epssPercentile)`     → EPSS boost
 *   3. `cisaKevBoostPoints(advisory.cisaKev)`         → KEV boost
 *   4. `malwareSignalBoostPoints(malwareSignals)`     → detection boost
 *   5. `Math.min(100, Math.max(0, sum))`              → clamped final score
 *
 * @param advisory       The CVE advisory to enrich.
 * @param malwareSignals Optional per-analyzer detection results.  Pass the
 *                       `malwareDetectionResults` array from a `BinaryAnalysis`
 *                       when the binary is suspected to contain exploit payloads
 *                       for this CVE.
 * @returns              Deterministic `EnrichedAdvisory` with full breakdown.
 */
export function correlateEpssWithMalware(
  advisory: Advisory,
  malwareSignals?: MalwareDetectionResult[]
): EnrichedAdvisory {
  const floor = cvssFloor(advisory.cvssV3Score);
  const epss = epssBoostPoints(advisory.epssPercentile);
  const kev = cisaKevBoostPoints(advisory.cisaKev);
  const { boost: malwareBoost, matchedAnalyzers } = malwareSignalBoostPoints(malwareSignals);

  const raw = floor + epss + kev + malwareBoost;
  const finalScore = Math.min(100, Math.max(0, raw));

  const scoreBreakdown: CorrelationBreakdown = {
    cvssFloor: floor,
    epssBoost: epss,
    cisaKevBoost: kev,
    malwareSignalBoost: malwareBoost,
    finalScore
  };

  return {
    ...advisory,
    correlatedScore: finalScore,
    correlatedSeverity: correlatedSeverityFromScore(finalScore),
    scoreBreakdown,
    matchedMalwareAnalyzers: matchedAnalyzers,
    correlatedAt: new Date().toISOString()
  };
}
