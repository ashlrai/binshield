import type {
  BehaviorSignal,
  BehaviorSummary,
  BinaryAnalysis,
  Finding,
  FindingSeverity,
  ManifestAnalysis,
  PackageAnalysis,
  RiskLevel,
  ScriptFinding,
  ScriptThreatSummary
} from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Active Vulnerability — real-time CVE/EPSS/KEV input shape
// ---------------------------------------------------------------------------

/**
 * A single active vulnerability entry derived from NVD + EPSS + CISA KEV
 * feeds.  Callers populate this from `nvd-feed-ingester` / `epss-feed-ingester`
 * output and pass an array to `scoreWithActiveVulnerabilities`.
 *
 * Staleness guard: entries whose `feedUpdatedAt` is older than 30 days are
 * silently ignored by the engine.
 */
export interface ActiveVulnerability {
  /** CVE identifier, e.g. "CVE-2024-12345". */
  cveId: string;
  /**
   * EPSS percentile [0, 1].  When ≥ 0.40 a per-finding boost applies.
   * See `epssPercentileBoost()`.
   */
  epssPercentile: number;
  /** True when this CVE appears in the CISA Known Exploited Vulnerabilities catalogue. */
  isKev: boolean;
  /** Exploit maturity — only meaningful when `isKev` is true. */
  exploitMaturity?: "proof-of-concept" | "active-exploitation" | "widespread";
  /** Earliest version that fully remediates this vulnerability (semver string). */
  patchedVersion?: string;
  /**
   * True when a patch exists but the consumer's lockfile has NOT been updated.
   * False / undefined when the fix is already applied or no patch exists.
   */
  patchAvailableButUnmerged?: boolean;
  /**
   * ISO timestamp of the last feed update.  Entries older than 30 days are
   * treated as stale and excluded from scoring.
   */
  feedUpdatedAt: string;
}

/**
 * Enriched threat context appended to analysis responses.
 * Contains enough detail for a security dashboard to surface actionable items.
 */
export interface ActiveThreatContext {
  /** CVE IDs confirmed as exploited (KEV active-exploitation or widespread). */
  exploitedCVEs: string[];
  /** Number of vulnerabilities where no fix has been applied yet. */
  unfixed_count: number;
  /** Highest EPSS percentile across all active vulnerabilities [0, 1]. */
  highest_epss_pct: number;
  /**
   * Net risk adjustment vs. the base score (positive = higher risk,
   * negative = lower risk after patch credits).  Aggregated across all
   * transitive deps.
   */
  risk_adjusted_from_base: number;
}

// ---------------------------------------------------------------------------
// Staleness guard
// ---------------------------------------------------------------------------

/** Maximum feed age (ms) before an ActiveVulnerability entry is ignored. */
const MAX_FEED_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * Returns true when the vulnerability's feed data is still fresh enough
 * to affect scoring (within the last 30 days).
 */
export function isFeedFresh(vuln: ActiveVulnerability, now = Date.now()): boolean {
  const feedMs = new Date(vuln.feedUpdatedAt).getTime();
  if (isNaN(feedMs)) return false;
  return now - feedMs <= MAX_FEED_AGE_MS;
}

// ---------------------------------------------------------------------------
// Per-vulnerability boost helpers
// ---------------------------------------------------------------------------

/**
 * EPSS percentile boost for a single vulnerability.
 *
 * 40th–74th percentile → +5 pts
 * 75th–90th percentile → +15 pts  (unchanged from legacy EpssContext path)
 * > 90th percentile    → +25 pts  (unchanged from legacy EpssContext path)
 *
 * The 40–74 band is new: previously these were zero.  Moving beyond the
 * binary 0.75 threshold lets the engine reflect moderate but real exploitation
 * activity without the sudden cliff.
 */
export function epssPercentileBoost(percentile: number): number {
  if (percentile > 0.90) return 25;
  if (percentile > 0.75) return 15;
  if (percentile >= 0.40) return 5;
  return 0;
}

/**
 * CISA KEV boost for a single vulnerability (+20 for confirmed exploitation).
 * Returns 0 for proof-of-concept or when the CVE is not in KEV.
 */
export function kevBoostForVuln(vuln: ActiveVulnerability): number {
  if (!vuln.isKev) return 0;
  if (
    vuln.exploitMaturity === "active-exploitation" ||
    vuln.exploitMaturity === "widespread"
  ) {
    return 20;
  }
  return 0;
}

/**
 * Fix-availability modifier for a single vulnerability.
 *
 * No patchedVersion (no fix exists) → +10 pts
 * Patch exists but unmerged          → +5 pts
 * Patch applied (or unknown)         → 0 pts
 */
export function fixAvailabilityBoost(vuln: ActiveVulnerability): number {
  if (!vuln.patchedVersion) return 10;          // no fix exists
  if (vuln.patchAvailableButUnmerged) return 5; // fix exists, not applied
  return 0;
}

// ---------------------------------------------------------------------------
// Critical override helper
// ---------------------------------------------------------------------------

/**
 * Returns true if the vulnerability should force the risk level to "critical"
 * regardless of the numeric score.
 *
 * Condition: the CVE is in CISA KEV with active-exploitation or widespread maturity.
 */
export function shouldForceCritical(vuln: ActiveVulnerability): boolean {
  return (
    vuln.isKev &&
    (vuln.exploitMaturity === "active-exploitation" ||
      vuln.exploitMaturity === "widespread")
  );
}

// ---------------------------------------------------------------------------
// Aggregate scoring across active vulnerabilities
// ---------------------------------------------------------------------------

/**
 * Compute the total risk point adjustment contributed by a set of active
 * vulnerabilities.  Stale entries (> 30 days) are silently dropped.
 *
 * Returns { adjustment, forceCritical } where:
 *   adjustment    – net pts to add to the base score (always >= 0)
 *   forceCritical – true when at least one KEV active-exploitation/widespread
 *                   CVE is present
 */
export function activeVulnAdjustment(
  vulns: ActiveVulnerability[],
  now = Date.now()
): { adjustment: number; forceCritical: boolean } {
  const fresh = vulns.filter((v) => isFeedFresh(v, now));
  if (fresh.length === 0) return { adjustment: 0, forceCritical: false };

  let adjustment = 0;
  let forceCritical = false;

  for (const v of fresh) {
    adjustment += epssPercentileBoost(v.epssPercentile);
    adjustment += kevBoostForVuln(v);
    adjustment += fixAvailabilityBoost(v);
    if (shouldForceCritical(v)) forceCritical = true;
  }

  return { adjustment, forceCritical };
}

/**
 * Build an `ActiveThreatContext` summary from a set of active vulnerabilities.
 * `baseAdjustment` is the raw point delta computed by `activeVulnAdjustment`.
 */
export function buildActiveThreatContext(
  vulns: ActiveVulnerability[],
  baseAdjustment: number,
  now = Date.now()
): ActiveThreatContext {
  const fresh = vulns.filter((v) => isFeedFresh(v, now));

  const exploitedCVEs = fresh
    .filter((v) => shouldForceCritical(v))
    .map((v) => v.cveId);

  const unfixed_count = fresh.filter(
    (v) => !v.patchedVersion || v.patchAvailableButUnmerged
  ).length;

  const highest_epss_pct =
    fresh.length > 0
      ? Math.max(...fresh.map((v) => v.epssPercentile))
      : 0;

  return {
    exploitedCVEs,
    unfixed_count,
    highest_epss_pct,
    risk_adjusted_from_base: baseAdjustment
  };
}

// ---------------------------------------------------------------------------
// DFS transitive dependency scan
// ---------------------------------------------------------------------------

/**
 * A minimal node in a dependency graph used by `transitiveVulnScan`.
 * Both direct and transitive dependencies must be present in `deps` for the
 * scan to traverse them.
 */
export interface DepNode {
  /** Package name, e.g. "lodash". */
  name: string;
  /** Vulnerabilities that apply directly to this node. */
  vulns: ActiveVulnerability[];
  /** Names of direct dependencies (must also be keys in the graph map). */
  directDeps?: string[];
}

/**
 * Perform a depth-first scan over a dependency graph, collecting every
 * unique `ActiveVulnerability` reachable from `rootName`.
 *
 * Each unique CVE ID is included at most once even if it appears in multiple
 * transitive dependencies (de-duplicated by `cveId`).
 *
 * @param rootName  The package to start DFS from.
 * @param graph     Map of package name → DepNode.
 * @returns         Array of unique active vulnerabilities (fresh-filtered).
 */
export function transitiveVulnScan(
  rootName: string,
  graph: Map<string, DepNode>,
  now = Date.now()
): ActiveVulnerability[] {
  const visited = new Set<string>();
  const seen = new Set<string>(); // CVE de-dup
  const result: ActiveVulnerability[] = [];

  function dfs(name: string): void {
    if (visited.has(name)) return;
    visited.add(name);

    const node = graph.get(name);
    if (!node) return;

    for (const v of node.vulns) {
      if (!isFeedFresh(v, now)) continue;
      if (seen.has(v.cveId)) continue;
      seen.add(v.cveId);
      result.push(v);
    }

    for (const dep of node.directDeps ?? []) {
      dfs(dep);
    }
  }

  dfs(rootName);
  return result;
}

// ---------------------------------------------------------------------------
// High-level scorer with active vulnerabilities
// ---------------------------------------------------------------------------

/**
 * Score a package using both its static analysis (binary + manifest) and a
 * set of active vulnerabilities from real-time CVE/EPSS/KEV feeds.
 *
 * Steps:
 *   1. Compute static base score via `aggregatePackageRiskWithManifest`.
 *   2. Apply per-vulnerability adjustments (EPSS boost, KEV boost, fix penalty).
 *   3. Clamp to [0, 100].
 *   4. Override risk level to "critical" when a KEV active-exploitation CVE
 *      is present (even if the numeric score is below 80).
 *   5. Return enriched `activeThreatContext`.
 */
export function scoreWithActiveVulnerabilities(
  binaries: BinaryAnalysis[],
  manifest: ManifestAnalysis | undefined,
  activeVulnerabilities: ActiveVulnerability[],
  now = Date.now()
): {
  riskScore: number;
  riskLevel: RiskLevel;
  activeThreatContext: ActiveThreatContext;
} {
  const base = aggregatePackageRiskWithManifest(binaries, manifest);
  const { adjustment, forceCritical } = activeVulnAdjustment(activeVulnerabilities, now);
  const riskScore = normalizeRisk(base.riskScore + adjustment);

  let riskLevel: RiskLevel = riskLevelFromScore(riskScore);
  if (forceCritical && riskLevel !== "critical") {
    riskLevel = "critical";
  }

  const activeThreatContext = buildActiveThreatContext(activeVulnerabilities, adjustment, now);

  return { riskScore, riskLevel, activeThreatContext };
}

// ---------------------------------------------------------------------------
// Vendor Patch Context — intelligent risk downgrade for patched CVEs
// ---------------------------------------------------------------------------

/**
 * Per-CVE vendor patch context.  When a patched version has been released the
 * risk engine applies a -15 pt penalty to the raw score because the attack
 * surface shrinks as soon as the fix is deployed.
 *
 * daysToFix  – calendar days from CVE disclosure to patch release (0 = same-day).
 * vendorConfidence – how confident we are in the patch data:
 *   "high"   = authoritative vendor advisory (GHSA, NVD confirmed patched)
 *   "medium" = OSV-derived, may be inaccurate for multi-range vulnerabilities
 *   "low"    = inferred or community-reported, treat as provisional
 */
export interface VendorPatchContext {
  cveId: string;
  patchedVersion: string;
  daysToFix: number;
  vendorConfidence: "high" | "medium" | "low";
}

/**
 * Lockfile resolution context.
 *
 * Carries the package version that the lockfile currently pins alongside
 * whatever patched version is available.  The risk engine uses this to decide
 * whether to emit a "Patchable vulnerability" finding instead of a raw
 * CRITICAL/HIGH severity.
 */
export interface LockfileResolutionContext {
  /** The version string that appears in the lockfile today. */
  resolvedVersion: string;
  /** The earliest version that fully remediates the vulnerability. */
  patchedVersion: string;
  /** CVE ID this context belongs to. */
  cveId: string;
  /**
   * True when `resolvedVersion` is still in the vulnerable range and
   * `patchedVersion` is available but has not been pinned in the lockfile.
   */
  isUnpatched: boolean;
}

/**
 * Patch deployment correlation context.
 *
 * Links the patch availability date to ecosystem-wide adoption telemetry.
 * A patch released 90 days ago with < 5 % adoption is treated differently
 * from one released yesterday.
 */
export interface PatchDeploymentContext {
  cveId: string;
  /** ISO date when the patch was first published. */
  patchPublishedAt: string;
  /** Number of calendar days since the patch was published (computed by caller). */
  daysSincePatch: number;
  /**
   * Fraction [0, 1] of the ecosystem that has adopted the patched version,
   * e.g. 0.05 = 5 %.  undefined = unknown / not enough telemetry.
   */
  ecosystemAdoptionRate?: number;
}

// ---------------------------------------------------------------------------
// Patch penalty / adjustment helpers
// ---------------------------------------------------------------------------

/**
 * Compute the vendor-patch risk penalty.
 *
 * Returns a *negative* number (penalty) to be subtracted from the raw score:
 *   - Patch exists, high confidence → -15 pts
 *   - Patch exists, medium confidence → -10 pts
 *   - Patch exists, low confidence  →  -5 pts
 *   - No patch context              →   0 pts
 */
export function vendorPatchPenalty(patches?: VendorPatchContext[]): number {
  if (!patches || patches.length === 0) return 0;

  // Use the best-confidence patch signal available
  const best = patches.reduce<VendorPatchContext | undefined>((acc, p) => {
    if (!acc) return p;
    const rank = { high: 3, medium: 2, low: 1 } as const;
    return rank[p.vendorConfidence] > rank[acc.vendorConfidence] ? p : acc;
  }, undefined);

  if (!best) return 0;

  switch (best.vendorConfidence) {
    case "high":
      return -15;
    case "medium":
      return -10;
    case "low":
      return -5;
  }
}

/**
 * Build a MEDIUM "Patchable-Vulnerability" finding for each lockfile entry
 * where a patch is available but the lockfile has not been updated.
 *
 * The generated findings are MEDIUM rather than the raw CVE severity because
 * the existence of a patch substantially reduces risk compared to an
 * unmitigated vulnerability.
 */
export function buildLockfilePatchableFindings(resolutions?: LockfileResolutionContext[]): Finding[] {
  if (!resolutions || resolutions.length === 0) return [];

  return resolutions
    .filter((r) => r.isUnpatched)
    .map((r) => ({
      severity: "medium" as FindingSeverity,
      title: `Patchable vulnerability: ${r.cveId}`,
      description:
        `Your lockfile resolves to version ${r.resolvedVersion} which is still vulnerable to ${r.cveId}. ` +
        `A patched version (${r.patchedVersion}) is available but has not been applied.`,
      recommendation:
        `Update your lockfile to resolve ${r.cveId.split("-")[0]}/${r.cveId.split("-").slice(1).join("-")} ` +
        `to ${r.patchedVersion} or later and re-lock dependencies.`
    }));
}

/**
 * Compute a patch-deployment urgency modifier [-10, 0].
 *
 * When a patch has been available for a long time but ecosystem adoption
 * remains very low, the vulnerability is still practically exploitable —
 * return 0 (no downgrade).  When the patch is mature and widely adopted,
 * apply an additional -10 to further de-prioritise the finding.
 *
 * Urgency modifiers (applied on top of vendorPatchPenalty):
 *   daysSincePatch < 7                    → 0  (too new to judge)
 *   daysSincePatch >= 7, adoption < 5 %   → 0  (patch exists but not adopted)
 *   daysSincePatch >= 30, adoption >= 25 %→ -5  (gaining traction)
 *   daysSincePatch >= 90, adoption >= 50 %→ -10 (widely deployed)
 */
export function patchDeploymentModifier(deployment?: PatchDeploymentContext): number {
  if (!deployment) return 0;
  const { daysSincePatch, ecosystemAdoptionRate } = deployment;

  if (daysSincePatch < 7) return 0;
  if (ecosystemAdoptionRate == null || ecosystemAdoptionRate < 0.05) return 0;
  if (daysSincePatch >= 90 && ecosystemAdoptionRate >= 0.5) return -10;
  if (daysSincePatch >= 30 && ecosystemAdoptionRate >= 0.25) return -5;
  return 0;
}

const severityWeight: Record<FindingSeverity, number> = {
  info: 2,
  low: 8,
  medium: 18,
  high: 30,
  critical: 45
};

const behaviorWeight: Record<keyof BehaviorSummary, number> = {
  network: 14,
  filesystem: 4,
  process: 12,
  crypto: 3,
  obfuscation: 24,
  dataExfiltration: 28
};

/**
 * Install-script threat weights. Heavier than binary behaviors because
 * install-time RCE / credential theft is the npm/PyPI worm vector — a
 * malicious postinstall hook is strictly worse than, say, a binary that
 * merely touches the filesystem.
 */
const scriptThreatWeight: Record<keyof ScriptThreatSummary, number> = {
  installHook: 6,
  scriptInjection: 24,
  environmentTheft: 34,
  dependencyConfusion: 20,
  wiper: 40,
  reverseShell: 40,
  remoteCodeExecution: 38
};

export function scoreFindings(findings: Finding[]): number {
  return findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
}

export function scoreScriptFindings(findings: ScriptFinding[]): number {
  return findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
}

export function scoreBehaviors(behaviors: BehaviorSummary): number {
  return (Object.entries(behaviors) as [keyof BehaviorSummary, BehaviorSignal][])
    .filter(([, signal]) => signal.detected)
    .reduce((total, [key, signal]) => total + behaviorWeight[key] + Math.min(signal.details.length, 3), 0);
}

export function scoreScriptThreats(threats: ScriptThreatSummary): number {
  return (Object.entries(threats) as [keyof ScriptThreatSummary, BehaviorSignal][])
    .filter(([, signal]) => signal.detected)
    .reduce((total, [key, signal]) => total + scriptThreatWeight[key] + Math.min(signal.details.length, 3), 0);
}

export function normalizeRisk(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 80) {
    return "critical";
  }
  if (score >= 60) {
    return "high";
  }
  if (score >= 30) {
    return "medium";
  }
  if (score > 0) {
    return "low";
  }
  return "none";
}

/**
 * Optional EPSS context passed to scoreBinary / scoreManifest.
 * When epssPercentile > 0.75 the engine boosts the risk score by 15–25 pts
 * to reflect active real-world exploitation rather than theoretical severity.
 *
 * epssPercentile > 0.90 → +25 pt boost ("Exploited in the Wild")
 * epssPercentile > 0.75 → +15 pt boost ("High real-world exploit activity")
 */
export interface EpssContext {
  /** Highest EPSS percentile among all CVEs affecting this package/version [0,1] */
  maxEpssPercentile: number;
}

/**
 * CISA KEV (Known Exploited Vulnerabilities) context.
 *
 * When a package has at least one CVE confirmed by CISA as actively exploited
 * in the wild the risk engine applies a +20 pt boost and emits a dedicated
 * "CVE-Actively-Exploited-In-Wild" CRITICAL finding.
 */
export type ExploitMaturity = "proof-of-concept" | "active-exploitation" | "widespread";

export interface CisaKevContext {
  /**
   * CVE IDs that appear in the CISA KEV catalogue for this package/version,
   * keyed by CVE ID with their maturity score.
   */
  kevMatches: Array<{
    cveId: string;
    firstSeenDate: string; // ISO date, e.g. "2024-03-15"
    exploitMaturity: ExploitMaturity;
  }>;
}

/**
 * Compute the CISA KEV risk boost (0 or 20 pts).
 *
 * Returns 20 when at least one matched CVE has exploit_maturity_score of
 * 'active-exploitation' or 'widespread'. Returns 0 otherwise (includes
 * 'proof-of-concept' and no matches).
 */
export function cisaKevBoost(kev?: CisaKevContext): number {
  if (!kev || kev.kevMatches.length === 0) return 0;
  const hasActive = kev.kevMatches.some(
    (m) => m.exploitMaturity === "active-exploitation" || m.exploitMaturity === "widespread"
  );
  return hasActive ? 20 : 0;
}

/**
 * Build a CRITICAL "CVE-Actively-Exploited-In-Wild" finding for each
 * active-exploitation or widespread KEV match. These findings are injected
 * into the package-level result so they surface in reports and gate checks.
 */
export function buildCisaKevFindings(kev?: CisaKevContext): Finding[] {
  if (!kev || kev.kevMatches.length === 0) return [];

  return kev.kevMatches
    .filter((m) => m.exploitMaturity === "active-exploitation" || m.exploitMaturity === "widespread")
    .map((m) => ({
      severity: "critical" as FindingSeverity,
      title: `CVE-Actively-Exploited-In-Wild: ${m.cveId}`,
      description:
        `${m.cveId} has been confirmed by CISA as actively exploited in the wild ` +
        `(maturity: ${m.exploitMaturity}, CISA KEV date: ${m.firstSeenDate}). ` +
        `Immediate remediation is strongly advised.`,
      recommendation:
        "Upgrade or replace this package immediately. Monitor CISA KEV for patch guidance."
    }));
}

/**
 * Compute the EPSS risk boost (0 | 15 | 25) for a given EPSS context.
 * Returns 0 when no context is provided or percentile is below threshold.
 */
export function epssBoost(epss?: EpssContext): number {
  if (!epss) return 0;
  if (epss.maxEpssPercentile > 0.9) return 25;
  if (epss.maxEpssPercentile > 0.75) return 15;
  return 0;
}

/**
 * Optional behavior-correlation context passed to scoreBinary.
 *
 * When the behavior-correlation analyzer detects a coordinated attack profile
 * (e.g. Injection+Spawn, Exfil+C2, Persistence+Wiper, CryptoStealing) the
 * risk engine applies a flat +10 pt boost to reflect the elevated threat level
 * of multi-technique coordinated attacks versus single-signal detections.
 */
export interface BehaviorCorrelationContext {
  /** True when at least one coordinated attack profile fired with confidence > 0.7. */
  correlatedProfileDetected: boolean;
}

/**
 * Compute the behavior-correlation risk boost (0 or 10).
 * Returns 10 when a coordinated attack profile was detected, 0 otherwise.
 */
export function behaviorCorrelationBoost(correlation?: BehaviorCorrelationContext): number {
  return correlation?.correlatedProfileDetected ? 10 : 0;
}

export function scoreBinary(
  binary: Pick<BinaryAnalysis, "behaviors" | "findings" | "importCount" | "functionCount">,
  epss?: EpssContext,
  kev?: CisaKevContext,
  correlation?: BehaviorCorrelationContext,
  patches?: VendorPatchContext[],
  deployment?: PatchDeploymentContext
) {
  const baseScore =
    scoreFindings(binary.findings) +
    scoreBehaviors(binary.behaviors) +
    Math.min(binary.importCount / 4, 6) +
    Math.min(binary.functionCount / 20, 5);

  const score = normalizeRisk(
    baseScore +
    epssBoost(epss) +
    cisaKevBoost(kev) +
    behaviorCorrelationBoost(correlation) +
    vendorPatchPenalty(patches) +
    patchDeploymentModifier(deployment)
  );

  return {
    riskScore: score,
    riskLevel: riskLevelFromScore(score)
  };
}

/**
 * Score a manifest / install-script analysis. A confirmed known-malware match
 * forces a maximum-severity verdict — a package on a malware advisory must
 * never score "low" just because its visible script happened to look benign.
 *
 * Optional EPSS context boosts the score when the package's CVEs have a high
 * real-world exploit probability (epssPercentile > 0.75 → +15 pts,
 * epssPercentile > 0.90 → +25 pts).
 */
export function scoreManifest(
  manifest: ManifestAnalysis,
  epss?: EpssContext,
  kev?: CisaKevContext,
  patches?: VendorPatchContext[],
  deployment?: PatchDeploymentContext
): { riskScore: number; riskLevel: RiskLevel } {
  if (manifest.knownMalwareAdvisoryIds.length > 0) {
    return { riskScore: 100, riskLevel: "critical" };
  }

  const score = normalizeRisk(
    scoreScriptFindings(manifest.findings) +
    scoreScriptThreats(manifest.threats) +
    epssBoost(epss) +
    cisaKevBoost(kev) +
    vendorPatchPenalty(patches) +
    patchDeploymentModifier(deployment)
  );
  return {
    riskScore: score,
    riskLevel: riskLevelFromScore(score)
  };
}

export function aggregatePackageRisk(binaries: BinaryAnalysis[]) {
  if (binaries.length === 0) {
    return {
      riskScore: 0,
      riskLevel: "none" as RiskLevel
    };
  }

  const maxBinary = Math.max(...binaries.map((binary) => binary.riskScore));
  const averageBinary = binaries.reduce((total, binary) => total + binary.riskScore, 0) / binaries.length;
  const aggregate = normalizeRisk(maxBinary * 0.65 + averageBinary * 0.35);

  return {
    riskScore: aggregate,
    riskLevel: riskLevelFromScore(aggregate)
  };
}

/**
 * Overall package risk combining native-binary analysis with install-script
 * analysis. Uses `max` (not an average) so a clean set of binaries cannot
 * dilute a malicious install script — and vice versa. This is the change that
 * lets a no-binary supply-chain worm score above "none".
 */
export function aggregatePackageRiskWithManifest(
  binaries: BinaryAnalysis[],
  manifest?: ManifestAnalysis
): { riskScore: number; riskLevel: RiskLevel } {
  const binaryAggregate = aggregatePackageRisk(binaries);
  if (!manifest) {
    return binaryAggregate;
  }

  if (manifest.knownMalwareAdvisoryIds.length > 0) {
    return { riskScore: 100, riskLevel: "critical" };
  }

  const manifestScore = scoreManifest(manifest);
  const score = Math.max(binaryAggregate.riskScore, manifestScore.riskScore);
  return {
    riskScore: score,
    riskLevel: riskLevelFromScore(score)
  };
}

export function summarizePackage(analysis: PackageAnalysis): string {
  const behaviors = new Set<string>();
  for (const binary of analysis.binaries) {
    for (const [name, signal] of Object.entries(binary.behaviors) as [keyof BehaviorSummary, BehaviorSignal][]) {
      if (signal.detected) {
        behaviors.add(name);
      }
    }
  }

  if (analysis.manifestAnalysis) {
    for (const [name, signal] of Object.entries(analysis.manifestAnalysis.threats) as [
      keyof ScriptThreatSummary,
      BehaviorSignal
    ][]) {
      if (signal.detected) {
        behaviors.add(name);
      }
    }
  }

  const behaviorText = behaviors.size > 0 ? Array.from(behaviors).join(", ") : "no notable behaviors";
  return `${analysis.packageName}@${analysis.version} exposes ${behaviorText} with overall ${analysis.riskLevel} risk.`;
}
