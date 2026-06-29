/**
 * Lockfile-Level Dependency Graph Risk Aggregation & Circular Dep Detection
 *
 * Builds a deterministic dependency graph from a parsed lockfile and computes:
 *   - Max transitive risk score across the entire supply chain
 *   - Circular dependency chains via DFS
 *   - Orphaned dependencies (in graph but unreferenced by any other node)
 *   - Audit summary of risk signals
 *   - Patchability scores per CVE (0–100 scale)
 *   - Blocker chains showing which intermediate deps prevent a fix
 *   - Lockfile patch recommendations sorted by impact
 *
 * Designed to be pure (no I/O) and deterministic so results are reproducible
 * across runs with the same input.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single node in the lockfile dependency graph. */
export interface DepNode {
  /** Package name (scoped names like @scope/pkg are supported). */
  name: string;
  /** Resolved version string. */
  version: string;
  /** Ecosystem: npm, pypi, or pnpm. */
  ecosystem: "npm" | "pypi" | "pnpm";
  /** Direct dependency names this package declares. May be empty. */
  deps: string[];
  /**
   * Pre-computed risk score for this individual package (0–100).
   * When omitted the analyzer treats the package as having risk 0.
   */
  riskScore?: number;
  /**
   * Declared version ranges for each dependency (name → semver range string).
   * Used by the patchability analyzer to determine whether a fix version is
   * compatible with what this intermediate dep demands.
   * e.g. { "lodash": "^4.17.0", "express": ">=4.0.0 <5.0.0" }
   */
  depRanges?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Patchability / vulnerability cascade types
// ---------------------------------------------------------------------------

/**
 * Per-CVE patchability assessment.
 *
 * patchability_score 0–100:
 *   100 = latest semver satisfies all intermediate dep constraints — easy patch
 *   75  = fix exists but requires minor version bump in one dep
 *   50  = fix requires multiple dep bumps or a major version bump
 *   25  = fix is heavily constrained (many blockers or wide version gap)
 *   0   = unpatchable (fix for A requires B update, B update breaks A)
 */
export interface CvePatchabilityScore {
  /** CVE identifier, e.g. "CVE-2024-12345". */
  cveId: string;
  /** The vulnerable package name. */
  packageName: string;
  /** The version currently pinned in the lockfile. */
  currentVersion: string;
  /** The earliest version that remediates the CVE (from registry metadata). */
  fixVersion: string | null;
  /**
   * Patchability score 0–100.
   * 100 = trivially patchable (semver compatible, no blockers)
   * 0   = unpatchable (circular or mutually-conflicting constraints)
   */
  patchabilityScore: number;
  /** Human-readable explanation of the score. */
  patchabilityReason: string;
  /**
   * Whether a circular dependency prevents applying the fix.
   * e.g. fix for A requires B@2, but B@2 requires A@<1 which re-introduces the vuln.
   */
  isCircularBlock: boolean;
}

/**
 * A chain of intermediate dependencies that block applying a fix.
 * Each entry is a dep name; the last entry is the vulnerable package.
 *
 * Example: ["express", "body-parser", "qs"] means:
 *   express pins body-parser which pins qs@vulnerable
 *   To fix qs you must update body-parser, which requires updating express first.
 */
export interface BlockerChain {
  /** The CVE this blocker chain applies to. */
  cveId: string;
  /** The vulnerable package at the end of the chain. */
  vulnerablePackage: string;
  /** Ordered list of intermediate blockers culminating in the vulnerable package. */
  chain: string[];
  /** Whether any node in the chain creates a circular dependency preventing the fix. */
  hasCircularBlock: boolean;
}

/**
 * A recommended PR / lockfile update action.
 *
 * Sorted by impact: highest-patchability CVEs first (easiest wins),
 * then by estimated risk reduction (CRITICAL CVEs before HIGH).
 */
export interface LockfilePatchRecommendation {
  /** Package to update. */
  packageName: string;
  /** Current pinned version in the lockfile. */
  currentVersion: string;
  /** Recommended target version (semver bump). */
  recommendedVersion: string;
  /** CVEs that this update remediates. */
  remediatesCves: string[];
  /**
   * Predicted semver bump type based on current→recommended version delta.
   * "patch" = z bump only, "minor" = y bump, "major" = x bump.
   */
  semverBumpType: "patch" | "minor" | "major";
  /** Estimated patchability score (average across remediatesCves). */
  estimatedPatchabilityScore: number;
  /** Whether this update has any known blocker dependencies. */
  hasBlockers: boolean;
}

/** Extended result from the patchability analysis pass. */
export interface PatchabilityAnalysis {
  /** Per-CVE patchability scores. */
  patchabilityScores: CvePatchabilityScore[];
  /** Blocker chains — intermediate deps that prevent applying fixes. */
  blockerChains: BlockerChain[];
  /** Sorted PR recommendations (easiest/highest-impact first). */
  lockfilePatchRecommendations: LockfilePatchRecommendation[];
}

/**
 * Input record describing a single CVE affecting a specific package version.
 * Callers populate this from advisory-service or a pre-fetched registry query.
 */
export interface VulnFixInfo {
  /** CVE identifier. */
  cveId: string;
  /** The vulnerable package name. */
  packageName: string;
  /** The version currently pinned. */
  currentVersion: string;
  /**
   * All published versions of the package since vulnerability discovery,
   * as returned by the npm registry (or a heuristic fallback).
   * May be empty when registry metadata is unavailable.
   */
  publishedVersionsSinceVuln: string[];
  /** The CVE severity level (for sorting recommendations). */
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

/**
 * Detected circular dependency chain.  The `chain` array lists package names
 * in DFS traversal order; the last entry depends (directly or transitively)
 * on the first, forming the cycle.
 */
export interface CircularDep {
  /** Nodes involved in the cycle, in discovery order. */
  chain: string[];
}

/** Aggregated graph analysis result. */
export interface LockfileGraphAnalysis {
  /**
   * Total number of unique packages in the graph (direct + transitive).
   */
  totalPackages: number;
  /**
   * Maximum risk score found anywhere in the transitive dependency tree (0–100).
   * Models "weakest-link in supply chain" — a single high-risk transitive dep
   * elevates the overall score.
   */
  maxTransitiveRisk: number;
  /**
   * All unique circular dependency cycles detected via DFS.
   * Each entry contains the chain of package names that form the cycle.
   */
  circularDeps: CircularDep[];
  /**
   * Packages that exist in the graph but are not reachable from any direct
   * dependency or from any other package's dep list.
   *
   * Truly orphaned packages represent dead weight (removed dependency that
   * was not cleaned up from the lockfile) or potential phantom dep injection.
   */
  orphanedDeps: string[];
  /**
   * Human-readable summary of overall risk across the graph.
   */
  auditSummary: string;
  /**
   * Per-CVE patchability scores (0–100).
   * Only populated when `vulnFixInfos` is passed to `analyzeLockfileGraph`.
   */
  patchabilityScores?: CvePatchabilityScore[];
  /**
   * Blocker chains showing which intermediate deps prevent applying fixes.
   * Only populated when `vulnFixInfos` is passed to `analyzeLockfileGraph`.
   */
  blockerChains?: BlockerChain[];
  /**
   * Sorted list of recommended lockfile PRs to cut (easiest/highest-impact first).
   * Only populated when `vulnFixInfos` is passed to `analyzeLockfileGraph`.
   */
  lockfilePatchRecommendations?: LockfilePatchRecommendation[];
}

// ---------------------------------------------------------------------------
// Internal graph representation
// ---------------------------------------------------------------------------

/** Normalised adjacency map: name → set of direct dependency names. */
type AdjMap = Map<string, Set<string>>;

/**
 * Build an adjacency map from an array of DepNodes.
 * Deduplicates edges and handles missing transitive nodes gracefully
 * (a dep name that has no corresponding node is treated as a leaf).
 */
function buildAdjMap(nodes: DepNode[]): AdjMap {
  const adj: AdjMap = new Map();

  for (const node of nodes) {
    if (!adj.has(node.name)) {
      adj.set(node.name, new Set());
    }
    for (const dep of node.deps) {
      adj.get(node.name)!.add(dep);
    }
  }

  return adj;
}

// ---------------------------------------------------------------------------
// Circular dependency detection via iterative DFS
// ---------------------------------------------------------------------------

/**
 * Detect all unique circular dependency cycles in the dependency graph.
 *
 * Uses an iterative DFS with an explicit call-stack to avoid stack-overflow
 * on very deep graphs (500+ nodes).  Each unique cycle (identified by its
 * canonical sorted form) is reported at most once.
 *
 * @param adj - Adjacency map built from lockfile nodes.
 * @returns Array of unique CircularDep entries.
 */
export function detectCircularDependencies(adj: AdjMap): CircularDep[] {
  const cycles: CircularDep[] = [];
  // Canonical set to deduplicate cycles that appear from multiple start nodes
  const seenCycleKeys = new Set<string>();

  // DFS colour states
  const WHITE = 0; // unvisited
  const GRAY = 1;  // on the current path (in-stack)
  const BLACK = 2; // fully processed

  const color = new Map<string, number>();
  for (const node of adj.keys()) {
    color.set(node, WHITE);
  }

  // We use an explicit stack of frames to avoid recursion depth issues.
  // Each frame records the node and an iterator over its neighbours.
  type Frame = { node: string; path: string[]; iter: Iterator<string> };

  for (const start of adj.keys()) {
    if (color.get(start) !== WHITE) continue;

    const stack: Frame[] = [];
    stack.push({
      node: start,
      path: [start],
      iter: (adj.get(start) ?? new Set()).values(),
    });
    color.set(start, GRAY);

    while (stack.length > 0) {
      const frame = stack[stack.length - 1]!;
      const next = frame.iter.next();

      if (next.done) {
        // All neighbours processed — pop the frame
        color.set(frame.node, BLACK);
        stack.pop();
        continue;
      }

      const neighbour = next.value;

      if (color.get(neighbour) === GRAY) {
        // Back-edge: found a cycle.  Extract the cycle chain from the current path.
        const cycleStart = frame.path.indexOf(neighbour);
        const chain =
          cycleStart >= 0
            ? [...frame.path.slice(cycleStart), neighbour]
            : [...frame.path, neighbour];

        // Canonical key: sort the interior nodes so A→B→A and B→A→B map to the same key
        const key = [...chain].sort().join("|");
        if (!seenCycleKeys.has(key)) {
          seenCycleKeys.add(key);
          cycles.push({ chain });
        }
        // Do not descend into the neighbour — it is already on-stack
        continue;
      }

      if (color.get(neighbour) === BLACK) {
        // Already fully explored — no cycle through this edge
        continue;
      }

      // WHITE: push onto stack
      color.set(neighbour, GRAY);
      stack.push({
        node: neighbour,
        path: [...frame.path, neighbour],
        iter: (adj.get(neighbour) ?? new Set()).values(),
      });
    }
  }

  return cycles;
}

// ---------------------------------------------------------------------------
// Orphaned dependency detection
// ---------------------------------------------------------------------------

/**
 * Find packages that are in the graph but are never referenced by any other
 * package's direct dependency list AND are not in the set of root/direct deps.
 *
 * An orphan is a lockfile entry that:
 *   1. Has a node in the graph, AND
 *   2. Is not reachable from any other node's dep list, AND
 *   3. Is not a declared root-level direct dependency.
 *
 * @param nodes - All nodes parsed from the lockfile.
 * @param directDepNames - The top-level direct dependency names (from the
 *   root package's own dependency declarations).
 * @returns Array of orphaned package names.
 */
export function detectOrphanedDeps(nodes: DepNode[], directDepNames: string[]): string[] {
  // Build the set of all packages that ARE referenced by someone
  const referenced = new Set<string>(directDepNames);

  for (const node of nodes) {
    for (const dep of node.deps) {
      referenced.add(dep);
    }
  }

  // Any node not in `referenced` is an orphan
  const orphans: string[] = [];
  for (const node of nodes) {
    if (!referenced.has(node.name)) {
      orphans.push(node.name);
    }
  }

  return orphans;
}

// ---------------------------------------------------------------------------
// Max transitive risk aggregation
// ---------------------------------------------------------------------------

/**
 * Walk the full transitive graph from every node and return the maximum
 * individual risk score encountered.
 *
 * Uses BFS from all roots to avoid O(n²) repeated traversal.  Because we want
 * the global maximum we only need one pass over all nodes.
 */
function computeMaxTransitiveRisk(nodes: DepNode[]): number {
  let max = 0;
  for (const node of nodes) {
    const score = node.riskScore ?? 0;
    if (score > max) max = score;
  }
  return max;
}

// ---------------------------------------------------------------------------
// Audit summary builder
// ---------------------------------------------------------------------------

function buildAuditSummary(
  totalPackages: number,
  maxTransitiveRisk: number,
  circularDeps: CircularDep[],
  orphanedDeps: string[]
): string {
  const parts: string[] = [];

  parts.push(`${totalPackages} package${totalPackages !== 1 ? "s" : ""} in graph`);

  if (maxTransitiveRisk === 0) {
    parts.push("no risk scores recorded");
  } else if (maxTransitiveRisk >= 75) {
    parts.push(`CRITICAL max-transitive risk score ${maxTransitiveRisk}/100`);
  } else if (maxTransitiveRisk >= 50) {
    parts.push(`HIGH max-transitive risk score ${maxTransitiveRisk}/100`);
  } else if (maxTransitiveRisk >= 25) {
    parts.push(`MEDIUM max-transitive risk score ${maxTransitiveRisk}/100`);
  } else {
    parts.push(`LOW max-transitive risk score ${maxTransitiveRisk}/100`);
  }

  if (circularDeps.length > 0) {
    parts.push(`${circularDeps.length} circular dep${circularDeps.length !== 1 ? "s" : ""} detected`);
  } else {
    parts.push("no circular deps");
  }

  if (orphanedDeps.length > 0) {
    parts.push(`${orphanedDeps.length} orphaned dep${orphanedDeps.length !== 1 ? "s" : ""}`);
  } else {
    parts.push("no orphaned deps");
  }

  return parts.join("; ") + ".";
}

// ---------------------------------------------------------------------------
// Semver heuristics (no external dependency)
// ---------------------------------------------------------------------------

/**
 * Parse a version string into [major, minor, patch] integers.
 * Returns null when the string is not a recognisable semver triplet.
 */
function parseSemver(v: string): [number, number, number] | null {
  const clean = v.replace(/^[v=^~>=<\s]+/, "").split(/[-+]/)[0] ?? "";
  const parts = clean.split(".").map(Number);
  if (parts.length < 2 || parts.some((p) => !Number.isFinite(p) || p < 0)) return null;
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

/**
 * Compare two semver tuples.
 * Returns negative when a < b, 0 when equal, positive when a > b.
 */
function compareSemver(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Determine the semver bump type from current → target.
 * Falls back to "major" when either version is unparseable.
 */
function semverBumpType(current: string, target: string): "patch" | "minor" | "major" {
  const c = parseSemver(current);
  const t = parseSemver(target);
  if (!c || !t) return "major";
  if (t[0] !== c[0]) return "major";
  if (t[1] !== c[1]) return "minor";
  return "patch";
}

/**
 * Select the lowest version from a list that is strictly greater than `current`.
 * Returns null when no such version exists (i.e. current is already at the latest).
 */
function findMinFixVersion(current: string, candidates: string[]): string | null {
  const cur = parseSemver(current);
  if (!cur) return candidates[0] ?? null;

  let best: [number, number, number] | null = null;
  let bestStr: string | null = null;

  for (const cand of candidates) {
    const parsed = parseSemver(cand);
    if (!parsed) continue;
    if (compareSemver(parsed, cur) <= 0) continue; // not newer
    if (!best || compareSemver(parsed, best) < 0) {
      best = parsed;
      bestStr = cand;
    }
  }
  return bestStr;
}

/**
 * Check whether a version string satisfies a semver range heuristically.
 *
 * Supports the most common range operators used in npm lockfiles:
 *   ^1.2.3  — compatible (same major, >= minor.patch)
 *   ~1.2.3  — approximately (same major.minor, >= patch)
 *   >=1.0.0 — at-least
 *   >1.0.0  — strictly-greater
 *   <=2.0.0 — at-most
 *   <2.0.0  — strictly-less
 *   =1.2.3 / 1.2.3 — exact
 *   *       — any version
 *
 * When the range is a compound (space-separated or &&-joined), ALL clauses
 * must be satisfied.  When the range contains "||" we check each alternative
 * and return true if any satisfies.
 */
export function semverSatisfies(version: string, range: string): boolean {
  if (!range || range === "*" || range === "") return true;

  const v = parseSemver(version);
  if (!v) return false;

  // OR: any alternative satisfies
  if (range.includes("||")) {
    return range.split("||").some((alt) => semverSatisfies(version, alt.trim()));
  }

  // AND: all clauses must hold (space-separated or &&)
  const clauses = range.split(/\s*&&\s*|\s+/).filter(Boolean);
  if (clauses.length > 1) {
    return clauses.every((clause) => semverSatisfies(version, clause.trim()));
  }

  const r = range.trim();

  // Caret: ^X.Y.Z — same major, >= minor.patch (or for 0.x, same minor >= patch)
  const caretMatch = r.match(/^\^([^\s]+)$/);
  if (caretMatch) {
    const base = parseSemver(caretMatch[1] ?? "");
    if (!base) return true;
    if (v[0] !== base[0]) return false;
    if (base[0] === 0) {
      if (v[1] !== base[1]) return false;
      return v[2] >= base[2];
    }
    return compareSemver(v, base) >= 0;
  }

  // Tilde: ~X.Y.Z — same major.minor, >= patch
  const tildeMatch = r.match(/^~([^\s]+)$/);
  if (tildeMatch) {
    const base = parseSemver(tildeMatch[1] ?? "");
    if (!base) return true;
    if (v[0] !== base[0] || v[1] !== base[1]) return false;
    return v[2] >= base[2];
  }

  // >=, >, <=, <, =
  const opMatch = r.match(/^(>=|>|<=|<|=)([^\s]+)$/);
  if (opMatch) {
    const op = opMatch[1]!;
    const base = parseSemver(opMatch[2] ?? "");
    if (!base) return true;
    const cmp = compareSemver(v, base);
    switch (op) {
      case ">=": return cmp >= 0;
      case ">":  return cmp > 0;
      case "<=": return cmp <= 0;
      case "<":  return cmp < 0;
      case "=":  return cmp === 0;
    }
  }

  // Exact match (no operator)
  const exact = parseSemver(r);
  if (exact) return compareSemver(v, exact) === 0;

  // Unknown range — be permissive
  return true;
}

// ---------------------------------------------------------------------------
// Patchability cascade detector
// ---------------------------------------------------------------------------

/**
 * For each vulnerable package, find all intermediate dependencies in the graph
 * that have a direct or transitive edge to that package.
 *
 * Returns a map of: vulnerablePackageName → list of intermediate dep names
 * (in reverse order: closest blocker first).
 */
function findIntermediateBlockers(
  nodes: DepNode[],
  vulnerablePackageNames: Set<string>
): Map<string, string[]> {
  // Build reverse adjacency: dep → set of packages that depend on it
  const reverseAdj = new Map<string, Set<string>>();
  for (const node of nodes) {
    for (const dep of node.deps) {
      if (!reverseAdj.has(dep)) reverseAdj.set(dep, new Set());
      reverseAdj.get(dep)!.add(node.name);
    }
  }

  const result = new Map<string, string[]>();

  for (const vulnPkg of vulnerablePackageNames) {
    // BFS from the vulnerable package upward through reverse edges
    const visited = new Set<string>();
    const queue: string[] = [vulnPkg];
    const blockers: string[] = [];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      const parents = reverseAdj.get(current) ?? new Set();
      for (const parent of parents) {
        if (!visited.has(parent)) {
          blockers.push(parent);
          queue.push(parent);
        }
      }
    }

    result.set(vulnPkg, blockers);
  }

  return result;
}

/**
 * Check whether a proposed fix version for `vulnerablePackage` is compatible
 * with all intermediate blocker deps' declared version ranges for that package.
 *
 * Returns an array of blocker names that would need to be updated to accept
 * the fix version. An empty array means the fix is range-compatible.
 */
function findRangeBlockers(
  nodes: DepNode[],
  vulnerablePackage: string,
  fixVersion: string,
  intermediateBlockers: string[]
): string[] {
  const nodeMap = new Map(nodes.map((n) => [n.name, n]));
  const rangeBlockers: string[] = [];

  for (const blockerName of intermediateBlockers) {
    const blockerNode = nodeMap.get(blockerName);
    if (!blockerNode) continue;

    const declaredRange = blockerNode.depRanges?.[vulnerablePackage];
    if (!declaredRange) continue; // No range info — assume compatible

    if (!semverSatisfies(fixVersion, declaredRange)) {
      rangeBlockers.push(blockerName);
    }
  }

  return rangeBlockers;
}

/**
 * Detect whether fixing a vulnerability creates a circular patchability problem.
 *
 * A circular block exists when:
 *   - Fixing vulnPackage requires upgrading blockerDep
 *   - blockerDep's upgrade requires a downgrade of vulnPackage
 *     (i.e. blockerDep@new declares a range for vulnPackage that excludes the fix)
 *
 * This is a simplified heuristic — a full solver would require SAT/constraint
 * solving, which is outside scope.
 */
function detectCircularPatchBlock(
  nodes: DepNode[],
  vulnPackage: string,
  fixVersion: string,
  rangeBlockers: string[]
): boolean {
  if (rangeBlockers.length === 0) return false;

  const nodeMap = new Map(nodes.map((n) => [n.name, n]));

  // Check if any blocker's dep list (depRanges) would restrict vulnPackage
  // back to a range that excludes the fix version.
  for (const blocker of rangeBlockers) {
    const blockerNode = nodeMap.get(blocker);
    if (!blockerNode) continue;

    // The blocker restricts the vulnerable package's version range.
    // If that range still excludes fixVersion after "upgrading" the blocker,
    // we have a circular block (heuristic: if the blocker pins to an exact
    // version or a tight range that excludes fix, it's circular).
    const blockerRangeForVuln = blockerNode.depRanges?.[vulnPackage];
    if (blockerRangeForVuln && !semverSatisfies(fixVersion, blockerRangeForVuln)) {
      // Also check whether the graph has a cycle involving both nodes
      // (already detected by detectCircularDependencies)
      return true;
    }
  }

  return false;
}

/**
 * Compute a patchability score [0–100] for a single CVE.
 *
 * Scoring heuristic:
 *   No fix version available:            0  (unpatchable)
 *   Fix exists, circular block:          0  (unpatchable)
 *   Fix exists, range blockers > 3:      15 (very hard)
 *   Fix exists, range blockers 2–3:      30 (hard)
 *   Fix exists, range blockers 1:        50 (moderate)
 *   Fix exists, 0 blockers, major bump:  65 (minor friction)
 *   Fix exists, 0 blockers, minor bump:  85 (easy)
 *   Fix exists, 0 blockers, patch bump: 100 (trivial)
 */
function computePatchabilityScore(
  fixVersion: string | null,
  currentVersion: string,
  rangeBlockers: string[],
  isCircularBlock: boolean
): { score: number; reason: string } {
  if (!fixVersion) {
    return { score: 0, reason: "No fix version is available — vulnerability is currently unpatchable." };
  }
  if (isCircularBlock) {
    return { score: 0, reason: "Circular dependency prevents applying the fix — upgrading the vulnerable package would break its blockers, which in turn require the vulnerable version." };
  }

  const bump = semverBumpType(currentVersion, fixVersion);
  const blockerCount = rangeBlockers.length;

  if (blockerCount > 3) {
    return {
      score: 15,
      reason: `Fix requires ${blockerCount} intermediate deps to relax their version constraints (${rangeBlockers.slice(0, 3).join(", ")}, …). Very hard to patch.`
    };
  }
  if (blockerCount === 3) {
    return {
      score: 30,
      reason: `Fix requires 3 intermediate deps to update (${rangeBlockers.join(", ")}). Significant coordination needed.`
    };
  }
  if (blockerCount === 2) {
    return {
      score: 30,
      reason: `Fix requires 2 intermediate deps to update (${rangeBlockers.join(", ")}). Multiple PRs likely needed.`
    };
  }
  if (blockerCount === 1) {
    return {
      score: 50,
      reason: `Fix version ${fixVersion} is not compatible with ${rangeBlockers[0]}'s declared range — that dep must be updated first.`
    };
  }

  // No range blockers
  if (bump === "major") {
    return {
      score: 65,
      reason: `Fix requires a major version bump (${currentVersion} → ${fixVersion}). No intermediate dep blockers, but the breaking-change risk is non-trivial.`
    };
  }
  if (bump === "minor") {
    return {
      score: 85,
      reason: `Fix is a minor version bump (${currentVersion} → ${fixVersion}) with no intermediate dep blockers. Low-friction patch.`
    };
  }
  return {
    score: 100,
    reason: `Fix is a patch-level bump (${currentVersion} → ${fixVersion}) with no intermediate dep blockers. Apply immediately.`
  };
}

/**
 * Run the full vulnerability cascade patchability analysis.
 *
 * For each entry in `vulnFixInfos`:
 *   1. Find the minimum fix version from the published candidates.
 *   2. Detect intermediate blocker deps (those that declare a version range
 *      for the vulnerable package that excludes the fix version).
 *   3. Detect circular patchability blocks.
 *   4. Compute a patchability score.
 *   5. Build a blocker chain entry.
 *
 * Then aggregate all results into sorted `LockfilePatchRecommendation` entries.
 *
 * This function is pure — it performs no I/O. Callers are responsible for
 * populating `VulnFixInfo.publishedVersionsSinceVuln` from the npm registry
 * (via `advisory-service.getCveFixVersions()`).
 *
 * @param nodes         All packages from the lockfile graph.
 * @param vulnFixInfos  Per-CVE fix information from advisory-service.
 * @param circularDeps  Pre-computed circular dep chains from `detectCircularDependencies`.
 */
export function analyzePatchability(
  nodes: DepNode[],
  vulnFixInfos: VulnFixInfo[],
  circularDeps: CircularDep[]
): PatchabilityAnalysis {
  if (vulnFixInfos.length === 0) {
    return { patchabilityScores: [], blockerChains: [], lockfilePatchRecommendations: [] };
  }

  // Set of package names involved in circular dependency chains (for fast lookup)
  const circularPackages = new Set(circularDeps.flatMap((c) => c.chain));

  // Build a set of all vulnerable package names for blocker traversal
  const vulnerablePackageNames = new Set(vulnFixInfos.map((v) => v.packageName));

  // Find all intermediate blockers for each vulnerable package
  const intermediateBlockersMap = findIntermediateBlockers(nodes, vulnerablePackageNames);

  const patchabilityScores: CvePatchabilityScore[] = [];
  const blockerChains: BlockerChain[] = [];

  for (const vulnInfo of vulnFixInfos) {
    const fixVersion = findMinFixVersion(vulnInfo.currentVersion, vulnInfo.publishedVersionsSinceVuln);
    const intermediateBlockers = intermediateBlockersMap.get(vulnInfo.packageName) ?? [];

    const rangeBlockers = fixVersion
      ? findRangeBlockers(nodes, vulnInfo.packageName, fixVersion, intermediateBlockers)
      : [];

    const isCircularBlock =
      circularPackages.has(vulnInfo.packageName) &&
      (fixVersion ? detectCircularPatchBlock(nodes, vulnInfo.packageName, fixVersion, rangeBlockers) : false);

    const { score, reason } = computePatchabilityScore(
      fixVersion,
      vulnInfo.currentVersion,
      rangeBlockers,
      isCircularBlock
    );

    patchabilityScores.push({
      cveId: vulnInfo.cveId,
      packageName: vulnInfo.packageName,
      currentVersion: vulnInfo.currentVersion,
      fixVersion,
      patchabilityScore: score,
      patchabilityReason: reason,
      isCircularBlock
    });

    // Build blocker chain entry when any blockers exist
    if (rangeBlockers.length > 0 || isCircularBlock) {
      blockerChains.push({
        cveId: vulnInfo.cveId,
        vulnerablePackage: vulnInfo.packageName,
        chain: [...rangeBlockers, vulnInfo.packageName],
        hasCircularBlock: isCircularBlock
      });
    }
  }

  // Build patch recommendations: group by (packageName, recommendedVersion)
  const recMap = new Map<string, LockfilePatchRecommendation>();

  for (const ps of patchabilityScores) {
    if (!ps.fixVersion) continue;
    const key = `${ps.packageName}@${ps.fixVersion}`;
    const existing = recMap.get(key);
    if (existing) {
      existing.remediatesCves.push(ps.cveId);
      existing.estimatedPatchabilityScore = Math.round(
        (existing.estimatedPatchabilityScore + ps.patchabilityScore) / 2
      );
      if (ps.isCircularBlock || blockerChains.some((b) => b.vulnerablePackage === ps.packageName)) {
        existing.hasBlockers = true;
      }
    } else {
      recMap.set(key, {
        packageName: ps.packageName,
        currentVersion: ps.currentVersion,
        recommendedVersion: ps.fixVersion,
        remediatesCves: [ps.cveId],
        semverBumpType: semverBumpType(ps.currentVersion, ps.fixVersion),
        estimatedPatchabilityScore: ps.patchabilityScore,
        hasBlockers: ps.isCircularBlock || blockerChains.some((b) => b.vulnerablePackage === ps.packageName && b.chain.length > 1)
      });
    }
  }

  // Sort recommendations: highest patchabilityScore first (easiest wins),
  // then by severity (CRITICAL first), then alphabetically.
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const vulnSeverityMap = new Map(vulnFixInfos.map((v) => [v.packageName, v.severity ?? "LOW"]));

  const lockfilePatchRecommendations = Array.from(recMap.values()).sort((a, b) => {
    const scoreDiff = b.estimatedPatchabilityScore - a.estimatedPatchabilityScore;
    if (scoreDiff !== 0) return scoreDiff;
    const sevA = severityOrder[vulnSeverityMap.get(a.packageName) ?? "LOW"] ?? 3;
    const sevB = severityOrder[vulnSeverityMap.get(b.packageName) ?? "LOW"] ?? 3;
    if (sevA !== sevB) return sevA - sevB;
    return a.packageName.localeCompare(b.packageName);
  });

  return { patchabilityScores, blockerChains, lockfilePatchRecommendations };
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Analyze a dependency graph derived from a parsed lockfile.
 *
 * @param nodes - All packages extracted from the lockfile (direct + transitive).
 *   Each node should carry its declared dep names (not versions).
 * @param directDepNames - Names of the root package's declared direct dependencies.
 *   Used to exclude those from the orphan calculation.  Pass an empty array when
 *   all packages are considered peers (e.g. monorepo workspace roots).
 * @param vulnFixInfos - Optional per-CVE fix information used to compute
 *   patchability scores, blocker chains, and patch recommendations.  When
 *   omitted, the patchability fields of the result are undefined.
 * @returns Deterministic {@link LockfileGraphAnalysis} result.
 */
export function analyzeLockfileGraph(
  nodes: DepNode[],
  directDepNames: string[] = [],
  vulnFixInfos: VulnFixInfo[] = []
): LockfileGraphAnalysis {
  if (nodes.length === 0) {
    return {
      totalPackages: 0,
      maxTransitiveRisk: 0,
      circularDeps: [],
      orphanedDeps: [],
      auditSummary: "Empty graph — no packages to analyze.",
    };
  }

  const adj = buildAdjMap(nodes);
  const circularDeps = detectCircularDependencies(adj);
  const orphanedDeps = detectOrphanedDeps(nodes, directDepNames);
  const maxTransitiveRisk = computeMaxTransitiveRisk(nodes);
  const totalPackages = nodes.length;

  const auditSummary = buildAuditSummary(
    totalPackages,
    maxTransitiveRisk,
    circularDeps,
    orphanedDeps
  );

  const base: LockfileGraphAnalysis = {
    totalPackages,
    maxTransitiveRisk,
    circularDeps,
    orphanedDeps,
    auditSummary,
  };

  if (vulnFixInfos.length > 0) {
    const patchability = analyzePatchability(nodes, vulnFixInfos, circularDeps);
    return {
      ...base,
      patchabilityScores: patchability.patchabilityScores,
      blockerChains: patchability.blockerChains,
      lockfilePatchRecommendations: patchability.lockfilePatchRecommendations,
    };
  }

  return base;
}

// ---------------------------------------------------------------------------
// Lockfile-format-specific graph builders
// ---------------------------------------------------------------------------

/**
 * Build a DepNode array from a parsed npm package-lock.json (v2/v3 format).
 *
 * The `packages` section maps `node_modules/<name>` → metadata.
 * We extract `dependencies` from each metadata entry as the direct dep names.
 *
 * @param lockJson - Already-parsed JSON object from package-lock.json.
 * @param riskScores - Optional map of package name → risk score (0–100).
 */
export function buildNpmLockfileGraph(
  lockJson: Record<string, unknown>,
  riskScores: Map<string, number> = new Map()
): DepNode[] {
  const nodes: DepNode[] = [];

  // v2/v3: packages section
  const pkgs = lockJson.packages as Record<string, Record<string, unknown>> | undefined;
  if (pkgs && typeof pkgs === "object") {
    for (const [pkgPath, pkgData] of Object.entries(pkgs)) {
      if (pkgPath === "" || !pkgData || typeof pkgData !== "object") continue;

      const name = pkgPath
        .replace(/^node_modules\//, "")
        .replace(/\/node_modules\//g, "/");
      const version = (pkgData.version as string | undefined) ?? "unknown";

      // Collect direct dep names and their declared version ranges
      const rawDeps = pkgData.dependencies as Record<string, unknown> | undefined;
      const deps = rawDeps && typeof rawDeps === "object" ? Object.keys(rawDeps) : [];
      const depRanges: Record<string, string> = {};
      if (rawDeps && typeof rawDeps === "object") {
        for (const [depName, depRange] of Object.entries(rawDeps)) {
          if (typeof depRange === "string") depRanges[depName] = depRange;
        }
      }

      nodes.push({
        name,
        version,
        ecosystem: "npm",
        deps,
        depRanges,
        riskScore: riskScores.get(name),
      });
    }
    return nodes;
  }

  // v1: dependencies section (flat map, nested deps not expanded here)
  const depsSection = lockJson.dependencies as Record<string, Record<string, unknown>> | undefined;
  if (depsSection && typeof depsSection === "object") {
    function extractV1(
      depMap: Record<string, Record<string, unknown>>,
    ): void {
      for (const [name, data] of Object.entries(depMap)) {
        if (!data || typeof data !== "object") continue;
        const version = (data.version as string | undefined) ?? "unknown";
        const rawReqs = data.requires as Record<string, unknown> | undefined;
        const deps = rawReqs && typeof rawReqs === "object" ? Object.keys(rawReqs) : [];
        nodes.push({
          name,
          version,
          ecosystem: "npm",
          deps,
          riskScore: riskScores.get(name),
        });
        // Recurse into nested dependencies
        if (data.dependencies && typeof data.dependencies === "object") {
          extractV1(data.dependencies as Record<string, Record<string, unknown>>);
        }
      }
    }
    extractV1(depsSection);
  }

  return nodes;
}

/**
 * Build a DepNode array from a pnpm-lock.yaml string.
 *
 * Parses the `packages:` and `importers:` sections using line-level regex —
 * no YAML library dependency required.
 *
 * @param content - Raw pnpm-lock.yaml text.
 * @param riskScores - Optional map of package name → risk score (0–100).
 */
export function buildPnpmLockfileGraph(
  content: string,
  riskScores: Map<string, number> = new Map()
): DepNode[] {
  const nodes: DepNode[] = [];
  // Match package entries: optional leading "/" then name@version or name@version(...)
  const pkgRe = /^\s{2}([A-Za-z0-9@/_.-]+)@([^:\s(]+)/gm;
  let m: RegExpExecArray | null;

  while ((m = pkgRe.exec(content)) !== null) {
    const name = (m[1] ?? "").replace(/^\//, "");
    const version = m[2] ?? "unknown";
    if (!name || name.includes("(")) continue;

    nodes.push({
      name,
      version,
      ecosystem: "pnpm",
      deps: [], // pnpm-lock.yaml dep graph is complex; dep list left empty (risk-only mode)
      riskScore: riskScores.get(name),
    });
  }

  return nodes;
}

/**
 * Build a DepNode array from a requirements.txt file (PyPI).
 *
 * requirements.txt has no dependency graph — each line is a direct dep.
 * All deps are treated as peers with no transitive edges.
 *
 * @param content - Raw requirements.txt text.
 * @param riskScores - Optional map of package name → risk score (0–100).
 */
export function buildRequirementsTxtGraph(
  content: string,
  riskScores: Map<string, number> = new Map()
): DepNode[] {
  const nodes: DepNode[] = [];

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;

    const match = line.match(/^([A-Za-z0-9_.-]+)(?:[=~><!\s].*)?$/);
    if (!match?.[1]) continue;

    const name = match[1];
    const versionMatch = line.match(/[=~><]{1,2}([^\s,;]+)/);
    const version = versionMatch?.[1] ?? "unknown";

    nodes.push({
      name,
      version,
      ecosystem: "pypi",
      deps: [],
      riskScore: riskScores.get(name),
    });
  }

  return nodes;
}
