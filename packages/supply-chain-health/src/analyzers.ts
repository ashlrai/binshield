/**
 * Supply-Chain Health — Named Analyzer Classes
 *
 * Each class encapsulates one signal dimension.  All analyzers are
 * deterministic: same inputs → same outputs.  They never perform network
 * calls; callers pass pre-fetched registry metadata.
 *
 * Classes exported here:
 *   CommitVelocityAnalyzer        — commits/90-day rolling window (proxy via publish freq)
 *   ReleaseCadenceAnalyzer        — median days-between-releases
 *   ContributorTurnoverAnalyzer   — turnover fraction 0–1
 *   DependencyAgeAnalyzer         — dependency age percentile 0–100
 *   CircularDepDetector           — DFS cycle counter
 *   OrphanedDepDetector           — in-degree=0 / unreferenced dep counter
 *   ScoreAggregator               — deterministic thresholds → RiskLevel with override
 */

import type { NpmRegistryMetadata, PypiRegistryMetadata } from "./index";
import type { RiskLevel } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// CommitVelocityAnalyzer
// ---------------------------------------------------------------------------

export interface CommitVelocityResult {
  /**
   * Estimated commits per 90-day rolling window.
   * `undefined` when no time-series data is available.
   */
  commits90d: number | undefined;
  /** ISO timestamp of the most recent publish/release. */
  lastPublishedAt: string | undefined;
}

/**
 * Approximates commit velocity for npm and PyPI packages from their publish
 * history.  Neither registry exposes raw git commit counts, so the proxy
 * metric is: every release ≈ 3 commits (tag + changelog + merge).
 *
 * For packages with a linked GitHub repository the caller may override
 * `commits90d` with a value obtained from the GitHub Commits API.
 */
export class CommitVelocityAnalyzer {
  /**
   * Analyze an npm package's publish time-series.
   *
   * @param time — `meta.time` from the npm registry full document
   */
  analyzeNpm(time: Record<string, string> | undefined): CommitVelocityResult {
    if (!time) {
      return { commits90d: undefined, lastPublishedAt: undefined };
    }

    const now = Date.now();
    const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;

    const versionEntries = Object.entries(time).filter(
      ([key]) => key !== "created" && key !== "modified"
    );

    const recentVersions = versionEntries.filter(
      ([, ts]) => new Date(ts).getTime() >= ninetyDaysAgo
    );

    const allTimestamps = versionEntries
      .map(([, ts]) => new Date(ts).getTime())
      .filter((ms) => !isNaN(ms));

    const lastPublishedAt =
      allTimestamps.length > 0
        ? new Date(Math.max(...allTimestamps)).toISOString()
        : undefined;

    return {
      commits90d: recentVersions.length * 3,
      lastPublishedAt,
    };
  }

  /**
   * Analyze a PyPI package's upload history.
   *
   * @param releases — `meta.releases` from the PyPI JSON API
   */
  analyzePypi(
    releases: Record<string, Array<{ upload_time?: string }>> | undefined
  ): CommitVelocityResult {
    if (!releases) {
      return { commits90d: 0, lastPublishedAt: undefined };
    }

    const now = Date.now();
    const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;

    const allUploads = Object.values(releases)
      .flat()
      .map((f) => (f.upload_time ? new Date(f.upload_time).getTime() : NaN))
      .filter((ms) => !isNaN(ms));

    const recentUploads = allUploads.filter((ms) => ms >= ninetyDaysAgo);

    const lastPublishedAt =
      allUploads.length > 0
        ? new Date(Math.max(...allUploads)).toISOString()
        : undefined;

    return {
      commits90d: recentUploads.length * 3,
      lastPublishedAt,
    };
  }

  /**
   * Analyze a private/monorepo package that has no public publish history.
   * Returns zero velocity — callers should treat this as unmaintained unless
   * they can supply a real commit count via `commits90dOverride`.
   */
  analyzePrivate(commits90dOverride?: number): CommitVelocityResult {
    return {
      commits90d: commits90dOverride ?? 0,
      lastPublishedAt: undefined,
    };
  }
}

// ---------------------------------------------------------------------------
// ReleaseCadenceAnalyzer
// ---------------------------------------------------------------------------

export interface ReleaseCadenceResult {
  /**
   * Average (mean) number of days between consecutive releases.
   * `undefined` when fewer than 2 releases exist.
   */
  medianDaysBetweenReleases: number | undefined;
  /** Total number of releases parsed. */
  totalReleases: number;
}

/**
 * Computes release cadence metrics from an ordered list of release timestamps.
 */
export class ReleaseCadenceAnalyzer {
  /**
   * Compute from a list of ISO-8601 / Date-parseable timestamp strings.
   */
  analyze(timestamps: string[]): ReleaseCadenceResult {
    const valid = timestamps
      .map((t) => new Date(t).getTime())
      .filter((ms) => !isNaN(ms))
      .sort((a, b) => a - b);

    if (valid.length < 2) {
      return { medianDaysBetweenReleases: undefined, totalReleases: valid.length };
    }

    const gaps: number[] = [];
    for (let i = 1; i < valid.length; i++) {
      gaps.push((valid[i]! - valid[i - 1]!) / (1000 * 60 * 60 * 24));
    }

    // Use median for robustness against one-off burst releases.
    const sorted = [...gaps].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    const median =
      sorted.length % 2 === 0
        ? (sorted[mid - 1]! + sorted[mid]!) / 2
        : sorted[mid]!;

    return {
      medianDaysBetweenReleases: Math.round(median),
      totalReleases: valid.length,
    };
  }

  /** Convenience: extract timestamps from npm registry `time` map. */
  fromNpmTime(time: Record<string, string> | undefined): ReleaseCadenceResult {
    if (!time) return { medianDaysBetweenReleases: undefined, totalReleases: 0 };
    const timestamps = Object.entries(time)
      .filter(([key]) => key !== "created" && key !== "modified")
      .map(([, ts]) => ts);
    return this.analyze(timestamps);
  }

  /** Convenience: extract timestamps from PyPI releases map. */
  fromPypiReleases(
    releases: Record<string, Array<{ upload_time?: string }>> | undefined
  ): ReleaseCadenceResult {
    if (!releases) return { medianDaysBetweenReleases: undefined, totalReleases: 0 };
    const timestamps = Object.values(releases)
      .map((files) => files[0]?.upload_time)
      .filter((t): t is string => typeof t === "string");
    return this.analyze(timestamps);
  }
}

// ---------------------------------------------------------------------------
// ContributorTurnoverAnalyzer
// ---------------------------------------------------------------------------

export interface ContributorTurnoverResult {
  /**
   * Turnover fraction [0, 1].
   * 0 = no turnover, 1 = complete turnover (100 % of contributors left).
   * `undefined` when no contributor data is available.
   */
  turnoverFraction: number | undefined;
  /**
   * Number of current maintainers.
   */
  currentMaintainerCount: number;
}

/**
 * Estimates contributor turnover risk from maintainer lists.
 *
 * Precise 12-month contributor comparison requires the GitHub Contributors
 * API.  When only the current maintainer list is available (as in npm/PyPI
 * registry metadata), bus-factor is used as a proxy:
 *   - 1 maintainer → 0.9 (single-point-of-failure)
 *   - 2 maintainers → 0.6
 *   - 3 maintainers → 0.4
 *   - 4 maintainers → 0.2
 *   - 5+ maintainers → 0.0 (healthy)
 */
export class ContributorTurnoverAnalyzer {
  /** Analyze from an npm `maintainers` array. */
  analyzeNpm(
    maintainers: Array<{ name: string; email?: string }> | undefined
  ): ContributorTurnoverResult {
    const count = (maintainers ?? []).length;
    if (count === 0) {
      return { turnoverFraction: undefined, currentMaintainerCount: 0 };
    }
    return {
      turnoverFraction: this.busFactorToTurnover(count),
      currentMaintainerCount: count,
    };
  }

  /**
   * Analyze from a PyPI package info object.
   * Single non-null author/maintainer = single-point-of-failure.
   */
  analyzePypi(info: {
    author?: string | null;
    maintainer?: string | null;
  }): ContributorTurnoverResult {
    const hasAuthor = typeof info.author === "string" && info.author.trim().length > 0;
    const hasMaintainer =
      typeof info.maintainer === "string" && info.maintainer.trim().length > 0;

    if (!hasAuthor && !hasMaintainer) {
      return { turnoverFraction: undefined, currentMaintainerCount: 0 };
    }

    // Both fields set → estimate 2 contributors
    const estimatedCount = hasAuthor && hasMaintainer ? 2 : 1;
    return {
      turnoverFraction: this.busFactorToTurnover(estimatedCount),
      currentMaintainerCount: estimatedCount,
    };
  }

  /**
   * Analyze from explicit current vs. past contributor sets.
   * This is the precise version used when GitHub API data is available.
   *
   * @param currentContributors — contributor logins/emails from the last 12 months
   * @param previousContributors — contributor logins/emails from 12–24 months ago
   */
  analyzeContributorSets(
    currentContributors: string[],
    previousContributors: string[]
  ): ContributorTurnoverResult {
    if (previousContributors.length === 0) {
      return {
        turnoverFraction: undefined,
        currentMaintainerCount: currentContributors.length,
      };
    }

    const currentSet = new Set(currentContributors);
    const departed = previousContributors.filter((c) => !currentSet.has(c));
    const turnoverFraction = departed.length / previousContributors.length;

    return {
      turnoverFraction: parseFloat(turnoverFraction.toFixed(4)),
      currentMaintainerCount: currentContributors.length,
    };
  }

  private busFactorToTurnover(maintainerCount: number): number {
    if (maintainerCount <= 0) return 1.0;
    if (maintainerCount === 1) return 0.9;
    return Math.max(0, 1 - Math.min(maintainerCount / 5, 1));
  }
}

// ---------------------------------------------------------------------------
// DependencyAgeAnalyzer
// ---------------------------------------------------------------------------

export interface DependencyAgeResult {
  /**
   * Percentile rank (0–100) of this package's dependency age distribution
   * relative to ecosystem median.  Higher = older dependencies.
   * `undefined` when no dependencies are present.
   */
  agePercentile: number | undefined;
  /** Number of direct dependencies analyzed. */
  depCount: number;
  /** Number of dependencies that appear exact-pinned (likely older). */
  exactPinnedCount: number;
}

/**
 * Approximates how old a package's dependencies are using the fraction of
 * exact-pinned versions as a proxy for staleness.
 *
 * The ecosystem median for npm is approximately 20–30 % exact pins.
 * A package with 100 % exact pins is treated as p100 (oldest possible).
 */
export class DependencyAgeAnalyzer {
  /**
   * Analyze from an npm dependency map (version → semver constraint string).
   *
   * @param dependencies — `meta.versions[version].dependencies`
   */
  analyzeNpm(
    dependencies: Record<string, string> | undefined
  ): DependencyAgeResult {
    const entries = Object.values(dependencies ?? {});
    if (entries.length === 0) {
      return { agePercentile: undefined, depCount: 0, exactPinnedCount: 0 };
    }

    const exactPinned = entries.filter((v) => /^\d+\.\d+\.\d+$/.test(v));
    const agePercentile = Math.round((exactPinned.length / entries.length) * 100);

    return {
      agePercentile,
      depCount: entries.length,
      exactPinnedCount: exactPinned.length,
    };
  }

  /**
   * Analyze from a PyPI `requires_dist` list.
   * PEP 508 `==` pins are treated as exact-pinned.
   *
   * @param requiresDist — `meta.info.requires_dist`
   */
  analyzePypi(
    requiresDist: string[] | null | undefined
  ): DependencyAgeResult {
    const entries = requiresDist ?? [];
    if (entries.length === 0) {
      return { agePercentile: undefined, depCount: 0, exactPinnedCount: 0 };
    }

    const exactPinned = entries.filter((r) => /==/.test(r));
    const agePercentile = Math.round((exactPinned.length / entries.length) * 100);

    return {
      agePercentile,
      depCount: entries.length,
      exactPinnedCount: exactPinned.length,
    };
  }

  /**
   * Compute age percentile from explicit publish-date data.
   * `depPublishDates` maps dep name → ISO publish date.
   * `ecosystemMedianAge` is the ecosystem-wide median dep age in days.
   */
  analyzeFromDates(
    depPublishDates: Record<string, string>,
    ecosystemMedianAge: number
  ): DependencyAgeResult {
    const now = Date.now();
    const entries = Object.entries(depPublishDates);

    if (entries.length === 0) {
      return { agePercentile: undefined, depCount: 0, exactPinnedCount: 0 };
    }

    const ages = entries.map(([, date]) => {
      const ms = new Date(date).getTime();
      return isNaN(ms) ? 0 : Math.max(0, (now - ms) / (1000 * 60 * 60 * 24));
    });

    const avgAge = ages.reduce((a, b) => a + b, 0) / ages.length;

    // Percentile relative to ecosystem median (logistic-style capping at 100)
    const rawPercentile = ecosystemMedianAge > 0
      ? Math.min(100, Math.round((avgAge / ecosystemMedianAge) * 50))
      : 50;

    return {
      agePercentile: rawPercentile,
      depCount: entries.length,
      exactPinnedCount: 0,
    };
  }
}

// ---------------------------------------------------------------------------
// CircularDepDetector
// ---------------------------------------------------------------------------

export interface CircularDepResult {
  /** Number of distinct cycles detected. */
  cycleCount: number;
  /** Node names involved in at least one cycle. */
  cycleNodes: string[];
  /** Representative cycle paths (one per detected cycle, up to 10). */
  cyclePaths: string[][];
}

/**
 * Detects circular dependencies in a package dependency graph using iterative
 * DFS with a visited/in-stack set.
 *
 * The graph is represented as `Record<packageName, string[]>` where each
 * value is the list of direct dependency names for that package.
 *
 * Algorithm: Johnson's algorithm simplified — a full cycle enumeration is
 * bounded to MAX_CYCLES to prevent combinatorial explosion on large graphs.
 */
export class CircularDepDetector {
  private static readonly MAX_CYCLES = 50;

  /**
   * Find all cycles in the given dependency graph.
   */
  detect(depGraph: Record<string, string[]>): CircularDepResult {
    const visited = new Set<string>();
    const inStack = new Set<string>();
    const cycleNodes = new Set<string>();
    const cyclePaths: string[][] = [];

    const dfs = (node: string, path: string[]): void => {
      if (cyclePaths.length >= CircularDepDetector.MAX_CYCLES) return;

      if (inStack.has(node)) {
        // Found a cycle — extract the cycle portion of the current path
        const cycleStart = path.indexOf(node);
        if (cycleStart !== -1) {
          const cycle = path.slice(cycleStart);
          cyclePaths.push([...cycle, node]);
          for (const n of cycle) cycleNodes.add(n);
        }
        return;
      }

      if (visited.has(node)) return;

      visited.add(node);
      inStack.add(node);
      path.push(node);

      for (const neighbor of depGraph[node] ?? []) {
        if (cyclePaths.length >= CircularDepDetector.MAX_CYCLES) break;
        dfs(neighbor, path);
      }

      path.pop();
      inStack.delete(node);
    };

    for (const node of Object.keys(depGraph)) {
      if (!visited.has(node)) {
        dfs(node, []);
      }
    }

    return {
      cycleCount: cyclePaths.length,
      cycleNodes: Array.from(cycleNodes),
      cyclePaths,
    };
  }

  /**
   * Quick boolean test — does the given graph contain any cycle?
   */
  hasCycles(depGraph: Record<string, string[]>): boolean {
    return this.detect(depGraph).cycleCount > 0;
  }

  /**
   * Compute transitive impact score for cyclic nodes: the fraction of all
   * graph nodes that are reachable from (or reach) a cyclic node.
   * Returns 0 when there are no cycles.
   */
  transitiveImpactScore(depGraph: Record<string, string[]>): number {
    const result = this.detect(depGraph);
    if (result.cycleCount === 0) return 0;

    const total = Object.keys(depGraph).length;
    if (total === 0) return 0;

    const cycleNodeSet = new Set(result.cycleNodes);

    // BFS to find all nodes reachable from any cyclic node
    const affected = new Set<string>(cycleNodeSet);
    const queue = [...cycleNodeSet];
    while (queue.length > 0) {
      const node = queue.shift()!;
      for (const neighbor of depGraph[node] ?? []) {
        if (!affected.has(neighbor)) {
          affected.add(neighbor);
          queue.push(neighbor);
        }
      }
    }

    return affected.size / total;
  }
}

// ---------------------------------------------------------------------------
// OrphanedDepDetector
// ---------------------------------------------------------------------------

export interface OrphanedDepResult {
  /**
   * Package names that appear in `allDeps` but are never referenced by any
   * other package in the graph AND are not listed in `directDeps`.
   */
  orphanedPackages: string[];
  /** Total count of orphaned packages. */
  orphanCount: number;
}

/**
 * Detects orphaned (unreferenced) dependencies in a flat dependency graph.
 *
 * A dependency D is "orphaned" when:
 *   1. It appears as a key in `depGraph` (it is a known package), AND
 *   2. It is NOT listed in `directDeps` (the package under analysis does not
 *      directly depend on it), AND
 *   3. No other package in `depGraph` lists it as a dependency.
 *
 * This matches packages that ended up in node_modules / site-packages but
 * are never actually imported — dead weight that expands the attack surface.
 */
export class OrphanedDepDetector {
  /**
   * Detect orphaned dependencies.
   *
   * @param directDeps — dependencies declared by the package under analysis
   * @param depGraph — full graph: all known packages and their own direct deps
   */
  detect(
    directDeps: string[],
    depGraph: Record<string, string[]>
  ): OrphanedDepResult {
    // Build the union of all referenced packages
    const referenced = new Set<string>(directDeps);
    for (const transitiveDeps of Object.values(depGraph)) {
      for (const dep of transitiveDeps) {
        referenced.add(dep);
      }
    }

    // Packages in the graph that are never referenced
    const orphaned = Object.keys(depGraph).filter((pkg) => !referenced.has(pkg));

    return {
      orphanedPackages: orphaned,
      orphanCount: orphaned.length,
    };
  }

  /**
   * Compute the transitive reverse-dependent count for each dep in the graph.
   * A dep with reverse-dependent count = 0 and in-degree = 0 is definitively
   * orphaned (no one needs it).
   */
  reverseDependentCounts(
    depGraph: Record<string, string[]>
  ): Record<string, number> {
    const counts: Record<string, number> = {};

    // Initialise all keys to 0
    for (const pkg of Object.keys(depGraph)) {
      counts[pkg] = 0;
    }

    // Count how many packages reference each dep
    for (const deps of Object.values(depGraph)) {
      for (const dep of deps) {
        if (dep in counts) {
          counts[dep]!++;
        }
      }
    }

    return counts;
  }
}

// ---------------------------------------------------------------------------
// ScoreAggregator
// ---------------------------------------------------------------------------

export interface AggregatedScore {
  /** Numeric risk score 0–100 (deterministic). */
  riskScore: number;
  /** Bucketed risk level. */
  riskLevel: RiskLevel;
  /**
   * True when the risk level was overridden by a combination rule
   * (e.g. unmaintained+orphaned → HIGH regardless of numeric score).
   */
  overridden: boolean;
  /** The override reason, if any. */
  overrideReason: string | undefined;
}

/** Signal subset needed by the aggregator. */
export interface AggregatorSignals {
  commit_velocity_90d?: number;
  release_cadence_days?: number;
  orphaned_dep_count?: number;
  circular_dep_count?: number;
  license_deprecated?: boolean;
}

/**
 * Deterministic score aggregator with combination-rule overrides.
 *
 * Combination overrides (applied after numeric scoring):
 *
 *   1. UNMAINTAINED + ORPHANED → HIGH
 *      commit_velocity_90d === 0 AND orphaned_dep_count >= 5
 *
 *   2. ABANDONED + CIRCULAR → HIGH (at minimum)
 *      No releases in 12+ months AND circular_dep_count > 0
 *
 *   3. ZERO_COMMITS + DEPRECATED_LICENSE → HIGH (at minimum)
 *      commit_velocity_90d === 0 AND license_deprecated === true
 *      (these together indicate an abandoned + legally unclear package)
 *
 * Overrides can only raise the risk level, never lower it.
 */
export class ScoreAggregator {
  /** Signal weights — must sum to ≤ 100 at max critical breach. */
  private static readonly WEIGHTS: Record<string, number> = {
    commit_velocity_90d:       20,
    release_cadence_days:      15,
    contributor_turnover:      15,
    dependency_age_percentile: 15,
    circular_dep_count:        10,
    orphaned_dep_count:        10,
    license_deprecated:        15,
  };

  private static readonly SEVERITY_MULTIPLIER: Record<string, number> = {
    critical: 1.0,
    high:     0.75,
    medium:   0.5,
    low:      0.25,
    info:     0.1,
  };

  /**
   * Aggregate raw weighted scores and apply combination overrides.
   *
   * @param weightedScore — sum of (weight × severityMultiplier) across all signals
   * @param signals — raw signal values for override rule evaluation
   */
  aggregate(
    weightedScore: number,
    signals: AggregatorSignals
  ): AggregatedScore {
    const maxPossible = Object.values(ScoreAggregator.WEIGHTS).reduce(
      (a, b) => a + b,
      0
    );

    const numericScore = Math.min(
      100,
      Math.round((weightedScore / maxPossible) * 100)
    );

    let riskLevel = this.scoreToLevel(numericScore);
    let overridden = false;
    let overrideReason: string | undefined;

    // Override 1: unmaintained (0 commits) + orphaned (5+ deps) → HIGH
    if (
      signals.commit_velocity_90d === 0 &&
      (signals.orphaned_dep_count ?? 0) >= 5
    ) {
      if (this.levelOrdinal(riskLevel) < this.levelOrdinal("high")) {
        riskLevel = "high";
        overridden = true;
        overrideReason =
          "Unmaintained package (0 commits/90d) with 5+ orphaned dependencies — risk overridden to HIGH.";
      }
    }

    // Override 2: abandoned (no releases in 12+ months) + circular deps → HIGH
    const twelveMonthsInDays = 365;
    if (
      (signals.release_cadence_days ?? 0) >= twelveMonthsInDays &&
      (signals.circular_dep_count ?? 0) > 0
    ) {
      if (this.levelOrdinal(riskLevel) < this.levelOrdinal("high")) {
        riskLevel = "high";
        overridden = true;
        overrideReason =
          "Abandoned release cadence (>12 months) combined with circular dependencies — risk overridden to HIGH.";
      }
    }

    // Override 3: zero commits + deprecated license → HIGH
    if (
      signals.commit_velocity_90d === 0 &&
      signals.license_deprecated === true
    ) {
      if (this.levelOrdinal(riskLevel) < this.levelOrdinal("high")) {
        riskLevel = "high";
        overridden = true;
        overrideReason =
          "Abandoned package (0 commits/90d) with a deprecated or missing license — risk overridden to HIGH.";
      }
    }

    return {
      riskScore: numericScore,
      riskLevel,
      overridden,
      overrideReason,
    };
  }

  private scoreToLevel(score: number): RiskLevel {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";
    if (score > 0)   return "low";
    return "none";
  }

  private levelOrdinal(level: RiskLevel): number {
    const map: Record<RiskLevel, number> = {
      none: 0, low: 1, medium: 2, high: 3, critical: 4
    };
    return map[level] ?? 0;
  }
}
