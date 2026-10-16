/**
 * Tests for named analyzer classes in @binshield/supply-chain-health.
 *
 * Covers:
 *   - CommitVelocityAnalyzer (npm, pypi, private, edge cases)
 *   - ReleaseCadenceAnalyzer (npm time map, pypi releases, edge cases)
 *   - ContributorTurnoverAnalyzer (npm, pypi, explicit contributor sets)
 *   - DependencyAgeAnalyzer (npm, pypi, date-based)
 *   - CircularDepDetector (simple cycle, multi-cycle, acyclic, transitive impact)
 *   - OrphanedDepDetector (orphans, referenced, reverse-dep counts)
 *   - ScoreAggregator (numeric bucketing, combination overrides)
 */

import { describe, it, expect } from "vitest";

import {
  CommitVelocityAnalyzer,
  ReleaseCadenceAnalyzer,
  ContributorTurnoverAnalyzer,
  DependencyAgeAnalyzer,
  CircularDepDetector,
  OrphanedDepDetector,
  ScoreAggregator,
} from "./analyzers";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function daysAgo(n: number): string {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

function yearsAgo(n: number): string {
  return daysAgo(n * 365);
}

// ---------------------------------------------------------------------------
// CommitVelocityAnalyzer
// ---------------------------------------------------------------------------

describe("CommitVelocityAnalyzer — npm", () => {
  const cva = new CommitVelocityAnalyzer();

  it("returns 0 commits when no releases in last 90 days", () => {
    const time = {
      created: yearsAgo(3),
      modified: yearsAgo(2),
      "1.0.0": yearsAgo(2),
    };
    const result = cva.analyzeNpm(time);
    expect(result.commits90d).toBe(0);
  });

  it("counts releases within 90-day window × 3", () => {
    const time = {
      created: yearsAgo(1),
      modified: new Date().toISOString(),
      "1.2.0": daysAgo(10),
      "1.1.0": daysAgo(45),
      "1.0.0": daysAgo(80),
      "0.9.0": daysAgo(120), // outside window
    };
    const result = cva.analyzeNpm(time);
    // 3 versions in 90d × 3 = 9
    expect(result.commits90d).toBe(9);
  });

  it("excludes 'created' and 'modified' keys from release count", () => {
    const time = {
      created: daysAgo(5),   // should NOT be counted
      modified: daysAgo(1),  // should NOT be counted
      "1.0.0": daysAgo(10),
    };
    const result = cva.analyzeNpm(time);
    expect(result.commits90d).toBe(3); // only 1 release × 3
  });

  it("returns undefined commits90d when time is undefined", () => {
    const result = cva.analyzeNpm(undefined);
    expect(result.commits90d).toBeUndefined();
    expect(result.lastPublishedAt).toBeUndefined();
  });

  it("returns the most recent lastPublishedAt", () => {
    const recent = daysAgo(5);
    const time = {
      created: yearsAgo(1),
      modified: recent,
      "1.0.0": daysAgo(30),
      "1.1.0": recent,
    };
    const result = cva.analyzeNpm(time);
    expect(result.lastPublishedAt).toBeDefined();
    const resultDate = new Date(result.lastPublishedAt!).getTime();
    const expectedDate = new Date(recent).getTime();
    expect(Math.abs(resultDate - expectedDate)).toBeLessThan(1000);
  });
});

describe("CommitVelocityAnalyzer — pypi", () => {
  const cva = new CommitVelocityAnalyzer();

  it("returns 0 for zero-release PyPI package", () => {
    const result = cva.analyzePypi({});
    expect(result.commits90d).toBe(0);
  });

  it("counts recent uploads × 3", () => {
    const releases = {
      "1.0.0": [{ upload_time: daysAgo(10) }],
      "0.9.0": [{ upload_time: daysAgo(50) }],
      "0.8.0": daysAgo(200) as unknown as Array<{ upload_time: string }>, // malformed
    };
    const releases2 = {
      "1.0.0": [{ upload_time: daysAgo(10) }],
      "0.9.0": [{ upload_time: daysAgo(50) }],
      "0.8.0": [{ upload_time: daysAgo(200) }], // outside window
    };
    const result = cva.analyzePypi(releases2);
    expect(result.commits90d).toBe(6);
  });

  it("handles undefined releases gracefully", () => {
    const result = cva.analyzePypi(undefined);
    expect(result.commits90d).toBe(0);
  });
});

describe("CommitVelocityAnalyzer — private", () => {
  const cva = new CommitVelocityAnalyzer();

  it("returns 0 commits for private package with no override", () => {
    const result = cva.analyzePrivate();
    expect(result.commits90d).toBe(0);
    expect(result.lastPublishedAt).toBeUndefined();
  });

  it("returns supplied override value", () => {
    const result = cva.analyzePrivate(42);
    expect(result.commits90d).toBe(42);
  });
});

// ---------------------------------------------------------------------------
// ReleaseCadenceAnalyzer
// ---------------------------------------------------------------------------

describe("ReleaseCadenceAnalyzer", () => {
  const rca = new ReleaseCadenceAnalyzer();

  it("returns undefined for empty timestamp list", () => {
    const result = rca.analyze([]);
    expect(result.medianDaysBetweenReleases).toBeUndefined();
    expect(result.totalReleases).toBe(0);
  });

  it("returns undefined for single release", () => {
    const result = rca.analyze([daysAgo(30)]);
    expect(result.medianDaysBetweenReleases).toBeUndefined();
    expect(result.totalReleases).toBe(1);
  });

  it("computes median cadence for two releases", () => {
    const result = rca.analyze([daysAgo(60), daysAgo(0)]);
    expect(result.medianDaysBetweenReleases).toBeCloseTo(60, 0);
    expect(result.totalReleases).toBe(2);
  });

  it("uses median, not mean — resistant to outlier burst releases", () => {
    // Gaps: 1, 1, 1, 365  → mean≈92, median=1
    const ts = [daysAgo(368), daysAgo(367), daysAgo(366), daysAgo(365), daysAgo(0)];
    const result = rca.analyze(ts);
    // median of [1,1,1,365] = 1
    expect(result.medianDaysBetweenReleases).toBeLessThan(10);
  });

  it("fromNpmTime extracts timestamps correctly", () => {
    const time = {
      created: yearsAgo(2),
      modified: daysAgo(0),
      "1.0.0": daysAgo(120),
      "0.9.0": daysAgo(240),
    };
    const result = rca.fromNpmTime(time);
    expect(result.totalReleases).toBe(2);
    expect(result.medianDaysBetweenReleases).toBeDefined();
  });

  it("fromNpmTime handles undefined time map", () => {
    const result = rca.fromNpmTime(undefined);
    expect(result.totalReleases).toBe(0);
    expect(result.medianDaysBetweenReleases).toBeUndefined();
  });

  it("fromPypiReleases extracts first file upload_time per version", () => {
    const releases = {
      "1.0.0": [{ upload_time: daysAgo(30) }],
      "0.9.0": [{ upload_time: daysAgo(90) }],
      "0.8.0": [{ upload_time: daysAgo(180) }],
    };
    const result = rca.fromPypiReleases(releases);
    expect(result.totalReleases).toBe(3);
    expect(result.medianDaysBetweenReleases).toBeGreaterThan(0);
  });

  it("fromPypiReleases handles undefined releases", () => {
    const result = rca.fromPypiReleases(undefined);
    expect(result.totalReleases).toBe(0);
    expect(result.medianDaysBetweenReleases).toBeUndefined();
  });

  it("ignores invalid/NaN date strings", () => {
    const result = rca.analyze(["not-a-date", "also-bad"]);
    expect(result.medianDaysBetweenReleases).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// ContributorTurnoverAnalyzer
// ---------------------------------------------------------------------------

describe("ContributorTurnoverAnalyzer — npm", () => {
  const cta = new ContributorTurnoverAnalyzer();

  it("returns high turnover (0.9) for single-maintainer package", () => {
    const result = cta.analyzeNpm([{ name: "solo" }]);
    expect(result.turnoverFraction).toBe(0.9);
    expect(result.currentMaintainerCount).toBe(1);
  });

  it("returns 0.6 for 2-maintainer package", () => {
    const result = cta.analyzeNpm([{ name: "a" }, { name: "b" }]);
    expect(result.turnoverFraction).toBeCloseTo(0.6, 5);
  });

  it("returns 0 for 5-maintainer package", () => {
    const result = cta.analyzeNpm([
      { name: "a" }, { name: "b" }, { name: "c" }, { name: "d" }, { name: "e" },
    ]);
    expect(result.turnoverFraction).toBe(0);
  });

  it("returns 0 for 10-maintainer package (capped at 5)", () => {
    const maintainers = Array.from({ length: 10 }, (_, i) => ({ name: `dev${i}` }));
    const result = cta.analyzeNpm(maintainers);
    expect(result.turnoverFraction).toBe(0);
  });

  it("returns undefined turnoverFraction for empty maintainers array", () => {
    const result = cta.analyzeNpm([]);
    expect(result.turnoverFraction).toBeUndefined();
    expect(result.currentMaintainerCount).toBe(0);
  });

  it("returns undefined for undefined maintainers", () => {
    const result = cta.analyzeNpm(undefined);
    expect(result.turnoverFraction).toBeUndefined();
  });
});

describe("ContributorTurnoverAnalyzer — pypi", () => {
  const cta = new ContributorTurnoverAnalyzer();

  it("flags single author (no maintainer) as high risk", () => {
    const result = cta.analyzePypi({ author: "Alice", maintainer: null });
    expect(result.turnoverFraction).toBe(0.9);
    expect(result.currentMaintainerCount).toBe(1);
  });

  it("estimates 2 contributors when both author and maintainer are set", () => {
    const result = cta.analyzePypi({ author: "Alice", maintainer: "Bob" });
    expect(result.currentMaintainerCount).toBe(2);
    expect(result.turnoverFraction).toBeGreaterThan(0);
    expect(result.turnoverFraction).toBeLessThan(0.9);
  });

  it("returns undefined when neither author nor maintainer is set", () => {
    const result = cta.analyzePypi({ author: null, maintainer: null });
    expect(result.turnoverFraction).toBeUndefined();
  });

  it("treats empty string author as absent", () => {
    const result = cta.analyzePypi({ author: "   ", maintainer: null });
    expect(result.turnoverFraction).toBeUndefined();
  });
});

describe("ContributorTurnoverAnalyzer — explicit contributor sets", () => {
  const cta = new ContributorTurnoverAnalyzer();

  it("computes 100% turnover when all contributors left", () => {
    const result = cta.analyzeContributorSets(["newDev"], ["alice", "bob", "carol"]);
    expect(result.turnoverFraction).toBe(1);
  });

  it("computes 0% turnover when no contributors left", () => {
    const result = cta.analyzeContributorSets(["alice", "bob"], ["alice", "bob"]);
    expect(result.turnoverFraction).toBe(0);
  });

  it("computes 50% turnover when half the contributors left", () => {
    const result = cta.analyzeContributorSets(["alice", "carol"], ["alice", "bob"]);
    expect(result.turnoverFraction).toBe(0.5);
  });

  it("returns undefined when previous contributor set is empty", () => {
    const result = cta.analyzeContributorSets(["alice"], []);
    expect(result.turnoverFraction).toBeUndefined();
  });

  it("rapid churn: new maintainer replaces original team", () => {
    const result = cta.analyzeContributorSets(
      ["hacker"],
      ["original-dev-1", "original-dev-2", "original-dev-3"]
    );
    expect(result.turnoverFraction).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// DependencyAgeAnalyzer
// ---------------------------------------------------------------------------

describe("DependencyAgeAnalyzer — npm", () => {
  const daa = new DependencyAgeAnalyzer();

  it("returns undefined agePercentile for empty dependencies", () => {
    const result = daa.analyzeNpm({});
    expect(result.agePercentile).toBeUndefined();
    expect(result.depCount).toBe(0);
  });

  it("returns 100 when all deps are exact-pinned", () => {
    const result = daa.analyzeNpm({ lodash: "4.17.21", axios: "1.0.0" });
    expect(result.agePercentile).toBe(100);
    expect(result.exactPinnedCount).toBe(2);
  });

  it("returns 0 when no deps are exact-pinned", () => {
    const result = daa.analyzeNpm({ lodash: "^4.17.21", axios: "~1.0.0" });
    expect(result.agePercentile).toBe(0);
    expect(result.exactPinnedCount).toBe(0);
  });

  it("returns 50 for half exact-pinned", () => {
    const result = daa.analyzeNpm({
      lodash: "4.17.21",  // exact
      axios: "^1.0.0",    // range
    });
    expect(result.agePercentile).toBe(50);
  });

  it("handles undefined dependencies gracefully", () => {
    const result = daa.analyzeNpm(undefined);
    expect(result.agePercentile).toBeUndefined();
    expect(result.depCount).toBe(0);
  });
});

describe("DependencyAgeAnalyzer — pypi", () => {
  const daa = new DependencyAgeAnalyzer();

  it("returns undefined agePercentile for empty requires_dist", () => {
    const result = daa.analyzePypi([]);
    expect(result.agePercentile).toBeUndefined();
  });

  it("returns undefined for null requires_dist", () => {
    const result = daa.analyzePypi(null);
    expect(result.agePercentile).toBeUndefined();
  });

  it("returns 100 when all requirements are exact-pinned (==)", () => {
    const result = daa.analyzePypi(["requests==2.0.0", "flask==1.0.0"]);
    expect(result.agePercentile).toBe(100);
    expect(result.exactPinnedCount).toBe(2);
  });

  it("returns 0 when no requirements are pinned", () => {
    const result = daa.analyzePypi(["requests>=2.0", "flask>=1.0"]);
    expect(result.agePercentile).toBe(0);
  });

  it("handles mixed exact and range requirements", () => {
    const result = daa.analyzePypi(["requests==2.0.0", "flask>=1.0"]);
    expect(result.agePercentile).toBe(50);
  });
});

describe("DependencyAgeAnalyzer — date-based", () => {
  const daa = new DependencyAgeAnalyzer();

  it("returns 50th percentile when avg age equals ecosystem median", () => {
    const result = daa.analyzeFromDates(
      { lodash: daysAgo(365) },
      730 // ecosystem median is 2 years
    );
    // avgAge=365, median=730 → percentile = round((365/730)*50) = 25
    expect(result.agePercentile).toBe(25);
  });

  it("caps at 100 when deps are very old", () => {
    const result = daa.analyzeFromDates(
      { ancient: yearsAgo(10) },
      365
    );
    expect(result.agePercentile).toBe(100);
  });

  it("returns undefined for empty dep map", () => {
    const result = daa.analyzeFromDates({}, 365);
    expect(result.agePercentile).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// CircularDepDetector
// ---------------------------------------------------------------------------

describe("CircularDepDetector", () => {
  const cdd = new CircularDepDetector();

  it("detects A→B→A simple cycle", () => {
    const result = cdd.detect({ A: ["B"], B: ["A"] });
    expect(result.cycleCount).toBeGreaterThan(0);
    expect(result.cycleNodes).toContain("A");
    expect(result.cycleNodes).toContain("B");
  });

  it("detects self-loop", () => {
    const result = cdd.detect({ A: ["A"] });
    expect(result.cycleCount).toBeGreaterThan(0);
  });

  it("detects three-node cycle A→B→C→A", () => {
    const result = cdd.detect({ A: ["B"], B: ["C"], C: ["A"] });
    expect(result.cycleCount).toBeGreaterThan(0);
    expect(result.cycleNodes.length).toBeGreaterThanOrEqual(3);
  });

  it("detects multiple independent cycles", () => {
    const graph = {
      A: ["B"], B: ["A"],   // cycle 1
      C: ["D"], D: ["C"],   // cycle 2
    };
    const result = cdd.detect(graph);
    expect(result.cycleCount).toBeGreaterThanOrEqual(2);
  });

  it("returns zero cycles for acyclic graph", () => {
    const result = cdd.detect({ A: ["B", "C"], B: ["D"], C: ["D"], D: [] });
    expect(result.cycleCount).toBe(0);
    expect(result.cycleNodes).toHaveLength(0);
  });

  it("returns zero cycles for empty graph", () => {
    const result = cdd.detect({});
    expect(result.cycleCount).toBe(0);
  });

  it("hasCycles returns true when cycles exist", () => {
    expect(cdd.hasCycles({ A: ["B"], B: ["A"] })).toBe(true);
  });

  it("hasCycles returns false for acyclic graph", () => {
    expect(cdd.hasCycles({ A: ["B"], B: [] })).toBe(false);
  });

  it("transitiveImpactScore is 0 for acyclic graph", () => {
    const score = cdd.transitiveImpactScore({ A: ["B"], B: [] });
    expect(score).toBe(0);
  });

  it("transitiveImpactScore is > 0 when cycles exist", () => {
    const score = cdd.transitiveImpactScore({ A: ["B"], B: ["A"], C: [] });
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  it("handles large isolated acyclic tree without false positives", () => {
    const graph: Record<string, string[]> = {};
    for (let i = 0; i < 20; i++) {
      graph[`pkg${i}`] = i < 10 ? [`pkg${i + 10}`] : [];
    }
    const result = cdd.detect(graph);
    expect(result.cycleCount).toBe(0);
  });

  it("deep cycle detection — 5-node ring", () => {
    const result = cdd.detect({
      A: ["B"], B: ["C"], C: ["D"], D: ["E"], E: ["A"],
    });
    expect(result.cycleCount).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// OrphanedDepDetector
// ---------------------------------------------------------------------------

describe("OrphanedDepDetector", () => {
  const odd = new OrphanedDepDetector();

  it("detects package in graph not referenced by anyone", () => {
    const result = odd.detect(["A"], { A: ["B"], B: [], ghost: [] });
    expect(result.orphanedPackages).toContain("ghost");
    expect(result.orphanCount).toBe(1);
  });

  it("does not flag deps that are referenced", () => {
    const result = odd.detect(["A"], { A: ["B"], B: ["C"], C: [] });
    expect(result.orphanCount).toBe(0);
  });

  it("does not flag direct deps as orphaned", () => {
    // "A" is listed as a direct dep, so even if nothing else references it
    // it should NOT be counted as orphaned.
    const result = odd.detect(["A"], { A: [] });
    expect(result.orphanCount).toBe(0);
  });

  it("returns empty for empty graph", () => {
    const result = odd.detect([], {});
    expect(result.orphanCount).toBe(0);
    expect(result.orphanedPackages).toHaveLength(0);
  });

  it("counts multiple orphans", () => {
    const result = odd.detect(
      ["root"],
      { root: [], orphan1: [], orphan2: [], orphan3: [] }
    );
    expect(result.orphanCount).toBe(3);
    expect(result.orphanedPackages).toContain("orphan1");
    expect(result.orphanedPackages).toContain("orphan2");
    expect(result.orphanedPackages).toContain("orphan3");
  });

  it("reverseDependentCounts gives 0 for orphans", () => {
    const counts = odd.reverseDependentCounts({
      A: ["B"],
      B: [],
      orphan: [],
    });
    expect(counts["A"]).toBe(0);
    expect(counts["B"]).toBe(1);
    expect(counts["orphan"]).toBe(0);
  });

  it("reverseDependentCounts counts shared deps correctly", () => {
    const counts = odd.reverseDependentCounts({
      A: ["shared"],
      B: ["shared"],
      shared: [],
    });
    expect(counts["shared"]).toBe(2);
    expect(counts["A"]).toBe(0);
    expect(counts["B"]).toBe(0);
  });

  it("isolated dep with in-degree=1 and no transitive reverse-deps is NOT orphaned", () => {
    // dep is referenced by root, so it has in-degree=1
    const result = odd.detect(["root"], { root: ["dep"], dep: [] });
    expect(result.orphanedPackages).not.toContain("dep");
    expect(result.orphanCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// ScoreAggregator
// ---------------------------------------------------------------------------

describe("ScoreAggregator — numeric bucketing", () => {
  const agg = new ScoreAggregator();

  it("returns none risk for 0 weighted score", () => {
    const result = agg.aggregate(0, {});
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe("none");
    expect(result.overridden).toBe(false);
  });

  it("returns low for low weighted score", () => {
    // 5 out of 100 max → 5 → low
    const result = agg.aggregate(5, {});
    expect(result.riskLevel).toBe("low");
  });

  it("returns medium for medium weighted score", () => {
    // ~30 out of 100 → medium
    const result = agg.aggregate(30, {});
    expect(result.riskLevel).toBe("medium");
  });

  it("returns high for high weighted score", () => {
    const result = agg.aggregate(55, {});
    expect(result.riskLevel).toBe("high");
  });

  it("returns critical for very high weighted score", () => {
    const result = agg.aggregate(90, {});
    expect(result.riskLevel).toBe("critical");
  });

  it("caps score at 100", () => {
    const result = agg.aggregate(999, {});
    expect(result.riskScore).toBe(100);
  });

  it("riskScore is always in range 0–100", () => {
    for (const ws of [0, 5, 25, 50, 75, 100]) {
      const r = agg.aggregate(ws, {});
      expect(r.riskScore).toBeGreaterThanOrEqual(0);
      expect(r.riskScore).toBeLessThanOrEqual(100);
    }
  });
});

describe("ScoreAggregator — combination-rule overrides", () => {
  const agg = new ScoreAggregator();

  it("override 1: unmaintained (0 commits) + 5+ orphaned → HIGH", () => {
    const result = agg.aggregate(5, {
      commit_velocity_90d: 0,
      orphaned_dep_count: 5,
    });
    expect(result.riskLevel).toBe("high");
    expect(result.overridden).toBe(true);
    expect(result.overrideReason).toContain("Unmaintained");
  });

  it("override 1 does NOT fire when fewer than 5 orphaned deps", () => {
    const result = agg.aggregate(5, {
      commit_velocity_90d: 0,
      orphaned_dep_count: 4,
    });
    expect(result.overridden).toBe(false);
  });

  it("override 1 does NOT fire when commits > 0", () => {
    const result = agg.aggregate(5, {
      commit_velocity_90d: 1,
      orphaned_dep_count: 10,
    });
    expect(result.overridden).toBe(false);
  });

  it("override 2: abandoned cadence + circular deps → HIGH", () => {
    const result = agg.aggregate(5, {
      release_cadence_days: 400, // > 365
      circular_dep_count: 1,
    });
    expect(result.riskLevel).toBe("high");
    expect(result.overridden).toBe(true);
    expect(result.overrideReason).toContain("Abandoned release cadence");
  });

  it("override 2 does NOT fire when cadence < 365 days", () => {
    const result = agg.aggregate(5, {
      release_cadence_days: 300,
      circular_dep_count: 3,
    });
    expect(result.overridden).toBe(false);
  });

  it("override 3: zero commits + deprecated license → HIGH", () => {
    const result = agg.aggregate(5, {
      commit_velocity_90d: 0,
      license_deprecated: true,
    });
    expect(result.riskLevel).toBe("high");
    expect(result.overridden).toBe(true);
    expect(result.overrideReason).toContain("deprecated");
  });

  it("override 3 does NOT fire when license is valid", () => {
    const result = agg.aggregate(5, {
      commit_velocity_90d: 0,
      license_deprecated: false,
    });
    expect(result.overridden).toBe(false);
  });

  it("override does NOT lower a score already at critical", () => {
    const result = agg.aggregate(90, {
      commit_velocity_90d: 0,
      orphaned_dep_count: 5,
    });
    // Score was already critical — override fired but level stays critical
    expect(result.riskLevel).toBe("critical");
    // The override boolean is still false because the level was already >= high
    // (override only fires when level would be RAISED)
    // Actually we need to trace the logic: critical > high so condition
    // `levelOrdinal(riskLevel) < levelOrdinal("high")` is false → no override
    expect(result.overridden).toBe(false);
  });

  it("overrideReason is undefined when no override fires", () => {
    const result = agg.aggregate(5, { commit_velocity_90d: 3 });
    expect(result.overrideReason).toBeUndefined();
  });
});
