import { describe, it, expect } from "vitest";

import {
  SupplyChainHealthAnalyzer,
  toHealthFinding,
  type NpmRegistryMetadata,
  type PypiRegistryMetadata,
  type SupplyChainSignals,
} from "./index";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeNpmMeta(overrides: Partial<NpmRegistryMetadata> = {}): NpmRegistryMetadata {
  const now = Date.now();
  // Produce ≥ 8 releases in the 90-day window (commit_velocity_90d = 24 > 20 threshold)
  // and ensure cadence < 90 days. 5 maintainers keeps contributor_turnover = 0.
  return {
    name: "test-package",
    "dist-tags": { latest: "1.0.0" },
    time: {
      created: new Date(now - 365 * 24 * 60 * 60 * 1000).toISOString(),
      modified: new Date().toISOString(),
      "1.0.0": new Date(now - 5 * 24 * 60 * 60 * 1000).toISOString(),
      "0.9.5": new Date(now - 15 * 24 * 60 * 60 * 1000).toISOString(),
      "0.9.4": new Date(now - 25 * 24 * 60 * 60 * 1000).toISOString(),
      "0.9.3": new Date(now - 35 * 24 * 60 * 60 * 1000).toISOString(),
      "0.9.2": new Date(now - 45 * 24 * 60 * 60 * 1000).toISOString(),
      "0.9.1": new Date(now - 55 * 24 * 60 * 60 * 1000).toISOString(),
      "0.9.0": new Date(now - 65 * 24 * 60 * 60 * 1000).toISOString(),
      "0.8.0": new Date(now - 75 * 24 * 60 * 60 * 1000).toISOString(),
      "0.7.0": new Date(now - 180 * 24 * 60 * 60 * 1000).toISOString(),
    },
    versions: {
      "1.0.0": {
        dependencies: { lodash: "^4.17.21", axios: "^1.0.0" },
        license: "MIT",
      },
    },
    maintainers: [{ name: "alice" }, { name: "bob" }, { name: "carol" }, { name: "dave" }, { name: "eve" }],
    license: "MIT",
    ...overrides,
  };
}

function makePypiMeta(overrides: Partial<PypiRegistryMetadata["info"]> = {}): PypiRegistryMetadata {
  const now = Date.now();
  return {
    info: {
      name: "test-package",
      version: "1.0.0",
      license: "MIT",
      requires_dist: ["requests>=2.0", "flask>=2.0"],
      author: "Alice",
      maintainer: "Bob",
      ...overrides,
    },
    releases: {
      "1.0.0": [{ upload_time: new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString() }],
      "0.9.0": [{ upload_time: new Date(now - 120 * 24 * 60 * 60 * 1000).toISOString() }],
      "0.8.0": [{ upload_time: new Date(now - 240 * 24 * 60 * 60 * 1000).toISOString() }],
    },
  };
}

const analyzer = new SupplyChainHealthAnalyzer();

// ---------------------------------------------------------------------------
// RiskLevel bucketing
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — healthy package", () => {
  it("returns none risk for a well-maintained npm package", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    expect(result.riskLevel).toBe("none");
    expect(result.riskScore).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("returns none risk for a well-maintained pypi package", () => {
    const meta = SupplyChainHealthAnalyzer.buildPypiMetadata(makePypiMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    // A package with both author and maintainer should have lower turnover
    expect(["none", "low"]).toContain(result.riskLevel);
    expect(result.riskScore).toBeLessThan(30);
  });

  it("includes correct package coordinates in result", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    expect(result.packageName).toBe("test-package");
    expect(result.version).toBe("1.0.0");
    expect(result.ecosystem).toBe("npm");
  });

  it("always includes an analyzedAt ISO timestamp", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    expect(() => new Date(result.analyzedAt)).not.toThrow();
    expect(new Date(result.analyzedAt).getFullYear()).toBeGreaterThan(2020);
  });
});

// ---------------------------------------------------------------------------
// Abandoned / zero-commit packages
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — zero-commit / abandoned packages", () => {
  it("flags a package with no recent releases as critical commit_velocity", () => {
    const now = Date.now();
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        time: {
          created: new Date(now - 3 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          modified: new Date(now - 2 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          "1.0.0": new Date(now - 2 * 365 * 24 * 60 * 60 * 1000).toISOString(),
        },
      })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    const commitFinding = result.findings.find((f) => f.signal === "commit_velocity_90d");
    expect(commitFinding).toBeDefined();
    expect(commitFinding?.severity).toBe("critical");
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it("flags very slow release cadence (>1 year)", () => {
    const now = Date.now();
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        time: {
          created: new Date(now - 4 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          modified: new Date(now - 2 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          "1.0.0": new Date(now - 1 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          "0.9.0": new Date(now - 3 * 365 * 24 * 60 * 60 * 1000).toISOString(),
        },
      })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    const cadenceFinding = result.findings.find((f) => f.signal === "release_cadence_days");
    expect(cadenceFinding).toBeDefined();
    expect(["high", "critical"]).toContain(cadenceFinding?.severity);
  });
});

// ---------------------------------------------------------------------------
// Deprecated licenses
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — deprecated licenses", () => {
  it("flags UNLICENSED as license_deprecated", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        license: "UNLICENSED",
        versions: { "1.0.0": { license: "UNLICENSED" } },
      })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    const finding = result.findings.find((f) => f.signal === "license_deprecated");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags GPL-2.0 (deprecated alias) as license_deprecated", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        license: "GPL-2.0",
        versions: { "1.0.0": { license: "GPL-2.0" } },
      })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    const finding = result.findings.find((f) => f.signal === "license_deprecated");
    expect(finding).toBeDefined();
  });

  it("flags missing license as license_deprecated", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        license: undefined,
        versions: { "1.0.0": {} },
      })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    const finding = result.findings.find((f) => f.signal === "license_deprecated");
    expect(finding).toBeDefined();
  });

  it("does NOT flag MIT as license_deprecated", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    const finding = result.findings.find((f) => f.signal === "license_deprecated");
    expect(finding).toBeUndefined();
  });

  it("flags null PyPI license as deprecated", () => {
    const meta = SupplyChainHealthAnalyzer.buildPypiMetadata(makePypiMeta({ license: null }));
    const result = analyzer.analyze(meta, "1.0.0");
    const finding = result.findings.find((f) => f.signal === "license_deprecated");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// Circular dependencies
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — circular dependencies", () => {
  it("flags a simple A→B→A cycle", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const depGraph = { A: ["B"], B: ["A"] };
    const result = analyzer.analyze(meta, "1.0.0", depGraph, ["A", "B"]);
    const finding = result.findings.find((f) => f.signal === "circular_dep_count");
    expect(finding).toBeDefined();
    expect(result.signals.circular_dep_count).toBeGreaterThan(0);
  });

  it("flags multiple circular dependency cycles", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const depGraph = { A: ["B"], B: ["A"], C: ["D"], D: ["E"], E: ["C"] };
    const result = analyzer.analyze(meta, "1.0.0", depGraph, ["A", "C"]);
    expect(result.signals.circular_dep_count).toBeGreaterThan(0);
    const finding = result.findings.find((f) => f.signal === "circular_dep_count");
    expect(finding).toBeDefined();
  });

  it("does NOT flag acyclic graph as circular", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const depGraph = { A: ["B", "C"], B: ["D"], C: ["D"], D: [] };
    const result = analyzer.analyze(meta, "1.0.0", depGraph, ["A"]);
    const finding = result.findings.find((f) => f.signal === "circular_dep_count");
    expect(finding).toBeUndefined();
    expect(result.signals.circular_dep_count).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Orphaned dependencies
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — orphaned dependencies", () => {
  it("flags packages in depGraph that are never referenced", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    // "ghost" is in the graph but not referenced by anyone
    const depGraph = { A: ["B"], B: [], ghost: [] };
    const result = analyzer.analyze(meta, "1.0.0", depGraph, ["A"]);
    expect(result.signals.orphaned_dep_count).toBeGreaterThan(0);
    const finding = result.findings.find((f) => f.signal === "orphaned_dep_count");
    expect(finding).toBeDefined();
  });

  it("does NOT flag orphans when all deps are referenced", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const depGraph = { A: ["B"], B: ["C"], C: [] };
    const result = analyzer.analyze(meta, "1.0.0", depGraph, ["A"]);
    const finding = result.findings.find((f) => f.signal === "orphaned_dep_count");
    expect(finding).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Contributor turnover / single-maintainer risk
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — contributor turnover", () => {
  it("flags single-maintainer packages as high contributor_turnover risk", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({ maintainers: [{ name: "solo-dev" }] })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    const finding = result.findings.find((f) => f.signal === "contributor_turnover");
    expect(finding).toBeDefined();
    expect(["high", "critical"]).toContain(finding?.severity);
  });

  it("does NOT flag packages with 5+ maintainers for turnover", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        maintainers: [
          { name: "alice" },
          { name: "bob" },
          { name: "carol" },
          { name: "dave" },
          { name: "eve" },
        ],
      })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    const finding = result.findings.find((f) => f.signal === "contributor_turnover");
    expect(finding).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Monorepo edge cases
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — monorepo / edge cases", () => {
  it("handles npm package with no versions map gracefully", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({ versions: undefined })
    );
    expect(() => analyzer.analyze(meta, "1.0.0")).not.toThrow();
    const result = analyzer.analyze(meta, "1.0.0");
    expect(result.riskLevel).toBeDefined();
  });

  it("handles PyPI package with no releases gracefully", () => {
    const pypiMeta: PypiRegistryMetadata = {
      info: {
        name: "zero-release-pkg",
        version: "0.0.1",
        license: "MIT",
        requires_dist: null,
        author: "Alice",
        maintainer: null,
      },
      releases: {},
    };
    const meta = SupplyChainHealthAnalyzer.buildPypiMetadata(pypiMeta);
    expect(() => analyzer.analyze(meta, "0.0.1")).not.toThrow();
    const result = analyzer.analyze(meta, "0.0.1");
    expect(result.riskLevel).toBeDefined();
  });

  it("handles empty dependency graph without crashing", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    expect(() => analyzer.analyze(meta, "1.0.0", {}, [])).not.toThrow();
  });

  it("handles a package with no time field (rare in npm)", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({ time: undefined })
    );
    expect(() => analyzer.analyze(meta, "1.0.0")).not.toThrow();
    const result = analyzer.analyze(meta, "1.0.0");
    expect(result.signals.commit_velocity_90d).toBeUndefined();
    expect(result.signals.release_cadence_days).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Deterministic scoring
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — deterministic scoring", () => {
  it("produces identical results for identical inputs", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const r1 = analyzer.analyze(meta, "1.0.0");
    const r2 = analyzer.analyze(meta, "1.0.0");
    expect(r1.riskScore).toBe(r2.riskScore);
    expect(r1.riskLevel).toBe(r2.riskLevel);
    expect(r1.findings.map((f) => f.signal).sort()).toEqual(
      r2.findings.map((f) => f.signal).sort()
    );
  });

  it("scores critical package higher than healthy package", () => {
    const healthyMeta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const healthyResult = analyzer.analyze(healthyMeta, "1.0.0");

    const now = Date.now();
    const abandonedMeta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        license: "UNLICENSED",
        versions: { "1.0.0": { license: "UNLICENSED" } },
        maintainers: [{ name: "gone" }],
        time: {
          created: new Date(now - 5 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          modified: new Date(now - 3 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          "1.0.0": new Date(now - 3 * 365 * 24 * 60 * 60 * 1000).toISOString(),
        },
      })
    );
    const abandonedResult = analyzer.analyze(abandonedMeta, "1.0.0");

    expect(abandonedResult.riskScore).toBeGreaterThan(healthyResult.riskScore);
  });

  it("returns riskScore in range 0–100", () => {
    const healthyMeta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const r = analyzer.analyze(healthyMeta, "1.0.0");
    expect(r.riskScore).toBeGreaterThanOrEqual(0);
    expect(r.riskScore).toBeLessThanOrEqual(100);
  });

  it("maps riskScore 0 to RiskLevel none", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    if (result.riskScore === 0) {
      expect(result.riskLevel).toBe("none");
    }
  });

  it("maps high riskScore to critical or high RiskLevel", () => {
    const now = Date.now();
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({
        license: "UNLICENSED",
        versions: { "1.0.0": { license: "UNLICENSED", dependencies: { a: "1.0.0", b: "2.0.0" } } },
        maintainers: [{ name: "abandoned" }],
        time: {
          created: new Date(now - 5 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          modified: new Date(now - 4 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          "1.0.0": new Date(now - 4 * 365 * 24 * 60 * 60 * 1000).toISOString(),
          "0.9.0": new Date(now - 5 * 365 * 24 * 60 * 60 * 1000).toISOString(),
        },
      })
    );
    const depGraph = { a: ["b"], b: ["a"] }; // circular
    const result = analyzer.analyze(meta, "1.0.0", depGraph, ["a", "b"]);
    expect(["high", "critical"]).toContain(result.riskLevel);
  });
});

// ---------------------------------------------------------------------------
// toHealthFinding converter
// ---------------------------------------------------------------------------

describe("toHealthFinding", () => {
  it("converts a signal finding to a SupplyChainHealthFinding", () => {
    const raw = {
      signal: "license_deprecated" as keyof SupplyChainSignals,
      severity: "high" as const,
      observed: "UNLICENSED",
      threshold: "valid OSI-approved SPDX identifier",
      detail: "Package uses a deprecated license.",
    };
    const finding = toHealthFinding(raw);
    expect(finding.title).toBe("Deprecated or missing license");
    expect(finding.severity).toBe("high");
    expect(finding.recommendation).toContain("SPDX");
    expect(finding.signal).toBe("license_deprecated");
  });

  it("includes correct recommendations for commit_velocity", () => {
    const raw = {
      signal: "commit_velocity_90d" as keyof SupplyChainSignals,
      severity: "critical" as const,
      observed: "0",
      threshold: ">20 commits/90d for healthy",
      detail: "No commits in 90 days.",
    };
    const finding = toHealthFinding(raw);
    expect(finding.recommendation).toContain("maintained");
  });
});

// ---------------------------------------------------------------------------
// PyPI-specific tests
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — PyPI", () => {
  it("extracts release cadence from PyPI releases", () => {
    const meta = SupplyChainHealthAnalyzer.buildPypiMetadata(makePypiMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    // 3 releases over ~240 days = ~120 day cadence
    expect(result.signals.release_cadence_days).toBeDefined();
    expect(result.signals.release_cadence_days).toBeGreaterThan(0);
  });

  it("handles PyPI package with exact-pinned requires_dist as older", () => {
    const meta = SupplyChainHealthAnalyzer.buildPypiMetadata(
      makePypiMeta({ requires_dist: ["requests==2.0.0", "flask==1.0.0"] })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    // All exact pins → high dependency_age_percentile
    expect(result.signals.dependency_age_percentile).toBe(100);
  });

  it("handles PyPI package with no requires_dist", () => {
    const meta = SupplyChainHealthAnalyzer.buildPypiMetadata(
      makePypiMeta({ requires_dist: null })
    );
    expect(() => analyzer.analyze(meta, "1.0.0")).not.toThrow();
    const result = analyzer.analyze(meta, "1.0.0");
    expect(result.signals.dependency_age_percentile).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Summary generation
// ---------------------------------------------------------------------------

describe("SupplyChainHealthAnalyzer — summary", () => {
  it("generates a clean summary for healthy packages", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(makeNpmMeta());
    const result = analyzer.analyze(meta, "1.0.0");
    if (result.findings.length === 0) {
      expect(result.summary).toContain("passes all supply-chain health checks");
    } else {
      expect(result.summary.length).toBeGreaterThan(10);
    }
  });

  it("generates a summary mentioning risk level for unhealthy packages", () => {
    const meta = SupplyChainHealthAnalyzer.buildNpmMetadata(
      makeNpmMeta({ license: "UNLICENSED", maintainers: [{ name: "solo" }] })
    );
    const result = analyzer.analyze(meta, "1.0.0");
    if (result.findings.length > 0) {
      expect(result.summary).toMatch(/risk/i);
    }
  });
});
