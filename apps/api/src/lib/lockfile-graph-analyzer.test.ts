import { describe, expect, it } from "vitest";

import {
  analyzeLockfileGraph,
  buildNpmLockfileGraph,
  buildPnpmLockfileGraph,
  buildRequirementsTxtGraph,
  detectCircularDependencies,
  detectOrphanedDeps,
} from "./lockfile-graph-analyzer";
import type { DepNode } from "./lockfile-graph-analyzer";
import { app } from "../app";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNode(
  name: string,
  deps: string[] = [],
  riskScore?: number,
  ecosystem: DepNode["ecosystem"] = "npm"
): DepNode {
  return { name, version: "1.0.0", ecosystem, deps, riskScore };
}

// ---------------------------------------------------------------------------
// 1. Empty graph
// ---------------------------------------------------------------------------

describe("analyzeLockfileGraph — empty graph", () => {
  it("returns zero totals for empty node list", () => {
    const result = analyzeLockfileGraph([]);
    expect(result.totalPackages).toBe(0);
    expect(result.maxTransitiveRisk).toBe(0);
    expect(result.circularDeps).toHaveLength(0);
    expect(result.orphanedDeps).toHaveLength(0);
    expect(result.auditSummary).toMatch(/empty/i);
  });
});

// ---------------------------------------------------------------------------
// 2. Simple linear chain — no cycles, no orphans
// ---------------------------------------------------------------------------

describe("analyzeLockfileGraph — linear chain", () => {
  it("computes max transitive risk across a chain", () => {
    // A → B → C; C has the highest risk score
    const nodes: DepNode[] = [
      makeNode("A", ["B"], 10),
      makeNode("B", ["C"], 20),
      makeNode("C", [], 80),
    ];
    const result = analyzeLockfileGraph(nodes, ["A"]);
    expect(result.totalPackages).toBe(3);
    expect(result.maxTransitiveRisk).toBe(80);
    expect(result.circularDeps).toHaveLength(0);
    expect(result.orphanedDeps).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 3. Direct circular dependency A ↔ B
// ---------------------------------------------------------------------------

describe("detectCircularDependencies — simple cycle", () => {
  it("detects A → B → A cycle", () => {
    const nodes: DepNode[] = [
      makeNode("A", ["B"]),
      makeNode("B", ["A"]),
    ];
    const result = analyzeLockfileGraph(nodes, ["A"]);
    expect(result.circularDeps.length).toBeGreaterThanOrEqual(1);
    const involvedNames = result.circularDeps.flatMap((c) => c.chain);
    expect(involvedNames).toContain("A");
    expect(involvedNames).toContain("B");
  });
});

// ---------------------------------------------------------------------------
// 4. Multi-node cycle A → B → C → A
// ---------------------------------------------------------------------------

describe("detectCircularDependencies — three-node cycle", () => {
  it("detects A → B → C → A cycle", () => {
    const nodes: DepNode[] = [
      makeNode("A", ["B"]),
      makeNode("B", ["C"]),
      makeNode("C", ["A"]),
    ];
    const result = analyzeLockfileGraph(nodes, ["A"]);
    expect(result.circularDeps.length).toBeGreaterThanOrEqual(1);
    const allChainNames = result.circularDeps.flatMap((c) => c.chain);
    expect(allChainNames).toContain("A");
    expect(allChainNames).toContain("B");
    expect(allChainNames).toContain("C");
  });
});

// ---------------------------------------------------------------------------
// 5. Orphaned dependency detection
// ---------------------------------------------------------------------------

describe("detectOrphanedDeps", () => {
  it("identifies packages unreferenced by any other node", () => {
    // A and B are direct deps; C is in the graph but not referenced
    const nodes: DepNode[] = [
      makeNode("A", []),
      makeNode("B", []),
      makeNode("C", []), // orphan — not in directDeps and nobody depends on it
    ];
    const orphans = detectOrphanedDeps(nodes, ["A", "B"]);
    expect(orphans).toContain("C");
    expect(orphans).not.toContain("A");
    expect(orphans).not.toContain("B");
  });

  it("does not flag nodes that are transitive deps of another node", () => {
    const nodes: DepNode[] = [
      makeNode("A", ["B"]),
      makeNode("B", []),
    ];
    const orphans = detectOrphanedDeps(nodes, ["A"]);
    expect(orphans).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 6. npm monorepo lockfile (package-lock.json v2 format)
// ---------------------------------------------------------------------------

describe("buildNpmLockfileGraph — monorepo package-lock.json v2", () => {
  const monorepoLock = {
    lockfileVersion: 2,
    packages: {
      "": { version: "1.0.0", dependencies: { lodash: "^4.0.0", express: "^4.0.0" } },
      "node_modules/lodash": { version: "4.17.21", dependencies: {} },
      "node_modules/express": {
        version: "4.18.2",
        dependencies: { "body-parser": "^1.0.0" },
      },
      "node_modules/body-parser": { version: "1.20.0", dependencies: {} },
    },
  };

  it("extracts all non-root packages", () => {
    const nodes = buildNpmLockfileGraph(monorepoLock as Record<string, unknown>);
    const names = nodes.map((n) => n.name);
    expect(names).toContain("lodash");
    expect(names).toContain("express");
    expect(names).toContain("body-parser");
    // Root entry ("") must be excluded
    expect(names.every((n) => n !== "")).toBe(true);
  });

  it("wires dep edges correctly", () => {
    const nodes = buildNpmLockfileGraph(monorepoLock as Record<string, unknown>);
    const express = nodes.find((n) => n.name === "express");
    expect(express?.deps).toContain("body-parser");
  });

  it("propagates risk scores from optional map", () => {
    const scores = new Map([["lodash", 55]]);
    const nodes = buildNpmLockfileGraph(monorepoLock as Record<string, unknown>, scores);
    const lodash = nodes.find((n) => n.name === "lodash");
    expect(lodash?.riskScore).toBe(55);
  });
});

// ---------------------------------------------------------------------------
// 7. pnpm-lock.yaml parsing
// ---------------------------------------------------------------------------

describe("buildPnpmLockfileGraph — pnpm-lock.yaml", () => {
  const pnpmContent = `
lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
  /express@4.18.2:
    resolution: {integrity: sha512-def}
  /@types/node@18.0.0:
    resolution: {integrity: sha512-ghi}
`;

  it("extracts package names and versions from packages section", () => {
    const nodes = buildPnpmLockfileGraph(pnpmContent);
    const names = nodes.map((n) => n.name);
    expect(names).toContain("lodash");
    expect(names).toContain("express");
    expect(names).toContain("@types/node");
  });

  it("sets ecosystem to pnpm", () => {
    const nodes = buildPnpmLockfileGraph(pnpmContent);
    expect(nodes.every((n) => n.ecosystem === "pnpm")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 8. requirements.txt (PyPI)
// ---------------------------------------------------------------------------

describe("buildRequirementsTxtGraph — requirements.txt", () => {
  const reqsTxt = `
# Production deps
requests==2.31.0
flask>=2.3.0
sqlalchemy~=2.0.0
pytest  # no version pin
-r other-requirements.txt
`;

  it("parses versioned and unversioned packages", () => {
    const nodes = buildRequirementsTxtGraph(reqsTxt);
    const names = nodes.map((n) => n.name);
    expect(names).toContain("requests");
    expect(names).toContain("flask");
    expect(names).toContain("sqlalchemy");
    expect(names).toContain("pytest");
  });

  it("ignores comment lines and -r directives", () => {
    const nodes = buildRequirementsTxtGraph(reqsTxt);
    expect(nodes.some((n) => n.name.startsWith("#"))).toBe(false);
    expect(nodes.some((n) => n.name.startsWith("-"))).toBe(false);
  });

  it("sets ecosystem to pypi", () => {
    const nodes = buildRequirementsTxtGraph(reqsTxt);
    expect(nodes.every((n) => n.ecosystem === "pypi")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 9. Mixed ecosystem analysis (npm + pypi nodes coexist)
// ---------------------------------------------------------------------------

describe("analyzeLockfileGraph — mixed ecosystems", () => {
  it("handles nodes from different ecosystems in one analysis", () => {
    const nodes: DepNode[] = [
      { name: "lodash", version: "4.17.21", ecosystem: "npm", deps: [], riskScore: 5 },
      { name: "requests", version: "2.31.0", ecosystem: "pypi", deps: [], riskScore: 10 },
      { name: "flask", version: "2.3.0", ecosystem: "pypi", deps: ["requests"], riskScore: 15 },
    ];
    const result = analyzeLockfileGraph(nodes, ["lodash", "flask"]);
    expect(result.totalPackages).toBe(3);
    expect(result.maxTransitiveRisk).toBe(15);
    expect(result.circularDeps).toHaveLength(0);
    expect(result.orphanedDeps).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 10. Large graph with 500+ nodes — performance + correctness
// ---------------------------------------------------------------------------

describe("analyzeLockfileGraph — large graph (500+ nodes)", () => {
  /** Generate a tree-shaped graph with no cycles and predictable risk scores. */
  function generateLargeGraph(size: number): DepNode[] {
    const nodes: DepNode[] = [];
    for (let i = 0; i < size; i++) {
      // Each node depends on nodes with higher index to avoid cycles
      const deps: string[] = [];
      if (i * 2 + 1 < size) deps.push(`pkg-${i * 2 + 1}`);
      if (i * 2 + 2 < size) deps.push(`pkg-${i * 2 + 2}`);
      nodes.push({
        name: `pkg-${i}`,
        version: "1.0.0",
        ecosystem: "npm",
        deps,
        riskScore: i % 100, // scores 0–99
      });
    }
    return nodes;
  }

  it("completes analysis on 500 nodes in reasonable time", () => {
    const nodes = generateLargeGraph(500);
    const start = Date.now();
    const result = analyzeLockfileGraph(nodes, ["pkg-0"]);
    const elapsed = Date.now() - start;

    expect(result.totalPackages).toBe(500);
    expect(elapsed).toBeLessThan(5000); // must complete in <5s
    expect(result.circularDeps).toHaveLength(0);
  });

  it("finds correct max risk in 500-node tree", () => {
    const nodes = generateLargeGraph(500);
    const result = analyzeLockfileGraph(nodes, ["pkg-0"]);
    // scores are i % 100 so max is 99
    expect(result.maxTransitiveRisk).toBe(99);
  });

  it("completes analysis on 600 nodes without stack overflow", () => {
    const nodes = generateLargeGraph(600);
    expect(() => analyzeLockfileGraph(nodes, ["pkg-0"])).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 11. POST /lockfiles/analyze API endpoint — integration tests
// ---------------------------------------------------------------------------

describe("POST /lockfiles/analyze", () => {
  const packageLockContent = JSON.stringify({
    lockfileVersion: 2,
    packages: {
      "": {},
      "node_modules/lodash": { version: "4.17.21", dependencies: {} },
      "node_modules/express": {
        version: "4.18.2",
        dependencies: { "body-parser": "^1.0.0" },
      },
      "node_modules/body-parser": { version: "1.20.0", dependencies: {} },
    },
  });

  it("returns 400 when filename is missing", async () => {
    const res = await app.request("/lockfiles/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: packageLockContent }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/filename/i);
  });

  it("returns 400 when content is missing", async () => {
    const res = await app.request("/lockfiles/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: "package-lock.json" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/content/i);
  });

  it("analyzes a valid package-lock.json and returns graph analysis", async () => {
    const res = await app.request("/lockfiles/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: "package-lock.json",
        content: packageLockContent,
        directDeps: ["lodash", "express"],
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.totalPackages).toBe(3);
    expect(typeof body.maxTransitiveRisk).toBe("number");
    expect(Array.isArray(body.circularDeps)).toBe(true);
    expect(Array.isArray(body.orphanedDeps)).toBe(true);
    expect(typeof body.auditSummary).toBe("string");
  });

  it("propagates riskScores in the response", async () => {
    const res = await app.request("/lockfiles/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: "package-lock.json",
        content: packageLockContent,
        directDeps: ["lodash", "express"],
        riskScores: { "body-parser": 72 },
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { maxTransitiveRisk: number };
    expect(body.maxTransitiveRisk).toBe(72);
  });

  it("returns 400 for an unrecognized filename with no detectable format", async () => {
    const res = await app.request("/lockfiles/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: "some-random.lock",
        content: "this is not a known lockfile format",
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/unrecognized/i);
  });

  it("handles requirements.txt via filename detection", async () => {
    const reqsContent = "requests==2.31.0\nflask>=2.3.0\n";
    const res = await app.request("/lockfiles/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: "requirements.txt",
        content: reqsContent,
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { totalPackages: number };
    expect(body.totalPackages).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 12. Circular dep detection standalone — multiple disjoint cycles
// ---------------------------------------------------------------------------

describe("detectCircularDependencies — multiple disjoint cycles", () => {
  it("detects two separate cycles in the same graph", () => {
    // Cycle 1: A → B → A
    // Cycle 2: C → D → E → C
    // Node F is acyclic
    const adj = new Map([
      ["A", new Set(["B"])],
      ["B", new Set(["A"])],
      ["C", new Set(["D"])],
      ["D", new Set(["E"])],
      ["E", new Set(["C"])],
      ["F", new Set<string>()],
    ]);

    const cycles = detectCircularDependencies(adj);
    expect(cycles.length).toBeGreaterThanOrEqual(2);

    const allNames = cycles.flatMap((c) => c.chain);
    // Both cycles should be represented
    expect(allNames.some((n) => n === "A" || n === "B")).toBe(true);
    expect(allNames.some((n) => n === "C" || n === "D" || n === "E")).toBe(true);
    // Acyclic node F should not appear in any cycle
    expect(allNames).not.toContain("F");
  });
});
