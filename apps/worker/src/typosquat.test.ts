import { describe, expect, it } from "vitest";

import { detectTyposquat, findTyposquatMatch, levenshtein, POPULAR_PACKAGES } from "./typosquat";

// ---------------------------------------------------------------------------
// Levenshtein unit tests
// ---------------------------------------------------------------------------

describe("levenshtein", () => {
  it("returns 0 for identical strings", () => {
    expect(levenshtein("lodash", "lodash")).toBe(0);
  });

  it("counts a single substitution as distance 1", () => {
    expect(levenshtein("lodash", "lodash".replace("d", "f"))).toBe(1); // "lofash"
    expect(levenshtein("react", "reaqt")).toBe(1);
  });

  it("counts a single insertion as distance 1", () => {
    expect(levenshtein("react", "reacts")).toBe(1);
    expect(levenshtein("axios", "axxios")).toBe(1);
  });

  it("counts a single deletion as distance 1", () => {
    expect(levenshtein("lodash", "lodas")).toBe(1);
    expect(levenshtein("express", "expres")).toBe(1);
  });

  it("returns 2 for two-character edit", () => {
    expect(levenshtein("lodash", "lodahs")).toBe(2); // swap last two chars
    expect(levenshtein("webpack", "webpakc")).toBe(2);
  });

  it("early-exits and returns > threshold when strings differ by more than threshold", () => {
    const d = levenshtein("lodash", "completely-different", 2);
    expect(d).toBeGreaterThan(2);
  });

  it("handles empty strings", () => {
    expect(levenshtein("", "")).toBe(0);
    expect(levenshtein("", "abc")).toBe(3);
    expect(levenshtein("abc", "")).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// findTyposquatMatch — detection logic
// ---------------------------------------------------------------------------

describe("findTyposquatMatch", () => {
  it("returns null for exact popular-package names", () => {
    expect(findTyposquatMatch("lodash")).toBeNull();
    expect(findTyposquatMatch("react")).toBeNull();
    expect(findTyposquatMatch("express")).toBeNull();
    expect(findTyposquatMatch("axios")).toBeNull();
    expect(findTyposquatMatch("webpack")).toBeNull();
  });

  it("detects edit-distance-1 variants", () => {
    const m = findTyposquatMatch("reacts"); // "react" + 's'
    expect(m).not.toBeNull();
    expect(m?.target).toBe("react");
    expect(m?.distance).toBe(1);
  });

  it("detects edit-distance-2 variants", () => {
    const m = findTyposquatMatch("lodahs"); // transpose last two letters of "lodash"
    expect(m).not.toBeNull();
    expect(m?.target).toBe("lodash");
  });

  it("detects separator variations", () => {
    // lo-dash → lodash
    const m1 = findTyposquatMatch("lo-dash");
    expect(m1).not.toBeNull();
    expect(m1?.target).toBe("lodash");
    expect(m1?.trick).toBe("separator-variation");

    // lo_dash → lodash
    const m2 = findTyposquatMatch("lo_dash");
    expect(m2).not.toBeNull();
    expect(m2?.target).toBe("lodash");
  });

  it("detects visual character substitution (0→o)", () => {
    // "axois" with '0' for 'o' → "ax0is" → normalised to "axois" → close to "axios"
    const m = findTyposquatMatch("ax0ios");
    expect(m).not.toBeNull();
  });

  it("returns null for clearly unrelated package names", () => {
    expect(findTyposquatMatch("my-company-internal-tool-xyz")).toBeNull();
    expect(findTyposquatMatch("abcdefghij-unique-pkg")).toBeNull();
    expect(findTyposquatMatch("")).toBeNull();
  });

  it("returns null for a scoped package that IS a popular package", () => {
    // @babel/core is in the popular list — should not match itself
    expect(findTyposquatMatch("@babel/core")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// detectTyposquat — ScriptFinding output
// ---------------------------------------------------------------------------

describe("detectTyposquat", () => {
  it("returns null for exact popular package names", () => {
    expect(detectTyposquat("lodash")).toBeNull();
    expect(detectTyposquat("express")).toBeNull();
    expect(detectTyposquat("react")).toBeNull();
  });

  it("returns a ScriptFinding for a typosquat candidate", () => {
    const finding = detectTyposquat("lodahs");
    expect(finding).not.toBeNull();
    expect(finding?.category).toBe("dependencyConfusion");
    expect(finding?.severity).toBe("high");
    expect(finding?.title).toContain("lodash");
    expect(finding?.filePath).toBe("package.json#name");
    expect(finding?.evidence).toContain("lodahs");
    expect(finding?.recommendation).toBeTruthy();
  });

  it("finding description names both the candidate and the target", () => {
    const finding = detectTyposquat("reacts");
    expect(finding?.description).toContain("reacts");
    expect(finding?.description).toContain("react");
  });

  it("returns null for null/undefined/empty input", () => {
    expect(detectTyposquat("")).toBeNull();
    // @ts-expect-error — testing defensive null handling
    expect(detectTyposquat(null)).toBeNull();
  });

  it("the popular package list contains expected well-known packages", () => {
    expect(POPULAR_PACKAGES.has("lodash")).toBe(true);
    expect(POPULAR_PACKAGES.has("react")).toBe(true);
    expect(POPULAR_PACKAGES.has("express")).toBe(true);
    expect(POPULAR_PACKAGES.has("axios")).toBe(true);
    expect(POPULAR_PACKAGES.has("webpack")).toBe(true);
    expect(POPULAR_PACKAGES.has("jest")).toBe(true);
    expect(POPULAR_PACKAGES.has("typescript")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Integration: manifest-analyzer wires in typosquat detection
// ---------------------------------------------------------------------------

import path from "node:path";
import { fileURLToPath } from "node:url";
import { ManifestAnalyzer } from "./manifest-analyzer";
import type { PackageManifest, ScriptAnalysisInput } from "./types";

const fixturesDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../fixtures");

function manifest(overrides: Partial<PackageManifest> = {}): PackageManifest {
  return { name: "fixture", version: "1.0.0", scripts: {}, dependencies: {}, optionalDependencies: {}, ...overrides };
}

describe("manifest-analyzer — typosquat integration", () => {
  it("emits a dependencyConfusion finding for a typosquat package name", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: { ecosystem: "npm", packageName: "lodahs", version: "4.17.21" },
      packageRoot: path.join(fixturesDir, "typosquat-lodash"),
      manifest: manifest({
        name: "lodahs",
        version: "4.17.21",
        scripts: { postinstall: "node install.js" }
      })
    };

    const result = await analyzer.analyze(input);
    const typosquatFindings = result.findings.filter(
      (f) => f.category === "dependencyConfusion" && f.title.includes("lodash")
    );
    expect(typosquatFindings.length).toBeGreaterThan(0);
    expect(typosquatFindings[0].severity).toBe("high");
  });

  it("does NOT emit a typosquat finding for a legitimate popular package name", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: { ecosystem: "npm", packageName: "lodash", version: "4.17.21" },
      packageRoot: path.join(fixturesDir, "benign-package"),
      manifest: manifest({ name: "lodash", version: "4.17.21" })
    };

    const result = await analyzer.analyze(input);
    const typosquatFindings = result.findings.filter(
      (f) => f.category === "dependencyConfusion" && f.title.includes("typosquat")
    );
    expect(typosquatFindings).toHaveLength(0);
  });

  it("demotes installHook to info for trusted allowlisted packages (sqlite3)", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: { ecosystem: "npm", packageName: "sqlite3", version: "5.1.7" },
      packageRoot: path.join(fixturesDir, "benign-native-addon"),
      manifest: manifest({
        name: "sqlite3",
        version: "5.1.7",
        scripts: { install: "node-pre-gyp install --fallback-to-build" }
      })
    };

    const result = await analyzer.analyze(input);
    // The installHook finding should be demoted to info, not low
    const installHookFindings = result.findings.filter((f) => f.category === "installHook");
    expect(installHookFindings.length).toBeGreaterThan(0);
    for (const f of installHookFindings) {
      expect(f.severity).toBe("info");
    }
    // No high/critical pattern hits on a clean install script
    const alarming = result.findings.filter((f) => f.severity === "high" || f.severity === "critical");
    expect(alarming).toHaveLength(0);
  });
});
