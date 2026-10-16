import { describe, expect, it } from "vitest";

import {
  PackageNameIntelligence,
  auditLockfileNames,
  isHomoglyphVariant,
  isCrossEcosystemRisky,
  levenshtein,
  normalizeHomoglyphs,
  parseLockfile,
  parsePackageLock,
  parsePnpmLock,
  parseRequirementsTxt,
  KNOWN_TYPOSQUATS,
  TYPOSQUAT_CORPUS_VERSION,
} from "./index";

// ---------------------------------------------------------------------------
// Levenshtein distance
// ---------------------------------------------------------------------------

describe("levenshtein", () => {
  it("returns 0 for identical strings", () => {
    expect(levenshtein("lodash", "lodash")).toBe(0);
  });

  it("returns correct distance for single insertion", () => {
    expect(levenshtein("axio", "axios")).toBe(1);
  });

  it("returns correct distance for single deletion", () => {
    expect(levenshtein("axiosx", "axios")).toBe(1);
  });

  it("returns correct distance for single substitution", () => {
    expect(levenshtein("axoos", "axios")).toBe(1);
  });

  it("returns correct distance for transposition", () => {
    // axois vs axios: o↔i swap = 2 ops (sub+sub)
    expect(levenshtein("axois", "axios")).toBe(2);
  });

  it("handles empty strings", () => {
    expect(levenshtein("", "abc")).toBe(3);
    expect(levenshtein("abc", "")).toBe(3);
    expect(levenshtein("", "")).toBe(0);
  });

  it("returns full length for completely different strings", () => {
    expect(levenshtein("abc", "xyz")).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Homoglyph normalisation
// ---------------------------------------------------------------------------

describe("normalizeHomoglyphs", () => {
  it("maps Cyrillic а to ASCII a", () => {
    // Cyrillic а (U+0430) looks identical to Latin a — maps to "a"
    expect(normalizeHomoglyphs("а")).toBe("a"); // Cyrillic а → a
    // Cyrillic о (U+043E) looks identical to Latin o — maps to "o"
    // so "lоdash" (Cyrillic о) normalises to "lodash"
    expect(normalizeHomoglyphs("lоdash")).toBe("lodash");
  });

  it("lowercases all output", () => {
    expect(normalizeHomoglyphs("LODASH")).toBe("lodash");
  });

  it("normalises digit substitutions", () => {
    expect(normalizeHomoglyphs("l0dash")).toBe("lodash"); // 0→o
  });
});

describe("isHomoglyphVariant", () => {
  it("returns false for identical strings", () => {
    expect(isHomoglyphVariant("lodash", "lodash")).toBe(false);
  });

  it("detects digit substitution homoglyph attacks", () => {
    // l0dash vs lodash: 0→o
    expect(isHomoglyphVariant("l0dash", "lodash")).toBe(true);
  });

  it("returns false for unrelated names", () => {
    expect(isHomoglyphVariant("express", "lodash")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Cross-ecosystem risk
// ---------------------------------------------------------------------------

describe("isCrossEcosystemRisky", () => {
  it("returns false for known-benign cross-listed packages", () => {
    expect(isCrossEcosystemRisky("redis")).toBe(false);
    expect(isCrossEcosystemRisky("cryptography")).toBe(false);
  });

  it("returns true for short unknown names", () => {
    expect(isCrossEcosystemRisky("axio")).toBe(true);
  });

  it("returns true for helper/util suffix names", () => {
    expect(isCrossEcosystemRisky("boto3-helper")).toBe(true);
    expect(isCrossEcosystemRisky("requests-utils")).toBe(true);
  });

  it("returns false for long, unique non-keyword names", () => {
    // A long descriptive name with no risky keywords
    expect(isCrossEcosystemRisky("pydantic")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// PackageNameIntelligence — known typosquats
// ---------------------------------------------------------------------------

describe("PackageNameIntelligence — corpus matches", () => {
  const intel = new PackageNameIntelligence();

  it("flags a known npm typosquat as critical", () => {
    const result = intel.analyze("crossenv", "npm");
    expect(result.isRisky).toBe(true);
    expect(result.isKnownTyposquat).toBe(true);
    expect(result.riskLevel).toBe("critical");
    expect(result.matches.some((m) => m.targetPackage === "cross-env")).toBe(true);
  });

  it("flags axois (transposition of axios) as critical corpus hit", () => {
    const result = intel.analyze("axois", "npm");
    expect(result.isRisky).toBe(true);
    expect(result.isKnownTyposquat).toBe(true);
    expect(result.riskLevel).toBe("critical");
  });

  it("flags lodash-helper as critical", () => {
    const result = intel.analyze("lodash-helper", "npm");
    expect(result.isRisky).toBe(true);
    expect(result.isKnownTyposquat).toBe(true);
    expect(result.riskLevel).toBe("critical");
  });

  it("flags requets (transposition of requests) for PyPI as critical", () => {
    const result = intel.analyze("requets", "pypi");
    expect(result.isRisky).toBe(true);
    expect(result.isKnownTyposquat).toBe(true);
    expect(result.riskLevel).toBe("critical");
  });

  it("flags nunpy (typosquat of numpy) for PyPI as critical", () => {
    const result = intel.analyze("nunpy", "pypi");
    expect(result.isRisky).toBe(true);
    expect(result.isKnownTyposquat).toBe(true);
    expect(result.riskLevel).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// PackageNameIntelligence — Levenshtein detection
// ---------------------------------------------------------------------------

describe("PackageNameIntelligence — levenshtein matches", () => {
  const intel = new PackageNameIntelligence({ levenshteinThreshold: 2 });

  it("flags axio (distance 1 from axios) as risky", () => {
    // axio is in the known corpus so it will be critical, not just high
    const result = intel.analyze("axio", "npm");
    expect(result.isRisky).toBe(true);
    const match = result.matches.find((m) => m.targetPackage === "axios");
    expect(match).toBeDefined();
  });

  it("flags moocha (distance 1 from mocha) as high risk via levenshtein only", () => {
    // "moocha" is NOT in the corpus so only Levenshtein fires → high
    const result = intel.analyze("moocha", "npm");
    expect(result.isRisky).toBe(true);
    expect(result.riskLevel).toBe("high");
    const match = result.matches.find((m) => m.targetPackage === "mocha");
    expect(match).toBeDefined();
    expect(match?.editDistance).toBe(1);
  });

  it("flags expres (distance 1 from express) as risky", () => {
    // expres is in the known corpus → critical
    const result = intel.analyze("expres", "npm");
    expect(result.isRisky).toBe(true);
    // corpus hit exists; match should be defined (may be corpus match without editDistance)
    const match = result.matches.find((m) => m.targetPackage === "express");
    expect(match).toBeDefined();
  });

  it("does NOT flag lodash-es as a typosquat of lodash (legitimate extension)", () => {
    const result = intel.analyze("lodash-es", "npm");
    // lodash-es should NOT be flagged because it starts with "lodash-"
    const lodashMatch = result.matches.find((m) => m.targetPackage === "lodash");
    expect(lodashMatch).toBeUndefined();
  });

  it("does NOT flag exact popular package names", () => {
    const result = intel.analyze("lodash", "npm");
    expect(result.isRisky).toBe(false);
  });

  it("does NOT flag packages from wrong ecosystem", () => {
    // "requests" is a popular PyPI package; checking it as npm should not flag
    const result = intel.analyze("requests", "npm");
    // It may still not be risky since "request" (npm) is distance 1 from "requests" (npm)
    // but it should NOT match the PyPI "requests" popular package
    const pypiMatch = result.matches.find((m) => m.targetEcosystem === "pypi");
    expect(pypiMatch).toBeUndefined();
  });

  it("does not flag genuinely different packages", () => {
    const result = intel.analyze("completely-unique-package-xyz", "npm");
    expect(result.isRisky).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// PackageNameIntelligence — homoglyph detection
// ---------------------------------------------------------------------------

describe("PackageNameIntelligence — homoglyph detection", () => {
  const intel = new PackageNameIntelligence();

  it("flags l0dash (digit substitution) as critical", () => {
    const result = intel.analyze("l0dash", "npm");
    expect(result.isRisky).toBe(true);
    expect(result.riskLevel).toBe("critical");
    expect(result.matches.some((m) => m.reason.includes("omoglyph"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PackageNameIntelligence — cross-ecosystem flag
// ---------------------------------------------------------------------------

describe("PackageNameIntelligence — cross-ecosystem flag", () => {
  const intel = new PackageNameIntelligence();

  it("flags a package present on both npm and PyPI with a risky name", () => {
    const result = intel.analyze("boto3-helper", "npm", true);
    expect(result.crossEcosystemFlag).toBe(true);
    expect(result.isRisky).toBe(true);
  });

  it("does NOT flag known-benign cross-listed packages", () => {
    const result = intel.analyze("redis", "npm", true);
    expect(result.crossEcosystemFlag).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// PackageNameIntelligence — advisory builder
// ---------------------------------------------------------------------------

describe("PackageNameIntelligence — advisory", () => {
  const intel = new PackageNameIntelligence();

  it("builds a non-empty advisory for risky package", () => {
    const result = intel.analyze("crossenv", "npm");
    const advisory = intel.buildAdvisory(result);
    expect(advisory).toContain("CRITICAL");
    expect(advisory).toContain("crossenv");
    expect(advisory).toContain("cross-env");
  });
});

// ---------------------------------------------------------------------------
// Corpus integrity
// ---------------------------------------------------------------------------

describe("typosquat corpus", () => {
  it("has a valid version string", () => {
    expect(TYPOSQUAT_CORPUS_VERSION).toMatch(/^\d{4}-\d{2}-\d{2}\.\d+$/);
  });

  it("contains known historically documented typosquats", () => {
    const names = KNOWN_TYPOSQUATS.map((e) => e.name);
    expect(names).toContain("crossenv");
    expect(names).toContain("axois");
    expect(names).toContain("lodash-helper");
    expect(names).toContain("requets");
    expect(names).toContain("nunpy");
    expect(names).toContain("leftpad");
  });

  it("all entries have required fields", () => {
    for (const entry of KNOWN_TYPOSQUATS) {
      expect(entry.name).toBeTruthy();
      expect(entry.ecosystem).toMatch(/^(npm|pypi)$/);
      expect(entry.imitates).toBeTruthy();
      expect(entry.description).toBeTruthy();
      expect(entry.addedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// Lockfile parsing
// ---------------------------------------------------------------------------

describe("parsePackageLock", () => {
  it("parses v2 format package-lock.json", () => {
    const content = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        "": {},
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/axios": { version: "1.6.0" },
        "node_modules/crossenv": { version: "1.0.0" },
      },
    });
    const pkgs = parsePackageLock(content);
    const names = pkgs.map((p) => p.name);
    expect(names).toContain("lodash");
    expect(names).toContain("axios");
    expect(names).toContain("crossenv");
    expect(names).not.toContain(""); // root entry stripped
  });

  it("parses v1 format package-lock.json", () => {
    const content = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        "lodash": { version: "4.17.21" },
        "axois": { version: "0.0.1" },
      },
    });
    const pkgs = parsePackageLock(content);
    const names = pkgs.map((p) => p.name);
    expect(names).toContain("lodash");
    expect(names).toContain("axois");
  });

  it("returns empty array for invalid JSON", () => {
    expect(parsePackageLock("not json")).toEqual([]);
  });
});

describe("parseRequirementsTxt", () => {
  it("parses pinned requirements", () => {
    const content = `
# comment
requests==2.31.0
numpy>=1.24.0
nunpy==0.0.1
pandas~=2.0
flask
`;
    const pkgs = parseRequirementsTxt(content);
    const names = pkgs.map((p) => p.name);
    expect(names).toContain("requests");
    expect(names).toContain("numpy");
    expect(names).toContain("nunpy");
    expect(names).toContain("pandas");
    expect(names).toContain("flask");
    expect(names).not.toContain(""); // no blank lines
  });

  it("skips comment lines", () => {
    const pkgs = parseRequirementsTxt("# This is a comment\nrequests==2.0\n");
    expect(pkgs.length).toBe(1);
    expect(pkgs[0]?.name).toBe("requests");
  });
});

describe("parsePnpmLock", () => {
  it("extracts package names from pnpm-lock.yaml format", () => {
    const content = `
lockfileVersion: '9.0'

packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-xxx}
  /axios@1.6.0:
    resolution: {integrity: sha512-yyy}
  /crossenv@1.0.0:
    resolution: {integrity: sha512-zzz}
`;
    const pkgs = parsePnpmLock(content);
    const names = pkgs.map((p) => p.name);
    expect(names).toContain("lodash");
    expect(names).toContain("axios");
    expect(names).toContain("crossenv");
  });
});

describe("parseLockfile", () => {
  it("auto-detects package-lock.json", () => {
    const content = JSON.stringify({ lockfileVersion: 2, packages: { "node_modules/lodash": { version: "4.17.21" } } });
    const pkgs = parseLockfile("package-lock.json", content);
    expect(pkgs[0]?.name).toBe("lodash");
    expect(pkgs[0]?.ecosystem).toBe("npm");
  });

  it("auto-detects requirements.txt", () => {
    const pkgs = parseLockfile("requirements.txt", "requests==2.31.0\n");
    expect(pkgs[0]?.name).toBe("requests");
    expect(pkgs[0]?.ecosystem).toBe("pypi");
  });

  it("returns empty for unknown format", () => {
    expect(parseLockfile("Cargo.lock", "")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// auditLockfileNames — end-to-end fixture test
// ---------------------------------------------------------------------------

describe("auditLockfileNames — E2E", () => {
  const FIXTURE_PACKAGE_LOCK = JSON.stringify({
    lockfileVersion: 2,
    packages: {
      "": {},
      "node_modules/lodash": { version: "4.17.21" },
      "node_modules/axios": { version: "1.6.0" },
      "node_modules/crossenv": { version: "1.0.0" },
      "node_modules/axois": { version: "0.0.1" },
      "node_modules/lodash-helper": { version: "0.0.1" },
      "node_modules/express": { version: "4.18.0" },
      "node_modules/expres": { version: "0.0.1" },
    },
  });

  it("detects known typosquats in fixture lockfile", () => {
    const packages = parsePackageLock(FIXTURE_PACKAGE_LOCK);
    const result = auditLockfileNames(packages);

    expect(result.scanned).toBe(7); // 7 non-root packages
    expect(result.risky.length).toBeGreaterThanOrEqual(3); // crossenv, axois, lodash-helper, expres

    const riskyNames = result.risky.map((r) => r.packageName);
    expect(riskyNames).toContain("crossenv");
    expect(riskyNames).toContain("axois");
    expect(riskyNames).toContain("lodash-helper");

    // Clean packages should not be flagged
    expect(riskyNames).not.toContain("lodash");
    expect(riskyNames).not.toContain("axios");
    expect(riskyNames).not.toContain("express");
  });

  it("reports critical risk for corpus-matched typosquats", () => {
    const packages = parsePackageLock(FIXTURE_PACKAGE_LOCK);
    const result = auditLockfileNames(packages);
    const crossenvResult = result.risky.find((r) => r.packageName === "crossenv");
    expect(crossenvResult?.riskLevel).toBe("critical");
    expect(crossenvResult?.isKnownTyposquat).toBe(true);
  });

  it("builds a non-trivial summary when risky packages found", () => {
    const packages = parsePackageLock(FIXTURE_PACKAGE_LOCK);
    const result = auditLockfileNames(packages);
    expect(result.summary).toContain("risky");
  });

  const FIXTURE_REQUIREMENTS = `
# good packages
requests==2.31.0
numpy==1.26.0
flask==3.0.0
# typosquats
requets==0.0.1
nunpy==0.0.1
tensorlfow==0.0.1
`;

  it("detects known typosquats in PyPI requirements.txt", () => {
    const packages = parseRequirementsTxt(FIXTURE_REQUIREMENTS);
    const result = auditLockfileNames(packages);
    const riskyNames = result.risky.map((r) => r.packageName);
    expect(riskyNames).toContain("requets");
    expect(riskyNames).toContain("nunpy");
    expect(riskyNames).toContain("tensorlfow");
  });

  it("returns clean summary when no issues found", () => {
    const packages = [
      { name: "lodash", version: "4.17.21", ecosystem: "npm" as const },
      { name: "axios", version: "1.6.0", ecosystem: "npm" as const },
    ];
    const result = auditLockfileNames(packages);
    expect(result.risky.length).toBe(0);
    expect(result.summary).toContain("passed");
  });
});
