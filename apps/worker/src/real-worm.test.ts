import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { AnalysisPipeline } from "./pipeline";

const fixturesDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../fixtures");

/**
 * End-to-end validation against a real-world worm. The fixture faithfully
 * replicates the documented payload of the Shai-Hulud npm worm (Sept 2025) —
 * the first self-propagating npm worm — running it through the full worker
 * pipeline, not just the analyzer in isolation.
 */
describe("real-worm validation — Shai-Hulud npm worm", () => {
  it("flags a faithful Shai-Hulud payload replica as critical, end to end", async () => {
    const pipeline = new AnalysisPipeline();
    const outcome = await pipeline.run({
      ecosystem: "npm",
      packageName: "binshield-fixture-shai-hulud",
      version: "1.0.0",
      packageRoot: path.join(fixturesDir, "shai-hulud-replica"),
      packageSource: "directory"
    });

    const analysis = outcome.analysis;
    // The package ships no native binary — pre-install-script-analysis this
    // would have scored "none". It must now be critical.
    expect(analysis.binaryCount).toBe(0);
    expect(analysis.riskLevel).toBe("critical");

    const manifest = analysis.manifestAnalysis;
    expect(manifest).toBeDefined();
    expect(manifest?.hasInstallScripts).toBe(true);

    const categories = new Set((manifest?.findings ?? []).map((finding) => finding.category));
    // The worm's defining behaviors must all be caught.
    expect(categories.has("remoteCodeExecution")).toBe(true); // curl | bash of trufflehog
    expect(categories.has("environmentTheft")).toBe(true); // NPM_TOKEN / GITHUB_TOKEN / AWS harvest
  });
});
