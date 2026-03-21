import { describe, expect, it } from "vitest";

import { AnalysisPipeline } from "./pipeline";

describe("analysis pipeline", () => {
  it("produces a complete package analysis", async () => {
    const pipeline = new AnalysisPipeline();
    const result = await pipeline.analyze({
      ecosystem: "npm",
      packageName: "bcrypt",
      version: "5.1.1"
    });

    expect(result.status).toBe("complete");
    expect(result.binaries.length).toBeGreaterThan(0);
    expect(result.riskLevel).toBe("low");
  });
});
