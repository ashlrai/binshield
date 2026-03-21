import path from "node:path";

import { describe, expect, it } from "vitest";

import { AnalysisPipeline, WorkerRuntime } from "./pipeline";

describe("analysis pipeline", () => {
  it("analyzes the fixture package and caches the result", async () => {
    const packageRoot = path.resolve(new URL("../fixtures/sample-package", import.meta.url).pathname);
    const pipeline = new AnalysisPipeline();

    const first = await pipeline.run({
      ecosystem: "npm",
      packageName: "binshield-fixture-addon",
      version: "1.0.0",
      packageRoot
    });

    expect(first.job.status).toBe("complete");
    expect(first.analysis.binaryCount).toBe(2);
    expect(first.analysis.riskLevel).toBe("critical");
    expect(first.analysis.summary).toContain("binshield-fixture-addon");

    const second = await pipeline.run({
      ecosystem: "npm",
      packageName: "binshield-fixture-addon",
      version: "1.0.0",
      packageRoot
    });

    expect(second.job.fromCache).toBe(true);
    expect(second.analysis.summary).toBe(first.analysis.summary);
  });

  it("supports direct runtime access for queue state", async () => {
    const packageRoot = path.resolve(new URL("../fixtures/sample-package", import.meta.url).pathname);
    const runtime = new WorkerRuntime();
    const job = runtime.submit({
      ecosystem: "npm",
      packageName: "binshield-fixture-addon",
      version: "1.0.0",
      packageRoot
    });

    const outcome = await runtime.process(job.id);
    expect(outcome.job.status).toBe("complete");
    expect(runtime.getJob(job.id)?.status).toBe("complete");
    expect(runtime.jobEvents(job.id)).toHaveLength(3);
  });
});
