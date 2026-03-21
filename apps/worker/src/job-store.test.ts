import { describe, expect, it } from "vitest";

import { InMemoryJobStore } from "./job-store";

describe("job store", () => {
  it("tracks lifecycle transitions and events", () => {
    const store = new InMemoryJobStore();
    const job = store.submit(
      {
        ecosystem: "npm",
        packageName: "fixture",
        version: "1.0.0"
      },
      "npm:fixture:1.0.0:pending"
    );

    expect(job.status).toBe("queued");

    const analyzing = store.start(job.id);
    expect(analyzing.status).toBe("analyzing");

    const completed = store.complete(job.id, {
      id: "fixture_1",
      ecosystem: "npm",
      packageName: "fixture",
      version: "1.0.0",
      status: "complete",
      riskScore: 5,
      riskLevel: "low",
      summary: "done",
      sourceMatchConfidence: "medium",
      binaryCount: 0,
      totalBinarySize: 0,
      aiModel: "test",
      createdAt: new Date().toISOString(),
      binaries: []
    }, [], "npm:fixture:1.0.0:hash");

    expect(completed.status).toBe("complete");
    expect(completed.cacheKey).toContain("hash");
    expect(store.events(job.id)).toHaveLength(3);
  });

  it("supports retries", () => {
    const store = new InMemoryJobStore();
    const job = store.submit(
      {
        ecosystem: "npm",
        packageName: "fixture",
        version: "1.0.0"
      },
      "pending"
    );

    const retried = store.retry(job.id);
    expect(retried.status).toBe("queued");
    expect(retried.retries).toBe(1);
  });
});
