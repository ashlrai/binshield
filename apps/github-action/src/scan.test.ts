import { describe, expect, it } from "vitest";

import { renderComment, shouldFail, summarize, shouldPublishComment, shouldPublishSummary } from "./report";

describe("github action helpers", () => {
  it("fails based on threshold ordering", () => {
    expect(shouldFail("high", "medium")).toBe(true);
    expect(shouldFail("low", "high")).toBe(false);
    expect(shouldFail("critical", "never")).toBe(false);
  });

  it("renders a markdown comment", () => {
    const comment = renderComment([
      {
        target: {
          name: "bcrypt",
          version: "5.1.1",
          path: "node_modules/bcrypt",
          source: "lockfile",
          nativeCandidate: true
        },
        analysis: {
          id: "pkg_bcrypt_5_1_1",
          ecosystem: "npm",
          packageName: "bcrypt",
          version: "5.1.1",
          status: "complete",
          riskScore: 12,
          riskLevel: "low",
          summary: "Standard bcrypt native addon",
          sourceMatchConfidence: "high",
          binaryCount: 1,
          totalBinarySize: 100,
          aiModel: "claude",
          createdAt: "2026-03-21T00:00:00.000Z",
          binaries: []
        }
      }
    ]);
    expect(comment).toContain("BinShield");
    expect(comment).toContain("bcrypt@5.1.1");
  });

  it("summarizes outcomes and comment modes", () => {
    const summary = summarize([
      {
        target: {
          name: "sharp",
          version: "0.33.2",
          path: "node_modules/sharp",
          source: "lockfile",
          nativeCandidate: true
        },
        error: "timeout"
      }
    ]);

    expect(summary.failures).toBe(1);
    expect(shouldPublishComment("both")).toBe(true);
    expect(shouldPublishSummary("summary")).toBe(true);
  });
});
