import { describe, expect, it } from "vitest";

import { sampleAnalyses } from "@binshield/analysis-types";
import { renderComment, shouldFail } from "./scan";

describe("github action helpers", () => {
  it("fails based on threshold ordering", () => {
    expect(shouldFail("high", "medium")).toBe(true);
    expect(shouldFail("low", "high")).toBe(false);
    expect(shouldFail("critical", "never")).toBe(false);
  });

  it("renders a markdown comment", () => {
    const comment = renderComment(sampleAnalyses);
    expect(comment).toContain("BinShield");
    expect(comment).toContain("bcrypt@5.1.1");
  });
});
