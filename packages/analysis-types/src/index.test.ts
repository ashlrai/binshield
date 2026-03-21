import { describe, expect, it } from "vitest";

import { getSampleAnalysis, sampleAnalyses } from "./index";

describe("analysis types", () => {
  it("returns seeded package analyses", () => {
    expect(sampleAnalyses.length).toBeGreaterThan(0);
    expect(getSampleAnalysis("bcrypt", "5.1.1")?.riskLevel).toBe("low");
  });
});
