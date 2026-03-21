import { describe, expect, it } from "vitest";

import { entitlementForPlan, getSampleAnalysis, sampleAnalyses, sampleDashboard } from "./index";

describe("analysis types", () => {
  it("returns seeded package analyses", () => {
    expect(sampleAnalyses.length).toBeGreaterThan(0);
    expect(getSampleAnalysis("bcrypt", "5.1.1")?.riskLevel).toBe("low");
  });

  it("returns plan entitlements and dashboard data", () => {
    expect(entitlementForPlan("free").maxRepos).toBe(3);
    expect(sampleDashboard.subscription.plan).toBe("pro");
    expect(sampleDashboard.apiKeys.length).toBeGreaterThan(0);
  });
});
