import { describe, expect, it } from "vitest";

import {
  entitlementForPlan,
  getSampleActionSummaries,
  getSampleAnalysis,
  getSamplePackageDiff,
  getSamplePackageHistory,
  sampleAnalyses,
  sampleDashboard
} from "./index";

describe("analysis types", () => {
  it("returns seeded package analyses", () => {
    expect(sampleAnalyses.length).toBeGreaterThanOrEqual(7);
    expect(getSampleAnalysis("bcrypt", "5.1.1")?.riskLevel).toBe("low");
    expect(getSamplePackageHistory("sharp").length).toBe(2);
    expect(getSamplePackageDiff("sqlite3", "5.1.6", "5.1.7")?.riskDelta).toBe(4);
  });

  it("returns plan entitlements and dashboard data", () => {
    expect(entitlementForPlan("free").maxRepos).toBe(3);
    expect(sampleDashboard.subscription.plan).toBe("pro");
    expect(sampleDashboard.apiKeys.length).toBeGreaterThan(0);
    expect(getSampleActionSummaries("canvas")[0]?.binaryFilenames.length).toBe(2);
  });
});
