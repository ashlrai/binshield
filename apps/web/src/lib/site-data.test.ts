import { describe, expect, it } from "vitest";

import {
  getBillingSnapshot,
  getDashboardSnapshot,
  getFeaturedPackages,
  getPackageWorkspace,
  getPublicBrowseCounts,
  getSettingsSnapshot,
  getWatchlistSnapshot,
  searchPackages
} from "./site-data";

describe("site data", () => {
  it("returns browse counts and featured packages", async () => {
    const counts = getPublicBrowseCounts();
    const featured = await getFeaturedPackages();

    expect(counts.packages).toBeGreaterThan(0);
    expect(featured.length).toBeGreaterThan(0);
  });

  it("searches and resolves package workspaces from fallback data", async () => {
    const search = await searchPackages("bcrypt");
    const workspace = await getPackageWorkspace("bcrypt");

    expect(search[0]?.packageName).toBe("bcrypt");
    expect(workspace.selected.packageName).toBe("bcrypt");
    expect(workspace.versions.length).toBeGreaterThan(0);
  });

  it("returns dashboard, billing, watchlist, and settings snapshots", async () => {
    const [dashboard, billing, watchlists, settings] = await Promise.all([
      getDashboardSnapshot(),
      getBillingSnapshot(),
      getWatchlistSnapshot(),
      getSettingsSnapshot()
    ]);

    expect(dashboard.metrics.length).toBeGreaterThan(0);
    expect(billing.invoices.length).toBeGreaterThan(0);
    expect(watchlists.items.length).toBeGreaterThan(0);
    expect(settings.apiKeys.length).toBeGreaterThan(0);
  });
});
