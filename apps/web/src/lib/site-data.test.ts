import { getSampleAnalysis } from "@binshield/analysis-types";
import { describe, expect, it, vi } from "vitest";

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
    const counts = await getPublicBrowseCounts();
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
    expect(workspace.evidenceCards.length).toBeGreaterThan(0);
    expect(workspace.packageSignals.length).toBeGreaterThan(0);
    expect(workspace.diffNarrative.reviewChecklist.length).toBeGreaterThan(0);
  });

  it("resolves scoped package route params without double-encoding the API path", async () => {
    const packageName = "@example/native";
    const routeName = encodeURIComponent(packageName);
    const analysis = { ...getSampleAnalysis("bcrypt")!, packageName };
    const apiPath = `/packages/npm/${routeName}`;
    const fetch = vi.fn(async (url: string) => {
      const { pathname } = new URL(url);
      if (pathname === apiPath) return Response.json({ versions: [analysis] });
      if (pathname === `${apiPath}/versions/${analysis.version}`) return Response.json(analysis);
      return new Response(null, { status: 404 });
    });
    vi.stubEnv("BINSHIELD_API_BASE_URL", "https://api.example.test");
    vi.stubGlobal("fetch", fetch);
    vi.resetModules();

    try {
      const { getBinaryWorkspace, getPackageWorkspace } = await import("./site-data");
      const workspace = await getPackageWorkspace(routeName);
      expect(workspace.found).toBe(true);
      expect(workspace.packageName).toBe(packageName);
      expect(fetch).toHaveBeenCalledWith(`https://api.example.test${apiPath}`, expect.anything());

      const detail = await getBinaryWorkspace(routeName, analysis.binaries[0].id);
      expect(detail?.breadcrumbs[1].href).toBe(`/packages/${routeName}?version=${analysis.version}`);
    } finally {
      vi.unstubAllEnvs();
      vi.unstubAllGlobals();
      vi.resetModules();
    }
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
