import type { MetadataRoute } from "next";

const SITE_URL = "https://binshield.dev";
const API_URL = "https://binshieldapi-production.up.railway.app";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticRoutes: MetadataRoute.Sitemap = [
    { url: SITE_URL, lastModified: new Date(), changeFrequency: "daily", priority: 1 },
    { url: `${SITE_URL}/packages`, lastModified: new Date(), changeFrequency: "daily", priority: 0.9 },
    { url: `${SITE_URL}/search`, lastModified: new Date(), changeFrequency: "weekly", priority: 0.7 },
    { url: `${SITE_URL}/login`, lastModified: new Date(), changeFrequency: "monthly", priority: 0.3 },
  ];

  // Fetch package names from API for dynamic routes
  try {
    const res = await fetch(`${API_URL}/packages/search`, { next: { revalidate: 3600 } });
    if (res.ok) {
      const data = await res.json() as { items: Array<{ packageName: string }> };
      const packageRoutes: MetadataRoute.Sitemap = data.items.map((pkg) => ({
        url: `${SITE_URL}/packages/${encodeURIComponent(pkg.packageName)}`,
        lastModified: new Date(),
        changeFrequency: "weekly" as const,
        priority: 0.8,
      }));
      return [...staticRoutes, ...packageRoutes];
    }
  } catch {
    // API unavailable, return static routes only
  }

  return staticRoutes;
}
