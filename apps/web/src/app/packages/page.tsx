import type { Metadata } from "next";
import Link from "next/link";

import { MetricCard } from "../../components/metric-card";
import { PageHeader } from "../../components/page-header";
import { RiskBadge } from "../../components/risk-badge";
import { getPublicBrowseCounts, searchPackages } from "../../lib/site-data";

export const metadata: Metadata = {
  title: "Package Database",
  description:
    "Browse BinShield's database of analyzed npm packages with native binaries. View risk scores, behavior classifications, and binary-level evidence for each package.",
  alternates: {
    canonical: "https://binshield.dev/packages"
  }
};

export default async function PackagesIndexPage({
  searchParams
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q = "" } = await searchParams;
  const [results, counts] = await Promise.all([searchPackages(q), getPublicBrowseCounts()]);

  return (
    <main className="browse-page">
      <PageHeader
        eyebrow="Public database"
        title="Package browser"
        description="Browse the current native-binary surface area, then drill into the exact package version and binary breakdown."
        actions={
          <form className="inline-search" action="/packages">
            <input name="q" defaultValue={q} placeholder="Search package name or summary" aria-label="Search packages" />
            <button type="submit">Filter</button>
          </form>
        }
      />

      <section className="metrics-grid">
        <MetricCard label="Packages" value={String(counts.packages)} detail="Publicly indexed package analyses" />
        <MetricCard label="Native binaries" value={String(counts.binaries)} detail="Across the current launch set" tone="warning" />
        <MetricCard label="Watchlists" value={String(counts.watchlists)} detail="Alerting-ready package tracking" tone="accent" />
      </section>

      <section className="featured-section">
        <div className="panel__heading">
          <h2>{q ? `Search results for "${q}"` : "Curated packages"}</h2>
          <span>{results.length} results</span>
        </div>
        <div className="browse-grid">
          {results.map((item) => (
            <Link key={`${item.packageName}-${item.latestVersion}`} href={`/packages/${item.packageName}`} className="package-tile package-tile--stacked">
              <div className="package-tile__header">
                <div>
                  <p className="eyebrow">{item.ecosystem}</p>
                  <h3>{item.packageName}</h3>
                </div>
                <RiskBadge level={item.riskLevel} score={item.riskScore} />
              </div>
              <p>{item.summary}</p>
              <div className="tag-list">
                {item.topBehaviors.length ? (
                  item.topBehaviors.map((behavior) => (
                    <span key={`${item.packageName}-${behavior}`} className="tag tag--review">
                      {behavior}
                    </span>
                  ))
                ) : (
                  <span className="tag tag-muted">No elevated behavior family</span>
                )}
              </div>
              <div className="package-tile__footer">
                <span>{item.binaryCount} binaries</span>
                <span>{item.sourceMatchConfidence} confidence</span>
                <span>Latest {item.latestVersion}</span>
              </div>
            </Link>
          ))}
        </div>
      </section>
    </main>
  );
}
