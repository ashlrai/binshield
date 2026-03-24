import type { Metadata } from "next";
import Link from "next/link";

import { MetricCard } from "../../components/metric-card";
import { PageHeader } from "../../components/page-header";
import { getRecentAdvisories } from "../../lib/site-data";

export const metadata: Metadata = {
  title: "Security Advisories",
  description:
    "Browse the latest security advisories affecting npm packages with native binaries. Data from OSV.dev, NVD, and GitHub Advisory Database.",
  alternates: { canonical: "https://binshield.dev/advisories" }
};

const severityColors: Record<string, string> = {
  critical: "risk-critical", high: "risk-high", medium: "risk-medium", low: "risk-low", none: "risk-none"
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const hours = Math.floor(diff / (1000 * 60 * 60));
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

export default async function AdvisoriesPage() {
  const advisories = await getRecentAdvisories();
  const criticalCount = advisories.filter((a) => a.severity === "critical").length;
  const highCount = advisories.filter((a) => a.severity === "high").length;

  return (
    <main className="browse-page">
      <PageHeader
        eyebrow="Vulnerability intelligence"
        title="Advisory Feed"
        description="Security advisories from OSV.dev, NVD, and GitHub Advisory Database, correlated with binary behavior analysis from BinShield scans."
      />
      <section className="metrics-grid">
        <MetricCard label="Total advisories" value={String(advisories.length)} detail="Across all tracked packages" />
        <MetricCard label="Critical" value={String(criticalCount)} detail="Require immediate attention" tone="danger" />
        <MetricCard label="High severity" value={String(highCount)} detail="Should be reviewed soon" tone="warning" />
        <MetricCard label="Sources" value="3" detail="OSV.dev, NVD, GitHub Advisory DB" tone="accent" />
      </section>
      <section className="featured-section">
        <div className="panel__heading">
          <h2>Recent advisories</h2>
          <span>{advisories.length} results</span>
        </div>
        {advisories.length === 0 ? (
          <div className="empty-state">
            <h3>Advisory feed loading</h3>
            <p>BinShield aggregates vulnerability data from OSV.dev, the National Vulnerability Database (NVD), and the GitHub Advisory Database. As packages are scanned, relevant advisories appear here automatically.</p>
            <p><Link href="/packages" className="button-link">Browse scanned packages</Link></p>
          </div>
        ) : (
          <div className="browse-grid">
            {advisories.map((advisory) => (
              <article key={advisory.id} className="package-tile package-tile--stacked">
                <div className="package-tile__header">
                  <div>
                    <p className="eyebrow">{advisory.source.toUpperCase()}</p>
                    <h3>{advisory.title}</h3>
                  </div>
                  <span className={`risk-badge ${severityColors[advisory.severity] ?? "risk-none"}`}>
                    {advisory.severity.toUpperCase()}
                  </span>
                </div>
                <p>{advisory.description.slice(0, 200)}{advisory.description.length > 200 ? "..." : ""}</p>
                <div className="tag-list">
                  <span className="tag tag--review">{advisory.sourceId}</span>
                  {advisory.affectedPackages.slice(0, 3).map((pkg) => (
                    <Link key={`${advisory.id}-${pkg}`} href={`/packages/${pkg}`} className="tag tag-muted">
                      {pkg}
                    </Link>
                  ))}
                </div>
                <div className="package-tile__footer">
                  <span>{timeAgo(advisory.publishedAt)}</span>
                  <span>{advisory.affectedPackages.length} affected packages</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
