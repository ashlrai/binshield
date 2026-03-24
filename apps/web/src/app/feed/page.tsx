import type { Metadata } from "next";
import Link from "next/link";

import { MetricCard } from "../../components/metric-card";
import { PageHeader } from "../../components/page-header";
import { getFeedEvents, getFeedStats } from "../../lib/site-data";

export const metadata: Metadata = {
  title: "Ecosystem Feed",
  description: "Real-time monitoring of the npm registry for newly published packages with native binaries.",
  alternates: { canonical: "https://binshield.dev/feed" }
};

const riskClasses: Record<string, string> = { none: "risk-none", low: "risk-low", medium: "risk-medium", high: "risk-high", critical: "risk-critical" };
const eventLabels: Record<string, string> = { new_package: "New package", new_version: "New version", risk_change: "Risk changed" };

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const min = Math.floor(diff / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default async function FeedPage() {
  const [events, stats] = await Promise.all([getFeedEvents(), getFeedStats()]);

  return (
    <main className="browse-page">
      <PageHeader eyebrow="Real-time monitoring" title="Ecosystem Feed" description="Live monitoring of the npm registry. BinShield tracks newly published packages with native binaries, auto-scans them, and flags risks in real time." />
      <section className="metrics-grid">
        <MetricCard label="Packages processed" value={String(stats.packagesProcessed)} detail="Total npm packages checked" />
        <MetricCard label="Native packages" value={String(stats.nativePackagesFound)} detail="Packages with native binaries" tone="warning" />
        <MetricCard label="Feed events" value={String(events.length)} detail="Recent scanning activity" tone="accent" />
        <MetricCard label="Latest events" value={String(stats.latestEvents)} detail="In the current monitoring window" tone="default" />
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Recent events</h2><span>{events.length} events</span></div>
        {events.length === 0 ? (
          <div className="empty-state">
            <h3>Feed starting up</h3>
            <p>The BinShield ecosystem feed monitors the npm registry in real time for newly published packages containing native binaries. Events will appear here as packages are discovered and scanned.</p>
            <p><Link href="/packages" className="button-link">Browse existing analyses</Link></p>
          </div>
        ) : (
          <div className="browse-grid">
            {events.map((event) => (
              <Link key={event.id} href={`/packages/${event.packageName}`} className="package-tile package-tile--stacked">
                <div className="package-tile__header">
                  <div><p className="eyebrow">npm</p><h3>{event.packageName}@{event.version}</h3></div>
                  <span className={`risk-badge ${riskClasses[event.riskLevel] ?? "risk-none"}`}>{event.riskLevel.toUpperCase()} ({event.riskScore})</span>
                </div>
                <div className="tag-list"><span className="tag tag--review">{eventLabels[event.eventType] ?? event.eventType}</span></div>
                <div className="package-tile__footer"><span>{timeAgo(event.timestamp)}</span></div>
              </Link>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
