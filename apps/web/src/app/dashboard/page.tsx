import Link from "next/link";

import { MetricCard } from "../../components/metric-card";
import { PageHeader } from "../../components/page-header";
import { RiskBadge } from "../../components/risk-badge";
import { getDashboardSnapshot } from "../../lib/site-data";

function scoreForLevel(level: string) {
  switch (level) {
    case "critical":
      return 91;
    case "high":
      return 67;
    case "medium":
      return 34;
    case "low":
      return 12;
    default:
      return 0;
  }
}

export default async function DashboardPage() {
  const snapshot = await getDashboardSnapshot();

  return (
    <main className="dashboard-page">
      <PageHeader
        eyebrow="Dashboard"
        title="Repository posture at a glance"
        description="Monitor compiled dependencies across your repos, watch for behavior drift, and jump from summary to package-level evidence."
        actions={
          <Link href="/dashboard/watchlists" className="button-link">
            Review watchlists
          </Link>
        }
      />

      <section className="metrics-grid">
        {snapshot.metrics.map((metric) => (
          <MetricCard key={metric.label} label={metric.label} value={metric.value} detail={metric.detail} />
        ))}
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Repository posture</h2>
            <span>Latest scans and aggregate risk</span>
          </div>
          <div className="repo-table">
            {snapshot.repos.map((repo) => (
              <article key={repo.name} className="repo-row">
                <div>
                  <h3>{repo.name}</h3>
                  <p>
                    {repo.nativeDependencyCount} native dependencies • last scan {repo.lastScanLabel}
                  </p>
                </div>
                <strong>{repo.aggregateRiskScore}</strong>
                <span className={`status-pill status-pill--${repo.status}`}>{repo.status}</span>
              </article>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Recent scans</h2>
            <span>Pipeline activity</span>
          </div>
          <div className="activity-list">
            {snapshot.recentScans.map((scan) => (
              <article key={`${scan.packageName}-${scan.version}`} className="activity-row">
                <div>
                  <strong>
                    {scan.packageName}@{scan.version}
                  </strong>
                  <p>
                    {scan.status} • {scan.timestampLabel}
                  </p>
                </div>
                <RiskBadge level={scan.riskLevel as "none" | "low" | "medium" | "high" | "critical"} score={scoreForLevel(scan.riskLevel)} />
              </article>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
