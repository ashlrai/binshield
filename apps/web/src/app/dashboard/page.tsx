import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { AnalyticsCollector } from "@binshield/analytics-collector";
import { MetricCard } from "../../components/metric-card";
import { PageHeader } from "../../components/page-header";
import { RiskBadge } from "../../components/risk-badge";
import { getDashboardSnapshot } from "../../lib/site-data";
import { createServerClient, getOrgContext } from "../../lib/supabase";

// Server-side analytics collector for the web app.
// Uses demo mode when BINSHIELD_DEMO=true or no Supabase credentials present.
const webAnalytics = new AnalyticsCollector({
  supabaseUrl: process.env.SUPABASE_URL,
  supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY
});

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
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const orgCtx = await getOrgContext(user.id);
  const snapshot = await getDashboardSnapshot(orgCtx?.orgId);

  // Emit user_action analytics event (fire-and-forget, never blocks render)
  webAnalytics.userAction(
    {
      action: "dashboard_viewed",
      metadata: {
        hasOrg: orgCtx?.orgId != null,
        repoCount: snapshot.repos.length,
        scanCount: snapshot.recentScans.length
      }
    },
    orgCtx?.orgId
  );

  const hasRepos = snapshot.repos.length > 0;

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

      {hasRepos ? (
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
              {snapshot.recentScans.length > 0 ? (
                snapshot.recentScans.map((scan) => (
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
                ))
              ) : (
                <p>No recent scan activity.</p>
              )}
            </div>
          </div>
        </section>
      ) : (
        <section className="surface-grid">
          <div className="panel">
            <div className="panel__heading">
              <h2>Connect your first repository</h2>
              <span>Get started</span>
            </div>
            <p>
              No repositories are connected yet. Add a repository to start monitoring native binary dependencies
              across your codebase.
            </p>
            <Link href="/docs/api" className="button-link" style={{ marginTop: "1rem", display: "inline-block" }}>
              View setup guide
            </Link>
          </div>
        </section>
      )}
    </main>
  );
}
