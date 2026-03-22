import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { PageHeader } from "../../../components/page-header";
import { RiskBadge } from "../../../components/risk-badge";
import { getWatchlistSnapshot } from "../../../lib/site-data";
import { createServerClient, getOrgContext } from "../../../lib/supabase";

export default async function WatchlistsPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const orgCtx = await getOrgContext(user.id);
  const watchlist = await getWatchlistSnapshot(orgCtx?.orgId);

  const hasItems = watchlist.items.length > 0;

  return (
    <main className="dashboard-page">
      <PageHeader
        eyebrow="Watchlists"
        title="Package version monitoring"
        description="Track packages that matter to your org, receive email-first alerts, and review when behavior changes across versions."
        actions={<Link href="/dashboard/settings" className="button-link">Alert settings</Link>}
      />

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Tracked packages</h2>
            <span>{watchlist.items.length} active</span>
          </div>
          {hasItems ? (
            <div className="watchlist-list">
              {watchlist.items.map((item) => (
                <article key={item.packageName} className="watchlist-row">
                  <div>
                    <p className="eyebrow">{item.ecosystem}</p>
                    <h3>{item.packageName}</h3>
                    <p>
                      {item.previousVersion} → {item.currentVersion}
                    </p>
                    <p>{item.note}</p>
                  </div>
                  <div className="watchlist-row__meta">
                    <RiskBadge level={item.riskChange < 0 ? "low" : item.riskChange > 0 ? "high" : "medium"} score={12 + item.riskChange} />
                    <span className={`status-pill status-pill--${item.status === "paused" ? "watch" : item.status === "active" ? "healthy" : "review"}`}>
                      {item.status}
                    </span>
                    <span>{item.channel}</span>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <div>
              <p>No packages are being tracked yet. Create a watchlist to monitor package behavior changes.</p>
              <Link href="/docs/api" className="button-link" style={{ marginTop: "1rem", display: "inline-block" }}>
                Create your first watchlist
              </Link>
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Notification channels</h2>
            <span>{watchlist.mode === "live" ? "Live configuration" : "Launch defaults"}</span>
          </div>
          <div className="stack-list">
            {watchlist.alertChannels.map((channel) => (
              <article key={channel.name} className="stack-item">
                <strong>{channel.name}</strong>
                <p>{channel.detail}</p>
                <span className={`status-pill status-pill--${channel.enabled ? "healthy" : "watch"}`}>
                  {channel.enabled ? "Enabled" : "Disabled"}
                </span>
              </article>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
