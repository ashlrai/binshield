import Link from "next/link";

import { productCopy } from "@binshield/config";

import { MetricCard } from "../components/metric-card";
import { PageHeader } from "../components/page-header";
import { RiskBadge } from "../components/risk-badge";
import { getDataMode, getFeaturedPackages, getPublicBrowseCounts } from "../lib/site-data";

export default async function HomePage() {
  const featured = await getFeaturedPackages();
  const counts = getPublicBrowseCounts();
  const mode = getDataMode();

  return (
    <main className="home-page">
      <section className="hero">
        <div className="hero__copy">
          <p className="eyebrow">Binary supply-chain security</p>
          <h1>{productCopy.tagline}</h1>
          <p className="hero-copy">
            Decompile native package binaries, explain their behavior in plain English, and block risky compiled code
            before it ships.
          </p>
          <form className="hero-search" action="/search">
            <input name="q" placeholder="Search bcrypt, sharp, sqlite3..." aria-label="Search packages" />
            <button type="submit">Search database</button>
          </form>
          <div className="hero__meta">
            <span className={`status-pill status-pill--${mode === "live" ? "healthy" : "watch"}`}>
              {mode === "live" ? "Live API connected" : "Demo data fallback"}
            </span>
            <span className="hero__meta-note">{counts.packages} packages surfaced, {counts.binaries} binaries tracked</span>
          </div>
        </div>
        <div className="hero-card">
          <div className="hero-card__terminal">
            <span>$</span>
            <code>binshield scan bcrypt@5.1.1</code>
          </div>
          <div className="hero-card__result">
            <RiskBadge level="low" score={12} />
            <p>Expected bcrypt hashing behavior. No suspicious network activity detected.</p>
            <div className="hero-card__stats">
              <span>1 binary</span>
              <span>17 imports</span>
              <span>high confidence</span>
            </div>
          </div>
        </div>
      </section>

      <section className="metrics-grid">
        <MetricCard label="Compiled code visibility" value="Binary-first" detail="Inspect native package artifacts, not just manifests." />
        <MetricCard label="Version diffs" value="Drift-aware" detail="Track behavior changes between package releases." tone="warning" />
        <MetricCard label="CI policy enforcement" value="Action-ready" detail="Reuse the same scan contract in GitHub Actions." tone="accent" />
      </section>

      <section className="surface-grid">
        <PageHeader
          eyebrow="Public database"
          title="Featured analyses"
          description="Browse the highest-signal compiled packages already surfaced in the BinShield database."
          actions={
            <Link href="/packages" className="button-link">
              Open package browser
            </Link>
          }
        />
        <div className="featured-grid">
          {featured.map((item) => (
            <Link key={item.packageName} href={`/packages/${item.packageName}`} className="package-tile">
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
              <span className="package-tile__meta">
                {item.binaryCount} binaries • {item.sourceMatchConfidence} confidence • latest {item.latestVersion}
              </span>
            </Link>
          ))}
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Launch surfaces</h2>
            <span>Built for product discovery and team adoption</span>
          </div>
          <div className="launch-link-grid">
            <Link href="/dashboard" className="launch-link">
              <strong>Dashboard</strong>
              <span>Repository coverage, risk posture, and scan history.</span>
            </Link>
            <Link href="/dashboard/watchlists" className="launch-link">
              <strong>Watchlists</strong>
              <span>Track package versions and receive email alerts.</span>
            </Link>
            <Link href="/dashboard/billing" className="launch-link">
              <strong>Billing</strong>
              <span>Plan usage, invoices, and customer portal handoff.</span>
            </Link>
            <Link href="/dashboard/settings" className="launch-link">
              <strong>Settings</strong>
              <span>API keys, org profile, and audit trail.</span>
            </Link>
          </div>
        </div>
        <div className="panel">
          <div className="panel__heading">
            <h2>How it works</h2>
            <span>Data flow</span>
          </div>
          <ol className="timeline">
            <li>Discover native binaries in npm package tarballs.</li>
            <li>Decompile and classify behavior through queued workers.</li>
            <li>Store immutable package results and surface them in the app.</li>
            <li>Use the same API in CI, dashboard, and future integrations.</li>
          </ol>
        </div>
      </section>
    </main>
  );
}
