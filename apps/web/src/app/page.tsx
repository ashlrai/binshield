import Link from "next/link";

import { productCopy } from "@binshield/config";

import { DemoVideo } from "../components/demo-video";
import { HeroViz } from "../components/hero-viz";
import { MetricCard } from "../components/metric-card";
import { PageHeader } from "../components/page-header";
import { RiskBadge } from "../components/risk-badge";
import { ScanForm } from "../components/scan-form";
import { getDataMode, getFeaturedPackages, getPublicBrowseCounts } from "../lib/site-data";

export default async function HomePage() {
  const [featured, counts, mode] = await Promise.all([
    getFeaturedPackages(),
    getPublicBrowseCounts(),
    getDataMode()
  ]);

  return (
    <main className="home-page">
      <section className="hero">
        <div className="hero__copy">
          <p className="eyebrow">For security &amp; compliance teams</p>
          <h1>
            The <span>binary-level evidence</span> your auditors are asking for.
          </h1>
          <p className="hero-copy">
            Every npm install ships compiled native binaries that no security tool checks. BinShield decompiles them,
            classifies behavior with AI, and generates the audit-ready CycloneDX SBOMs that SOC 2, ISO 27001,
            and EU Cyber Resilience Act compliance require.
          </p>
          <div className="hero__who">
            <span className="hero__who-pill">DevSecOps</span>
            <span className="hero__who-pill">Compliance teams</span>
            <span className="hero__who-pill">AppSec engineers</span>
          </div>
          <form className="hero-search" action="/search">
            <input name="q" placeholder="Search bcrypt, sharp, sqlite3..." aria-label="Search packages" />
            <button type="submit">Search database</button>
          </form>
          <div className="hero__meta">
            <span className={`status-pill status-pill--${mode === "live" ? "healthy" : "watch"}`}>
              {mode === "live" ? "Live" : "Demo"}
            </span>
            <span className="hero__meta-note">{counts.packages} packages · {counts.binaries} binaries analyzed</span>
          </div>
        </div>
        <HeroViz />
      </section>

      <ScanForm apiBase={process.env.BINSHIELD_API_BASE_URL ?? process.env.NEXT_PUBLIC_BINSHIELD_API_BASE_URL ?? ""} />

      <DemoVideo />

      <section className="metrics-grid">
        <MetricCard label="The problem" value="Zero visibility" detail="Native .node binaries execute on your servers. Snyk, Socket, and npm audit only check source code — not compiled machine code." tone="danger" />
        <MetricCard label="The solution" value="AI decompilation" detail="BinShield decompiles binaries, classifies 6 behavior categories with Grok AI, and generates CycloneDX SBOMs for compliance." tone="accent" />
        <MetricCard label="The result" value="Audit-ready evidence" detail="Binary-level documentation that SOC 2, ISO 27001, and EU Cyber Resilience Act auditors require. No other tool produces this." tone="warning" />
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
          {featured.map((item, i) => (
            <Link key={item.packageName} href={`/packages/${item.packageName}`} className="package-tile" style={{ animationDelay: `${0.1 + i * 0.08}s` }}>
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
            <h2>Who is this for?</h2>
            <span>Built for security and compliance teams</span>
          </div>
          <div className="launch-link-grid">
            <Link href="/use-cases/compliance" className="launch-link">
              <strong>Compliance officers</strong>
              <span>Generate binary-level SBOMs for SOC 2, ISO 27001, and EU CRA audits.</span>
            </Link>
            <Link href="/use-cases/ci-cd" className="launch-link">
              <strong>DevSecOps engineers</strong>
              <span>Block risky native binaries in CI with a GitHub Action.</span>
            </Link>
            <Link href="/use-cases/threat-intelligence" className="launch-link">
              <strong>AppSec teams</strong>
              <span>Monitor packages for behavioral changes in compiled code.</span>
            </Link>
            <Link href="/pricing" className="launch-link">
              <strong>Get started free</strong>
              <span>Public database, 3 repos, 50 scans/month. No credit card needed.</span>
            </Link>
          </div>
        </div>
        <div className="panel">
          <div className="panel__heading">
            <h2>How it works</h2>
            <span>3 steps to binary visibility</span>
          </div>
          <ol className="timeline">
            <li><strong>Scan</strong> — Point BinShield at your npm dependencies via GitHub Action, CLI, or API.</li>
            <li><strong>Classify</strong> — AI decompiles every native binary and classifies behavior across 6 categories.</li>
            <li><strong>Document</strong> — Get audit-ready risk scores, behavior reports, and CycloneDX SBOMs.</li>
          </ol>
        </div>
      </section>
    </main>
  );
}
