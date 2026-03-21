import Link from "next/link";

import { productCopy } from "@binshield/config";

import { RiskBadge } from "../components/risk-badge";
import { getFeaturedPackages } from "../lib/data";

export default async function HomePage() {
  const featured = await getFeaturedPackages();

  return (
    <main className="home-page">
      <section className="hero">
        <div>
          <p className="eyebrow">Binary supply-chain security</p>
          <h1>{productCopy.tagline}</h1>
          <p className="hero-copy">
            Decompile native package binaries, explain their behavior in plain English, and block risky compiled code
            before it ships.
          </p>
        </div>
        <div className="hero-card">
          <div className="hero-card__terminal">
            <span>$</span>
            <code>binshield scan bcrypt@5.1.1</code>
          </div>
          <div className="hero-card__result">
            <RiskBadge level="low" score={12} />
            <p>Expected bcrypt hashing behavior. No suspicious network activity detected.</p>
          </div>
        </div>
      </section>

      <section className="metrics-grid">
        <article>
          <strong>Compiled code visibility</strong>
          <p>See what `.node`, `.so`, `.dylib`, and WASM artifacts actually do.</p>
        </article>
        <article>
          <strong>Version diffs</strong>
          <p>Track behavioral changes between package releases instead of trusting release notes.</p>
        </article>
        <article>
          <strong>CI policy enforcement</strong>
          <p>Push the same API contract into your GitHub Action and your public package database.</p>
        </article>
      </section>

      <section className="featured-section">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Public database</p>
            <h2>Featured analyses</h2>
          </div>
          <Link href="/dashboard" className="button-link">
            View dashboard
          </Link>
        </div>
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
              <span className="package-tile__meta">
                {item.binaryCount} binaries • latest {item.latestVersion}
              </span>
            </Link>
          ))}
        </div>
      </section>
    </main>
  );
}
