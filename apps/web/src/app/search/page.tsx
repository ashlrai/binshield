import Link from "next/link";

import { PageHeader } from "../../components/page-header";
import { RiskBadge } from "../../components/risk-badge";
import { searchPackages } from "../../lib/site-data";

export default async function SearchPage({
  searchParams
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q = "" } = await searchParams;
  const results = await searchPackages(q);

  return (
    <main className="browse-page">
      <PageHeader
        eyebrow="Search"
        title="Find compiled packages"
        description="Search by package name, version, or behavior summary. When the backend is unavailable, this page falls back to local launch data."
        actions={
          <form className="inline-search" action="/search">
            <input name="q" defaultValue={q} placeholder="Search bcrypt, sharp, sqlite3..." aria-label="Search packages" />
            <button type="submit">Search</button>
          </form>
        }
      />

      <section className="panel">
        <div className="panel__heading">
          <h2>{q ? `Results for "${q}"` : "Explore the database"}</h2>
          <span>{results.length} packages</span>
        </div>
        <div className="search-results">
          {results.length ? (
            results.map((item) => (
              <Link key={`${item.packageName}-${item.latestVersion}`} href={`/packages/${item.packageName}`} className="search-row">
                <div>
                  <p className="eyebrow">{item.ecosystem}</p>
                  <strong>{item.packageName}</strong>
                  <p>{item.summary}</p>
                  <small className="stack-item__meta">
                    {item.topBehaviors.length ? item.topBehaviors.join(", ") : "No elevated behavior family"} • {item.sourceMatchConfidence} confidence
                  </small>
                </div>
                <div className="search-row__meta">
                  <RiskBadge level={item.riskLevel} score={item.riskScore} />
                  <span>{item.latestVersion}</span>
                </div>
              </Link>
            ))
          ) : (
            <p className="empty-state">No matching packages surfaced from the current dataset. Try a package name like `bcrypt` or `sharp`.</p>
          )}
        </div>
      </section>
    </main>
  );
}
