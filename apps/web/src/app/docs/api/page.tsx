import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "API Reference",
  description:
    "BinShield REST API reference — endpoints for packages, scans, organizations, and billing with example requests.",
  alternates: { canonical: "https://binshield.dev/docs/api" }
};

const API = "https://binshieldapi-production.up.railway.app";

const groups = [
  {
    name: "Packages",
    endpoints: [
      {
        method: "GET",
        path: "/packages/search?q={query}",
        description: "Search the public package database by name or keyword.",
        curl: `curl "${API}/packages/search?q=bcrypt"`
      },
      {
        method: "GET",
        path: "/packages/{ecosystem}/{name}",
        description: "Retrieve full analysis for a specific package.",
        curl: `curl "${API}/packages/npm/bcrypt"`
      },
      {
        method: "GET",
        path: "/packages/{ecosystem}/{name}/versions/{version}",
        description: "Retrieve analysis for a specific version of a package.",
        curl: `curl "${API}/packages/npm/bcrypt/versions/6.0.0"`
      },
      {
        method: "GET",
        path: "/packages/{ecosystem}/{name}/versions/{version}/sbom",
        description: "Export a CycloneDX 1.5 SBOM for a specific package version.",
        curl: `curl "${API}/packages/npm/bcrypt/versions/6.0.0/sbom"`
      },
      {
        method: "GET",
        path: "/packages/browse",
        description: "Browse all surfaced packages with pagination and filters.",
        curl: `curl "${API}/packages/browse?limit=20&offset=0"`
      }
    ]
  },
  {
    name: "Scans",
    endpoints: [
      {
        method: "POST",
        path: "/scans",
        description: "Submit a new binary scan. Returns a scan ID for polling.",
        curl: `curl -X POST "${API}/scans" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"ecosystem":"npm","package":"bcrypt","version":"6.0.0"}'`
      },
      {
        method: "GET",
        path: "/scans/{scanId}",
        description: "Poll scan status and results. Status progresses: queued -> processing -> complete.",
        curl: `curl "${API}/scans/scan_abc123" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "GET",
        path: "/scans/{scanId}/report",
        description: "Retrieve the full structured report for a completed scan.",
        curl: `curl "${API}/scans/scan_abc123/report" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      }
    ]
  },
  {
    name: "Organizations",
    endpoints: [
      {
        method: "GET",
        path: "/orgs/me",
        description: "Retrieve the authenticated organization profile and usage summary.",
        curl: `curl "${API}/orgs/me" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "GET",
        path: "/orgs/me/api-keys",
        description: "List API keys for the authenticated organization.",
        curl: `curl "${API}/orgs/me/api-keys" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "POST",
        path: "/orgs/me/watchlists",
        description: "Add a package to the organization watchlist for version-change alerts.",
        curl: `curl -X POST "${API}/orgs/me/watchlists" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"ecosystem":"npm","package":"sharp"}'`
      }
    ]
  },
  {
    name: "Billing",
    endpoints: [
      {
        method: "GET",
        path: "/billing/usage",
        description: "Current billing period usage, scan counts, and plan limits.",
        curl: `curl "${API}/billing/usage" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "POST",
        path: "/billing/portal",
        description: "Generate a Stripe customer portal link for plan management.",
        curl: `curl -X POST "${API}/billing/portal" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      }
    ]
  }
];

export default function ApiReferencePage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Reference</p>
            <h1>API Reference</h1>
            <p className="page-copy">
              All public REST endpoints for the BinShield platform. Base URL:{" "}
              <code>{API}</code>
            </p>
          </div>
          <div className="page-header__actions">
            <Link href="/openapi.json" className="button-link">
              OpenAPI spec
            </Link>
          </div>
        </div>

        {groups.map((group) => (
          <div key={group.name} className="panel" style={{ display: "grid", gap: "24px" }}>
            <div className="panel__heading">
              <h2>{group.name}</h2>
            </div>

            {group.endpoints.map((ep) => (
              <div key={ep.path} style={{ display: "grid", gap: "8px" }}>
                <h3 style={{ margin: 0, fontFamily: "var(--font-mono)", fontSize: "0.95rem" }}>
                  <span className="tag tag--review" style={{ marginRight: "8px" }}>
                    {ep.method}
                  </span>
                  {ep.path}
                </h3>
                <p style={{ margin: 0, color: "var(--muted)" }}>{ep.description}</p>
                <pre
                  style={{
                    margin: 0,
                    padding: "14px 16px",
                    borderRadius: "var(--radius-sm)",
                    background: "var(--card-strong)",
                    border: "1px solid var(--border)",
                    overflowX: "auto",
                    fontSize: "0.85rem",
                    lineHeight: 1.5
                  }}
                >
                  <code>{ep.curl}</code>
                </pre>
              </div>
            ))}
          </div>
        ))}
      </div>
    </main>
  );
}
