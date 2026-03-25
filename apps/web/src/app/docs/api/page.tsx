import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "API Reference",
  description:
    "BinShield REST API reference — endpoints for packages, scans, advisories, feed, compliance reports, organizations, and billing with example requests.",
  alternates: { canonical: "https://binshield.dev/docs/api" }
};

const API = "https://binshieldapi-production.up.railway.app";

const groups = [
  {
    name: "Packages",
    endpoints: [
      {
        method: "GET",
        path: "/health",
        description: "Service health check and configuration.",
        curl: `curl "${API}/health"`
      },
      {
        method: "GET",
        path: "/packages/search?q={query}",
        description: "Search the public package database by name or keyword.",
        curl: `curl "${API}/packages/search?q=bcrypt"`
      },
      {
        method: "GET",
        path: "/packages/:ecosystem/:name",
        description: "List all analyzed versions of a package.",
        curl: `curl "${API}/packages/npm/bcrypt"`
      },
      {
        method: "GET",
        path: "/packages/:ecosystem/:name/versions/:version",
        description: "Retrieve full analysis for a specific version of a package.",
        curl: `curl "${API}/packages/npm/bcrypt/versions/5.1.1"`
      },
      {
        method: "GET",
        path: "/packages/:ecosystem/:name/versions/:version/sbom",
        description: "Export a CycloneDX 1.5 SBOM for a specific package version.",
        curl: `curl "${API}/packages/npm/bcrypt/versions/5.1.1/sbom"`
      },
      {
        method: "GET",
        path: "/packages/:ecosystem/:name/diff?from={v1}&to={v2}",
        description: "Binary behavior diff between two versions of a package.",
        curl: `curl "${API}/packages/npm/bcrypt/diff?from=5.1.0&to=5.1.1"`
      }
    ]
  },
  {
    name: "Advisories",
    endpoints: [
      {
        method: "GET",
        path: "/packages/:ecosystem/:name/advisories",
        description: "Get known vulnerability advisories for a package (OSV, NVD, GitHub).",
        curl: `curl "${API}/packages/npm/bcrypt/advisories"`
      },
      {
        method: "GET",
        path: "/advisories/recent",
        description: "List recently published advisories across all packages.",
        curl: `curl "${API}/advisories/recent?limit=20"`
      },
      {
        method: "POST",
        path: "/advisories/sync",
        description: "Trigger advisory sync for a specific package from upstream sources.",
        curl: `curl -X POST "${API}/advisories/sync" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"ecosystem":"npm","packageName":"bcrypt"}'`
      }
    ]
  },
  {
    name: "Feed",
    endpoints: [
      {
        method: "GET",
        path: "/feed/events",
        description: "Live stream of ecosystem analysis events (new packages, version updates, risk changes).",
        curl: `curl "${API}/feed/events?limit=50"`
      },
      {
        method: "GET",
        path: "/feed/stats",
        description: "Feed processing statistics — packages processed, native packages found.",
        curl: `curl "${API}/feed/stats"`
      }
    ]
  },
  {
    name: "Scans",
    endpoints: [
      {
        method: "POST",
        path: "/scans/packages",
        description: "Submit a package for binary analysis. Returns a job ID for polling.",
        curl: `curl -X POST "${API}/scans/packages" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"ecosystem":"npm","packageName":"bcrypt","version":"5.1.1"}'`
      },
      {
        method: "GET",
        path: "/scans/:id",
        description: "Poll scan job status and results. Status: queued → processing → complete.",
        curl: `curl "${API}/scans/scan_abc123" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      }
    ]
  },
  {
    name: "Lockfile Scanning",
    endpoints: [
      {
        method: "POST",
        path: "/scans/lockfile",
        description: "Submit a lockfile for dependency-level risk scanning (package-lock.json, yarn.lock, pnpm-lock.yaml).",
        curl: `curl -X POST "${API}/scans/lockfile" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"filename":"package-lock.json","content":"..."}'`
      }
    ]
  },
  {
    name: "Organizations",
    endpoints: [
      {
        method: "GET",
        path: "/orgs/:orgId",
        description: "Retrieve organization profile and usage summary.",
        curl: `curl "${API}/orgs/org_abc123" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "GET",
        path: "/orgs/:orgId/repos",
        description: "List monitored repositories for an organization.",
        curl: `curl "${API}/orgs/org_abc123/repos" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "POST",
        path: "/orgs/:orgId/repos",
        description: "Add a repository to the organization for monitoring.",
        curl: `curl -X POST "${API}/orgs/org_abc123/repos" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"githubRepo":"owner/repo"}'`
      },
      {
        method: "GET",
        path: "/orgs/:orgId/watchlists",
        description: "List watchlists for version-change alerts.",
        curl: `curl "${API}/orgs/org_abc123/watchlists" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "POST",
        path: "/orgs/:orgId/watchlists",
        description: "Create a new watchlist with notification channel.",
        curl: `curl -X POST "${API}/orgs/org_abc123/watchlists" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"name":"Critical deps","channel":"slack","destination":"#security"}'`
      },
      {
        method: "POST",
        path: "/orgs/:orgId/watchlists/:watchlistId/packages",
        description: "Add a package to a watchlist.",
        curl: `curl -X POST "${API}/orgs/org_abc123/watchlists/wl_123/packages" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"ecosystem":"npm","packageName":"sharp"}'`
      },
      {
        method: "GET",
        path: "/orgs/:orgId/subscription",
        description: "Get subscription details and plan limits.",
        curl: `curl "${API}/orgs/org_abc123/subscription" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "POST",
        path: "/orgs/:orgId/subscription",
        description: "Update subscription plan and status.",
        curl: `curl -X POST "${API}/orgs/org_abc123/subscription" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"plan":"pro","status":"active"}'`
      },
      {
        method: "GET",
        path: "/orgs/:orgId/api-keys",
        description: "List API keys for the organization.",
        curl: `curl "${API}/orgs/org_abc123/api-keys" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "POST",
        path: "/orgs/:orgId/api-keys",
        description: "Create a new API key.",
        curl: `curl -X POST "${API}/orgs/org_abc123/api-keys" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"label":"CI pipeline"}'`
      }
    ]
  },
  {
    name: "Compliance Reports",
    endpoints: [
      {
        method: "POST",
        path: "/orgs/:orgId/reports",
        description: "Generate a compliance report (SOC 2, ISO 27001, or EU CRA).",
        curl: `curl -X POST "${API}/orgs/org_abc123/reports" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"reportType":"soc2"}'`
      },
      {
        method: "GET",
        path: "/orgs/:orgId/reports",
        description: "List previously generated compliance reports.",
        curl: `curl "${API}/orgs/org_abc123/reports" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      }
    ]
  },
  {
    name: "Invitations",
    endpoints: [
      {
        method: "POST",
        path: "/orgs/:orgId/invitations",
        description: "Invite a user to join the organization.",
        curl: `curl -X POST "${API}/orgs/org_abc123/invitations" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"email":"user@example.com","role":"member"}'`
      },
      {
        method: "GET",
        path: "/orgs/:orgId/invitations",
        description: "List pending invitations for the organization.",
        curl: `curl "${API}/orgs/org_abc123/invitations" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY"`
      },
      {
        method: "POST",
        path: "/invitations/:token/accept",
        description: "Accept an organization invitation using the invitation token.",
        curl: `curl -X POST "${API}/invitations/inv_token_abc/accept" \\
  -H "Content-Type: application/json" \\
  -d '{"userId":"user_123"}'`
      }
    ]
  },
  {
    name: "Billing",
    endpoints: [
      {
        method: "POST",
        path: "/billing/checkout",
        description: "Create a Stripe checkout session for plan upgrade.",
        curl: `curl -X POST "${API}/billing/checkout" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  -d '{"plan":"pro"}'`
      },
      {
        method: "POST",
        path: "/billing/webhook",
        description: "Stripe webhook handler for subscription lifecycle events.",
        curl: `# Handled automatically by Stripe`
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
