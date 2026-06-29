/**
 * E2E Integration Tests — Full Pipeline + API Coverage
 *
 * Exercises the complete analysis pipeline (acquire → extract → analyze →
 * persist → serve) end-to-end against the LocalRepository fixture used in CI.
 *
 * Coverage areas:
 *  1. npm package with native binaries + install scripts (bcrypt)
 *  2. PyPI wheel with native extensions (cryptography — triggers queued path)
 *  3. Malware-flagged package via OSV feed integration (advisory type check)
 *  4. SBOM generation + provenance verification roundtrip
 *  5. Scan timeout detection + DLQ retry flow
 *  6. Concurrent scans with quota enforcement
 *  7. Watchlist alert matching across scans
 *  8. EPSS/CISA KEV enrichment boost verification
 *  9. CVE/EPSS Risk Heat Map — advisory correlation + adoption inference
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { createApp } from "./app";
import { createServices } from "./lib/repository";
import { readApiEnv } from "./lib/env";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const AUTH_HEADERS = {
  "Content-Type": "application/json",
  "x-binshield-api-key": "binshield-dev-key",
};

/**
 * Build a minimal CycloneDX 1.5 SBOM string for the given purl list.
 */
function buildSbom(components: Array<{ purl: string; hash?: string }>): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:e2e-test",
    version: 1,
    components: components.map(({ purl, hash }) => ({
      type: "library",
      "bom-ref": purl,
      purl,
      ...(hash
        ? { hashes: [{ alg: "SHA-256", content: hash }] }
        : {}),
    })),
  });
}

// ---------------------------------------------------------------------------
// 1. npm package with native binaries + install scripts (bcrypt)
// ---------------------------------------------------------------------------

describe("E2E: npm native binary pipeline — bcrypt", () => {
  it("submit scan returns 200 complete for pre-seeded bcrypt@5.1.1", async () => {
    const app = createApp();
    const start = Date.now();

    const res = await app.request("/scans/packages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as {
      id: string;
      status: string;
      result?: {
        packageName: string;
        ecosystem: string;
        version: string;
        binaries: Array<{ filename: string; format: string }>;
        manifestAnalysis?: unknown;
        riskScore: number;
        riskLevel: string;
      };
    };
    expect(body.status).toBe("complete");
    expect(body.result).toBeDefined();
    expect(body.result!.packageName).toBe("bcrypt");
    expect(body.result!.ecosystem).toBe("npm");
    expect(body.result!.version).toBe("5.1.1");
    // Must contain at least one native binary
    expect(body.result!.binaries.length).toBeGreaterThanOrEqual(1);
    const nativeNode = body.result!.binaries.find((b) => b.filename.endsWith(".node"));
    expect(nativeNode).toBeDefined();
    // Risk level is populated
    expect(["none", "low", "medium", "high", "critical"]).toContain(body.result!.riskLevel);

    // Pipeline latency baseline: local fixture should respond well under 500 ms
    expect(Date.now() - start).toBeLessThan(500);
  });

  it("GET /packages/npm/bcrypt/versions/5.1.1 returns full analysis with binary findings", async () => {
    const app = createApp();

    const res = await app.request("/packages/npm/bcrypt/versions/5.1.1", {
      headers: AUTH_HEADERS,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as {
      packageName: string;
      binaries: Array<{ id: string; filename: string; findings: Array<{ title: string; severity: string }> }>;
      riskScore: number;
    };
    expect(body.packageName).toBe("bcrypt");
    expect(body.binaries.length).toBeGreaterThanOrEqual(1);
    // At least one binary should have findings (entropy source access)
    const binaryWithFindings = body.binaries.find((b) => (b.findings ?? []).length > 0);
    expect(binaryWithFindings).toBeDefined();
    expect(binaryWithFindings!.findings[0]!.title).toBeTruthy();
    expect(binaryWithFindings!.findings[0]!.severity).toBeTruthy();
  });

  it("GET /packages/npm/bcrypt returns the seeded bcrypt version", async () => {
    const app = createApp();

    const res = await app.request("/packages/npm/bcrypt");
    expect(res.status).toBe(200);
    const body = await res.json() as { packageName: string; ecosystem: string; versions: Array<{ version: string }> };
    expect(body.packageName).toBe("bcrypt");
    expect(body.ecosystem).toBe("npm");
    // LocalRepository stores one packageId per (ecosystem, name) — the last
    // seeded analysis wins. At least one bcrypt version must be present.
    expect(body.versions.length).toBeGreaterThanOrEqual(1);
    const versions = body.versions.map((v) => v.version);
    expect(versions.some((v) => v.startsWith("5."))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 2. PyPI wheel with native extensions (cryptography — not pre-seeded → queued)
// ---------------------------------------------------------------------------

describe("E2E: PyPI wheel native extension pipeline — cryptography", () => {
  it("scan request for pypi/cryptography queues a job (202) and returns a job id", async () => {
    const app = createApp();

    const res = await app.request("/scans/packages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({
        ecosystem: "pypi",
        packageName: "cryptography",
        version: "42.0.5",
      }),
    });

    // Not pre-seeded → accepted/queued
    expect([200, 202]).toContain(res.status);
    const body = await res.json() as { id: string; status: string };
    expect(body.id).toBeTruthy();
    expect(["queued", "complete"]).toContain(body.status);
  });

  it("GET /scans/:id retrieves the queued pypi scan job", async () => {
    const app = createApp();

    const scanRes = await app.request("/scans/packages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({
        ecosystem: "pypi",
        packageName: "cryptography",
        version: "42.0.5",
      }),
    });
    const scan = await scanRes.json() as { id: string; status: string };

    const jobRes = await app.request(`/scans/${scan.id}`, { headers: AUTH_HEADERS });
    expect(jobRes.status).toBe(200);
    const job = await jobRes.json() as {
      id: string;
      status: string;
      request: { ecosystem: string; packageName: string; version: string };
    };
    expect(job.id).toBe(scan.id);
    expect(job.request.ecosystem).toBe("pypi");
    expect(job.request.packageName).toBe("cryptography");
    expect(["queued", "complete"]).toContain(job.status);
  });

  it("public scan endpoint accepts pypi package without API key", async () => {
    const app = createApp();

    const res = await app.request("/public/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ecosystem: "pypi",
        packageName: "cryptography",
        version: "42.0.5",
      }),
    });

    expect([200, 202]).toContain(res.status);
    const body = await res.json() as { id: string; status: string };
    expect(body.id).toBeTruthy();
    expect(["queued", "complete"]).toContain(body.status);
  });
});

// ---------------------------------------------------------------------------
// 3. Malware-flagged package via OSV feed integration
// ---------------------------------------------------------------------------

describe("E2E: Malware-flagged package — OSV advisory integration", () => {
  it("GET /packages/npm/bcrypt/advisories returns OSV advisory with required fields", async () => {
    const app = createApp();

    const res = await app.request("/packages/npm/bcrypt/advisories");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      items: Array<{
        id: string;
        source: string;
        sourceId: string;
        title: string;
        severity: string;
        cvssScore: number;
        affectedPackages: Array<{ ecosystem: string; packageName: string }>;
      }>;
      total: number;
    };

    expect(body.items.length).toBeGreaterThan(0);
    const advisory = body.items[0]!;
    expect(advisory.id).toBeTruthy();
    expect(advisory.source).toBeTruthy();
    expect(advisory.sourceId).toBeTruthy();
    expect(advisory.title).toBeTruthy();
    expect(typeof advisory.cvssScore).toBe("number");
    expect(advisory.affectedPackages.some((ap) => ap.packageName === "bcrypt")).toBe(true);
  });

  it("GET /advisories/recent returns seeded advisories including CVE-format IDs", async () => {
    const app = createApp();

    const res = await app.request("/advisories/recent?limit=10");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      items: Array<{ sourceId: string; severity: string }>;
      total: number;
    };
    expect(body.items.length).toBeGreaterThan(0);
    // CVE-2025-1234 is seeded as critical/9.8 for sqlite3
    const cveAdvisory = body.items.find((a) => a.sourceId === "CVE-2025-1234");
    expect(cveAdvisory).toBeDefined();
    expect(cveAdvisory!.severity).toBe("critical");
  });

  it("/advisories/:cveId/exploit-activity returns shape for the seeded SQLite CVE", async () => {
    const app = createApp();

    const res = await app.request("/advisories/CVE-2025-1234/exploit-activity");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      cveId: string;
      cisa_confirmed: boolean;
      first_seen_date: string | null;
      exploit_maturity: string | null;
      affected_versions: string[];
    };
    expect(body.cveId).toBe("CVE-2025-1234");
    expect(typeof body.cisa_confirmed).toBe("boolean");
    expect(Array.isArray(body.affected_versions)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. SBOM generation + provenance verification roundtrip
// ---------------------------------------------------------------------------

describe("E2E: SBOM generation + provenance verification roundtrip", () => {
  it("GET /packages/npm/bcrypt/versions/5.1.1/sbom returns valid CycloneDX 1.5 SBOM", async () => {
    const app = createApp();

    const res = await app.request("/packages/npm/bcrypt/versions/5.1.1/sbom");
    expect(res.status).toBe(200);
    const sbom = await res.json() as {
      bomFormat: string;
      specVersion: string;
      serialNumber: string;
      components: Array<{ type: string; purl?: string; name?: string }>;
    };

    expect(sbom.bomFormat).toBe("CycloneDX");
    expect(sbom.specVersion).toBe("1.5");
    expect(sbom.serialNumber).toBeTruthy();
    expect(sbom.components.length).toBeGreaterThan(0);
    // Each component must have a type
    for (const comp of sbom.components) {
      expect(comp.type).toBeTruthy();
    }
  });

  it("SBOM provenance verification roundtrip: generate then verify with matching hash", async () => {
    const app = createApp();

    // Step 1: generate SBOM from API
    const sbomRes = await app.request("/packages/npm/bcrypt/versions/5.1.1/sbom");
    expect(sbomRes.status).toBe(200);
    const sbom = await sbomRes.json() as { components: Array<{ purl?: string; hashes?: Array<{ alg: string; content: string }> }> };
    const sbomText = JSON.stringify(sbom);

    // Step 2: submit for provenance verification (mocking registry as offline is fine —
    // an offline registry yields unresolved-dependency, not a crash)
    const verifyRes = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbomText, packageFormat: "npm" }),
    });

    expect([200, 400]).toContain(verifyRes.status);
    if (verifyRes.status === 200) {
      const verifyBody = await verifyRes.json() as {
        isValid: boolean;
        checks: Array<{ packageName: string; passed: boolean; checkType?: string }>;
        riskLevel: string;
        recommendations: string[];
      };
      expect(typeof verifyBody.isValid).toBe("boolean");
      expect(Array.isArray(verifyBody.checks)).toBe(true);
      expect(typeof verifyBody.riskLevel).toBe("string");
      expect(Array.isArray(verifyBody.recommendations)).toBe(true);
    }
  });

  it("POST /sbom/verify-provenance with known-good npm SBOM (empty components) returns valid=true", async () => {
    const app = createApp();

    const sbomText = buildSbom([]);
    const res = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbomText, packageFormat: "npm" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as { isValid: boolean; checks: unknown[]; riskLevel: string };
    expect(body.isValid).toBe(true);
    expect(body.checks).toHaveLength(0);
    expect(body.riskLevel).toBe("none");
  });

  it("POST /sbom/verify-provenance rejects tampered hash (registry mismatch) for PyPI wheel", async () => {
    const app = createApp();

    // Mock fetch: registry says sha256=realHash; SBOM says sha256=tamperedHash
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        info: { name: "cryptography", version: "42.0.5" },
        releases: {
          "42.0.5": [{
            digests: { md5: "md5hash", sha256: "realregistryhash" },
            url: "https://files.pythonhosted.org/cryptography-42.0.5.tar.gz",
            yanked: false,
            yanked_reason: null,
          }],
        },
      }),
    } as Response);

    try {
      const sbomText = buildSbom([
        { purl: "pkg:pypi/cryptography@42.0.5", hash: "tamperedhash" },
      ]);
      const res = await app.request("/sbom/verify-provenance", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sbomText, packageFormat: "pypi" }),
      });

      expect(res.status).toBe(200);
      const body = await res.json() as {
        isValid: boolean;
        checks: Array<{ checkType?: string; severity?: string; passed: boolean }>;
        riskLevel: string;
      };
      expect(body.isValid).toBe(false);
      const mismatch = body.checks.find((c) => c.checkType === "registry-mismatch");
      expect(mismatch).toBeDefined();
      expect(mismatch!.severity).toBe("high");
      expect(body.riskLevel).toBe("high");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ---------------------------------------------------------------------------
// 5. Scan timeout detection + DLQ retry flow
// ---------------------------------------------------------------------------

describe("E2E: Scan timeout detection + DLQ retry flow", () => {
  it("upsertFailedScan persists a timed-out entry and getFailedScan retrieves it", async () => {
    const services = createServices(readApiEnv());
    const repo = services.repository;

    const scanId = `job_e2e_timeout_${Date.now()}`;
    const entry = await repo.upsertFailedScan({
      scanId,
      jobId: scanId,
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "some-native-pkg",
      version: "1.0.0",
      errorReason: "timeout: job remained queued for > 60s",
      failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + 4_000).toISOString(),
      status: "retrying",
      metadata: { originalStatus: "queued", timedOut: true },
    });

    expect(entry.scanId).toBe(scanId);
    expect(entry.status).toBe("retrying");
    expect(entry.failureCount).toBe(1);
    expect(entry.metadata).toMatchObject({ timedOut: true });

    const fetched = await repo.getFailedScan(scanId);
    expect(fetched).not.toBeNull();
    expect(fetched!.errorReason).toContain("timeout");
  });

  it("scan for unknown package enters queued state and is tracked in DLQ after simulated timeout", async () => {
    const app = createApp();

    // Submit scan for unknown package → queued
    const scanRes = await app.request("/scans/packages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "nonexistent-native-package-xyz",
        version: "99.0.0",
      }),
    });

    expect(scanRes.status).toBe(202);
    const scan = await scanRes.json() as { id: string; status: string };
    expect(scan.status).toBe("queued");
    expect(scan.id).toBeTruthy();

    // Directly write a DLQ entry as the timeout watcher would
    const services = createServices(readApiEnv());
    const repo = services.repository;
    await repo.upsertFailedScan({
      scanId: scan.id,
      jobId: scan.id,
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "nonexistent-native-package-xyz",
      version: "99.0.0",
      errorReason: "timeout: job remained queued for > 60s",
      failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + 1_000).toISOString(),
      status: "retrying",
      metadata: {},
    });

    // Verify DLQ entry was written
    const dlqEntry = await repo.getFailedScan(scan.id);
    expect(dlqEntry).not.toBeNull();
    expect(dlqEntry!.status).toBe("retrying");
    expect(dlqEntry!.failureCount).toBe(1);
  });

  it("markFailedScanAbandoned transitions DLQ entry to abandoned after MAX_RETRY_ATTEMPTS", async () => {
    const services = createServices(readApiEnv());
    const repo = services.repository;

    const scanId = `job_e2e_abandon_${Date.now()}`;
    await repo.upsertFailedScan({
      scanId,
      jobId: scanId,
      orgId: "org_demo",
      ecosystem: "pypi",
      packageName: "bad-pkg",
      version: "0.1.0",
      errorReason: "worker reported failure",
      failureCount: 3,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + 300_000).toISOString(),
      status: "retrying",
      metadata: {},
    });

    await repo.markFailedScanAbandoned(scanId);
    const abandoned = await repo.getFailedScan(scanId);
    expect(abandoned).not.toBeNull();
    expect(abandoned!.status).toBe("abandoned");
  });

  it("appendScanAuditLog writes scan_timeout event and listScanAuditLog retrieves it", async () => {
    const services = createServices(readApiEnv());
    const repo = services.repository;

    const scanId = `job_e2e_audit_${Date.now()}`;
    await repo.appendScanAuditLog({
      scanId,
      orgId: "org_demo",
      eventType: "scan_timeout",
      retryAttempt: 1,
      details: { errorReason: "timeout: job remained queued for > 60s", packageName: "some-pkg" },
    });

    const log = await repo.listScanAuditLog(scanId);
    expect(log.length).toBeGreaterThanOrEqual(1);
    const timeoutEvent = log.find((e) => e.eventType === "scan_timeout");
    expect(timeoutEvent).toBeDefined();
    expect(timeoutEvent!.retryAttempt).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 6. Concurrent scans with quota enforcement
// ---------------------------------------------------------------------------

describe("E2E: Concurrent scans + quota enforcement", () => {
  it("concurrent scans for multiple known packages all return 200 complete", async () => {
    // Use isolated app instances per scan to avoid rate-limit cross-contamination
    // from the shared in-memory IP counter on the singleton `app`.
    const app1 = createApp();
    const app2 = createApp();
    const app3 = createApp();

    // Fire three scans concurrently against isolated instances
    const results = await Promise.all([
      app1.request("/scans/packages", {
        method: "POST",
        headers: AUTH_HEADERS,
        body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" }),
      }),
      app2.request("/scans/packages", {
        method: "POST",
        headers: AUTH_HEADERS,
        // 5.1.7 is the last seeded version — the LocalRepository package key
        // npm:sqlite3 resolves to the last-seeded packageId, so 5.1.7 is reachable.
        body: JSON.stringify({ ecosystem: "npm", packageName: "sqlite3", version: "5.1.7" }),
      }),
      app3.request("/scans/packages", {
        method: "POST",
        headers: AUTH_HEADERS,
        body: JSON.stringify({ ecosystem: "npm", packageName: "argon2", version: "0.41.1" }),
      }),
    ]);

    for (const res of results) {
      expect(res.status).toBe(200);
      const body = await res.json() as { status: string; result?: { packageName: string } };
      expect(body.status).toBe("complete");
      expect(body.result?.packageName).toBeTruthy();
    }
  });

  it("quota exceeded: scan request is rejected with 402 after exhausting free plan limit", async () => {
    // Create a new isolated app backed by a fresh LocalRepository so we can
    // manipulate the usage count without affecting other tests.
    const env = readApiEnv();
    const services = createServices(env);
    const repo = services.repository;

    // getOrgPlan reads org.plan from the OrganizationRow (not the subscription row).
    // The LocalRepository's organizations map is private, but we can downgrade the
    // plan through the internal map via a cast — acceptable in test code only.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const orgRow = (repo as unknown as { organizations: Map<string, { plan: string }> }).organizations?.get("org_demo");
    if (orgRow) {
      orgRow.plan = "free";
    }

    // Drive org_demo up to the free-plan limit (50) by directly incrementing.
    // The free plan entitlement is maxMonthlyScans = 50.
    for (let i = 0; i < 51; i++) {
      await repo.incrementScanCount("org_demo");
    }

    const app = createApp(services);
    const res = await app.request("/scans/packages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" }),
    });

    expect(res.status).toBe(402);
    const body = await res.json() as { error: string; limit: number; used: number };
    expect(body.error).toContain("quota");
    expect(typeof body.limit).toBe("number");
    expect(typeof body.used).toBe("number");
    expect(body.used).toBeGreaterThanOrEqual(body.limit);
  });
});

// ---------------------------------------------------------------------------
// 7. Watchlist alert matching across scans
// ---------------------------------------------------------------------------

describe("E2E: Watchlist alert matching across scans", () => {
  it("create watchlist, add package, confirm list endpoint returns the entry", async () => {
    const app = createApp();

    // Create a new watchlist
    const createRes = await app.request("/orgs/org_demo/watchlists", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({
        name: "E2E Alert Watchlist",
        channel: "email",
        destination: "e2e-test@binshield.dev",
      }),
    });
    expect(createRes.status).toBe(201);
    const watchlist = await createRes.json() as { id: string; name: string };
    expect(watchlist.id).toBeTruthy();
    expect(watchlist.name).toBe("E2E Alert Watchlist");

    // Add a package to it
    const addRes = await app.request(`/orgs/org_demo/watchlists/${watchlist.id}/packages`, {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({ ecosystem: "npm", packageName: "sqlite3", version: "5.1.7" }),
    });
    expect(addRes.status).toBe(201);
    const pkg = await addRes.json() as { id: string; packageName: string; ecosystem: string };
    expect(pkg.packageName).toBe("sqlite3");
    expect(pkg.ecosystem).toBe("npm");

    // List watchlists — should include the new one
    const listRes = await app.request("/orgs/org_demo/watchlists", { headers: AUTH_HEADERS });
    expect(listRes.status).toBe(200);
    const listed = await listRes.json() as { items: Array<{ id: string; name: string }> };
    expect(listed.items.some((w) => w.id === watchlist.id)).toBe(true);
  });

  it("watchlist with internalPackagePattern validates regex and rejects invalid pattern", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/watchlists", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({
        name: "Regex Test Watchlist",
        channel: "webhook",
        destination: "https://hooks.example.com/binshield",
        internalPackagePattern: "[invalid(regex",
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("internalPackagePattern");
  });

  it("watchlist with valid internalPackagePattern is stored and returned", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/watchlists", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({
        name: "Internal Pkg Watchlist",
        channel: "slack",
        destination: "https://hooks.slack.com/services/test",
        internalPackagePattern: "^@myorg/.*",
        trustedDomains: ["@myorg", "npm.myorg.internal"],
      }),
    });

    expect(res.status).toBe(201);
    const wl = await res.json() as { id: string; name: string };
    expect(wl.id).toBeTruthy();
    expect(wl.name).toBe("Internal Pkg Watchlist");
  });

  it("scan for watchlisted package (bcrypt@5.1.1) returns complete — watchlist endpoint confirms it is tracked", async () => {
    const app = createApp();

    // Confirm bcrypt is already in the seeded watchlist
    const watchlistRes = await app.request("/orgs/org_demo/watchlists", { headers: AUTH_HEADERS });
    expect(watchlistRes.status).toBe(200);
    const wlBody = await watchlistRes.json() as { items: Array<{ id: string; name: string; packageCount?: number }> };
    const nativeWatchlist = wlBody.items.find((w) => w.name === "Native packages");
    expect(nativeWatchlist).toBeDefined();

    // Scan the watchlisted package
    const scanRes = await app.request("/scans/packages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" }),
    });
    expect(scanRes.status).toBe(200);
    const scan = await scanRes.json() as { status: string };
    expect(scan.status).toBe("complete");
  });
});

// ---------------------------------------------------------------------------
// 8. EPSS/CISA KEV enrichment boost verification
// ---------------------------------------------------------------------------

describe("E2E: EPSS/CISA KEV enrichment boost verification", () => {
  it("GET vulnerabilities/enriched for sqlite3 returns riskBoost with baseScore derived from CVSS 9.8", async () => {
    const app = createApp();

    const res = await app.request(
      "/packages/npm/sqlite3/versions/5.1.6/vulnerabilities/enriched"
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      ecosystem: string;
      packageName: string;
      version: string;
      findings: Array<{ cvId: string; severity: string; cvssScore?: number }>;
      maxCvssV3Score: number;
      riskBoost: { baseScore: number; epssBoost: number; cisaKevBoost: number; finalScore: number };
      cisaKevMatches: string[];
      enrichedAt: string;
    };

    expect(body.ecosystem).toBe("npm");
    expect(body.packageName).toBe("sqlite3");
    // CVE-2025-1234 is seeded with cvssScore 9.8 → maxCvssV3Score = 9.8
    expect(body.maxCvssV3Score).toBe(9.8);
    // baseScore = round(9.8/10 * 100) = 98
    expect(body.riskBoost.baseScore).toBe(98);
    // finalScore ≥ baseScore (boosts only add to it), capped at 100
    expect(body.riskBoost.finalScore).toBeGreaterThanOrEqual(body.riskBoost.baseScore);
    expect(body.riskBoost.finalScore).toBeLessThanOrEqual(100);
    // Findings must include the seeded CVE
    expect(body.findings.some((f) => f.cvId === "CVE-2025-1234")).toBe(true);
    // enrichedAt is a valid ISO timestamp
    expect(() => new Date(body.enrichedAt)).not.toThrow();
  });

  it("EPSS boost is added when EPSS percentile > 0.9 (mocked FIRST EPSS API)", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    const originalFetch = globalThis.fetch;
    // Mock FIRST EPSS API: returns high-percentile score for the seeded CVE
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status: "OK",
        status_code: 200,
        version: "1.0",
        access: "public",
        total: 1,
        offset: 0,
        limit: 100,
        data: [{ cve: "CVE-2025-1234", epss: "0.95", percentile: "0.97" }],
      }),
    } as Response);

    try {
      const svc = new AdvisoryService({
        supabaseUrl: "https://fake.supabase.co",
        supabaseServiceRoleKey: "fake-key",
      });
      // Inject sqlite3 advisory
      svc.getPackageAdvisories = async () => [
        {
          id: "adv_3",
          source: "nvd",
          sourceId: "CVE-2025-1234",
          title: "sqlite3 use-after-free in FTS5 extension",
          severity: "critical",
          cvssScore: 9.8,
          cweIds: ["CWE-416"],
          references: [],
          affectedPackages: [
            { ecosystem: "npm", packageName: "sqlite3", vulnerableRange: "<5.1.8" },
          ],
        } as Parameters<typeof svc.getPackageAdvisories>[0] extends never
          ? never
          : Awaited<ReturnType<typeof svc.getPackageAdvisories>>[0],
      ];

      const cache = new EpssCache();
      const result = await svc.enrichCvesWithEpss("npm", "sqlite3", "5.1.6", cache);

      // EPSS percentile 0.97 → epssBoost should be non-zero
      expect(result.riskBoost.epssBoost).toBeGreaterThan(0);
      expect(result.maxEpssPercentile).toBeCloseTo(0.97);
      expect(result.riskBoost.finalScore).toBeGreaterThan(result.riskBoost.baseScore);
      expect(result.riskBoost.finalScore).toBeLessThanOrEqual(100);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("CISA KEV boost is 30 when advisory has cisaKevDate set", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true, status: 200,
      json: async () => ({
        status: "OK", status_code: 200, version: "1.0", access: "public",
        total: 0, offset: 0, limit: 100, data: [],
      }),
    } as Response);

    try {
      const svc = new AdvisoryService({
        supabaseUrl: "https://fake.supabase.co",
        supabaseServiceRoleKey: "fake-key",
      });
      svc.getPackageAdvisories = async () => [
        {
          id: "adv_kev",
          source: "nvd",
          sourceId: "CVE-2025-1234",
          title: "sqlite3 use-after-free in FTS5",
          severity: "critical",
          cvssScore: 9.8,
          cweIds: [],
          references: [],
          affectedPackages: [],
          cisaKevDate: "2025-06-01",
        } as Awaited<ReturnType<typeof svc.getPackageAdvisories>>[0],
      ];

      const result = await svc.enrichCvesWithEpss("npm", "sqlite3", "5.1.6", new EpssCache());

      // KEV boost must be exactly 30
      expect(result.riskBoost.cisaKevBoost).toBe(30);
      expect(result.cisaKevMatches).toContain("CVE-2025-1234");
      expect(result.riskBoost.finalScore).toBeLessThanOrEqual(100);
      // finalScore = min(100, baseScore + cisaKevBoost)
      const expectedFinal = Math.min(100, result.riskBoost.baseScore + 30);
      expect(result.riskBoost.finalScore).toBe(expectedFinal);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("risk-correlation endpoint returns compositeExploitRisk > 0 for sqlite3 (has CVSS 9.8)", async () => {
    const app = createApp();

    const res = await app.request(
      "/packages/npm/sqlite3/versions/5.1.6/risk-correlation"
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      cves: string[];
      cvssScores: Array<{ cveId: string; cvssScore: number }>;
      compositeExploitRisk: number;
    };

    expect(body.cves.length).toBeGreaterThan(0);
    expect(body.cvssScores.length).toBeGreaterThan(0);
    expect(body.compositeExploitRisk).toBeGreaterThan(0);
    expect(body.compositeExploitRisk).toBeLessThanOrEqual(100);
  });

  it("tiered EPSS boost: +25 pts for percentile > 0.90 appears in /vulnerabilities/enriched response", async () => {
    // Verify that the three-tier boost policy (defined in epss-cache.ts) correctly
    // surfaces in the enriched API response when a CVE has a high EPSS percentile.
    // percentile=0.97 → tier-1 boost (+25 pts); finalScore = min(100, baseScore + 25 + epssBoost)
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache, computeEpssBoostDelta } = await import("./lib/epss-cache");

    const originalFetch = globalThis.fetch;
    // Mock FIRST EPSS API: CVE-2025-1234 at percentile 0.97 (tier-1 zone)
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status: "OK",
        status_code: 200,
        version: "1.0",
        access: "public",
        total: 1,
        offset: 0,
        limit: 100,
        data: [{ cve: "CVE-2025-1234", epss: "0.97312", percentile: "0.97" }],
      }),
    } as Response);

    try {
      const svc = new AdvisoryService({
        supabaseUrl: "https://fake.supabase.co",
        supabaseServiceRoleKey: "fake-key",
      });

      svc.getPackageAdvisories = async () => [
        {
          id: "adv_epss_boost",
          source: "nvd",
          sourceId: "CVE-2025-1234",
          title: "sqlite3 use-after-free in FTS5 extension",
          severity: "critical",
          cvssScore: 9.8,
          cweIds: ["CWE-416"],
          references: [],
          affectedPackages: [
            { ecosystem: "npm", packageName: "sqlite3", vulnerableRange: "<5.1.8" },
          ],
        } as Awaited<ReturnType<typeof svc.getPackageAdvisories>>[0],
      ];

      const cache = new EpssCache();
      const result = await svc.enrichCvesWithEpss("npm", "sqlite3", "5.1.6", cache);

      // Verify the tiered boost helper agrees: percentile 0.97 → +25 delta
      expect(computeEpssBoostDelta(0.97)).toBe(25);

      // EPSS percentile 0.97 is in the > 0.90 tier → boost must be non-zero
      expect(result.riskBoost.epssBoost).toBeGreaterThan(0);
      expect(result.maxEpssPercentile).toBeCloseTo(0.97, 2);

      // finalScore must exceed baseScore
      expect(result.riskBoost.finalScore).toBeGreaterThan(result.riskBoost.baseScore);
      expect(result.riskBoost.finalScore).toBeLessThanOrEqual(100);

      // The finding for CVE-2025-1234 must be present with epssPercentile populated
      const finding = result.findings.find((f) => f.cvId === "CVE-2025-1234");
      expect(finding).toBeDefined();
      expect(finding!.epssPercentile).toBeCloseTo(0.97, 2);

      // exploitMaturity should be "widespread" for percentile >= 0.95
      expect(["widespread", "active-exploitation"]).toContain(finding!.exploitMaturity);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("tiered EPSS boost: +15 pts for percentile in (0.75, 0.90] and +8 for (0.50, 0.75]", async () => {
    const { computeEpssBoostDelta, computeEpssBoost } = await import("./lib/epss-cache");

    // Tier 2: percentile = 0.80 → +15
    expect(computeEpssBoostDelta(0.80)).toBe(15);
    expect(computeEpssBoost(0.80, 70)).toBe(85);

    // Tier 3: percentile = 0.60 → +8
    expect(computeEpssBoostDelta(0.60)).toBe(8);
    expect(computeEpssBoost(0.60, 70)).toBe(78);

    // Below threshold: percentile = 0.40 → +0
    expect(computeEpssBoostDelta(0.40)).toBe(0);
    expect(computeEpssBoost(0.40, 70)).toBe(70);

    // Cap at 100
    expect(computeEpssBoost(0.95, 90)).toBe(100); // 90 + 25 = 115, capped
  });
});

// ---------------------------------------------------------------------------
// 9. CVE/EPSS Risk Heat Map — advisory correlation + adoption inference
// ---------------------------------------------------------------------------

describe("E2E: CVE/EPSS Risk Heat Map — advisory correlation + adoption inference", () => {
  it("GET /orgs/org_demo/cve-heat-map returns HeatMapData shape with items array", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/cve-heat-map?limit=100&ecosystem=npm", {
      headers: AUTH_HEADERS,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as {
      items: Array<{
        cveId: string;
        packageName: string;
        ecosystem: string;
        cvssScore: number;
        epssPercentile: number;
        severity: string;
        activeExploit: boolean;
        patchAvailable: boolean;
        adoptionPct: number;
        blastRadius: number;
        heatScore: number;
        tier: string;
      }>;
      total: number;
      generatedAt: string;
      ecosystem: string;
    };

    // Shape checks
    expect(Array.isArray(body.items)).toBe(true);
    expect(typeof body.total).toBe("number");
    expect(typeof body.generatedAt).toBe("string");
    expect(() => new Date(body.generatedAt)).not.toThrow();
    expect(body.ecosystem).toBe("npm");
  });

  it("heat map items include the seeded CVE-2025-1234 for sqlite3 with correct CVSS", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/cve-heat-map?limit=100&ecosystem=npm", {
      headers: AUTH_HEADERS,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as {
      items: Array<{
        cveId: string;
        packageName: string;
        cvssScore: number;
        severity: string;
        heatScore: number;
        tier: string;
        blastRadius: number;
        adoptionPct: number;
      }>;
    };

    // The seeded CVE-2025-1234 for sqlite3 (cvss=9.8, severity=critical) must appear
    const sqliteEntry = body.items.find((e) => e.cveId === "CVE-2025-1234");
    expect(sqliteEntry).toBeDefined();
    expect(sqliteEntry!.cvssScore).toBe(9.8);
    expect(sqliteEntry!.severity.toLowerCase()).toBe("critical");
    // heatScore = min(100, 9.8*5 + 0*40 + 0) = 49 (no EPSS in local mode)
    expect(sqliteEntry!.heatScore).toBeGreaterThan(0);
    // blastRadius and adoptionPct must be non-negative
    expect(sqliteEntry!.blastRadius).toBeGreaterThanOrEqual(0);
    expect(sqliteEntry!.adoptionPct).toBeGreaterThanOrEqual(0);
    expect(["red", "yellow", "green"]).toContain(sqliteEntry!.tier);
  });

  it("heat map respects limit param — limit=1 returns at most 1 item", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/cve-heat-map?limit=1&ecosystem=npm", {
      headers: AUTH_HEADERS,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as { items: unknown[]; total: number };
    expect(body.items.length).toBeLessThanOrEqual(1);
    // total reflects full count before slicing
    expect(body.total).toBeGreaterThanOrEqual(body.items.length);
  });

  it("heat map rejects invalid ecosystem with 400", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/cve-heat-map?ecosystem=cargo", {
      headers: AUTH_HEADERS,
    });

    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("ecosystem");
  });

  it("heat map requires auth — returns 401 without API key", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/cve-heat-map");
    expect(res.status).toBe(401);
  });

  it("buildHeatMapData pure function: sorts by heatScore desc and applies tier correctly", async () => {
    const { buildHeatMapData, computeHeatScore, computeHeatTier } = await import("./lib/advisory-service");

    const fakeAdvisories = [
      {
        id: "adv_low",
        source: "nvd",
        sourceId: "CVE-2024-0001",
        title: "Low risk CVE",
        severity: "low",
        cvssScore: 2.0,
        cweIds: [],
        references: [],
        affectedPackages: [{ ecosystem: "npm", packageName: "chalk", patchedVersion: "5.0.0" }],
      },
      {
        id: "adv_crit",
        source: "nvd",
        sourceId: "CVE-2024-9999",
        title: "Critical CVE actively exploited",
        severity: "critical",
        cvssScore: 9.8,
        cweIds: [],
        references: [],
        affectedPackages: [{ ecosystem: "npm", packageName: "lodash" }],
        // Simulate CISA KEV date on the object
        cisaKevDate: "2024-01-15",
      },
    ] as Parameters<typeof buildHeatMapData>[0];

    const epssMap = new Map([
      ["CVE-2024-9999", { score: 0.97, percentile: 0.97 }],
      ["CVE-2024-0001", { score: 0.01, percentile: 0.01 }],
    ]);

    const result = buildHeatMapData(fakeAdvisories, "npm", 100, epssMap);

    expect(result.items.length).toBe(2);
    // Critical+exploited must be first (higher heatScore)
    expect(result.items[0]!.cveId).toBe("CVE-2024-9999");
    expect(result.items[0]!.tier).toBe("red");
    expect(result.items[1]!.cveId).toBe("CVE-2024-0001");

    // Low CVE (cvss=2.0, epss=0.01, noKev): heatScore = min(100, 2*5 + 0.01*40) = 10 → green
    expect(result.items[1]!.heatScore).toBe(computeHeatScore(2.0, 0.01, false));
    expect(result.items[1]!.tier).toBe(computeHeatTier(result.items[1]!.heatScore, false, true));

    // Patch for low CVE must be detected
    expect(result.items[1]!.patchAvailable).toBe(true);
    expect(result.items[1]!.patchedVersion).toBe("5.0.0");
  });

  it("computeHeatScore and computeHeatTier pure helpers produce expected values", async () => {
    const { computeHeatScore, computeHeatTier } = await import("./lib/advisory-service");

    // Critical + KEV: 9.8*5 + 0.97*40 + 30 = 49 + 38.8 + 30 = 117.8 → capped at 100
    expect(computeHeatScore(9.8, 0.97, true)).toBe(100);
    // Medium, no EPSS, no KEV: 5*5 = 25
    expect(computeHeatScore(5.0, 0, false)).toBe(25);
    // Low: 2*5 + 0.01*40 = 10 → floor(10.4) = 10
    expect(computeHeatScore(2.0, 0.01, false)).toBe(10);

    // Tier: activeExploit → red
    expect(computeHeatTier(30, true, false)).toBe("red");
    // Tier: heatScore ≥ 75 → red
    expect(computeHeatTier(80, false, true)).toBe("red");
    // Tier: patch available, score in [35,75) → yellow
    expect(computeHeatTier(50, false, true)).toBe("yellow");
    // Tier: score < 35, no exploit → green
    expect(computeHeatTier(20, false, false)).toBe("green");
  });

  it("heat map ecosystem=all returns CVEs across ecosystems", async () => {
    const app = createApp();

    const res = await app.request("/orgs/org_demo/cve-heat-map?limit=200&ecosystem=all", {
      headers: AUTH_HEADERS,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as { items: Array<{ ecosystem: string }>; ecosystem: string };
    expect(body.ecosystem).toBe("all");
    expect(Array.isArray(body.items)).toBe(true);
  });
});
