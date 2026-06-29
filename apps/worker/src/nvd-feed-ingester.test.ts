/**
 * NVD Feed Ingester — unit tests
 *
 * All tests run entirely against in-memory fixtures; no real HTTP calls are
 * made and no Supabase credentials are required.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { NvdFeedIngester, RateLimiter } from "./nvd-feed-ingester";
import type { CisaKevCatalog, IngesterConfig } from "./nvd-feed-ingester";

// ---------------------------------------------------------------------------
// Fixture factories
// ---------------------------------------------------------------------------

function makeNvdResponse(cveIds: string[]) {
  return {
    resultsPerPage: cveIds.length,
    startIndex: 0,
    totalResults: cveIds.length,
    vulnerabilities: cveIds.map((id) => ({
      cve: {
        id,
        published: "2024-01-01T00:00:00.000",
        lastModified: "2024-01-02T00:00:00.000",
        descriptions: [{ lang: "en", value: `Description of ${id}` }],
        metrics: {
          cvssMetricV31: [
            {
              cvssData: {
                baseScore: 7.5,
                vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                baseSeverity: "HIGH"
              }
            }
          ]
        },
        weaknesses: [{ description: [{ lang: "en", value: "CWE-79" }] }],
        references: [{ url: `https://nvd.nist.gov/vuln/detail/${id}`, tags: ["Patch"] }]
      }
    }))
  };
}

function makeCisaKevCatalog(entries: Array<{
  cveID: string;
  dateAdded?: string;
  ransomware?: "Known" | "Unknown";
}>): CisaKevCatalog {
  return {
    title: "CISA Known Exploited Vulnerabilities Catalog",
    catalogVersion: "2024.01.01",
    dateReleased: "2024-01-01T00:00:00.0000000Z",
    count: entries.length,
    vulnerabilities: entries.map((e) => ({
      cveID: e.cveID,
      vendorProject: "TestVendor",
      product: "TestProduct",
      vulnerabilityName: `${e.cveID} Test Vulnerability`,
      dateAdded: e.dateAdded ?? "2024-01-15",
      shortDescription: `Test description for ${e.cveID}`,
      requiredAction: "Apply update",
      dueDate: "2024-02-15",
      knownRansomwareCampaignUse: e.ransomware ?? "Unknown",
      notes: ""
    }))
  };
}

// ---------------------------------------------------------------------------
// Mock fetch builder
// ---------------------------------------------------------------------------

type MockRoute = {
  matcher: (url: string) => boolean;
  response: () => Response;
  callCount?: number;
};

function buildMockFetch(routes: MockRoute[]) {
  return vi.fn(async (url: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    for (const route of routes) {
      if (route.matcher(urlStr)) {
        if (route.callCount !== undefined) route.callCount++;
        return route.response();
      }
    }
    return new Response(JSON.stringify({ error: "No mock route matched" }), { status: 404 });
  });
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" }
  });
}

/** No-op sleep for tests — eliminates all retry back-off delays. */
const noopSleep = () => Promise.resolve();

function makeConfig(overrides: Partial<IngesterConfig> = {}): IngesterConfig {
  return {
    supabaseUrl: "https://test.supabase.co",
    supabaseServiceRoleKey: "test-service-role-key",
    runOnce: true,
    lookbackDays: 1,
    sleep: noopSleep,
    ...overrides
  };
}

// Supabase REST URL helpers
const SUPABASE_BASE = "https://test.supabase.co/rest/v1";
const isAdvisoryUpsert = (url: string) =>
  url.startsWith(`${SUPABASE_BASE}/advisories`) && url.includes("on_conflict");
const isAdvisorySelect = (url: string) =>
  url.startsWith(`${SUPABASE_BASE}/advisories`) && url.includes("source_id=like.CVE");
const isAdvisoryPatch = (url: string) =>
  url.startsWith(`${SUPABASE_BASE}/advisories`) && url.includes("id=eq.");
const isNvdApi = (url: string) =>
  url.startsWith("https://services.nvd.nist.gov/rest/json/cves/2.0");
const isCisaKev = (url: string) =>
  url.includes("known_exploited_vulnerabilities.json");

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

describe("RateLimiter", () => {
  it("allows requests up to the window limit without waiting", async () => {
    const limiter = new RateLimiter(5, 30_000);
    const start = Date.now();
    for (let i = 0; i < 5; i++) {
      await limiter.acquire();
    }
    // Should complete essentially instantly (< 50 ms)
    expect(Date.now() - start).toBeLessThan(50);
  });
});

// ---------------------------------------------------------------------------
// fetchWithRetry — rate-limit retry behaviour
// ---------------------------------------------------------------------------

describe("fetchWithRetry", () => {
  it("retries once on 429 then succeeds", async () => {
    // sleep is noopSleep via makeConfig — no real delay
    let callCount = 0;
    const mockFetch = vi.fn(async (): Promise<Response> => {
      callCount++;
      if (callCount === 1) {
        return new Response("rate limited", {
          status: 429,
          headers: { "Retry-After": "30" }
        });
      }
      return jsonResponse({ ok: true });
    });

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    const resp = await ingester.fetchWithRetry("https://example.com/api", {}, 3);
    expect(resp.status).toBe(200);
    expect(callCount).toBe(2);
  });

  it("throws after exhausting retries on repeated 429", async () => {
    // sleep is noopSleep — all back-off calls return immediately
    const mockFetch = vi.fn(async (): Promise<Response> =>
      new Response("rate limited", {
        status: 429,
        headers: { "Retry-After": "30" }
      })
    );

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    await expect(ingester.fetchWithRetry("https://example.com/api", {}, 2)).rejects.toThrow();
    // 1 initial + 2 retries = 3 total calls
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it("retries on 5xx transient errors", async () => {
    let callCount = 0;
    const mockFetch = vi.fn(async (): Promise<Response> => {
      callCount++;
      if (callCount < 3) {
        return new Response("server error", { status: 503 });
      }
      return jsonResponse({ ok: true });
    });

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    const resp = await ingester.fetchWithRetry("https://example.com/api", {}, 3);
    expect(resp.status).toBe(200);
    expect(callCount).toBe(3);
  });

  it("propagates non-retryable 4xx errors immediately", async () => {
    const mockFetch = vi.fn(async (): Promise<Response> =>
      new Response("not found", { status: 404 })
    );

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    await expect(ingester.fetchWithRetry("https://example.com/api", {}, 3)).rejects.toThrow("HTTP 404");
    // 404 is non-retriable — called exactly once
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// NvdFeedIngester.runOnce — NVD upsert
// ---------------------------------------------------------------------------

describe("NvdFeedIngester.runOnce — NVD upsert", () => {
  it("upserts CVEs returned by the NVD API into Supabase", async () => {
    const upsertBodies: unknown[] = [];

    const mockFetch = buildMockFetch([
      {
        matcher: isNvdApi,
        response: () => jsonResponse(makeNvdResponse(["CVE-2024-0001", "CVE-2024-0002"]))
      },
      {
        matcher: isCisaKev,
        response: () => jsonResponse(makeCisaKevCatalog([]))
      },
      {
        matcher: isAdvisoryUpsert,
        response: () => {
          // capture the body — we'll need to intercept the body separately
          return new Response(null, { status: 204 });
        }
      },
      {
        matcher: isAdvisorySelect,
        response: () => jsonResponse([])
      }
    ]);

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    const result = await ingester.runOnce();

    expect(result.nvdUpserted).toBe(2);
    expect(result.errors).toHaveLength(0);

    // Ensure we hit the NVD API
    const nvdCalls = mockFetch.mock.calls.filter(([url]) =>
      typeof url === "string" && isNvdApi(url)
    );
    expect(nvdCalls.length).toBeGreaterThanOrEqual(1);
  });

  it("is idempotent — upserting the same CVE ID twice does not create duplicates", async () => {
    const upsertRequests: string[] = [];

    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

      if (isNvdApi(urlStr)) {
        return jsonResponse(makeNvdResponse(["CVE-2024-DUPE"]));
      }
      if (isCisaKev(urlStr)) {
        return jsonResponse(makeCisaKevCatalog([]));
      }
      if (isAdvisoryUpsert(urlStr)) {
        upsertRequests.push(urlStr);
        return new Response(null, { status: 204 });
      }
      if (isAdvisorySelect(urlStr)) {
        return jsonResponse([]);
      }
      return new Response(null, { status: 204 });
    });

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));

    // Run twice
    await ingester.runOnce();
    await ingester.runOnce();

    // Both runs upsert (Supabase handles dedup via on_conflict), not duplicates on our side
    expect(upsertRequests.length).toBeGreaterThanOrEqual(2); // one per run
    // The URL always includes on_conflict (idempotent upsert, not insert)
    for (const u of upsertRequests) {
      expect(u).toContain("on_conflict");
    }
  });
});

// ---------------------------------------------------------------------------
// NvdFeedIngester.runOnce — CISA KEV correlation
// ---------------------------------------------------------------------------

describe("NvdFeedIngester.runOnce — CISA KEV correlation", () => {
  it("patches advisories with cisa_kev_date and exploit_maturity_score", async () => {
    const patched: Array<{ url: string; body: string }> = [];

    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

      if (isNvdApi(urlStr)) {
        return jsonResponse(makeNvdResponse(["CVE-2024-0099"]));
      }
      if (isCisaKev(urlStr)) {
        return jsonResponse(
          makeCisaKevCatalog([
            { cveID: "CVE-2024-0099", dateAdded: "2024-03-15", ransomware: "Unknown" }
          ])
        );
      }
      if (isAdvisoryUpsert(urlStr)) {
        return new Response(null, { status: 204 });
      }
      if (isAdvisorySelect(urlStr)) {
        // Simulate one matching row
        return jsonResponse([
          { id: "adv_test_1", source_id: "CVE-2024-0099", cisa_kev_date: null, exploit_maturity_score: null }
        ]);
      }
      if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
        patched.push({ url: urlStr, body: init.body as string });
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 204 });
    });

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    const result = await ingester.runOnce();

    expect(result.cisaMatched).toBeGreaterThan(0);
    expect(result.cisaUpdated).toBeGreaterThan(0);
    expect(patched.length).toBeGreaterThan(0);

    const patchBody = JSON.parse(patched[0]!.body) as {
      cisa_kev_date: string;
      exploit_maturity_score: string;
    };
    expect(patchBody.cisa_kev_date).toBe("2024-03-15");
    expect(patchBody.exploit_maturity_score).toBe("active-exploitation");
  });

  it("sets exploit_maturity_score to 'widespread' for ransomware-linked CVEs", async () => {
    const patched: string[] = [];

    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

      if (isNvdApi(urlStr)) return jsonResponse(makeNvdResponse(["CVE-2024-RANSOM"]));
      if (isCisaKev(urlStr)) {
        return jsonResponse(
          makeCisaKevCatalog([{ cveID: "CVE-2024-RANSOM", dateAdded: "2024-06-01", ransomware: "Known" }])
        );
      }
      if (isAdvisoryUpsert(urlStr)) return new Response(null, { status: 204 });
      if (isAdvisorySelect(urlStr)) {
        return jsonResponse([{ id: "adv_r1", source_id: "CVE-2024-RANSOM", cisa_kev_date: null, exploit_maturity_score: null }]);
      }
      if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
        patched.push(init.body as string);
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 204 });
    });

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    await ingester.runOnce();

    expect(patched.length).toBeGreaterThan(0);
    const body = JSON.parse(patched[0]!) as { exploit_maturity_score: string };
    expect(body.exploit_maturity_score).toBe("widespread");
  });

  it("is idempotent — skips PATCH when cisa_kev_date and maturity already match", async () => {
    const patchCount = { n: 0 };

    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

      if (isNvdApi(urlStr)) return jsonResponse(makeNvdResponse(["CVE-2024-IDEM"]));
      if (isCisaKev(urlStr)) {
        return jsonResponse(
          makeCisaKevCatalog([{ cveID: "CVE-2024-IDEM", dateAdded: "2024-03-15", ransomware: "Unknown" }])
        );
      }
      if (isAdvisoryUpsert(urlStr)) return new Response(null, { status: 204 });
      if (isAdvisorySelect(urlStr)) {
        // Row already has up-to-date KEV data — should NOT be patched again
        return jsonResponse([{
          id: "adv_idem",
          source_id: "CVE-2024-IDEM",
          cisa_kev_date: "2024-03-15",          // already set
          exploit_maturity_score: "active-exploitation" // already set
        }]);
      }
      if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
        patchCount.n++;
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 204 });
    });

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    await ingester.runOnce();

    expect(patchCount.n).toBe(0);
  });

  it("degrades gracefully when CISA API is unavailable", async () => {
    const mockFetch = vi.fn(async (url: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

      if (isNvdApi(urlStr)) return jsonResponse(makeNvdResponse(["CVE-2024-0001"]));
      if (isCisaKev(urlStr)) {
        // Simulate complete CISA outage (network failure)
        throw new Error("ECONNREFUSED: CISA feed unreachable");
      }
      // Supabase calls succeed
      return new Response(null, { status: 204 });
    });

    // sleep is noopSleep via makeConfig — fetchWithRetry back-off resolves instantly
    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    const result = await ingester.runOnce();

    // NVD sync should still succeed
    expect(result.nvdUpserted).toBe(1);
    // CISA error captured, not thrown
    expect(result.errors.some((e) => e.startsWith("cisa:"))).toBe(true);
    expect(result.cisaMatched).toBe(0);
  });

  it("does not enrich advisories for CVEs absent from KEV catalogue", async () => {
    const patchCount = { n: 0 };

    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

      if (isNvdApi(urlStr)) return jsonResponse(makeNvdResponse(["CVE-2024-NOT-IN-KEV"]));
      if (isCisaKev(urlStr)) {
        // Catalogue contains different CVEs
        return jsonResponse(makeCisaKevCatalog([{ cveID: "CVE-2024-OTHER", dateAdded: "2024-01-01" }]));
      }
      if (isAdvisoryUpsert(urlStr)) return new Response(null, { status: 204 });
      if (isAdvisorySelect(urlStr)) {
        return jsonResponse([{
          id: "adv_x",
          source_id: "CVE-2024-NOT-IN-KEV",
          cisa_kev_date: null,
          exploit_maturity_score: null
        }]);
      }
      if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
        patchCount.n++;
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 204 });
    });

    const ingester = new NvdFeedIngester(makeConfig({ fetch: mockFetch as unknown as typeof fetch }));
    const result = await ingester.runOnce();

    expect(patchCount.n).toBe(0);
    expect(result.cisaMatched).toBe(0);
    expect(result.cisaUpdated).toBe(0);
  });
});
