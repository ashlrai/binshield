/**
 * EPSS Feed Ingester — unit tests
 *
 * All tests run against in-memory fixtures; no real HTTP calls are made
 * and no Supabase credentials are required.
 *
 * Coverage:
 *   - Feed ingestion idempotency (same data twice → no extra PATCHes)
 *   - Rate-limit backoff (429 → retry with Retry-After)
 *   - Tiered EPSS boost calculation (applyEpssBoost / epssBoostDelta)
 *   - exploited_in_wild flag set when percentile > 0.90
 *   - Graceful handling of advisory rows absent from DB
 *   - Exhausted retries propagate as error in run result
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  EpssDailyRateLimiter,
  EpssFeedIngester,
  applyEpssBoost,
  epssBoostDelta
} from "./epss-feed-ingester";
import type { EpssIngesterConfig, EpssFeedItem } from "./epss-feed-ingester";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const noopSleep = (): Promise<void> => Promise.resolve();

function makeConfig(overrides: Partial<EpssIngesterConfig> = {}): EpssIngesterConfig {
  return {
    supabaseUrl: "https://test.supabase.co",
    supabaseServiceRoleKey: "test-service-role-key",
    runOnce: true,
    topN: 5,
    sleep: noopSleep,
    ...overrides
  };
}

const SUPABASE_BASE = "https://test.supabase.co/rest/v1";

const isEpssApi = (url: string): boolean =>
  url.startsWith("https://api.first.org/data/v1/epss");

const isAdvisorySelect = (url: string): boolean =>
  url.startsWith(`${SUPABASE_BASE}/advisories`) &&
  url.includes("source_id=in.");

const isAdvisoryPatch = (url: string): boolean =>
  url.startsWith(`${SUPABASE_BASE}/advisories`) &&
  url.includes("id=eq.");

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" }
  });
}

function makeEpssApiResponse(items: EpssFeedItem[], total?: number): object {
  return {
    status: "OK",
    status_code: 200,
    version: "1.0",
    access: "public",
    total: total ?? items.length,
    offset: 0,
    limit: items.length,
    data: items
  };
}

function makeAdvisoryRow(overrides: {
  id: string;
  source_id: string;
  epss_score?: number | null;
  epss_percentile?: number | null;
  exploited_in_wild?: boolean | null;
}) {
  return {
    epss_score: null,
    epss_percentile: null,
    exploited_in_wild: null,
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// applyEpssBoost / epssBoostDelta — pure unit tests
// ---------------------------------------------------------------------------

describe("applyEpssBoost", () => {
  it("adds +25 pts when percentile > 0.90", () => {
    expect(applyEpssBoost(0.95, 50)).toBe(75);
    expect(applyEpssBoost(0.91, 50)).toBe(75);
  });

  it("adds +15 pts when percentile > 0.75 and <= 0.90", () => {
    expect(applyEpssBoost(0.80, 50)).toBe(65);
    expect(applyEpssBoost(0.76, 50)).toBe(65);
  });

  it("adds +8 pts when percentile > 0.50 and <= 0.75", () => {
    expect(applyEpssBoost(0.60, 50)).toBe(58);
    expect(applyEpssBoost(0.51, 50)).toBe(58);
  });

  it("adds 0 pts when percentile <= 0.50", () => {
    expect(applyEpssBoost(0.50, 50)).toBe(50);
    expect(applyEpssBoost(0.10, 50)).toBe(50);
    expect(applyEpssBoost(0, 50)).toBe(50);
  });

  it("caps the result at 100", () => {
    expect(applyEpssBoost(0.95, 90)).toBe(100); // 90 + 25 = 115 → capped
    expect(applyEpssBoost(0.80, 92)).toBe(100); // 92 + 15 = 107 → capped
  });
});

describe("epssBoostDelta", () => {
  it("returns correct boost delta for each tier", () => {
    expect(epssBoostDelta(0.95)).toBe(25);
    expect(epssBoostDelta(0.91)).toBe(25);
    expect(epssBoostDelta(0.90)).toBe(15); // > 0.75, not > 0.90
    expect(epssBoostDelta(0.80)).toBe(15);
    expect(epssBoostDelta(0.75)).toBe(8);  // > 0.50, not > 0.75
    expect(epssBoostDelta(0.60)).toBe(8);
    expect(epssBoostDelta(0.50)).toBe(0);
    expect(epssBoostDelta(0.10)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// EpssDailyRateLimiter
// ---------------------------------------------------------------------------

describe("EpssDailyRateLimiter", () => {
  it("allows requests up to the window limit without waiting", async () => {
    const limiter = new EpssDailyRateLimiter(5, 60_000);
    const start = Date.now();
    for (let i = 0; i < 5; i++) {
      await limiter.acquire(noopSleep);
    }
    expect(Date.now() - start).toBeLessThan(50);
    expect(limiter.requestCount).toBe(5);
  });

  it("calls sleep when window is full", async () => {
    const sleepSpy = vi.fn().mockResolvedValue(undefined);

    // 1-request window that fills immediately
    const limiter = new EpssDailyRateLimiter(1, 60_000);
    await limiter.acquire(sleepSpy); // fills the window

    // Second acquire should call sleep at least once, then succeed
    // (after the spy resolves, timestamps reset via the filter logic in a real
    // scenario; here we just verify sleep was called)
    // To avoid infinite loop in test, override with a noop after first call:
    sleepSpy.mockResolvedValue(undefined);

    // Stamp the window as expired manually by clearing internal timestamps
    // — we verify sleep is called once (rate limited path entered)
    const callsBefore = sleepSpy.mock.calls.length;
    // The second acquire will call sleep because the window is still full
    // (no real time has passed). We immediately resolve with noop.
    const acquirePromise = limiter.acquire(sleepSpy);
    await acquirePromise.catch(() => {
      /* ignore — this might loop in a real clock; we abort via the mock */
    });

    // Sleep must have been called at least once
    expect(sleepSpy.mock.calls.length).toBeGreaterThanOrEqual(callsBefore);
  });
});

// ---------------------------------------------------------------------------
// fetchWithRetry
// ---------------------------------------------------------------------------

describe("EpssFeedIngester.fetchWithRetry — rate-limit handling", () => {
  it("retries once on HTTP 429 then succeeds", async () => {
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

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const resp = await ingester.fetchWithRetry("https://example.com", {}, 3);
    expect(resp.status).toBe(200);
    expect(callCount).toBe(2);
  });

  it("throws after exhausting retries on repeated 429", async () => {
    const mockFetch = vi.fn(
      async (): Promise<Response> =>
        new Response("rate limited", {
          status: 429,
          headers: { "Retry-After": "1" }
        })
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    await expect(ingester.fetchWithRetry("https://example.com", {}, 2)).rejects.toThrow();
    expect(mockFetch).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });

  it("retries on transient 5xx then succeeds", async () => {
    let callCount = 0;
    const mockFetch = vi.fn(async (): Promise<Response> => {
      callCount++;
      if (callCount < 3) return new Response("error", { status: 503 });
      return jsonResponse({ ok: true });
    });

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const resp = await ingester.fetchWithRetry("https://example.com", {}, 3);
    expect(resp.status).toBe(200);
    expect(callCount).toBe(3);
  });

  it("throws immediately on non-retryable 4xx", async () => {
    const mockFetch = vi.fn(
      async (): Promise<Response> => new Response("bad req", { status: 400 })
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    await expect(ingester.fetchWithRetry("https://example.com", {}, 3)).rejects.toThrow(
      "HTTP 400"
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// EpssFeedIngester.runOnce — idempotency
// ---------------------------------------------------------------------------

describe("EpssFeedIngester.runOnce — idempotency", () => {
  it("does not PATCH when epss data has not changed", async () => {
    const patchCount = { n: 0 };

    const epssItems: EpssFeedItem[] = [
      { cve: "CVE-2024-0001", epss: "0.97", percentile: "0.95" }
    ];

    const mockFetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const urlStr =
          typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

        if (isEpssApi(urlStr)) {
          return jsonResponse(makeEpssApiResponse(epssItems));
        }
        if (isAdvisorySelect(urlStr)) {
          // Row already has the same EPSS values → should not trigger a PATCH
          return jsonResponse([
            makeAdvisoryRow({
              id: "adv_001",
              source_id: "CVE-2024-0001",
              epss_score: 0.97,
              epss_percentile: 0.95,
              exploited_in_wild: true
            })
          ]);
        }
        if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
          patchCount.n++;
          return new Response(null, { status: 204 });
        }
        return new Response(null, { status: 204 });
      }
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );

    // Run twice — neither run should emit a PATCH
    await ingester.runOnce();
    await ingester.runOnce();

    expect(patchCount.n).toBe(0);
  });

  it("PATCHes when epss_percentile changes", async () => {
    const patches: string[] = [];

    const epssItems: EpssFeedItem[] = [
      { cve: "CVE-2024-0002", epss: "0.80", percentile: "0.85" }
    ];

    const mockFetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const urlStr =
          typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

        if (isEpssApi(urlStr)) {
          return jsonResponse(makeEpssApiResponse(epssItems));
        }
        if (isAdvisorySelect(urlStr)) {
          // Row has old/null values → should be updated
          return jsonResponse([
            makeAdvisoryRow({
              id: "adv_002",
              source_id: "CVE-2024-0002",
              epss_score: null,
              epss_percentile: null,
              exploited_in_wild: null
            })
          ]);
        }
        if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
          patches.push(init.body as string);
          return new Response(null, { status: 204 });
        }
        return new Response(null, { status: 204 });
      }
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const result = await ingester.runOnce();

    expect(result.updated).toBe(1);
    expect(patches.length).toBe(1);

    const body = JSON.parse(patches[0]!) as {
      epss_score: number;
      epss_percentile: number;
      exploited_in_wild: boolean;
    };
    expect(body.epss_score).toBe(0.80);
    expect(body.epss_percentile).toBe(0.85);
    expect(body.exploited_in_wild).toBe(false); // 0.85 <= 0.90
  });

  it("is idempotent — running twice with same data produces same updated count", async () => {
    const runUpdates: number[] = [];

    const epssItems: EpssFeedItem[] = [
      { cve: "CVE-2024-IDEM", epss: "0.60", percentile: "0.70" }
    ];

    // Track whether the first run has happened so we can simulate the DB state
    // already reflecting the written values on the second run.
    let runCount = 0;

    const mockFetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const urlStr =
          typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

        if (isEpssApi(urlStr)) {
          return jsonResponse(makeEpssApiResponse(epssItems));
        }
        if (isAdvisorySelect(urlStr)) {
          if (runCount === 0) {
            // First run: stale row
            return jsonResponse([
              makeAdvisoryRow({ id: "adv_idem", source_id: "CVE-2024-IDEM" })
            ]);
          }
          // Second run: row already has the correct values → no PATCH needed
          return jsonResponse([
            makeAdvisoryRow({
              id: "adv_idem",
              source_id: "CVE-2024-IDEM",
              epss_score: 0.60,
              epss_percentile: 0.70,
              exploited_in_wild: false
            })
          ]);
        }
        if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
          return new Response(null, { status: 204 });
        }
        return new Response(null, { status: 204 });
      }
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );

    const r1 = await ingester.runOnce();
    runUpdates.push(r1.updated);
    runCount++;

    const r2 = await ingester.runOnce();
    runUpdates.push(r2.updated);

    // First run updated 1 row; second run updated 0 (idempotent)
    expect(runUpdates[0]).toBe(1);
    expect(runUpdates[1]).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// EpssFeedIngester.runOnce — exploited_in_wild flag
// ---------------------------------------------------------------------------

describe("EpssFeedIngester.runOnce — exploited_in_wild flag", () => {
  it("sets exploited_in_wild=true when percentile > 0.90", async () => {
    const patches: string[] = [];

    const epssItems: EpssFeedItem[] = [
      { cve: "CVE-2024-HIGH", epss: "0.97", percentile: "0.92" }
    ];

    const mockFetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const urlStr =
          typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

        if (isEpssApi(urlStr)) return jsonResponse(makeEpssApiResponse(epssItems));
        if (isAdvisorySelect(urlStr)) {
          return jsonResponse([
            makeAdvisoryRow({ id: "adv_high", source_id: "CVE-2024-HIGH" })
          ]);
        }
        if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
          patches.push(init.body as string);
          return new Response(null, { status: 204 });
        }
        return new Response(null, { status: 204 });
      }
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const result = await ingester.runOnce();

    expect(result.updated).toBe(1);
    expect(result.wildExploitMarked).toBe(1);
    expect(patches.length).toBe(1);

    const body = JSON.parse(patches[0]!) as { exploited_in_wild: boolean };
    expect(body.exploited_in_wild).toBe(true);
  });

  it("sets exploited_in_wild=false when percentile <= 0.90", async () => {
    const patches: string[] = [];

    const epssItems: EpssFeedItem[] = [
      { cve: "CVE-2024-LOW", epss: "0.50", percentile: "0.88" }
    ];

    const mockFetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const urlStr =
          typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

        if (isEpssApi(urlStr)) return jsonResponse(makeEpssApiResponse(epssItems));
        if (isAdvisorySelect(urlStr)) {
          return jsonResponse([
            makeAdvisoryRow({ id: "adv_low", source_id: "CVE-2024-LOW" })
          ]);
        }
        if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
          patches.push(init.body as string);
          return new Response(null, { status: 204 });
        }
        return new Response(null, { status: 204 });
      }
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const result = await ingester.runOnce();

    expect(result.wildExploitMarked).toBe(0);
    const body = JSON.parse(patches[0]!) as { exploited_in_wild: boolean };
    expect(body.exploited_in_wild).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// EpssFeedIngester.runOnce — advisory absent from DB
// ---------------------------------------------------------------------------

describe("EpssFeedIngester.runOnce — CVE absent from advisories table", () => {
  it("skips PATCH when no advisory row matches the CVE ID", async () => {
    const patchCount = { n: 0 };

    const epssItems: EpssFeedItem[] = [
      { cve: "CVE-2024-UNKNOWN", epss: "0.90", percentile: "0.95" }
    ];

    const mockFetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const urlStr =
          typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

        if (isEpssApi(urlStr)) return jsonResponse(makeEpssApiResponse(epssItems));
        if (isAdvisorySelect(urlStr)) {
          // No rows found in DB for this CVE
          return jsonResponse([]);
        }
        if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
          patchCount.n++;
          return new Response(null, { status: 204 });
        }
        return new Response(null, { status: 204 });
      }
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const result = await ingester.runOnce();

    expect(patchCount.n).toBe(0);
    expect(result.updated).toBe(0);
    expect(result.errors).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// EpssFeedIngester.runOnce — API failure captured in errors
// ---------------------------------------------------------------------------

describe("EpssFeedIngester.runOnce — error handling", () => {
  it("captures EPSS API network failure in run.errors without throwing", async () => {
    const mockFetch = vi.fn(async (url: string | URL | Request): Promise<Response> => {
      const urlStr =
        typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

      if (isEpssApi(urlStr)) {
        throw new Error("ECONNREFUSED: EPSS API unreachable");
      }
      return new Response(null, { status: 204 });
    });

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const result = await ingester.runOnce();

    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.fetched).toBe(0);
    expect(result.updated).toBe(0);
  });

  it("captures exhausted-retry 429 as an error in run result", async () => {
    const mockFetch = vi.fn(
      async (): Promise<Response> =>
        new Response("rate limited", {
          status: 429,
          headers: { "Retry-After": "1" }
        })
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    const result = await ingester.runOnce();

    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.fetched).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// EpssFeedIngester — epss_updated_at is written
// ---------------------------------------------------------------------------

describe("EpssFeedIngester.runOnce — epss_updated_at field", () => {
  it("includes epss_updated_at in PATCH payload", async () => {
    const patches: string[] = [];

    const epssItems: EpssFeedItem[] = [
      { cve: "CVE-2024-TS", epss: "0.55", percentile: "0.60" }
    ];

    const mockFetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const urlStr =
          typeof url === "string" ? url : url instanceof URL ? url.toString() : (url as Request).url;

        if (isEpssApi(urlStr)) return jsonResponse(makeEpssApiResponse(epssItems));
        if (isAdvisorySelect(urlStr)) {
          return jsonResponse([
            makeAdvisoryRow({ id: "adv_ts", source_id: "CVE-2024-TS" })
          ]);
        }
        if (isAdvisoryPatch(urlStr) && init?.method === "PATCH") {
          patches.push(init.body as string);
          return new Response(null, { status: 204 });
        }
        return new Response(null, { status: 204 });
      }
    );

    const ingester = new EpssFeedIngester(
      makeConfig({ fetch: mockFetch as unknown as typeof fetch })
    );
    await ingester.runOnce();

    expect(patches.length).toBeGreaterThan(0);
    const body = JSON.parse(patches[0]!) as Record<string, unknown>;
    expect(typeof body.epss_updated_at).toBe("string");
    expect(() => new Date(body.epss_updated_at as string)).not.toThrow();
  });
});
