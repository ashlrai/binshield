/**
 * EPSS Feed Ingester
 *
 * Continuously polls the FIRST EPSS API (https://api.first.org/data/v1/epss)
 * to enrich advisories with real-world exploitation percentiles.
 *
 * Design:
 *   - Polls top 10K CVEs by EPSS score on a 6-hour cadence.
 *   - Upserts `advisories.epss_percentile`, `advisories.epss_score`,
 *     `advisories.exploited_in_wild`, and `advisories.epss_updated_at`.
 *   - Respects the FIRST EPSS API's ~300 req/day soft limit with a sliding
 *     window rate limiter + Retry-After back-off on HTTP 429.
 *   - Fully idempotent: re-running never creates duplicate advisories.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EpssIngesterConfig {
  /** Supabase REST base URL, e.g. "https://xxx.supabase.co" */
  supabaseUrl: string;
  /** Supabase service-role key */
  supabaseServiceRoleKey: string;
  /** How many top CVEs to fetch per poll cycle. Default: 10_000. */
  topN?: number;
  /** Milliseconds between full poll cycles. Default: 21_600_000 (6 hours). */
  pollIntervalMs?: number;
  /** If true, run once and return instead of looping. Useful for tests. */
  runOnce?: boolean;
  /** Injectable fetch for testing (default: global fetch). */
  fetch?: typeof fetch;
  /** Injectable sleep for testing (default: real setTimeout-based sleep). */
  sleep?: (ms: number) => Promise<void>;
}

/** Shape returned after each ingestion cycle. */
export interface EpssIngesterRun {
  /** Total EPSS data rows fetched from the FIRST API. */
  fetched: number;
  /** Advisories rows updated with new EPSS data. */
  updated: number;
  /** Advisory rows where exploited_in_wild flipped to true. */
  wildExploitMarked: number;
  errors: string[];
}

/** A single row from the FIRST EPSS API response. */
export interface EpssFeedItem {
  cve: string;
  epss: string;    // float as string, e.g. "0.97312"
  percentile: string; // float as string, e.g. "0.99734"
  date?: string;
  model_version?: string;
}

/** Shape of FIRST EPSS API /data/v1/epss?... JSON response. */
interface EpssApiResponse {
  status: string;
  status_code: number;
  version?: string;
  access?: string;
  total: number;
  offset: number;
  limit: number;
  data?: EpssFeedItem[];
}

// ---------------------------------------------------------------------------
// Tiered EPSS risk boost
// ---------------------------------------------------------------------------

/**
 * Apply a tiered score boost based on EPSS percentile.
 *
 *   percentile > 0.90  → +25 pts
 *   percentile > 0.75  → +15 pts
 *   percentile > 0.50  → +8 pts
 *   otherwise          → 0 pts
 *
 * @param percentile - EPSS percentile in [0, 1]
 * @param baseScore  - Current numeric risk score (0–100)
 * @returns Final capped score (0–100)
 */
export function applyEpssBoost(percentile: number, baseScore: number): number {
  let boost = 0;
  if (percentile > 0.90) {
    boost = 25;
  } else if (percentile > 0.75) {
    boost = 15;
  } else if (percentile > 0.50) {
    boost = 8;
  }
  return Math.min(100, baseScore + boost);
}

/**
 * Returns just the boost delta for a given percentile (not clamped).
 */
export function epssBoostDelta(percentile: number): number {
  if (percentile > 0.90) return 25;
  if (percentile > 0.75) return 15;
  if (percentile > 0.50) return 8;
  return 0;
}

// ---------------------------------------------------------------------------
// Daily rate limiter  (FIRST EPSS: ~300 req/day soft cap)
// ---------------------------------------------------------------------------

/**
 * A lightweight sliding-window rate limiter.
 * Used to keep daily FIRST EPSS API consumption under the 300 req/day limit.
 */
export class EpssDailyRateLimiter {
  private timestamps: number[] = [];

  constructor(
    private readonly maxRequests: number,
    private readonly windowMs: number
  ) {}

  /**
   * Acquire a slot, sleeping until one is available if the window is full.
   * In tests the injected sleep is a no-op so this resolves immediately.
   */
  async acquire(sleep: (ms: number) => Promise<void>): Promise<void> {
    const now = Date.now();
    this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);

    if (this.timestamps.length >= this.maxRequests) {
      const oldestInWindow = this.timestamps[0]!;
      const waitMs = this.windowMs - (now - oldestInWindow) + 150;
      await sleep(waitMs);
      return this.acquire(sleep);
    }

    this.timestamps.push(Date.now());
  }

  /** Current number of recorded requests in the window (for testing). */
  get requestCount(): number {
    const now = Date.now();
    this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);
    return this.timestamps.length;
  }
}

// ---------------------------------------------------------------------------
// EpssFeedIngester
// ---------------------------------------------------------------------------

export class EpssFeedIngester {
  private readonly _fetch: typeof fetch;
  private readonly _sleep: (ms: number) => Promise<void>;
  private readonly baseUrl: string;
  private readonly limiter: EpssDailyRateLimiter;

  constructor(private readonly config: EpssIngesterConfig) {
    this._fetch = config.fetch ?? globalThis.fetch;
    this._sleep = config.sleep ?? sleep;
    this.baseUrl = config.supabaseUrl.replace(/\/$/, "");

    // FIRST EPSS API: ~300 req/day hard cap.
    // Use a 24-hour sliding window with a 280-req limit for safety margin.
    this.limiter = new EpssDailyRateLimiter(280, 24 * 60 * 60 * 1000);
  }

  // -------------------------------------------------------------------------
  // Public entry points
  // -------------------------------------------------------------------------

  /**
   * Run a single ingestion cycle: fetch top-N CVEs from FIRST EPSS API,
   * then upsert enrichment data into the `advisories` table.
   */
  async runOnce(): Promise<EpssIngesterRun> {
    const run: EpssIngesterRun = {
      fetched: 0,
      updated: 0,
      wildExploitMarked: 0,
      errors: []
    };

    try {
      const topN = this.config.topN ?? 10_000;
      const items = await this.fetchTopNEpss(topN);
      run.fetched = items.length;

      if (items.length > 0) {
        const { updated, wildExploitMarked } = await this.upsertAdvisoryEpss(items);
        run.updated = updated;
        run.wildExploitMarked = wildExploitMarked;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[epss-feed-ingester] Cycle error:", msg);
      run.errors.push(msg);
    }

    return run;
  }

  /**
   * Start the continuous polling loop. Resolves only when `signal` is aborted.
   */
  async startPolling(signal?: AbortSignal): Promise<void> {
    const intervalMs = this.config.pollIntervalMs ?? 21_600_000; // 6 hours
    console.log(`[epss-feed-ingester] Starting poll loop (interval=${intervalMs}ms)`);

    while (!signal?.aborted) {
      const result = await this.runOnce();
      console.log(
        `[epss-feed-ingester] Cycle complete — fetched=${result.fetched}, ` +
        `updated=${result.updated}, wildExploit=${result.wildExploitMarked}, ` +
        `errors=${result.errors.length}`
      );

      if (this.config.runOnce) break;

      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, intervalMs);
        signal?.addEventListener("abort", () => {
          clearTimeout(t);
          resolve();
        }, { once: true });
      });
    }
  }

  // -------------------------------------------------------------------------
  // FIRST EPSS API fetching
  // -------------------------------------------------------------------------

  /**
   * Fetch the top N CVEs sorted by EPSS score (descending) from the FIRST API.
   * Pages through results in batches of 100 (API limit per request).
   *
   * URL: GET https://api.first.org/data/v1/epss?order=!epss&limit=100&offset=0
   */
  async fetchTopNEpss(topN: number): Promise<EpssFeedItem[]> {
    const pageSize = 100;
    const results: EpssFeedItem[] = [];
    let offset = 0;

    while (results.length < topN) {
      await this.limiter.acquire(this._sleep);

      const remaining = topN - results.length;
      const limit = Math.min(pageSize, remaining);
      const url =
        `https://api.first.org/data/v1/epss` +
        `?order=!epss&limit=${limit}&offset=${offset}`;

      let resp: Response;
      try {
        resp = await this.fetchWithRetry(url, { headers: { accept: "application/json" } }, 3);
      } catch (err) {
        throw new Error(
          `FIRST EPSS API request failed at offset=${offset}: ${err instanceof Error ? err.message : String(err)}`
        );
      }

      const data = await resp.json() as EpssApiResponse;
      const page = data.data ?? [];
      results.push(...page);

      // Stop if the API returned fewer items than requested (last page)
      if (page.length < limit) break;

      offset += pageSize;
    }

    return results.slice(0, topN);
  }

  // -------------------------------------------------------------------------
  // Supabase upsert
  // -------------------------------------------------------------------------

  /**
   * For each EPSS row, update the matching advisory in the `advisories` table
   * (matched by source_id = CVE ID) with:
   *   - epss_score
   *   - epss_percentile
   *   - exploited_in_wild  (true when percentile > 0.90)
   *   - epss_updated_at
   *
   * Rows that have not changed are skipped (idempotent).
   */
  private async upsertAdvisoryEpss(
    items: EpssFeedItem[]
  ): Promise<{ updated: number; wildExploitMarked: number }> {
    let updated = 0;
    let wildExploitMarked = 0;

    // Batch look-ups: find which CVE IDs exist in `advisories`
    // We process in chunks of 50 to stay well within URL length limits.
    const chunkSize = 50;

    for (let i = 0; i < items.length; i += chunkSize) {
      const chunk = items.slice(i, i + chunkSize);
      const cveIds = chunk.map((r) => r.cve.toUpperCase());

      // Fetch existing advisory rows for this chunk
      const existing = await this.dbSelect<{
        id: string;
        source_id: string;
        epss_score: number | null;
        epss_percentile: number | null;
        exploited_in_wild: boolean | null;
      }>(
        "advisories",
        `select=id,source_id,epss_score,epss_percentile,exploited_in_wild` +
        `&source_id=in.(${cveIds.map((id) => encodeURIComponent(id)).join(",")})` +
        `&limit=${chunkSize}`
      );

      if (existing.length === 0) continue;

      // Build a lookup from CVE ID → EPSS row
      const epssMap = new Map<string, EpssFeedItem>(
        chunk.map((r) => [r.cve.toUpperCase(), r])
      );

      for (const row of existing) {
        const epssRow = epssMap.get(row.source_id.toUpperCase());
        if (!epssRow) continue;

        const newScore = parseFloat(epssRow.epss);
        const newPercentile = parseFloat(epssRow.percentile);
        const newExploitedInWild = newPercentile > 0.90;

        // Skip if nothing has changed (idempotency check)
        if (
          row.epss_score === newScore &&
          row.epss_percentile === newPercentile &&
          row.exploited_in_wild === newExploitedInWild
        ) {
          continue;
        }

        const wasExploited = row.exploited_in_wild === true;

        await this.dbRequest(
          `/advisories?id=eq.${encodeURIComponent(row.id)}`,
          {
            method: "PATCH",
            headers: { Prefer: "return=minimal" },
            body: JSON.stringify({
              epss_score: newScore,
              epss_percentile: newPercentile,
              exploited_in_wild: newExploitedInWild,
              epss_updated_at: new Date().toISOString()
            })
          }
        );

        updated++;
        if (newExploitedInWild && !wasExploited) {
          wildExploitMarked++;
        }
      }
    }

    return { updated, wildExploitMarked };
  }

  // -------------------------------------------------------------------------
  // HTTP helpers
  // -------------------------------------------------------------------------

  /**
   * Fetch with automatic retry on HTTP 429 (rate limited) or transient 5xx.
   * Respects `Retry-After` response header when present.
   */
  async fetchWithRetry(url: string, init: RequestInit, maxRetries: number): Promise<Response> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      let resp: Response;
      try {
        resp = await this._fetch(url, init);
      } catch (err) {
        lastError = err;
        if (attempt < maxRetries) {
          const backoffMs = 500 * 2 ** attempt;
          await this._sleep(backoffMs);
        }
        continue;
      }

      if (resp.status === 429) {
        const retryAfterRaw = Number(resp.headers.get("Retry-After") ?? 0);
        const waitMs = Math.max(retryAfterRaw, 1) * 1000;
        console.warn(`[epss-feed-ingester] Rate limited (429), waiting ${waitMs}ms`);
        await this._sleep(waitMs);
        lastError = new Error(`HTTP 429 from ${url}`);
        continue;
      }

      if (resp.status >= 500 && attempt < maxRetries) {
        const backoffMs = 1000 * 2 ** attempt;
        console.warn(`[epss-feed-ingester] Server error ${resp.status}, backing off ${backoffMs}ms`);
        await this._sleep(backoffMs);
        lastError = new Error(`HTTP ${resp.status} from ${url}`);
        continue;
      }

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} from ${url}`);
      }

      return resp;
    }

    throw lastError ?? new Error(`All ${maxRetries + 1} attempts failed for ${url}`);
  }

  // -------------------------------------------------------------------------
  // Supabase REST helpers
  // -------------------------------------------------------------------------

  private dbHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return {
      apikey: this.config.supabaseServiceRoleKey,
      authorization: `Bearer ${this.config.supabaseServiceRoleKey}`,
      "content-type": "application/json",
      ...extra
    };
  }

  private async dbRequest<T = void>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(this.dbHeaders());
    if (init.headers) {
      new Headers(init.headers as Record<string, string>).forEach((v, k) => headers.set(k, v));
    }
    const url = `${this.baseUrl}/rest/v1${path}`;
    const resp = await this._fetch(url, { ...init, headers });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "(unreadable)");
      throw new Error(
        `Supabase ${init.method ?? "GET"} ${path} failed (${resp.status}): ${text}`
      );
    }

    if (resp.status === 204) return undefined as T;

    const text = await resp.text();
    return text ? (JSON.parse(text) as T) : (undefined as T);
  }

  private async dbSelect<T>(table: string, query = ""): Promise<T[]> {
    const path = `/${table}${query.startsWith("?") ? query : `?${query}`}`;
    return this.dbRequest<T[]>(path, { method: "GET" });
  }
}

// ---------------------------------------------------------------------------
// Internal sleep helper
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Standalone entry point
// ---------------------------------------------------------------------------

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const supabaseUrl = env.SUPABASE_URL ?? env.BINSHIELD_SUPABASE_URL;
  const supabaseServiceRoleKey =
    env.SUPABASE_SERVICE_ROLE_KEY ?? env.BINSHIELD_SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    console.error(
      "[epss-feed-ingester] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required"
    );
    process.exit(1);
  }

  const ingester = new EpssFeedIngester({
    supabaseUrl,
    supabaseServiceRoleKey,
    topN: Number(env.EPSS_TOP_N ?? 10_000),
    pollIntervalMs: Number(env.EPSS_POLL_INTERVAL_MS ?? 21_600_000)
  });

  const controller = new AbortController();
  process.on("SIGTERM", () => controller.abort());
  process.on("SIGINT", () => controller.abort());

  await ingester.startPolling(controller.signal);
}
