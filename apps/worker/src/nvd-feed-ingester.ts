/**
 * NVD + CISA KEV Feed Ingester
 *
 * Continuously polls:
 *   1. NVD CVE API 2.0   (https://services.nvd.nist.gov/rest/json/cves/2.0)
 *      — fetches recently modified CVEs, upserts them into `advisories`
 *   2. CISA Known Exploited Vulnerabilities (KEV) catalogue
 *      (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
 *      — cross-references against stored advisories, sets `cisa_kev_date` and
 *        `exploit_maturity_score` on any matching rows
 *
 * Design principles:
 *   - Idempotent: upserts keyed on (source, source_id) so re-running never
 *     creates duplicates.
 *   - Graceful degradation: CISA feed errors do not prevent NVD sync and vice
 *     versa.
 *   - Rate-limit aware: respects NVD's 5 req/30 s (no key) / 50 req/30 s (with
 *     key) limits with automatic back-off on HTTP 429.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ExploitMaturity = "proof-of-concept" | "active-exploitation" | "widespread";

export interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string; // YYYY-MM-DD
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: "Known" | "Unknown";
  notes: string;
}

export interface CisaKevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CisaKevEntry[];
}

interface NvdCveItem {
  cve: {
    id: string;
    published?: string;
    lastModified?: string;
    descriptions?: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: { baseScore: number; vectorString: string; baseSeverity?: string };
      }>;
      cvssMetricV2?: Array<{
        cvssData: { baseScore: number; vectorString: string };
      }>;
    };
    weaknesses?: Array<{ description: Array<{ lang: string; value: string }> }>;
    references?: Array<{ url: string; source?: string; tags?: string[] }>;
  };
}

interface NvdApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities?: NvdCveItem[];
}

export interface IngesterConfig {
  /** Supabase REST base URL, e.g. "https://xxx.supabase.co" */
  supabaseUrl: string;
  /** Supabase service-role key */
  supabaseServiceRoleKey: string;
  /** Optional NVD API key (raises rate limit from 5 to 50 req/30 s) */
  nvdApiKey?: string;
  /** Milliseconds between full poll cycles. Default: 3 600 000 (1 hour). */
  pollIntervalMs?: number;
  /** Number of days to look back on first run. Default: 7. */
  lookbackDays?: number;
  /** If true, run once and return instead of looping. Useful for tests. */
  runOnce?: boolean;
  /** Injectable fetch for testing (default: global fetch). */
  fetch?: typeof fetch;
  /** Injectable sleep for testing (default: real setTimeout-based sleep). */
  sleep?: (ms: number) => Promise<void>;
}

export interface IngesterRun {
  nvdUpserted: number;
  cisaMatched: number;
  cisaUpdated: number;
  errors: string[];
}

// ---------------------------------------------------------------------------
// Internal DB row shapes (mirrors Supabase schema)
// ---------------------------------------------------------------------------

interface AdvisoryRow {
  id: string;
  source: string;
  source_id: string;
  title: string;
  description?: string | null;
  severity?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  cwe_ids: string[];
  published_at?: string | null;
  updated_at?: string | null;
  references: Array<{ url: string; type?: string }>;
  raw_data?: unknown;
  cisa_kev_date?: string | null;
  exploit_maturity_score?: ExploitMaturity | null;
}

// ---------------------------------------------------------------------------
// Rate limiter — NVD-specific sliding window
// ---------------------------------------------------------------------------

export class RateLimiter {
  private timestamps: number[] = [];

  constructor(
    private readonly maxRequests: number,
    private readonly windowMs: number
  ) {}

  async acquire(): Promise<void> {
    const now = Date.now();
    this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);
    if (this.timestamps.length >= this.maxRequests) {
      const oldestInWindow = this.timestamps[0]!;
      const waitMs = this.windowMs - (now - oldestInWindow) + 150; // 150 ms buffer
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
      return this.acquire();
    }
    this.timestamps.push(Date.now());
  }
}

// ---------------------------------------------------------------------------
// NvdFeedIngester
// ---------------------------------------------------------------------------

export class NvdFeedIngester {
  private readonly limiter: RateLimiter;
  private readonly _fetch: typeof fetch;
  private readonly baseUrl: string;

  private readonly _sleep: (ms: number) => Promise<void>;

  constructor(private readonly config: IngesterConfig) {
    // NVD: 5 req/30 s without key, 50 req/30 s with key (use conservative margin)
    const maxReqs = config.nvdApiKey ? 45 : 4;
    this.limiter = new RateLimiter(maxReqs, 30_000);
    this._fetch = config.fetch ?? globalThis.fetch;
    this._sleep = config.sleep ?? sleep;
    this.baseUrl = config.supabaseUrl.replace(/\/$/, "");
  }

  // -------------------------------------------------------------------------
  // Public entry points
  // -------------------------------------------------------------------------

  /**
   * Run a single ingestion cycle: NVD sync + CISA KEV correlation.
   * Called on a schedule by `startPolling()`.
   */
  async runOnce(): Promise<IngesterRun> {
    const run: IngesterRun = { nvdUpserted: 0, cisaMatched: 0, cisaUpdated: 0, errors: [] };

    // 1. Fetch recently-modified NVD CVEs and upsert them
    try {
      const nvdCount = await this.syncNvd();
      run.nvdUpserted = nvdCount;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[nvd-feed-ingester] NVD sync error:", msg);
      run.errors.push(`nvd: ${msg}`);
    }

    // 2. Fetch CISA KEV catalogue and enrich matching advisories
    try {
      const { matched, updated } = await this.syncCisaKev();
      run.cisaMatched = matched;
      run.cisaUpdated = updated;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[nvd-feed-ingester] CISA KEV sync error:", msg);
      run.errors.push(`cisa: ${msg}`);
    }

    return run;
  }

  /**
   * Start the continuous polling loop. Resolves only when `signal` is aborted.
   */
  async startPolling(signal?: AbortSignal): Promise<void> {
    const intervalMs = this.config.pollIntervalMs ?? 3_600_000;
    console.log(`[nvd-feed-ingester] Starting poll loop (interval=${intervalMs}ms)`);

    while (!signal?.aborted) {
      const result = await this.runOnce();
      console.log(
        `[nvd-feed-ingester] Cycle complete — NVD upserted=${result.nvdUpserted}, ` +
        `CISA matched=${result.cisaMatched}, updated=${result.cisaUpdated}, ` +
        `errors=${result.errors.length}`
      );

      if (this.config.runOnce) break;

      // Wait for next cycle or abort
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, intervalMs);
        signal?.addEventListener("abort", () => { clearTimeout(t); resolve(); }, { once: true });
      });
    }
  }

  // -------------------------------------------------------------------------
  // NVD sync
  // -------------------------------------------------------------------------

  private async syncNvd(): Promise<number> {
    const lookback = this.config.lookbackDays ?? 7;
    const pubStartDate = new Date(Date.now() - lookback * 86_400_000).toISOString().replace(/\.\d{3}Z$/, ".000");
    const pubEndDate = new Date().toISOString().replace(/\.\d{3}Z$/, ".000");

    const pageSize = 200;
    let startIndex = 0;
    let totalResults = Infinity;
    let totalUpserted = 0;

    while (startIndex < totalResults) {
      await this.limiter.acquire();

      const params = new URLSearchParams({
        lastModStartDate: pubStartDate,
        lastModEndDate: pubEndDate,
        resultsPerPage: String(pageSize),
        startIndex: String(startIndex)
      });

      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
      const headers: Record<string, string> = { accept: "application/json" };
      if (this.config.nvdApiKey) {
        headers["apiKey"] = this.config.nvdApiKey;
      }

      let resp: Response;
      try {
        resp = await this.fetchWithRetry(url, { headers }, 3);
      } catch (err) {
        throw new Error(`NVD API request failed: ${err instanceof Error ? err.message : String(err)}`);
      }

      const data = await resp.json() as NvdApiResponse;
      totalResults = data.totalResults;

      for (const item of data.vulnerabilities ?? []) {
        await this.upsertNvdCve(item);
        totalUpserted++;
      }

      startIndex += pageSize;

      // Safety: no infinite loop if API returns empty pages
      if ((data.vulnerabilities ?? []).length === 0) break;
    }

    return totalUpserted;
  }

  private async upsertNvdCve(item: NvdCveItem): Promise<void> {
    const cve = item.cve;
    const title = cve.descriptions?.find((d) => d.lang === "en")?.value?.slice(0, 240) ?? cve.id;

    let cvssScore: number | undefined;
    let cvssVector: string | undefined;
    let severity: string | undefined;

    const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    if (v31) {
      cvssScore = v31.baseScore;
      cvssVector = v31.vectorString;
      severity = v31.baseSeverity?.toUpperCase() ?? this.severityFromScore(v31.baseScore);
    } else {
      const v2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
      if (v2) {
        cvssScore = v2.baseScore;
        cvssVector = v2.vectorString;
        severity = this.severityFromScore(v2.baseScore);
      }
    }

    const cweIds: string[] = [];
    for (const weakness of cve.weaknesses ?? []) {
      for (const desc of weakness.description) {
        if (desc.value && !["NVD-CWE-Other", "NVD-CWE-noinfo"].includes(desc.value)) {
          cweIds.push(desc.value);
        }
      }
    }

    const references = (cve.references ?? []).map((ref) => ({
      url: ref.url,
      type: ref.tags?.[0]
    }));

    const payload: Omit<AdvisoryRow, "id"> = {
      source: "nvd",
      source_id: cve.id,
      title: `${cve.id}: ${title}`,
      description: title,
      severity: severity ?? null,
      cvss_score: cvssScore ?? null,
      cvss_vector: cvssVector ?? null,
      cwe_ids: cweIds,
      published_at: cve.published ?? null,
      updated_at: cve.lastModified ?? null,
      references,
      raw_data: item
    };

    await this.dbRequest(
      "/advisories?on_conflict=source,source_id",
      {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(payload)
      }
    );
  }

  // -------------------------------------------------------------------------
  // CISA KEV sync
  // -------------------------------------------------------------------------

  private async syncCisaKev(): Promise<{ matched: number; updated: number }> {
    const catalog = await this.fetchCisaKev();
    if (catalog.vulnerabilities.length === 0) {
      return { matched: 0, updated: 0 };
    }

    let matched = 0;
    let updated = 0;

    // Build a quick lookup: CVE-ID → KEV entry
    const kevMap = new Map<string, CisaKevEntry>(
      catalog.vulnerabilities.map((v) => [v.cveID.toUpperCase(), v])
    );

    // Fetch all advisories whose source_id looks like a CVE ID (NVD-sourced rows)
    // We page through advisories to avoid a single massive query.
    const pageSize = 500;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const rows = await this.dbSelect<AdvisoryRow>(
        "advisories",
        `select=id,source_id,cisa_kev_date,exploit_maturity_score` +
        `&source_id=like.CVE-*` +
        `&limit=${pageSize}&offset=${offset}&order=id.asc`
      );

      if (rows.length < pageSize) hasMore = false;
      offset += pageSize;

      for (const row of rows) {
        const entry = kevMap.get(row.source_id.toUpperCase());
        if (!entry) continue;

        matched++;

        const maturity = this.kevMaturity(entry);
        const kevDate = entry.dateAdded; // YYYY-MM-DD

        // Skip if already up-to-date
        if (row.cisa_kev_date === kevDate && row.exploit_maturity_score === maturity) {
          continue;
        }

        await this.dbRequest(
          `/advisories?id=eq.${encodeURIComponent(row.id)}`,
          {
            method: "PATCH",
            headers: { Prefer: "return=minimal" },
            body: JSON.stringify({
              cisa_kev_date: kevDate,
              exploit_maturity_score: maturity
            })
          }
        );

        updated++;
      }

      if (rows.length === 0) break;
    }

    return { matched, updated };
  }

  /**
   * Determine ExploitMaturity from a KEV entry.
   * Ransomware use → 'widespread'; all others → 'active-exploitation'.
   */
  private kevMaturity(entry: CisaKevEntry): ExploitMaturity {
    if (entry.knownRansomwareCampaignUse === "Known") {
      return "widespread";
    }
    return "active-exploitation";
  }

  private async fetchCisaKev(): Promise<CisaKevCatalog> {
    const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const resp = await this.fetchWithRetry(url, { headers: { accept: "application/json" } }, 3);
    return await resp.json() as CisaKevCatalog;
  }

  // -------------------------------------------------------------------------
  // HTTP helpers
  // -------------------------------------------------------------------------

  /**
   * Fetch with automatic retry on HTTP 429 (rate limited) or transient 5xx.
   * Respects `Retry-After` response header when present.
   *
   * Non-retriable responses (4xx other than 429) throw immediately.
   * Network errors (thrown by fetch) are retried up to maxRetries times.
   */
  async fetchWithRetry(url: string, init: RequestInit, maxRetries: number): Promise<Response> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      let resp: Response;
      try {
        resp = await this._fetch(url, init);
      } catch (err) {
        // Network-level failure — retry with back-off
        lastError = err;
        if (attempt < maxRetries) {
          const backoffMs = 500 * 2 ** attempt;
          await this._sleep(backoffMs);
        }
        continue;
      }

      if (resp.status === 429) {
        // Rate limited — honour Retry-After (minimum 1 s to avoid zero-sleep loops)
        const retryAfterRaw = Number(resp.headers.get("Retry-After") ?? 0);
        const waitMs = Math.max(retryAfterRaw, 1) * 1000;
        console.warn(`[nvd-feed-ingester] Rate limited (429), waiting ${waitMs}ms`);
        await this._sleep(waitMs);
        lastError = new Error(`HTTP 429 from ${url}`);
        continue;
      }

      if (resp.status >= 500 && attempt < maxRetries) {
        const backoffMs = 1000 * 2 ** attempt;
        console.warn(`[nvd-feed-ingester] Server error ${resp.status}, backing off ${backoffMs}ms`);
        await this._sleep(backoffMs);
        lastError = new Error(`HTTP ${resp.status} from ${url}`);
        continue;
      }

      if (!resp.ok) {
        // Non-retriable (4xx etc.) — throw immediately, no further attempts
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
      throw new Error(`Supabase ${init.method ?? "GET"} ${path} failed (${resp.status}): ${text}`);
    }

    if (resp.status === 204) return undefined as T;

    const text = await resp.text();
    return text ? (JSON.parse(text) as T) : (undefined as T);
  }

  private async dbSelect<T>(table: string, query = ""): Promise<T[]> {
    const path = `/${table}${query.startsWith("?") ? query : `?${query}`}`;
    return this.dbRequest<T[]>(path, { method: "GET" });
  }

  // -------------------------------------------------------------------------
  // Utilities
  // -------------------------------------------------------------------------

  private severityFromScore(score: number): string {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0) return "LOW";
    return "NONE";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// NvdEpssCache — rolling in-memory CVE→EPSS mapping
// ---------------------------------------------------------------------------

/**
 * A single CVE entry in the NVD EPSS cache.
 */
export interface NvdEpssCacheEntry {
  /** CVE identifier in uppercase, e.g. "CVE-2024-12345". */
  cveId: string;
  /** EPSS percentile [0, 1] — probability of exploitation within the next 30 days. */
  epss_percentile: number;
  /** Raw EPSS probability score [0, 1]. */
  epss_score: number;
  /** True when this CVE is in the CISA KEV catalogue (set during syncCisaKev). */
  kev_active: boolean;
  /** Exploit maturity from CISA KEV — only meaningful when kev_active is true. */
  kev_maturity?: ExploitMaturity;
  /**
   * Package name + version key this entry was indexed under, e.g. "lodash@4.17.21".
   * Allows callers to quickly look up all CVEs for a specific package version.
   */
  packageVersionKey?: string;
  /** ISO timestamp when the EPSS score was last fetched from the FIRST API. */
  fetchedAt: string;
}

/**
 * Rolling in-memory CVE→EPSS mapping maintained by the NVD feed ingester.
 *
 * Keyed by CVE ID (uppercase).  The ingester populates this cache during each
 * poll cycle so downstream consumers (e.g. the risk-engine EPSS severity
 * override pipeline) can look up EPSS data without an extra HTTP round-trip.
 *
 * Design:
 *   - Maximum 10 000 entries (oldest evicted on overflow).
 *   - Entries older than 30 days are treated as stale by `isFresh()`.
 *   - Thread-safe for single-process Node.js (synchronous Map access).
 */
export class NvdEpssCache {
  private readonly cache = new Map<string, NvdEpssCacheEntry>();
  private readonly MAX_ENTRIES = 10_000;
  private readonly TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

  /** Insert or overwrite a single entry. Evicts the oldest entry on overflow. */
  set(entry: NvdEpssCacheEntry): void {
    const key = entry.cveId.toUpperCase();
    if (!this.cache.has(key) && this.cache.size >= this.MAX_ENTRIES) {
      // Evict the first (oldest) key
      const oldest = this.cache.keys().next().value;
      if (oldest) this.cache.delete(oldest);
    }
    this.cache.set(key, { ...entry, cveId: key });
  }

  /** Bulk-insert entries. */
  setMany(entries: NvdEpssCacheEntry[]): void {
    for (const entry of entries) {
      this.set(entry);
    }
  }

  /** Retrieve a single entry by CVE ID. Returns undefined when not cached. */
  get(cveId: string): NvdEpssCacheEntry | undefined {
    return this.cache.get(cveId.toUpperCase());
  }

  /**
   * Retrieve entries for all CVE IDs in the list.
   * Missing CVEs are omitted from the result map.
   */
  getMany(cveIds: string[]): Map<string, NvdEpssCacheEntry> {
    const result = new Map<string, NvdEpssCacheEntry>();
    for (const id of cveIds) {
      const entry = this.cache.get(id.toUpperCase());
      if (entry) result.set(id.toUpperCase(), entry);
    }
    return result;
  }

  /**
   * Returns true when the entry's `fetchedAt` timestamp is within the 30-day TTL.
   */
  isFresh(entry: NvdEpssCacheEntry, now = Date.now()): boolean {
    const fetchedMs = new Date(entry.fetchedAt).getTime();
    if (isNaN(fetchedMs)) return false;
    return now - fetchedMs <= this.TTL_MS;
  }

  /**
   * Return the highest-percentile fresh entry across the given CVE IDs.
   * Returns undefined when no fresh entries exist for any of the CVE IDs.
   */
  getBestEntry(cveIds: string[], now = Date.now()): NvdEpssCacheEntry | undefined {
    let best: NvdEpssCacheEntry | undefined;
    for (const id of cveIds) {
      const entry = this.cache.get(id.toUpperCase());
      if (!entry || !this.isFresh(entry, now)) continue;
      if (!best || entry.epss_percentile > best.epss_percentile) {
        best = entry;
      }
    }
    return best;
  }

  /** Total number of entries currently held. */
  get size(): number {
    return this.cache.size;
  }

  /** Remove all entries. */
  clear(): void {
    this.cache.clear();
  }
}

// Module-level singleton cache shared across all NvdFeedIngester instances.
// Consumers can import `nvdEpssCache` directly for zero-latency CVE lookups.
export const nvdEpssCache = new NvdEpssCache();

// ---------------------------------------------------------------------------
// Standalone entry point (invoked when this module is run directly)
// ---------------------------------------------------------------------------

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const supabaseUrl = env.SUPABASE_URL ?? env.BINSHIELD_SUPABASE_URL;
  const supabaseServiceRoleKey =
    env.SUPABASE_SERVICE_ROLE_KEY ?? env.BINSHIELD_SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    console.error("[nvd-feed-ingester] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");
    process.exit(1);
  }

  const ingester = new NvdFeedIngester({
    supabaseUrl,
    supabaseServiceRoleKey,
    nvdApiKey: env.NVD_API_KEY,
    pollIntervalMs: Number(env.NVD_POLL_INTERVAL_MS ?? 3_600_000),
    lookbackDays: Number(env.NVD_LOOKBACK_DAYS ?? 7)
  });

  const controller = new AbortController();
  process.on("SIGTERM", () => controller.abort());
  process.on("SIGINT", () => controller.abort());

  await ingester.startPolling(controller.signal);
}
