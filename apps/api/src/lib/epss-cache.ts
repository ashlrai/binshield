/**
 * EPSS Cache — lightweight in-memory + optional Supabase-backed cache.
 *
 * TTL: 7 days. The in-memory layer is consulted first; on a miss the
 * Supabase `epss_cache` table is queried. Writes propagate to both layers.
 *
 * Table schema (Supabase):
 *   epss_cache (
 *     ecosystem   text,
 *     cve_id      text,
 *     score       float8,
 *     percentile  float8,
 *     fetched_at  timestamptz,
 *     PRIMARY KEY (ecosystem, cve_id)
 *   )
 *
 * Tiered EPSS risk boost (applied via `computeEpssBoost`):
 *   percentile > 0.90  → +25 pts
 *   percentile > 0.75  → +15 pts
 *   percentile > 0.50  → +8 pts
 *   otherwise          → 0 pts
 */

// ---------------------------------------------------------------------------
// Tiered EPSS boost helpers (exported so callers don't duplicate the logic)
// ---------------------------------------------------------------------------

/**
 * Returns the boost delta for a given EPSS percentile according to the
 * three-tier policy:
 *
 *   percentile > 0.90  → +25 pts
 *   percentile > 0.75  → +15 pts
 *   percentile > 0.50  → +8 pts
 *   otherwise          → 0 pts
 */
export function computeEpssBoostDelta(percentile: number): number {
  if (percentile > 0.90) return 25;
  if (percentile > 0.75) return 15;
  if (percentile > 0.50) return 8;
  return 0;
}

/**
 * Apply the tiered EPSS boost to a base score, capping at 100.
 *
 * @param percentile - EPSS percentile in [0, 1]
 * @param baseScore  - Current numeric risk score (0–100)
 * @returns Final score capped at 100
 */
export function computeEpssBoost(percentile: number, baseScore: number): number {
  return Math.min(100, baseScore + computeEpssBoostDelta(percentile));
}

export interface EpssCacheEntry {
  ecosystem: string;
  cveId: string;
  score: number;
  percentile: number;
  fetchedAt: string; // ISO-8601
}

const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

interface SupabaseConfig {
  supabaseUrl: string;
  supabaseServiceRoleKey: string;
}

/** Returns true if the entry is still within the 7-day TTL. */
function isEntryFresh(entry: EpssCacheEntry): boolean {
  return Date.now() - new Date(entry.fetchedAt).getTime() < CACHE_TTL_MS;
}

/**
 * EpssCache provides a two-tier (in-memory + Supabase) cache for EPSS scores.
 * All methods are safe to call without a Supabase config — the DB layer is
 * simply skipped and only the in-memory map is used.
 */
export class EpssCache {
  /** In-memory store: key = `${ecosystem}:${cveId}` */
  private readonly mem = new Map<string, EpssCacheEntry>();

  constructor(private readonly db?: SupabaseConfig) {}

  private memKey(ecosystem: string, cveId: string): string {
    return `${ecosystem}:${cveId.toUpperCase()}`;
  }

  private get baseUrl(): string {
    return this.db!.supabaseUrl.replace(/\/$/, "");
  }

  private dbHeaders(): Record<string, string> {
    return {
      apikey: this.db!.supabaseServiceRoleKey,
      authorization: `Bearer ${this.db!.supabaseServiceRoleKey}`,
      "content-type": "application/json"
    };
  }

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  /**
   * Returns a cached entry for the given ecosystem + CVE, or null if not
   * present / expired.
   */
  async get(ecosystem: string, cveId: string): Promise<EpssCacheEntry | null> {
    const key = this.memKey(ecosystem, cveId);

    // 1. In-memory hit
    const memEntry = this.mem.get(key);
    if (memEntry) {
      if (isEntryFresh(memEntry)) return memEntry;
      this.mem.delete(key); // stale — evict
    }

    // 2. Supabase hit
    if (!this.db) return null;
    try {
      const url =
        `${this.baseUrl}/rest/v1/epss_cache` +
        `?ecosystem=eq.${encodeURIComponent(ecosystem)}` +
        `&cve_id=eq.${encodeURIComponent(cveId.toUpperCase())}` +
        `&select=ecosystem,cve_id,score,percentile,fetched_at&limit=1`;

      const res = await fetch(url, { headers: this.dbHeaders() });
      if (!res.ok) return null;

      const rows = (await res.json()) as Array<{
        ecosystem: string;
        cve_id: string;
        score: number;
        percentile: number;
        fetched_at: string;
      }>;

      if (rows.length === 0) return null;

      const row = rows[0]!;
      const entry: EpssCacheEntry = {
        ecosystem: row.ecosystem,
        cveId: row.cve_id,
        score: row.score,
        percentile: row.percentile,
        fetchedAt: row.fetched_at
      };

      if (!isEntryFresh(entry)) return null;

      // Backfill in-memory layer
      this.mem.set(key, entry);
      return entry;
    } catch {
      return null;
    }
  }

  /**
   * Bulk-get: returns a map of cveId → entry for all CVE IDs that are cached
   * and still fresh. CVE IDs with no entry (or stale entries) are absent from
   * the returned map.
   */
  async getMany(ecosystem: string, cveIds: string[]): Promise<Map<string, EpssCacheEntry>> {
    const result = new Map<string, EpssCacheEntry>();
    const missing: string[] = [];

    for (const cveId of cveIds) {
      const key = this.memKey(ecosystem, cveId);
      const memEntry = this.mem.get(key);
      if (memEntry && isEntryFresh(memEntry)) {
        result.set(cveId.toUpperCase(), memEntry);
      } else {
        if (memEntry) this.mem.delete(key);
        missing.push(cveId.toUpperCase());
      }
    }

    if (missing.length === 0 || !this.db) return result;

    try {
      const url =
        `${this.baseUrl}/rest/v1/epss_cache` +
        `?ecosystem=eq.${encodeURIComponent(ecosystem)}` +
        `&cve_id=in.(${missing.map((c) => encodeURIComponent(c)).join(",")})` +
        `&select=ecosystem,cve_id,score,percentile,fetched_at`;

      const res = await fetch(url, { headers: this.dbHeaders() });
      if (!res.ok) return result;

      const rows = (await res.json()) as Array<{
        ecosystem: string;
        cve_id: string;
        score: number;
        percentile: number;
        fetched_at: string;
      }>;

      for (const row of rows) {
        const entry: EpssCacheEntry = {
          ecosystem: row.ecosystem,
          cveId: row.cve_id,
          score: row.score,
          percentile: row.percentile,
          fetchedAt: row.fetched_at
        };
        if (isEntryFresh(entry)) {
          const key = this.memKey(ecosystem, row.cve_id);
          this.mem.set(key, entry);
          result.set(row.cve_id, entry);
        }
      }
    } catch {
      // best-effort
    }

    return result;
  }

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /**
   * Persist a set of EPSS entries.  Writes to the in-memory layer immediately
   * and fire-and-forgets the upsert to Supabase.
   */
  async setMany(entries: EpssCacheEntry[]): Promise<void> {
    for (const entry of entries) {
      const key = this.memKey(entry.ecosystem, entry.cveId);
      this.mem.set(key, entry);
    }

    if (!this.db || entries.length === 0) return;

    // Fire-and-forget Supabase upsert — don't let DB errors block callers.
    const rows = entries.map((e) => ({
      ecosystem: e.ecosystem,
      cve_id: e.cveId.toUpperCase(),
      score: e.score,
      percentile: e.percentile,
      fetched_at: e.fetchedAt
    }));

    fetch(
      `${this.baseUrl}/rest/v1/epss_cache?on_conflict=ecosystem,cve_id`,
      {
        method: "POST",
        headers: {
          ...this.dbHeaders(),
          Prefer: "resolution=merge-duplicates,return=minimal"
        },
        body: JSON.stringify(rows)
      }
    ).catch((err) => {
      console.warn("[epss-cache] Supabase upsert failed:", err instanceof Error ? err.message : err);
    });
  }
}

// ---------------------------------------------------------------------------
// C Extension EPSS enrichment helpers
// ---------------------------------------------------------------------------

/**
 * Result of enriching a C extension finding with EPSS/CVE context.
 */
export interface CExtensionEpssEnrichment {
  /**
   * The highest-percentile CVE found among the provided CVE IDs.
   * null when no CVEs were found in the cache.
   */
  topCve: EpssCacheEntry | null;
  /**
   * EPSS boost delta for the top CVE (0 when no CVE found).
   * Apply this to a base risk score: finalScore = min(100, base + epssBoost).
   */
  epssBoost: number;
  /**
   * Human-readable summary of the enrichment result.
   * Empty string when no CVE data was found.
   */
  summary: string;
  /**
   * All CVEs found in the cache, sorted by percentile descending.
   * Empty array when none found.
   */
  allCves: EpssCacheEntry[];
}

/**
 * Enrich a C extension finding with EPSS/CVE context from the cache.
 *
 * This is the primary integration point between the PyPiCExtensionAnalyzer
 * and the EPSS risk boost system. When a wheel's METADATA lists
 * `install_requires` packages that have known-vulnerable CVEs in the cache,
 * this function returns the boost delta to apply to the C extension's base
 * risk score.
 *
 * Usage pattern:
 * ```ts
 * const cache = new EpssCache(dbConfig);
 * const enrichment = await enrichCExtensionWithEpss(cache, cveIds);
 * const finalScore = Math.min(100, baseScore + enrichment.epssBoost);
 * ```
 *
 * @param cache   EpssCache instance (in-memory or DB-backed).
 * @param cveIds  CVE IDs associated with the wheel's install_requires deps.
 * @returns       Enrichment result with boost delta and top CVE.
 */
export async function enrichCExtensionWithEpss(
  cache: EpssCache,
  cveIds: string[]
): Promise<CExtensionEpssEnrichment> {
  if (cveIds.length === 0) {
    return { topCve: null, epssBoost: 0, summary: "", allCves: [] };
  }

  const entries = await cache.getMany("pypi", cveIds);
  if (entries.size === 0) {
    return { topCve: null, epssBoost: 0, summary: "", allCves: [] };
  }

  // Sort all found entries by percentile descending
  const allCves = [...entries.values()].sort((a, b) => b.percentile - a.percentile);
  const topCve = allCves[0]!;
  const epssBoost = computeEpssBoostDelta(topCve.percentile);

  const summary =
    epssBoost > 0
      ? `EPSS boost +${epssBoost}pts from ${topCve.cveId} ` +
        `(percentile: ${(topCve.percentile * 100).toFixed(1)}%, ` +
        `score: ${topCve.score.toFixed(4)})`
      : `Top CVE ${topCve.cveId} EPSS percentile ${(topCve.percentile * 100).toFixed(1)}% ` +
        `below boost threshold`;

  return { topCve, epssBoost, summary, allCves };
}
