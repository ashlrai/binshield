// ---------------------------------------------------------------------------
// @binshield/feed-sync-engine
//
// Real-time CVE/EPSS/KEV feed ingestion pipeline.
//
// Sub-modules:
//   nvd-feed-ingester    — fetch latest NVD JSON feeds, parse CVEs, dedup/delta
//   epss-percentile-fetcher — call EPSS API per CVE, cache with TTL
//   cisa-kev-syncer      — fetch CISA KEV catalogue, extract maturity scores
//   DepGraphEnricher     — cross-reference CVEs against lockfile dep graphs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Configuration shared across all feed ingestors.
 */
export interface FeedIngestorConfig {
  /**
   * Maximum age (ms) before a cached feed snapshot is considered stale.
   * Default: 30 days.
   */
  maxFeedAgeMs?: number;
  /**
   * EPSS API base URL (override for testing).
   * Default: "https://api.first.org/data/1.0"
   */
  epssApiBaseUrl?: string;
  /**
   * NVD CVE feed base URL (override for testing).
   * Default: "https://nvd.nist.gov/feeds/json/cve/1.1"
   */
  nvdFeedBaseUrl?: string;
  /**
   * CISA KEV catalog URL (override for testing).
   * Default: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
   */
  cisaKevUrl?: string;
  /**
   * EPSS cache TTL in ms.
   * Default: 6 hours.
   */
  epssCacheTtlMs?: number;
}

/**
 * A single CVE advisory as emitted by the feed pipeline.
 *
 * Mirrors `Advisory` from `@binshield/analysis-types` but is the canonical
 * shape for data flowing through the feed-sync-engine.
 */
export interface SyncedAdvisory {
  /** CVE identifier, e.g. "CVE-2024-12345". */
  cveId: string;
  /** Human-readable description from NVD. */
  description: string;
  /** CVSS v3 base score [0, 10], if available. */
  cvssV3Score?: number;
  /** CVSS v3 severity label (e.g. "HIGH", "CRITICAL"). */
  cvssV3Severity?: string;
  /** EPSS probability percentile [0, 1], populated by epss-percentile-fetcher. */
  epssPercentile?: number;
  /** True when this CVE appears in the CISA KEV catalogue. */
  isKev: boolean;
  /** CISA KEV date added (ISO string), if applicable. */
  kevDateAdded?: string;
  /**
   * CISA KEV exploit maturity inferred from the catalog.
   * Always "active-exploitation" for entries in the KEV list.
   */
  exploitMaturity?: "proof-of-concept" | "active-exploitation" | "widespread";
  /**
   * CPE strings from NVD describing affected products.
   * Used to cross-reference against dependency package names.
   */
  affectedProducts: string[];
  /**
   * Affected version ranges in the form "[minVersion, maxVersion]".
   * Empty when NVD does not provide structured range data.
   */
  affectedVersionRanges: Array<{ minVersion?: string; maxVersion?: string }>;
  /** ISO timestamp of the NVD last-modified date. */
  lastModifiedAt: string;
  /** ISO timestamp when this advisory was fetched and ingested. */
  ingestedAt: string;
}

/**
 * Result emitted by `DepGraphEnricher.enrich()`.
 *
 * Per-dependency vulnerability counts and the highest EPSS percentile
 * across all matched CVEs.
 */
export interface DepGraphEnrichmentResult {
  /** Package name (e.g. "lodash"). */
  packageName: string;
  /** Package version from the lockfile (e.g. "4.17.21"). */
  version: string;
  /** Number of CVEs matched for this package@version. */
  vulnCount: number;
  /**
   * Highest EPSS percentile among all matched CVEs [0, 1].
   * 0 when there are no matches or no EPSS data.
   */
  highestEpssPercentile: number;
  /** CVE IDs matched for this package. */
  matchedCveIds: string[];
  /** Whether any of the matched CVEs are in the CISA KEV catalogue. */
  hasKevMatch: boolean;
  /** ISO timestamp when this enrichment was computed. */
  enrichedAt: string;
}

// ---------------------------------------------------------------------------
// Staleness guard (shared)
// ---------------------------------------------------------------------------

/** Default maximum feed age: 30 days. */
const DEFAULT_MAX_FEED_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Returns true when a feed snapshot is still considered fresh.
 *
 * @param fetchedAt ISO timestamp when the feed was fetched.
 * @param maxAgeMs  Maximum acceptable age in milliseconds (default 30 days).
 * @param now       Current time in ms since epoch (injectable for tests).
 */
export function isFresh(
  fetchedAt: string,
  maxAgeMs = DEFAULT_MAX_FEED_AGE_MS,
  now = Date.now()
): boolean {
  const fetchedMs = new Date(fetchedAt).getTime();
  if (isNaN(fetchedMs)) return false;
  return now - fetchedMs <= maxAgeMs;
}

// ---------------------------------------------------------------------------
// NVD raw shapes (subset of fields we consume)
// ---------------------------------------------------------------------------

/** Minimal NVD CVE item shape (NVD JSON feed 1.1 format). */
export interface NvdCveItem {
  cve: {
    CVE_data_meta: { ID: string };
    description: {
      description_data: Array<{ lang: string; value: string }>;
    };
    affects?: {
      vendor?: {
        vendor_data?: Array<{
          product?: {
            product_data?: Array<{
              version?: {
                version_data?: Array<{
                  version_value?: string;
                  version_affected?: string;
                }>;
              };
            }>;
          };
        }>;
      };
    };
  };
  impact?: {
    baseMetricV3?: {
      cvssV3?: { baseScore?: number; baseSeverity?: string };
    };
  };
  configurations?: {
    nodes?: Array<{
      cpe_match?: Array<{
        cpe23Uri?: string;
        versionStartIncluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
      }>;
    }>;
  };
  lastModifiedDate?: string;
}

/** NVD JSON feed envelope. */
export interface NvdFeedEnvelope {
  CVE_Items: NvdCveItem[];
}

// ---------------------------------------------------------------------------
// nvd-feed-ingester
// ---------------------------------------------------------------------------

/**
 * Result from `NvdFeedIngester.ingest()`.
 */
export interface NvdIngestResult {
  /** All parsed CVE advisories from the feed. */
  advisories: SyncedAdvisory[];
  /** CVE IDs that were already present and unchanged (deduplicated). */
  unchanged: string[];
  /** CVE IDs that are new since the last snapshot. */
  added: string[];
  /** CVE IDs that differ from the last snapshot (delta detected). */
  updated: string[];
  /** ISO timestamp when the feed was fetched. */
  fetchedAt: string;
}

/**
 * Parses a raw NVD CVE item into a `SyncedAdvisory`.
 * Exposed for unit testing.
 */
export function parseNvdCveItem(item: NvdCveItem): SyncedAdvisory {
  const cveId = item.cve.CVE_data_meta.ID;

  const description =
    item.cve.description.description_data.find((d) => d.lang === "en")?.value ??
    item.cve.description.description_data[0]?.value ??
    "";

  const cvssV3Score = item.impact?.baseMetricV3?.cvssV3?.baseScore;
  const cvssV3Severity = item.impact?.baseMetricV3?.cvssV3?.baseSeverity;

  // Collect CPE strings from configurations nodes
  const affectedProducts: string[] = [];
  const affectedVersionRanges: Array<{ minVersion?: string; maxVersion?: string }> = [];

  for (const node of item.configurations?.nodes ?? []) {
    for (const cpe of node.cpe_match ?? []) {
      if (cpe.cpe23Uri) affectedProducts.push(cpe.cpe23Uri);

      const minVersion = cpe.versionStartIncluding;
      const maxVersion = cpe.versionEndIncluding ?? cpe.versionEndExcluding;
      if (minVersion || maxVersion) {
        affectedVersionRanges.push({ minVersion, maxVersion });
      }
    }
  }

  const now = new Date().toISOString();

  return {
    cveId,
    description,
    cvssV3Score,
    cvssV3Severity,
    epssPercentile: undefined,
    isKev: false,
    affectedProducts,
    affectedVersionRanges,
    lastModifiedAt: item.lastModifiedDate ?? now,
    ingestedAt: now
  };
}

/**
 * Deduplicates and computes a delta between a new batch of advisories and an
 * existing snapshot.
 *
 * Returns { unchanged, added, updated } keyed by CVE ID.
 *
 * Detection logic: a CVE is considered "updated" when its `lastModifiedAt`
 * timestamp differs from the stored snapshot (or when it was previously absent).
 */
export function computeNvdDelta(
  incoming: SyncedAdvisory[],
  existing: Map<string, SyncedAdvisory>
): { unchanged: string[]; added: string[]; updated: string[] } {
  const unchanged: string[] = [];
  const added: string[] = [];
  const updated: string[] = [];

  for (const advisory of incoming) {
    const stored = existing.get(advisory.cveId);
    if (!stored) {
      added.push(advisory.cveId);
    } else if (stored.lastModifiedAt !== advisory.lastModifiedAt) {
      updated.push(advisory.cveId);
    } else {
      unchanged.push(advisory.cveId);
    }
  }

  return { unchanged, added, updated };
}

/**
 * NVD feed ingester.
 *
 * Fetches the NVD CVE JSON feed, parses each CVE item, deduplicates against
 * an in-memory snapshot, and emits a delta report.
 *
 * In production wire `fetchFn` to the global `fetch`. In tests inject a stub.
 */
export class NvdFeedIngester {
  private readonly baseUrl: string;
  private readonly maxAgeMs: number;
  private snapshot: Map<string, SyncedAdvisory> = new Map();
  private lastFetchedAt: string | null = null;

  constructor(
    config: FeedIngestorConfig = {},
    private readonly fetchFn: typeof fetch = fetch
  ) {
    this.baseUrl =
      config.nvdFeedBaseUrl ?? "https://nvd.nist.gov/feeds/json/cve/1.1";
    this.maxAgeMs = config.maxFeedAgeMs ?? DEFAULT_MAX_FEED_AGE_MS;
  }

  /**
   * True when the last fetched snapshot is still within the freshness window.
   */
  isSnapshotFresh(now = Date.now()): boolean {
    if (!this.lastFetchedAt) return false;
    return isFresh(this.lastFetchedAt, this.maxAgeMs, now);
  }

  /**
   * Fetch the NVD recent-changes feed, parse, deduplicate, and return a delta.
   *
   * @param feedPath  Path segment appended to baseUrl (default "nvdcve-1.1-recent.json.gz").
   */
  async ingest(feedPath = "nvdcve-1.1-recent.json.gz"): Promise<NvdIngestResult> {
    const url = `${this.baseUrl}/${feedPath}`;
    const response = await this.fetchFn(url);
    if (!response.ok) {
      throw new Error(
        `NvdFeedIngester: HTTP ${response.status} fetching ${url}`
      );
    }

    const envelope = (await response.json()) as NvdFeedEnvelope;
    const fetchedAt = new Date().toISOString();
    this.lastFetchedAt = fetchedAt;

    const incoming = envelope.CVE_Items.map(parseNvdCveItem);
    const { unchanged, added, updated } = computeNvdDelta(incoming, this.snapshot);

    // Merge incoming into snapshot
    for (const advisory of incoming) {
      this.snapshot.set(advisory.cveId, advisory);
    }

    return { advisories: incoming, unchanged, added, updated, fetchedAt };
  }

  /** Current in-memory snapshot (read-only). */
  getSnapshot(): ReadonlyMap<string, SyncedAdvisory> {
    return this.snapshot;
  }
}

// ---------------------------------------------------------------------------
// EPSS percentile fetcher
// ---------------------------------------------------------------------------

/** Cached EPSS entry. */
interface EpssCacheEntry {
  percentile: number;
  cachedAt: number; // Date.now()
}

/**
 * Fetches EPSS percentiles for CVE IDs from the FIRST.org EPSS API and caches
 * results with a configurable TTL (default 6 hours).
 *
 * EPSS API: https://api.first.org/data/1.0/epss?cve=CVE-2024-12345,CVE-2024-99999
 */
export class EpssPercentileFetcher {
  private readonly baseUrl: string;
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, EpssCacheEntry>();

  constructor(
    config: FeedIngestorConfig = {},
    private readonly fetchFn: typeof fetch = fetch
  ) {
    this.baseUrl =
      config.epssApiBaseUrl ?? "https://api.first.org/data/1.0";
    this.cacheTtlMs = config.epssCacheTtlMs ?? 6 * 60 * 60 * 1000; // 6 hours
  }

  /**
   * Returns the cached EPSS percentile for a CVE if it is still fresh,
   * otherwise returns undefined.
   */
  getCached(cveId: string, now = Date.now()): number | undefined {
    const entry = this.cache.get(cveId);
    if (!entry) return undefined;
    if (now - entry.cachedAt > this.cacheTtlMs) {
      this.cache.delete(cveId);
      return undefined;
    }
    return entry.percentile;
  }

  /**
   * Fetch EPSS percentiles for a batch of CVE IDs.
   *
   * Results are cached with the configured TTL. Already-cached (fresh) CVEs
   * are not re-fetched — only uncached CVEs go to the API.
   *
   * @returns Map from CVE ID → EPSS percentile [0, 1]. CVEs with no EPSS
   *          data are omitted from the result map.
   */
  async fetchBatch(
    cveIds: string[],
    now = Date.now()
  ): Promise<Map<string, number>> {
    if (cveIds.length === 0) return new Map();

    const result = new Map<string, number>();
    const toFetch: string[] = [];

    for (const cveId of cveIds) {
      const cached = this.getCached(cveId, now);
      if (cached !== undefined) {
        result.set(cveId, cached);
      } else {
        toFetch.push(cveId);
      }
    }

    if (toFetch.length === 0) return result;

    const queryParam = toFetch.join(",");
    const url = `${this.baseUrl}/epss?cve=${encodeURIComponent(queryParam)}`;
    const response = await this.fetchFn(url);
    if (!response.ok) {
      throw new Error(
        `EpssPercentileFetcher: HTTP ${response.status} fetching EPSS data`
      );
    }

    const body = (await response.json()) as {
      data?: Array<{ cve: string; epss: string; percentile: string }>;
    };

    for (const entry of body.data ?? []) {
      const percentile = parseFloat(entry.percentile);
      if (!isNaN(percentile)) {
        result.set(entry.cve, percentile);
        this.cache.set(entry.cve, { percentile, cachedAt: now });
      }
    }

    return result;
  }

  /**
   * Fetch the EPSS percentile for a single CVE ID.
   * Returns undefined when the CVE has no EPSS record.
   */
  async fetch(cveId: string, now = Date.now()): Promise<number | undefined> {
    const batch = await this.fetchBatch([cveId], now);
    return batch.get(cveId);
  }

  /** Evict all cache entries whose TTL has expired. */
  pruneCache(now = Date.now()): number {
    let evicted = 0;
    for (const [cveId, entry] of this.cache.entries()) {
      if (now - entry.cachedAt > this.cacheTtlMs) {
        this.cache.delete(cveId);
        evicted++;
      }
    }
    return evicted;
  }
}

// ---------------------------------------------------------------------------
// CISA KEV syncer
// ---------------------------------------------------------------------------

/** Raw shape of a CISA KEV catalog entry (subset). */
export interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse?: "Known" | "Unknown";
}

/** Parsed CISA KEV record used internally by the engine. */
export interface KevRecord {
  cveId: string;
  dateAdded: string;
  /**
   * Maturity classification inferred from the catalog.
   * All KEV entries represent confirmed active exploitation.
   */
  exploitMaturity: "active-exploitation" | "widespread";
  /** True when ransomware campaigns are known to exploit this CVE. */
  isRansomware: boolean;
}

/** Result from `CisaKevSyncer.sync()`. */
export interface KevSyncResult {
  /** All parsed KEV records. */
  records: KevRecord[];
  /** CVE IDs that were newly added since the last sync. */
  added: string[];
  /** ISO timestamp when the catalog was fetched. */
  fetchedAt: string;
}

/**
 * Parse a raw CISA KEV entry into a `KevRecord`.
 * Exposed for unit testing.
 */
export function parseCisaKevEntry(entry: CisaKevEntry): KevRecord {
  const isRansomware = entry.knownRansomwareCampaignUse === "Known";
  // All KEV entries represent active exploitation. Promote to "widespread"
  // when ransomware campaigns are involved.
  const exploitMaturity: KevRecord["exploitMaturity"] = isRansomware
    ? "widespread"
    : "active-exploitation";

  return {
    cveId: entry.cveID,
    dateAdded: entry.dateAdded,
    exploitMaturity,
    isRansomware
  };
}

/**
 * CISA KEV catalog syncer.
 *
 * Fetches the known exploited vulnerabilities JSON from CISA, parses entries,
 * and maintains an in-memory set for fast CVE lookups.
 */
export class CisaKevSyncer {
  private readonly url: string;
  private readonly maxAgeMs: number;
  private kevSet = new Map<string, KevRecord>();
  private lastFetchedAt: string | null = null;

  constructor(
    config: FeedIngestorConfig = {},
    private readonly fetchFn: typeof fetch = fetch
  ) {
    this.url =
      config.cisaKevUrl ??
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    this.maxAgeMs = config.maxFeedAgeMs ?? DEFAULT_MAX_FEED_AGE_MS;
  }

  /** True when the last fetched snapshot is still within the freshness window. */
  isSnapshotFresh(now = Date.now()): boolean {
    if (!this.lastFetchedAt) return false;
    return isFresh(this.lastFetchedAt, this.maxAgeMs, now);
  }

  /**
   * Fetch and parse the CISA KEV catalog.
   * Returns a delta of newly added CVE IDs since the last sync.
   */
  async sync(): Promise<KevSyncResult> {
    const response = await this.fetchFn(this.url);
    if (!response.ok) {
      throw new Error(
        `CisaKevSyncer: HTTP ${response.status} fetching CISA KEV catalog`
      );
    }

    const body = (await response.json()) as {
      vulnerabilities: CisaKevEntry[];
    };

    const fetchedAt = new Date().toISOString();
    this.lastFetchedAt = fetchedAt;

    const records = body.vulnerabilities.map(parseCisaKevEntry);
    const added: string[] = [];

    for (const record of records) {
      if (!this.kevSet.has(record.cveId)) {
        added.push(record.cveId);
      }
      this.kevSet.set(record.cveId, record);
    }

    return { records, added, fetchedAt };
  }

  /**
   * Look up a CVE ID in the KEV set.
   * Returns the record if present, undefined otherwise.
   */
  lookup(cveId: string): KevRecord | undefined {
    return this.kevSet.get(cveId);
  }

  /** True when the CVE is in the KEV catalog. */
  isKev(cveId: string): boolean {
    return this.kevSet.has(cveId);
  }

  /** Current KEV set size. */
  get size(): number {
    return this.kevSet.size;
  }
}

// ---------------------------------------------------------------------------
// Version range matching
// ---------------------------------------------------------------------------

/**
 * Coerce a semver-like string to a comparable numeric tuple [major, minor, patch].
 * Returns null for non-parseable strings.
 */
export function coerceVersion(version: string): [number, number, number] | null {
  if (!version) return null;
  // Strip leading "v" or "=" prefix and any build metadata
  const clean = version.replace(/^[v=]/, "").split(/[-+]/)[0];
  if (!clean) return null;
  const parts = clean.split(".").map(Number);
  if (parts.length < 1 || parts.some(isNaN)) return null;
  const [major = 0, minor = 0, patch = 0] = parts;
  return [major, minor, patch];
}

/** Compare two version tuples. Returns negative, 0, or positive. */
function compareTuples(
  a: [number, number, number],
  b: [number, number, number]
): number {
  if (a[0] !== b[0]) return a[0] - b[0];
  if (a[1] !== b[1]) return a[1] - b[1];
  return a[2] - b[2];
}

/**
 * Check whether `version` falls within an affected version range.
 *
 * When a range has both minVersion and maxVersion the check is inclusive on both ends.
 * When only maxVersion is set, all versions up to and including maxVersion are affected.
 * When only minVersion is set, all versions from minVersion onwards are affected.
 * An empty range object matches any version.
 */
export function versionInRange(
  version: string,
  range: { minVersion?: string; maxVersion?: string }
): boolean {
  const vTuple = coerceVersion(version);
  if (!vTuple) return false;

  if (range.minVersion) {
    const minTuple = coerceVersion(range.minVersion);
    if (minTuple && compareTuples(vTuple, minTuple) < 0) return false;
  }

  if (range.maxVersion) {
    const maxTuple = coerceVersion(range.maxVersion);
    if (maxTuple && compareTuples(vTuple, maxTuple) > 0) return false;
  }

  return true;
}

/**
 * Check whether a package name and version match a `SyncedAdvisory`.
 *
 * Matching strategy:
 *   1. A package name match is a case-insensitive substring of any CPE URI in
 *      `affectedProducts` (CPE format: "cpe:2.3:a:vendor:product:version:...").
 *      This is intentionally permissive — false positives are filtered downstream.
 *   2. If `affectedVersionRanges` is non-empty, the version must fall within
 *      at least one range.
 *   3. If `affectedVersionRanges` is empty, any version is considered affected
 *      (the advisory lacks structured range data).
 */
export function advisoryMatchesPackage(
  advisory: SyncedAdvisory,
  packageName: string,
  version: string
): boolean {
  const lowerName = packageName.toLowerCase();

  // Step 1: product name match
  const nameMatches =
    advisory.affectedProducts.length === 0 ||
    advisory.affectedProducts.some((cpe) =>
      cpe.toLowerCase().includes(lowerName)
    );

  if (!nameMatches) return false;

  // Step 2: version range match
  if (advisory.affectedVersionRanges.length === 0) return true;

  return advisory.affectedVersionRanges.some((range) =>
    versionInRange(version, range)
  );
}

// ---------------------------------------------------------------------------
// DepGraphEnricher
// ---------------------------------------------------------------------------

/** A single entry in a dependency graph (name → version). */
export interface DepGraphEntry {
  packageName: string;
  version: string;
}

/**
 * Enriches a lockfile dependency graph by cross-referencing each dependency
 * against the synced advisory set.
 *
 * Per dep output:
 *   - vulnerability count
 *   - matched CVE IDs
 *   - highest EPSS percentile across all matches
 *   - whether any match is in CISA KEV
 */
export class DepGraphEnricher {
  constructor(
    private readonly advisories: ReadonlyMap<string, SyncedAdvisory>,
    private readonly kevSyncer?: CisaKevSyncer
  ) {}

  /**
   * Enrich a single dependency.
   *
   * Scans all advisories for matches against the package name and version,
   * then aggregates vulnerability counts and the highest EPSS percentile.
   */
  enrichOne(dep: DepGraphEntry, now = Date.now()): DepGraphEnrichmentResult {
    const matchedAdvisories: SyncedAdvisory[] = [];

    for (const advisory of this.advisories.values()) {
      // Skip stale feed entries
      if (!isFresh(advisory.ingestedAt, DEFAULT_MAX_FEED_AGE_MS, now)) continue;

      if (advisoryMatchesPackage(advisory, dep.packageName, dep.version)) {
        matchedAdvisories.push(advisory);
      }
    }

    const matchedCveIds = matchedAdvisories.map((a) => a.cveId);

    const highestEpssPercentile =
      matchedAdvisories.length > 0
        ? Math.max(
            ...matchedAdvisories.map((a) => a.epssPercentile ?? 0)
          )
        : 0;

    const hasKevMatch = matchedAdvisories.some(
      (a) =>
        a.isKev ||
        (this.kevSyncer?.isKev(a.cveId) ?? false)
    );

    return {
      packageName: dep.packageName,
      version: dep.version,
      vulnCount: matchedAdvisories.length,
      highestEpssPercentile,
      matchedCveIds,
      hasKevMatch,
      enrichedAt: new Date().toISOString()
    };
  }

  /**
   * Enrich all dependencies in a lockfile graph.
   *
   * @param deps  Dependency entries (packageName + version pairs).
   * @returns     One `DepGraphEnrichmentResult` per dependency, sorted by
   *              `vulnCount` descending (most vulnerable first).
   */
  enrich(deps: DepGraphEntry[], now = Date.now()): DepGraphEnrichmentResult[] {
    return deps
      .map((dep) => this.enrichOne(dep, now))
      .sort((a, b) => b.vulnCount - a.vulnCount);
  }
}

// ---------------------------------------------------------------------------
// Re-exports for convenience
// ---------------------------------------------------------------------------

export { isFresh as isFeedFresh };
