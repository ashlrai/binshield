/**
 * Batch Scanning Orchestrator
 *
 * Coordinates discovery, persistence, and queueing of native packages
 * for analysis. Tracks each run in the crawler_runs table.
 */

import {
  PackageDiscoveryEngine,
  type DiscoveryConfig,
  type DiscoveredPackage,
} from "./discovery";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CrawlerConfig extends DiscoveryConfig {
  /** Number of packages to queue per batch (default 10). */
  batchSize: number;
  /** Milliseconds to wait between batches (default 2000). */
  delayBetweenBatches: number;
  /** Maximum packages to queue per run (default 100). */
  maxPackages: number;
}

export interface CrawlResult {
  runId: string;
  source: string;
  packagesDiscovered: number;
  packagesQueued: number;
  packagesScanned: number;
  errors: string[];
  durationMs: number;
}

interface CrawlerRunRow {
  id: string;
  source: string;
  status: string;
  packages_discovered: number;
  packages_queued: number;
  packages_scanned: number;
  errors: string[] | null;
  started_at: string;
  completed_at: string | null;
}

interface DiscoveredPackageRow {
  id: string;
  ecosystem: string;
  name: string;
  latest_version: string;
  priority_score: number;
  scan_status: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(message: string) {
  console.log(`[Crawler] ${message}`);
}

function logError(message: string, error?: unknown) {
  const detail =
    error instanceof Error
      ? error.message
      : error !== undefined
        ? String(error)
        : "";
  console.error(`[Crawler] ${message}${detail ? `: ${detail}` : ""}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// PackageCrawler
// ---------------------------------------------------------------------------

export class PackageCrawler {
  private readonly baseUrl: string;
  private readonly serviceRoleKey: string;
  private readonly engine: PackageDiscoveryEngine;
  private readonly config: CrawlerConfig;

  constructor(config: CrawlerConfig) {
    this.config = config;
    this.baseUrl = config.supabaseUrl.replace(/\/$/, "");
    this.serviceRoleKey = config.supabaseServiceRoleKey;
    this.engine = new PackageDiscoveryEngine({
      supabaseUrl: config.supabaseUrl,
      supabaseServiceRoleKey: config.supabaseServiceRoleKey,
    });
  }

  // -------------------------------------------------------------------------
  // Supabase helpers
  // -------------------------------------------------------------------------

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      apikey: this.serviceRoleKey,
      authorization: `Bearer ${this.serviceRoleKey}`,
      "content-type": "application/json",
      ...extra,
    };
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}/rest/v1${path}`, {
      ...init,
      headers: {
        ...this.headers(),
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Supabase request failed (${response.status}): ${text}`,
      );
    }

    if (response.status === 204) {
      return undefined as T;
    }

    const text = await response.text();
    if (!text) {
      return undefined as T;
    }

    return JSON.parse(text) as T;
  }

  // -------------------------------------------------------------------------
  // Crawl run lifecycle
  // -------------------------------------------------------------------------

  /**
   * Run a full discovery + scan cycle.
   *
   * 1. Start a crawler_runs record
   * 2. Run discovery (seed list or registry)
   * 3. Persist discovered packages with priority scores
   * 4. Queue top-priority unscanned packages as analysis_jobs
   * 5. Track progress in crawler_runs
   * 6. Update enrichment data (downloads, GitHub stats)
   */
  async runCrawl(
    source: "seed-list" | "npm-registry",
  ): Promise<CrawlResult> {
    const startTime = Date.now();
    const errors: string[] = [];

    // 1. Start a crawler_runs record
    const runId = await this.startCrawlerRun(source);
    log(`Crawl run ${runId} started (source: ${source})`);

    let packagesDiscovered = 0;
    let packagesQueued = 0;

    try {
      // 2. Run discovery
      let discovered: DiscoveredPackage[];
      if (source === "seed-list") {
        discovered = await this.engine.discoverFromSeedList();
      } else {
        discovered = await this.engine.discoverFromRegistry();
      }

      packagesDiscovered = discovered.length;
      log(`Discovered ${packagesDiscovered} packages`);

      // 3. Persist discovered packages
      await this.updateCrawlerRun(runId, {
        packages_discovered: packagesDiscovered,
        status: "persisting",
      });

      const persisted = await this.engine.persistDiscovered(discovered);
      log(`Persisted ${persisted} packages to discovered_packages`);

      // 4. Queue top-priority unscanned packages
      await this.updateCrawlerRun(runId, { status: "queueing" });
      packagesQueued = await this.queueForScanning(this.config.maxPackages);
      log(`Queued ${packagesQueued} packages for scanning`);

      // 5. Run enrichment on recently discovered packages
      await this.updateCrawlerRun(runId, { status: "enriching" });
      const toEnrich = discovered
        .slice(0, 50) // Enrich top 50 to stay within rate limits
        .map((p) => ({ ecosystem: p.ecosystem, name: p.name }));

      if (toEnrich.length > 0) {
        await this.engine.enrichPackages(toEnrich);
      }

      // 6. Mark run as complete
      await this.completeCrawlerRun(runId, {
        packages_discovered: packagesDiscovered,
        packages_queued: packagesQueued,
        errors,
      });

      log(`Crawl run ${runId} completed`);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      errors.push(message);
      logError("Crawl run failed", error);

      await this.failCrawlerRun(runId, errors);
    }

    const durationMs = Date.now() - startTime;

    return {
      runId,
      source,
      packagesDiscovered,
      packagesQueued,
      packagesScanned: 0, // Scanning happens asynchronously via the daemon
      errors,
      durationMs,
    };
  }

  // -------------------------------------------------------------------------
  // Queueing
  // -------------------------------------------------------------------------

  /**
   * Queue discovered packages for scanning by inserting them into
   * the analysis_jobs table. Selects top-priority packages that
   * haven't been scanned yet.
   */
  async queueForScanning(limit?: number): Promise<number> {
    const maxToQueue = limit ?? this.config.maxPackages;

    // Fetch top-priority unscanned packages
    const candidates = await this.request<DiscoveredPackageRow[]>(
      `/discovered_packages?scan_status=eq.pending&order=priority_score.desc&limit=${maxToQueue}&select=id,ecosystem,name,latest_version,priority_score,scan_status`,
      { method: "GET" },
    );

    if (candidates.length === 0) {
      log("No unscanned packages to queue");
      return 0;
    }

    log(`Found ${candidates.length} candidates for scanning`);

    let queued = 0;

    // Process in batches to avoid overwhelming the queue
    for (
      let i = 0;
      i < candidates.length;
      i += this.config.batchSize
    ) {
      const batch = candidates.slice(i, i + this.config.batchSize);

      const jobs = batch.map((pkg) => ({
        ecosystem: pkg.ecosystem,
        package_name: pkg.name,
        version: pkg.latest_version,
        status: "queued",
        requested_at: new Date().toISOString(),
      }));

      try {
        // Insert analysis jobs. Use ON CONFLICT to skip already-queued packages.
        // PostgREST doesn't support ON CONFLICT on arbitrary columns for analysis_jobs,
        // so we check for existing jobs first.
        const existingJobs = await this.request<Array<{ package_name: string }>>(
          `/analysis_jobs?package_name=in.(${batch.map((p) => `"${p.name}"`).join(",")})&status=in.(queued,analyzing)&select=package_name`,
          { method: "GET" },
        );

        const existingNames = new Set(
          existingJobs.map((j) => j.package_name),
        );
        const newJobs = jobs.filter(
          (j) => !existingNames.has(j.package_name),
        );

        if (newJobs.length > 0) {
          await this.request<unknown>(`/analysis_jobs`, {
            method: "POST",
            headers: { Prefer: "return=minimal" },
            body: JSON.stringify(newJobs),
          });

          // Mark these discovered packages as queued
          const queuedNames = newJobs.map((j) => j.package_name);
          for (const name of queuedNames) {
            await this.request<unknown>(
              `/discovered_packages?ecosystem=eq.npm&name=eq.${encodeURIComponent(name)}`,
              {
                method: "PATCH",
                headers: { Prefer: "return=minimal" },
                body: JSON.stringify({ scan_status: "queued" }),
              },
            );
          }

          queued += newJobs.length;
        }
      } catch (error) {
        logError(
          `Failed to queue batch ${i}-${i + batch.length}`,
          error,
        );
      }

      if (i + this.config.batchSize < candidates.length) {
        await sleep(this.config.delayBetweenBatches);
      }
    }

    log(`Queued ${queued} packages for scanning`);
    return queued;
  }

  // -------------------------------------------------------------------------
  // Enrichment
  // -------------------------------------------------------------------------

  /**
   * Enrich already-scanned packages with metadata (downloads, GitHub
   * stars, etc.). Selects packages that have been scanned but may
   * have stale or missing enrichment data.
   */
  async enrichScannedPackages(): Promise<void> {
    log("Starting enrichment of scanned packages");

    // Fetch packages that have been scanned
    const scanned = await this.request<
      Array<{ ecosystem: string; name: string }>
    >(
      `/discovered_packages?scan_status=eq.scanned&select=ecosystem,name&limit=100&order=updated_at.asc`,
      { method: "GET" },
    );

    if (scanned.length === 0) {
      log("No scanned packages to enrich");
      return;
    }

    await this.engine.enrichPackages(scanned);
  }

  // -------------------------------------------------------------------------
  // Crawler run tracking
  // -------------------------------------------------------------------------

  private async startCrawlerRun(source: string): Promise<string> {
    const [row] = await this.request<CrawlerRunRow[]>(
      `/crawler_runs?select=id`,
      {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          source,
          status: "running",
          packages_discovered: 0,
          packages_queued: 0,
          packages_scanned: 0,
          errors: [],
          started_at: new Date().toISOString(),
        }),
      },
    );

    if (!row) {
      throw new Error("Failed to create crawler_runs record");
    }
    return row.id;
  }

  private async updateCrawlerRun(
    runId: string,
    updates: Record<string, unknown>,
  ): Promise<void> {
    await this.request<unknown>(`/crawler_runs?id=eq.${runId}`, {
      method: "PATCH",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify(updates),
    });
  }

  private async completeCrawlerRun(
    runId: string,
    data: {
      packages_discovered: number;
      packages_queued: number;
      errors: string[];
    },
  ): Promise<void> {
    await this.updateCrawlerRun(runId, {
      status: "completed",
      packages_discovered: data.packages_discovered,
      packages_queued: data.packages_queued,
      errors: data.errors.length > 0 ? data.errors : null,
      completed_at: new Date().toISOString(),
    });
  }

  private async failCrawlerRun(
    runId: string,
    errors: string[],
  ): Promise<void> {
    await this.updateCrawlerRun(runId, {
      status: "failed",
      errors,
      completed_at: new Date().toISOString(),
    });
  }
}
