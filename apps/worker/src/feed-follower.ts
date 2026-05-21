/**
 * npm Registry Feed Follower
 *
 * Polls the npm registry /_changes endpoint (CouchDB changes feed) to
 * discover newly published packages. Filters for packages with native
 * binary indicators and auto-queues them for BinShield analysis.
 *
 * Usage:
 *   BINSHIELD_WORKER_MODE=feed pnpm --filter @binshield/worker dev
 */

import type { SupabaseWorkerConfig } from "./supabase-store";
import { hasNativeIndicators as checkNativeIndicators, hasInstallScripts } from "./native-indicators";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FeedFollowerConfig extends SupabaseWorkerConfig {
  /** Milliseconds between poll cycles. Default: 10000. */
  pollIntervalMs: number;
  /** Maximum docs per poll. Default: 100. */
  batchSize: number;
  /** Only queue packages with weekly downloads above this threshold. Default: 100. */
  minDownloads: number;
}

interface CouchDBChange {
  seq: string | number;
  id: string;
  changes: Array<{ rev: string }>;
  deleted?: boolean;
  doc?: NpmPackageDoc;
}

interface CouchDBChangesResponse {
  results: CouchDBChange[];
  last_seq: string;
}

interface NpmPackageDoc {
  _id: string;
  name: string;
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, NpmVersionDoc>;
  time?: Record<string, string>;
}

interface NpmVersionDoc {
  name: string;
  version: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  binary?: Record<string, unknown>;
  gypfile?: boolean;
  files?: string[];
}

interface FeedEvent {
  ecosystem: string;
  package_name: string;
  version: string;
  event_type: string;
  risk_score?: number;
  risk_level?: string;
  metadata: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Feed Follower
// ---------------------------------------------------------------------------

function hasNativeIndicators(doc: NpmVersionDoc): boolean {
  return checkNativeIndicators(doc);
}

function log(message: string) {
  console.log(`[BinShield Feed] ${message}`);
}

function logError(message: string, error?: unknown) {
  const detail = error instanceof Error ? error.message : error !== undefined ? String(error) : "";
  console.error(`[BinShield Feed] ${message}${detail ? `: ${detail}` : ""}`);
}

export class FeedFollower {
  private readonly config: FeedFollowerConfig;
  private readonly baseUrl: string;
  private readonly serviceRoleKey: string;

  private timer: ReturnType<typeof setInterval> | null = null;
  private stopping = false;
  private polling = false;
  private lastSeq = "0";

  constructor(config: FeedFollowerConfig) {
    this.config = config;
    this.baseUrl = config.supabaseUrl.replace(/\/$/, "");
    this.serviceRoleKey = config.supabaseServiceRoleKey;
  }

  private headers(): Record<string, string> {
    return {
      apikey: this.serviceRoleKey,
      authorization: `Bearer ${this.serviceRoleKey}`,
      "content-type": "application/json",
    };
  }

  private async supabaseRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}/rest/v1${path}`, {
      ...init,
      headers: { ...this.headers(), ...(init.headers as Record<string, string> | undefined) },
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Supabase request failed (${response.status}): ${text}`);
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  async start(): Promise<void> {
    log("Starting npm feed follower");
    log(`Poll interval: ${this.config.pollIntervalMs}ms`);
    log(`Batch size: ${this.config.batchSize}`);
    log(`Min downloads: ${this.config.minDownloads}`);

    // Restore last sequence from database
    await this.restoreState();
    log(`Resuming from seq: ${this.lastSeq}`);

    // Graceful shutdown
    const onSignal = () => this.stop();
    process.on("SIGTERM", onSignal);
    process.on("SIGINT", onSignal);

    // Initial poll + interval
    await this.poll();
    this.timer = setInterval(() => {
      void this.poll();
    }, this.config.pollIntervalMs);
  }

  stop(): void {
    if (this.stopping) return;
    this.stopping = true;
    log("Shutting down feed follower...");
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  // ---------------------------------------------------------------------------
  // State persistence
  // ---------------------------------------------------------------------------

  private async restoreState(): Promise<void> {
    try {
      const rows = await this.supabaseRequest<Array<{ last_seq: string }>>(
        "/feed_state?id=eq.npm&select=last_seq",
        { method: "GET" },
      );
      if (rows.length > 0) {
        this.lastSeq = rows[0].last_seq;
      } else {
        // Initialize feed state — start from "now" to avoid processing entire history
        await this.supabaseRequest<unknown>("/feed_state", {
          method: "POST",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({
            id: "npm",
            last_seq: "now",
            packages_processed: 0,
            native_packages_found: 0,
          }),
        });
        this.lastSeq = "now";
      }
    } catch (error) {
      logError("Failed to restore feed state", error);
    }
  }

  private async saveState(
    lastSeq: string,
    packagesProcessed: number,
    nativeFound: number,
  ): Promise<void> {
    try {
      await this.supabaseRequest<unknown>("/feed_state?id=eq.npm", {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          last_seq: lastSeq,
          packages_processed: packagesProcessed,
          native_packages_found: nativeFound,
          updated_at: new Date().toISOString(),
        }),
      });
    } catch (error) {
      logError("Failed to save feed state", error);
    }
  }

  // ---------------------------------------------------------------------------
  // Polling
  // ---------------------------------------------------------------------------

  private async poll(): Promise<void> {
    if (this.stopping || this.polling) return;
    this.polling = true;

    try {
      // Fetch changes from npm registry
      const url = `https://replicate.npmjs.com/_changes?since=${this.lastSeq}&limit=${this.config.batchSize}&include_docs=true`;
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(30000),
      });

      if (!response.ok) {
        logError(`npm changes API returned ${response.status}`);
        return;
      }

      const data = (await response.json()) as CouchDBChangesResponse;

      if (data.results.length === 0) {
        return;
      }

      let nativeCount = 0;
      const events: FeedEvent[] = [];

      for (const change of data.results) {
        if (change.deleted || !change.doc) continue;

        const doc = change.doc;
        const latestTag = doc["dist-tags"]?.latest;
        if (!latestTag || !doc.versions) continue;

        const latestVersion = doc.versions[latestTag];
        if (!latestVersion) continue;

        // Queue packages that ship native binaries OR run install scripts.
        // Install-script packages are the npm supply-chain worm vector and
        // were previously ignored by the native-only filter.
        const isNative = hasNativeIndicators(latestVersion);
        const hasScripts = hasInstallScripts(latestVersion);
        if (isNative || hasScripts) {
          if (isNative) {
            nativeCount++;
          }

          // Check download count (quick heuristic: skip very low-traffic packages)
          const downloads = await this.getWeeklyDownloads(doc.name);
          if (downloads < this.config.minDownloads) continue;

          // Queue for analysis if not already scanned
          const alreadyExists = await this.packageExists(doc.name, latestTag);
          if (!alreadyExists) {
            await this.queueScan(doc.name, latestTag);
            events.push({
              ecosystem: "npm",
              package_name: doc.name,
              version: latestTag,
              event_type: "new_version",
              metadata: {
                downloads,
                source: "feed",
                reason: isNative ? "native-binary" : "install-script",
              },
            });
          }
        }
      }

      // Persist feed events
      if (events.length > 0) {
        await this.recordEvents(events);
      }

      // Save state
      this.lastSeq = data.last_seq;
      await this.saveState(
        data.last_seq,
        data.results.length,
        nativeCount,
      );

      if (nativeCount > 0) {
        log(`Processed ${data.results.length} changes, found ${nativeCount} native packages, queued ${events.length} scans`);
      }
    } catch (error) {
      logError("Poll cycle failed", error);
    } finally {
      this.polling = false;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private async getWeeklyDownloads(packageName: string): Promise<number> {
    try {
      const response = await fetch(
        `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`,
        { signal: AbortSignal.timeout(5000) },
      );
      if (!response.ok) return 0;
      const data = (await response.json()) as { downloads?: number };
      return data.downloads ?? 0;
    } catch {
      return 0;
    }
  }

  private async packageExists(name: string, version: string): Promise<boolean> {
    try {
      const rows = await this.supabaseRequest<Array<{ id: string }>>(
        `/packages?select=id&ecosystem=eq.npm&name=eq.${encodeURIComponent(name)}`,
        { method: "GET" },
      );
      if (rows.length === 0) return false;

      // Check if this specific version has been analyzed
      const analyses = await this.supabaseRequest<Array<{ id: string }>>(
        `/analyses?select=id&package_id=eq.${rows[0].id}&version=eq.${encodeURIComponent(version)}&limit=1`,
        { method: "GET" },
      );
      return analyses.length > 0;
    } catch {
      return false;
    }
  }

  private async queueScan(name: string, version: string): Promise<void> {
    try {
      await this.supabaseRequest<unknown>("/analysis_jobs", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          ecosystem: "npm",
          package_name: name,
          version,
          status: "queued",
        }),
      });
    } catch (error) {
      logError(`Failed to queue scan for ${name}@${version}`, error);
    }
  }

  private async recordEvents(events: FeedEvent[]): Promise<void> {
    try {
      await this.supabaseRequest<unknown>("/feed_events", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify(events),
      });
    } catch (error) {
      logError("Failed to record feed events", error);
    }
  }
}
