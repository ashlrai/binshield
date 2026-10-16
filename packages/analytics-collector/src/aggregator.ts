/**
 * Dashboard aggregation — computes KPIs from a stream of AnalyticsEvents.
 *
 * Designed to work against both:
 *   1. An in-memory snapshot (for tests and local dev).
 *   2. Supabase row data (for production, fetched by the API route).
 */

import type { AnalyticsEvent, ScanCompletedEvent } from "./schema";

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export interface TopPackageEntry {
  packageName: string;
  ecosystem: string;
  scanCount: number;
}

export interface DashboardKPIs {
  /** Successful scans in the past 7 days (demo events excluded). */
  total_scans_7d: number;
  /** Percentage of scans that failed in the past 7 days (0–100, 2 dp). */
  error_rate_pct: number;
  /** 95th-percentile latency in milliseconds across successful scans (7d). */
  p95_latency_ms: number;
  /** Distinct orgs that ran at least one scan in the past 7 days. */
  active_orgs_7d: number;
  /** Top 10 packages by scan volume in the past 7 days. */
  top_packages_by_volume: TopPackageEntry[];
  /**
   * Conversion rate: % of orgs that have at least one paid scan (riskLevel ≠
   * "none") out of all active orgs.  Proxy for free→paid conversion when
   * billing data is absent.
   */
  conversion_rate: number;
  /** ISO-8601 timestamp of when these KPIs were computed. */
  computed_at: string;
  /** Window covered by these KPIs. */
  window_days: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function cutoff(windowDays: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - windowDays);
  return d;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0]!;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))]!;
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

export class DashboardAggregator {
  /**
   * Compute KPIs from an in-memory event snapshot.
   *
   * @param events   All events in the buffer (mixed types, any age).
   * @param windowDays  Lookback window in days. Default: 7.
   */
  compute(events: readonly AnalyticsEvent[], windowDays = 7): DashboardKPIs {
    const since = cutoff(windowDays);

    // Filter to the window
    const inWindow = events.filter(
      (e) => !e.demo && new Date(e.timestamp) >= since
    );

    const completedInWindow = inWindow.filter(
      (e): e is ScanCompletedEvent => e.type === "scan_completed"
    );

    const failedCount = inWindow.filter((e) => e.type === "scan_failed").length;
    const totalAttempts = completedInWindow.length + failedCount;

    // error_rate_pct
    const error_rate_pct =
      totalAttempts === 0
        ? 0
        : Math.round((failedCount / totalAttempts) * 10000) / 100;

    // p95_latency_ms
    const latencies = completedInWindow
      .map((e) => e.durationMs)
      .sort((a, b) => a - b);
    const p95_latency_ms = percentile(latencies, 95);

    // active_orgs_7d
    const activeOrgs = new Set<string>();
    for (const e of inWindow) {
      if (e.orgId) activeOrgs.add(e.orgId);
    }

    // top_packages_by_volume
    const pkgCounts = new Map<string, TopPackageEntry>();
    for (const e of completedInWindow) {
      const key = `${e.ecosystem}:${e.packageName}`;
      const existing = pkgCounts.get(key);
      if (existing) {
        existing.scanCount++;
      } else {
        pkgCounts.set(key, {
          packageName: e.packageName,
          ecosystem: e.ecosystem,
          scanCount: 1
        });
      }
    }
    const top_packages_by_volume = [...pkgCounts.values()]
      .sort((a, b) => b.scanCount - a.scanCount)
      .slice(0, 10);

    // conversion_rate — orgs with at least one non-"none" risk scan / all active orgs
    const orgsWithRisk = new Set<string>();
    for (const e of completedInWindow) {
      if (e.orgId && e.riskLevel !== "none") {
        orgsWithRisk.add(e.orgId);
      }
    }
    const conversion_rate =
      activeOrgs.size === 0
        ? 0
        : Math.round((orgsWithRisk.size / activeOrgs.size) * 10000) / 100;

    return {
      total_scans_7d: completedInWindow.length,
      error_rate_pct,
      p95_latency_ms,
      active_orgs_7d: activeOrgs.size,
      top_packages_by_volume,
      conversion_rate,
      computed_at: new Date().toISOString(),
      window_days: windowDays
    };
  }

  /**
   * Compute KPIs from raw Supabase row data.
   *
   * Rows are expected to have the shape returned by
   * `SELECT event_type, org_id, demo, timestamp, payload FROM analytics_events`.
   */
  computeFromRows(
    rows: Array<{
      event_type: string;
      org_id: string | null;
      demo: boolean;
      timestamp: string;
      payload: Record<string, unknown>;
    }>,
    windowDays = 7
  ): DashboardKPIs {
    // Reconstruct lightweight event objects from DB rows
    const events: AnalyticsEvent[] = rows.map((row) => ({
      ...row.payload,
      type: row.event_type,
      orgId: row.org_id ?? undefined,
      demo: row.demo,
      timestamp: row.timestamp
    })) as AnalyticsEvent[];

    return this.compute(events, windowDays);
  }
}

export const aggregator = new DashboardAggregator();
