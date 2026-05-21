/**
 * Alert matcher.
 *
 * Given a package that analysis flagged as malicious / high-risk, find every
 * org that should be warned: orgs watching the package, and orgs whose scanned
 * lockfiles contain it (including transitively, via `lockfile_dependencies`).
 */

import type { SupabaseWorkerConfig } from "./supabase-store";
import { pgSelect } from "./supabase-rest";

export type AlertChannelKind = "email" | "slack" | "webhook";

export interface FlaggedPackage {
  ecosystem: string;
  packageName: string;
  version: string;
}

export interface AffectedOrg {
  orgId: string;
  matchReason: "watchlist" | "lockfile";
  watchlistId?: string;
  lockfileScanId?: string;
  /** Channel carried directly by a matched watchlist (legacy per-watchlist channel). */
  channel?: AlertChannelKind;
  destination?: string;
}

interface WatchlistPackageRow {
  watchlist_id: string;
  version: string | null;
  watchlists: {
    org_id: string;
    channel: AlertChannelKind;
    destination: string;
  } | null;
}

interface LockfileDependencyRow {
  org_id: string;
  lockfile_scan_id: string | null;
}

/**
 * Resolve the orgs affected by a flagged package. Watchlist matches carry the
 * watchlist's own delivery channel; lockfile matches are resolved against the
 * org's `notification_channels` later by the alert loop.
 */
export async function findAffectedOrgs(
  config: SupabaseWorkerConfig,
  pkg: FlaggedPackage
): Promise<AffectedOrg[]> {
  const ecosystem = encodeURIComponent(pkg.ecosystem);
  const name = encodeURIComponent(pkg.packageName);
  const affected: AffectedOrg[] = [];

  // 1. Watchlist matches — a watchlist entry with no version watches all
  //    versions; a versioned entry matches only the exact version.
  try {
    const watchRows = await pgSelect<WatchlistPackageRow>(
      config,
      `/watchlist_packages?package_name=eq.${name}&ecosystem=eq.${ecosystem}` +
        `&select=watchlist_id,version,watchlists(org_id,channel,destination)`
    );
    const seenWatch = new Set<string>();
    for (const row of watchRows) {
      if (row.version && row.version !== pkg.version) {
        continue;
      }
      const watchlist = row.watchlists;
      if (!watchlist?.org_id) {
        continue;
      }
      const key = `${watchlist.org_id}:${row.watchlist_id}`;
      if (seenWatch.has(key)) {
        continue;
      }
      seenWatch.add(key);
      affected.push({
        orgId: watchlist.org_id,
        matchReason: "watchlist",
        watchlistId: row.watchlist_id,
        channel: watchlist.channel,
        destination: watchlist.destination
      });
    }
  } catch (error) {
    console.error(`[alert-matcher] watchlist lookup failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  // 2. Lockfile matches — the org has this dependency in a scanned lockfile.
  try {
    const depRows = await pgSelect<LockfileDependencyRow>(
      config,
      `/lockfile_dependencies?package_name=eq.${name}&ecosystem=eq.${ecosystem}&select=org_id,lockfile_scan_id`
    );
    const seenOrgs = new Set<string>();
    for (const row of depRows) {
      if (seenOrgs.has(row.org_id)) {
        continue;
      }
      seenOrgs.add(row.org_id);
      affected.push({
        orgId: row.org_id,
        matchReason: "lockfile",
        lockfileScanId: row.lockfile_scan_id ?? undefined
      });
    }
  } catch (error) {
    console.error(`[alert-matcher] lockfile lookup failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return affected;
}
