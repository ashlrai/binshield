/**
 * Alert matcher.
 *
 * Given a package that analysis flagged as malicious / high-risk, find every
 * org that should be warned: orgs watching the package, and orgs whose scanned
 * lockfiles contain it (including transitively, via `lockfile_dependencies`).
 *
 * Additionally provides closed-loop detection for two supply-chain attack
 * patterns that operate independently of the general risk-scoring pipeline:
 *
 *   dependency_confusion   — a package matches an org's internal naming pattern
 *                            (e.g. `@acme/.*`) but was resolved from public npm
 *                            rather than from the org's trusted scopes/registry.
 *
 *   typosquat_high_confidence — the typosquat engine scored the package above
 *                            0.8 confidence (edit-distance-1, scope-strip, or
 *                            separator/visual-substitution tricks).
 */

import type { SupabaseWorkerConfig } from "./supabase-store";
import { pgSelect } from "./supabase-rest";

export type AlertChannelKind = "email" | "slack" | "webhook";

/** The two new proactive trigger types added in this milestone. */
export type ProactiveTriggerKind = "dependency_confusion" | "typosquat_high_confidence";

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

/**
 * Result of a proactive confusion/typosquat check against one watchlist.
 * The trigger kind determines the alert severity and notification template.
 */
export interface ProactiveAlertMatch {
  orgId: string;
  watchlistId: string;
  channel: AlertChannelKind;
  destination: string;
  triggerKind: ProactiveTriggerKind;
  /** Human-readable description of why the rule fired. */
  reason: string;
  /** Always "critical" for dependency_confusion, "high" for typosquat_high_confidence. */
  severity: "critical" | "high";
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

/** Watchlist row with the new proactive-enforcement columns. */
interface WatchlistRow {
  id: string;
  org_id: string;
  channel: AlertChannelKind;
  destination: string;
  internal_package_pattern: string | null;
  trusted_domains: string[] | null;
}

// ---------------------------------------------------------------------------
// Typosquat confidence score
// ---------------------------------------------------------------------------

/**
 * Map a typosquat `trick` string (from typosquat.ts TyposquatMatch) to a
 * confidence score in [0, 1].  Tricks that require almost no creativity to
 * execute (scope-strip, separator) or are very close (edit-distance-1) score
 * highest.
 */
export function typosquatTrickScore(trick: string): number {
  switch (trick) {
    case "scope-strip":           return 0.95;
    case "separator-variation":   return 0.90;
    case "visual-substitution":   return 0.85;
    case "edit-distance-1":       return 0.85;
    case "edit-distance-2":       return 0.65;
    default:                      return 0.50;
  }
}

// ---------------------------------------------------------------------------
// Dependency-confusion detection
// ---------------------------------------------------------------------------

/**
 * Check whether `packageName` matches the watchlist's `internalPackagePattern`
 * but is NOT coming from one of the watchlist's `trustedDomains` (npm scopes
 * or registry hostnames the org controls).
 *
 * A match means the package appears to be an org-internal name that was
 * resolved from public npm — a classic dependency-confusion attack vector.
 *
 * @param packageName   The scanned package name (e.g. `@acme/payments`).
 * @param resolvedFrom  Optional registry/scope the package came from.
 * @param watchlist     The watchlist row with the org's policy.
 * @returns `true` when a confusion hit is detected.
 */
export function isDependencyConfusion(
  packageName: string,
  resolvedFrom: string | undefined,
  watchlist: { internalPackagePattern?: string | null; trustedDomains?: string[] | null }
): boolean {
  const pattern = watchlist.internalPackagePattern;
  if (!pattern) {
    return false;
  }

  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch {
    // Malformed pattern stored in DB — skip rather than throw.
    return false;
  }

  if (!re.test(packageName)) {
    return false;
  }

  // The package matches the internal naming pattern. If we don't know where it
  // came from, assume it's a confusion hit (worst-case / safe default).
  if (!resolvedFrom) {
    return true;
  }

  const trusted = watchlist.trustedDomains ?? [];

  // A package is safe if at least one trusted domain matches the source.
  // We extract the hostname from URL-style sources so that a trusted domain
  // of "@acme" does NOT accidentally match the package-name segment inside a
  // full npm registry URL like:
  //   https://registry.npmjs.org/@acme/pkg/-/pkg-1.0.0.tgz
  const srcLower = resolvedFrom.toLowerCase();

  // If it looks like a URL, compare only against the hostname.
  let srcHostname: string | null = null;
  try {
    const url = new URL(resolvedFrom);
    srcHostname = url.hostname.toLowerCase();
  } catch {
    // Not a URL — fall through to raw string comparison.
  }

  const isTrusted = trusted.some((domain) => {
    const d = domain.toLowerCase();
    if (d.startsWith("@")) {
      // Scope match: the source must be exactly the scope, or start with
      // "<scope>/" — never matched against a URL path component.
      return srcLower === d || srcLower.startsWith(d + "/");
    }
    // Hostname / registry match: compare against the extracted hostname when
    // available, otherwise fall back to prefix/exact match on the raw string.
    if (srcHostname !== null) {
      return srcHostname === d || srcHostname.endsWith("." + d);
    }
    return srcLower === d || srcLower.startsWith(d + "/") || srcLower.endsWith("." + d);
  });

  return !isTrusted;
}

// ---------------------------------------------------------------------------
// Proactive watchlist scan (new closed-loop entry-point)
// ---------------------------------------------------------------------------

/**
 * Scan all org watchlists that have an `internalPackagePattern` configured and
 * check every supplied `scannedPackages` entry for:
 *
 *   1. dependency_confusion — package name matches pattern but is NOT from a
 *      trusted source.
 *   2. typosquat_high_confidence — typosquat score > 0.8.
 *
 * Returns one `ProactiveAlertMatch` per (watchlist × package × trigger) that
 * fired, ready to be fed into the notification pipeline.
 *
 * This function is intentionally pure (no DB writes) so callers decide how to
 * batch / deduplicate deliveries.
 */
export async function findProactiveAlerts(
  config: SupabaseWorkerConfig,
  scannedPackages: Array<{
    packageName: string;
    version: string;
    ecosystem: string;
    resolvedFrom?: string;
    typosquatTrick?: string;
  }>
): Promise<ProactiveAlertMatch[]> {
  const matches: ProactiveAlertMatch[] = [];

  // Load watchlists that have proactive enforcement configured.
  let watchlists: WatchlistRow[] = [];
  try {
    watchlists = await pgSelect<WatchlistRow>(
      config,
      "/watchlists?internal_package_pattern=not.is.null" +
        "&select=id,org_id,channel,destination,internal_package_pattern,trusted_domains"
    );
  } catch (error) {
    console.error(
      `[alert-matcher] proactive watchlist fetch failed: ${error instanceof Error ? error.message : String(error)}`
    );
    return [];
  }

  if (watchlists.length === 0) {
    return [];
  }

  const seen = new Set<string>();

  for (const pkg of scannedPackages) {
    for (const wl of watchlists) {
      // --- 1. Dependency confusion ---
      if (
        isDependencyConfusion(pkg.packageName, pkg.resolvedFrom, {
          internalPackagePattern: wl.internal_package_pattern,
          trustedDomains: wl.trusted_domains
        })
      ) {
        const dedupeKey = `confusion:${wl.id}:${pkg.packageName}@${pkg.version}`;
        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);
          matches.push({
            orgId: wl.org_id,
            watchlistId: wl.id,
            channel: wl.channel,
            destination: wl.destination,
            triggerKind: "dependency_confusion",
            reason:
              `Package \`${pkg.packageName}@${pkg.version}\` matches the org's internal naming ` +
              `pattern \`${wl.internal_package_pattern}\` but was resolved from public npm ` +
              (pkg.resolvedFrom ? `(\`${pkg.resolvedFrom}\`)` : "(unknown registry)") +
              ` rather than a trusted source. This may be a dependency confusion attack.`,
            severity: "critical"
          });
        }
      }

      // --- 2. High-confidence typosquat ---
      if (pkg.typosquatTrick) {
        const score = typosquatTrickScore(pkg.typosquatTrick);
        if (score > 0.8) {
          const dedupeKey = `typosquat:${wl.id}:${pkg.packageName}@${pkg.version}`;
          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);
            matches.push({
              orgId: wl.org_id,
              watchlistId: wl.id,
              channel: wl.channel,
              destination: wl.destination,
              triggerKind: "typosquat_high_confidence",
              reason:
                `Package \`${pkg.packageName}@${pkg.version}\` is a high-confidence typosquat ` +
                `(trick: \`${pkg.typosquatTrick}\`, confidence: ${(score * 100).toFixed(0)}%). ` +
                `It closely resembles a popular package and may be malicious.`,
              severity: "high"
            });
          }
        }
      }
    }
  }

  return matches;
}

// ---------------------------------------------------------------------------
// Original findAffectedOrgs (unchanged — existing alert loop uses this)
// ---------------------------------------------------------------------------

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
