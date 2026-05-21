/**
 * Proactive alert loop orchestrator.
 *
 * After analysis flags a malicious / high-risk package, this fans the verdict
 * out to every affected org: it matches the package against watchlists and
 * scanned lockfiles, resolves each org's delivery channels, and delivers a
 * deduplicated alert. It is the trigger → match → notify chain.
 */

import type { PackageAnalysis } from "@binshield/analysis-types";

import { findAffectedOrgs, type FlaggedPackage } from "./alert-matcher";
import {
  deliverAlert,
  type AlertPayload,
  type NotificationConfig,
  type NotificationTarget
} from "./notification-service";
import { pgSelect } from "./supabase-rest";

const RISK_RANK: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const DEFAULT_MIN_RISK = "high";
const MAX_CONCURRENT_DELIVERIES = 5;

interface NotificationChannelRow {
  channel: "email" | "slack" | "webhook";
  destination: string;
  secret: string | null;
  min_risk_level: string;
}

function riskRank(level: string): number {
  return RISK_RANK[level] ?? 0;
}

async function fetchOrgChannels(
  config: NotificationConfig,
  orgId: string
): Promise<NotificationChannelRow[]> {
  try {
    return await pgSelect<NotificationChannelRow>(
      config,
      `/notification_channels?org_id=eq.${orgId}&enabled=eq.true&select=channel,destination,secret,min_risk_level`
    );
  } catch (error) {
    console.error(
      `[alert-loop] channel lookup failed for org ${orgId}: ${error instanceof Error ? error.message : String(error)}`
    );
    return [];
  }
}

/**
 * Run the alert loop for a freshly analyzed package. Safe to call
 * fire-and-forget — all failures are caught so an alert never blocks a job.
 */
export async function runAlertLoop(
  config: NotificationConfig,
  pkg: FlaggedPackage,
  analysis: PackageAnalysis
): Promise<void> {
  // 1. Risk-threshold gate — below-threshold results never enter the loop.
  const minRisk = (process.env.BINSHIELD_ALERT_MIN_RISK ?? DEFAULT_MIN_RISK).toLowerCase();
  const threshold = RISK_RANK[minRisk] ?? RISK_RANK.high;
  if (riskRank(analysis.riskLevel) < threshold) {
    return;
  }

  // 2. Match the package to affected orgs.
  const affected = await findAffectedOrgs(config, pkg);
  if (affected.length === 0) {
    return;
  }

  const payload: AlertPayload = {
    ecosystem: pkg.ecosystem,
    packageName: pkg.packageName,
    version: pkg.version,
    riskLevel: analysis.riskLevel,
    riskScore: analysis.riskScore,
    binaryCount: analysis.binaryCount,
    summary: analysis.summary
  };

  // 3. Resolve delivery targets.
  const targets: NotificationTarget[] = [];
  const channelCache = new Map<string, NotificationChannelRow[]>();

  for (const org of affected) {
    if (org.matchReason === "watchlist" && org.channel && org.destination) {
      // The matched watchlist carries its own channel.
      targets.push({
        orgId: org.orgId,
        channel: org.channel,
        destination: org.destination,
        matchReason: "watchlist",
        watchlistId: org.watchlistId
      });
      continue;
    }

    if (org.matchReason === "lockfile") {
      let channels = channelCache.get(org.orgId);
      if (!channels) {
        channels = await fetchOrgChannels(config, org.orgId);
        channelCache.set(org.orgId, channels);
      }
      for (const channel of channels) {
        // Honour the channel's minimum-risk preference.
        if (riskRank(analysis.riskLevel) < riskRank(channel.min_risk_level)) {
          continue;
        }
        targets.push({
          orgId: org.orgId,
          channel: channel.channel,
          destination: channel.destination,
          secret: channel.secret ?? undefined,
          matchReason: "lockfile",
          lockfileScanId: org.lockfileScanId
        });
      }
    }
  }

  if (targets.length === 0) {
    return;
  }

  // 4. Deliver, capped for concurrency so a popular package cannot burst
  //    thousands of outbound requests at once.
  let sent = 0;
  let suppressed = 0;
  let failed = 0;

  for (let i = 0; i < targets.length; i += MAX_CONCURRENT_DELIVERIES) {
    const batch = targets.slice(i, i + MAX_CONCURRENT_DELIVERIES);
    const results = await Promise.allSettled(batch.map((target) => deliverAlert(config, target, payload)));
    for (const result of results) {
      if (result.status === "fulfilled") {
        if (result.value.outcome === "sent") {
          sent += 1;
        } else if (result.value.outcome === "suppressed") {
          suppressed += 1;
        } else {
          failed += 1;
        }
      } else {
        failed += 1;
      }
    }
  }

  console.log(
    `[alert-loop] ${pkg.ecosystem}/${pkg.packageName}@${pkg.version}: ` +
      `${sent} sent, ${suppressed} deduped, ${failed} failed across ${targets.length} target(s)`
  );
}
