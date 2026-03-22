/**
 * Watchlist alert trigger.
 *
 * After an analysis completes, checks if any watchlist entries match the
 * analyzed package and sends email alerts to the watchlist owners.
 */

import type { PackageAnalysis, Ecosystem, AlertDeliveryStatus } from "@binshield/analysis-types";
import type { SupabaseWorkerConfig } from "./supabase-store";
import { sendEmail } from "./email";
import { buildAlertEmail } from "./templates/alert-email";

interface WatchlistMatch {
  watchlistId: string;
  email: string;
  orgId: string;
}

interface WatchlistPackageRow {
  id: string;
  watchlist_id: string;
  package_name: string;
  ecosystem: string;
  watchlists: {
    id: string;
    org_id: string;
    email: string;
  };
}

/**
 * Query Supabase for watchlist entries matching the given package, then send
 * email alerts and record delivery status.
 *
 * This function is intentionally fire-and-forget safe — all errors are caught
 * and logged rather than thrown, so a failed alert never blocks job completion.
 */
export async function checkAndSendAlerts(
  config: SupabaseWorkerConfig & { resendApiKey: string; fromEmail: string },
  packageName: string,
  ecosystem: string,
  version: string,
  analysis: PackageAnalysis,
): Promise<void> {
  if (!config.resendApiKey) {
    return;
  }

  const baseUrl = config.supabaseUrl.replace(/\/$/, "");

  const headers: Record<string, string> = {
    apikey: config.supabaseServiceRoleKey,
    authorization: `Bearer ${config.supabaseServiceRoleKey}`,
    "content-type": "application/json",
  };

  try {
    // Query watchlist_packages with a join to watchlists for the destination email
    const queryPath =
      `/rest/v1/watchlist_packages?package_name=eq.${encodeURIComponent(packageName)}` +
      `&ecosystem=eq.${encodeURIComponent(ecosystem)}` +
      `&select=id,watchlist_id,package_name,ecosystem,watchlists(id,org_id,email)`;

    const response = await fetch(`${baseUrl}${queryPath}`, {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`[BinShield Alerts] Failed to query watchlist_packages (${response.status}): ${text}`);
      return;
    }

    const rows = (await response.json()) as WatchlistPackageRow[];

    if (rows.length === 0) {
      return;
    }

    // Deduplicate by email so we don't send duplicate alerts
    const matchMap = new Map<string, WatchlistMatch>();
    for (const row of rows) {
      const email = row.watchlists?.email;
      if (email && !matchMap.has(email)) {
        matchMap.set(email, {
          watchlistId: row.watchlist_id,
          email,
          orgId: row.watchlists.org_id,
        });
      }
    }

    const matches = Array.from(matchMap.values());

    console.log(
      `[BinShield Alerts] ${matches.length} watchlist match(es) for ${ecosystem}/${packageName}@${version}`,
    );

    // Send alerts in parallel
    const results = await Promise.allSettled(
      matches.map(async (match) => {
        const subject = `[BinShield] ${analysis.riskLevel.toUpperCase()} risk: ${packageName}@${version}`;
        const html = buildAlertEmail(
          packageName,
          version,
          analysis.riskLevel,
          analysis.riskScore,
          analysis.binaryCount,
          analysis.summary,
        );

        const sent = await sendEmail(
          { resendApiKey: config.resendApiKey, fromEmail: config.fromEmail },
          match.email,
          subject,
          html,
        );

        const deliveryStatus: AlertDeliveryStatus = sent ? "sent" : "failed";

        // Record the alert in the email_alerts table
        await recordAlert(baseUrl, headers, {
          orgId: match.orgId,
          watchlistId: match.watchlistId,
          packageName,
          ecosystem,
          version,
          email: match.email,
          deliveryStatus,
          riskLevel: analysis.riskLevel,
          riskScore: analysis.riskScore,
        });

        return { email: match.email, sent };
      }),
    );

    for (const result of results) {
      if (result.status === "rejected") {
        console.error(`[BinShield Alerts] Alert delivery failed: ${result.reason}`);
      }
    }
  } catch (error) {
    console.error(
      `[BinShield Alerts] Unexpected error: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface AlertInsert {
  orgId: string;
  watchlistId: string;
  packageName: string;
  ecosystem: string;
  version: string;
  email: string;
  deliveryStatus: AlertDeliveryStatus;
  riskLevel: string;
  riskScore: number;
}

async function recordAlert(
  baseUrl: string,
  headers: Record<string, string>,
  alert: AlertInsert,
): Promise<void> {
  try {
    const response = await fetch(`${baseUrl}/rest/v1/email_alerts`, {
      method: "POST",
      headers: { ...headers, Prefer: "return=minimal" },
      body: JSON.stringify({
        org_id: alert.orgId,
        watchlist_id: alert.watchlistId,
        package_name: alert.packageName,
        ecosystem: alert.ecosystem,
        version: alert.version,
        email: alert.email,
        delivery_status: alert.deliveryStatus,
        risk_level: alert.riskLevel,
        risk_score: alert.riskScore,
        sent_at: new Date().toISOString(),
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`[BinShield Alerts] Failed to insert email_alerts row (${response.status}): ${text}`);
    }
  } catch (error) {
    console.error(
      `[BinShield Alerts] Failed to record alert: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
