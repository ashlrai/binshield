/**
 * Watchlist alert trigger.
 *
 * After an analysis completes, checks if any watchlist entries match the
 * analyzed package and sends alerts via the configured channel (email,
 * Slack, or generic webhook).
 */

import crypto from "node:crypto";

import type { PackageAnalysis, AlertDeliveryStatus, AlertChannel } from "@binshield/analysis-types";
import type { SupabaseWorkerConfig } from "./supabase-store";
import { sendEmail } from "./email";
import { buildAlertEmail } from "./templates/alert-email";

/**
 * Validate that a URL is safe for outbound requests (no SSRF).
 * Allows only https:// URLs to non-private hostnames.
 */
function isValidWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    // Block private/reserved IPs and localhost
    if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0") return false;
    if (host.startsWith("10.") || host.startsWith("192.168.")) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
    if (host === "169.254.169.254" || host.startsWith("169.254.")) return false;
    if (host.endsWith(".internal") || host.endsWith(".local")) return false;
    return true;
  } catch {
    return false;
  }
}

interface WatchlistMatch {
  watchlistId: string;
  channel: AlertChannel;
  destination: string;
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
    channel: AlertChannel;
    destination: string;
  };
}

/**
 * Query Supabase for watchlist entries matching the given package, then send
 * alerts via the appropriate channel and record delivery status.
 *
 * This function is intentionally fire-and-forget safe — all errors are caught
 * and logged rather than thrown, so a failed alert never blocks job completion.
 */
export async function checkAndSendAlerts(
  config: SupabaseWorkerConfig & { sendgridApiKey: string; fromEmail: string },
  packageName: string,
  ecosystem: string,
  version: string,
  analysis: PackageAnalysis,
): Promise<void> {
  const baseUrl = config.supabaseUrl.replace(/\/$/, "");

  const headers: Record<string, string> = {
    apikey: config.supabaseServiceRoleKey,
    authorization: `Bearer ${config.supabaseServiceRoleKey}`,
    "content-type": "application/json",
  };

  try {
    // Query watchlist_packages with a join to watchlists for channel + destination
    const queryPath =
      `/rest/v1/watchlist_packages?package_name=eq.${encodeURIComponent(packageName)}` +
      `&ecosystem=eq.${encodeURIComponent(ecosystem)}` +
      `&select=id,watchlist_id,package_name,ecosystem,watchlists(id,org_id,channel,destination)`;

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

    // Deduplicate by destination so we don't send duplicate alerts
    const matchMap = new Map<string, WatchlistMatch>();
    for (const row of rows) {
      const destination = row.watchlists?.destination;
      if (destination && !matchMap.has(destination)) {
        matchMap.set(destination, {
          watchlistId: row.watchlist_id,
          channel: row.watchlists.channel,
          destination,
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
        let sent = false;

        switch (match.channel) {
          case "email":
            sent = await deliverEmailAlert(config, match.destination, packageName, version, analysis);
            break;
          case "slack":
            sent = await deliverSlackAlert(match.destination, packageName, version, analysis);
            break;
          case "webhook":
            sent = await deliverWebhookAlert(match.destination, packageName, ecosystem, version, analysis);
            break;
          default:
            console.error(`[BinShield Alerts] Unknown channel: ${match.channel}`);
        }

        const deliveryStatus: AlertDeliveryStatus = sent ? "sent" : "failed";

        // Record the alert in the email_alerts table (kept for backwards compatibility)
        await recordAlert(baseUrl, headers, {
          orgId: match.orgId,
          watchlistId: match.watchlistId,
          packageName,
          ecosystem,
          version,
          channel: match.channel,
          destination: match.destination,
          deliveryStatus,
          riskLevel: analysis.riskLevel,
          riskScore: analysis.riskScore,
        });

        return { destination: match.destination, channel: match.channel, sent };
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
// Channel-specific delivery
// ---------------------------------------------------------------------------

async function deliverEmailAlert(
  config: { sendgridApiKey: string; fromEmail: string },
  email: string,
  packageName: string,
  version: string,
  analysis: PackageAnalysis,
): Promise<boolean> {
  if (!config.sendgridApiKey) {
    console.warn("[BinShield Alerts] SENDGRID_API_KEY not configured, skipping email alert");
    return false;
  }

  const subject = `[BinShield] ${analysis.riskLevel.toUpperCase()} risk: ${packageName}@${version}`;
  const html = buildAlertEmail(
    packageName,
    version,
    analysis.riskLevel,
    analysis.riskScore,
    analysis.binaryCount,
    analysis.summary,
  );

  return sendEmail(
    { sendgridApiKey: config.sendgridApiKey, fromEmail: config.fromEmail },
    email,
    subject,
    html,
  );
}

/**
 * Send a Slack notification via incoming webhook URL.
 */
async function deliverSlackAlert(
  webhookUrl: string,
  packageName: string,
  version: string,
  analysis: PackageAnalysis,
): Promise<boolean> {
  if (!isValidWebhookUrl(webhookUrl)) {
    console.error(`[BinShield Alerts] Blocked Slack webhook to unsafe URL: ${webhookUrl}`);
    return false;
  }
  try {
    const riskEmoji = analysis.riskLevel === "critical" || analysis.riskLevel === "high" ? ":rotating_light:" : ":warning:";
    const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://binshield.dev";
    const packageUrl = `${appUrl}/packages/${encodeURIComponent(packageName)}?version=${encodeURIComponent(version)}`;

    const payload = {
      text: `${riskEmoji} BinShield Alert: ${packageName}@${version} — ${analysis.riskLevel.toUpperCase()} risk (${analysis.riskScore}/100)`,
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: `BinShield Alert: ${packageName}@${version}`,
            emoji: true,
          },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Risk Level:*\n${analysis.riskLevel.toUpperCase()}` },
            { type: "mrkdwn", text: `*Risk Score:*\n${analysis.riskScore}/100` },
            { type: "mrkdwn", text: `*Binaries:*\n${analysis.binaryCount}` },
          ],
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: analysis.summary,
          },
        },
        {
          type: "actions",
          elements: [
            {
              type: "button",
              text: { type: "plain_text", text: "View Analysis" },
              url: packageUrl,
            },
          ],
        },
      ],
    };

    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`[BinShield Alerts] Slack webhook failed (${response.status}): ${text}`);
      return false;
    }

    return true;
  } catch (error) {
    console.error(
      `[BinShield Alerts] Slack delivery error: ${error instanceof Error ? error.message : String(error)}`,
    );
    return false;
  }
}

/**
 * Send a generic webhook notification with HMAC-SHA256 signature.
 */
async function deliverWebhookAlert(
  webhookUrl: string,
  packageName: string,
  ecosystem: string,
  version: string,
  analysis: PackageAnalysis,
): Promise<boolean> {
  if (!isValidWebhookUrl(webhookUrl)) {
    console.error(`[BinShield Alerts] Blocked webhook to unsafe URL: ${webhookUrl}`);
    return false;
  }
  try {
    const payload = JSON.stringify({
      event: "analysis.complete",
      timestamp: new Date().toISOString(),
      package: {
        ecosystem,
        name: packageName,
        version,
      },
      risk: {
        level: analysis.riskLevel,
        score: analysis.riskScore,
      },
      binaryCount: analysis.binaryCount,
      summary: analysis.summary,
    });

    // Sign the payload with HMAC-SHA256 using the webhook URL as the key.
    // In production, a per-watchlist secret would be stored; for now we derive
    // a deterministic signature so consumers can verify authenticity.
    const signature = crypto
      .createHmac("sha256", webhookUrl)
      .update(payload)
      .digest("hex");

    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-BinShield-Signature": signature,
        "X-BinShield-Event": "analysis.complete",
      },
      body: payload,
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`[BinShield Alerts] Webhook delivery failed (${response.status}): ${text}`);
      return false;
    }

    return true;
  } catch (error) {
    console.error(
      `[BinShield Alerts] Webhook delivery error: ${error instanceof Error ? error.message : String(error)}`,
    );
    return false;
  }
}

// ---------------------------------------------------------------------------
// Alert recording
// ---------------------------------------------------------------------------

interface AlertInsert {
  orgId: string;
  watchlistId: string;
  packageName: string;
  ecosystem: string;
  version: string;
  channel: AlertChannel;
  destination: string;
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
        channel: alert.channel,
        destination: alert.destination,
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
