/**
 * Notification service.
 *
 * Delivers a single alert to one channel (email / Slack / webhook) and records
 * it in the `alerts` ledger. The ledger's unique index is the dedup key: an
 * idempotent insert that returns no row means the org was already alerted for
 * this package@version on this channel, so delivery is skipped.
 */

import crypto from "node:crypto";

import type { SupabaseWorkerConfig } from "./supabase-store";
import { pgInsert, pgUpdate } from "./supabase-rest";
import { sendEmail } from "./email";
import { buildAlertEmail } from "./templates/alert-email";
import type { AlertChannelKind } from "./alert-matcher";

export type NotificationConfig = SupabaseWorkerConfig & {
  sendgridApiKey: string;
  fromEmail: string;
};

export interface AlertPayload {
  ecosystem: string;
  packageName: string;
  version: string;
  riskLevel: string;
  riskScore: number;
  binaryCount: number;
  summary: string;
}

export interface NotificationTarget {
  orgId: string;
  channel: AlertChannelKind;
  destination: string;
  /** HMAC secret for webhook channels. */
  secret?: string;
  matchReason: "watchlist" | "lockfile";
  watchlistId?: string;
  lockfileScanId?: string;
}

export type AlertOutcome = "sent" | "failed" | "suppressed";

interface InsertedAlertRow {
  id: string;
}

/**
 * Validate that a URL is safe for outbound requests (SSRF guard).
 * Allows only https:// URLs to non-private hostnames.
 */
export function isValidWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0") {
      return false;
    }
    if (host.startsWith("10.") || host.startsWith("192.168.")) {
      return false;
    }
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) {
      return false;
    }
    if (host.startsWith("169.254.")) {
      return false;
    }
    if (host.endsWith(".internal") || host.endsWith(".local")) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Deliver one alert. Idempotent: a duplicate (org, package@version, channel,
 * destination) is recorded once and never re-sent.
 */
export async function deliverAlert(
  config: NotificationConfig,
  target: NotificationTarget,
  payload: AlertPayload
): Promise<{ outcome: AlertOutcome; alertId: string | null }> {
  // Idempotent insert — `ignore-duplicates` returns [] when the alert already exists.
  let inserted: InsertedAlertRow[];
  try {
    inserted = await pgInsert<InsertedAlertRow>(
      config,
      "/alerts?on_conflict=org_id,ecosystem,package_name,version,channel,destination&select=id",
      {
        org_id: target.orgId,
        ecosystem: payload.ecosystem,
        package_name: payload.packageName,
        version: payload.version,
        risk_level: payload.riskLevel,
        risk_score: payload.riskScore,
        match_reason: target.matchReason,
        watchlist_id: target.watchlistId ?? null,
        lockfile_scan_id: target.lockfileScanId ?? null,
        channel: target.channel,
        destination: target.destination,
        status: "pending",
        payload
      },
      "resolution=ignore-duplicates,return=representation"
    );
  } catch (error) {
    console.error(`[notification] failed to record alert: ${error instanceof Error ? error.message : String(error)}`);
    return { outcome: "failed", alertId: null };
  }

  if (inserted.length === 0) {
    // Already alerted for this package@version on this channel — skip.
    return { outcome: "suppressed", alertId: null };
  }

  const alertId = inserted[0].id;
  let error: string | undefined;
  let ok = false;

  try {
    ok = await sendToChannel(config, target, payload);
  } catch (sendError) {
    error = sendError instanceof Error ? sendError.message : String(sendError);
  }

  try {
    await pgUpdate(config, `/alerts?id=eq.${alertId}`, {
      status: ok ? "sent" : "failed",
      error: error ?? null,
      delivered_at: ok ? new Date().toISOString() : null
    });
  } catch (updateError) {
    console.error(
      `[notification] failed to update alert status: ${
        updateError instanceof Error ? updateError.message : String(updateError)
      }`
    );
  }

  return { outcome: ok ? "sent" : "failed", alertId };
}

// ---------------------------------------------------------------------------
// Channel delivery
// ---------------------------------------------------------------------------

async function sendToChannel(
  config: NotificationConfig,
  target: NotificationTarget,
  payload: AlertPayload
): Promise<boolean> {
  switch (target.channel) {
    case "email":
      return sendEmailAlert(config, target.destination, payload);
    case "slack":
      return sendSlackAlert(target.destination, payload);
    case "webhook":
      return sendWebhookAlert(target.destination, target.secret, payload);
    default:
      console.error(`[notification] unknown channel: ${target.channel as string}`);
      return false;
  }
}

async function sendEmailAlert(
  config: NotificationConfig,
  email: string,
  payload: AlertPayload
): Promise<boolean> {
  if (!config.sendgridApiKey) {
    console.warn("[notification] SENDGRID_API_KEY not configured — skipping email alert");
    return false;
  }
  const subject = `[BinShield] ${payload.riskLevel.toUpperCase()} risk: ${payload.packageName}@${payload.version}`;
  const html = buildAlertEmail(
    payload.packageName,
    payload.version,
    payload.riskLevel,
    payload.riskScore,
    payload.binaryCount,
    payload.summary
  );
  return sendEmail({ sendgridApiKey: config.sendgridApiKey, fromEmail: config.fromEmail }, email, subject, html);
}

function packageUrl(payload: AlertPayload): string {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://binshield.dev";
  return `${appUrl}/packages/${encodeURIComponent(payload.packageName)}?version=${encodeURIComponent(payload.version)}`;
}

async function sendSlackAlert(webhookUrl: string, payload: AlertPayload): Promise<boolean> {
  if (!isValidWebhookUrl(webhookUrl)) {
    console.error("[notification] blocked Slack webhook to unsafe URL");
    return false;
  }
  const isHigh = payload.riskLevel === "critical" || payload.riskLevel === "high";
  const body = {
    text: `${isHigh ? ":rotating_light:" : ":warning:"} BinShield Alert: ${payload.packageName}@${payload.version} — ${payload.riskLevel.toUpperCase()} risk (${payload.riskScore}/100)`,
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `BinShield Alert: ${payload.packageName}@${payload.version}`, emoji: true }
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Risk:*\n${payload.riskLevel.toUpperCase()} (${payload.riskScore}/100)` },
          { type: "mrkdwn", text: `*Ecosystem:*\n${payload.ecosystem}` }
        ]
      },
      { type: "section", text: { type: "mrkdwn", text: payload.summary } },
      {
        type: "actions",
        elements: [{ type: "button", text: { type: "plain_text", text: "View Analysis" }, url: packageUrl(payload) }]
      }
    ]
  };

  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  return response.ok;
}

async function sendWebhookAlert(
  webhookUrl: string,
  secret: string | undefined,
  payload: AlertPayload
): Promise<boolean> {
  if (!isValidWebhookUrl(webhookUrl)) {
    console.error("[notification] blocked webhook to unsafe URL");
    return false;
  }
  const body = JSON.stringify({
    event: "package.flagged",
    timestamp: new Date().toISOString(),
    package: { ecosystem: payload.ecosystem, name: payload.packageName, version: payload.version },
    risk: { level: payload.riskLevel, score: payload.riskScore },
    summary: payload.summary,
    url: packageUrl(payload)
  });

  // Sign with the channel's stored secret so consumers can verify authenticity.
  const signature = crypto.createHmac("sha256", secret ?? webhookUrl).update(body).digest("hex");

  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-BinShield-Event": "package.flagged",
      "X-BinShield-Signature": `sha256=${signature}`
    },
    body
  });
  return response.ok;
}
