/**
 * HTML email templates for proactive dependency-confusion and high-confidence
 * typosquat alerts.
 *
 * These templates are used when the closed-loop detection fires independently
 * of the standard risk-scoring pipeline — i.e. for the two new trigger types:
 *   - dependency_confusion
 *   - typosquat_high_confidence
 *
 * Visual style mirrors alert-email.ts (BinShield forensic terminal branding).
 */

import type { ProactiveTriggerKind } from "../alert-matcher";

const LOGO_SVG = `<svg width="28" height="28" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="2" y="2" width="28" height="28" rx="5" stroke="#5ffbbd" stroke-width="1.5"/><rect x="7" y="7" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><rect x="18" y="7" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><rect x="7" y="15" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><rect x="18" y="15" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><circle cx="16" cy="16" r="4" fill="#5ffbbd"/><path d="M16 13v6M13 16h6" stroke="#050d18" stroke-width="1.5" stroke-linecap="round"/><rect x="7" y="23" width="18" height="2" rx="1" fill="#5ffbbd" opacity="0.3"/></svg>`;

interface ProactiveAlertEmailOptions {
  packageName: string;
  version: string;
  ecosystem: string;
  triggerKind: ProactiveTriggerKind;
  reason: string;
  severity: "critical" | "high";
}

function severityColor(severity: "critical" | "high"): string {
  return severity === "critical" ? "#ff4040" : "#ff5c5c";
}

function triggerLabel(kind: ProactiveTriggerKind): string {
  return kind === "dependency_confusion"
    ? "DEPENDENCY CONFUSION ATTACK DETECTED"
    : "HIGH-CONFIDENCE TYPOSQUAT DETECTED";
}

function remediationSteps(kind: ProactiveTriggerKind, packageName: string): string {
  if (kind === "dependency_confusion") {
    return `
      <li>Immediately audit your lockfile for <code>${packageName}</code> and remove it if unexpected.</li>
      <li>Run <code>npm audit signatures</code> to verify package provenance.</li>
      <li>Pin all internal packages using your private registry scope in <code>.npmrc</code>.</li>
      <li>Configure <code>registry</code> scope mapping so <code>${packageName.replace(/\/.*/, "/*")}</code> always resolves from your private registry.</li>
      <li>Consider enabling Subresource Integrity (SRI) or lockfile integrity checks in CI.</li>
    `;
  }
  // typosquat_high_confidence
  return `
    <li>Verify the exact package name you intended to install — check for 1–2 character differences from a popular package.</li>
    <li>Run <code>npm audit signatures</code> to verify package provenance.</li>
    <li>Remove <code>${packageName}</code> from your lockfile if it was installed unintentionally.</li>
    <li>Add a lockfile integrity check to your CI pipeline to catch unexpected new packages.</li>
    <li>Review recent <code>npm install</code> logs for unexpected network calls during installation.</li>
  `;
}

/**
 * Build an HTML email for a proactive dependency-confusion or typosquat alert.
 */
export function buildProactiveAlertEmail(opts: ProactiveAlertEmailOptions): string {
  const { packageName, version, ecosystem, triggerKind, reason, severity } = opts;
  const color = severityColor(severity);
  const label = triggerLabel(triggerKind);
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://binshield.dev";
  const packageUrl = `${appUrl}/packages/${encodeURIComponent(packageName)}?version=${encodeURIComponent(version)}`;
  const remediation = remediationSteps(triggerKind, packageName);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BinShield Proactive Alert: ${packageName}@${version}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #050d18; font-family: 'Segoe UI', Roboto, -apple-system, sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #050d18;">
    <tr>
      <td align="center" style="padding: 48px 16px;">
        <table role="presentation" width="580" cellpadding="0" cellspacing="0" style="max-width: 580px; width: 100%;">

          <!-- Logo + Wordmark -->
          <tr>
            <td style="padding-bottom: 32px;">
              <table role="presentation" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding-right: 12px; vertical-align: middle;">${LOGO_SVG}</td>
                  <td style="vertical-align: middle;">
                    <span style="font-size: 18px; font-weight: 800; color: #e4edf8; letter-spacing: 0.04em; font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;">
                      BINSHIELD
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Alert Card -->
          <tr>
            <td style="background-color: rgba(10, 20, 36, 0.95); border-radius: 16px; padding: 36px; border: 1px solid ${color}33;">

              <!-- Alert kind label -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom: 20px;">
                <tr>
                  <td style="background-color: ${color}15; border: 1px solid ${color}44; border-radius: 999px; padding: 4px 14px;">
                    <span style="color: ${color}; font-size: 11px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; font-family: 'JetBrains Mono', monospace;">
                      ${label}
                    </span>
                  </td>
                </tr>
              </table>

              <!-- Package name -->
              <h1 style="margin: 0 0 8px; font-size: 24px; color: #e4edf8; font-weight: 700; font-family: 'JetBrains Mono', monospace; letter-spacing: -0.02em;">
                ${packageName}<span style="color: #7b93b0;">@</span>${version}
              </h1>
              <p style="margin: 0 0 20px; color: #7b93b0; font-size: 12px; font-family: 'JetBrains Mono', monospace;">
                Ecosystem: ${ecosystem.toUpperCase()}
              </p>

              <!-- Severity badge -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                <tr>
                  <td style="background-color: ${color}15; border: 1px solid ${color}33; border-radius: 10px; padding: 8px 16px;">
                    <span style="color: ${color}; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-family: 'JetBrains Mono', monospace;">
                      ${severity.toUpperCase()} SEVERITY
                    </span>
                  </td>
                </tr>
              </table>

              <!-- Detection reason -->
              <p style="margin: 0 0 20px; color: #b0c4de; font-size: 14px; line-height: 1.7;">
                ${reason.replace(/`([^`]+)`/g, '<code style="background: rgba(95,251,189,0.08); color: #5ffbbd; padding: 1px 5px; border-radius: 4px; font-family: monospace;">$1</code>')}
              </p>

              <!-- Divider -->
              <hr style="border: none; border-top: 1px solid rgba(95,251,189,0.1); margin: 0 0 20px;" />

              <!-- Remediation steps -->
              <p style="margin: 0 0 10px; color: #e4edf8; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; font-family: 'JetBrains Mono', monospace;">
                Recommended Actions
              </p>
              <ul style="margin: 0 0 28px; padding-left: 20px; color: #b0c4de; font-size: 13px; line-height: 1.8;">
                ${remediation}
              </ul>

              <!-- CTA Button -->
              <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td align="center">
                    <a href="${packageUrl}" target="_blank" style="display: inline-block; padding: 14px 32px; background-color: #5ffbbd; color: #050d18; font-size: 14px; font-weight: 700; text-decoration: none; border-radius: 10px; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.02em;">
                      View package analysis
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding-top: 32px; text-align: center;">
              <p style="margin: 0 0 6px; color: #4a5f78; font-size: 12px; line-height: 1.5;">
                You received this alert because your org has proactive watchlist enforcement enabled.
              </p>
              <p style="margin: 0 0 6px; color: #3a4f68; font-size: 11px;">
                <a href="${appUrl}/dashboard/watchlists" style="color: #5ffbbd; text-decoration: none;">Manage watchlists</a>
                &nbsp;&middot;&nbsp;
                <a href="${appUrl}/docs/proactive-alerts" style="color: #5ffbbd; text-decoration: none;">Documentation</a>
                &nbsp;&middot;&nbsp;
                <a href="${appUrl}/privacy" style="color: #5ffbbd; text-decoration: none;">Privacy</a>
              </p>
              <p style="margin: 12px 0 0; color: #2a3f58; font-size: 10px;">
                &copy; ${new Date().getFullYear()} BinShield &middot; Built by Ashlr AI &middot; support@ashlr.ai
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Slack block-kit template
// ---------------------------------------------------------------------------

/**
 * Build a Slack block-kit payload for a proactive dependency-confusion or
 * typosquat alert.  Returns a plain JSON-serialisable object ready to POST to
 * a Slack incoming-webhook URL.
 */
export function buildProactiveSlackPayload(opts: ProactiveAlertEmailOptions): object {
  const { packageName, version, ecosystem, triggerKind, reason, severity } = opts;
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://binshield.dev";
  const packageUrl = `${appUrl}/packages/${encodeURIComponent(packageName)}?version=${encodeURIComponent(version)}`;

  const emoji = severity === "critical" ? ":rotating_light:" : ":warning:";
  const label = triggerKind === "dependency_confusion"
    ? "Dependency Confusion Attack"
    : "High-Confidence Typosquat";

  const remediationText = triggerKind === "dependency_confusion"
    ? "• Run `npm audit signatures` to verify package provenance\n• Pin internal packages via private registry scope in `.npmrc`\n• Remove the package if it was not intentionally installed"
    : "• Verify the exact package name you intended to install\n• Run `npm audit signatures` to verify package provenance\n• Remove the package from your lockfile if unexpected";

  return {
    text: `${emoji} BinShield Proactive Alert: ${label} — \`${packageName}@${version}\``,
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `${emoji} ${label}: ${packageName}@${version}`,
          emoji: true
        }
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Severity:*\n${severity.toUpperCase()}` },
          { type: "mrkdwn", text: `*Ecosystem:*\n${ecosystem.toUpperCase()}` }
        ]
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*Detection reason:*\n${reason}` }
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Recommended actions:*\n${remediationText}`
        }
      },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            style: severity === "critical" ? "danger" : "primary",
            text: { type: "plain_text", text: "View Analysis" },
            url: packageUrl
          }
        ]
      }
    ]
  };
}
