/**
 * HTML email template for watchlist alert notifications.
 *
 * Dark-themed to match BinShield branding.
 */

function riskBadgeColor(riskLevel: string): string {
  switch (riskLevel) {
    case "critical":
      return "#ef4444";
    case "high":
      return "#f97316";
    case "medium":
      return "#eab308";
    case "low":
      return "#22c55e";
    default:
      return "#6b7280";
  }
}

export function buildAlertEmail(
  packageName: string,
  version: string,
  riskLevel: string,
  riskScore: number,
  binaryCount: number,
  summary: string,
): string {
  const badgeColor = riskBadgeColor(riskLevel);
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://binshield.dev";
  const packageUrl = `${appUrl}/packages/${encodeURIComponent(packageName)}?version=${encodeURIComponent(version)}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BinShield Alert: ${packageName}@${version}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0a0a0f; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #0a0a0f;">
    <tr>
      <td align="center" style="padding: 40px 16px;">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width: 560px; width: 100%;">

          <!-- Logo / Header -->
          <tr>
            <td style="padding-bottom: 32px;">
              <span style="font-size: 20px; font-weight: 700; color: #e4e4e7; letter-spacing: -0.02em;">
                BinShield
              </span>
            </td>
          </tr>

          <!-- Card -->
          <tr>
            <td style="background-color: #18181b; border-radius: 12px; padding: 32px; border: 1px solid #27272a;">

              <!-- Title -->
              <p style="margin: 0 0 8px; font-size: 14px; color: #a1a1aa; text-transform: uppercase; letter-spacing: 0.05em;">
                Watchlist Alert
              </p>
              <h1 style="margin: 0 0 24px; font-size: 22px; color: #e4e4e7; font-weight: 600;">
                ${packageName}@${version}
              </h1>

              <!-- Risk Badge -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                <tr>
                  <td style="background-color: ${badgeColor}20; border: 1px solid ${badgeColor}40; border-radius: 6px; padding: 6px 14px;">
                    <span style="color: ${badgeColor}; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">
                      ${riskLevel} &mdash; Score ${riskScore}
                    </span>
                  </td>
                </tr>
              </table>

              <!-- Metrics -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                <tr>
                  <td style="padding: 12px 0; border-top: 1px solid #27272a;">
                    <span style="color: #a1a1aa; font-size: 13px;">Binaries detected</span>
                  </td>
                  <td align="right" style="padding: 12px 0; border-top: 1px solid #27272a;">
                    <span style="color: #e4e4e7; font-size: 14px; font-weight: 600;">${binaryCount}</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px 0; border-top: 1px solid #27272a;">
                    <span style="color: #a1a1aa; font-size: 13px;">Risk level</span>
                  </td>
                  <td align="right" style="padding: 12px 0; border-top: 1px solid #27272a;">
                    <span style="color: ${badgeColor}; font-size: 14px; font-weight: 600;">${riskLevel.toUpperCase()}</span>
                  </td>
                </tr>
              </table>

              <!-- Summary -->
              <p style="margin: 0 0 28px; color: #d4d4d8; font-size: 14px; line-height: 1.6;">
                ${summary}
              </p>

              <!-- CTA Button -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin: 0 auto;">
                <tr>
                  <td style="background-color: #6366f1; border-radius: 8px;">
                    <a href="${packageUrl}" target="_blank" style="display: inline-block; padding: 12px 28px; color: #ffffff; font-size: 14px; font-weight: 600; text-decoration: none;">
                      View analysis on BinShield
                    </a>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding-top: 28px; text-align: center;">
              <p style="margin: 0; color: #52525b; font-size: 12px; line-height: 1.5;">
                You received this because you're watching <strong style="color: #71717a;">${packageName}</strong> on BinShield.
              </p>
              <p style="margin: 8px 0 0; color: #3f3f46; font-size: 11px;">
                &copy; ${new Date().getFullYear()} BinShield &middot; Ashlr AI
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
