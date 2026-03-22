/**
 * HTML email template for watchlist alert notifications.
 *
 * Uses BinShield's forensic terminal branding:
 * - Dark navy background (#050d18)
 * - Mint accent (#5ffbbd)
 * - JetBrains Mono aesthetic
 * - Inline BinShield shield+grid logo as base64 SVG
 */

const LOGO_SVG = `<svg width="28" height="28" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="2" y="2" width="28" height="28" rx="5" stroke="#5ffbbd" stroke-width="1.5"/><rect x="7" y="7" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><rect x="18" y="7" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><rect x="7" y="15" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><rect x="18" y="15" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5"/><circle cx="16" cy="16" r="4" fill="#5ffbbd"/><path d="M16 13v6M13 16h6" stroke="#050d18" stroke-width="1.5" stroke-linecap="round"/><rect x="7" y="23" width="18" height="2" rx="1" fill="#5ffbbd" opacity="0.3"/></svg>`;

function riskColor(level: string): string {
  switch (level) {
    case "critical": return "#ff4040";
    case "high": return "#ff5c5c";
    case "medium": return "#ffb040";
    case "low": return "#5ffbbd";
    default: return "#7b93b0";
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
  const color = riskColor(riskLevel);
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://binshield.dev";
  const packageUrl = `${appUrl}/packages/${encodeURIComponent(packageName)}?version=${encodeURIComponent(version)}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BinShield Alert: ${packageName}@${version}</title>
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
                  <td style="padding-right: 12px; vertical-align: middle;">
                    ${LOGO_SVG}
                  </td>
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
            <td style="background-color: rgba(10, 20, 36, 0.95); border-radius: 16px; padding: 36px; border: 1px solid rgba(95, 251, 189, 0.12);">

              <!-- Alert label -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom: 20px;">
                <tr>
                  <td style="background-color: rgba(95, 251, 189, 0.08); border: 1px solid rgba(95, 251, 189, 0.2); border-radius: 999px; padding: 4px 14px;">
                    <span style="color: #5ffbbd; font-size: 11px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; font-family: 'JetBrains Mono', monospace;">
                      WATCHLIST ALERT
                    </span>
                  </td>
                </tr>
              </table>

              <!-- Package name -->
              <h1 style="margin: 0 0 20px; font-size: 24px; color: #e4edf8; font-weight: 700; font-family: 'JetBrains Mono', monospace; letter-spacing: -0.02em;">
                ${packageName}<span style="color: #7b93b0;">@</span>${version}
              </h1>

              <!-- Risk badge -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                <tr>
                  <td style="background-color: ${color}15; border: 1px solid ${color}33; border-radius: 10px; padding: 8px 16px;">
                    <span style="color: ${color}; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-family: 'JetBrains Mono', monospace;">
                      ${riskLevel} &mdash; ${riskScore}/100
                    </span>
                  </td>
                </tr>
              </table>

              <!-- Metrics row -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                <tr>
                  <td width="50%" style="padding: 14px 16px; background-color: rgba(5, 13, 24, 0.6); border-radius: 10px; border: 1px solid rgba(95, 251, 189, 0.06);">
                    <span style="display: block; color: #7b93b0; font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; font-family: 'JetBrains Mono', monospace; margin-bottom: 4px;">
                      Binaries
                    </span>
                    <span style="color: #e4edf8; font-size: 20px; font-weight: 700; font-family: 'JetBrains Mono', monospace;">
                      ${binaryCount}
                    </span>
                  </td>
                  <td width="8"></td>
                  <td width="50%" style="padding: 14px 16px; background-color: rgba(5, 13, 24, 0.6); border-radius: 10px; border: 1px solid rgba(95, 251, 189, 0.06);">
                    <span style="display: block; color: #7b93b0; font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; font-family: 'JetBrains Mono', monospace; margin-bottom: 4px;">
                      Risk Score
                    </span>
                    <span style="color: ${color}; font-size: 20px; font-weight: 700; font-family: 'JetBrains Mono', monospace;">
                      ${riskScore}
                    </span>
                  </td>
                </tr>
              </table>

              <!-- Summary -->
              <p style="margin: 0 0 28px; color: #b0c4de; font-size: 14px; line-height: 1.7;">
                ${summary}
              </p>

              <!-- CTA Button -->
              <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td align="center">
                    <a href="${packageUrl}" target="_blank" style="display: inline-block; padding: 14px 32px; background-color: #5ffbbd; color: #050d18; font-size: 14px; font-weight: 700; text-decoration: none; border-radius: 10px; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.02em;">
                      View full analysis
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
                You received this because you're watching <strong style="color: #7b93b0;">${packageName}</strong> on BinShield.
              </p>
              <p style="margin: 0 0 6px; color: #3a4f68; font-size: 11px;">
                <a href="${appUrl}/dashboard/watchlists" style="color: #5ffbbd; text-decoration: none;">Manage watchlists</a>
                &nbsp;&middot;&nbsp;
                <a href="${appUrl}/docs" style="color: #5ffbbd; text-decoration: none;">Documentation</a>
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
