/**
 * Email sender using the SendGrid API.
 *
 * Uses native fetch — no SDKs required.
 * Consistent with AshlrAI email infrastructure (Koala, Probe).
 */

const SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send";

export interface EmailConfig {
  sendgridApiKey: string;
  fromEmail: string;
}

/**
 * Send an email via the SendGrid API.
 *
 * Returns `true` on success (2xx), `false` on any failure.
 * Failures are logged but never thrown — callers should treat
 * email delivery as best-effort.
 */
export async function sendEmail(
  config: EmailConfig,
  to: string,
  subject: string,
  html: string,
): Promise<boolean> {
  if (!config.sendgridApiKey) {
    console.warn("[BinShield Email] SENDGRID_API_KEY is not configured, skipping email");
    return false;
  }

  try {
    const response = await fetch(SENDGRID_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.sendgridApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: config.fromEmail, name: "BinShield" },
        subject,
        content: [{ type: "text/html", value: html }],
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      console.error(
        `[BinShield Email] SendGrid API error (${response.status}): ${body}`,
      );
      return false;
    }

    return true;
  } catch (error) {
    console.error(
      `[BinShield Email] Failed to send email: ${error instanceof Error ? error.message : String(error)}`,
    );
    return false;
  }
}
