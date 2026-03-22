/**
 * Email sender using the Resend API.
 *
 * Uses native fetch — no SDKs required.
 */

const RESEND_API_URL = "https://api.resend.com/emails";

export interface EmailConfig {
  resendApiKey: string;
  fromEmail: string;
}

/**
 * Send an email via the Resend API.
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
  if (!config.resendApiKey) {
    console.warn("[BinShield Email] RESEND_API_KEY is not configured, skipping email");
    return false;
  }

  try {
    const response = await fetch(RESEND_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: config.fromEmail,
        to,
        subject,
        html,
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      console.error(
        `[BinShield Email] Resend API error (${response.status}): ${body}`,
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
