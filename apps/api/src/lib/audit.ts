/**
 * Lightweight audit logger for BinShield.
 *
 * Records actions to the `audit_log` table in Supabase. Fire-and-forget safe —
 * all errors are caught and logged rather than thrown, so a failed audit entry
 * never blocks request processing.
 *
 * Table schema: id, org_id, user_id, action, resource_type, resource_id,
 *               metadata (jsonb), created_at
 */

export async function logAudit(
  config: { supabaseUrl: string; supabaseServiceRoleKey: string },
  orgId: string,
  action: string,
  resourceType: string,
  resourceId?: string,
  userId?: string,
  metadata?: Record<string, unknown>
): Promise<void> {
  if (!config.supabaseUrl || !config.supabaseServiceRoleKey) {
    return;
  }

  const baseUrl = config.supabaseUrl.replace(/\/$/, "");

  try {
    const response = await fetch(`${baseUrl}/rest/v1/audit_log`, {
      method: "POST",
      headers: {
        apikey: config.supabaseServiceRoleKey,
        authorization: `Bearer ${config.supabaseServiceRoleKey}`,
        "content-type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        org_id: orgId,
        user_id: userId ?? null,
        action,
        resource_type: resourceType,
        resource_id: resourceId ?? null,
        metadata: metadata ?? null,
        created_at: new Date().toISOString(),
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(
        `[BinShield Audit] Failed to insert audit log (${response.status}): ${text}`
      );
    }
  } catch (error) {
    console.error(
      `[BinShield Audit] Unexpected error: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
