/**
 * Minimal PostgREST helpers for the worker's alert-loop modules.
 *
 * Mirrors the request pattern in `supabase-store.ts` but as free functions so
 * the alert matcher / notification service / lockfile scanner can share it.
 * All calls use the service-role key and therefore bypass RLS.
 */

import type { SupabaseWorkerConfig } from "./supabase-store";

function restUrl(config: SupabaseWorkerConfig, path: string): string {
  return `${config.supabaseUrl.replace(/\/$/, "")}/rest/v1${path}`;
}

function restHeaders(config: SupabaseWorkerConfig, extra: Record<string, string> = {}): Record<string, string> {
  return {
    apikey: config.supabaseServiceRoleKey,
    authorization: `Bearer ${config.supabaseServiceRoleKey}`,
    "content-type": "application/json",
    ...extra
  };
}

export async function pgSelect<T>(config: SupabaseWorkerConfig, path: string): Promise<T[]> {
  const response = await fetch(restUrl(config, path), { headers: restHeaders(config) });
  if (!response.ok) {
    throw new Error(`Supabase select failed (${response.status}): ${await response.text()}`);
  }
  const text = await response.text();
  return text ? (JSON.parse(text) as T[]) : [];
}

/**
 * Insert rows. Returns the representation of the rows actually inserted — with
 * `Prefer: resolution=ignore-duplicates` a conflicting row yields an empty
 * array, which the alert ledger relies on for dedup.
 */
export async function pgInsert<T>(
  config: SupabaseWorkerConfig,
  path: string,
  body: unknown,
  prefer = "return=representation"
): Promise<T[]> {
  const response = await fetch(restUrl(config, path), {
    method: "POST",
    headers: restHeaders(config, { Prefer: prefer }),
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw new Error(`Supabase insert failed (${response.status}): ${await response.text()}`);
  }
  if (response.status === 204) {
    return [];
  }
  const text = await response.text();
  return text ? (JSON.parse(text) as T[]) : [];
}

export async function pgUpdate(config: SupabaseWorkerConfig, path: string, body: unknown): Promise<void> {
  const response = await fetch(restUrl(config, path), {
    method: "PATCH",
    headers: restHeaders(config, { Prefer: "return=minimal" }),
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw new Error(`Supabase update failed (${response.status}): ${await response.text()}`);
  }
}

export async function pgDelete(config: SupabaseWorkerConfig, path: string): Promise<void> {
  const response = await fetch(restUrl(config, path), {
    method: "DELETE",
    headers: restHeaders(config, { Prefer: "return=minimal" })
  });
  if (!response.ok) {
    throw new Error(`Supabase delete failed (${response.status}): ${await response.text()}`);
  }
}
