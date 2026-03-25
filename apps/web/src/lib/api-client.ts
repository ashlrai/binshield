"use client";

import { createBrowserClient } from "./supabase";

const API_BASE =
  process.env.NEXT_PUBLIC_BINSHIELD_API_BASE_URL ?? "";

/**
 * Client-side fetch wrapper that attaches the Supabase access token
 * as an Authorization header for authenticated API calls.
 */
export async function apiFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  try {
    const supabase = createBrowserClient();
    const {
      data: { session },
    } = await supabase.auth.getSession();
    if (session?.access_token) {
      headers.set("Authorization", `Bearer ${session.access_token}`);
    }
  } catch {
    // Auth not available — proceed without token
  }

  const base = API_BASE.replace(/\/+$/, "");
  return fetch(`${base}${path}`, { ...init, headers });
}

/** Returns the configured API base URL (empty string if not set). */
export function getApiBase(): string {
  return API_BASE;
}
