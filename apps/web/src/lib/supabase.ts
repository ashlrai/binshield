import { createBrowserClient as createBrowserSupabaseClient } from "@supabase/ssr";
import { createServerClient as createServerSupabaseClient } from "@supabase/ssr";
import { createClient as createSupabaseAdmin } from "@supabase/supabase-js";
import type { CookieOptions } from "@supabase/ssr";
import type { ReadonlyRequestCookies } from "next/dist/server/web/spec-extension/adapters/request-cookies";

function getSupabaseConfig() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) {
    throw new Error("Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY");
  }
  return { url, anonKey };
}

/** Service-role client for server-side admin queries (e.g. looking up org membership). */
export function createServiceRoleClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceRoleKey) {
    throw new Error("Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  }
  return createSupabaseAdmin(url, serviceRoleKey);
}

export interface OrgContext {
  orgId: string;
  orgName: string;
  orgSlug: string;
  role: string;
  apiKey: string | null;
}

/**
 * Look up the authenticated user's organization by querying organization_members,
 * then fetch an active API key for that org to use for authenticated API calls.
 */
export async function getOrgContext(userId: string): Promise<OrgContext | null> {
  const admin = createServiceRoleClient();

  // Find the user's org membership
  const { data: membership } = await admin
    .from("organization_members")
    .select("org_id, role, organizations(id, name, slug)")
    .eq("user_id", userId)
    .limit(1)
    .maybeSingle();

  if (!membership?.org_id) {
    return null;
  }

  const org = membership.organizations as unknown as { id: string; name: string; slug: string } | null;

  // Look up an active (non-revoked) API key for this org so we can call the API
  const { data: keyRow } = await admin
    .from("api_keys")
    .select("prefix, hashed_key")
    .eq("org_id", membership.org_id)
    .is("revoked_at", null)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  return {
    orgId: membership.org_id,
    orgName: org?.name ?? "My Organization",
    orgSlug: org?.slug ?? "my-org",
    role: membership.role ?? "member",
    // Note: we only have the hashed key in the DB, not the raw key.
    // The prefix is stored for display. For API calls we need the raw key,
    // which is only returned at creation time. We'll fall back to null
    // and let the dashboard pages query Supabase directly when no key is available.
    apiKey: null
  };
}

/** Client-side Supabase client (for use in "use client" components). */
export function createBrowserClient() {
  const { url, anonKey } = getSupabaseConfig();
  return createBrowserSupabaseClient(url, anonKey);
}

/** Server-side Supabase client (for use in Server Components, Route Handlers, Server Actions). */
export function createServerClient(cookieStore: ReadonlyRequestCookies) {
  const { url, anonKey } = getSupabaseConfig();
  return createServerSupabaseClient(url, anonKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet: { name: string; value: string; options: CookieOptions }[]) {
        for (const { name, value, options } of cookiesToSet) {
          try {
            cookieStore.set(name, value, options);
          } catch {
            // In Server Components we cannot set cookies — this is expected.
            // The cookie will be set by the middleware or Route Handler instead.
          }
        }
      }
    }
  });
}
