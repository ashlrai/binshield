import { createBrowserClient as createBrowserSupabaseClient } from "@supabase/ssr";
import { createServerClient as createServerSupabaseClient } from "@supabase/ssr";
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
