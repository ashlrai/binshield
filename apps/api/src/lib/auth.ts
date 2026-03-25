import crypto from "node:crypto";

import type { Context } from "hono";

import type { AuthPrincipal } from "./types";
import type { BinShieldRepository } from "./repository";
import type { ApiEnv } from "./env";

export function hashApiKey(rawKey: string) {
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

export function extractApiKey(c: Context) {
  const headerKey = c.req.header("x-binshield-api-key");
  if (headerKey) {
    return headerKey.trim();
  }

  const authorization = c.req.header("authorization");
  if (!authorization) {
    return undefined;
  }

  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim();
}

/**
 * Try to resolve a Supabase JWT into an AuthPrincipal by verifying
 * the token with Supabase auth and looking up org membership.
 */
async function resolveJwtPrincipal(token: string, env: ApiEnv): Promise<AuthPrincipal | null> {
  if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
    return null;
  }

  try {
    // Verify the JWT with Supabase's auth.getUser endpoint
    const userRes = await fetch(`${env.supabaseUrl}/auth/v1/user`, {
      headers: {
        Authorization: `Bearer ${token}`,
        apikey: env.supabaseServiceRoleKey,
      },
    });

    if (!userRes.ok) return null;
    const user = (await userRes.json()) as { id?: string; email?: string };
    if (!user.id) return null;

    // Look up the user's org membership via PostgREST
    const membershipRes = await fetch(
      `${env.supabaseUrl}/rest/v1/organization_members?user_id=eq.${user.id}&select=org_id,role&limit=1`,
      {
        headers: {
          apikey: env.supabaseServiceRoleKey,
          Authorization: `Bearer ${env.supabaseServiceRoleKey}`,
        },
      },
    );

    if (!membershipRes.ok) return null;
    const memberships = (await membershipRes.json()) as Array<{ org_id: string; role: string }>;
    if (!memberships.length) return null;

    return {
      apiKeyId: `jwt:${user.id}`,
      orgId: memberships[0].org_id,
      userId: user.id,
      label: user.email ?? "jwt-user",
      scopes: ["*"],
    };
  } catch {
    return null;
  }
}

export async function resolvePrincipal(repo: BinShieldRepository, c: Context, env?: ApiEnv): Promise<AuthPrincipal | null> {
  const token = extractApiKey(c);
  if (!token) {
    return null;
  }

  // First try API key validation
  const principal = await repo.validateApiKey(token);
  if (principal) return principal;

  // Fall back to Supabase JWT validation
  if (env) {
    return resolveJwtPrincipal(token, env);
  }

  return null;
}

export function assertSameOrg(
  principal: AuthPrincipal | null,
  orgId: string
): { status: 401 | 403; message: string } | null {
  if (!principal) {
    return { status: 401, message: "API key required" };
  }

  if (principal.orgId !== orgId) {
    return { status: 403, message: "API key does not have access to this organization" };
  }

  return null;
}
