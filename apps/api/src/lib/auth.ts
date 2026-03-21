import crypto from "node:crypto";

import type { Context } from "hono";

import type { AuthPrincipal } from "./types";
import type { BinShieldRepository } from "./repository";

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

export async function resolvePrincipal(repo: BinShieldRepository, c: Context): Promise<AuthPrincipal | null> {
  const apiKey = extractApiKey(c);
  if (!apiKey) {
    return null;
  }

  return repo.validateApiKey(apiKey);
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
