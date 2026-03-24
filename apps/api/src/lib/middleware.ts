/**
 * Hono middleware for entitlement enforcement and usage tracking.
 *
 * These middleware functions sit between auth resolution (already done in app.ts)
 * and route handlers, enforcing plan-based access control and quota limits.
 */

import type { MiddlewareHandler } from "hono";

import type { PlanName } from "@binshield/analysis-types";
import { entitlementForPlan } from "@binshield/analysis-types";

import { checkEntitlement, checkScanQuota, checkRepoQuota, PLAN_RANK } from "./entitlements";
import type { AuthPrincipal } from "./types";
import type { BinShieldRepository } from "./repository";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getOrgPlan(repository: BinShieldRepository, orgId: string): Promise<PlanName> {
  const org = await repository.getOrganization(orgId);
  return (org?.plan as PlanName) ?? "free";
}

// ---------------------------------------------------------------------------
// Middleware factories
// ---------------------------------------------------------------------------

/**
 * Require the authenticated org to be on at least the given plan tier.
 */
export function requirePlan(minPlan: PlanName): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get("auth") as AuthPrincipal | null;
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const repository = c.get("services").repository as BinShieldRepository;
    const plan = await getOrgPlan(repository, auth.orgId);

    if (PLAN_RANK[plan] < PLAN_RANK[minPlan]) {
      return c.json(
        {
          error: `This endpoint requires the ${minPlan} plan or higher`,
          currentPlan: plan,
          requiredPlan: minPlan,
          upgradeUrl: "/billing/checkout",
        },
        402
      );
    }

    await next();
  };
}

/**
 * Check that the authenticated org has not exceeded their monthly scan quota.
 */
export function requireScanQuota(): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get("auth") as AuthPrincipal | null;
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const repository = c.get("services").repository as BinShieldRepository;
    const plan = await getOrgPlan(repository, auth.orgId);
    const usage = await repository.getUsageRecord(auth.orgId);
    const currentScans = usage?.scanCount ?? 0;

    if (!checkScanQuota(plan, currentScans)) {
      const entitlements = entitlementForPlan(plan);
      return c.json(
        {
          error: "Monthly scan quota exceeded",
          currentPlan: plan,
          limit: entitlements.maxMonthlyScans,
          used: currentScans,
          upgradeUrl: "/billing/checkout",
        },
        402
      );
    }

    await next();
  };
}

/**
 * Check that the authenticated org has not exceeded their repo limit.
 */
export function requireRepoQuota(): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get("auth") as AuthPrincipal | null;
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const repository = c.get("services").repository as BinShieldRepository;
    const plan = await getOrgPlan(repository, auth.orgId);
    const usage = await repository.getUsageRecord(auth.orgId);
    const currentRepos = usage?.repoCount ?? 0;

    if (!checkRepoQuota(plan, currentRepos)) {
      const entitlements = entitlementForPlan(plan);
      return c.json(
        {
          error: "Repository limit reached",
          currentPlan: plan,
          limit: entitlements.maxRepos,
          used: currentRepos,
          upgradeUrl: "/billing/checkout",
        },
        402
      );
    }

    await next();
  };
}

/**
 * Increment the scan counter for the authenticated org after the handler runs.
 * Should be placed AFTER requireScanQuota in the middleware chain.
 */
export function trackScanUsage(): MiddlewareHandler {
  return async (c, next) => {
    await next();

    // Only track on successful scan submissions (2xx)
    if (c.res.status >= 200 && c.res.status < 300) {
      const auth = c.get("auth") as AuthPrincipal | null;
      if (auth) {
        const repository = c.get("services").repository as BinShieldRepository;
        try {
          await repository.incrementScanCount(auth.orgId);
        } catch (err) {
          console.error(
            `[BinShield Middleware] Failed to track scan usage: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }
    }
  };
}

/**
 * Require the authenticated org's plan to have access to a specific feature.
 */
export function requireFeature(feature: string): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get("auth") as AuthPrincipal | null;
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const repository = c.get("services").repository as BinShieldRepository;
    const plan = await getOrgPlan(repository, auth.orgId);

    if (!checkEntitlement(plan, feature)) {
      return c.json(
        {
          error: `Feature "${feature}" is not available on your current plan`,
          currentPlan: plan,
          feature,
          upgradeUrl: "/billing/checkout",
        },
        403
      );
    }

    await next();
  };
}
