import type { PlanName, EntitlementRecord } from "@binshield/analysis-types";
import { entitlementForPlan } from "@binshield/analysis-types";

export { entitlementForPlan };
export type { PlanName, EntitlementRecord };

// ---------------------------------------------------------------------------
// Feature definitions and plan mapping
// ---------------------------------------------------------------------------

/**
 * Features that can be gated by plan. Each feature maps to the minimum plan
 * tier required to access it.
 */
const FEATURE_MIN_PLAN: Record<string, PlanName> = {
  api_access: "pro",
  watchlists: "pro",
  proactive_alerts: "pro",
  binary_diff_alerts: "pro",
  sbom_export: "team",
  slack_alerts: "team",
  compliance_reports: "enterprise",
};

/** Ordered plan tiers from lowest to highest. */
export const PLAN_RANK: Record<PlanName, number> = {
  free: 0,
  pro: 1,
  team: 2,
  enterprise: 3,
};

// ---------------------------------------------------------------------------
// Entitlement checks
// ---------------------------------------------------------------------------

/**
 * Returns true if the given plan has access to the specified feature.
 * Unknown features are denied by default.
 */
export function checkEntitlement(plan: PlanName, feature: string): boolean {
  const minPlan = FEATURE_MIN_PLAN[feature];
  if (!minPlan) {
    // Unknown features are denied by default
    return false;
  }

  return PLAN_RANK[plan] >= PLAN_RANK[minPlan];
}

/**
 * Returns true if the plan's monthly scan quota has not been exceeded.
 */
export function checkScanQuota(plan: PlanName, currentUsage: number): boolean {
  const entitlements = entitlementForPlan(plan);
  return currentUsage < entitlements.maxMonthlyScans;
}

/**
 * Returns true if the plan's repo limit has not been reached.
 */
export function checkRepoQuota(plan: PlanName, currentCount: number): boolean {
  const entitlements = entitlementForPlan(plan);
  return currentCount < entitlements.maxRepos;
}

/**
 * Throws an error if the given plan does not have access to the specified
 * feature. Intended for use in route handlers where denial should halt
 * execution.
 */
export function requireEntitlement(plan: PlanName, feature: string): void {
  if (!checkEntitlement(plan, feature)) {
    const minPlan = FEATURE_MIN_PLAN[feature];
    const message = minPlan
      ? `Feature "${feature}" requires the ${minPlan} plan or higher`
      : `Unknown feature: ${feature}`;

    const error = new Error(message) as Error & { statusCode: number };
    error.statusCode = 403;
    throw error;
  }
}
