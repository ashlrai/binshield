import { Hono } from "hono";
import type { Context } from "hono";
import { cors } from "hono/cors";

import { AdvisoryService } from "./lib/advisory-service";
import { logAudit } from "./lib/audit";
import { assertSameOrg, resolvePrincipal } from "./lib/auth";
import { generateReport } from "./lib/compliance-reports";
import { readApiEnv } from "./lib/env";
import { requireFeature, requireRepoQuota, requireScanQuota, trackScanUsage } from "./lib/middleware";
import { rateLimitByIp, rateLimitByAuth } from "./lib/rate-limit";
import { createServices } from "./lib/repository";
import type { AppServices } from "./lib/repository";
import { generateCycloneDxSbom } from "./lib/sbom";
import type { AuthPrincipal, Ecosystem, PackageAnalysis } from "./lib/types";
import { detectLockfileFormat, validateEcosystem, validateReportType } from "./lib/validation";

type AppVariables = {
  auth: AuthPrincipal | null;
  services: AppServices;
};

type AppContext = Context<{ Variables: AppVariables }>;

function requireBody<T>(value: unknown, fields: (keyof T)[]) {
  if (!value || typeof value !== "object") {
    return "Request body must be an object";
  }

  for (const field of fields) {
    if (!(field in (value as Record<string, unknown>))) {
      return `Missing required field: ${String(field)}`;
    }
  }

  return null;
}

function getServices(c: AppContext) {
  return c.get("services");
}

async function getOrgAuth(c: AppContext, orgId: string) {
  const auth = c.get("auth");
  const error = assertSameOrg(auth, orgId);
  if (error) {
    return { auth: null, error };
  }

  return { auth, error: null };
}

function getAuditConfig(c: AppContext) {
  const { env } = c.get("services");
  return {
    supabaseUrl: env.supabaseUrl ?? "",
    supabaseServiceRoleKey: env.supabaseServiceRoleKey ?? ""
  };
}

export function createApp(services = createServices(readApiEnv())) {
  const app = new Hono<{ Variables: AppVariables }>();

  // Global error handler
  app.onError((err, c) => {
    // JSON parse errors from malformed request bodies → 400
    if (err instanceof SyntaxError && err.message.includes("JSON")) {
      return c.json({ error: "Invalid JSON in request body" }, 400);
    }
    console.error(`[BinShield API] Unhandled error: ${err.message}`, err.stack);
    const statusCode = "statusCode" in err ? (err as { statusCode: number }).statusCode : 500;
    return c.json(
      { error: statusCode === 500 ? "Internal server error" : err.message },
      statusCode >= 400 && statusCode < 600 ? (statusCode as 400 | 401 | 403 | 404 | 500) : 500
    );
  });

  app.use("*", cors({
    origin: (services.env.publicAppUrl && services.env.publicAppUrl !== "http://localhost:3000")
      ? [services.env.publicAppUrl, "https://binshield.dev"]
      : "*",
    credentials: true,
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "X-BinShield-API-Key"],
  }));

  // Auth resolution (must run before rate limiting so rateLimitByAuth can key on orgId)
  app.use("*", async (c, next) => {
    const start = Date.now();
    c.set("services", services);
    c.set("auth", await resolvePrincipal(services.repository, c, services.env));
    await next();
    console.log(`[BinShield API] ${c.req.method} ${c.req.path} ${c.res.status} ${Date.now() - start}ms`);
  });

  // Rate limiting (after auth so rateLimitByAuth can use orgId)
  app.use("*", rateLimitByIp({ windowMs: 60_000, max: 120 }));
  app.use("/scans/*", rateLimitByAuth({ windowMs: 60_000, max: 30 }));
  app.use("/scans/*", async (c, next) => {
    if (!c.get("auth")) {
      return c.json({ error: "API key required" }, 401);
    }
    await next();
  });
  app.use("/orgs/*", async (c, next) => {
    if (!c.get("auth")) {
      return c.json({ error: "API key required" }, 401);
    }
    await next();
  });

  app.get("/health", (c) => {
    const { env, repositoryInfo } = getServices(c);
    return c.json({
      ok: true,
      service: "binshield-api",
      mode: repositoryInfo.mode,
      repository: repositoryInfo,
      defaultFailOn: env.defaultFailOn
    });
  });

  app.get("/packages/search", async (c) => {
    const query = c.req.query("q") ?? undefined;
    const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 20), 1), 100);
    const offset = Math.max(Number(c.req.query("offset") ?? 0), 0);
    const results = await getServices(c).repository.searchPackages(query);
    const paged = results.items.slice(offset, offset + limit);
    return c.json({ items: paged, total: results.total });
  });

  app.get("/packages/:ecosystem/:name", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const versions = await getServices(c).repository.listPackageVersions(ecosystem, name);

    if (versions.length === 0) {
      return c.json({ error: "Package not found" }, 404);
    }

    return c.json({
      packageName: name,
      ecosystem,
      versions
    });
  });

  app.get("/packages/:ecosystem/:name/versions/:version", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const version = c.req.param("version");
    const analysis = await getServices(c).repository.getPackage(ecosystem, name, version);

    if (!analysis) {
      return c.json({ error: "Analysis not found" }, 404);
    }

    return c.json(analysis);
  });

  app.get("/packages/:ecosystem/:name/versions/:version/sbom", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const version = c.req.param("version");
    const analysis = await getServices(c).repository.getPackage(ecosystem, name, version);

    if (!analysis) {
      return c.json({ error: "Analysis not found" }, 404);
    }

    const sbom = generateCycloneDxSbom(analysis);
    c.header("Content-Type", "application/json");
    c.header("Content-Disposition", `attachment; filename="sbom-${name}-${version}.cdx.json"`);
    return c.json(sbom);
  });

  app.get("/packages/:ecosystem/:name/diff", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const from = c.req.query("from");
    const to = c.req.query("to");

    if (!from || !to) {
      return c.json({ error: "Both from and to query params are required" }, 400);
    }

    const diff = await getServices(c).repository.getPackageDiff(ecosystem, name, from, to);
    if (!diff) {
      return c.json({ error: "Diff not found" }, 404);
    }

    return c.json(diff);
  });

  app.post("/scans/packages", requireScanQuota(), trackScanUsage(), async (c) => {
    const auth = c.get("auth")!;

    const body = await c.req.json();
    const validationError = requireBody<{ ecosystem: Ecosystem; packageName: string; version: string }>(body, [
      "ecosystem",
      "packageName",
      "version"
    ]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    if (!validateEcosystem(body.ecosystem)) {
      return c.json({ error: "Invalid ecosystem. Must be one of: npm, pypi, crates, go" }, 400);
    }

    const job = await getServices(c).repository.submitScan(body, auth);

    // Fire-and-forget audit log
    logAudit(getAuditConfig(c), auth.orgId, "scan.submitted", "scan", job.id, auth.userId, {
      ecosystem: body.ecosystem,
      packageName: body.packageName,
      version: body.version
    });

    return c.json(job, job.status === "complete" ? 200 : 202);
  });

  app.get("/scans/:id", async (c) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const job = await getServices(c).repository.getScanJob(c.req.param("id"), auth.orgId);
    if (!job) {
      return c.json({ error: "Scan not found" }, 404);
    }
    return c.json(job);
  });

  app.get("/orgs/:orgId", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const org = await getServices(c).repository.getOrganization(orgId);
    if (!org) {
      return c.json({ error: "Organization not found" }, 404);
    }

    return c.json(org);
  });

  app.get("/orgs/:orgId/repos", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listRepos(orgId);
    return c.json({ items });
  });

  app.post("/orgs/:orgId/repos", requireRepoQuota(), async (c) => {
    const orgId = c.req.param("orgId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ githubRepo: string }>(body, ["githubRepo"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const repo = await getServices(c).repository.createRepo(orgId, body.githubRepo);

    // Track repo usage and audit
    getServices(c).repository.incrementRepoCount(orgId).catch((err) => {
      console.error("[BinShield API] Failed to increment repo count:", err instanceof Error ? err.message : err);
    });
    logAudit(getAuditConfig(c), orgId, "repo.created", "repo", repo.id, auth.userId, {
      githubRepo: body.githubRepo
    });

    return c.json(repo, 201);
  });

  app.get("/orgs/:orgId/watchlists", requireFeature("watchlists"), async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listWatchlists(orgId);
    return c.json({ items });
  });

  app.post("/orgs/:orgId/watchlists", requireFeature("watchlists"), async (c) => {
    const orgId = c.req.param("orgId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ name: string; channel: "email" | "slack" | "webhook"; destination: string }>(body, [
      "name",
      "channel",
      "destination"
    ]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const watchlist = await getServices(c).repository.createWatchlist(orgId, body);

    logAudit(getAuditConfig(c), orgId, "watchlist.created", "watchlist", watchlist.id, auth.userId, {
      name: body.name,
      channel: body.channel
    });

    return c.json(watchlist, 201);
  });

  app.post("/orgs/:orgId/watchlists/:watchlistId/packages", requireFeature("watchlists"), async (c) => {
    const orgId = c.req.param("orgId");
    const watchlistId = c.req.param("watchlistId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ ecosystem: Ecosystem; packageName: string; version?: string }>(body, [
      "ecosystem",
      "packageName"
    ]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    try {
      const item = await getServices(c).repository.addWatchlistPackage(orgId, watchlistId, body);
      return c.json(item, 201);
    } catch {
      return c.json({ error: "Watchlist not found" }, 404);
    }
  });

  app.delete("/orgs/:orgId/watchlists/:watchlistId/packages/:packageName", requireFeature("watchlists"), async (c) => {
    const orgId = c.req.param("orgId");
    const watchlistId = c.req.param("watchlistId");
    const packageName = decodeURIComponent(c.req.param("packageName"));
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const removed = await getServices(c).repository.removeWatchlistPackage(orgId, watchlistId, packageName);
    if (!removed) {
      return c.json({ error: "Package not found in watchlist" }, 404);
    }
    return c.json({ ok: true });
  });

  app.get("/orgs/:orgId/subscription", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listSubscriptions(orgId);
    return c.json({ items });
  });

  app.post("/orgs/:orgId/subscription", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ plan: string; status: string }>(body, ["plan", "status"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const subscription = await getServices(c).repository.upsertSubscription(orgId, body);
    return c.json(subscription, 200);
  });

  app.get("/orgs/:orgId/api-keys", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listApiKeys(orgId);
    return c.json({ items });
  });

  app.post("/orgs/:orgId/api-keys", async (c) => {
    const orgId = c.req.param("orgId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ label: string }>(body, ["label"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const apiKey = await getServices(c).repository.createApiKey(orgId, body.label);

    logAudit(getAuditConfig(c), orgId, "api_key.created", "api_key", apiKey.summary.id, auth.userId, {
      label: body.label
    });

    return c.json(apiKey, 201);
  });

  app.delete("/orgs/:orgId/api-keys/:keyId", async (c) => {
    const orgId = c.req.param("orgId");
    const keyId = c.req.param("keyId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const revoked = await getServices(c).repository.revokeApiKey(orgId, keyId);
    if (!revoked) {
      return c.json({ error: "API key not found" }, 404);
    }

    logAudit(getAuditConfig(c), orgId, "api_key.revoked", "api_key", keyId, auth.userId, {});
    return c.json({ ok: true });
  });

  // -----------------------------------------------------------------------
  // Invitation routes
  // -----------------------------------------------------------------------

  app.post("/orgs/:orgId/invitations", async (c) => {
    const orgId = c.req.param("orgId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ email: string; role: string }>(body, ["email", "role"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const invitation = await getServices(c).repository.createInvitation(orgId, body.email, body.role, auth.userId);

    logAudit(getAuditConfig(c), orgId, "invitation.created", "invitation", invitation.id, auth.userId, {
      email: body.email,
      role: body.role
    });

    return c.json(invitation, 201);
  });

  app.get("/orgs/:orgId/invitations", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listInvitations(orgId);
    return c.json({ items });
  });

  // Accept invitation — no auth required (validates by token)
  app.post("/invitations/:token/accept", async (c) => {
    const token = c.req.param("token");

    const body = await c.req.json();
    const validationError = requireBody<{ userId: string }>(body, ["userId"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const result = await getServices(c).repository.acceptInvitation(token, body.userId);
    if (!result) {
      return c.json({ error: "Invitation not found, expired, or already accepted" }, 404);
    }

    logAudit(getAuditConfig(c), result.orgId, "invitation.accepted", "invitation", undefined, body.userId, {
      role: result.role
    });

    return c.json(result);
  });

  // -----------------------------------------------------------------------
  // Billing routes
  // -----------------------------------------------------------------------

  app.post("/billing/checkout", async (c) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ plan: string }>(body, ["plan"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const { env, repository } = getServices(c);

    // Try real Stripe checkout if configured
    if (env.stripeSecretKey && env.stripeSecretKey !== "sk_test_placeholder") {
      try {
        const { readEnv } = await import("@binshield/config");
        const config = readEnv();
        const priceId = config.stripePriceIds[body.plan];
        if (!priceId || priceId.includes("placeholder")) {
          return c.json({ error: `No Stripe price configured for plan: ${body.plan}` }, 400);
        }

        const { createCheckoutSession } = await import("./lib/stripe");
        const org = await repository.getOrganization(auth.orgId);
        const session = await createCheckoutSession(
          { secretKey: env.stripeSecretKey, webhookSecret: env.stripeWebhookSecret ?? "", publishableKey: "", prices: config.stripePriceIds },
          {
            orgId: auth.orgId,
            plan: body.plan,
            customerEmail: undefined,
            successUrl: `${env.publicAppUrl}/dashboard/billing?session_id={CHECKOUT_SESSION_ID}`,
            cancelUrl: `${env.publicAppUrl}/pricing`,
          }
        );
        return c.json({ checkoutUrl: session.url, sessionId: session.sessionId }, 201);
      } catch (err) {
        return c.json({ error: err instanceof Error ? err.message : "Checkout failed" }, 500);
      }
    }

    // Fallback to local/demo mode
    const checkout = await repository.createBillingCheckout(auth.orgId, body.plan);
    return c.json(checkout, 201);
  });

  // -----------------------------------------------------------------------
  // Advisory routes
  // -----------------------------------------------------------------------

  app.get("/packages/:ecosystem/:name/advisories", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const advisories = await getServices(c).repository.getPackageAdvisories(ecosystem, name);
    return c.json({ items: advisories, total: advisories.length });
  });

  app.get("/advisories/recent", async (c) => {
    const limit = Math.min(Number(c.req.query("limit") ?? 50), 200);
    const advisories = await getServices(c).repository.getRecentAdvisories(limit);
    return c.json({ items: advisories, total: advisories.length });
  });

  app.post("/advisories/sync", async (c) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ ecosystem: string; packageName: string }>(body, [
      "ecosystem",
      "packageName"
    ]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const { env } = getServices(c);
    if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
      return c.json({ error: "Advisory sync requires Supabase configuration" }, 503);
    }

    const advisoryService = new AdvisoryService({
      supabaseUrl: env.supabaseUrl,
      supabaseServiceRoleKey: env.supabaseServiceRoleKey,
      githubToken: env.githubToken,
      nvdApiKey: env.nvdApiKey
    });

    const result = await advisoryService.syncPackageAdvisories(body.ecosystem, body.packageName);
    return c.json(result);
  });

  // -----------------------------------------------------------------------
  // Feed routes (public)
  // -----------------------------------------------------------------------

  app.get("/feed/events", async (c) => {
    const limit = Number(c.req.query("limit") ?? 50);
    const { env } = getServices(c);
    if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
      return c.json({ items: [], total: 0 });
    }
    try {
      const response = await fetch(
        `${env.supabaseUrl.replace(/\/$/, "")}/rest/v1/feed_events?select=*&order=created_at.desc&limit=${limit}`,
        { headers: { apikey: env.supabaseServiceRoleKey!, authorization: `Bearer ${env.supabaseServiceRoleKey!}` } }
      );
      if (!response.ok) return c.json({ items: [], total: 0 });
      const rows = await response.json() as Array<Record<string, unknown>>;
      const items = rows.map((r) => ({
        id: r.id, ecosystem: r.ecosystem, packageName: r.package_name,
        version: r.version, eventType: r.event_type,
        riskScore: r.risk_score, riskLevel: r.risk_level,
        timestamp: r.created_at, metadata: r.metadata,
      }));
      return c.json({ items, total: items.length });
    } catch {
      return c.json({ items: [], total: 0 });
    }
  });

  app.get("/feed/stats", async (c) => {
    const { env } = getServices(c);
    if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
      return c.json({ packagesProcessed: 0, nativePackagesFound: 0, latestEvents: 0 });
    }
    try {
      const response = await fetch(
        `${env.supabaseUrl.replace(/\/$/, "")}/rest/v1/feed_state?id=eq.npm&select=*`,
        { headers: { apikey: env.supabaseServiceRoleKey!, authorization: `Bearer ${env.supabaseServiceRoleKey!}` } }
      );
      if (!response.ok) return c.json({ packagesProcessed: 0, nativePackagesFound: 0, latestEvents: 0 });
      const rows = await response.json() as Array<{ packages_processed: number; native_packages_found: number; updated_at: string }>;
      const state = rows[0];
      return c.json({
        packagesProcessed: state?.packages_processed ?? 0,
        nativePackagesFound: state?.native_packages_found ?? 0,
        latestEvents: 0,
        lastUpdated: state?.updated_at,
      });
    } catch {
      return c.json({ packagesProcessed: 0, nativePackagesFound: 0, latestEvents: 0 });
    }
  });

  // -----------------------------------------------------------------------
  // Lockfile scanning route
  // -----------------------------------------------------------------------

  app.post("/scans/lockfile", async (c) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ filename: string; content: string }>(body, ["filename", "content"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    if (typeof body.content === "string" && body.content.length > 5 * 1024 * 1024) {
      return c.json({ error: "Lockfile content exceeds 5MB limit" }, 413);
    }

    const lockfileFormat = detectLockfileFormat(body.filename, body.content ?? "");
    if (!lockfileFormat) {
      return c.json({ error: "Unrecognized lockfile format. Supported: package-lock.json, yarn.lock, pnpm-lock.yaml" }, 400);
    }

    const { env } = getServices(c);
    if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
      return c.json({ error: "Lockfile scanning requires Supabase configuration" }, 503);
    }

    // Store the lockfile scan request in Supabase for the worker to process
    try {
      const baseUrl = env.supabaseUrl.replace(/\/$/, "");
      const headers = {
        apikey: env.supabaseServiceRoleKey,
        authorization: `Bearer ${env.supabaseServiceRoleKey}`,
        "content-type": "application/json",
        Prefer: "return=representation",
      };
      const [scan] = await fetch(`${baseUrl}/rest/v1/lockfile_scans?select=id`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          org_id: auth.orgId,
          repo_id: body.repoId ?? null,
          filename: body.filename,
          format: lockfileFormat,
          status: "processing",
        }),
      }).then((r) => r.json() as Promise<Array<{ id: string }>>);

      return c.json({ id: scan.id, status: "processing", filename: body.filename }, 202);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : "Lockfile scan failed" }, 500);
    }
  });

  app.get("/orgs/:orgId/lockfile-scans", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const { env } = getServices(c);
    if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
      return c.json({ items: [] });
    }

    try {
      const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 50), 1), 200);
      const baseUrl = env.supabaseUrl.replace(/\/$/, "");
      const res = await fetch(
        `${baseUrl}/rest/v1/lockfile_scans?org_id=eq.${orgId}&order=created_at.desc&limit=${limit}&select=*`,
        { headers: { apikey: env.supabaseServiceRoleKey, authorization: `Bearer ${env.supabaseServiceRoleKey}` } }
      );
      if (!res.ok) return c.json({ items: [] });
      const rows = await res.json() as Array<Record<string, unknown>>;
      const items = rows.map((r) => ({
        id: r.id,
        filename: r.filename,
        format: r.format,
        totalDeps: r.total_dependencies ?? 0,
        nativeDeps: r.native_dependencies ?? 0,
        riskScore: r.aggregate_risk_score ?? 0,
        riskLevel: r.aggregate_risk_level ?? "none",
        status: r.status,
        scannedAt: r.created_at,
      }));
      return c.json({ items });
    } catch {
      return c.json({ items: [] });
    }
  });

  // -----------------------------------------------------------------------
  // Compliance report routes
  // -----------------------------------------------------------------------

  app.post("/orgs/:orgId/reports", requireFeature("compliance_reports"), async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ reportType: string }>(body, ["reportType"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    if (!validateReportType(body.reportType)) {
      return c.json({ error: "Invalid reportType. Must be one of: soc2, iso27001, cra, custom" }, 400);
    }

    const { env, repository } = getServices(c);
    const org = await repository.getOrganization(orgId);
    const orgName = org?.name ?? "Organization";

    const scope = body.scope as { packageNames?: string[] } | undefined;

    let analyses: PackageAnalysis[];
    if (scope?.packageNames?.length) {
      const results = await Promise.all(
        scope.packageNames.slice(0, 200).map((name) => repository.getPackage("npm", name))
      );
      analyses = results.filter((a): a is PackageAnalysis => a !== null);
    } else {
      const searchResults = await repository.searchPackages();
      const results = await Promise.all(
        searchResults.items.slice(0, 200).map((item) => repository.getPackage(item.ecosystem, item.packageName))
      );
      analyses = results.filter((a): a is PackageAnalysis => a !== null);
    }

    const title = body.title ?? `${body.reportType.toUpperCase()} Report — ${new Date().toLocaleDateString()}`;
    const { summary, html } = generateReport(body.reportType, title, orgName, analyses);

    if (env.supabaseUrl && env.supabaseServiceRoleKey) {
      try {
        const res = await fetch(
          `${env.supabaseUrl.replace(/\/$/, "")}/rest/v1/compliance_reports?select=id`,
          {
            method: "POST",
            headers: {
              apikey: env.supabaseServiceRoleKey,
              authorization: `Bearer ${env.supabaseServiceRoleKey}`,
              "content-type": "application/json",
              Prefer: "return=representation",
            },
            body: JSON.stringify({
              org_id: orgId, report_type: body.reportType, title,
              status: "ready", scope: body.scope ?? {}, summary,
              generated_at: new Date().toISOString(),
            }),
          }
        );
        if (res.ok) {
          const [row] = await res.json() as Array<{ id: string }>;
          return c.json({ id: row.id, title, reportType: body.reportType, status: "ready", summary, html }, 201);
        }
      } catch { /* fall through */ }
    }

    return c.json({ title, reportType: body.reportType, status: "ready", summary, html }, 201);
  });

  app.get("/orgs/:orgId/reports", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const { env } = getServices(c);
    if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
      return c.json({ items: [] });
    }

    try {
      const res = await fetch(
        `${env.supabaseUrl.replace(/\/$/, "")}/rest/v1/compliance_reports?org_id=eq.${orgId}&order=created_at.desc&select=*`,
        { headers: { apikey: env.supabaseServiceRoleKey, authorization: `Bearer ${env.supabaseServiceRoleKey}` } }
      );
      if (!res.ok) return c.json({ items: [] });
      const rows = await res.json() as Array<Record<string, unknown>>;
      const items = rows.map((r) => ({
        id: r.id, reportType: r.report_type, title: r.title,
        status: r.status, summary: r.summary,
        createdAt: r.created_at, generatedAt: r.generated_at,
      }));
      return c.json({ items });
    } catch {
      return c.json({ items: [] });
    }
  });

  // -----------------------------------------------------------------------
  // Billing routes
  // -----------------------------------------------------------------------

  app.post("/billing/portal", async (c) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const { env, repository } = getServices(c);
    if (!env.stripeSecretKey || env.stripeSecretKey === "sk_test_placeholder") {
      return c.json({ error: "Stripe not configured" }, 503);
    }

    const org = await repository.getOrganization(auth.orgId);
    if (!org) {
      return c.json({ error: "Organization not found" }, 404);
    }

    try {
      // Look up the org's Stripe customer ID
      // First check the organization table, then fall back to subscriptions
      let customerId: string | undefined;

      if (env.supabaseUrl && env.supabaseServiceRoleKey) {
        const baseUrl = env.supabaseUrl.replace(/\/$/, "");
        const orgRes = await fetch(
          `${baseUrl}/rest/v1/organizations?id=eq.${auth.orgId}&select=stripe_customer_id`,
          { headers: { apikey: env.supabaseServiceRoleKey, authorization: `Bearer ${env.supabaseServiceRoleKey}` } }
        );
        if (orgRes.ok) {
          const rows = await orgRes.json() as Array<{ stripe_customer_id?: string | null }>;
          customerId = rows[0]?.stripe_customer_id ?? undefined;
        }
      }

      if (!customerId) {
        // Fall back to checking subscriptions table
        if (env.supabaseUrl && env.supabaseServiceRoleKey) {
          const baseUrl = env.supabaseUrl.replace(/\/$/, "");
          const subRes = await fetch(
            `${baseUrl}/rest/v1/subscriptions?org_id=eq.${auth.orgId}&provider=eq.stripe&select=customer_id&limit=1`,
            { headers: { apikey: env.supabaseServiceRoleKey, authorization: `Bearer ${env.supabaseServiceRoleKey}` } }
          );
          if (subRes.ok) {
            const rows = await subRes.json() as Array<{ customer_id?: string | null }>;
            customerId = rows[0]?.customer_id ?? undefined;
          }
        }
      }

      if (!customerId) {
        return c.json({
          error: "No Stripe subscription found. Subscribe to a plan first.",
          redirectUrl: `${env.publicAppUrl}/pricing`,
        }, 400);
      }

      const { createPortalSession } = await import("./lib/stripe");
      const config = { secretKey: env.stripeSecretKey, webhookSecret: env.stripeWebhookSecret ?? "", publishableKey: "", prices: {} };
      const body = await c.req.json().catch(() => ({})) as { returnUrl?: string };
      const returnUrl = body.returnUrl ?? `${env.publicAppUrl}/dashboard/billing`;
      const session = await createPortalSession(config, customerId, returnUrl);
      return c.json({ url: session.url });
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : "Failed to create portal session" }, 500);
    }
  });

  app.post("/billing/webhook", async (c) => {
    const { env, repository } = getServices(c);
    const stripeSecretKey = env.stripeSecretKey;
    const stripeWebhookSecret = env.stripeWebhookSecret;

    if (!stripeSecretKey || stripeSecretKey === "sk_test_placeholder" || !stripeWebhookSecret || stripeWebhookSecret === "whsec_placeholder") {
      return c.json({ ok: true, note: "Stripe not configured, webhook ignored" });
    }

    try {
      const { constructWebhookEvent, handleWebhookEvent } = await import("./lib/stripe");
      const payload = await c.req.text();
      const signature = c.req.header("stripe-signature") ?? "";
      const config = { secretKey: stripeSecretKey, webhookSecret: stripeWebhookSecret, publishableKey: "", prices: {} };
      const event = constructWebhookEvent(config, payload, signature);
      await handleWebhookEvent(event, repository);
      return c.json({ ok: true });
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : "Webhook processing failed" }, 400);
    }
  });

  return app;
}

export const app = createApp();
