import { Hono } from "hono";
import type { Context } from "hono";
import { cors } from "hono/cors";

import { PackageNameIntelligence } from "@binshield/package-intelligence";
import type { Ecosystem as PkgIntelEcosystem } from "@binshield/package-intelligence";

import { AdvisoryService, getHeatMapData } from "./lib/advisory-service";
import { EpssCache } from "./lib/epss-cache";
import { logAudit } from "./lib/audit";
import { assertSameOrg, resolvePrincipal } from "./lib/auth";
import { generateReport } from "./lib/compliance-reports";
import { readApiEnv } from "./lib/env";
import { requireFeature, requireRepoQuota, requireScanQuota, trackScanUsage } from "./lib/middleware";
import { rateLimitByIp, rateLimitByAuth } from "./lib/rate-limit";
import { createServices } from "./lib/repository";
import type { AppServices, FailedScanEntry } from "./lib/repository";
import { generateCycloneDxSbom } from "./lib/sbom";
import { verifySbomProvenance } from "./lib/sbom-provenance-checker";
import type { AuthPrincipal, Ecosystem, PackageAnalysis, SuppressionSummary } from "./lib/types";
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

// ---------------------------------------------------------------------------
// Scan resilience helpers
// ---------------------------------------------------------------------------

/** Exponential backoff delays (ms) for retry attempts 1–5. */
const RETRY_BACKOFF_MS = [1_000, 4_000, 16_000, 60_000, 300_000] as const;

/** Maximum number of retry attempts before a scan is marked 'abandoned'. */
const MAX_RETRY_ATTEMPTS = 3;

/** How long (ms) a scan may remain 'queued' before it is considered timed-out. */
const QUEUE_TIMEOUT_MS = 60_000;

/** Compute the next retry timestamp given the current failure count (1-based). */
function nextRetryAt(failureCount: number): string {
  const delayMs = RETRY_BACKOFF_MS[Math.min(failureCount - 1, RETRY_BACKOFF_MS.length - 1)] ?? 300_000;
  return new Date(Date.now() + delayMs).toISOString();
}

/**
 * Fire-and-forget background poller that monitors a newly submitted scan job.
 * If the job remains 'queued' for > QUEUE_TIMEOUT_MS or transitions to 'failed',
 * it is inserted into the FailedScanQueue.  After MAX_RETRY_ATTEMPTS failures
 * the job is abandoned and a console alert is emitted (hook for email/webhook).
 */
function startScanTimeoutWatch(
  repository: AppServices["repository"],
  jobId: string,
  orgId: string,
  scanPayload: { ecosystem: string; packageName: string; version: string }
): void {
  const POLL_INTERVAL_MS = 2_000;
  const deadlineMs = Date.now() + QUEUE_TIMEOUT_MS;
  let pollHandle: ReturnType<typeof setTimeout> | undefined;

  async function poll(): Promise<void> {
    try {
      const job = await repository.getScanJob(jobId, orgId === "anon" ? undefined : orgId);
      if (!job) return; // job vanished — nothing to do

      const timedOut = job.status === "queued" && Date.now() > deadlineMs;
      const failed = job.status === "failed";

      if (!timedOut && !failed) {
        // Still in progress — schedule next poll unless deadline already past
        if (Date.now() < deadlineMs + POLL_INTERVAL_MS) {
          pollHandle = setTimeout(() => { void poll(); }, POLL_INTERVAL_MS);
        }
        return;
      }

      const errorReason = timedOut ? "timeout: job remained queued for > 60s" : (job.error ?? "worker reported failure");

      // Read existing DLQ entry (if any) to determine failure count
      const existing = await repository.getFailedScan(jobId).catch(() => null);
      const failureCount = (existing?.failureCount ?? 0) + 1;
      const status: FailedScanEntry["status"] = failureCount >= MAX_RETRY_ATTEMPTS ? "abandoned" : "retrying";

      await repository.upsertFailedScan({
        scanId: jobId,
        jobId,
        orgId: orgId === "anon" ? null : orgId,
        ecosystem: scanPayload.ecosystem,
        packageName: scanPayload.packageName,
        version: scanPayload.version,
        errorReason,
        failureCount,
        lastAttemptAt: new Date().toISOString(),
        nextRetryAt: nextRetryAt(failureCount),
        status,
        metadata: { originalStatus: job.status, timedOut }
      });

      await repository.appendScanAuditLog({
        scanId: jobId,
        orgId: orgId === "anon" ? null : orgId,
        eventType: timedOut ? "scan_timeout" : "scan_failed",
        retryAttempt: failureCount,
        details: { errorReason, packageName: scanPayload.packageName, version: scanPayload.version }
      });

      if (status === "abandoned") {
        console.warn(
          `[BinShield] scan ${jobId} abandoned after ${failureCount} failed attempts ` +
          `(org=${orgId}, pkg=${scanPayload.packageName}@${scanPayload.version}). ` +
          "Consider configuring an email/webhook alert channel."
        );
        await repository.appendScanAuditLog({
          scanId: jobId,
          orgId: orgId === "anon" ? null : orgId,
          eventType: "scan_abandoned",
          retryAttempt: failureCount,
          details: { alertSent: false }
        });
      }
    } catch (err) {
      // Poller errors must never crash the server process
      console.error("[BinShield] startScanTimeoutWatch poll error:", err instanceof Error ? err.message : err);
    }
  }

  // First poll fires after the timeout window; intermediate polls track status
  pollHandle = setTimeout(() => { void poll(); }, POLL_INTERVAL_MS);
  // Suppress TS unused-variable warning
  void pollHandle;
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

  // Strict IP-based rate limiter for anonymous public scan (10 req/min per IP)
  const publicScanRateLimit = rateLimitByIp({ windowMs: 60_000, max: 10 });

  /** Filter binary-level findings out of an analysis according to org suppressions. */
  function applySuppressions(analysis: PackageAnalysis, suppressions: SuppressionSummary[]): PackageAnalysis {
    if (suppressions.length === 0) return analysis;

    const active = suppressions.filter(
      (s) =>
        s.ecosystem === analysis.ecosystem &&
        s.packageName === analysis.packageName &&
        (s.version == null || s.version === analysis.version)
    );

    if (active.length === 0) return analysis;

    return {
      ...analysis,
      binaries: analysis.binaries.map((b) => ({
        ...b,
        // Finding has only title/severity/description — match on title only
        findings: (b.findings ?? []).filter(
          (f) => !active.some((s) => s.findingTitle == null || s.findingTitle === f.title)
        )
      }))
    };
  }

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

  // -----------------------------------------------------------------------
  // Public anonymous scan — no API key required, strictly IP-rate-limited
  // -----------------------------------------------------------------------

  app.post("/public/scan", publicScanRateLimit, async (c) => {
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

    // Use a synthetic anonymous principal so the job is not org-scoped and
    // does not consume any org's quota.
    const anonPrincipal: AuthPrincipal = {
      apiKeyId: "anon",
      orgId: "anon",
      label: "public-scan",
      scopes: []
    };

    const job = await getServices(c).repository.submitScan(body, anonPrincipal);
    return c.json(job, job.status === "complete" ? 200 : 202);
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

    // Apply org-level finding suppressions for authenticated requests
    const auth = c.get("auth");
    if (auth) {
      const suppressions = await getServices(c).repository.listSuppressions(auth.orgId);
      return c.json(applySuppressions(analysis, suppressions));
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

    // Start background timeout watcher for non-complete jobs
    if (job.status !== "complete") {
      startScanTimeoutWatch(getServices(c).repository, job.id, auth.orgId, {
        ecosystem: body.ecosystem,
        packageName: body.packageName,
        version: body.version
      });
    }

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

  // Register a repo's dependencies (from the GitHub Action) so the proactive
  // alert loop can warn this org if any of them is later flagged malicious.
  app.post("/dependency-registration", async (c) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ dependencies: unknown }>(body, ["dependencies"]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }
    if (!Array.isArray(body.dependencies)) {
      return c.json({ error: "dependencies must be an array" }, 400);
    }

    const dependencies = (body.dependencies as unknown[])
      .filter(
        (entry): entry is { ecosystem?: string; packageName: string; version: string } =>
          Boolean(entry) &&
          typeof (entry as { packageName?: unknown }).packageName === "string" &&
          typeof (entry as { version?: unknown }).version === "string"
      )
      .slice(0, 5000)
      .map((entry) => ({
        ecosystem: entry.ecosystem === "pypi" ? "pypi" : "npm",
        packageName: entry.packageName,
        version: entry.version
      }));

    const registered = await getServices(c).repository.registerDependencies(auth.orgId, dependencies);
    logAudit(
      getAuditConfig(c),
      auth.orgId,
      "dependencies.registered",
      "lockfile_dependencies",
      auth.orgId,
      auth.userId,
      { count: registered }
    );
    return c.json({ registered });
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

    // Validate internalPackagePattern if provided
    if (body.internalPackagePattern !== undefined) {
      if (typeof body.internalPackagePattern !== "string") {
        return c.json({ error: "internalPackagePattern must be a string" }, 400);
      }
      try {
        new RegExp(body.internalPackagePattern);
      } catch {
        return c.json({ error: "internalPackagePattern is not a valid regular expression" }, 400);
      }
    }
    // Validate trustedDomains if provided
    if (body.trustedDomains !== undefined) {
      if (!Array.isArray(body.trustedDomains) || !body.trustedDomains.every((d: unknown) => typeof d === "string")) {
        return c.json({ error: "trustedDomains must be an array of strings" }, 400);
      }
    }

    const watchlist = await getServices(c).repository.createWatchlist(orgId, {
      name: body.name,
      channel: body.channel,
      destination: body.destination,
      internalPackagePattern: body.internalPackagePattern,
      trustedDomains: body.trustedDomains
    });

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

  // --- Notification channels (proactive alert loop) -----------------------

  app.get("/orgs/:orgId/notification-channels", requireFeature("proactive_alerts"), async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listNotificationChannels(orgId);
    return c.json({ items });
  });

  app.post("/orgs/:orgId/notification-channels", requireFeature("proactive_alerts"), async (c) => {
    const orgId = c.req.param("orgId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ channel: string; destination: string; minRiskLevel?: string }>(body, [
      "channel",
      "destination"
    ]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }
    if (!["email", "slack", "webhook"].includes(body.channel)) {
      return c.json({ error: "channel must be one of: email, slack, webhook" }, 400);
    }
    if (body.minRiskLevel && !["low", "medium", "high", "critical"].includes(body.minRiskLevel)) {
      return c.json({ error: "minRiskLevel must be one of: low, medium, high, critical" }, 400);
    }

    const channel = await getServices(c).repository.createNotificationChannel(orgId, {
      channel: body.channel,
      destination: body.destination,
      minRiskLevel: body.minRiskLevel
    });

    logAudit(getAuditConfig(c), orgId, "notification_channel.created", "notification_channel", channel.id, auth.userId, {
      channel: body.channel
    });

    // `secret` is returned exactly once, at creation time.
    return c.json(channel, 201);
  });

  app.delete("/orgs/:orgId/notification-channels/:channelId", requireFeature("proactive_alerts"), async (c) => {
    const orgId = c.req.param("orgId");
    const channelId = c.req.param("channelId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const removed = await getServices(c).repository.deleteNotificationChannel(orgId, channelId);
    if (!removed) {
      return c.json({ error: "Notification channel not found" }, 404);
    }
    logAudit(getAuditConfig(c), orgId, "notification_channel.deleted", "notification_channel", channelId, auth.userId, {});
    return c.json({ ok: true });
  });

  app.get("/orgs/:orgId/alerts", requireFeature("proactive_alerts"), async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const limitParam = Number.parseInt(c.req.query("limit") ?? "50", 10);
    const limit = Number.isFinite(limitParam) ? Math.min(Math.max(limitParam, 1), 200) : 50;
    const items = await getServices(c).repository.listAlerts(orgId, limit);
    return c.json({ items });
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
  // Finding suppression routes
  // -----------------------------------------------------------------------

  app.get("/orgs/:orgId/suppressions", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listSuppressions(orgId);
    return c.json({ items });
  });

  app.post("/orgs/:orgId/suppressions", async (c) => {
    const orgId = c.req.param("orgId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ ecosystem: string; packageName: string; reason: string }>(body, [
      "ecosystem",
      "packageName",
      "reason"
    ]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const suppression = await getServices(c).repository.createSuppression(orgId, {
      ecosystem: body.ecosystem,
      packageName: body.packageName,
      version: body.version,
      findingCategory: body.findingCategory,
      findingTitle: body.findingTitle,
      reason: body.reason
    });

    logAudit(getAuditConfig(c), orgId, "suppression.created", "suppression", suppression.id, auth.userId, {
      ecosystem: body.ecosystem,
      packageName: body.packageName,
      version: body.version
    });

    return c.json(suppression, 201);
  });

  app.delete("/orgs/:orgId/suppressions/:suppressionId", async (c) => {
    const orgId = c.req.param("orgId");
    const suppressionId = c.req.param("suppressionId");
    const auth = c.get("auth")!;
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const removed = await getServices(c).repository.deleteSuppression(orgId, suppressionId);
    if (!removed) {
      return c.json({ error: "Suppression not found" }, 404);
    }

    logAudit(getAuditConfig(c), orgId, "suppression.deleted", "suppression", suppressionId, auth.userId, {});
    return c.json({ ok: true });
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

    // Enrich each advisory with vendor patch context when available.
    // The advisory service parses patchedVersion from the affectedPackages
    // array already stored in the advisory row, so no extra network call is needed.
    const { env } = getServices(c);
    const advisoryService = (env.supabaseUrl && env.supabaseServiceRoleKey)
      ? new AdvisoryService({
          supabaseUrl: env.supabaseUrl,
          supabaseServiceRoleKey: env.supabaseServiceRoleKey,
          githubToken: env.githubToken,
          nvdApiKey: env.nvdApiKey
        })
      : null;

    // Build a synthetic VendorAdvisoryJson array from the existing advisory
    // rows so parseVendorAdvisoryPatches can derive VendorPatchContext entries
    // without an additional DB round-trip.
    const vendorAdvisoryJsons = advisories.map((a) => ({
      id: a.sourceId,
      cve_id: a.sourceId.toUpperCase().startsWith("CVE-") ? a.sourceId : null,
      vulnerabilities: a.affectedPackages.map((ap) => ({
        package: { name: ap.packageName, ecosystem: ap.ecosystem },
        patched_versions: ap.patchedVersion ?? null,
        first_patched_version: ap.patchedVersion ? { identifier: ap.patchedVersion } : null,
        vulnerable_version_range: ap.vulnerableRange ?? null
      })),
      published_at: a.publishedAt ?? null,
      updated_at: a.updatedAt ?? null,
      withdrawn_at: null
    }));

    const { patches } = advisoryService
      ? advisoryService.parseVendorAdvisoryPatches(vendorAdvisoryJsons, name)
      : { patches: [] };

    // Build a map of cveId → VendorPatchContext for O(1) lookup
    const patchMap = new Map(patches.map((p) => [p.cveId.toUpperCase(), p]));

    const enrichedItems = advisories.map((advisory) => {
      const patch = patchMap.get(advisory.sourceId.toUpperCase());
      return {
        ...advisory,
        vendorPatch: patch
          ? {
              patchedVersion: patch.patchedVersion,
              daysToFix: patch.daysToFix,
              vendorConfidence: patch.vendorConfidence
            }
          : null
      };
    });

    return c.json({ items: enrichedItems, total: enrichedItems.length });
  });

  // -----------------------------------------------------------------------
  // Risk-correlation endpoint — EPSS + CVSS enrichment
  // GET /packages/:ecosystem/:name/versions/:version/risk-correlation
  // Returns: { cves, cvssScores[], epssScores[], compositeExploitRisk }
  // -----------------------------------------------------------------------

  app.get("/packages/:ecosystem/:name/versions/:version/risk-correlation", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const version = c.req.param("version");

    const { env } = getServices(c);
    if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
      // In local/dev mode return a mock correlation based on seed data
      const advisories = await getServices(c).repository.getPackageAdvisories(ecosystem, name);
      const cves = [...new Set(
        advisories
          .map((a) => a.sourceId)
          .filter((id) => id.toUpperCase().startsWith("CVE-"))
      )];
      const cvssScores = advisories
        .filter((a) => a.cvssScore != null)
        .map((a) => ({ cveId: a.sourceId, cvssScore: a.cvssScore!, severity: a.severity }));
      const compositeExploitRisk = cvssScores.length > 0
        ? Math.min(100, Math.round((Math.max(...cvssScores.map((c) => c.cvssScore)) / 10) * 100))
        : 0;
      return c.json({ ecosystem, packageName: name, version, cves, cvssScores, epssScores: [], compositeExploitRisk });
    }

    const advisoryService = new AdvisoryService({
      supabaseUrl: env.supabaseUrl,
      supabaseServiceRoleKey: env.supabaseServiceRoleKey,
      githubToken: env.githubToken,
      nvdApiKey: env.nvdApiKey
    });

    const correlation = await advisoryService.getRiskCorrelation(ecosystem, name, version);
    return c.json(correlation);
  });

  // -----------------------------------------------------------------------
  // GET /advisories/:cveId/exploit-activity
  // Returns CISA KEV + NVD exploit enrichment for a single CVE ID.
  // -----------------------------------------------------------------------

  app.get("/advisories/:cveId/exploit-activity", async (c) => {
    const cveId = c.req.param("cveId").toUpperCase();

    if (!cveId.startsWith("CVE-")) {
      return c.json({ error: "cveId must be a CVE identifier (e.g. CVE-2024-1234)" }, 400);
    }

    const { env } = getServices(c);

    // -----------------------------------------------------------------------
    // Supabase mode: look up real advisory row
    // -----------------------------------------------------------------------
    if (env.supabaseUrl && env.supabaseServiceRoleKey) {
      const baseUrl = env.supabaseUrl.replace(/\/$/, "");
      const dbHeaders = {
        apikey: env.supabaseServiceRoleKey,
        authorization: `Bearer ${env.supabaseServiceRoleKey}`
      };

      const res = await fetch(
        `${baseUrl}/rest/v1/advisories` +
        `?source_id=eq.${encodeURIComponent(cveId)}` +
        `&select=source_id,cisa_kev_date,exploit_maturity_score,published_at,updated_at` +
        `&limit=1`,
        { headers: dbHeaders }
      );

      if (!res.ok) {
        return c.json({ error: "Advisory lookup failed" }, 502);
      }

      const rows = await res.json() as Array<{
        source_id: string;
        cisa_kev_date: string | null;
        exploit_maturity_score: string | null;
        published_at: string | null;
        updated_at: string | null;
      }>;

      if (rows.length === 0) {
        return c.json({ error: "CVE not found" }, 404);
      }

      const row = rows[0]!;

      // Fetch affected versions from package_advisories join
      const paRes = await fetch(
        `${baseUrl}/rest/v1/package_advisories` +
        `?advisory_id=eq.${encodeURIComponent(row.source_id)}` +
        `&select=ecosystem,package_name,vulnerable_range,patched_version`,
        { headers: dbHeaders }
      );

      const paRows = paRes.ok
        ? (await paRes.json() as Array<{
            ecosystem: string;
            package_name: string;
            vulnerable_range: string | null;
            patched_version: string | null;
          }>)
        : [];

      const affectedVersions = paRows.map((pa) => pa.vulnerable_range ?? "unknown").filter(Boolean);

      return c.json({
        cveId: row.source_id,
        cisa_confirmed: row.cisa_kev_date !== null,
        first_seen_date: row.cisa_kev_date ?? null,
        exploit_maturity: row.exploit_maturity_score ?? null,
        affected_versions: affectedVersions
      });
    }

    // -----------------------------------------------------------------------
    // Local / dev mode: check against seeded sample advisories
    // -----------------------------------------------------------------------
    const advisories = await getServices(c).repository.getRecentAdvisories(200);
    const match = advisories.find(
      (a) => a.sourceId.toUpperCase() === cveId || a.source === "nvd" && a.sourceId.toUpperCase() === cveId
    );

    if (!match) {
      return c.json({ error: "CVE not found" }, 404);
    }

    const affectedVersions = (match.affectedPackages ?? [])
      .map((ap) => ap.vulnerableRange ?? "unknown")
      .filter(Boolean);

    return c.json({
      cveId: match.sourceId,
      cisa_confirmed: false,
      first_seen_date: null,
      exploit_maturity: null,
      affected_versions: affectedVersions
    });
  });

  // -----------------------------------------------------------------------
  // GET /binaries/:id/malware-analysis
  // Returns per-analyzer malware detection breakdowns for a specific binary.
  // The binary is located by scanning all stored package analyses for a
  // matching binary id.
  // -----------------------------------------------------------------------

  app.get("/binaries/:id/malware-analysis", async (c) => {
    const binaryId = c.req.param("id");
    const { repository } = getServices(c);

    // Search all indexed packages for a binary with this id.
    const searchResults = await repository.searchPackages();
    for (const item of searchResults.items) {
      const analysis = await repository.getPackage(item.ecosystem, item.packageName);
      if (!analysis) continue;

      const binary = analysis.binaries.find((b) => b.id === binaryId);
      if (!binary) continue;

      const malwareDetectionResults = binary.malwareDetectionResults ?? [];
      const anyDetected = malwareDetectionResults.some((r) => r.detected);
      const maxConfidence =
        malwareDetectionResults.length > 0
          ? Math.max(...malwareDetectionResults.map((r) => r.confidence))
          : 0;

      return c.json({
        binaryId: binary.id,
        filename: binary.filename,
        packageName: item.packageName,
        ecosystem: item.ecosystem,
        overallDetected: anyDetected,
        overallConfidence: maxConfidence,
        analyzerCount: malwareDetectionResults.length,
        analyzers: malwareDetectionResults.map((r) => ({
          analyzerName: r.analyzerName,
          analyzerVersion: r.analyzerVersion,
          detected: r.detected,
          confidence: r.confidence,
          signals: r.signals
        }))
      });
    }

    return c.json({ error: "Binary not found" }, 404);
  });

  // -----------------------------------------------------------------------
  // GET /packages/:ecosystem/:name/:version/pypi-build-analysis
  // Returns PyPI build system type and hook inventory for a package version.
  // Only meaningful for PyPI packages; returns 404 for non-PyPI packages that
  // have no build analysis recorded, and a structured empty result for PyPI
  // packages with no build config.
  // -----------------------------------------------------------------------

  app.get("/packages/:ecosystem/:name/:version/pypi-build-analysis", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const version = c.req.param("version");

    const analysis = await getServices(c).repository.getPackage(ecosystem, name, version);

    if (!analysis) {
      return c.json({ error: "Analysis not found" }, 404);
    }

    const manifest = analysis.manifestAnalysis;

    // For non-PyPI or packages with no manifest analysis, return a minimal
    // structured response so callers don't have to special-case missing fields.
    if (ecosystem !== "pypi" || !manifest) {
      return c.json({
        ecosystem,
        packageName: name,
        version,
        buildSystemType: "other",
        pythonBuildThreatDetails: {
          detectedHooks: [],
          cythonFiles: [],
          suspiciousPatterns: []
        }
      });
    }

    return c.json({
      ecosystem,
      packageName: name,
      version,
      buildSystemType: manifest.buildSystemType ?? "other",
      pythonBuildThreatDetails: manifest.pythonBuildThreatDetails ?? {
        detectedHooks: [],
        cythonFiles: [],
        suspiciousPatterns: []
      }
    });
  });

  // -----------------------------------------------------------------------
  // GET /packages/:ecosystem/:name/versions/:version/vulnerabilities/enriched
  // EPSS/CVE enrichment: fetches CVEs from advisories table, queries FIRST
  // EPSS API, checks CISA KEV membership, and returns a structured risk report.
  // -----------------------------------------------------------------------

  app.get("/packages/:ecosystem/:name/versions/:version/vulnerabilities/enriched", async (c) => {
    const ecosystem = c.req.param("ecosystem") as Ecosystem;
    const name = c.req.param("name");
    const version = c.req.param("version");

    const { env } = getServices(c);

    // Build the EPSS cache: use Supabase backing when credentials are available
    const epssCache = new EpssCache(
      env.supabaseUrl && env.supabaseServiceRoleKey
        ? { supabaseUrl: env.supabaseUrl, supabaseServiceRoleKey: env.supabaseServiceRoleKey }
        : undefined
    );

    if (env.supabaseUrl && env.supabaseServiceRoleKey) {
      // Supabase mode — use real advisory data from the DB
      const advisoryService = new AdvisoryService({
        supabaseUrl: env.supabaseUrl,
        supabaseServiceRoleKey: env.supabaseServiceRoleKey,
        githubToken: env.githubToken,
        nvdApiKey: env.nvdApiKey
      });

      try {
        const enrichment = await advisoryService.enrichCvesWithEpss(ecosystem, name, version, epssCache);
        return c.json(enrichment);
      } catch (err) {
        console.error(`[BinShield API] enrichCvesWithEpss failed for ${ecosystem}/${name}@${version}:`, err instanceof Error ? err.message : err);
        return c.json({ error: "Enrichment failed" }, 500);
      }
    }

    // Local/dev mode — use seeded advisory data with mocked EPSS (no live fetch)
    const advisories = await getServices(c).repository.getPackageAdvisories(ecosystem, name);

    const findings = advisories.map((advisory) => ({
      cvId: advisory.sourceId,
      title: advisory.title,
      severity: advisory.severity ?? "unknown",
      cvssScore: advisory.cvssScore,
      epssPercentile: undefined as number | undefined,
      cisaKevDate: undefined as string | undefined,
      exploitMaturity: undefined as string | undefined,
      recommendation: `Review ${advisory.sourceId} and apply the latest patched version.`
    }));

    const maxCvssV3Score = findings.reduce((max, f) => Math.max(max, f.cvssScore ?? 0), 0);
    const baseScore = Math.round((maxCvssV3Score / 10) * 100);

    return c.json({
      ecosystem,
      packageName: name,
      version,
      findings,
      maxEpssPercentile: 0,
      maxCvssV3Score,
      cisaKevMatches: [],
      exploitMaturityStats: { proofOfConcept: 0, activeExploitation: 0, widespread: 0 },
      riskBoost: { baseScore, epssBoost: 0, cisaKevBoost: 0, finalScore: baseScore },
      recommendations: findings.length > 0
        ? [`Review all listed advisories and upgrade to the patched version as soon as feasible.`]
        : ["No known CVEs found for this package version. Continue monitoring for new advisories."],
      enrichedAt: new Date().toISOString()
    });
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

    // Fetch packages in batches of 20 to avoid exhausting Supabase connection pool
    async function fetchInBatches(items: Array<{ ecosystem: Ecosystem; name: string }>): Promise<PackageAnalysis[]> {
      const results: PackageAnalysis[] = [];
      for (let i = 0; i < items.length; i += 20) {
        const batch = items.slice(i, i + 20);
        const fetched = await Promise.all(batch.map((item) => repository.getPackage(item.ecosystem, item.name)));
        for (const a of fetched) { if (a) results.push(a); }
      }
      return results;
    }

    let analyses: PackageAnalysis[];
    if (scope?.packageNames?.length) {
      analyses = await fetchInBatches(scope.packageNames.slice(0, 200).map((name) => ({ ecosystem: "npm" as Ecosystem, name })));
    } else {
      const searchResults = await repository.searchPackages();
      analyses = await fetchInBatches(searchResults.items.slice(0, 200).map((item) => ({ ecosystem: item.ecosystem, name: item.packageName })));
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

  // -----------------------------------------------------------------------
  // SBOM Provenance Verification — supply-chain resilience checks
  // POST /sbom/verify-provenance
  //
  // Accepts a CycloneDX SBOM and optional lockfile, fetches authoritative
  // registry metadata for every dependency, and returns per-package
  // provenance checks: registry-mismatch (HIGH), yanked-version (HIGH),
  // unresolved-dependency (MEDIUM).
  // -----------------------------------------------------------------------

  app.post("/sbom/verify-provenance", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return c.json({ error: "Request body must be a JSON object" }, 400);
    }

    const { sbomText, packageFormat, lockfileContent } = body as {
      sbomText?: unknown;
      packageFormat?: unknown;
      lockfileContent?: unknown;
    };

    if (typeof sbomText !== "string" || sbomText.trim().length === 0) {
      return c.json({ error: "Missing required field: sbomText (non-empty string)" }, 400);
    }

    if (packageFormat !== "npm" && packageFormat !== "pypi") {
      return c.json({ error: "packageFormat must be 'npm' or 'pypi'" }, 400);
    }

    if (lockfileContent !== undefined && typeof lockfileContent !== "string") {
      return c.json({ error: "lockfileContent must be a string if provided" }, 400);
    }

    // Size guard: 10 MB hard limit across sbomText + lockfileContent
    const totalSize = sbomText.length + (typeof lockfileContent === "string" ? lockfileContent.length : 0);
    if (totalSize > 10 * 1024 * 1024) {
      return c.json({ error: "Combined sbomText + lockfileContent exceeds 10 MB limit" }, 413);
    }

    let result;
    try {
      result = await verifySbomProvenance({
        sbomText,
        packageFormat,
        lockfileContent: typeof lockfileContent === "string" ? lockfileContent : undefined,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Provenance verification failed";
      return c.json({ error: message }, 400);
    }

    // Persist to sbom_provenance_audit_log (fire-and-forget, Supabase only)
    const { env } = getServices(c);
    if (env.supabaseUrl && env.supabaseServiceRoleKey) {
      const baseUrl = env.supabaseUrl.replace(/\/$/, "");
      fetch(`${baseUrl}/rest/v1/sbom_provenance_audit_log`, {
        method: "POST",
        headers: {
          apikey: env.supabaseServiceRoleKey,
          authorization: `Bearer ${env.supabaseServiceRoleKey}`,
          "content-type": "application/json",
          Prefer: "return=minimal",
        },
        body: JSON.stringify({
          package_format: packageFormat,
          is_valid: result.isValid,
          check_count: result.checks.length,
          failed_check_count: result.checks.filter((ch) => !ch.passed).length,
          risk_level: result.riskLevel,
          checks: result.checks,
          recommendations: result.recommendations,
          created_at: result.checkedAt,
        }),
      }).catch((err) => {
        console.error("[BinShield] Failed to persist provenance audit log:", err instanceof Error ? err.message : err);
      });
    }

    return c.json(result);
  });

  // -----------------------------------------------------------------------
  // GET /packages/:ecosystem/confusable/:name
  // Package name intelligence — returns Levenshtein + homoglyph + corpus
  // analysis for the given package name in the given ecosystem.
  // -----------------------------------------------------------------------

  // -----------------------------------------------------------------------
  // GET /orgs/:orgId/cve-heat-map?limit=100&ecosystem=npm|pypi|all
  // CVE/EPSS Risk Heat Map — top CVEs by exploitability × severity × adoption.
  // Returns HeatMapData: [{cveId, cvssScore, epssPercentile, heatScore, tier, …}]
  // -----------------------------------------------------------------------

  app.get("/orgs/:orgId/cve-heat-map", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const limitParam = Number.parseInt(c.req.query("limit") ?? "100", 10);
    const limit = Number.isFinite(limitParam) ? Math.min(Math.max(limitParam, 1), 200) : 100;
    const ecosystemParam = (c.req.query("ecosystem") ?? "npm").toLowerCase();
    const validEcosystems = ["npm", "pypi", "crates", "go", "all"];
    if (!validEcosystems.includes(ecosystemParam)) {
      return c.json({ error: `ecosystem must be one of: ${validEcosystems.join(", ")}` }, 400);
    }

    const { env } = getServices(c);

    // Fetch recent advisories — Supabase or local seeded data
    let advisories: import("./lib/types").Advisory[];
    if (env.supabaseUrl && env.supabaseServiceRoleKey) {
      const advisoryService = new AdvisoryService({
        supabaseUrl: env.supabaseUrl,
        supabaseServiceRoleKey: env.supabaseServiceRoleKey,
        githubToken: env.githubToken,
        nvdApiKey: env.nvdApiKey
      });
      advisories = await advisoryService.getRecentAdvisories(500);
    } else {
      // Local/dev mode — use in-memory seeded advisories
      advisories = await getServices(c).repository.getRecentAdvisories(500);
    }

    const heatMap = await getHeatMapData(
      {
        supabaseUrl: env.supabaseUrl ?? "",
        supabaseServiceRoleKey: env.supabaseServiceRoleKey ?? "",
        githubToken: env.githubToken,
        nvdApiKey: env.nvdApiKey
      },
      advisories,
      ecosystemParam,
      limit
    );

    return c.json(heatMap);
  });

  app.get("/packages/:ecosystem/confusable/:name", async (c) => {
    const rawEcosystem = c.req.param("ecosystem");
    const name = decodeURIComponent(c.req.param("name"));

    if (rawEcosystem !== "npm" && rawEcosystem !== "pypi") {
      return c.json(
        { error: "ecosystem must be 'npm' or 'pypi' for name intelligence checks" },
        400
      );
    }

    const ecosystem = rawEcosystem as PkgIntelEcosystem;

    if (!name || name.trim().length === 0) {
      return c.json({ error: "package name must not be empty" }, 400);
    }

    // Optional: caller can assert the name is present on both ecosystems
    const crossEcosystem = c.req.query("crossEcosystem") === "true";

    const intelligence = new PackageNameIntelligence();
    const result = intelligence.analyze(name, ecosystem, crossEcosystem);

    return c.json(result);
  });

  return app;
}

export const app = createApp();
