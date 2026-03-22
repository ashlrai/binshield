import { Hono } from "hono";
import type { Context } from "hono";
import { cors } from "hono/cors";

import { assertSameOrg, resolvePrincipal } from "./lib/auth";
import { readApiEnv } from "./lib/env";
import { createServices } from "./lib/repository";
import type { AppServices } from "./lib/repository";
import type { AuthPrincipal, Ecosystem } from "./lib/types";

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

export function createApp(services = createServices(readApiEnv())) {
  const app = new Hono<{ Variables: AppVariables }>();

  app.use("*", cors());
  app.use("*", async (c, next) => {
    c.set("services", services);
    c.set("auth", await resolvePrincipal(services.repository, c));
    await next();
  });
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
    const results = await getServices(c).repository.searchPackages(query);
    return c.json(results);
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

  app.post("/scans/packages", async (c) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "API key required" }, 401);
    }

    const body = await c.req.json();
    const validationError = requireBody<{ ecosystem: Ecosystem; packageName: string; version: string }>(body, [
      "ecosystem",
      "packageName",
      "version"
    ]);
    if (validationError) {
      return c.json({ error: validationError }, 400);
    }

    const job = await getServices(c).repository.submitScan(body, auth);
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

  app.post("/orgs/:orgId/repos", async (c) => {
    const orgId = c.req.param("orgId");
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
    return c.json(repo, 201);
  });

  app.get("/orgs/:orgId/watchlists", async (c) => {
    const orgId = c.req.param("orgId");
    const { error } = await getOrgAuth(c, orgId);
    if (error) {
      return c.json({ error: error.message }, error.status);
    }

    const items = await getServices(c).repository.listWatchlists(orgId);
    return c.json({ items });
  });

  app.post("/orgs/:orgId/watchlists", async (c) => {
    const orgId = c.req.param("orgId");
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
    return c.json(watchlist, 201);
  });

  app.post("/orgs/:orgId/watchlists/:watchlistId/packages", async (c) => {
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
    return c.json(apiKey, 201);
  });

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

    const checkout = await getServices(c).repository.createBillingCheckout(auth.orgId, body.plan);
    return c.json(checkout, 201);
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
