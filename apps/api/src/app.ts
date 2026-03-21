import { Hono } from "hono";
import { cors } from "hono/cors";

import { store } from "./store";

export const app = new Hono();

app.use("*", cors());

app.get("/health", (c) => c.json({ ok: true, service: "binshield-api" }));

app.get("/packages/search", (c) => {
  const query = c.req.query("q");
  return c.json(store.search(query));
});

app.get("/packages/:ecosystem/:name", (c) => {
  const pkg = c.req.param("name");
  const versions = store.getVersions(pkg);
  if (versions.length === 0) {
    return c.json({ error: "Package not found" }, 404);
  }

  return c.json({
    packageName: pkg,
    ecosystem: c.req.param("ecosystem"),
    versions
  });
});

app.get("/packages/:ecosystem/:name/versions/:version", (c) => {
  const analysis = store.getPackage(c.req.param("name"), c.req.param("version"));
  if (!analysis) {
    return c.json({ error: "Analysis not found" }, 404);
  }

  return c.json(analysis);
});

app.get("/packages/:ecosystem/:name/diff", (c) => {
  return c.json(store.getDiff());
});

app.post("/scans/packages", async (c) => {
  const payload = await c.req.json();
  const job = store.submitScan(payload);
  return c.json(job, job.status === "complete" ? 200 : 202);
});

app.get("/scans/:id", (c) => {
  const job = store.getJob(c.req.param("id"));
  if (!job) {
    return c.json({ error: "Scan not found" }, 404);
  }
  return c.json(job);
});

app.get("/orgs/:orgId/repos", (c) => {
  return c.json({
    items: store.listRepos(c.req.param("orgId"))
  });
});

app.post("/orgs/:orgId/repos", async (c) => {
  const payload = await c.req.json();
  const repo = store.createRepo(c.req.param("orgId"), payload.githubRepo);
  return c.json(repo, 201);
});
