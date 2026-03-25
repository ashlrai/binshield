import { beforeEach, describe, expect, it } from "vitest";

import { createApp } from "./app";
import { app } from "./app";

const headers = {
  "Content-Type": "application/json",
  "x-binshield-api-key": "binshield-dev-key"
};

describe("api", () => {
  beforeEach(() => {});

  it("returns search results", async () => {
    const response = await app.request("/packages/search?q=bcrypt");
    expect(response.status).toBe(200);

    const body = await response.json();
    expect(body.total).toBeGreaterThan(0);
  });

  it("supports search pagination", async () => {
    const response = await app.request("/packages/search?limit=1&offset=0");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.items.length).toBeLessThanOrEqual(1);
    expect(body.total).toBeGreaterThan(0);
  });

  it("creates a scan job with api key auth", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "bcrypt",
        version: "5.1.1"
      })
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("complete");
  });

  it("rejects invalid ecosystem on scan", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "rubygems",
        packageName: "bcrypt",
        version: "5.1.1"
      })
    });

    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toContain("Invalid ecosystem");
  });

  it("requires auth for scan endpoints", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" })
    });
    expect(response.status).toBe(401);
  });

  it("creates org-scoped resources", async () => {
    const watchlistResponse = await app.request("/orgs/org_demo/watchlists", {
      method: "POST",
      headers,
      body: JSON.stringify({
        name: "Runtime dependencies",
        channel: "email",
        destination: "security@binshield.dev"
      })
    });

    expect(watchlistResponse.status).toBe(201);
    const watchlist = await watchlistResponse.json();
    expect(watchlist.name).toBe("Runtime dependencies");

    const subscriptionResponse = await app.request("/orgs/org_demo/subscription", {
      method: "POST",
      headers,
      body: JSON.stringify({
        plan: "pro",
        status: "active"
      })
    });

    expect(subscriptionResponse.status).toBe(200);
    const subscription = await subscriptionResponse.json();
    expect(subscription.plan).toBe("pro");
  });

  it("creates and revokes an API key", async () => {
    const createResponse = await app.request("/orgs/org_demo/api-keys", {
      method: "POST",
      headers,
      body: JSON.stringify({ label: "test-key" })
    });

    expect(createResponse.status).toBe(201);
    const created = await createResponse.json();
    expect(created.plaintextKey).toBeTruthy();
    expect(created.summary.label).toBe("test-key");

    // Revoke the key
    const revokeResponse = await app.request(`/orgs/org_demo/api-keys/${created.summary.id}`, {
      method: "DELETE",
      headers,
    });
    expect(revokeResponse.status).toBe(200);

    // Revoking again should 404
    const revokeAgain = await app.request(`/orgs/org_demo/api-keys/${created.summary.id}`, {
      method: "DELETE",
      headers,
    });
    expect(revokeAgain.status).toBe(404);
  });

  it("returns package advisories", async () => {
    const response = await app.request("/packages/npm/bcrypt/advisories");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.items.length).toBeGreaterThan(0);
    expect(body.items[0].title).toBeTruthy();
  });

  it("returns recent advisories", async () => {
    const response = await app.request("/advisories/recent?limit=3");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.items.length).toBeLessThanOrEqual(3);
    expect(body.items.length).toBeGreaterThan(0);
  });

  it("generates SBOM for a package", async () => {
    const response = await app.request("/packages/npm/bcrypt/versions/5.1.1/sbom");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.bomFormat).toBe("CycloneDX");
    expect(body.specVersion).toBe("1.5");
    expect(body.components.length).toBeGreaterThan(0);
  });

  it("enforces feature gate on compliance reports", async () => {
    const response = await app.request("/orgs/org_demo/reports", {
      method: "POST",
      headers,
      body: JSON.stringify({ reportType: "soc2" })
    });
    // Demo org is on "free" plan, compliance_reports requires "enterprise"
    expect(response.status).toBe(403);
    const body = await response.json();
    expect(body.error).toContain("compliance_reports");
  });

  it("rejects unrecognized lockfile format", async () => {
    const response = await app.request("/scans/lockfile", {
      method: "POST",
      headers,
      body: JSON.stringify({ filename: "random.txt", content: "hello world" })
    });
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toContain("Unrecognized lockfile format");
  });
});
