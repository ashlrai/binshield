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

  // ---------------------------------------------------------------------------
  // Public scan
  // ---------------------------------------------------------------------------

  it("allows anonymous public scan without API key", async () => {
    const response = await app.request("/public/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" })
    });
    // LocalRepository has bcrypt pre-seeded, so it returns 200 complete
    expect([200, 202]).toContain(response.status);
    const body = await response.json();
    expect(body.id).toBeTruthy();
    expect(body.status).toMatch(/^(queued|complete)$/);
  });

  it("rejects invalid ecosystem on public scan", async () => {
    const response = await app.request("/public/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ecosystem: "rubygems", packageName: "bcrypt", version: "1.0.0" })
    });
    expect(response.status).toBe(400);
  });

  // ---------------------------------------------------------------------------
  // Finding suppressions
  // ---------------------------------------------------------------------------

  it("creates, lists, and deletes a suppression", async () => {
    // Create
    const createRes = await app.request("/orgs/org_demo/suppressions", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "bcrypt",
        reason: "false positive — internal audit confirmed benign"
      })
    });
    expect(createRes.status).toBe(201);
    const created = await createRes.json();
    expect(created.id).toBeTruthy();
    expect(created.packageName).toBe("bcrypt");

    // List
    const listRes = await app.request("/orgs/org_demo/suppressions", { headers });
    expect(listRes.status).toBe(200);
    const listed = await listRes.json();
    expect(listed.items.length).toBeGreaterThan(0);
    expect(listed.items.some((s: { id: string }) => s.id === created.id)).toBe(true);

    // Delete
    const deleteRes = await app.request(`/orgs/org_demo/suppressions/${created.id}`, {
      method: "DELETE",
      headers
    });
    expect(deleteRes.status).toBe(200);

    // Confirm removed
    const listAfter = await app.request("/orgs/org_demo/suppressions", { headers });
    const afterBody = await listAfter.json();
    expect(afterBody.items.some((s: { id: string }) => s.id === created.id)).toBe(false);
  });

  it("requires auth for suppression endpoints", async () => {
    const res = await app.request("/orgs/org_demo/suppressions", {
      headers: { "Content-Type": "application/json" }
    });
    expect(res.status).toBe(401);
  });

  it("filters suppressed findings from package analysis", async () => {
    // Use a fresh app instance to avoid cross-test suppression state
    const freshApp = createApp();

    // Get unfiltered analysis — findings live on binaries
    const before = await freshApp.request("/packages/npm/bcrypt/versions/5.1.1", { headers });
    expect(before.status).toBe(200);
    const beforeBody = await before.json();

    // Find a binary that has findings
    const binaryWithFindings = (beforeBody.binaries ?? []).find(
      (b: { findings?: unknown[] }) => (b.findings ?? []).length > 0
    );

    if (binaryWithFindings) {
      const firstFinding = binaryWithFindings.findings[0] as { title: string };
      const originalCount = binaryWithFindings.findings.length;

      // Create a suppression targeting the first finding's title
      await freshApp.request("/orgs/org_demo/suppressions", {
        method: "POST",
        headers,
        body: JSON.stringify({
          ecosystem: "npm",
          packageName: "bcrypt",
          findingTitle: firstFinding.title,
          reason: "test suppression"
        })
      });

      // The filtered response should have one fewer finding on that binary
      const after = await freshApp.request("/packages/npm/bcrypt/versions/5.1.1", { headers });
      const afterBody = await after.json();
      const filteredBinary = (afterBody.binaries ?? []).find(
        (b: { id: string }) => b.id === binaryWithFindings.id
      ) as { findings?: unknown[] } | undefined;
      expect((filteredBinary?.findings ?? []).length).toBe(originalCount - 1);
    }
  });
});

describe("suppression repository methods", () => {
  it("round-trips create / list / delete on LocalRepository", async () => {
    const app2 = createApp();

    const createRes = await app2.request("/orgs/org_demo/suppressions", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "lodash",
        version: "4.17.21",
        findingCategory: "network",
        findingTitle: "unexpected outbound connection",
        reason: "confirmed false positive"
      })
    });
    expect(createRes.status).toBe(201);
    const s = await createRes.json();
    expect(s.version).toBe("4.17.21");
    expect(s.findingCategory).toBe("network");

    const listRes = await app2.request("/orgs/org_demo/suppressions", { headers });
    const { items } = await listRes.json();
    expect(items.length).toBe(1);

    const delRes = await app2.request(`/orgs/org_demo/suppressions/${s.id}`, {
      method: "DELETE",
      headers
    });
    expect(delRes.status).toBe(200);

    const listAfter = await app2.request("/orgs/org_demo/suppressions", { headers });
    const { items: afterItems } = await listAfter.json();
    expect(afterItems.length).toBe(0);
  });
});
