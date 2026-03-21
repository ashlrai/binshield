import { describe, expect, it } from "vitest";

import { app } from "./app";

describe("api", () => {
  it("returns search results", async () => {
    const response = await app.request("/packages/search?q=bcrypt");
    expect(response.status).toBe(200);

    const body = await response.json();
    expect(body.total).toBeGreaterThan(0);
  });

  it("creates a scan job", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
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
});
