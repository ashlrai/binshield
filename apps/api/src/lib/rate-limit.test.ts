import { describe, expect, it } from "vitest";
import { Hono } from "hono";

import { rateLimitByIp } from "./rate-limit";

describe("rate-limit", () => {
  it("allows requests within limit", async () => {
    const app = new Hono();
    app.use("*", rateLimitByIp({ windowMs: 60_000, max: 5 }));
    app.get("/test", (c) => c.json({ ok: true }));

    const res = await app.request("/test", {
      headers: { "x-forwarded-for": "1.2.3.4" },
    });
    expect(res.status).toBe(200);
  });

  it("returns 429 when limit exceeded", async () => {
    const app = new Hono();
    app.use("*", rateLimitByIp({ windowMs: 60_000, max: 3 }));
    app.get("/test", (c) => c.json({ ok: true }));

    // Use a unique IP to avoid interference from other tests
    const ip = `10.0.0.${Math.floor(Math.random() * 255)}`;

    for (let i = 0; i < 3; i++) {
      const res = await app.request("/test", {
        headers: { "x-forwarded-for": ip },
      });
      expect(res.status).toBe(200);
    }

    const res = await app.request("/test", {
      headers: { "x-forwarded-for": ip },
    });
    expect(res.status).toBe(429);
    const body = await res.json();
    expect(body.error).toBe("Rate limit exceeded");
    expect(body.retryAfter).toBeGreaterThan(0);
    expect(res.headers.get("Retry-After")).toBeTruthy();
  });

  it("allows different IPs independently", async () => {
    const app = new Hono();
    app.use("*", rateLimitByIp({ windowMs: 60_000, max: 1 }));
    app.get("/test", (c) => c.json({ ok: true }));

    const ip1 = `192.168.1.${Math.floor(Math.random() * 255)}`;
    const ip2 = `192.168.2.${Math.floor(Math.random() * 255)}`;

    const res1 = await app.request("/test", {
      headers: { "x-forwarded-for": ip1 },
    });
    expect(res1.status).toBe(200);

    const res2 = await app.request("/test", {
      headers: { "x-forwarded-for": ip2 },
    });
    expect(res2.status).toBe(200);
  });
});
