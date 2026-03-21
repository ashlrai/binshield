import { afterEach, describe, expect, it, vi } from "vitest";

import { BinShieldClient } from "./client";

function response(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: async () => body
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("submits and polls scans until complete", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        response({
          id: "job_1",
          status: "queued",
          requestedAt: "2026-03-21T00:00:00.000Z",
          request: { ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" }
        })
      )
      .mockResolvedValueOnce(
        response({
          id: "job_1",
          status: "analyzing",
          requestedAt: "2026-03-21T00:00:00.000Z",
          request: { ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" }
        })
      )
      .mockResolvedValueOnce(
        response({
          id: "job_1",
          status: "complete",
          requestedAt: "2026-03-21T00:00:00.000Z",
          completedAt: "2026-03-21T00:00:01.000Z",
          request: { ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" },
          result: {
            id: "pkg_bcrypt_5_1_1",
            ecosystem: "npm",
            packageName: "bcrypt",
            version: "5.1.1",
            status: "complete",
            riskScore: 12,
            riskLevel: "low",
            summary: "Standard bcrypt native addon",
            sourceMatchConfidence: "high",
            binaryCount: 1,
            totalBinarySize: 198451,
            aiModel: "claude",
            createdAt: "2026-03-21T00:00:01.000Z",
            binaries: []
          }
        })
      );

    vi.stubGlobal("fetch", fetchMock);

    const client = new BinShieldClient({
      apiBaseUrl: "https://api.example.test",
      pollIntervalMs: 0,
      timeoutMs: 1000
    });

    const job = await client.submitScan({
      ecosystem: "npm",
      packageName: "bcrypt",
      version: "5.1.1"
    });

    const result = await client.waitForResult(job);
    expect(result.packageName).toBe("bcrypt");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("fails on scan errors", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      response(
        {
          id: "job_2",
          status: "failed",
          requestedAt: "2026-03-21T00:00:00.000Z",
          request: { ecosystem: "npm", packageName: "sharp", version: "0.33.2" },
          error: "worker error"
        },
        200
      )
    );

    vi.stubGlobal("fetch", fetchMock);

    const client = new BinShieldClient({
      apiBaseUrl: "https://api.example.test",
      pollIntervalMs: 0,
      timeoutMs: 1000
    });

    await expect(
      client.waitForResult({
        id: "job_2",
        status: "failed",
        requestedAt: "2026-03-21T00:00:00.000Z",
        request: { ecosystem: "npm", packageName: "sharp", version: "0.33.2" },
        error: "worker error"
      })
    ).rejects.toThrow("worker error");
  });
});
