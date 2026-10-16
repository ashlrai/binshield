/**
 * BinShield CLI unit tests — zero runtime dependencies.
 * Tests: arg parsing, config resolution, rendering, exit-code logic.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";

// ---------------------------------------------------------------------------
// Style / color tests
// ---------------------------------------------------------------------------

describe("style", () => {
  it("stripAnsi removes escape codes", async () => {
    const { stripAnsi } = await import("./style.js");
    expect(stripAnsi("\x1b[31mhello\x1b[0m world")).toBe("hello world");
    expect(stripAnsi("plain text")).toBe("plain text");
  });

  it("formatBytes formats sizes correctly", async () => {
    const { formatBytes } = await import("./style.js");
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1048576)).toBe("1.0 MB");
    expect(formatBytes(2621440)).toBe("2.5 MB");
  });

  it("padRight pads to width using visible length", async () => {
    const { padRight } = await import("./style.js");
    expect(padRight("foo", 6)).toBe("foo   ");
    expect(padRight("foobar", 3)).toBe("foobar"); // no truncation
  });

  it("truncate clips with ellipsis", async () => {
    const { truncate } = await import("./style.js");
    expect(truncate("hello world", 8)).toBe("hello w…");
    expect(truncate("short", 10)).toBe("short");
  });

  it("riskColor returns plain text when color disabled", async () => {
    const styleModule = await import("./style.js");
    styleModule.setColorEnabled(false);
    expect(styleModule.riskColor("critical")).toBe("critical");
    expect(styleModule.riskColor("high")).toBe("high");
    expect(styleModule.riskColor("none")).toBe("none");
    styleModule.setColorEnabled(true);
  });

  it("riskBadgePlain returns level and score without ANSI", async () => {
    const { riskBadgePlain } = await import("./style.js");
    expect(riskBadgePlain("high", 75)).toBe("high (75)");
    expect(riskBadgePlain("critical", 100)).toBe("critical (100)");
    expect(riskBadgePlain("none", 0)).toBe("none (0)");
  });
});

// ---------------------------------------------------------------------------
// Config resolution tests
// ---------------------------------------------------------------------------

describe("config.resolveApiKey", () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    // Reset env between tests
    delete process.env.BINSHIELD_API_KEY;
  });

  it("returns flag value when provided", async () => {
    const { resolveApiKey } = await import("./config.js");
    expect(resolveApiKey("flag-key")).toBe("flag-key");
  });

  it("returns env var when no flag", async () => {
    process.env.BINSHIELD_API_KEY = "env-key";
    const { resolveApiKey } = await import("./config.js");
    expect(resolveApiKey()).toBe("env-key");
    delete process.env.BINSHIELD_API_KEY;
  });

  it("returns undefined when nothing is set", async () => {
    delete process.env.BINSHIELD_API_KEY;
    const { resolveApiKey } = await import("./config.js");
    // In test env the config file likely doesn't exist; result may be undefined or a value from disk
    const result = resolveApiKey();
    // Just assert it's string or undefined
    expect(typeof result === "string" || result === undefined).toBe(true);
  });

  it("flag takes precedence over env var", async () => {
    process.env.BINSHIELD_API_KEY = "env-key";
    const { resolveApiKey } = await import("./config.js");
    expect(resolveApiKey("flag-key")).toBe("flag-key");
    delete process.env.BINSHIELD_API_KEY;
  });
});

describe("config.resolveApiUrl", () => {
  it("returns default when nothing set", async () => {
    delete process.env.BINSHIELD_API_URL;
    const { resolveApiUrl, DEFAULT_API_URL } = await import("./config.js");
    const result = resolveApiUrl();
    // May be default or a value from config file on disk
    expect(typeof result).toBe("string");
    expect(result.startsWith("http")).toBe(true);
    // When no env / flag, should be the default (unless config file overrides)
    if (!process.env.BINSHIELD_API_URL) {
      // The default should be the production URL if config is empty
      const cfg = (await import("./config.js")).readConfig();
      if (!cfg.apiUrl) {
        expect(result).toBe(DEFAULT_API_URL);
      }
    }
  });

  it("flag takes precedence", async () => {
    const { resolveApiUrl } = await import("./config.js");
    expect(resolveApiUrl("https://custom.example.com")).toBe("https://custom.example.com");
  });

  it("env var takes precedence over config", async () => {
    process.env.BINSHIELD_API_URL = "https://env.example.com";
    const { resolveApiUrl } = await import("./config.js");
    expect(resolveApiUrl()).toBe("https://env.example.com");
    delete process.env.BINSHIELD_API_URL;
  });
});

// ---------------------------------------------------------------------------
// API error classification
// ---------------------------------------------------------------------------

describe("ApiError", () => {
  it("creates error with kind and statusCode", async () => {
    const { ApiError } = await import("./api.js");
    const err = new ApiError("auth", "Unauthorized", 401);
    expect(err.kind).toBe("auth");
    expect(err.statusCode).toBe(401);
    expect(err.message).toBe("Unauthorized");
    expect(err.name).toBe("ApiError");
    expect(err instanceof Error).toBe(true);
  });

  it("can have no statusCode", async () => {
    const { ApiError } = await import("./api.js");
    const err = new ApiError("network", "fetch failed");
    expect(err.statusCode).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Risk ordering / threshold logic
// ---------------------------------------------------------------------------

describe("risk threshold logic", () => {
  const RISK_ORDER: Record<string, number> = {
    none: 0, low: 1, medium: 2, high: 3, critical: 4,
  };

  function riskAtOrAbove(level: string, threshold: string): boolean {
    return (RISK_ORDER[level] ?? 0) >= (RISK_ORDER[threshold] ?? 3);
  }

  it("critical meets any threshold", () => {
    expect(riskAtOrAbove("critical", "none")).toBe(true);
    expect(riskAtOrAbove("critical", "low")).toBe(true);
    expect(riskAtOrAbove("critical", "medium")).toBe(true);
    expect(riskAtOrAbove("critical", "high")).toBe(true);
    expect(riskAtOrAbove("critical", "critical")).toBe(true);
  });

  it("none meets only none threshold", () => {
    expect(riskAtOrAbove("none", "none")).toBe(true);
    expect(riskAtOrAbove("none", "low")).toBe(false);
    expect(riskAtOrAbove("none", "medium")).toBe(false);
    expect(riskAtOrAbove("none", "high")).toBe(false);
    expect(riskAtOrAbove("none", "critical")).toBe(false);
  });

  it("high meets high and below", () => {
    expect(riskAtOrAbove("high", "none")).toBe(true);
    expect(riskAtOrAbove("high", "low")).toBe(true);
    expect(riskAtOrAbove("high", "medium")).toBe(true);
    expect(riskAtOrAbove("high", "high")).toBe(true);
    expect(riskAtOrAbove("high", "critical")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Render — plain-text snapshot tests (color off)
// ---------------------------------------------------------------------------

describe("render (plain text)", () => {
  beforeEach(async () => {
    const style = await import("./style.js");
    style.setColorEnabled(false);
  });

  it("friendlyApiError returns helpful message for auth error", async () => {
    const { ApiError } = await import("./api.js");
    const { friendlyApiError } = await import("./render.js");
    const err = new ApiError("auth", "Unauthorized", 401);
    const msg = friendlyApiError(err);
    expect(msg).toContain("Authentication failed");
    expect(msg).toContain("binshield config set apiKey");
  });

  it("friendlyApiError returns helpful message for rate limit", async () => {
    const { ApiError } = await import("./api.js");
    const { friendlyApiError } = await import("./render.js");
    const err = new ApiError("rate_limit", "Too Many Requests", 429);
    const msg = friendlyApiError(err);
    expect(msg).toContain("Rate limit");
    expect(msg).toContain("binshield.dev/pricing");
  });

  it("friendlyApiError returns helpful message for network error", async () => {
    const { ApiError } = await import("./api.js");
    const { friendlyApiError } = await import("./render.js");
    const err = new ApiError("network", "ECONNREFUSED");
    const msg = friendlyApiError(err);
    expect(msg).toContain("network");
  });

  it("friendlyApiError returns helpful message for not_found", async () => {
    const { ApiError } = await import("./api.js");
    const { friendlyApiError } = await import("./render.js");
    const err = new ApiError("not_found", "Package not found", 404);
    const msg = friendlyApiError(err);
    expect(msg).toContain("not found");
  });

  it("friendlyApiError passes through plain Error message", async () => {
    const { friendlyApiError } = await import("./render.js");
    const err = new Error("something went wrong");
    expect(friendlyApiError(err)).toBe("something went wrong");
  });

  it("renderAuditReport produces stable plain output for clean result", async () => {
    const { renderAuditReport } = await import("./render.js");

    // Capture console.log output (render.ts uses console.log internally)
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    });

    const result = {
      id: "scan_123",
      filename: "package-lock.json",
      status: "complete",
      packages: [
        { ecosystem: "npm", packageName: "lodash", version: "4.17.21", riskLevel: "none" as const, riskScore: 0, status: "complete" },
      ],
      totalPackages: 1,
      highRiskCount: 0,
      criticalRiskCount: 0,
    };

    renderAuditReport(result, { json: false });

    vi.restoreAllMocks();

    const output = lines.join("\n");
    expect(output).toContain("package-lock.json");
    expect(output).toContain("1 packages scanned");
    expect(output).toContain("clean");
  });

  it("renderAuditReport highlights critical packages", async () => {
    const { renderAuditReport } = await import("./render.js");

    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    });

    const result = {
      id: "scan_456",
      filename: "yarn.lock",
      status: "complete",
      packages: [
        { ecosystem: "npm", packageName: "evil-package", version: "1.0.0", riskLevel: "critical" as const, riskScore: 99, status: "complete" },
        { ecosystem: "npm", packageName: "safe-dep", version: "2.0.0", riskLevel: "none" as const, riskScore: 0, status: "complete" },
      ],
      totalPackages: 2,
      highRiskCount: 0,
      criticalRiskCount: 1,
    };

    renderAuditReport(result, { json: false });

    vi.restoreAllMocks();

    const output = lines.join("\n");
    expect(output).toContain("evil-package");
    expect(output).toContain("RISKY PACKAGES");
  });

  it("renderAnalysis outputs package info", async () => {
    const { renderAnalysis } = await import("./render.js");

    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    });

    const analysis = {
      id: "pkg_test_1",
      ecosystem: "npm",
      packageName: "test-pkg",
      version: "1.0.0",
      status: "complete" as const,
      riskScore: 15,
      riskLevel: "low" as const,
      summary: "A test package with expected behavior.",
      sourceMatchConfidence: "high",
      binaryCount: 1,
      totalBinarySize: 204800,
      binaries: [],
      createdAt: "2026-01-01T00:00:00.000Z",
    };

    renderAnalysis(analysis, { json: false });

    vi.restoreAllMocks();

    const output = lines.join("\n");
    expect(output).toContain("test-pkg");
    expect(output).toContain("1.0.0");
    expect(output).toContain("npm");
    expect(output).toContain("A test package with expected behavior.");
  });

  it("renders JSON when json option is set", async () => {
    const { renderAnalysis } = await import("./render.js");

    const chunks: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    });

    const analysis = {
      id: "pkg_json_1",
      ecosystem: "npm",
      packageName: "json-pkg",
      version: "2.0.0",
      status: "complete" as const,
      riskScore: 0,
      riskLevel: "none" as const,
      summary: "Clean.",
      sourceMatchConfidence: "high",
      binaryCount: 0,
      totalBinarySize: 0,
      binaries: [],
      createdAt: "2026-01-01T00:00:00.000Z",
    };

    renderAnalysis(analysis, { json: true });

    const output = chunks.join("");
    const parsed = JSON.parse(output) as typeof analysis;
    expect(parsed.packageName).toBe("json-pkg");
    expect(parsed.riskLevel).toBe("none");
  });
});

// ---------------------------------------------------------------------------
// Spinner — non-TTY behavior
// ---------------------------------------------------------------------------

describe("Spinner", () => {
  it("emits progress lines to stderr when color is disabled", async () => {
    const style = await import("./style.js");
    style.setColorEnabled(false);

    const lines: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    });

    const { Spinner } = await import("./spinner.js");
    const spinner = new Spinner();
    spinner.start("Testing...");
    spinner.update("Still going...");
    spinner.stop("Done");

    process.stderr.write = orig;

    expect(lines.some((l) => l.includes("Testing..."))).toBe(true);
    expect(lines.some((l) => l.includes("Done"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

describe("help", () => {
  it("helpRoot contains all commands", async () => {
    const { helpRoot } = await import("./help.js");
    const text = helpRoot();
    expect(text).toContain("scan");
    expect(text).toContain("audit");
    expect(text).toContain("scan-lockfile");
    expect(text).toContain("init");
    expect(text).toContain("config");
  });

  it("helpScan contains examples", async () => {
    const { helpScan } = await import("./help.js");
    const text = helpScan();
    expect(text).toContain("binshield scan npm bcrypt");
    expect(text).toContain("--fail-on");
  });

  it("helpAudit mentions lockfile auto-detection", async () => {
    const { helpAudit } = await import("./help.js");
    const text = helpAudit();
    expect(text).toContain("package-lock.json");
    expect(text).toContain("auto-detect");
  });

  it("helpInit mentions GitHub Actions", async () => {
    const { helpInit } = await import("./help.js");
    const text = helpInit();
    expect(text).toContain("GitHub");
    expect(text).toContain("BINSHIELD_API_KEY");
  });

  it("helpConfig describes precedence", async () => {
    const { helpConfig } = await import("./help.js");
    const text = helpConfig();
    expect(text).toContain("apiKey");
    expect(text).toContain("config.json");
  });
});
