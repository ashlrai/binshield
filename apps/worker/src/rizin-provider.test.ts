import { describe, it, expect, vi, beforeEach } from "vitest";

import { RizinDecompilerProvider } from "./rizin-provider";
import type { FingerprintedArtifact } from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeArtifact(overrides: Partial<FingerprintedArtifact> = {}): FingerprintedArtifact {
  return {
    filename: "addon.node",
    relativePath: "build/Release/addon.node",
    absolutePath: "/tmp/test-pkg/build/Release/addon.node",
    sha256: "abc123",
    kind: "native-addon",
    format: "ELF",
    architecture: "x86_64",
    fileSize: 8192,
    bytes: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]), // ELF magic
    strings: ["libssl.so"],
    interestingStrings: ["connect", "getaddrinfo"],
    ...overrides,
  };
}

function makeRequest() {
  return {
    ecosystem: "npm" as const,
    packageName: "test-pkg",
    version: "1.0.0",
    packageRoot: "/tmp/test-pkg",
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("RizinDecompilerProvider — Docker unavailable", () => {
  beforeEach(() => {
    // Reset module-level docker availability cache between tests
    vi.restoreAllMocks();
  });

  it("returns a stub DecompiledArtifact instead of throwing when Docker is down", async () => {
    const provider = new RizinDecompilerProvider();

    // Force isAvailable() to report Docker as unavailable
    vi.spyOn(provider, "isAvailable").mockResolvedValue(false);

    const artifact = makeArtifact();
    const result = await provider.decompile({
      packageRequest: makeRequest(),
      packageRoot: "/tmp/test-pkg",
      artifact,
    });

    // Must not throw — we get a valid DecompiledArtifact back
    expect(result).toBeDefined();
    expect(typeof result.pseudoSource).toBe("string");
    expect(Array.isArray(result.imports)).toBe(true);
    expect(Array.isArray(result.strings)).toBe(true);
    expect(Array.isArray(result.callTargets)).toBe(true);
    expect(typeof result.functionCount).toBe("number");
    expect(result.functionCount).toBeGreaterThan(0);
    expect(typeof result.confidence).toBe("number");
  });

  it("stub confidence is lower than live rizin confidence (0.65)", async () => {
    const provider = new RizinDecompilerProvider();
    vi.spyOn(provider, "isAvailable").mockResolvedValue(false);

    const result = await provider.decompile({
      packageRequest: makeRequest(),
      packageRoot: "/tmp/test-pkg",
      artifact: makeArtifact(),
    });

    expect(result.confidence).toBeLessThan(0.65);
  });

  it("stub pseudoSource notes Docker was unavailable", async () => {
    const provider = new RizinDecompilerProvider();
    vi.spyOn(provider, "isAvailable").mockResolvedValue(false);

    const result = await provider.decompile({
      packageRequest: makeRequest(),
      packageRoot: "/tmp/test-pkg",
      artifact: makeArtifact(),
    });

    expect(result.pseudoSource).toContain("Docker unavailable");
  });

  it("stub infers network imports from artifact strings", async () => {
    const provider = new RizinDecompilerProvider();
    vi.spyOn(provider, "isAvailable").mockResolvedValue(false);

    const artifact = makeArtifact({ strings: ["curl", "http_get"] });
    const result = await provider.decompile({
      packageRequest: makeRequest(),
      packageRoot: "/tmp/test-pkg",
      artifact,
    });

    expect(result.imports).toContain("connect");
    expect(result.imports).toContain("getaddrinfo");
  });

  it("stub includes WASM import for WASM format artifacts", async () => {
    const provider = new RizinDecompilerProvider();
    vi.spyOn(provider, "isAvailable").mockResolvedValue(false);

    const artifact = makeArtifact({ format: "WASM", strings: [] });
    const result = await provider.decompile({
      packageRequest: makeRequest(),
      packageRoot: "/tmp/test-pkg",
      artifact,
    });

    expect(result.imports).toContain("wasm32_runtime_call");
  });

  it("triage still degrades gracefully — returns shouldEscalate:true with reason", async () => {
    const provider = new RizinDecompilerProvider();
    vi.spyOn(provider, "isAvailable").mockResolvedValue(false);

    const result = await provider.triage(makeArtifact());

    expect(result.shouldEscalate).toBe(true);
    expect(result.reasons).toContain("rizin unavailable");
  });
});
