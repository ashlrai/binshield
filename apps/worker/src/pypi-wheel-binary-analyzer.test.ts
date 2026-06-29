/**
 * Tests for pypi-wheel-binary-analyzer.ts
 *
 * Covers:
 *  1.  parseWheelAbiTag — wheel filename parsing + ABI tag components
 *  2.  isCompiledWheel — compiled vs pure-Python wheel detection
 *  3.  selectBestWheel — CPython preference, abi3 fallback, pure-Python last
 *  4.  detectWheelOnlyPackage — sdist vs wheel-only detection (mocked fetch)
 *  5.  analyzeWheelBinaries — extraction + binary pipeline (fixture-based)
 *  6.  analyzeWheelOnlyPackage — end-to-end convenience wrapper (mocked fetch)
 *  7.  Malformed wheel handling — missing files, bad zips, oversized wheels
 *  8.  Architecture/platform tag round-trip in findings output
 *  9.  ScriptFinding wheelNativeBinary category integration
 * 10.  SCRIPT_THREAT_CATEGORIES contains wheelNativeBinary (types package)
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { createWriteStream } from "node:fs";
import { execFile } from "node:child_process";

import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";

import {
  parseWheelAbiTag,
  isCompiledWheel,
  selectBestWheel,
  detectWheelOnlyPackage,
  analyzeWheelBinaries,
  analyzeWheelOnlyPackage,
  computeWheelBinaryFingerprint,
  buildFingerprintData,
  type WheelAbiTag,
  type WheelBinaryAnalysis,
  type WheelBinaryFingerprintData,
} from "./pypi-wheel-binary-analyzer";

import { SCRIPT_THREAT_CATEGORIES } from "@binshield/analysis-types";

const execFileAsync = promisify(execFile);
const gzip = promisify(zlib.gzip);

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../fixtures"
);

// ---------------------------------------------------------------------------
// Helpers — minimal zip builder for creating test wheels in-memory
// ---------------------------------------------------------------------------

/**
 * Builds a minimal zip archive (which is all a .whl file is) from a list of
 * in-memory entries.  This is intentionally minimal: it uses the DEFLATE
 * stored format (store-only, no compression) so we avoid requiring any zip
 * library and can test unzip extraction without extra deps.
 *
 * We use Node's built-in execFile("zip") when available, otherwise fall back
 * to a very simple stored-entry zip builder we construct manually.
 */

/**
 * Write a minimal zip using a temp dir + the system `zip` command.
 * Returns the zip bytes as a Buffer.
 */
async function buildZip(
  entries: Array<{ name: string; content: Buffer }>
): Promise<Buffer> {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "bswheeltest-"));
  try {
    for (const entry of entries) {
      const entryPath = path.join(tempDir, entry.name);
      await mkdir(path.dirname(entryPath), { recursive: true });
      await writeFile(entryPath, entry.content);
    }
    const zipPath = path.join(tempDir, "archive.zip");
    const names = entries.map((e) => e.name);
    await execFileAsync("zip", ["-q", "-r", zipPath, ...names], { cwd: tempDir });
    const { readFile } = await import("node:fs/promises");
    return await readFile(zipPath);
  } finally {
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Temp-dir lifecycle
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "binshield-wba-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// 1. parseWheelAbiTag
// ---------------------------------------------------------------------------

describe("parseWheelAbiTag — wheel filename parsing", () => {
  it("parses a CPython manylinux wheel (numpy)", () => {
    const tag = parseWheelAbiTag(
      "numpy-1.26.4-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    );
    expect(tag).not.toBeNull();
    expect(tag!.pythonTag).toBe("cp311");
    expect(tag!.abiTag).toBe("cp311");
    expect(tag!.platformTag).toMatch(/manylinux/);
    expect(tag!.label).toMatch(/numpy.*cp311/);
  });

  it("parses a CPython linux_x86_64 wheel (cryptography)", () => {
    const tag = parseWheelAbiTag("cryptography-41.0.5-cp311-cp311-linux_x86_64.whl");
    expect(tag).not.toBeNull();
    expect(tag!.pythonTag).toBe("cp311");
    expect(tag!.abiTag).toBe("cp311");
    expect(tag!.platformTag).toBe("linux_x86_64");
    expect(tag!.label).toMatch(/cryptography.*cp311.*linux_x86_64/);
    expect(tag!.filename).toBe("cryptography-41.0.5-cp311-cp311-linux_x86_64.whl");
  });

  it("parses a stable abi3 wheel (lxml)", () => {
    const tag = parseWheelAbiTag("lxml-4.9.3-cp36-abi3-linux_x86_64.whl");
    expect(tag).not.toBeNull();
    expect(tag!.abiTag).toBe("abi3");
    expect(tag!.pythonTag).toBe("cp36");
  });

  it("parses a macOS wheel", () => {
    const tag = parseWheelAbiTag(
      "numpy-1.26.4-cp311-cp311-macosx_10_9_x86_64.whl"
    );
    expect(tag).not.toBeNull();
    expect(tag!.platformTag).toMatch(/macosx/);
  });

  it("parses a Windows win_amd64 wheel", () => {
    const tag = parseWheelAbiTag("numpy-1.26.4-cp311-cp311-win_amd64.whl");
    expect(tag).not.toBeNull();
    expect(tag!.platformTag).toBe("win_amd64");
  });

  it("parses a pure-Python py3-none-any wheel", () => {
    const tag = parseWheelAbiTag("requests-2.31.0-py3-none-any.whl");
    expect(tag).not.toBeNull();
    expect(tag!.abiTag).toBe("none");
    expect(tag!.platformTag).toBe("any");
  });

  it("returns null for a non-.whl filename", () => {
    expect(parseWheelAbiTag("numpy-1.26.4.tar.gz")).toBeNull();
  });

  it("returns null for a filename with too few dash-separated parts", () => {
    expect(parseWheelAbiTag("bad.whl")).toBeNull();
    expect(parseWheelAbiTag("a-b.whl")).toBeNull();
  });

  it("includes the original filename in the result", () => {
    const filename = "cryptography-41.0.5-cp311-cp311-linux_x86_64.whl";
    const tag = parseWheelAbiTag(filename);
    expect(tag?.filename).toBe(filename);
  });
});

// ---------------------------------------------------------------------------
// 2. isCompiledWheel
// ---------------------------------------------------------------------------

describe("isCompiledWheel — compiled vs pure-Python", () => {
  it("returns true for a CPython platform wheel", () => {
    const tag = parseWheelAbiTag("cryptography-41.0.5-cp311-cp311-linux_x86_64.whl")!;
    expect(isCompiledWheel(tag)).toBe(true);
  });

  it("returns true for an abi3 wheel", () => {
    const tag = parseWheelAbiTag("lxml-4.9.3-cp36-abi3-linux_x86_64.whl")!;
    expect(isCompiledWheel(tag)).toBe(true);
  });

  it("returns true for a macOS wheel", () => {
    const tag = parseWheelAbiTag("numpy-1.26.4-cp311-cp311-macosx_10_9_x86_64.whl")!;
    expect(isCompiledWheel(tag)).toBe(true);
  });

  it("returns true for a Windows wheel", () => {
    const tag = parseWheelAbiTag("numpy-1.26.4-cp311-cp311-win_amd64.whl")!;
    expect(isCompiledWheel(tag)).toBe(true);
  });

  it("returns false for a pure-Python none-any wheel", () => {
    const tag = parseWheelAbiTag("requests-2.31.0-py3-none-any.whl")!;
    expect(isCompiledWheel(tag)).toBe(false);
  });

  it("returns false when both abi=none and platform=any", () => {
    const tag: WheelAbiTag = {
      filename: "pkg-1.0-py3-none-any.whl",
      pythonTag: "py3",
      abiTag: "none",
      platformTag: "any",
      label: "pkg-py3-any",
    };
    expect(isCompiledWheel(tag)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 3. selectBestWheel
// ---------------------------------------------------------------------------

describe("selectBestWheel — best wheel selection strategy", () => {
  const cpythonLinux = {
    packagetype: "bdist_wheel",
    url: "https://files.example/cp311-linux.whl",
    filename: "pkg-1.0-cp311-cp311-linux_x86_64.whl",
  };
  const abi3Linux = {
    packagetype: "bdist_wheel",
    url: "https://files.example/abi3-linux.whl",
    filename: "pkg-1.0-cp36-abi3-linux_x86_64.whl",
  };
  const pureWheel = {
    packagetype: "bdist_wheel",
    url: "https://files.example/pure.whl",
    filename: "pkg-1.0-py3-none-any.whl",
  };
  const win64Wheel = {
    packagetype: "bdist_wheel",
    url: "https://files.example/win64.whl",
    filename: "pkg-1.0-cp311-cp311-win_amd64.whl",
  };

  it("prefers CPython platform wheel over abi3 and pure-Python", () => {
    const best = selectBestWheel([pureWheel, abi3Linux, cpythonLinux]);
    expect(best?.filename).toBe(cpythonLinux.filename);
  });

  it("prefers CPython wheel over Windows wheel when both are CPython", () => {
    const best = selectBestWheel([win64Wheel, cpythonLinux]);
    // Both are CPython compiled — should return the first matching CPython wheel
    expect(best).not.toBeNull();
    expect(best?.filename).toMatch(/cp311/);
  });

  it("falls back to abi3 when no CPython wheel is present", () => {
    const best = selectBestWheel([pureWheel, abi3Linux]);
    expect(best?.filename).toBe(abi3Linux.filename);
  });

  it("returns the only wheel when only one is available", () => {
    expect(selectBestWheel([pureWheel])?.filename).toBe(pureWheel.filename);
  });

  it("returns null for an empty list", () => {
    expect(selectBestWheel([])).toBeNull();
  });

  it("returns first wheel when none have recognised ABI tags", () => {
    const weird = {
      packagetype: "bdist_wheel",
      url: "https://files.example/weird.whl",
      filename: "weird.whl", // no valid ABI tag
    };
    expect(selectBestWheel([weird])?.filename).toBe(weird.filename);
  });
});

// ---------------------------------------------------------------------------
// 4. detectWheelOnlyPackage — mocked fetch
// ---------------------------------------------------------------------------

describe("detectWheelOnlyPackage — PyPI metadata interpretation", () => {
  it("detects a wheel-only package (no sdist)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          urls: [
            {
              packagetype: "bdist_wheel",
              url: "https://files.example/cryptography-cp311.whl",
              filename: "cryptography-41.0.5-cp311-cp311-linux_x86_64.whl",
            },
          ],
        }),
      })
    );

    const result = await detectWheelOnlyPackage("cryptography", "41.0.5");
    expect(result.hasSdist).toBe(false);
    expect(result.isWheelOnly).toBe(true);
    expect(result.wheels).toHaveLength(1);
  });

  it("returns hasSdist=true when sdist is present alongside wheels", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          urls: [
            { packagetype: "sdist", url: "https://files.example/pkg.tar.gz", filename: "pkg-1.0.tar.gz" },
            { packagetype: "bdist_wheel", url: "https://files.example/pkg.whl", filename: "pkg-1.0-cp311-cp311-linux_x86_64.whl" },
          ],
        }),
      })
    );

    const result = await detectWheelOnlyPackage("pkg", "1.0");
    expect(result.hasSdist).toBe(true);
    expect(result.isWheelOnly).toBe(false);
  });

  it("returns isWheelOnly=false when there are no wheels and no sdist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ urls: [] }),
      })
    );

    const result = await detectWheelOnlyPackage("empty-pkg", "0.0.1");
    expect(result.isWheelOnly).toBe(false);
    expect(result.wheels).toHaveLength(0);
  });

  it("throws when the PyPI API returns a non-200 status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 404 })
    );

    await expect(detectWheelOnlyPackage("no-such-pkg", "9.9.9")).rejects.toThrow(
      "PyPI metadata request returned 404"
    );
  });
});

// ---------------------------------------------------------------------------
// 5. analyzeWheelBinaries — fixture-based (offline)
// ---------------------------------------------------------------------------

describe("analyzeWheelBinaries — fixture wheel extraction", () => {
  /**
   * Build a minimal wheel zip from the benign-wheel fixture's .so file and
   * serve it via a mocked fetch.  Then call analyzeWheelBinaries and assert
   * that the pipeline produces findings with category wheelNativeBinary.
   */
  it("extracts .so from wheel zip and runs binary pipeline (benign-wheel fixture)", async () => {
    // Build a zip containing the benign-wheel .so file
    const soPath = path.join(
      fixturesDir,
      "benign-wheel",
      "numpy_core",
      "_multiarray_umath.cpython-311-x86_64-linux-gnu.so"
    );
    let soBytes: Buffer;
    try {
      const { readFile } = await import("node:fs/promises");
      soBytes = await readFile(soPath);
    } catch {
      // If the fixture does not have the exact path, try any .so in benign-wheel
      const { readdir, readFile } = await import("node:fs/promises");
      const entries = await readdir(path.join(fixturesDir, "benign-wheel"), { recursive: true });
      const soEntry = (entries as string[]).find((e) => e.endsWith(".so"));
      if (!soEntry) {
        // Skip if no fixture .so file is available
        return;
      }
      soBytes = await readFile(path.join(fixturesDir, "benign-wheel", soEntry));
    }

    const zipBuf = await buildZip([
      {
        name: "numpy_core/_multiarray_umath.cpython-311-x86_64-linux-gnu.so",
        content: soBytes,
      },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const wheelEntry = {
      packagetype: "bdist_wheel",
      url: "https://files.example/numpy-cp311-linux.whl",
      filename: "numpy-1.26.4-cp311-cp311-linux_x86_64.whl",
    };

    const result = await analyzeWheelBinaries("numpy", "1.26.4", wheelEntry);

    expect(result.hasNativeExtensions).toBe(true);
    expect(result.nativeExtensions.length).toBeGreaterThanOrEqual(1);
    expect(result.confidence).toBe("high");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.every((f) => f.category === "wheelNativeBinary")).toBe(true);
  });

  it("returns hasNativeExtensions=false for a wheel with no .so/.pyd/.dylib files", async () => {
    // Build a zip with only Python source — no native extensions
    const zipBuf = await buildZip([
      { name: "mypackage/__init__.py", content: Buffer.from("# pure python\n") },
      { name: "mypackage-1.0.dist-info/WHEEL", content: Buffer.from("Wheel-Version: 1.0\n") },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries(
      "pure-pkg",
      "1.0.0",
      {
        packagetype: "bdist_wheel",
        url: "https://files.example/pure-cp311.whl",
        filename: "pure_pkg-1.0.0-py3-none-any.whl",
      },
      // Isolate the native-binary-detection contract: a wheel with no native
      // extensions must produce no *binary* findings. Provenance/attestation
      // findings are a separate concern verified in their own suites, and the
      // stubbed fetch would otherwise make the provenance verifier emit a
      // "missing attestation" finding here.
      { skipProvenance: true, skipProvenanceVerifier: true }
    );

    expect(result.hasNativeExtensions).toBe(false);
    expect(result.nativeExtensions).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it("parses and attaches ABI tag to the analysis result", async () => {
    // Minimal zip — we just care about the ABI tag parsing
    const zipBuf = await buildZip([
      { name: "placeholder.py", content: Buffer.from("") },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries("cryptography", "41.0.5", {
      packagetype: "bdist_wheel",
      url: "https://files.example/crypto.whl",
      filename: "cryptography-41.0.5-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.abiTag).not.toBeNull();
    expect(result.abiTag?.pythonTag).toBe("cp311");
    expect(result.abiTag?.platformTag).toBe("linux_x86_64");
    expect(result.abiTag?.label).toMatch(/cryptography.*cp311.*linux_x86_64/);
  });

  it("includes architecture/platform label in finding filePath", async () => {
    // Build a zip with a .pyd file (Windows-style extension)
    const pydContent = Buffer.alloc(64, 0);
    // Write a PE magic byte header so fingerprint detects it as PE
    pydContent[0] = 0x4d; // M
    pydContent[1] = 0x5a; // Z

    const zipBuf = await buildZip([
      { name: "_ssl.pyd", content: pydContent },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries("pyssl", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/pyssl-win.whl",
      filename: "pyssl-1.0.0-cp311-cp311-win_amd64.whl",
    });

    expect(result.hasNativeExtensions).toBe(true);
    // Every finding should include the ABI label in the filePath
    for (const finding of result.findings) {
      expect(finding.filePath).toMatch(/win_amd64|pyssl/);
    }
  });

  it("includes .dylib files from macOS wheels", async () => {
    const dylibContent = Buffer.alloc(32, 0);
    // Mach-O magic (64-bit little-endian): CF FA ED FE
    dylibContent[0] = 0xcf;
    dylibContent[1] = 0xfa;
    dylibContent[2] = 0xed;
    dylibContent[3] = 0xfe;

    const zipBuf = await buildZip([
      { name: "libssl.dylib", content: dylibContent },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries("oslib", "2.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/oslib.whl",
      filename: "oslib-2.0.0-cp311-cp311-macosx_10_9_x86_64.whl",
    });

    expect(result.hasNativeExtensions).toBe(true);
    expect(result.nativeExtensions.some((e) => e.filename === "libssl.dylib")).toBe(true);
    const dylibExt = result.nativeExtensions.find((e) => e.filename === "libssl.dylib");
    expect(dylibExt?.artifact.format).toBe("Mach-O");
  });

  it("throws when the wheel download returns a non-200 status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 403 })
    );

    await expect(
      analyzeWheelBinaries("private-pkg", "1.0.0", {
        packagetype: "bdist_wheel",
        url: "https://files.example/private.whl",
        filename: "private_pkg-1.0.0-cp311-cp311-linux_x86_64.whl",
      })
    ).rejects.toThrow("Wheel download returned 403");
  });

  it("throws when the wheel exceeds maximum size", async () => {
    // Return a fake ArrayBuffer that claims to be larger than MAX_WHEEL_BYTES
    const HUGE = 201 * 1024 * 1024; // 201 MB
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => new ArrayBuffer(HUGE),
      })
    );

    await expect(
      analyzeWheelBinaries("huge-pkg", "1.0.0", {
        packagetype: "bdist_wheel",
        url: "https://files.example/huge.whl",
        filename: "huge_pkg-1.0.0-cp311-cp311-linux_x86_64.whl",
      })
    ).rejects.toThrow(/exceeds maximum size/);
  });
});

// ---------------------------------------------------------------------------
// 6. analyzeWheelOnlyPackage — convenience wrapper (mocked fetch)
// ---------------------------------------------------------------------------

describe("analyzeWheelOnlyPackage — end-to-end convenience wrapper", () => {
  it("returns null when no wheels are available", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ urls: [] }),
      })
    );

    const result = await analyzeWheelOnlyPackage("no-wheels", "1.0.0");
    expect(result).toBeNull();
  });

  it("selects best wheel and calls analyzeWheelBinaries", async () => {
    const cpWheelFilename = "somepkg-1.0.0-cp311-cp311-linux_x86_64.whl";
    const pureWheelFilename = "somepkg-1.0.0-py3-none-any.whl";

    const zipBuf = await buildZip([
      { name: "placeholder.py", content: Buffer.from("") },
    ]);

    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        // First call: PyPI metadata
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            urls: [
              { packagetype: "bdist_wheel", url: "https://files.example/cp.whl", filename: cpWheelFilename },
              { packagetype: "bdist_wheel", url: "https://files.example/pure.whl", filename: pureWheelFilename },
            ],
          }),
        })
        // Second call: wheel download
        .mockResolvedValueOnce({
          ok: true,
          arrayBuffer: async () =>
            zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
        })
    );

    const result = await analyzeWheelOnlyPackage("somepkg", "1.0.0");

    // Should have called fetch twice (metadata + wheel)
    expect(result).not.toBeNull();
    // CPython wheel should be selected (not the pure-Python one)
    expect(result!.abiTag?.filename).toBe(cpWheelFilename);
  });
});

// ---------------------------------------------------------------------------
// 7. Malformed wheel handling
// ---------------------------------------------------------------------------

describe("analyzeWheelBinaries — malformed wheel handling", () => {
  it("throws (or propagates unzip error) when wheel zip is corrupted", async () => {
    // Return garbage bytes that are not a valid zip
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => Buffer.from("not a zip").buffer,
      })
    );

    await expect(
      analyzeWheelBinaries("bad-zip", "1.0.0", {
        packagetype: "bdist_wheel",
        url: "https://files.example/bad.whl",
        filename: "bad_zip-1.0.0-cp311-cp311-linux_x86_64.whl",
      })
    ).rejects.toThrow();
  });

  it("handles a wheel zip containing only non-binary files gracefully", async () => {
    const zipBuf = await buildZip([
      { name: "README.txt", content: Buffer.from("Hello world") },
      { name: "LICENSE", content: Buffer.from("MIT") },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries(
      "text-only",
      "1.0.0",
      {
        packagetype: "bdist_wheel",
        url: "https://files.example/text-only.whl",
        filename: "text_only-1.0.0-py3-none-any.whl",
      },
      // See note above: isolate the binary-findings contract from provenance.
      { skipProvenance: true, skipProvenanceVerifier: true }
    );

    expect(result.hasNativeExtensions).toBe(false);
    expect(result.nativeExtensions).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 8. ABI tag in findings output
// ---------------------------------------------------------------------------

describe("ABI tag / architecture integration in findings", () => {
  it("confidence is always 'high' for wheel-binary findings", async () => {
    const zipBuf = await buildZip([
      { name: "stub.py", content: Buffer.from("") },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result: WheelBinaryAnalysis = await analyzeWheelBinaries("mypkg", "2.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/mypkg.whl",
      filename: "mypkg-2.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.confidence).toBe("high");
  });

  it("abiTag is null for a filename that cannot be parsed", async () => {
    const zipBuf = await buildZip([
      { name: "stub.py", content: Buffer.from("") },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries("mypkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/unknown.whl",
      filename: "bad.whl", // too few parts — parseWheelAbiTag returns null
    });

    expect(result.abiTag).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 9. ScriptFinding wheelNativeBinary category
// ---------------------------------------------------------------------------

describe("ScriptFinding wheelNativeBinary category", () => {
  it("all findings from analyzeWheelBinaries carry category wheelNativeBinary", async () => {
    const elfContent = Buffer.alloc(64, 0);
    // ELF magic header
    elfContent[0] = 0x7f;
    elfContent[1] = 0x45; // E
    elfContent[2] = 0x4c; // L
    elfContent[3] = 0x46; // F

    const zipBuf = await buildZip([
      { name: "module.so", content: elfContent },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries("mymodule", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/mymodule.whl",
      filename: "mymodule-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.hasNativeExtensions).toBe(true);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    for (const finding of result.findings) {
      expect(finding.category).toBe("wheelNativeBinary");
    }
  });

  it("wheelNativeBinary finding has non-empty title and recommendation", async () => {
    const elfContent = Buffer.alloc(64, 0);
    elfContent[0] = 0x7f;
    elfContent[1] = 0x45;
    elfContent[2] = 0x4c;
    elfContent[3] = 0x46;

    const zipBuf = await buildZip([
      { name: "_native.so", content: elfContent },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => zipBuf.buffer.slice(
          zipBuf.byteOffset,
          zipBuf.byteOffset + zipBuf.byteLength
        ),
      })
    );

    const result = await analyzeWheelBinaries("nativepkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/native.whl",
      filename: "nativepkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    for (const finding of result.findings) {
      expect(finding.title.length).toBeGreaterThan(0);
      expect(finding.recommendation.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// 11. Binary fingerprinting — computeWheelBinaryFingerprint + helpers
// ---------------------------------------------------------------------------

describe("computeWheelBinaryFingerprint — fingerprint computation", () => {
  it("returns a BinaryFingerprint with all required fields", async () => {
    const elfContent = Buffer.alloc(128, 0);
    elfContent[0] = 0x7f;
    elfContent[1] = 0x45; // E
    elfContent[2] = 0x4c; // L
    elfContent[3] = 0x46; // F

    const zipBuf = await buildZip([{ name: "mod.so", content: elfContent }]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () =>
          zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
      })
    );

    const result = await analyzeWheelBinaries("modpkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/mod.whl",
      filename: "modpkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.hasNativeExtensions).toBe(true);
    expect(result.binaryFingerprints).toHaveLength(1);

    const fpData = result.binaryFingerprints[0]!;
    expect(fpData.ecosystem).toBe("pypi");
    expect(fpData.packageName).toBe("modpkg");
    expect(fpData.version).toBe("1.0.0");
    expect(typeof fpData.fingerprint.sha256).toBe("string");
    expect(fpData.fingerprint.hashAlgorithm).toBe("sha256");
    expect(typeof fpData.fingerprint.importSig).toBe("string");
    expect(typeof fpData.fingerprint.syscallSig).toBe("string");
    expect(typeof fpData.fingerprint.ssdeepFuzzyHash).toBe("string");
    expect(fpData.fingerprint.ssdeepFuzzyHash!.length).toBe(64);
  });

  it("produces an empty binaryFingerprints array for pure-Python wheels", async () => {
    const zipBuf = await buildZip([
      { name: "mypkg/__init__.py", content: Buffer.from("") },
    ]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () =>
          zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
      })
    );

    const result = await analyzeWheelBinaries("purepy", "2.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/purepy.whl",
      filename: "purepy-2.0.0-py3-none-any.whl",
    });

    expect(result.hasNativeExtensions).toBe(false);
    expect(result.binaryFingerprints).toHaveLength(0);
  });

  it("importSig is a 64-char hex string", async () => {
    const elfContent = Buffer.alloc(64, 0);
    elfContent[0] = 0x7f;
    elfContent[1] = 0x45;
    elfContent[2] = 0x4c;
    elfContent[3] = 0x46;

    const zipBuf = await buildZip([{ name: "lib.so", content: elfContent }]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () =>
          zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
      })
    );

    const result = await analyzeWheelBinaries("libpkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/lib.whl",
      filename: "libpkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.binaryFingerprints.length).toBeGreaterThan(0);
    const sig = result.binaryFingerprints[0]!.fingerprint.importSig;
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("syscallSig is a 64-char hex string", async () => {
    const elfContent = Buffer.alloc(64, 0);
    elfContent[0] = 0x7f;
    elfContent[1] = 0x45;
    elfContent[2] = 0x4c;
    elfContent[3] = 0x46;

    const zipBuf = await buildZip([{ name: "syscall.so", content: elfContent }]);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () =>
          zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
      })
    );

    const result = await analyzeWheelBinaries("syscallpkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/syscall.whl",
      filename: "syscallpkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.binaryFingerprints.length).toBeGreaterThan(0);
    const sig = result.binaryFingerprints[0]!.fingerprint.syscallSig;
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("two identical binaries produce identical fingerprint signals", async () => {
    const elfContent = Buffer.alloc(128, 0xab);
    elfContent[0] = 0x7f;
    elfContent[1] = 0x45;
    elfContent[2] = 0x4c;
    elfContent[3] = 0x46;

    const zipBuf = await buildZip([{ name: "clone.so", content: elfContent }]);
    const makeResponse = () => ({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    });

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeResponse()));
    const result1 = await analyzeWheelBinaries("pkga", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/pkga.whl",
      filename: "pkga-1.0.0-cp311-cp311-linux_x86_64.whl",
    });
    vi.restoreAllMocks();

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeResponse()));
    const result2 = await analyzeWheelBinaries("pkgb", "2.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/pkgb.whl",
      filename: "pkgb-2.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result1.binaryFingerprints.length).toBe(1);
    expect(result2.binaryFingerprints.length).toBe(1);

    const fp1 = result1.binaryFingerprints[0]!.fingerprint;
    const fp2 = result2.binaryFingerprints[0]!.fingerprint;

    // Identical binary bytes → identical similarity signals
    expect(fp1.importSig).toBe(fp2.importSig);
    expect(fp1.syscallSig).toBe(fp2.syscallSig);
    expect(fp1.ssdeepFuzzyHash).toBe(fp2.ssdeepFuzzyHash);
  });

  it("buildFingerprintData sets ecosystem=pypi and normalises packageName", async () => {
    const elfContent = Buffer.alloc(64, 0);
    elfContent[0] = 0x7f; elfContent[1] = 0x45; elfContent[2] = 0x4c; elfContent[3] = 0x46;

    const zipBuf = await buildZip([{ name: "ext.so", content: elfContent }]);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    }));

    const result = await analyzeWheelBinaries("MyPkg", "3.1.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/mypkg.whl",
      filename: "MyPkg-3.1.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.binaryFingerprints.length).toBeGreaterThan(0);
    const fpd = result.binaryFingerprints[0]!;
    expect(fpd.ecosystem).toBe("pypi");
    // packageName should be lowercased
    expect(fpd.packageName).toBe("mypkg");
    expect(fpd.version).toBe("3.1.0");
    expect(typeof fpd.computedAt).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// 12. Fuzzy matching & deduplication resilience
// ---------------------------------------------------------------------------

describe("binary fingerprint fuzzy-match resilience", () => {
  it("two binaries differing only in one byte produce different sha256 but may share importSig", async () => {
    // Build two binaries that are identical except for one non-significant byte
    const mkElf = (fillByte: number) => {
      const b = Buffer.alloc(128, fillByte);
      b[0] = 0x7f; b[1] = 0x45; b[2] = 0x4c; b[3] = 0x46;
      return b;
    };

    const makeZip = (content: Buffer) =>
      buildZip([{ name: "mod.so", content }]);

    const zip1 = await makeZip(mkElf(0xaa));
    const zip2 = await makeZip(mkElf(0xbb));

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => zip1.buffer.slice(zip1.byteOffset, zip1.byteOffset + zip1.byteLength),
    }));
    const res1 = await analyzeWheelBinaries("pka", "1.0.0", {
      packagetype: "bdist_wheel", url: "https://x/a.whl",
      filename: "pka-1.0.0-cp311-cp311-linux_x86_64.whl",
    });
    vi.restoreAllMocks();

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => zip2.buffer.slice(zip2.byteOffset, zip2.byteOffset + zip2.byteLength),
    }));
    const res2 = await analyzeWheelBinaries("pkb", "1.0.0", {
      packagetype: "bdist_wheel", url: "https://x/b.whl",
      filename: "pkb-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    // sha256 must differ (different bytes)
    expect(res1.binaryFingerprints[0]!.fingerprint.sha256).not.toBe(
      res2.binaryFingerprints[0]!.fingerprint.sha256
    );
    // Both have importSig and syscallSig as valid hex
    expect(res1.binaryFingerprints[0]!.fingerprint.importSig).toMatch(/^[0-9a-f]{64}$/);
    expect(res2.binaryFingerprints[0]!.fingerprint.importSig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("multiple .so files in one wheel each get their own fingerprint entry", async () => {
    const mkElf = (byte: number) => {
      const b = Buffer.alloc(64, byte);
      b[0] = 0x7f; b[1] = 0x45; b[2] = 0x4c; b[3] = 0x46;
      return b;
    };

    const zipBuf = await buildZip([
      { name: "ext1.so", content: mkElf(0x01) },
      { name: "ext2.so", content: mkElf(0x02) },
      { name: "ext3.so", content: mkElf(0x03) },
    ]);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    }));

    const result = await analyzeWheelBinaries("multipkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/multi.whl",
      filename: "multipkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.nativeExtensions).toHaveLength(3);
    expect(result.binaryFingerprints).toHaveLength(3);

    // Each fingerprint entry should have a distinct binaryPath
    const paths = result.binaryFingerprints.map((fp) => fp.binaryPath);
    const uniquePaths = new Set(paths);
    expect(uniquePaths.size).toBe(3);
  });

  it("fingerprint computedAt is a valid ISO timestamp", async () => {
    const elfContent = Buffer.alloc(64, 0);
    elfContent[0] = 0x7f; elfContent[1] = 0x45; elfContent[2] = 0x4c; elfContent[3] = 0x46;

    const zipBuf = await buildZip([{ name: "ts.so", content: elfContent }]);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    }));

    const result = await analyzeWheelBinaries("tspkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/ts.whl",
      filename: "tspkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.binaryFingerprints.length).toBeGreaterThan(0);
    const ts = result.binaryFingerprints[0]!.computedAt;
    expect(() => new Date(ts)).not.toThrow();
    expect(new Date(ts).getFullYear()).toBeGreaterThan(2020);
  });

  it("fingerprint packageVersionKey follows pypi:<name>@<version> format", async () => {
    const elfContent = Buffer.alloc(64, 0);
    elfContent[0] = 0x7f; elfContent[1] = 0x45; elfContent[2] = 0x4c; elfContent[3] = 0x46;

    const zipBuf = await buildZip([{ name: "key.so", content: elfContent }]);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    }));

    const result = await analyzeWheelBinaries("keypkg", "4.2.1", {
      packagetype: "bdist_wheel",
      url: "https://files.example/key.whl",
      filename: "keypkg-4.2.1-cp311-cp311-linux_x86_64.whl",
    });

    expect(result.binaryFingerprints.length).toBeGreaterThan(0);
    const pvk = result.binaryFingerprints[0]!.fingerprint.packageVersionKey;
    expect(pvk).toBe("pypi:keypkg@4.2.1");
  });
});

// ---------------------------------------------------------------------------
// 10. SCRIPT_THREAT_CATEGORIES — types package integration
// ---------------------------------------------------------------------------

describe("SCRIPT_THREAT_CATEGORIES — analysis-types package", () => {
  it("contains 'wheelNativeBinary'", () => {
    expect(SCRIPT_THREAT_CATEGORIES).toContain("wheelNativeBinary");
  });

  it("still contains all previously defined categories", () => {
    const expected = [
      "installHook",
      "scriptInjection",
      "environmentTheft",
      "dependencyConfusion",
      "wiper",
      "reverseShell",
      "remoteCodeExecution",
      "obfuscation",
      "knownMalware",
      "pythonBinaryExtension",
      "setupToolsHookExecution",
      "cythonBinaryExtension",
    ];
    for (const cat of expected) {
      expect(SCRIPT_THREAT_CATEGORIES).toContain(cat);
    }
  });

  it("has no duplicate categories", () => {
    const unique = new Set(SCRIPT_THREAT_CATEGORIES);
    expect(unique.size).toBe(SCRIPT_THREAT_CATEGORIES.length);
  });
});
