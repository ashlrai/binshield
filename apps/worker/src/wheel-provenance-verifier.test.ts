/**
 * Tests for wheel-provenance-verifier.ts
 *
 * Covers:
 *   1.  parseWheelRecord — RECORD file parsing, base64url decoding
 *   2.  verifyRecordEntry — per-file hash verification against disk
 *   3.  verifyWheelHash — archive SHA-256 against published hash
 *   4.  findRecordFile — locating .dist-info/RECORD in extracted dir
 *   5.  extractExtModulesFromSetupPy — regex-based ext_modules extraction
 *   6.  extractExtModulesFromPyproject — TOML ext_modules detection
 *   7.  compareWheelToSdistModules — extra binary detection logic
 *   8.  matchWheelToSdist — full sdist vs wheel comparison
 *   9.  checkPyPiAttestation — PEP 740 attestation (mocked fetch)
 *  10.  verifyWheelProvenance — end-to-end provenance verification
 *  11.  provenanceResultToFindings — finding emission logic
 *  12.  Integration: provenance in analyzeWheelBinaries result
 *  13.  WheelProvenanceResult shape / confidence levels
 *  14.  Supply-chain mismatch findings
 *  15.  RECORD hash mismatch findings severity
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";

import {
  parseWheelRecord,
  verifyRecordEntry,
  verifyWheelHash,
  findRecordFile,
  extractExtModulesFromSetupPy,
  extractExtModulesFromPyproject,
  compareWheelToSdistModules,
  matchWheelToSdist,
  checkPyPiAttestation,
  verifyWheelProvenance,
  provenanceResultToFindings,
  type RecordEntry,
  type WheelProvenanceResult,
} from "./wheel-provenance-verifier";

import {
  analyzeWheelBinaries,
} from "./pypi-wheel-binary-analyzer";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "bswpv-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

/**
 * Write a minimal wheel zip using the system `zip` command.
 */
async function buildZip(
  entries: Array<{ name: string; content: Buffer }>
): Promise<Buffer> {
  const td = await mkdtemp(path.join(os.tmpdir(), "bswpv-zip-"));
  try {
    for (const entry of entries) {
      const entryPath = path.join(td, entry.name);
      await mkdir(path.dirname(entryPath), { recursive: true });
      await writeFile(entryPath, entry.content);
    }
    const zipPath = path.join(td, "archive.zip");
    const names = entries.map((e) => e.name);
    await execFileAsync("zip", ["-q", "-r", zipPath, ...names], { cwd: td });
    const { readFile } = await import("node:fs/promises");
    return await readFile(zipPath);
  } finally {
    await rm(td, { recursive: true, force: true }).catch(() => {});
  }
}

/** Write files into tempDir to simulate an extracted wheel. */
async function writeExtractedWheel(
  files: Array<{ name: string; content: Buffer }>
): Promise<string> {
  const extractDir = path.join(tempDir, "wheel");
  await mkdir(extractDir, { recursive: true });
  for (const f of files) {
    const p = path.join(extractDir, f.name);
    await mkdir(path.dirname(p), { recursive: true });
    await writeFile(p, f.content);
  }
  return extractDir;
}

/** Compute SHA-256 of a buffer and encode as base64url (PEP 376 style). */
function sha256Base64url(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("base64url");
}

// ---------------------------------------------------------------------------
// 1. parseWheelRecord
// ---------------------------------------------------------------------------

describe("parseWheelRecord — RECORD file parsing", () => {
  it("parses a standard RECORD entry with sha256 hash", () => {
    const content = "mypkg/__init__.py,sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890,512\n";
    const entries = parseWheelRecord(content);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.filePath).toBe("mypkg/__init__.py");
    expect(entries[0]!.algorithm).toBe("sha256");
    expect(entries[0]!.recordedSize).toBe(512);
    expect(entries[0]!.digest).toBeTruthy(); // base64url decoded to hex
  });

  it("parses a RECORD self-entry with no hash (as per PEP 376)", () => {
    const content = "mypkg-1.0.dist-info/RECORD,,\n";
    const entries = parseWheelRecord(content);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.filePath).toBe("mypkg-1.0.dist-info/RECORD");
    expect(entries[0]!.algorithm).toBeNull();
    expect(entries[0]!.digest).toBeNull();
    expect(entries[0]!.recordedSize).toBeNull();
  });

  it("skips empty lines", () => {
    const content = "\n\nmypkg/__init__.py,sha256=AAAA,100\n\n";
    const entries = parseWheelRecord(content);
    expect(entries).toHaveLength(1);
  });

  it("parses multiple entries correctly", () => {
    const fileA = Buffer.from("hello world");
    const fileB = Buffer.from("native binary");
    const content = [
      `mypkg/__init__.py,sha256=${sha256Base64url(fileA)},${fileA.length}`,
      `mypkg/_core.so,sha256=${sha256Base64url(fileB)},${fileB.length}`,
      "mypkg-1.0.dist-info/RECORD,,",
    ].join("\n") + "\n";

    const entries = parseWheelRecord(content);
    expect(entries).toHaveLength(3);
    expect(entries[0]!.filePath).toBe("mypkg/__init__.py");
    expect(entries[1]!.filePath).toBe("mypkg/_core.so");
    expect(entries[2]!.filePath).toBe("mypkg-1.0.dist-info/RECORD");
  });

  it("sets hashMatches to null (not yet verified)", () => {
    const content = "mypkg/__init__.py,sha256=AAAA,100\n";
    const entries = parseWheelRecord(content);
    expect(entries[0]!.hashMatches).toBeNull();
  });

  it("handles entries with no size field", () => {
    const content = "mypkg/__init__.py,sha256=AAAA\n";
    const entries = parseWheelRecord(content);
    expect(entries[0]!.recordedSize).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. verifyRecordEntry
// ---------------------------------------------------------------------------

describe("verifyRecordEntry — per-file hash verification", () => {
  it("sets hashMatches=true when hash matches file on disk", async () => {
    const content = Buffer.from("hello world");
    const extractDir = await writeExtractedWheel([
      { name: "mypkg/__init__.py", content },
    ]);

    const entry: RecordEntry = {
      filePath: "mypkg/__init__.py",
      algorithm: "sha256",
      digest: crypto.createHash("sha256").update(content).digest("hex"),
      recordedSize: content.length,
      hashMatches: null,
    };

    const result = await verifyRecordEntry(extractDir, entry);
    expect(result.hashMatches).toBe(true);
  });

  it("sets hashMatches=false when hash does not match", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg/_core.so", content: Buffer.from("tampered bytes") },
    ]);

    const entry: RecordEntry = {
      filePath: "mypkg/_core.so",
      algorithm: "sha256",
      digest: "0000000000000000000000000000000000000000000000000000000000000000",
      recordedSize: 14,
      hashMatches: null,
    };

    const result = await verifyRecordEntry(extractDir, entry);
    expect(result.hashMatches).toBe(false);
  });

  it("sets hashMatches=false when file is missing", async () => {
    const extractDir = path.join(tempDir, "empty-extract");
    await mkdir(extractDir, { recursive: true });

    const entry: RecordEntry = {
      filePath: "mypkg/missing.py",
      algorithm: "sha256",
      digest: "aaaa",
      recordedSize: 10,
      hashMatches: null,
    };

    const result = await verifyRecordEntry(extractDir, entry);
    expect(result.hashMatches).toBe(false);
  });

  it("returns hashMatches=null for RECORD file itself", async () => {
    const extractDir = path.join(tempDir, "exemption-test");
    await mkdir(extractDir, { recursive: true });

    const entry: RecordEntry = {
      filePath: "mypkg-1.0.dist-info/RECORD",
      algorithm: null,
      digest: null,
      recordedSize: null,
      hashMatches: null,
    };

    const result = await verifyRecordEntry(extractDir, entry);
    expect(result.hashMatches).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 3. verifyWheelHash
// ---------------------------------------------------------------------------

describe("verifyWheelHash — archive hash verification", () => {
  it("returns matches=true when hash matches published hash", () => {
    const bytes = Buffer.from("wheel archive bytes");
    const hash = crypto.createHash("sha256").update(bytes).digest("hex");
    const { wheelHash, matches } = verifyWheelHash(bytes, hash);
    expect(wheelHash).toBe(hash);
    expect(matches).toBe(true);
  });

  it("returns matches=false when hash does not match", () => {
    const bytes = Buffer.from("wheel archive bytes");
    const { matches } = verifyWheelHash(bytes, "0".repeat(64));
    expect(matches).toBe(false);
  });

  it("returns matches=true when no published hash is provided (cannot verify)", () => {
    const bytes = Buffer.from("wheel archive bytes");
    const { matches } = verifyWheelHash(bytes, undefined);
    expect(matches).toBe(true);
  });

  it("wheelHash is always a 64-char hex string", () => {
    const bytes = Buffer.from("test");
    const { wheelHash } = verifyWheelHash(bytes, undefined);
    expect(wheelHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// 4. findRecordFile
// ---------------------------------------------------------------------------

describe("findRecordFile — locate RECORD in extracted wheel", () => {
  it("finds RECORD inside .dist-info directory", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from("") },
      { name: "mypkg/__init__.py", content: Buffer.from("") },
    ]);

    const recordPath = await findRecordFile(extractDir);
    expect(recordPath).not.toBeNull();
    expect(recordPath!).toContain("RECORD");
    expect(recordPath!).toContain(".dist-info");
  });

  it("returns null when no .dist-info directory exists", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg/__init__.py", content: Buffer.from("") },
    ]);
    const recordPath = await findRecordFile(extractDir);
    expect(recordPath).toBeNull();
  });

  it("returns null for a non-existent extract directory", async () => {
    const recordPath = await findRecordFile("/nonexistent/path/here");
    expect(recordPath).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 5. extractExtModulesFromSetupPy
// ---------------------------------------------------------------------------

describe("extractExtModulesFromSetupPy — ext_modules parsing", () => {
  it("extracts single Extension declaration", () => {
    const content = `
from setuptools import setup, Extension
setup(
  ext_modules=[Extension("mypackage._core", sources=["src/core.c"])]
)`;
    const modules = extractExtModulesFromSetupPy(content);
    expect(modules).toHaveLength(1);
    expect(modules[0]!.name).toBe("mypackage._core");
  });

  it("extracts multiple Extension declarations", () => {
    const content = `
ext_modules=[
  Extension("mypackage._fast", sources=["fast.c"]),
  Extension("mypackage._util", sources=["util.c"]),
  Extension('mypackage._extra', sources=["extra.c"]),
]`;
    const modules = extractExtModulesFromSetupPy(content);
    expect(modules).toHaveLength(3);
    const names = modules.map((m) => m.name);
    expect(names).toContain("mypackage._fast");
    expect(names).toContain("mypackage._util");
    expect(names).toContain("mypackage._extra");
  });

  it("returns empty array when no Extension declarations exist", () => {
    const content = `
from setuptools import setup
setup(name="pure-python", version="1.0")`;
    const modules = extractExtModulesFromSetupPy(content);
    expect(modules).toHaveLength(0);
  });

  it("handles Extension with both single and double quotes", () => {
    const content = `Extension("pkg.mod1", ...) Extension('pkg.mod2', ...)`;
    const modules = extractExtModulesFromSetupPy(content);
    expect(modules.some((m) => m.name === "pkg.mod1")).toBe(true);
    expect(modules.some((m) => m.name === "pkg.mod2")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 6. extractExtModulesFromPyproject
// ---------------------------------------------------------------------------

describe("extractExtModulesFromPyproject — TOML ext_modules detection", () => {
  it("returns empty array for pure-Python pyproject.toml", () => {
    const content = `
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "pure"
version = "1.0.0"`;
    const modules = extractExtModulesFromPyproject(content);
    expect(modules).toHaveLength(0);
  });

  it("detects ext-modules section presence", () => {
    const content = `
[build-system]
requires = ["setuptools", "cython"]

[[tool.setuptools.ext-modules]]
name = "mypkg._core"
sources = ["src/core.pyx"]

[[tool.setuptools.ext-modules]]
name = "mypkg._util"
sources = ["src/util.pyx"]`;
    const modules = extractExtModulesFromPyproject(content);
    expect(modules.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// 7. compareWheelToSdistModules
// ---------------------------------------------------------------------------

describe("compareWheelToSdistModules — supply-chain mismatch detection", () => {
  it("returns matchesSdist=true when all binaries have matching declarations", () => {
    const declared = [
      { name: "mypkg._core", sources: [] },
      { name: "mypkg._util", sources: [] },
    ];
    const wheelBinaries = [
      "mypkg/_core.cpython-311-x86_64-linux-gnu.so",
      "mypkg/_util.cpython-311-x86_64-linux-gnu.so",
    ];
    const result = compareWheelToSdistModules(declared, wheelBinaries);
    expect(result.matchesSdist).toBe(true);
    expect(result.extraBinaries).toHaveLength(0);
  });

  it("returns extra binary when wheel has undeclared binary", () => {
    const declared = [{ name: "mypkg._core", sources: [] }];
    const wheelBinaries = [
      "mypkg/_core.cpython-311-x86_64-linux-gnu.so",
      "mypkg/_injected.cpython-311-x86_64-linux-gnu.so",
    ];
    const result = compareWheelToSdistModules(declared, wheelBinaries);
    expect(result.matchesSdist).toBe(false);
    expect(result.extraBinaries).toHaveLength(1);
    expect(result.extraBinaries[0]).toContain("_injected");
  });

  it("returns all binaries as extra when no declarations exist", () => {
    const declared: never[] = [];
    const wheelBinaries = ["mypkg/_secret.so", "mypkg/_backdoor.pyd"];
    const result = compareWheelToSdistModules(declared, wheelBinaries);
    expect(result.matchesSdist).toBe(false);
    expect(result.extraBinaries).toHaveLength(2);
  });

  it("returns matchesSdist=true for pure-Python wheel (no binaries)", () => {
    const declared = [{ name: "mypkg._core", sources: [] }];
    const wheelBinaries: string[] = [];
    const result = compareWheelToSdistModules(declared, wheelBinaries);
    expect(result.matchesSdist).toBe(true);
    expect(result.extraBinaries).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 8. matchWheelToSdist
// ---------------------------------------------------------------------------

describe("matchWheelToSdist — full sdist comparison function", () => {
  it("returns null when no extract dir and no wheelBinaries provided", async () => {
    const result = await matchWheelToSdist({ setupPyContent: "Extension('pkg._core',...)" });
    expect(result).toBeNull();
  });

  it("detects extra binary when wheel has more than sdist declares", async () => {
    const result = await matchWheelToSdist({
      setupPyContent: `Extension("mypkg._core", sources=["core.c"])`,
      wheelBinaries: [
        "mypkg/_core.cpython-311-x86_64-linux-gnu.so",
        "mypkg/_extra.cpython-311-x86_64-linux-gnu.so",
      ],
    });
    expect(result).not.toBeNull();
    expect(result!.matchesSdist).toBe(false);
    expect(result!.extraBinaries.some((b) => b.includes("_extra"))).toBe(true);
  });

  it("is consistent when sdist and wheel both have no native code", async () => {
    const result = await matchWheelToSdist({
      setupPyContent: "from setuptools import setup\nsetup(name='pure')",
      wheelBinaries: [],
    });
    expect(result).not.toBeNull();
    expect(result!.matchesSdist).toBe(true);
  });

  it("flags all wheel binaries as extra when setup.py has no ext_modules", async () => {
    const result = await matchWheelToSdist({
      setupPyContent: "from setuptools import setup\nsetup(name='pkg', version='1.0')",
      wheelBinaries: ["pkg/_backdoor.so"],
    });
    expect(result).not.toBeNull();
    expect(result!.matchesSdist).toBe(false);
    expect(result!.extraBinaries).toHaveLength(1);
  });

  it("scans extractDir for binaries when wheelBinaries not provided", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg/_core.so", content: Buffer.from("\x7fELF") },
      { name: "mypkg/__init__.py", content: Buffer.from("") },
    ]);
    const result = await matchWheelToSdist({
      setupPyContent: `Extension("mypkg._core", sources=["core.c"])`,
      extractDir,
    });
    expect(result).not.toBeNull();
    expect(result!.matchesSdist).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 9. checkPyPiAttestation — mocked fetch
// ---------------------------------------------------------------------------

describe("checkPyPiAttestation — PEP 740 attestation check", () => {
  it("returns hasAttestation=false when no provenance field exists", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        urls: [
          {
            filename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
            packagetype: "bdist_wheel",
            url: "https://files.example/mypkg.whl",
          },
        ],
      }),
    }));

    const result = await checkPyPiAttestation("mypkg", "1.0", "mypkg-1.0-cp311-cp311-linux_x86_64.whl");
    expect(result.hasAttestation).toBe(false);
    expect(result.verified).toBeNull();
  });

  it("returns hasAttestation=true and verified=true when valid attestation bundle exists", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        urls: [
          {
            filename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
            packagetype: "bdist_wheel",
            url: "https://files.example/mypkg.whl",
            provenance: {
              attestation_bundles: [
                {
                  attestations: [
                    {
                      version: 1,
                      envelope: {
                        statement: "base64statement",
                        signature: "base64signature",
                      },
                    },
                  ],
                },
              ],
            },
          },
        ],
      }),
    }));

    const result = await checkPyPiAttestation("mypkg", "1.0", "mypkg-1.0-cp311-cp311-linux_x86_64.whl");
    expect(result.hasAttestation).toBe(true);
    expect(result.verified).toBe(true);
  });

  it("returns hasAttestation=false on network error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network error")));
    const result = await checkPyPiAttestation("mypkg", "1.0", "mypkg-1.0-cp311-cp311-linux_x86_64.whl");
    expect(result.hasAttestation).toBe(false);
    expect(result.verified).toBeNull();
  });

  it("returns hasAttestation=false when PyPI returns non-200", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    const result = await checkPyPiAttestation("missing", "9.9.9", "missing-9.9.9-cp311-cp311-linux_x86_64.whl");
    expect(result.hasAttestation).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 10. verifyWheelProvenance — end-to-end
// ---------------------------------------------------------------------------

describe("verifyWheelProvenance — end-to-end provenance verification", () => {
  it("returns isVerified=true and confidence=medium for a wheel with valid RECORD (no attestation)", async () => {
    const fileContent = Buffer.from("pure python file");
    const hash = sha256Base64url(fileContent);
    const recordContent = [
      `mypkg/__init__.py,sha256=${hash},${fileContent.length}`,
      "mypkg-1.0.dist-info/RECORD,,",
    ].join("\n") + "\n";

    const extractDir = await writeExtractedWheel([
      { name: "mypkg/__init__.py", content: fileContent },
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from(recordContent) },
    ]);

    const wheelBytes = Buffer.from("fake wheel bytes");

    const result = await verifyWheelProvenance({
      wheelBytes,
      wheelFilename: "mypkg-1.0-py3-none-any.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
    });

    expect(result.isVerified).toBe(true);
    expect(result.confidence).toBe("medium"); // no attestation
    expect(result.wheelHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.recordEntries.length).toBeGreaterThan(0);
    expect(result.hasAttestation).toBe(false);
    expect(result.attestationVerified).toBeNull();
  });

  it("returns isVerified=false when RECORD hash mismatches", async () => {
    const fileContent = Buffer.from("real content");
    const badHash = sha256Base64url(Buffer.from("different content"));
    const recordContent = `mypkg/_core.so,sha256=${badHash},${fileContent.length}\n`;
    const extractDir = await writeExtractedWheel([
      { name: "mypkg/_core.so", content: fileContent },
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from(recordContent) },
    ]);

    const result = await verifyWheelProvenance({
      wheelBytes: Buffer.from("wheel"),
      wheelFilename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
    });

    expect(result.isVerified).toBe(false);
    expect(result.confidence).toBe("low");
    expect(result.findings.some((f) => f.title.includes("RECORD hash mismatch"))).toBe(true);
  });

  it("emits critical finding when wheel archive hash mismatches published hash", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from("") },
    ]);

    const wheelBytes = Buffer.from("actual wheel bytes");
    const wrongHash = "0".repeat(64);

    const result = await verifyWheelProvenance({
      wheelBytes,
      wheelFilename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
      publishedHash: wrongHash,
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
    });

    expect(result.isVerified).toBe(false);
    expect(result.confidence).toBe("low");
    const critical = result.findings.find((f) => f.severity === "critical");
    expect(critical).toBeDefined();
    expect(critical!.title).toMatch(/hash mismatch/i);
  });

  it("emits medium finding for missing RECORD file", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg/__init__.py", content: Buffer.from("") },
      // No .dist-info/RECORD
    ]);

    const result = await verifyWheelProvenance({
      wheelBytes: Buffer.from("wheel"),
      wheelFilename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
    });

    expect(result.isVerified).toBe(false);
    const missing = result.findings.find((f) => f.title.includes("Missing RECORD"));
    expect(missing).toBeDefined();
    expect(missing!.severity).toBe("medium");
  });

  it("includes sdistMatch extraBinaries in findings when mismatch detected", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from("") },
    ]);

    const result = await verifyWheelProvenance({
      wheelBytes: Buffer.from("wheel"),
      wheelFilename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
      sdistMatch: {
        declaredModules: [],
        wheelBinaries: ["mypkg/_secret.cpython-311-x86_64-linux-gnu.so"],
        extraBinaries: ["mypkg/_secret.cpython-311-x86_64-linux-gnu.so"],
        matchesSdist: false,
      },
    });

    expect(result.matchesSdist).toBe(false);
    expect(result.extraBinaries).toHaveLength(1);
    const mismatchFinding = result.findings.find((f) => f.title.includes("Undeclared native binary"));
    expect(mismatchFinding).toBeDefined();
    expect(mismatchFinding!.severity).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// 11. provenanceResultToFindings
// ---------------------------------------------------------------------------

describe("provenanceResultToFindings — finding emission", () => {
  it("returns existing findings when findings array is non-empty", () => {
    const mockResult: WheelProvenanceResult = {
      wheelHash: "a".repeat(64),
      isVerified: false,
      matchesSdist: null,
      extraBinaries: [],
      confidence: "low",
      findings: [
        {
          category: "wheelNativeBinary",
          severity: "high",
          title: "existing finding",
          description: "desc",
          filePath: "pkg.whl",
          evidence: "",
          recommendation: "rec",
        },
      ],
      recordEntries: [],
      hasAttestation: false,
      attestationVerified: null,
    };
    const findings = provenanceResultToFindings(mockResult, "pkg.whl");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toBe("existing finding");
  });

  it("emits summary finding when isVerified=false but findings array is empty", () => {
    const mockResult: WheelProvenanceResult = {
      wheelHash: "b".repeat(64),
      isVerified: false,
      matchesSdist: null,
      extraBinaries: [],
      confidence: "low",
      findings: [],
      recordEntries: [],
      hasAttestation: false,
      attestationVerified: null,
    };
    const findings = provenanceResultToFindings(mockResult, "pkg.whl");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toMatch(/unverified/i);
  });

  it("returns empty array when wheel is verified", () => {
    const mockResult: WheelProvenanceResult = {
      wheelHash: "c".repeat(64),
      isVerified: true,
      matchesSdist: true,
      extraBinaries: [],
      confidence: "high",
      findings: [],
      recordEntries: [],
      hasAttestation: true,
      attestationVerified: true,
    };
    const findings = provenanceResultToFindings(mockResult, "pkg.whl");
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 12. Integration: provenance in analyzeWheelBinaries result
// ---------------------------------------------------------------------------

describe("analyzeWheelBinaries provenance integration", () => {
  it("provenance is null when skipProvenance=true", async () => {
    const zipBuf = await buildZip([
      { name: "stub.py", content: Buffer.from("") },
    ]);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    }));

    const result = await analyzeWheelBinaries("mypkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/mypkg.whl",
      filename: "mypkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    }, { skipProvenance: true });

    expect(result.provenance).toBeNull();
  });

  it("provenance is populated when skipProvenance is not set", async () => {
    // Wheel with RECORD file included
    const fileContent = Buffer.from("");
    const zipBuf = await buildZip([
      { name: "mypkg/__init__.py", content: fileContent },
      { name: "mypkg-1.0.0.dist-info/RECORD", content: Buffer.from("mypkg/__init__.py,,\n") },
    ]);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    }));

    const result = await analyzeWheelBinaries("mypkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/mypkg.whl",
      filename: "mypkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    }, { skipProvenance: false, skipAttestation: true });

    expect(result.provenance).not.toBeNull();
    expect(result.provenance!.wheelHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("provenance findings appear in the top-level findings array for native wheels", async () => {
    // Build a wheel with a .so and a mismatched RECORD entry to trigger a provenance finding
    const soContent = Buffer.from("\x7fELF" + "\x00".repeat(60));
    const badHash = sha256Base64url(Buffer.from("wrong content"));
    const recordContent = `mypkg/_core.so,sha256=${badHash},${soContent.length}\n`;

    const zipBuf = await buildZip([
      { name: "mypkg/_core.so", content: soContent },
      { name: "mypkg-1.0.0.dist-info/RECORD", content: Buffer.from(recordContent) },
    ]);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        zipBuf.buffer.slice(zipBuf.byteOffset, zipBuf.byteOffset + zipBuf.byteLength),
    }));

    const result = await analyzeWheelBinaries("mypkg", "1.0.0", {
      packagetype: "bdist_wheel",
      url: "https://files.example/mypkg.whl",
      filename: "mypkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    }, { skipProvenance: false, skipAttestation: true });

    // RECORD mismatch finding should be present
    const recordFinding = result.findings.find((f) => f.title.includes("RECORD hash mismatch"));
    expect(recordFinding).toBeDefined();
    expect(recordFinding!.severity).toBe("high"); // .so extension → high severity
  });
});

// ---------------------------------------------------------------------------
// 13. WheelProvenanceResult confidence levels
// ---------------------------------------------------------------------------

describe("WheelProvenanceResult confidence levels", () => {
  it("confidence is high when RECORD passes and attestation verified", async () => {
    const fileContent = Buffer.from("source file");
    const hash = sha256Base64url(fileContent);
    const recordContent = `mypkg/__init__.py,sha256=${hash},${fileContent.length}\nmypkg-1.0.dist-info/RECORD,,\n`;

    const extractDir = await writeExtractedWheel([
      { name: "mypkg/__init__.py", content: fileContent },
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from(recordContent) },
    ]);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        urls: [{
          filename: "mypkg-1.0-py3-none-any.whl",
          provenance: {
            attestation_bundles: [{
              attestations: [{ envelope: { signature: "validSig" } }],
            }],
          },
        }],
      }),
    }));

    const wheelBytes = Buffer.from("wheel bytes");
    const result = await verifyWheelProvenance({
      wheelBytes,
      wheelFilename: "mypkg-1.0-py3-none-any.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: false,
    });

    expect(result.confidence).toBe("high");
    expect(result.isVerified).toBe(true);
  });

  it("confidence is low when any hash fails", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg/_core.so", content: Buffer.from("tampered") },
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from("mypkg/_core.so,sha256=AAAA,999\n") },
    ]);

    const result = await verifyWheelProvenance({
      wheelBytes: Buffer.from("wheel"),
      wheelFilename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
    });

    expect(result.confidence).toBe("low");
    expect(result.isVerified).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 14. Supply-chain mismatch findings severity
// ---------------------------------------------------------------------------

describe("supply-chain mismatch findings", () => {
  it("emits high-severity finding for each undeclared binary", async () => {
    const extractDir = await writeExtractedWheel([
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from("") },
    ]);

    const result = await verifyWheelProvenance({
      wheelBytes: Buffer.from("wheel"),
      wheelFilename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
      sdistMatch: {
        declaredModules: [],
        wheelBinaries: [
          "mypkg/_injected_a.so",
          "mypkg/_injected_b.so",
        ],
        extraBinaries: [
          "mypkg/_injected_a.so",
          "mypkg/_injected_b.so",
        ],
        matchesSdist: false,
      },
    });

    const mismatchFindings = result.findings.filter((f) =>
      f.title.includes("Undeclared native binary")
    );
    expect(mismatchFindings).toHaveLength(2);
    for (const f of mismatchFindings) {
      expect(f.severity).toBe("high");
      expect(f.category).toBe("wheelNativeBinary");
    }
  });
});

// ---------------------------------------------------------------------------
// 15. RECORD hash mismatch severity depends on file type
// ---------------------------------------------------------------------------

describe("RECORD hash mismatch severity", () => {
  it("emits high severity for a mismatched .so file", async () => {
    const soContent = Buffer.from("real so");
    const badHash = sha256Base64url(Buffer.from("different"));
    const recordContent = `mypkg/_core.so,sha256=${badHash},${soContent.length}\n`;

    const extractDir = await writeExtractedWheel([
      { name: "mypkg/_core.so", content: soContent },
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from(recordContent) },
    ]);

    const result = await verifyWheelProvenance({
      wheelBytes: Buffer.from("wheel"),
      wheelFilename: "mypkg-1.0-cp311-cp311-linux_x86_64.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
    });

    const mismatch = result.findings.find((f) => f.title.includes("RECORD hash mismatch"));
    expect(mismatch).toBeDefined();
    expect(mismatch!.severity).toBe("high");
  });

  it("emits medium severity for a mismatched .py file", async () => {
    const pyContent = Buffer.from("real py");
    const badHash = sha256Base64url(Buffer.from("different py"));
    const recordContent = `mypkg/__init__.py,sha256=${badHash},${pyContent.length}\n`;

    const extractDir = await writeExtractedWheel([
      { name: "mypkg/__init__.py", content: pyContent },
      { name: "mypkg-1.0.dist-info/RECORD", content: Buffer.from(recordContent) },
    ]);

    const result = await verifyWheelProvenance({
      wheelBytes: Buffer.from("wheel"),
      wheelFilename: "mypkg-1.0-py3-none-any.whl",
      extractDir,
      packageName: "mypkg",
      version: "1.0",
      skipAttestation: true,
    });

    const mismatch = result.findings.find((f) => f.title.includes("RECORD hash mismatch"));
    expect(mismatch).toBeDefined();
    expect(mismatch!.severity).toBe("medium");
  });
});
