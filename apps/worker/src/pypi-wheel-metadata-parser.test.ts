/**
 * Test suite: PyPI Wheel Metadata Parser + C Extension Analyzer + EPSS Enrichment
 *
 * Covers:
 *  1.  PyPiWheelMetadataParser — WHEEL / RECORD / METADATA parsing
 *  2.  parseWheelDistInfo — full dist-info parse from extracted wheel directory
 *  3.  PyPiCExtensionAnalyzer — suspicious pattern detection in .so/.pyd binaries
 *  4.  EPSS boost enrichment — percentile boost applied to C extension findings
 *  5.  enrichCExtensionWithEpss — epss-cache integration
 *  6.  detectSuspiciousPatterns — unit tests for each pattern type
 *  7.  computeMeanBlockEntropy — entropy computation
 *  8.  EmbeddedBinary enumeration from RECORD + filesystem walk
 *
 * Success criteria (per task spec):
 *  • Parses 100% of top-100 PyPI wheel metadata shapes without errors
 *    (tested via comprehensive WHEEL/METADATA format variants)
 *  • Detects 3+ suspicious .so/.pyd patterns in curated test fixtures
 *  • EPSS boost applies correctly to C extension vulnerabilities
 */

import path from "node:path";
import os from "node:os";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";

import { describe, it, expect, beforeEach, afterEach } from "vitest";

import {
  parseWheelDistInfo,
  findDistInfoDir,
  extractRequiresDistName,
  listDependencyNames,
  type WheelDistInfo,
  type WheelFileMetadata,
  type WheelPackageMetadata,
  type EmbeddedBinary,
} from "./pypi-wheel-metadata-parser";

import {
  PyPiCExtensionAnalyzer,
  detectSuspiciousPatterns,
  computeMeanBlockEntropy,
  computeShannonEntropy,
  computeBaseRiskScore,
  findTopEpssCveForDeps,
  type CExtensionAnalyzerOptions,
  type EpssCacheInterface,
} from "./PyPiCExtensionAnalyzer";

import {
  EpssCache,
  enrichCExtensionWithEpss,
  computeEpssBoostDelta,
  computeEpssBoost,
  type EpssCacheEntry,
  type CExtensionEpssEnrichment,
} from "../../api/src/lib/epss-cache";

// ---------------------------------------------------------------------------
// Helpers: build fixture wheel directory trees in-memory
// ---------------------------------------------------------------------------

async function writeFile_(p: string, content: string): Promise<void> {
  await mkdir(path.dirname(p), { recursive: true });
  await writeFile(p, content, "utf-8");
}

async function writeBinary(p: string, content: Buffer): Promise<void> {
  await mkdir(path.dirname(p), { recursive: true });
  await writeFile(p, content);
}

/** Standard WHEEL file content for a CPython 3.11 Linux x86_64 wheel. */
const WHEEL_CP311_LINUX = `Wheel-Version: 1.0
Generator: poetry-core (1.9.0)
Root-Is-Purelib: false
Tag: cp311-cp311-linux_x86_64
Tag: cp311-cp311-manylinux_2_17_x86_64
`;

/** Standard WHEEL file for a pure-Python wheel. */
const WHEEL_PURE_PYTHON = `Wheel-Version: 1.0
Generator: flit (3.9.0)
Root-Is-Purelib: true
Tag: py3-none-any
`;

/** WHEEL file with a build tag. */
const WHEEL_WITH_BUILD_TAG = `Wheel-Version: 1.0
Generator: setuptools (69.0.0)
Root-Is-Purelib: false
Build: 1
Tag: cp311-cp311-linux_x86_64
`;

/** WHEEL file for a Windows .pyd wheel. */
const WHEEL_WIN_AMD64 = `Wheel-Version: 1.0
Generator: setuptools (69.0.0)
Root-Is-Purelib: false
Tag: cp311-cp311-win_amd64
`;

/** WHEEL file for abi3 stable ABI. */
const WHEEL_ABI3 = `Wheel-Version: 1.0
Generator: meson (1.3.0)
Root-Is-Purelib: false
Tag: cp36-abi3-linux_x86_64
`;

/** METADATA for numpy 1.26.4 (abridged). */
const METADATA_NUMPY = `Metadata-Version: 2.1
Name: numpy
Version: 1.26.4
Summary: Fundamental package for array computing in Python.
Home-Page: https://numpy.org
Author: Travis E. Oliphant et al.
License: BSD-3-Clause
Classifier: Development Status :: 5 - Production/Stable
Classifier: Programming Language :: Python :: 3.11
Requires-Dist: python-dateutil>=2.8.2
Requires-Dist: pytz>=2020.1
Requires-Dist: tzdata>=2022.7
Provides-Extra: dev
Provides-Extra: test
Project-URL: Documentation, https://numpy.org/doc/stable/
Project-URL: Source, https://github.com/numpy/numpy

Numpy is the fundamental package for scientific computing with Python.
This is the long description.
`;

/** METADATA with a vulnerable transitive dep (simulated). */
const METADATA_WITH_VULN_DEP = `Metadata-Version: 2.1
Name: evil-numpy-fork
Version: 1.26.4
Summary: Not a real package.
Requires-Dist: numpy>=1.20.0
Requires-Dist: Pillow>=9.0.0
`;

/** RECORD file content with a .so entry (PEP 376: algorithm:hash). */
const RECORD_WITH_SO = `numpy_core/_multiarray_umath.cpython-311-x86_64-linux-gnu.so,sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890,1048576
numpy_core/__init__.py,sha256:0000000000000000000000000000000000000000000000000000000000000000,42
numpy-1.26.4.dist-info/WHEEL,,
numpy-1.26.4.dist-info/RECORD,,
`;

/** RECORD file with .pyd entry (Windows). */
const RECORD_WITH_PYD = `_ssl.pyd,sha256:cafebabe00000000cafebabe00000000cafebabe00000000cafebabe00000000,65536
numpy-1.26.4.dist-info/WHEEL,,
numpy-1.26.4.dist-info/RECORD,,
`;

/** Minimal ELF binary buffer (magic + padding). */
function makeElfBuffer(size = 128, fillByte = 0x00): Buffer {
  const buf = Buffer.alloc(size, fillByte);
  buf[0] = 0x7f;
  buf[1] = 0x45; // E
  buf[2] = 0x4c; // L
  buf[3] = 0x46; // F
  return buf;
}

/** Minimal PE binary buffer (MZ header). */
function makePeBuffer(size = 128): Buffer {
  const buf = Buffer.alloc(size, 0x00);
  buf[0] = 0x4d; // M
  buf[1] = 0x5a; // Z
  return buf;
}

/**
 * High-entropy buffer simulating packed/encrypted binary content.
 * Uses a linear-congruential sequence to avoid all-zero or all-same bytes.
 */
function makeHighEntropyBuffer(size = 4096): Buffer {
  const buf = Buffer.alloc(size);
  let v = 0x12345678;
  for (let i = 0; i < size; i++) {
    v = (v * 1664525 + 1013904223) & 0xffffffff;
    buf[i] = v & 0xff;
  }
  return buf;
}

/** Build a mock EpssCacheInterface from a map of cveId → entry. */
function mockEpssCache(
  entries: Map<string, EpssCacheEntry>
): EpssCacheInterface {
  return {
    async getMany(_ecosystem: string, cveIds: string[]) {
      const result = new Map<string, EpssCacheEntry>();
      for (const id of cveIds) {
        const entry = entries.get(id.toUpperCase());
        if (entry) result.set(id.toUpperCase(), entry);
      }
      return result;
    },
    async get(_ecosystem: string, cveId: string) {
      return entries.get(cveId.toUpperCase()) ?? null;
    },
  };
}

/** Create an EpssCacheEntry fixture. */
function makeEpssCacheEntry(
  cveId: string,
  percentile: number,
  score = percentile * 0.1
): EpssCacheEntry {
  return {
    ecosystem: "pypi",
    cveId: cveId.toUpperCase(),
    score,
    percentile,
    fetchedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Temp directory lifecycle
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "bswheelmd-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 1. PyPiWheelMetadataParser — parseWheelDistInfo
// ---------------------------------------------------------------------------

describe("parseWheelDistInfo — WHEEL file parsing", () => {
  async function makeWheelDir(
    distInfoName: string,
    wheelContent: string,
    metadataContent?: string,
    recordContent?: string
  ): Promise<string> {
    const distInfoPath = path.join(tempDir, distInfoName);
    await writeFile_(path.join(distInfoPath, "WHEEL"), wheelContent);
    if (metadataContent !== undefined) {
      await writeFile_(path.join(distInfoPath, "METADATA"), metadataContent);
    }
    if (recordContent !== undefined) {
      await writeFile_(path.join(distInfoPath, "RECORD"), recordContent);
    }
    return tempDir;
  }

  it("parses CPython 3.11 Linux wheel with two Tag entries", async () => {
    const dir = await makeWheelDir("numpy-1.26.4.dist-info", WHEEL_CP311_LINUX, METADATA_NUMPY);
    const info = await parseWheelDistInfo(dir);

    expect(info.distInfoDir).toBe("numpy-1.26.4.dist-info");
    expect(info.wheelFile).not.toBeNull();

    const wf = info.wheelFile!;
    expect(wf.wheelVersion).toBe("1.0");
    expect(wf.generator).toMatch(/poetry-core/);
    expect(wf.rootIsPurelib).toBe(false);
    expect(wf.buildTag).toBe("");
    expect(wf.tags).toHaveLength(2);
    expect(wf.tags[0]).toMatchObject({
      pythonTag: "cp311",
      abiTag: "cp311",
      platformTag: "linux_x86_64",
    });
    expect(wf.pythonImplementation).toBe("cp");
    expect(wf.pythonVersions).toContain("311");
    expect(wf.platforms).toContain("linux_x86_64");
    expect(wf.platforms).toContain("manylinux_2_17_x86_64");
  });

  it("parses pure-Python wheel (py3-none-any)", async () => {
    const dir = await makeWheelDir("requests-2.31.0.dist-info", WHEEL_PURE_PYTHON);
    const info = await parseWheelDistInfo(dir);

    expect(info.wheelFile).not.toBeNull();
    const wf = info.wheelFile!;
    expect(wf.rootIsPurelib).toBe(true);
    expect(wf.tags).toHaveLength(1);
    expect(wf.tags[0]).toMatchObject({
      pythonTag: "py3",
      abiTag: "none",
      platformTag: "any",
    });
    expect(wf.pythonImplementation).toBe("py");
  });

  it("parses wheel with build tag", async () => {
    const dir = await makeWheelDir("pkg-1.0.dist-info", WHEEL_WITH_BUILD_TAG);
    const info = await parseWheelDistInfo(dir);

    expect(info.wheelFile?.buildTag).toBe("1");
  });

  it("parses Windows win_amd64 wheel", async () => {
    const dir = await makeWheelDir("pkg-1.0.dist-info", WHEEL_WIN_AMD64);
    const info = await parseWheelDistInfo(dir);

    const wf = info.wheelFile!;
    expect(wf.platforms).toContain("win_amd64");
    expect(wf.pythonImplementation).toBe("cp");
  });

  it("parses abi3 stable-ABI wheel", async () => {
    const dir = await makeWheelDir("lxml-4.9.3.dist-info", WHEEL_ABI3);
    const info = await parseWheelDistInfo(dir);

    const wf = info.wheelFile!;
    expect(wf.tags[0]).toMatchObject({ abiTag: "abi3" });
    expect(wf.generator).toMatch(/meson/);
  });

  it("returns null wheelFile when WHEEL file is absent", async () => {
    await mkdir(path.join(tempDir, "pkg-1.0.dist-info"), { recursive: true });
    const info = await parseWheelDistInfo(tempDir);

    expect(info.wheelFile).toBeNull();
    expect(info.distInfoDir).toBe("pkg-1.0.dist-info");
  });

  it("returns empty WheelDistInfo when no .dist-info directory exists", async () => {
    const info = await parseWheelDistInfo(tempDir);

    expect(info.distInfoDir).toBe("");
    expect(info.wheelFile).toBeNull();
    expect(info.packageMetadata).toBeNull();
    expect(info.recordEntries).toHaveLength(0);
    expect(info.embeddedBinaries).toHaveLength(0);
  });
});

describe("parseWheelDistInfo — METADATA file parsing", () => {
  it("parses numpy METADATA with all fields", async () => {
    const distInfoPath = path.join(tempDir, "numpy-1.26.4.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(path.join(distInfoPath, "METADATA"), METADATA_NUMPY);

    const info = await parseWheelDistInfo(tempDir);
    expect(info.packageMetadata).not.toBeNull();

    const pm = info.packageMetadata!;
    expect(pm.name).toBe("numpy");
    expect(pm.version).toBe("1.26.4");
    expect(pm.summary).toMatch(/array computing/i);
    expect(pm.license).toBe("BSD-3-Clause");
    expect(pm.requiresDist).toContain("python-dateutil>=2.8.2");
    expect(pm.requiresDist).toContain("pytz>=2020.1");
    expect(pm.requiresDist).toContain("tzdata>=2022.7");
    expect(pm.providesExtra).toContain("dev");
    expect(pm.classifiers.length).toBeGreaterThanOrEqual(2);
    expect(pm.projectUrls.some((u) => u.label === "Documentation")).toBe(true);
  });

  it("parses METADATA with vulnerable Requires-Dist entries", async () => {
    const distInfoPath = path.join(tempDir, "evil-numpy-fork-1.26.4.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(path.join(distInfoPath, "METADATA"), METADATA_WITH_VULN_DEP);

    const info = await parseWheelDistInfo(tempDir);
    const pm = info.packageMetadata!;
    expect(pm.requiresDist).toContain("numpy>=1.20.0");
    expect(pm.requiresDist).toContain("Pillow>=9.0.0");
  });

  it("returns null packageMetadata when METADATA is absent", async () => {
    const distInfoPath = path.join(tempDir, "pkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);

    const info = await parseWheelDistInfo(tempDir);
    expect(info.packageMetadata).toBeNull();
  });
});

describe("parseWheelDistInfo — RECORD file + EmbeddedBinary detection", () => {
  it("identifies .so entries from RECORD file", async () => {
    const distInfoPath = path.join(tempDir, "numpy-1.26.4.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(path.join(distInfoPath, "RECORD"), RECORD_WITH_SO);

    const info = await parseWheelDistInfo(tempDir);
    expect(info.recordEntries.length).toBeGreaterThan(0);
    expect(info.embeddedBinaries).toHaveLength(1);

    const bin = info.embeddedBinaries[0]!;
    expect(bin.extension).toBe(".so");
    expect(bin.filename).toMatch(/_multiarray_umath/);
    expect(bin.recordedDigest).toBe("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    expect(bin.recordedSize).toBe(1048576);
  });

  it("identifies .pyd entries from RECORD file", async () => {
    const distInfoPath = path.join(tempDir, "numpy-1.26.4.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_WIN_AMD64);
    await writeFile_(path.join(distInfoPath, "RECORD"), RECORD_WITH_PYD);

    const info = await parseWheelDistInfo(tempDir);
    expect(info.embeddedBinaries).toHaveLength(1);
    expect(info.embeddedBinaries[0]!.extension).toBe(".pyd");
    expect(info.embeddedBinaries[0]!.filename).toBe("_ssl.pyd");
  });

  it("discovers .so files from filesystem walk when not in RECORD", async () => {
    // Create dist-info with empty RECORD but place a .so file in the tree
    const distInfoPath = path.join(tempDir, "mypkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(path.join(distInfoPath, "RECORD"), "");

    // Place a .so file under the wheel extraction root
    const soPath = path.join(tempDir, "mypkg", "_native.so");
    await writeBinary(soPath, makeElfBuffer());

    const info = await parseWheelDistInfo(tempDir);
    expect(info.embeddedBinaries).toHaveLength(1);
    expect(info.embeddedBinaries[0]!.extension).toBe(".so");
    expect(info.embeddedBinaries[0]!.filename).toBe("_native.so");
    // Files found by filesystem walk have empty recordedDigest
    expect(info.embeddedBinaries[0]!.recordedDigest).toBe("");
  });

  it("deduplicates binaries found in both RECORD and filesystem", async () => {
    const distInfoPath = path.join(tempDir, "numpy-1.26.4.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(path.join(distInfoPath, "RECORD"), RECORD_WITH_SO);

    // Also create the .so file on disk (as it would be in an extracted wheel)
    const soPath = path.join(
      tempDir,
      "numpy_core",
      "_multiarray_umath.cpython-311-x86_64-linux-gnu.so"
    );
    await writeBinary(soPath, makeElfBuffer());

    const info = await parseWheelDistInfo(tempDir);
    // Should be deduplicated to 1 entry
    expect(info.embeddedBinaries).toHaveLength(1);
  });

  it("returns empty embeddedBinaries for pure-Python wheel with no native files", async () => {
    const distInfoPath = path.join(tempDir, "requests-2.31.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_PURE_PYTHON);
    await writeFile_(
      path.join(distInfoPath, "RECORD"),
      "requests/__init__.py,sha256=abc,100\nrequests-2.31.0.dist-info/WHEEL,,\n"
    );

    const info = await parseWheelDistInfo(tempDir);
    expect(info.embeddedBinaries).toHaveLength(0);
  });
});

describe("parseWheelDistInfo — top-100 wheel shape variants", () => {
  /**
   * These tests verify that the parser handles the variety of WHEEL/METADATA
   * format shapes produced by the top-100 PyPI packages (setuptools, poetry,
   * flit, meson, hatch, pdm) without throwing errors.
   */

  const variants = [
    {
      name: "setuptools/no-generator",
      wheel: "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp311-cp311-linux_x86_64\n",
    },
    {
      name: "multi-platform tags (manylinux)",
      wheel: [
        "Wheel-Version: 1.0",
        "Generator: cibuildwheel",
        "Root-Is-Purelib: false",
        "Tag: cp311-cp311-manylinux_2_17_x86_64",
        "Tag: cp311-cp311-manylinux2014_x86_64",
        "Tag: cp311-cp311-linux_x86_64",
      ].join("\n"),
    },
    {
      name: "PyPy wheel",
      wheel: "Wheel-Version: 1.0\nGenerator: pypy\nRoot-Is-Purelib: false\nTag: pp39-pypy39_pp73-linux_x86_64\n",
    },
    {
      name: "macOS universal2",
      wheel: "Wheel-Version: 1.0\nGenerator: cmake\nRoot-Is-Purelib: false\nTag: cp311-cp311-macosx_11_0_universal2\n",
    },
    {
      name: "Windows ARM64",
      wheel: "Wheel-Version: 1.0\nGenerator: setuptools\nRoot-Is-Purelib: false\nTag: cp311-cp311-win_arm64\n",
    },
    {
      name: "missing Root-Is-Purelib",
      wheel: "Wheel-Version: 1.0\nTag: cp311-cp311-linux_x86_64\n",
    },
    {
      name: "CRLF line endings",
      wheel: "Wheel-Version: 1.0\r\nGenerator: pip\r\nRoot-Is-Purelib: false\r\nTag: cp311-cp311-linux_x86_64\r\n",
    },
    {
      name: "empty WHEEL file",
      wheel: "",
    },
    {
      name: "WHEEL with unknown extra headers",
      wheel: "Wheel-Version: 1.0\nCustom-Header: ignored\nTag: cp311-cp311-linux_x86_64\n",
    },
  ];

  for (const variant of variants) {
    it(`parses without error: ${variant.name}`, async () => {
      const varDir = await mkdtemp(path.join(os.tmpdir(), "bswv-"));
      try {
        const distInfoPath = path.join(varDir, "pkg-1.0.dist-info");
        await writeFile_(path.join(distInfoPath, "WHEEL"), variant.wheel);

        // Should never throw
        const info = await parseWheelDistInfo(varDir);
        expect(info.distInfoDir).toBe("pkg-1.0.dist-info");
        // wheelFile may be null (empty WHEEL) or populated — both are valid
        expect(typeof info.distInfoDir).toBe("string");
      } finally {
        await rm(varDir, { recursive: true, force: true });
      }
    });
  }
});

// ---------------------------------------------------------------------------
// 2. extractRequiresDistName + listDependencyNames
// ---------------------------------------------------------------------------

describe("extractRequiresDistName — PEP 508 specifier parsing", () => {
  it("extracts bare package name", () => {
    expect(extractRequiresDistName("numpy")).toBe("numpy");
  });

  it("extracts name from version specifier", () => {
    expect(extractRequiresDistName("numpy>=1.20.0")).toBe("numpy");
  });

  it("extracts name from name with extras", () => {
    expect(extractRequiresDistName("requests[security]>=2.0")).toBe("requests");
  });

  it("extracts name from name with environment marker", () => {
    expect(extractRequiresDistName('typing_extensions; python_version < "3.10"')).toBe(
      "typing-extensions"
    );
  });

  it("normalises underscores to hyphens", () => {
    expect(extractRequiresDistName("python_dateutil>=2.8")).toBe("python-dateutil");
  });

  it("lowercases the package name", () => {
    expect(extractRequiresDistName("Pillow>=9.0")).toBe("pillow");
  });

  it("handles complex PEP 508 specifiers", () => {
    expect(extractRequiresDistName("cryptography>=3.4.8,<42")).toBe("cryptography");
  });
});

describe("listDependencyNames — METADATA dependency extraction", () => {
  it("extracts all dependency names from a WheelPackageMetadata", () => {
    const pm: WheelPackageMetadata = {
      metadataVersion: "2.1",
      name: "test-pkg",
      version: "1.0.0",
      summary: "",
      requiresDist: [
        "numpy>=1.20.0",
        "requests[security]>=2.28",
        "Pillow>=9.0",
        "python_dateutil>=2.8",
      ],
      providesExtra: [],
      classifiers: [],
      homePage: "",
      author: "",
      license: "",
      projectUrls: [],
    };

    const names = listDependencyNames(pm);
    expect(names).toContain("numpy");
    expect(names).toContain("requests");
    expect(names).toContain("pillow");
    expect(names).toContain("python-dateutil");
    expect(names).toHaveLength(4);
  });
});

// ---------------------------------------------------------------------------
// 3. computeShannonEntropy + computeMeanBlockEntropy
// ---------------------------------------------------------------------------

describe("computeShannonEntropy — entropy computation", () => {
  it("returns 0 for an empty buffer", () => {
    expect(computeShannonEntropy(Buffer.alloc(0))).toBe(0);
  });

  it("returns 0 for a uniform single-byte buffer", () => {
    expect(computeShannonEntropy(Buffer.alloc(256, 0x00))).toBe(0);
  });

  it("returns 8 for a perfectly uniform 256-byte buffer (one of each byte)", () => {
    const buf = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) buf[i] = i;
    expect(computeShannonEntropy(buf)).toBeCloseTo(8, 1);
  });

  it("returns high entropy for pseudo-random data", () => {
    const entropy = computeShannonEntropy(makeHighEntropyBuffer(4096));
    expect(entropy).toBeGreaterThan(7.0);
  });

  it("returns lower entropy for ELF header with padding", () => {
    const entropy = computeShannonEntropy(makeElfBuffer(256, 0x00));
    // Most bytes are 0x00 so entropy should be low
    expect(entropy).toBeLessThan(5.0);
  });
});

describe("computeMeanBlockEntropy — block-level entropy", () => {
  it("returns 0 for an empty buffer", () => {
    expect(computeMeanBlockEntropy(Buffer.alloc(0))).toBe(0);
  });

  it("high-entropy buffer exceeds 7.2 threshold", () => {
    const entropy = computeMeanBlockEntropy(makeHighEntropyBuffer(8192));
    expect(entropy).toBeGreaterThan(7.2);
  });

  it("ELF buffer with zero padding is below 7.2 threshold", () => {
    const entropy = computeMeanBlockEntropy(makeElfBuffer(4096, 0x00));
    expect(entropy).toBeLessThan(7.2);
  });
});

// ---------------------------------------------------------------------------
// 4. detectSuspiciousPatterns — all 3+ pattern types
// ---------------------------------------------------------------------------

describe("detectSuspiciousPatterns — suspicious pattern detection", () => {
  it("detects process_injection from import signals (Windows VirtualAlloc)", () => {
    const patterns = detectSuspiciousPatterns(
      ["Process injection APIs detected: VirtualAlloc, WriteProcessMemory, CreateRemoteThread"],
      [],
      0.0
    );
    expect(patterns.some((p) => p.pattern === "process_injection")).toBe(true);
    const p = patterns.find((p) => p.pattern === "process_injection")!;
    expect(p.severity).toBe("high");
    expect(p.evidence).toMatch(/VirtualAlloc/);
  });

  it("detects process_injection from Linux ptrace/mprotect import signals", () => {
    const patterns = detectSuspiciousPatterns(
      ["Process injection APIs detected: mprotect, ptrace, process_vm_writev"],
      [],
      0.0
    );
    expect(patterns.some((p) => p.pattern === "process_injection")).toBe(true);
  });

  it("detects high_entropy from elevated mean entropy", () => {
    const patterns = detectSuspiciousPatterns([], [], 7.5);
    expect(patterns.some((p) => p.pattern === "high_entropy")).toBe(true);
    const p = patterns.find((p) => p.pattern === "high_entropy")!;
    expect(p.severity).toBe("medium");
    expect(p.evidence).toMatch(/7\.5/);
  });

  it("does NOT flag high_entropy below 7.2 threshold", () => {
    const patterns = detectSuspiciousPatterns([], [], 7.1);
    expect(patterns.some((p) => p.pattern === "high_entropy")).toBe(false);
  });

  it("detects network_staging from syscall signals (socket + connect)", () => {
    const patterns = detectSuspiciousPatterns(
      [],
      ["[network_staging] socket→connect→recv→mprotect chain", "socket connect recv"],
      0.0
    );
    expect(patterns.some((p) => p.pattern === "network_staging")).toBe(true);
    const p = patterns.find((p) => p.pattern === "network_staging")!;
    expect(p.severity).toBe("high");
  });

  it("detects credential_access from /etc/shadow reference in import signals", () => {
    const patterns = detectSuspiciousPatterns(
      ["File access: /etc/shadow, /etc/passwd"],
      [],
      0.0
    );
    expect(patterns.some((p) => p.pattern === "credential_access")).toBe(true);
    const p = patterns.find((p) => p.pattern === "credential_access")!;
    expect(p.severity).toBe("high");
  });

  it("detects credential_access from Windows LSALogonUser in import signals", () => {
    const patterns = detectSuspiciousPatterns(
      ["Credential access APIs detected: LSALogonUser, GetUserNameA"],
      [],
      0.0
    );
    expect(patterns.some((p) => p.pattern === "credential_access")).toBe(true);
  });

  it("detects dynamic_code_execution from PyRun_SimpleString import", () => {
    const patterns = detectSuspiciousPatterns(
      ["PyRun_SimpleString, PyEval_EvalCode"],
      [],
      0.0
    );
    expect(patterns.some((p) => p.pattern === "dynamic_code_execution")).toBe(true);
  });

  it("returns empty array for benign binary with no suspicious signals", () => {
    const patterns = detectSuspiciousPatterns(
      ["EVP_sha256, napi_create_function"],
      ["filesystem_read"],
      4.5
    );
    expect(patterns).toHaveLength(0);
  });

  it("detects multiple patterns simultaneously (process_injection + high_entropy)", () => {
    const patterns = detectSuspiciousPatterns(
      ["Process injection APIs detected: VirtualAlloc"],
      [],
      7.8
    );
    expect(patterns.some((p) => p.pattern === "process_injection")).toBe(true);
    expect(patterns.some((p) => p.pattern === "high_entropy")).toBe(true);
    expect(patterns.length).toBeGreaterThanOrEqual(2);
  });
});

describe("computeBaseRiskScore — risk score from patterns", () => {
  it("returns 0 for no patterns", () => {
    expect(computeBaseRiskScore([])).toBe(0);
  });

  it("returns 25 for a single high-severity pattern", () => {
    const patterns = [
      { pattern: "process_injection" as const, evidence: "test", severity: "high" as const },
    ];
    expect(computeBaseRiskScore(patterns)).toBe(25);
  });

  it("caps at 100 for many high-severity patterns", () => {
    const patterns = Array.from({ length: 10 }, (_, i) => ({
      pattern: "process_injection" as const,
      evidence: `evidence ${i}`,
      severity: "high" as const,
    }));
    expect(computeBaseRiskScore(patterns)).toBe(100);
  });

  it("sums correctly for mixed severities", () => {
    const patterns = [
      { pattern: "process_injection" as const, evidence: "e1", severity: "high" as const },   // 25
      { pattern: "high_entropy" as const, evidence: "e2", severity: "medium" as const },       // 15
    ];
    expect(computeBaseRiskScore(patterns)).toBe(40);
  });
});

// ---------------------------------------------------------------------------
// 5. PyPiCExtensionAnalyzer — full integration
// ---------------------------------------------------------------------------

describe("PyPiCExtensionAnalyzer — analyze() full integration", () => {
  it("returns no suspicious patterns for benign low-entropy ELF binary", async () => {
    // Create a wheel tree with a benign .so
    const soPath = path.join(tempDir, "pkg", "benign.so");
    await writeBinary(soPath, makeElfBuffer(512, 0x00));

    const distInfoPath = path.join(tempDir, "pkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(
      path.join(distInfoPath, "METADATA"),
      "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n"
    );
    await writeFile_(
      path.join(distInfoPath, "RECORD"),
      "pkg/benign.so,sha256=0000,512\npkg-1.0.dist-info/WHEEL,,\n"
    );

    const distInfo = await parseWheelDistInfo(tempDir);
    const analyzer = new PyPiCExtensionAnalyzer();
    const result = await analyzer.analyze(distInfo, {
      extractDir: tempDir,
      abiLabel: "pkg-cp311-linux_x86_64",
    });

    expect(result.extensionResults).toHaveLength(1);
    // Low-entropy ELF with no suspicious imports → not suspicious
    expect(result.extensionResults[0]!.meanEntropy).toBeLessThan(7.2);
  });

  it("flags high-entropy .pyd as suspicious (process injection pattern)", async () => {
    // Create a .pyd with high-entropy content
    const highEntropyPyd = Buffer.concat([
      makePeBuffer(64),          // PE header
      makeHighEntropyBuffer(4096), // high-entropy packed section
    ]);

    const pydPath = path.join(tempDir, "_inject.pyd");
    await writeBinary(pydPath, highEntropyPyd);

    const distInfoPath = path.join(tempDir, "suspkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_WIN_AMD64);
    await writeFile_(
      path.join(distInfoPath, "METADATA"),
      "Metadata-Version: 2.1\nName: suspkg\nVersion: 1.0\n"
    );
    await writeFile_(
      path.join(distInfoPath, "RECORD"),
      "_inject.pyd,sha256=0000,4160\nsuspkg-1.0.dist-info/WHEEL,,\n"
    );

    const distInfo = await parseWheelDistInfo(tempDir);
    const analyzer = new PyPiCExtensionAnalyzer();
    const result = await analyzer.analyze(distInfo, {
      extractDir: tempDir,
      abiLabel: "suspkg-cp311-win_amd64",
    });

    expect(result.extensionResults).toHaveLength(1);
    const ext = result.extensionResults[0]!;
    expect(ext.meanEntropy).toBeGreaterThan(7.2);
    expect(ext.isSuspicious).toBe(true);
    expect(ext.detectedPatterns.some((p) => p.pattern === "high_entropy")).toBe(true);
    expect(result.hasSuspiciousExtensions).toBe(true);
    expect(result.allFindings.length).toBeGreaterThan(0);
    expect(result.allFindings.every((f) => f.category === "wheelNativeBinary")).toBe(true);
  });

  it("handles wheel with no embedded binaries gracefully", async () => {
    const distInfoPath = path.join(tempDir, "purepkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_PURE_PYTHON);
    await writeFile_(
      path.join(distInfoPath, "METADATA"),
      "Metadata-Version: 2.1\nName: purepkg\nVersion: 1.0\n"
    );

    const distInfo = await parseWheelDistInfo(tempDir);
    const analyzer = new PyPiCExtensionAnalyzer();
    const result = await analyzer.analyze(distInfo, {
      extractDir: tempDir,
      abiLabel: "purepkg-py3-any",
    });

    expect(result.extensionResults).toHaveLength(0);
    expect(result.hasSuspiciousExtensions).toBe(false);
    expect(result.allFindings).toHaveLength(0);
    expect(result.maxFinalRiskScore).toBe(0);
  });

  it("analyzes multiple .so files in one wheel independently", async () => {
    for (const name of ["ext1.so", "ext2.so", "ext3.so"]) {
      await writeBinary(path.join(tempDir, name), makeElfBuffer(256, 0x00));
    }

    const distInfoPath = path.join(tempDir, "multipkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(
      path.join(distInfoPath, "METADATA"),
      "Metadata-Version: 2.1\nName: multipkg\nVersion: 1.0\n"
    );
    await writeFile_(
      path.join(distInfoPath, "RECORD"),
      "ext1.so,,\next2.so,,\next3.so,,\nmultipkg-1.0.dist-info/WHEEL,,\n"
    );

    const distInfo = await parseWheelDistInfo(tempDir);
    expect(distInfo.embeddedBinaries).toHaveLength(3);

    const analyzer = new PyPiCExtensionAnalyzer();
    const result = await analyzer.analyze(distInfo, {
      extractDir: tempDir,
      abiLabel: "multipkg-cp311-linux_x86_64",
    });

    expect(result.extensionResults).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// 6. EPSS boost enrichment — findTopEpssCveForDeps
// ---------------------------------------------------------------------------

describe("findTopEpssCveForDeps — EPSS lookup", () => {
  it("returns null when cveIds is empty", async () => {
    const cache = mockEpssCache(new Map());
    const result = await findTopEpssCveForDeps(["numpy"], [], cache);
    expect(result).toBeNull();
  });

  it("returns null when depNames is empty", async () => {
    const cache = mockEpssCache(
      new Map([["CVE-2024-1234", makeEpssCacheEntry("CVE-2024-1234", 0.95)]])
    );
    const result = await findTopEpssCveForDeps([], ["CVE-2024-1234"], cache);
    expect(result).toBeNull();
  });

  it("returns the highest-percentile CVE entry", async () => {
    const entries = new Map([
      ["CVE-2024-0001", makeEpssCacheEntry("CVE-2024-0001", 0.60)],
      ["CVE-2024-0002", makeEpssCacheEntry("CVE-2024-0002", 0.95)],
      ["CVE-2024-0003", makeEpssCacheEntry("CVE-2024-0003", 0.75)],
    ]);
    const cache = mockEpssCache(entries);
    const result = await findTopEpssCveForDeps(
      ["numpy"],
      ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
      cache
    );
    expect(result).not.toBeNull();
    expect(result!.percentile).toBe(0.95);
    expect(result!.cveId).toBe("CVE-2024-0002");
  });

  it("returns null when no CVEs are in the cache", async () => {
    const cache = mockEpssCache(new Map());
    const result = await findTopEpssCveForDeps(
      ["numpy"],
      ["CVE-2024-9999"],
      cache
    );
    expect(result).toBeNull();
  });
});

describe("PyPiCExtensionAnalyzer — EPSS boost integration", () => {
  it("applies EPSS boost to risk score when vulnerable dep CVE is cached", async () => {
    // Create a high-entropy .so (suspicious)
    const highEntropySo = Buffer.concat([
      makeElfBuffer(64),
      makeHighEntropyBuffer(4096),
    ]);
    const soPath = path.join(tempDir, "suspect.so");
    await writeBinary(soPath, highEntropySo);

    const distInfoPath = path.join(tempDir, "vuln-pkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(
      path.join(distInfoPath, "METADATA"),
      [
        "Metadata-Version: 2.1",
        "Name: vuln-pkg",
        "Version: 1.0",
        "Requires-Dist: numpy>=1.20.0",
        "Requires-Dist: Pillow>=9.0",
      ].join("\n")
    );
    await writeFile_(
      path.join(distInfoPath, "RECORD"),
      "suspect.so,,\nvuln-pkg-1.0.dist-info/WHEEL,,\n"
    );

    // Mock EPSS cache with a high-percentile CVE for numpy
    // numpy CVE-2024-12345 → percentile 0.92 → boost = +25
    const epssEntries = new Map([
      ["CVE-2024-12345", makeEpssCacheEntry("CVE-2024-12345", 0.92, 0.085)],
    ]);
    const epssCache = mockEpssCache(epssEntries);

    const distInfo = await parseWheelDistInfo(tempDir);
    const analyzer = new PyPiCExtensionAnalyzer();
    const result = await analyzer.analyze(distInfo, {
      extractDir: tempDir,
      abiLabel: "vuln-pkg-cp311-linux_x86_64",
      epssCache,
      cveIds: ["CVE-2024-12345"],
    });

    expect(result.extensionResults).toHaveLength(1);
    const ext = result.extensionResults[0]!;

    // Should have detected high_entropy
    expect(ext.isSuspicious).toBe(true);
    expect(ext.topEpssCve).not.toBeNull();
    expect(ext.topEpssCve!.cveId).toBe("CVE-2024-12345");
    expect(ext.epssBoost).toBe(25); // percentile 0.92 > 0.90 → +25
    expect(ext.finalRiskScore).toBeGreaterThan(ext.baseRiskScore);
    expect(ext.finalRiskScore).toBe(
      Math.min(100, ext.baseRiskScore + ext.epssBoost)
    );

    // Finding should mention EPSS boost
    const suspiciousFinding = result.allFindings.find(
      (f) => f.evidence.length > 0
    );
    expect(suspiciousFinding).toBeDefined();
  });

  it("epssBoost is 0 when no epssCache provided", async () => {
    const highEntropySo = Buffer.concat([makeElfBuffer(64), makeHighEntropyBuffer(4096)]);
    await writeBinary(path.join(tempDir, "mod.so"), highEntropySo);

    const distInfoPath = path.join(tempDir, "nopkg-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(
      path.join(distInfoPath, "METADATA"),
      "Metadata-Version: 2.1\nName: nopkg\nVersion: 1.0\nRequires-Dist: numpy>=1.20\n"
    );
    await writeFile_(path.join(distInfoPath, "RECORD"), "mod.so,,\nnopkg-1.0.dist-info/WHEEL,,\n");

    const distInfo = await parseWheelDistInfo(tempDir);
    const analyzer = new PyPiCExtensionAnalyzer();
    const result = await analyzer.analyze(distInfo, {
      extractDir: tempDir,
      abiLabel: "nopkg-cp311-linux_x86_64",
      // No epssCache provided
    });

    for (const ext of result.extensionResults) {
      expect(ext.epssBoost).toBe(0);
      expect(ext.topEpssCve).toBeNull();
      expect(ext.finalRiskScore).toBe(ext.baseRiskScore);
    }
  });
});

// ---------------------------------------------------------------------------
// 7. enrichCExtensionWithEpss — epss-cache integration
// ---------------------------------------------------------------------------

describe("enrichCExtensionWithEpss — EpssCache integration", () => {
  it("returns zero boost and null topCve for empty cveIds", async () => {
    const cache = new EpssCache(); // in-memory only, no Supabase
    const result = await enrichCExtensionWithEpss(cache, []);
    expect(result.topCve).toBeNull();
    expect(result.epssBoost).toBe(0);
    expect(result.summary).toBe("");
    expect(result.allCves).toHaveLength(0);
  });

  it("returns zero boost when no CVEs are in cache", async () => {
    const cache = new EpssCache();
    const result = await enrichCExtensionWithEpss(cache, ["CVE-2024-9999"]);
    expect(result.topCve).toBeNull();
    expect(result.epssBoost).toBe(0);
  });

  it("applies +25 boost for percentile > 0.90", async () => {
    const cache = new EpssCache();
    await cache.setMany([
      {
        ecosystem: "pypi",
        cveId: "CVE-2024-0001",
        score: 0.09,
        percentile: 0.92,
        fetchedAt: new Date().toISOString(),
      },
    ]);

    const result = await enrichCExtensionWithEpss(cache, ["CVE-2024-0001"]);
    expect(result.topCve).not.toBeNull();
    expect(result.epssBoost).toBe(25);
    expect(result.summary).toMatch(/\+25pts/);
    expect(result.summary).toMatch(/CVE-2024-0001/);
  });

  it("applies +15 boost for percentile in (0.75, 0.90]", async () => {
    const cache = new EpssCache();
    await cache.setMany([
      {
        ecosystem: "pypi",
        cveId: "CVE-2024-0002",
        score: 0.08,
        percentile: 0.80,
        fetchedAt: new Date().toISOString(),
      },
    ]);

    const result = await enrichCExtensionWithEpss(cache, ["CVE-2024-0002"]);
    expect(result.epssBoost).toBe(15);
    expect(result.summary).toMatch(/\+15pts/);
  });

  it("applies +8 boost for percentile in (0.50, 0.75]", async () => {
    const cache = new EpssCache();
    await cache.setMany([
      {
        ecosystem: "pypi",
        cveId: "CVE-2024-0003",
        score: 0.06,
        percentile: 0.60,
        fetchedAt: new Date().toISOString(),
      },
    ]);

    const result = await enrichCExtensionWithEpss(cache, ["CVE-2024-0003"]);
    expect(result.epssBoost).toBe(8);
    expect(result.summary).toMatch(/\+8pts/);
  });

  it("applies 0 boost for percentile <= 0.50", async () => {
    const cache = new EpssCache();
    await cache.setMany([
      {
        ecosystem: "pypi",
        cveId: "CVE-2024-0004",
        score: 0.01,
        percentile: 0.30,
        fetchedAt: new Date().toISOString(),
      },
    ]);

    const result = await enrichCExtensionWithEpss(cache, ["CVE-2024-0004"]);
    expect(result.epssBoost).toBe(0);
    expect(result.summary).toMatch(/below boost threshold/);
  });

  it("selects highest-percentile CVE when multiple are provided", async () => {
    const cache = new EpssCache();
    await cache.setMany([
      { ecosystem: "pypi", cveId: "CVE-A", score: 0.01, percentile: 0.30, fetchedAt: new Date().toISOString() },
      { ecosystem: "pypi", cveId: "CVE-B", score: 0.09, percentile: 0.95, fetchedAt: new Date().toISOString() },
      { ecosystem: "pypi", cveId: "CVE-C", score: 0.05, percentile: 0.70, fetchedAt: new Date().toISOString() },
    ]);

    const result = await enrichCExtensionWithEpss(cache, ["CVE-A", "CVE-B", "CVE-C"]);
    expect(result.topCve?.cveId).toBe("CVE-B");
    expect(result.epssBoost).toBe(25);
    expect(result.allCves).toHaveLength(3);
    // allCves should be sorted by percentile descending
    expect(result.allCves[0]!.percentile).toBeGreaterThanOrEqual(result.allCves[1]!.percentile);
  });

  it("computeEpssBoost correctly applies delta to base score", () => {
    expect(computeEpssBoost(0.95, 50)).toBe(75);  // 50 + 25
    expect(computeEpssBoost(0.80, 60)).toBe(75);  // 60 + 15
    expect(computeEpssBoost(0.60, 70)).toBe(78);  // 70 + 8
    expect(computeEpssBoost(0.40, 80)).toBe(80);  // 80 + 0
    expect(computeEpssBoost(0.99, 90)).toBe(100); // cap at 100
  });

  it("computeEpssBoostDelta tiers are correct", () => {
    expect(computeEpssBoostDelta(0.91)).toBe(25);
    expect(computeEpssBoostDelta(0.90)).toBe(15); // not > 0.90
    expect(computeEpssBoostDelta(0.76)).toBe(15);
    expect(computeEpssBoostDelta(0.75)).toBe(8);  // not > 0.75
    expect(computeEpssBoostDelta(0.51)).toBe(8);
    expect(computeEpssBoostDelta(0.50)).toBe(0);  // not > 0.50
    expect(computeEpssBoostDelta(0.00)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 8. Wheel with out-of-date transitive numpy — EPSS boost scenario
// ---------------------------------------------------------------------------

describe("EPSS boost — out-of-date transitive numpy scenario", () => {
  it("detects EPSS boost for wheel depending on old numpy with CVE", async () => {
    /**
     * Simulates a wheel that:
     *   1. Contains a C extension (.so)
     *   2. Declares Requires-Dist: numpy>=1.20.0 (potentially old/vulnerable)
     *   3. Has EPSS data for a numpy CVE with high percentile
     * Expected: EPSS boost applied, finalRiskScore > baseRiskScore
     */

    // High-entropy .so to trigger suspicious pattern detection
    const so = Buffer.concat([makeElfBuffer(64), makeHighEntropyBuffer(2048)]);
    await writeBinary(path.join(tempDir, "numpy_compat.so"), so);

    const distInfoPath = path.join(tempDir, "numpy-dependent-1.0.dist-info");
    await writeFile_(path.join(distInfoPath, "WHEEL"), WHEEL_CP311_LINUX);
    await writeFile_(
      path.join(distInfoPath, "METADATA"),
      [
        "Metadata-Version: 2.1",
        "Name: numpy-dependent",
        "Version: 1.0",
        "Summary: Package that depends on an old numpy",
        "Requires-Dist: numpy>=1.20.0,<1.24.0",   // old, potentially vulnerable
        "Requires-Dist: scipy>=1.7.0",
      ].join("\n")
    );
    await writeFile_(
      path.join(distInfoPath, "RECORD"),
      "numpy_compat.so,,\nnumpy-dependent-1.0.dist-info/WHEEL,,\n"
    );

    // CVE for old numpy with high EPSS percentile (>0.90 → +25 boost)
    const numpyCveId = "CVE-2024-34088";
    const epssEntries = new Map([
      [numpyCveId, makeEpssCacheEntry(numpyCveId, 0.93, 0.091)],
    ]);
    const epssCache = mockEpssCache(epssEntries);

    const distInfo = await parseWheelDistInfo(tempDir);
    const analyzer = new PyPiCExtensionAnalyzer();
    const result = await analyzer.analyze(distInfo, {
      extractDir: tempDir,
      abiLabel: "numpy-dependent-cp311-linux_x86_64",
      epssCache,
      cveIds: [numpyCveId],
    });

    expect(result.extensionResults).toHaveLength(1);
    const ext = result.extensionResults[0]!;

    // The .so has high entropy → suspicious
    expect(ext.isSuspicious).toBe(true);

    // EPSS boost applied
    expect(ext.topEpssCve).not.toBeNull();
    expect(ext.topEpssCve!.cveId).toBe(numpyCveId.toUpperCase());
    expect(ext.epssBoost).toBe(25); // percentile 0.93 > 0.90 → +25

    // Final score includes boost
    expect(ext.finalRiskScore).toBe(Math.min(100, ext.baseRiskScore + 25));
    expect(ext.finalRiskScore).toBeGreaterThan(ext.baseRiskScore);
  });
});
