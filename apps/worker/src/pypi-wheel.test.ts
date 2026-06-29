/**
 * Tests for PyPI wheel binary analysis:
 *   - PyPiWheelPackageSource (package-source.ts)
 *   - Python native-extension detection (native-indicators.ts)
 *   - PYD / CPython ABI-tagged .so picking in extractor.ts / fingerprint.ts
 *   - manifest-analyzer pythonBinaryExtension finding + ManifestAnalysis fields
 *
 * All tests are offline — no network calls. Fixture directories contain
 * pre-crafted ELF binaries with .so / .pyd / cpython-ABI-tagged names.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  hasPyPiAbiTag,
  isPythonNativeExtension,
  PYTHON_NATIVE_EXTENSIONS,
  PYPI_ABI_TAG_RE,
} from "./native-indicators";
import { isCandidateBinary } from "./fingerprint";
import { collectWheelNativeExtensions } from "./package-source";
import { FileSystemBinaryExtractor } from "./extractor";
import { ManifestAnalyzer } from "./manifest-analyzer";
import type { PackageManifest, ScriptAnalysisInput } from "./types";

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../fixtures"
);

function manifest(overrides: Partial<PackageManifest> = {}): PackageManifest {
  return {
    name: "fixture",
    version: "1.0.0",
    scripts: {},
    dependencies: {},
    optionalDependencies: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// native-indicators: hasPyPiAbiTag
// ---------------------------------------------------------------------------

describe("hasPyPiAbiTag — wheel filename ABI tag detection", () => {
  it("detects CPython platform wheel (numpy manylinux)", () => {
    expect(
      hasPyPiAbiTag(
        "numpy-1.26.4-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
      )
    ).toBe(true);
  });

  it("detects CPython platform wheel (cryptography linux_x86_64)", () => {
    expect(
      hasPyPiAbiTag("cryptography-41.0.5-cp311-cp311-linux_x86_64.whl")
    ).toBe(true);
  });

  it("detects abi3 stable ABI wheel", () => {
    expect(hasPyPiAbiTag("lxml-4.9.3-cp36-abi3-linux_x86_64.whl")).toBe(true);
  });

  it("detects macOS wheel", () => {
    expect(
      hasPyPiAbiTag(
        "numpy-1.26.4-cp311-cp311-macosx_10_9_x86_64.whl"
      )
    ).toBe(true);
  });

  it("detects Windows wheel", () => {
    expect(
      hasPyPiAbiTag("numpy-1.26.4-cp311-cp311-win_amd64.whl")
    ).toBe(true);
  });

  it("rejects pure-Python wheel (py3-none-any)", () => {
    expect(hasPyPiAbiTag("requests-2.31.0-py3-none-any.whl")).toBe(false);
  });

  it("rejects an sdist tarball filename", () => {
    expect(hasPyPiAbiTag("numpy-1.26.4.tar.gz")).toBe(false);
  });

  it("PYPI_ABI_TAG_RE is exported and is a RegExp", () => {
    expect(PYPI_ABI_TAG_RE).toBeInstanceOf(RegExp);
  });
});

// ---------------------------------------------------------------------------
// native-indicators: isPythonNativeExtension
// ---------------------------------------------------------------------------

describe("isPythonNativeExtension — file extension detection", () => {
  it("detects plain .so", () => {
    expect(isPythonNativeExtension("libssl.so")).toBe(true);
  });

  it("detects .pyd (Windows CPython extension)", () => {
    expect(isPythonNativeExtension("_hashlib.pyd")).toBe(true);
  });

  it("detects .dylib (macOS)", () => {
    expect(isPythonNativeExtension("libcrypto.dylib")).toBe(true);
  });

  it("detects CPython ABI-tagged .so", () => {
    expect(
      isPythonNativeExtension(
        "_ssl.cpython-311-x86_64-linux-gnu.so"
      )
    ).toBe(true);
  });

  it("detects PyPy ABI-tagged .so", () => {
    expect(
      isPythonNativeExtension("_cffi_backend.pypy311-pp73-x86_64-linux-gnu.so")
    ).toBe(true);
  });

  it("rejects .py source files", () => {
    expect(isPythonNativeExtension("setup.py")).toBe(false);
  });

  it("rejects .pyc bytecode", () => {
    expect(isPythonNativeExtension("module.pyc")).toBe(false);
  });

  it("rejects plain text files", () => {
    expect(isPythonNativeExtension("README.txt")).toBe(false);
  });

  it("PYTHON_NATIVE_EXTENSIONS contains .so, .pyd, .dylib", () => {
    expect(PYTHON_NATIVE_EXTENSIONS).toContain(".so");
    expect(PYTHON_NATIVE_EXTENSIONS).toContain(".pyd");
    expect(PYTHON_NATIVE_EXTENSIONS).toContain(".dylib");
  });
});

// ---------------------------------------------------------------------------
// fingerprint: isCandidateBinary now includes .pyd
// ---------------------------------------------------------------------------

describe("isCandidateBinary — .pyd support", () => {
  it("accepts .pyd files", () => {
    expect(isCandidateBinary("_hashlib.pyd")).toBe(true);
  });

  it("still accepts .node, .so, .dll, .dylib, .wasm", () => {
    expect(isCandidateBinary("addon.node")).toBe(true);
    expect(isCandidateBinary("lib.so")).toBe(true);
    expect(isCandidateBinary("mod.dll")).toBe(true);
    expect(isCandidateBinary("lib.dylib")).toBe(true);
    expect(isCandidateBinary("module.wasm")).toBe(true);
  });

  it("rejects .py and .txt", () => {
    expect(isCandidateBinary("setup.py")).toBe(false);
    expect(isCandidateBinary("README.txt")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// collectWheelNativeExtensions — walks fixture dirs
// ---------------------------------------------------------------------------

describe("collectWheelNativeExtensions — fixture walking", () => {
  it("finds the CPython ABI-tagged .so in the benign-wheel fixture", async () => {
    const extensions = await collectWheelNativeExtensions(
      path.join(fixturesDir, "benign-wheel")
    );
    expect(extensions.length).toBeGreaterThanOrEqual(1);
    expect(extensions.some((f) => f.endsWith(".so"))).toBe(true);
    // Should include the numpy_core directory path
    expect(extensions.some((f) => f.includes("_multiarray_umath"))).toBe(true);
  });

  it("finds the malicious .so in the malicious-wheel fixture", async () => {
    const extensions = await collectWheelNativeExtensions(
      path.join(fixturesDir, "malicious-wheel")
    );
    expect(extensions.length).toBeGreaterThanOrEqual(1);
    expect(extensions.some((f) => f.includes("_native"))).toBe(true);
  });

  it("returns empty array for a directory with no native extensions", async () => {
    const extensions = await collectWheelNativeExtensions(
      path.join(fixturesDir, "benign-package")
    );
    expect(extensions).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// FileSystemBinaryExtractor — discovers .so from wheel fixture
// ---------------------------------------------------------------------------

describe("FileSystemBinaryExtractor — Python native extension discovery", () => {
  it("discovers the ELF .so from the benign-wheel fixture", async () => {
    const extractor = new FileSystemBinaryExtractor();
    const artifacts = await extractor.discover(
      path.join(fixturesDir, "benign-wheel")
    );
    expect(artifacts.length).toBeGreaterThanOrEqual(1);
    const soArtifact = artifacts.find((a) => a.filename.endsWith(".so"));
    expect(soArtifact).toBeDefined();
    expect(soArtifact?.format).toBe("ELF");
  });

  it("discovers and fingerprints the malicious .so with network strings", async () => {
    const extractor = new FileSystemBinaryExtractor();
    const artifacts = await extractor.discover(
      path.join(fixturesDir, "malicious-wheel")
    );
    expect(artifacts.length).toBeGreaterThanOrEqual(1);
    const soArtifact = artifacts.find((a) => a.filename.endsWith(".so"));
    expect(soArtifact).toBeDefined();
    expect(soArtifact?.format).toBe("ELF");
    // The malicious fixture embeds network/exfil strings
    const allStrings = soArtifact?.interestingStrings ?? [];
    expect(
      allStrings.some((s) => s.includes("evil.example.test") || s.includes("exfil") || s.includes("connect"))
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ManifestAnalyzer — pythonBinaryExtension finding for wheel packages
// ---------------------------------------------------------------------------

describe("manifest-analyzer — pythonBinaryExtension finding", () => {
  it("emits pythonBinaryExtension finding for a PyPI package with compiled .so", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: {
        ecosystem: "pypi",
        packageName: "numpy",
        version: "1.26.4",
      },
      packageRoot: path.join(fixturesDir, "benign-wheel"),
      manifest: manifest({ name: "numpy", version: "1.26.4" }),
    };

    const result = await analyzer.analyze(input);

    expect(result.hasPythonBinaryExtension).toBe(true);
    expect(result.pythonExtensionFiles).toBeDefined();
    expect(result.pythonExtensionFiles!.length).toBeGreaterThanOrEqual(1);
    const binaryFinding = result.findings.find(
      (f) => f.category === "pythonBinaryExtension"
    );
    expect(binaryFinding).toBeDefined();
    expect(binaryFinding?.severity).toBe("medium");
    expect(binaryFinding?.title).toMatch(/compiled Python native extension/i);
  });

  it("emits pythonBinaryExtension for malicious wheel with network-calling .so", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: {
        ecosystem: "pypi",
        packageName: "evil-package",
        version: "0.0.1",
      },
      packageRoot: path.join(fixturesDir, "malicious-wheel"),
      manifest: manifest({ name: "evil-package", version: "0.0.1" }),
    };

    const result = await analyzer.analyze(input);

    expect(result.hasPythonBinaryExtension).toBe(true);
    const binaryFinding = result.findings.find(
      (f) => f.category === "pythonBinaryExtension"
    );
    expect(binaryFinding).toBeDefined();
    expect(binaryFinding?.severity).toBe("medium");
  });

  it("does not set hasPythonBinaryExtension for npm packages", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: {
        ecosystem: "npm",
        packageName: "benign-fixture-npm",
        version: "1.0.0",
      },
      packageRoot: path.join(fixturesDir, "benign-package"),
      manifest: manifest({ name: "benign-fixture-npm" }),
    };

    const result = await analyzer.analyze(input);

    expect(result.hasPythonBinaryExtension).toBeUndefined();
    expect(result.pythonExtensionFiles).toBeUndefined();
    expect(result.findings.some((f) => f.category === "pythonBinaryExtension")).toBe(false);
  });

  it("does not set hasPythonBinaryExtension for a PyPI sdist with no .so files", async () => {
    const analyzer = new ManifestAnalyzer();
    const input: ScriptAnalysisInput = {
      packageRequest: {
        ecosystem: "pypi",
        packageName: "pure-python-pkg",
        version: "1.0.0",
      },
      // malicious-setup-py has setup.py but no .so files
      packageRoot: path.join(fixturesDir, "malicious-setup-py"),
      manifest: manifest({ name: "pure-python-pkg", version: "1.0.0" }),
    };

    const result = await analyzer.analyze(input);

    expect(result.hasPythonBinaryExtension).toBeUndefined();
    expect(result.findings.some((f) => f.category === "pythonBinaryExtension")).toBe(false);
  });
});
