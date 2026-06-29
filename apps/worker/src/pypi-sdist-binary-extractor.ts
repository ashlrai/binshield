/**
 * PyPI Source Distribution (sdist) Binary Extraction & Analysis
 *
 * Implements `PySdistExtractorAndAnalyzer` — the sdist counterpart to
 * `pypi-wheel-binary-analyzer.ts`.
 *
 * PyPI attackers increasingly bundle pre-compiled native binaries inside
 * source distributions to evade wheel-focused scanning. Common hiding spots:
 *
 *   • build/          — setuptools bdist_* artifacts left behind by a
 *                       previous build run committed to the sdist
 *   • build/lib/      — shared-library copies from bdist_ext
 *   • src/<pkg>/      — Cython .c → compiled .so shipped as "prebuilt"
 *   • <pkg>/_vendor/  — vendored compiled helpers
 *   • __pycache__/    — .pyc files renamed to .so (rare but seen in the wild)
 *   • dist-info/      — WHEEL METADATA only, but sometimes abused for .so hiding
 *   • top-level       — binaries placed directly at the sdist root
 *
 * Detection pipeline for each found binary:
 *   1. Entropy analysis          — high-entropy sections → packing / encryption
 *   2. Import table scan         — suspicious dlopen/dlsym/socket/WinAPI imports
 *   3. String literal scan       — URLs, shell commands, credential patterns
 *   4. Syscall trace             — attack-pattern sequences in string literals
 *   5. YARA / behavioral sigs    — via AnalyzerRegistry.createDefault()
 *
 * All findings are surfaced as `wheelNativeBinary` findings so they flow
 * through the same risk-scoring path used for wheel binaries.
 *
 * This module intentionally mirrors the structure of pypi-wheel-binary-analyzer.ts
 * so the two can be used side-by-side in the pipeline without duplication.
 */

import { mkdir, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { fingerprintBytes, fingerprintFile } from "./fingerprint.js";
import { AnalyzerRegistry } from "./malware-analyzer.js";

import type { ScriptFinding, FindingSeverity } from "@binshield/analysis-types";
import type { FingerprintedArtifact } from "./types.js";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Binary extensions we look for inside sdists. */
const SDIST_BINARY_EXTENSIONS = new Set([".so", ".pyd", ".dll", ".dylib"]);

/** Maximum sdist size we are willing to download / extract (300 MB). */
const MAX_SDIST_BYTES = 300 * 1024 * 1024;

/** Maximum depth to walk when collecting binaries from an extracted sdist. */
const MAX_WALK_DEPTH = 12;

/**
 * Directory names that commonly contain build artifacts in sdists.
 * We scan ALL directories, but we assign higher suspicion to binaries found
 * in these paths.
 */
const SUSPICIOUS_SDIST_DIRS = new Set([
  "build",
  "dist",
  "_build",
  "_dist",
  ".libs",
  ".eggs",
  "lib",
  "libs",
  "_vendor",
  "vendor",
  "prebuilt",
  "prebuilt_binaries",
  "wheels",
  "bin",
]);

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/** A single native binary found inside an sdist. */
export interface SdistNativeBinary {
  /** Relative path inside the extracted sdist tree. */
  relativePath: string;
  /** Basename of the binary file. */
  filename: string;
  /** Fingerprinted artifact ready for the analysis pipeline. */
  artifact: FingerprintedArtifact;
  /**
   * Whether the binary was found in a directory known to be used for
   * build artifacts (build/, _vendor/, etc.).
   */
  isInSuspiciousDirectory: boolean;
  /**
   * Whether the binary looks like a legitimate Cython-compiled extension
   * (carries Python ABI tags like `_ssl.cpython-311-x86_64-linux-gnu.so`).
   */
  looksLikeCythonExtension: boolean;
}

/** Full result of analyzing all native binaries inside a single sdist. */
export interface SdistBinaryAnalysis {
  /** Package name (normalised). */
  packageName: string;
  /** Version string. */
  version: string;
  /** All native binary files found in the sdist. */
  nativeBinaries: SdistNativeBinary[];
  /** All findings produced by the binary analysis pipeline. */
  findings: ScriptFinding[];
  /** Whether the sdist contains at least one native binary. */
  hasNativeBinaries: boolean;
  /**
   * Confidence level for these findings.
   * "high"   — actual compiled binary analysed
   * "medium" — binary found but analysis was partial (e.g. analysis error)
   */
  confidence: "high" | "medium";
  /**
   * Whether any binary was found in a suspicious build-artifact directory
   * (build/, _vendor/, etc.) as opposed to a normal source directory.
   */
  hasSuspiciousDirectoryBinary: boolean;
}

/** Options for `analyzeSdistBinaries`. */
export interface AnalyzeSdistBinariesOptions {
  /**
   * When true the tar extraction step is skipped and `extractedRoot` is used
   * directly as the package root. Useful when the caller has already extracted
   * the sdist (e.g. `PyPiPackageSource`).
   */
  alreadyExtracted?: boolean;

  /**
   * Absolute path to an already-extracted sdist root.
   * Required when `alreadyExtracted` is true; ignored otherwise.
   */
  extractedRoot?: string;
}

// ---------------------------------------------------------------------------
// Binary classification helpers
// ---------------------------------------------------------------------------

/**
 * Returns true when the filename carries a Python ABI tag that indicates it
 * was produced by Cython / setuptools build_ext:
 *   `<module>.cpython-<pyver>-<arch>-<os>.so`
 *   `<module>.pyd`
 *
 * Note: even Cython-compiled binaries can be malicious; this flag is only
 * used to adjust the finding title and help the analyst understand context.
 */
export function looksLikeCythonExtension(filename: string): boolean {
  // CPython ABI-tagged .so: _speedups.cpython-311-x86_64-linux-gnu.so
  if (/\.cpython-\d+[^.]*\.so$/i.test(filename)) return true;
  // PyPy ABI-tagged .so: _speedups.pypy39-pp73-x86_64-linux-gnu.so
  if (/\.pypy\d+-[^.]+\.so$/i.test(filename)) return true;
  // Windows Python extension DLL
  if (filename.endsWith(".pyd")) return true;
  return false;
}

/**
 * Returns true when the given relative path is inside a directory commonly
 * used to store build artifacts inside sdists.
 */
export function isInSuspiciousDirectory(relativePath: string): boolean {
  const parts = relativePath.split(path.sep);
  // Also normalise forward slashes for cross-platform compatibility
  const allParts = relativePath.split("/").concat(parts);
  return allParts.some((part) => SUSPICIOUS_SDIST_DIRS.has(part.toLowerCase()));
}

// ---------------------------------------------------------------------------
// Directory walker
// ---------------------------------------------------------------------------

/**
 * Walk an extracted sdist tree and collect every file with a native binary
 * extension (.so / .pyd / .dll / .dylib).
 *
 * Returns absolute paths.
 */
export async function collectSdistBinaryPaths(root: string): Promise<string[]> {
  const found: string[] = [];

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > MAX_WALK_DEPTH) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // Skip Python cache dirs and VCS dirs — never contain interesting binaries
        const lower = entry.name.toLowerCase();
        if (lower === "__pycache__" || lower === ".git" || lower === ".svn") {
          continue;
        }
        await walk(full, depth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SDIST_BINARY_EXTENSIONS.has(ext)) {
          found.push(full);
        }
      }
    }
  }

  await walk(root, 0);
  return found;
}

// ---------------------------------------------------------------------------
// Binary analysis pipeline (mirrors pypi-wheel-binary-analyzer.ts)
// ---------------------------------------------------------------------------

/**
 * Run the full malware-engine pipeline on a single FingerprintedArtifact and
 * return `ScriptFinding[]` tagged with category `wheelNativeBinary`.
 *
 * On pipeline failure a single medium-severity warning finding is returned so
 * the caller always gets a result even when individual analyzer plugins throw.
 */
async function runSdistBinaryPipeline(
  artifact: FingerprintedArtifact,
  contextLabel: string
): Promise<ScriptFinding[]> {
  const findings: ScriptFinding[] = [];

  try {
    const registry = await AnalyzerRegistry.createDefault();
    const merged = await registry.analyze(artifact);

    for (const finding of merged.findings) {
      findings.push({
        category: "wheelNativeBinary",
        severity: finding.severity as FindingSeverity,
        title: finding.title,
        description: finding.description,
        filePath: `${artifact.relativePath} [sdist:${contextLabel}]`,
        evidence: finding.location ?? "",
        recommendation: finding.recommendation,
      });
    }

    if (findings.length === 0) {
      findings.push({
        category: "wheelNativeBinary",
        severity: "info",
        title: `Native binary in sdist: ${artifact.filename}`,
        description:
          `Compiled native binary found inside PyPI source distribution ` +
          `(${contextLabel}). Format: ${artifact.format}, architecture: ${artifact.architecture}. ` +
          `Presence of pre-compiled binaries in an sdist is unusual and warrants review.`,
        filePath: `${artifact.relativePath} [sdist:${contextLabel}]`,
        evidence: `sha256:${artifact.sha256.slice(0, 16)}… size:${artifact.fileSize}`,
        recommendation:
          "Verify whether this binary was intentionally included or is a build artifact that " +
          "should not have been committed to the sdist. Wheels distribute compiled binaries; " +
          "sdists should contain only source code.",
      });
    }
  } catch {
    findings.push({
      category: "wheelNativeBinary",
      severity: "medium",
      title: `Sdist binary analysis failed: ${artifact.filename}`,
      description:
        `Could not complete binary analysis for ${artifact.filename} extracted from sdist ` +
        `(${contextLabel}). Manual review is recommended.`,
      filePath: `${artifact.relativePath} [sdist:${contextLabel}]`,
      evidence: "",
      recommendation: "Manually inspect the native binary extracted from this sdist.",
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Sdist extraction helper
// ---------------------------------------------------------------------------

/**
 * Extract a `.tar.gz` sdist archive into `destDir`.
 * Uses the system `tar` command (present on all Linux/macOS build hosts and
 * available via WSL / Git-for-Windows on Windows CI agents).
 */
async function extractTarGz(archivePath: string, destDir: string): Promise<void> {
  await execFileAsync("tar", ["xzf", archivePath, "-C", destDir, "--strip-components=1"]);
}

// ---------------------------------------------------------------------------
// Main analyzer class
// ---------------------------------------------------------------------------

/**
 * Extracts and analyses native binaries embedded inside PyPI source
 * distributions (`.tar.gz` sdists).
 *
 * Usage (from a URL):
 * ```ts
 * const analyzer = new PySdistExtractorAndAnalyzer();
 * const result = await analyzer.analyzeFromUrl(
 *   "cryptography", "41.0.7",
 *   "https://files.pythonhosted.org/packages/.../cryptography-41.0.7.tar.gz"
 * );
 * ```
 *
 * Usage (already-extracted directory):
 * ```ts
 * const result = await analyzer.analyzeFromDirectory(
 *   "cryptography", "41.0.7", "/tmp/cryptography-41.0.7"
 * );
 * ```
 */
export class PySdistExtractorAndAnalyzer {
  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Download a `.tar.gz` sdist from `url`, extract it, and run the full
   * binary analysis pipeline.
   *
   * @param packageName  PyPI package name (used in finding labels).
   * @param version      Exact version string.
   * @param url          Direct URL to the `.tar.gz` sdist (from PyPI JSON API).
   * @returns Structured analysis with per-binary findings.
   */
  async analyzeFromUrl(
    packageName: string,
    version: string,
    url: string
  ): Promise<SdistBinaryAnalysis> {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "binshield-sdist-"));
    const extractDir = path.join(tempRoot, "sdist");
    await mkdir(extractDir, { recursive: true });

    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(
          `Sdist download returned ${response.status} for ${url}`
        );
      }

      const arrayBuf = await response.arrayBuffer();
      if (arrayBuf.byteLength > MAX_SDIST_BYTES) {
        throw new Error(
          `Sdist ${packageName}-${version}.tar.gz exceeds maximum size ` +
          `(${arrayBuf.byteLength} > ${MAX_SDIST_BYTES})`
        );
      }

      const sdistPath = path.join(tempRoot, `${packageName}-${version}.tar.gz`);
      const { writeFile } = await import("node:fs/promises");
      await writeFile(sdistPath, Buffer.from(arrayBuf));

      await extractTarGz(sdistPath, extractDir);

      return this._analyzeExtractedRoot(packageName, version, extractDir);
    } finally {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  }

  /**
   * Analyse an already-extracted sdist directory (no download / extraction).
   *
   * @param packageName  PyPI package name.
   * @param version      Exact version string.
   * @param extractedRoot  Absolute path to the extracted sdist root.
   * @returns Structured analysis with per-binary findings.
   */
  async analyzeFromDirectory(
    packageName: string,
    version: string,
    extractedRoot: string
  ): Promise<SdistBinaryAnalysis> {
    return this._analyzeExtractedRoot(packageName, version, extractedRoot);
  }

  /**
   * Analyse raw sdist bytes (already in memory, e.g. from a test fixture or
   * an in-memory download cache).
   *
   * @param packageName  PyPI package name.
   * @param version      Exact version string.
   * @param tarGzBytes   Raw `.tar.gz` bytes.
   * @returns Structured analysis with per-binary findings.
   */
  async analyzeFromBytes(
    packageName: string,
    version: string,
    tarGzBytes: Buffer
  ): Promise<SdistBinaryAnalysis> {
    if (tarGzBytes.byteLength > MAX_SDIST_BYTES) {
      throw new Error(
        `Sdist bytes for ${packageName}-${version} exceed maximum size ` +
        `(${tarGzBytes.byteLength} > ${MAX_SDIST_BYTES})`
      );
    }

    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "binshield-sdist-"));
    const extractDir = path.join(tempRoot, "sdist");
    await mkdir(extractDir, { recursive: true });

    try {
      const { writeFile } = await import("node:fs/promises");
      const sdistPath = path.join(tempRoot, `${packageName}-${version}.tar.gz`);
      await writeFile(sdistPath, tarGzBytes);

      await extractTarGz(sdistPath, extractDir);

      return this._analyzeExtractedRoot(packageName, version, extractDir);
    } finally {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  }

  // -------------------------------------------------------------------------
  // Core analysis (works on an extracted directory)
  // -------------------------------------------------------------------------

  private async _analyzeExtractedRoot(
    packageName: string,
    version: string,
    extractedRoot: string
  ): Promise<SdistBinaryAnalysis> {
    const contextLabel = `${packageName}@${version}`;

    // 1. Walk the extracted tree for native binaries
    const absPaths = await collectSdistBinaryPaths(extractedRoot);

    if (absPaths.length === 0) {
      return {
        packageName: packageName.toLowerCase(),
        version,
        nativeBinaries: [],
        findings: [],
        hasNativeBinaries: false,
        confidence: "high",
        hasSuspiciousDirectoryBinary: false,
      };
    }

    // 2. Fingerprint and analyse each binary
    const nativeBinaries: SdistNativeBinary[] = [];
    const allFindings: ScriptFinding[] = [];
    let hasSuspiciousDirectoryBinary = false;

    for (const absPath of absPaths) {
      const relPath = path.relative(extractedRoot, absPath);
      const artifact = Object.assign(
        await fingerprintFile(absPath, relPath),
        { path: absPath }
      );

      const inSuspiciousDir = isInSuspiciousDirectory(relPath);
      const looksLikeCython = looksLikeCythonExtension(path.basename(absPath));

      if (inSuspiciousDir) {
        hasSuspiciousDirectoryBinary = true;
      }

      nativeBinaries.push({
        relativePath: relPath,
        filename: path.basename(absPath),
        artifact,
        isInSuspiciousDirectory: inSuspiciousDir,
        looksLikeCythonExtension: looksLikeCython,
      });

      // Emit a suspicion-level finding when a binary sits in a known
      // build-artifact directory — even before running the full pipeline.
      if (inSuspiciousDir && !looksLikeCython) {
        allFindings.push(
          buildSuspiciousBuildArtifactFinding(relPath, contextLabel, artifact)
        );
      }

      const binaryFindings = await runSdistBinaryPipeline(artifact, contextLabel);
      allFindings.push(...binaryFindings);
    }

    return {
      packageName: packageName.toLowerCase(),
      version,
      nativeBinaries,
      findings: allFindings,
      hasNativeBinaries: true,
      confidence: "high",
      hasSuspiciousDirectoryBinary,
    };
  }
}

// ---------------------------------------------------------------------------
// Finding builders
// ---------------------------------------------------------------------------

/**
 * Build a medium-severity finding for a binary found in a suspicious
 * build-artifact directory inside an sdist.
 */
function buildSuspiciousBuildArtifactFinding(
  relPath: string,
  contextLabel: string,
  artifact: FingerprintedArtifact
): ScriptFinding {
  const dir = relPath.split(path.sep)[0] ?? relPath.split("/")[0] ?? "(root)";
  return {
    category: "wheelNativeBinary",
    severity: "medium",
    title: `Pre-compiled binary in sdist build-artifact directory: ${path.basename(relPath)}`,
    description:
      `A native binary '${relPath}' was found inside the '${dir}/' directory of the ` +
      `PyPI source distribution for ${contextLabel}. This directory is typically used ` +
      `for compiled build artifacts and should not contain pre-built binaries in a ` +
      `legitimate sdist. Attackers use this pattern to embed malicious native code ` +
      `that is executed when the extension is imported.`,
    filePath: `${relPath} [sdist:${contextLabel}]`,
    evidence:
      `sha256:${artifact.sha256.slice(0, 16)}… ` +
      `format:${artifact.format} ` +
      `size:${artifact.fileSize}`,
    recommendation:
      "Verify whether this binary was intentionally bundled. Legitimate packages that " +
      "pre-build binaries should ship wheels, not sdists with embedded artifacts. " +
      "If you cannot confirm the provenance of this binary, block the package.",
  };
}

// ---------------------------------------------------------------------------
// Convenience function — mirrors analyzeWheelOnlyPackage pattern
// ---------------------------------------------------------------------------

/**
 * Fetch the PyPI JSON API for `packageName@version`, locate the sdist entry,
 * and run the full sdist binary extraction + analysis pipeline.
 *
 * Returns `null` when no sdist is available for the given version.
 */
export async function analyzePySdist(
  packageName: string,
  version: string
): Promise<SdistBinaryAnalysis | null> {
  const metaUrl =
    `https://pypi.org/pypi/${encodeURIComponent(packageName)}/` +
    `${encodeURIComponent(version)}/json`;

  const response = await fetch(metaUrl);
  if (!response.ok) {
    throw new Error(
      `PyPI metadata request returned ${response.status} for ${packageName}@${version}`
    );
  }

  const meta = (await response.json()) as {
    urls?: Array<{ packagetype: string; url: string; filename: string }>;
  };

  const sdistEntry = (meta.urls ?? []).find((u) => u.packagetype === "sdist");
  if (!sdistEntry) {
    return null;
  }

  const analyzer = new PySdistExtractorAndAnalyzer();
  return analyzer.analyzeFromUrl(packageName, version, sdistEntry.url);
}
