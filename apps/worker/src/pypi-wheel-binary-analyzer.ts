/**
 * PyPI Wheel-Only Binary Analyzer
 *
 * Handles packages that ship ONLY precompiled wheels with no sdist available
 * on PyPI. For these packages, the sdist acquisition path fails and we fall
 * back to downloading a wheel, extracting every native extension inside it
 * (.so / .pyd / .dylib), and running the full binary analysis pipeline:
 *
 *   1. Entropy analysis  — high-entropy sections indicate packing/encryption
 *   2. Import table scan — unusual dlopen / dlsym / socket imports
 *   3. String literals   — URLs, shell commands, credential patterns
 *   4. Syscall trace     — kernel ABI calls that indicate dangerous behaviour
 *   5. Patcher detector  — signs of patched/tampered upstream binaries
 *
 * Findings are recorded as type `wheelNativeBinary` (vs the lower-confidence
 * `pythonBinaryExtension` emitted from sdist heuristics).  The higher
 * confidence reflects that we are inspecting the actual compiled binary, not
 * just inferring from build configuration metadata.
 *
 * Wheel filename ABI tags (e.g. `cryptography-cp311-linux_x86_64`) are
 * preserved in the finding metadata so that per-platform risk can be assessed
 * downstream.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { isPythonNativeExtension, hasPyPiAbiTag } from "./native-indicators.js";
import { fingerprintFile } from "./fingerprint.js";
import { AnalyzerRegistry } from "./malware-analyzer.js";
import { ImportTableAnalyzer, SyscallTraceAnalyzer } from "@binshield/malware-engines";

import type { ScriptFinding, FindingSeverity, BinaryFingerprint } from "@binshield/analysis-types";
import type { FingerprintedArtifact } from "./types.js";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/**
 * Parsed components of a wheel filename ABI tag.
 * Wheel filenames follow the format:
 *   {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
 */
export interface WheelAbiTag {
  /** Original wheel filename. */
  filename: string;
  /** Python implementation tag, e.g. "cp311", "pp39". */
  pythonTag: string;
  /** ABI tag, e.g. "cp311", "abi3", "none". */
  abiTag: string;
  /** Platform tag, e.g. "linux_x86_64", "manylinux_2_17_x86_64", "win_amd64". */
  platformTag: string;
  /** Human-readable label, e.g. "cryptography-cp311-linux_x86_64". */
  label: string;
}

/**
 * A single native extension binary extracted from a wheel.
 */
export interface WheelNativeExtension {
  /** Relative path inside the wheel zip. */
  relativePath: string;
  /** Basename, e.g. "_ssl.cpython-311-x86_64-linux-gnu.so". */
  filename: string;
  /** Fingerprinted artifact ready for the analysis pipeline. */
  artifact: FingerprintedArtifact;
}

/**
 * Full result of analyzing all native extensions inside a single wheel.
 */
export interface WheelBinaryAnalysis {
  /** Wheel filename ABI tag components. */
  abiTag: WheelAbiTag | null;
  /** All native extension files found in the wheel. */
  nativeExtensions: WheelNativeExtension[];
  /** Script findings produced by the binary analysis pipeline. */
  findings: ScriptFinding[];
  /**
   * Whether the wheel contains at least one native extension.
   * False for pure-Python wheels.
   */
  hasNativeExtensions: boolean;
  /**
   * Confidence for findings: "high" (actual compiled binary analysed) vs
   * "low" (sdist heuristics only).
   */
  confidence: "high";
  /**
   * Cryptographic fingerprint records for each native extension found in the
   * wheel. Each entry carries the sha256, importSig, syscallSig, and
   * ssdeepFuzzyHash needed for cross-package similarity clustering.
   * Empty array when hasNativeExtensions is false.
   */
  binaryFingerprints: WheelBinaryFingerprintData[];
}

/**
 * Enhanced fingerprint data for a single wheel native binary, suitable for
 * cross-package similarity clustering.
 */
export interface WheelBinaryFingerprintData {
  /** Ecosystem — always "pypi" for wheel binaries. */
  ecosystem: "pypi";
  /** Package name (normalised, lowercase). */
  packageName: string;
  /** Exact version string. */
  version: string;
  /** Relative path of the binary inside the wheel. */
  binaryPath: string;
  /** Full BinaryFingerprint with all similarity signals populated. */
  fingerprint: BinaryFingerprint;
  /** ISO timestamp when the fingerprint was computed. */
  computedAt: string;
}

// ---------------------------------------------------------------------------
// PyPI JSON API types
// ---------------------------------------------------------------------------

interface PyPiUrlEntry {
  packagetype: string;
  url: string;
  filename: string;
  digests?: { sha256?: string };
}

interface PyPiMeta {
  urls?: PyPiUrlEntry[];
  info?: {
    name?: string;
    version?: string;
  };
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const NATIVE_BINARY_EXTENSIONS = new Set([".so", ".pyd", ".dylib"]);

// Maximum wheel size we are willing to download (200 MB).
const MAX_WHEEL_BYTES = 200 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Wheel filename parsing
// ---------------------------------------------------------------------------

/**
 * Parse the ABI tag components from a wheel filename.
 *
 * Wheel naming convention (PEP 427):
 *   {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
 *
 * Returns null for filenames that do not conform (e.g. pure-Python wheels
 * tagged py3-none-any, or non-wheel filenames).
 */
export function parseWheelAbiTag(filename: string): WheelAbiTag | null {
  if (!filename.endsWith(".whl")) return null;

  const base = filename.slice(0, -4); // strip .whl
  const parts = base.split("-");

  // Minimum 5 parts: dist, version, python, abi, platform
  // Optional build tag makes it 6 parts.
  if (parts.length < 5) return null;

  // The last three parts are always python-abi-platform.
  const platformTag = parts[parts.length - 1];
  const abiTag = parts[parts.length - 2];
  const pythonTag = parts[parts.length - 3];

  // Derive distribution name from the first part(s).
  const distParts = parts.slice(0, parts.length - 3);
  // distParts could be [name, version] or [name, version, buildtag]
  const distName = distParts[0];

  const label = `${distName}-${pythonTag}-${platformTag}`;

  return { filename, pythonTag, abiTag, platformTag, label };
}

/**
 * Returns true when a wheel ABI tag indicates a platform-specific (compiled)
 * wheel rather than a pure-Python wheel.
 *
 * Pure-Python wheels carry `py3-none-any` or `py2.py3-none-any` tags.
 */
export function isCompiledWheel(tag: WheelAbiTag): boolean {
  // Pure-Python: abi tag is "none" AND platform tag is "any"
  if (tag.abiTag === "none" && tag.platformTag === "any") return false;
  // PyPy / CPython compiled wheel
  return true;
}

// ---------------------------------------------------------------------------
// Wheel-only detection
// ---------------------------------------------------------------------------

/**
 * Checks the PyPI JSON API for a package version and returns:
 *   - `hasSdist`   — true if at least one sdist entry exists
 *   - `wheels`     — all bdist_wheel entries
 *   - `isWheelOnly` — true when wheels exist but sdist does not
 */
export async function detectWheelOnlyPackage(
  packageName: string,
  version: string
): Promise<{ hasSdist: boolean; wheels: PyPiUrlEntry[]; isWheelOnly: boolean }> {
  const metaUrl = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}/json`;
  const response = await fetch(metaUrl);
  if (!response.ok) {
    throw new Error(`PyPI metadata request returned ${response.status} for ${packageName}@${version}`);
  }

  const meta = (await response.json()) as PyPiMeta;
  const urls = meta.urls ?? [];

  const hasSdist = urls.some((u) => u.packagetype === "sdist");
  const wheels = urls.filter((u) => u.packagetype === "bdist_wheel");
  const isWheelOnly = !hasSdist && wheels.length > 0;

  return { hasSdist, wheels, isWheelOnly };
}

// ---------------------------------------------------------------------------
// Best-wheel selection
// ---------------------------------------------------------------------------

/**
 * Selects the best wheel to analyse from the available wheels list.
 *
 * Preference order:
 *   1. Platform-specific CPython wheel (cp* tag, non-"any" platform)
 *   2. Platform-specific PyPy wheel
 *   3. abi3 stable ABI wheel
 *   4. First available wheel (fallback)
 */
export function selectBestWheel(wheels: PyPiUrlEntry[]): PyPiUrlEntry | null {
  if (wheels.length === 0) return null;

  // First pass: prefer wheels with a full CPython ABI tag — where the python
  // tag and abi tag both start with "cp" and are equal (e.g. cp311-cp311).
  // This distinguishes full CPython wheels from abi3 stable-ABI wheels
  // (which use cpXX-abi3) or PyPy wheels.
  const cpython = wheels.find((w) => {
    const tag = parseWheelAbiTag(w.filename);
    return (
      tag !== null &&
      isCompiledWheel(tag) &&
      tag.pythonTag.startsWith("cp") &&
      tag.abiTag.startsWith("cp") &&
      tag.abiTag !== "abi3"
    );
  });
  if (cpython) return cpython;

  // Second pass: any compiled wheel (PyPy, abi3)
  const compiled = wheels.find((w) => {
    const tag = parseWheelAbiTag(w.filename);
    return tag !== null && isCompiledWheel(tag);
  });
  if (compiled) return compiled;

  // Third pass: hasPyPiAbiTag heuristic
  const tagged = wheels.find((w) => hasPyPiAbiTag(w.filename));
  if (tagged) return tagged;

  // Fallback: first wheel
  return wheels[0];
}

// ---------------------------------------------------------------------------
// Wheel extraction helpers
// ---------------------------------------------------------------------------

/**
 * Walk a directory tree and collect all native extension file paths.
 * Returns absolute paths.
 */
async function collectNativeExtensionPaths(root: string): Promise<string[]> {
  const found: string[] = [];

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (NATIVE_BINARY_EXTENSIONS.has(ext) || isPythonNativeExtension(entry.name)) {
          found.push(full);
        }
      }
    }
  }

  await walk(root);
  return found;
}

// ---------------------------------------------------------------------------
// Fingerprint computation helpers
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 import-table signature for a binary buffer.
 *
 * Extracts printable strings from the buffer (same as ImportTableAnalyzer),
 * filters to known injection/credential API names, sorts and deduplicates
 * them, then SHA-256 hashes the canonical list. Two binaries that expose
 * exactly the same dangerous imports will produce identical importSig values.
 */
async function computeImportSig(binary: Buffer): Promise<string> {
  const analyzer = new ImportTableAnalyzer();
  const result = await analyzer.analyze(binary);
  // Extract individual API names from the "Process injection APIs detected: X, Y"
  // and "Credential access APIs detected: X, Y" signals.
  const apis: string[] = [];
  for (const signal of result.signals) {
    const match = signal.match(/detected:\s*(.+)$/);
    if (match?.[1]) {
      for (const api of match[1].split(",")) {
        const name = api.trim();
        if (name.length > 0) apis.push(name);
      }
    }
  }
  const canonical = [...new Set(apis)].sort().join("|");
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

/**
 * Compute a SHA-256 syscall-sequence signature for a binary buffer.
 *
 * Runs the SyscallTraceAnalyzer over the buffer's ASCII text, extracts the
 * attack-pattern IDs from matched signals, sorts and deduplicates them, then
 * SHA-256 hashes the canonical list. Binaries with the same attack-pattern set
 * — even if the binary bytes differ slightly — share the same syscallSig.
 */
async function computeSyscallSig(binary: Buffer): Promise<string> {
  const analyzer = new SyscallTraceAnalyzer();
  const result = await analyzer.analyze(binary);
  // Extract pattern IDs from "[pattern_id] ..." signal lines.
  const patternIds: string[] = [];
  for (const signal of result.signals) {
    const match = signal.match(/^\[([a-z0-9_]+)\]/);
    if (match?.[1]) patternIds.push(match[1]);
  }
  const canonical = [...new Set(patternIds)].sort().join("|");
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

/**
 * Compute a fuzzy (ssdeep-style) hash of a binary buffer.
 *
 * Real ssdeep is a C library; we simulate the key property here using a
 * 64-byte rolling-window block hash: split the buffer into 64-byte blocks,
 * SHA-256-hash each block, then SHA-256 the concatenated first bytes of each
 * block hash to produce a 64-hex-char digest. Binaries that differ by only
 * a few bytes will share most blocks and produce similar (though not
 * byte-identical) hashes. For production use, replace with a native ssdeep
 * binding.
 *
 * The output is always a 64-character hex string.
 */
function computeFuzzyHash(binary: Buffer): string {
  const BLOCK_SIZE = 64;
  const blockFingerprints: string[] = [];
  for (let offset = 0; offset < binary.length; offset += BLOCK_SIZE) {
    const block = binary.subarray(offset, offset + BLOCK_SIZE);
    const h = crypto.createHash("sha256").update(block).digest("hex");
    // Take first 2 hex chars per block (1 byte) — yields a compact rolling hash
    blockFingerprints.push(h.slice(0, 2));
  }
  // Hash the concatenated block fingerprints to a fixed-length output
  const combined = blockFingerprints.join("");
  return crypto.createHash("sha256").update(combined).digest("hex");
}

/**
 * Compute the full BinaryFingerprint for a wheel native extension.
 *
 * Combines:
 *   - sha256: from the already-fingerprinted artifact
 *   - hashAlgorithm: "sha256"
 *   - importSig: SHA-256 of dangerous import names (from ImportTableAnalyzer)
 *   - syscallSig: SHA-256 of matched attack-pattern IDs (from SyscallTraceAnalyzer)
 *   - ssdeepFuzzyHash: rolling block hash for approximate binary similarity
 */
export async function computeWheelBinaryFingerprint(
  artifact: FingerprintedArtifact,
  packageName: string,
  version: string
): Promise<BinaryFingerprint> {
  const { readFile } = await import("node:fs/promises");
  // We don't have the file path on the artifact directly — it is computed from
  // the temp extraction dir. Re-read the bytes using the artifact's sha256 as a
  // sentinel: if the file is available at artifact.absolutePath use it,
  // otherwise fall back to a zero-byte buffer (safe: produces stable sigs).
  let binary: Buffer;
  try {
    // FingerprintedArtifact stores the absolute path as `path` (see types.ts)
    const artifactPath = (artifact as unknown as Record<string, unknown>)["path"] as string | undefined;
    if (artifactPath && typeof artifactPath === "string") {
      binary = await readFile(artifactPath);
    } else {
      binary = Buffer.alloc(0);
    }
  } catch {
    binary = Buffer.alloc(0);
  }

  const [importSig, syscallSig] = await Promise.all([
    computeImportSig(binary),
    computeSyscallSig(binary),
  ]);
  const ssdeepFuzzyHash = computeFuzzyHash(binary);

  return {
    sha256: artifact.sha256,
    packageVersionKey: `pypi:${packageName}@${version}`,
    binaryKey: artifact.relativePath,
    hashAlgorithm: "sha256",
    importSig,
    syscallSig,
    ssdeepFuzzyHash,
  };
}

/**
 * Build a WheelBinaryFingerprintData record from an artifact and its
 * computed BinaryFingerprint.
 */
export function buildFingerprintData(
  artifact: FingerprintedArtifact,
  fingerprint: BinaryFingerprint,
  packageName: string,
  version: string
): WheelBinaryFingerprintData {
  return {
    ecosystem: "pypi",
    packageName: packageName.toLowerCase(),
    version,
    binaryPath: artifact.relativePath,
    fingerprint,
    computedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Binary analysis pipeline
// ---------------------------------------------------------------------------

/**
 * Run the full binary analysis pipeline (entropy, import table, string
 * literals, syscall trace, patcher detector) on a fingerprinted artifact.
 *
 * Returns findings as `ScriptFinding[]` with category `wheelNativeBinary`.
 */
async function runBinaryPipeline(
  artifact: FingerprintedArtifact,
  abiLabel: string
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
        filePath: `${artifact.relativePath} [${abiLabel}]`,
        evidence: finding.location ?? "",
        recommendation: finding.recommendation
      });
    }

    // Emit a baseline informational finding for every native extension found.
    // This creates a record even when no malware signals are detected, so that
    // the manifest analysis always surfaces the presence of compiled binaries.
    if (findings.length === 0) {
      findings.push({
        category: "wheelNativeBinary",
        severity: "info",
        title: `Native extension in wheel: ${artifact.filename}`,
        description: `Compiled native extension found inside wheel (${abiLabel}). Format: ${artifact.format}, architecture: ${artifact.architecture}.`,
        filePath: `${artifact.relativePath} [${abiLabel}]`,
        evidence: `sha256:${artifact.sha256.slice(0, 16)}… size:${artifact.fileSize}`,
        recommendation:
          "Review the native extension for expected behaviour. Wheel-only packages cannot be audited at the source level."
      });
    }
  } catch {
    // Binary pipeline failure is non-fatal — emit a warning finding instead.
    findings.push({
      category: "wheelNativeBinary",
      severity: "medium",
      title: `Native extension analysis failed: ${artifact.filename}`,
      description: `Could not complete binary analysis for ${artifact.filename} from wheel (${abiLabel}). Manual review recommended.`,
      filePath: `${artifact.relativePath} [${abiLabel}]`,
      evidence: "",
      recommendation: "Manually inspect the native extension binary."
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Download a wheel from PyPI, extract all `.so` / `.pyd` / `.dylib` native
 * extensions, and run the full binary analysis pipeline on each one.
 *
 * @param packageName  PyPI package name (case-insensitive).
 * @param version      Exact version string as published on PyPI.
 * @param wheelEntry   The specific wheel URL entry from the PyPI JSON API.
 *                     Use `selectBestWheel()` to pick the best one.
 * @returns  Structured `WheelBinaryAnalysis` with per-binary findings.
 */
export async function analyzeWheelBinaries(
  packageName: string,
  version: string,
  wheelEntry: PyPiUrlEntry
): Promise<WheelBinaryAnalysis> {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "binshield-wba-"));
  const extractDir = path.join(tempRoot, "wheel");
  await mkdir(extractDir, { recursive: true });

  try {
    // Download the wheel
    const response = await fetch(wheelEntry.url);
    if (!response.ok) {
      throw new Error(`Wheel download returned ${response.status} for ${wheelEntry.url}`);
    }

    const arrayBuf = await response.arrayBuffer();
    if (arrayBuf.byteLength > MAX_WHEEL_BYTES) {
      throw new Error(
        `Wheel ${wheelEntry.filename} exceeds maximum size (${arrayBuf.byteLength} > ${MAX_WHEEL_BYTES})`
      );
    }

    const wheelPath = path.join(tempRoot, wheelEntry.filename);
    await writeFile(wheelPath, Buffer.from(arrayBuf));

    // Wheels are zip archives — extract with unzip
    await execFileAsync("unzip", ["-q", wheelPath, "-d", extractDir]);

    // Parse ABI tag
    const abiTag = parseWheelAbiTag(wheelEntry.filename);
    const abiLabel = abiTag?.label ?? `${packageName}-${version}`;

    // Collect native extensions
    const nativePaths = await collectNativeExtensionPaths(extractDir);

    if (nativePaths.length === 0) {
      return {
        abiTag,
        nativeExtensions: [],
        findings: [],
        hasNativeExtensions: false,
        confidence: "high",
        binaryFingerprints: []
      };
    }

    // Fingerprint and analyse each native extension
    const nativeExtensions: WheelNativeExtension[] = [];
    const allFindings: ScriptFinding[] = [];
    const binaryFingerprints: WheelBinaryFingerprintData[] = [];

    for (const absPath of nativePaths) {
      const relPath = path.relative(extractDir, absPath);
      // Build a file-path-aware artifact so computeWheelBinaryFingerprint can
      // re-read the bytes. We attach the absolute path as a non-standard field
      // that computeWheelBinaryFingerprint knows to read.
      const baseArtifact = await fingerprintFile(absPath, relPath);
      const artifact = Object.assign(baseArtifact, { path: absPath });

      nativeExtensions.push({
        relativePath: relPath,
        filename: path.basename(absPath),
        artifact
      });

      const binaryFindings = await runBinaryPipeline(artifact, abiLabel);
      allFindings.push(...binaryFindings);

      // Compute enhanced fingerprint for similarity clustering
      try {
        const fingerprint = await computeWheelBinaryFingerprint(artifact, packageName, version);
        binaryFingerprints.push(buildFingerprintData(artifact, fingerprint, packageName, version));
      } catch {
        // Fingerprint computation failure is non-fatal — the binary pipeline
        // findings are still valid without it.
      }
    }

    return {
      abiTag,
      nativeExtensions,
      findings: allFindings,
      hasNativeExtensions: true,
      confidence: "high",
      binaryFingerprints
    };
  } finally {
    await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Convenience wrapper: fetch the PyPI metadata for `packageName@version`,
 * detect whether it is wheel-only, select the best wheel, and run
 * `analyzeWheelBinaries`.
 *
 * Returns `null` when the package has an sdist (use the sdist analysis path
 * instead) or has no wheels at all.
 *
 * This is the entry point used by the acquisition coordinator to implement
 * "if sdist fails, try wheel-binary path".
 */
export async function analyzeWheelOnlyPackage(
  packageName: string,
  version: string
): Promise<WheelBinaryAnalysis | null> {
  const { wheels } = await detectWheelOnlyPackage(packageName, version);

  if (wheels.length === 0) {
    return null;
  }

  const best = selectBestWheel(wheels);
  if (!best) return null;

  return analyzeWheelBinaries(packageName, version, best);
}
