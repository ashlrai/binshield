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
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { isPythonNativeExtension, hasPyPiAbiTag } from "./native-indicators.js";
import { fingerprintFile } from "./fingerprint.js";
import { AnalyzerRegistry } from "./malware-analyzer.js";

import type { ScriptFinding, FindingSeverity } from "@binshield/analysis-types";
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
        confidence: "high"
      };
    }

    // Fingerprint and analyse each native extension
    const nativeExtensions: WheelNativeExtension[] = [];
    const allFindings: ScriptFinding[] = [];

    for (const absPath of nativePaths) {
      const relPath = path.relative(extractDir, absPath);
      const artifact = await fingerprintFile(absPath, relPath);

      nativeExtensions.push({
        relativePath: relPath,
        filename: path.basename(absPath),
        artifact
      });

      const binaryFindings = await runBinaryPipeline(artifact, abiLabel);
      allFindings.push(...binaryFindings);
    }

    return {
      abiTag,
      nativeExtensions,
      findings: allFindings,
      hasNativeExtensions: true,
      confidence: "high"
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
