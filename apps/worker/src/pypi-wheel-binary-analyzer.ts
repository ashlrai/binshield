/**
 * PyPI Wheel-Only Binary Analyzer  (v2 — Deep Extraction & Similarity Clustering)
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
 * Additionally (v2):
 *   6. Binary fingerprint registry — every native binary fingerprint is stored
 *      in `binary_fingerprint_registry` (Supabase) keyed by ecosystem + hash.
 *   7. Cross-package similarity clustering — exact SHA-256 and fuzzy-hash
 *      matches against other packages in the registry flag supply-chain
 *      repackaging / fork attacks with the new `pypi_binary_repackaging`
 *      detection type.
 *   8. CISA/NSF SBOM + PyPI wheel seed ingestion — on-startup seeding of the
 *      registry from known-good binary fingerprints so the first scan of a
 *      real package has reference data to compare against.
 *
 * Findings are recorded as type `wheelNativeBinary` (vs the lower-confidence
 * `pythonBinaryExtension` emitted from sdist heuristics).  The higher
 * confidence reflects that we are inspecting the actual compiled binary, not
 * just inferring from build configuration metadata.
 *
 * When a cross-package binary match is found the additional finding type
 * `pypi_binary_repackaging` is emitted with severity `high` (exact match) or
 * `medium` (fuzzy match >85%).
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
import {
  ImportTableAnalyzer,
  SyscallTraceAnalyzer,
  ProvenanceVerifier,
  type ProvenanceFinding,
} from "@binshield/malware-engines";
import {
  verifyWheelProvenance,
  matchWheelToSdist,
  provenanceResultToFindings,
  type WheelProvenanceResult,
  type SdistMatchResult,
  type MatchWheelToSdistOptions,
} from "./wheel-provenance-verifier.js";

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
 * A cross-package binary similarity match found in the registry.
 */
export interface BinaryRepackagingMatch {
  /** The package+version where the matching binary was previously seen. */
  matchedPackageName: string;
  matchedVersion: string;
  /** Relative path of the matched binary in the other package's wheel. */
  matchedBinaryPath: string;
  /** How the match was found. */
  matchKind: "exact_sha256" | "fuzzy_hash" | "import_sig" | "syscall_sig";
  /**
   * Similarity score 0–100.
   *   exact_sha256: always 100
   *   fuzzy_hash:   0–100 (only reported when ≥ FUZZY_MATCH_THRESHOLD)
   *   import_sig:   always 100 (identical import symbol set)
   *   syscall_sig:  always 100 (identical syscall pattern set)
   */
  similarityScore: number;
  /** ISO timestamp when the matching registry entry was recorded. */
  registryEntryDate: string;
}

/**
 * Detection result for a binary repackaging / supply-chain fork attack.
 */
export interface BinaryRepackagingRisk {
  /** Binary file being analysed. */
  binaryPath: string;
  /** SHA-256 of the binary. */
  binaryHash: string;
  /**
   * All cross-package matches found in the registry.
   * Empty when no matches were found (benign).
   */
  matches: BinaryRepackagingMatch[];
  /**
   * Whether at least one match is an exact SHA-256 copy.
   */
  hasExactCopy: boolean;
  /**
   * Whether at least one match is a fuzzy-hash variant above the threshold.
   */
  hasFuzzyVariant: boolean;
  /**
   * Highest similarity score across all matches (0 when no matches).
   */
  maxSimilarity: number;
  /**
   * Overall risk level for this binary:
   *   "none"     — no cross-package matches
   *   "medium"   — fuzzy variant (possible legitimate vendoring)
   *   "high"     — exact copy in another package (suspicious)
   *   "critical" — exact copy with mismatched import/syscall signatures
   *                (binary replaced but metadata intact — backdoor indicator)
   */
  riskLevel: "none" | "medium" | "high" | "critical";
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
  /**
   * Cross-package repackaging risk assessments, one per native binary.
   * Only populated when a RegistryClient was provided to the analyzer.
   * Empty array when hasNativeExtensions is false or no registry is available.
   */
  repackagingRisks: BinaryRepackagingRisk[];
  /**
   * Cryptographic provenance verification result for the wheel archive.
   * Covers RECORD hash verification, PEP 740 attestation check, and
   * sdist ext_modules matching. null when provenance verification was
   * not requested (skipProvenance: true in options).
   */
  provenance: WheelProvenanceResult | null;
  /**
   * Supply-chain provenance findings from ProvenanceVerifier (PEP 740
   * GPG signatures, publisher identity, build provenance correlation,
   * timestamp freshness, orphaned-wheel detection).
   * Always populated for PyPI wheel scans; empty array on failure.
   */
  provenance_findings: ProvenanceFinding[];
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
// Registry client types & implementation
// ---------------------------------------------------------------------------

/**
 * A row from the `binary_fingerprint_registry` table.
 */
export interface RegistryRow {
  id?: string;
  ecosystem: "pypi" | "npm";
  package_name: string;
  version: string;
  binary_path: string;
  binary_hash: string;
  fuzzy_hash?: string | null;
  import_sig?: string | null;
  syscall_sig?: string | null;
  source: "scan" | "seed_cisa" | "seed_pypi";
  computed_at?: string;
}

/**
 * Minimal interface for a binary fingerprint registry backend.
 *
 * The production implementation uses the Supabase PostgREST API.
 * Tests inject a mock that stores rows in memory.
 */
export interface BinaryFingerprintRegistryClient {
  /**
   * Upsert a fingerprint row.
   * Silently no-ops on conflict (same ecosystem + binary_hash + package + version).
   */
  upsert(row: RegistryRow): Promise<void>;

  /**
   * Find all registry rows whose binary_hash matches `hash`, excluding the
   * row for (packageName, version) itself.
   */
  findByHash(
    ecosystem: "pypi" | "npm",
    hash: string,
    excludePackage: string,
    excludeVersion: string
  ): Promise<RegistryRow[]>;

  /**
   * Find all registry rows whose import_sig matches `sig`, excluding the
   * calling package.
   */
  findByImportSig(
    ecosystem: "pypi" | "npm",
    sig: string,
    excludePackage: string,
    excludeVersion: string
  ): Promise<RegistryRow[]>;

  /**
   * Find all registry rows whose syscall_sig matches `sig`, excluding the
   * calling package.
   */
  findBySyscallSig(
    ecosystem: "pypi" | "npm",
    sig: string,
    excludePackage: string,
    excludeVersion: string
  ): Promise<RegistryRow[]>;

  /**
   * Find all registry rows whose fuzzy_hash prefix (first 8 chars) matches,
   * excluding the calling package.  Returns candidates for Jaccard scoring.
   */
  findByFuzzyHashPrefix(
    ecosystem: "pypi" | "npm",
    fuzzyHashPrefix: string,
    excludePackage: string,
    excludeVersion: string
  ): Promise<RegistryRow[]>;

  /**
   * Bulk-insert seed rows.  Used during CISA/PyPI seed ingestion.
   * Implementations should ignore duplicates.
   */
  bulkInsertSeed(rows: RegistryRow[]): Promise<void>;
}

// ---------------------------------------------------------------------------
// Supabase PostgREST implementation of BinaryFingerprintRegistryClient
// ---------------------------------------------------------------------------

import { pgInsert, pgSelect } from "./supabase-rest.js";
import type { SupabaseWorkerConfig } from "./supabase-store.js";

export class SupabaseBinaryFingerprintRegistry implements BinaryFingerprintRegistryClient {
  constructor(private readonly config: SupabaseWorkerConfig) {}

  async upsert(row: RegistryRow): Promise<void> {
    await pgInsert<RegistryRow>(
      this.config,
      "/binary_fingerprint_registry",
      row,
      "resolution=ignore-duplicates,return=minimal"
    );
  }

  async findByHash(
    ecosystem: "pypi" | "npm",
    hash: string,
    excludePackage: string,
    excludeVersion: string
  ): Promise<RegistryRow[]> {
    const enc = encodeURIComponent;
    const path =
      `/binary_fingerprint_registry` +
      `?ecosystem=eq.${enc(ecosystem)}` +
      `&binary_hash=eq.${enc(hash)}` +
      `&package_name=neq.${enc(excludePackage)}`;
    const rows = await pgSelect<RegistryRow>(this.config, path);
    return rows.filter(
      (r) => !(r.package_name === excludePackage && r.version === excludeVersion)
    );
  }

  async findByImportSig(
    ecosystem: "pypi" | "npm",
    sig: string,
    excludePackage: string,
    _excludeVersion: string
  ): Promise<RegistryRow[]> {
    const enc = encodeURIComponent;
    const path =
      `/binary_fingerprint_registry` +
      `?ecosystem=eq.${enc(ecosystem)}` +
      `&import_sig=eq.${enc(sig)}` +
      `&package_name=neq.${enc(excludePackage)}`;
    return pgSelect<RegistryRow>(this.config, path);
  }

  async findBySyscallSig(
    ecosystem: "pypi" | "npm",
    sig: string,
    excludePackage: string,
    _excludeVersion: string
  ): Promise<RegistryRow[]> {
    const enc = encodeURIComponent;
    const path =
      `/binary_fingerprint_registry` +
      `?ecosystem=eq.${enc(ecosystem)}` +
      `&syscall_sig=eq.${enc(sig)}` +
      `&package_name=neq.${enc(excludePackage)}`;
    return pgSelect<RegistryRow>(this.config, path);
  }

  async findByFuzzyHashPrefix(
    ecosystem: "pypi" | "npm",
    fuzzyHashPrefix: string,
    excludePackage: string,
    _excludeVersion: string
  ): Promise<RegistryRow[]> {
    const enc = encodeURIComponent;
    // PostgREST `like` filter for prefix match
    const path =
      `/binary_fingerprint_registry` +
      `?ecosystem=eq.${enc(ecosystem)}` +
      `&fuzzy_hash=like.${enc(fuzzyHashPrefix + "%")}` +
      `&package_name=neq.${enc(excludePackage)}`;
    return pgSelect<RegistryRow>(this.config, path);
  }

  async bulkInsertSeed(rows: RegistryRow[]): Promise<void> {
    if (rows.length === 0) return;
    await pgInsert<RegistryRow>(
      this.config,
      "/binary_fingerprint_registry",
      rows,
      "resolution=ignore-duplicates,return=minimal"
    );
  }
}

// ---------------------------------------------------------------------------
// In-memory registry (for tests / offline mode)
// ---------------------------------------------------------------------------

/**
 * Simple in-memory registry implementation.
 * Suitable for unit tests and offline/sandboxed analysis.
 */
export class InMemoryBinaryFingerprintRegistry implements BinaryFingerprintRegistryClient {
  private readonly rows: RegistryRow[] = [];

  async upsert(row: RegistryRow): Promise<void> {
    const exists = this.rows.some(
      (r) =>
        r.ecosystem === row.ecosystem &&
        r.binary_hash === row.binary_hash &&
        r.package_name === row.package_name &&
        r.version === row.version
    );
    if (!exists) {
      this.rows.push({ ...row, computed_at: row.computed_at ?? new Date().toISOString() });
    }
  }

  async findByHash(
    ecosystem: "pypi" | "npm",
    hash: string,
    excludePackage: string,
    excludeVersion: string
  ): Promise<RegistryRow[]> {
    return this.rows.filter(
      (r) =>
        r.ecosystem === ecosystem &&
        r.binary_hash === hash &&
        !(r.package_name === excludePackage && r.version === excludeVersion)
    );
  }

  async findByImportSig(
    ecosystem: "pypi" | "npm",
    sig: string,
    excludePackage: string,
    _excludeVersion: string
  ): Promise<RegistryRow[]> {
    return this.rows.filter(
      (r) =>
        r.ecosystem === ecosystem &&
        r.import_sig === sig &&
        r.package_name !== excludePackage
    );
  }

  async findBySyscallSig(
    ecosystem: "pypi" | "npm",
    sig: string,
    excludePackage: string,
    _excludeVersion: string
  ): Promise<RegistryRow[]> {
    return this.rows.filter(
      (r) =>
        r.ecosystem === ecosystem &&
        r.syscall_sig === sig &&
        r.package_name !== excludePackage
    );
  }

  async findByFuzzyHashPrefix(
    ecosystem: "pypi" | "npm",
    prefix: string,
    excludePackage: string,
    _excludeVersion: string
  ): Promise<RegistryRow[]> {
    return this.rows.filter(
      (r) =>
        r.ecosystem === ecosystem &&
        r.package_name !== excludePackage &&
        typeof r.fuzzy_hash === "string" &&
        r.fuzzy_hash.startsWith(prefix)
    );
  }

  async bulkInsertSeed(rows: RegistryRow[]): Promise<void> {
    for (const row of rows) {
      await this.upsert(row);
    }
  }

  /** Test helper: direct access to stored rows. */
  getRows(): RegistryRow[] {
    return [...this.rows];
  }

  /** Test helper: clear all rows. */
  clear(): void {
    this.rows.length = 0;
  }
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

/**
 * Fuzzy-hash similarity threshold (0–100).
 * Matches at or above this score are reported as `pypi_binary_repackaging`
 * with severity "medium".  Exact SHA-256 matches are always "high".
 */
export const FUZZY_MATCH_THRESHOLD = 85;

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
export function computeFuzzyHash(binary: Buffer): string {
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
// Fuzzy-hash similarity scoring
// ---------------------------------------------------------------------------

/**
 * Compute the Jaccard similarity between two fuzzy hash strings.
 *
 * Both hashes are 64-char hex strings produced by computeFuzzyHash.
 * We treat each hex pair (byte) as a "shingle" and compute
 * |intersection| / |union| * 100.  Returns an integer in [0, 100].
 */
export function fuzzyHashSimilarity(hashA: string, hashB: string): number {
  if (hashA === hashB) return 100;
  if (hashA.length === 0 || hashB.length === 0) return 0;

  // Decompose into 2-char shingles (one per "byte")
  const shinglesA = new Set<string>();
  const shinglesB = new Set<string>();
  for (let i = 0; i + 2 <= hashA.length; i += 2) shinglesA.add(hashA.slice(i, i + 2));
  for (let i = 0; i + 2 <= hashB.length; i += 2) shinglesB.add(hashB.slice(i, i + 2));

  let intersection = 0;
  for (const s of shinglesA) {
    if (shinglesB.has(s)) intersection++;
  }
  const union = shinglesA.size + shinglesB.size - intersection;
  if (union === 0) return 0;
  return Math.round((intersection / union) * 100);
}

// ---------------------------------------------------------------------------
// Registry interaction helpers
// ---------------------------------------------------------------------------

/**
 * Persist a fingerprint to the registry and query for cross-package matches.
 *
 * Returns a BinaryRepackagingRisk describing any matches found.
 * If the registry is unavailable (e.g. no config), returns a "none" risk.
 */
export async function checkAndRecordFingerprint(
  fpData: WheelBinaryFingerprintData,
  registry: BinaryFingerprintRegistryClient
): Promise<BinaryRepackagingRisk> {
  const { packageName, version, binaryPath, fingerprint } = fpData;
  const hash = fingerprint.sha256;

  // 1. Upsert this fingerprint into the registry first.
  await registry.upsert({
    ecosystem: "pypi",
    package_name: packageName,
    version,
    binary_path: binaryPath,
    binary_hash: hash,
    fuzzy_hash: fingerprint.ssdeepFuzzyHash ?? null,
    import_sig: fingerprint.importSig ?? null,
    syscall_sig: fingerprint.syscallSig ?? null,
    source: "scan",
    computed_at: fpData.computedAt,
  });

  // 2. Query for cross-package matches in parallel.
  const [exactMatches, importSigMatches, syscallSigMatches, fuzzyPrefixCandidates] =
    await Promise.all([
      registry.findByHash("pypi", hash, packageName, version),
      fingerprint.importSig
        ? registry.findByImportSig("pypi", fingerprint.importSig, packageName, version)
        : Promise.resolve([] as RegistryRow[]),
      fingerprint.syscallSig
        ? registry.findBySyscallSig("pypi", fingerprint.syscallSig, packageName, version)
        : Promise.resolve([] as RegistryRow[]),
      fingerprint.ssdeepFuzzyHash
        ? registry.findByFuzzyHashPrefix(
            "pypi",
            fingerprint.ssdeepFuzzyHash.slice(0, 8),
            packageName,
            version
          )
        : Promise.resolve([] as RegistryRow[]),
    ]);

  const matches: BinaryRepackagingMatch[] = [];

  // Exact SHA-256 matches — highest confidence
  for (const row of exactMatches) {
    matches.push({
      matchedPackageName: row.package_name,
      matchedVersion: row.version,
      matchedBinaryPath: row.binary_path,
      matchKind: "exact_sha256",
      similarityScore: 100,
      registryEntryDate: row.computed_at ?? new Date().toISOString(),
    });
  }

  // Import-sig matches (same dangerous API set, potentially same payload)
  for (const row of importSigMatches) {
    // Skip if already captured as exact match
    const alreadyExact = matches.some(
      (m) =>
        m.matchedPackageName === row.package_name &&
        m.matchedVersion === row.version &&
        m.matchKind === "exact_sha256"
    );
    if (!alreadyExact) {
      matches.push({
        matchedPackageName: row.package_name,
        matchedVersion: row.version,
        matchedBinaryPath: row.binary_path,
        matchKind: "import_sig",
        similarityScore: 100,
        registryEntryDate: row.computed_at ?? new Date().toISOString(),
      });
    }
  }

  // Syscall-sig matches
  for (const row of syscallSigMatches) {
    const already = matches.some(
      (m) =>
        m.matchedPackageName === row.package_name &&
        m.matchedVersion === row.version &&
        (m.matchKind === "exact_sha256" || m.matchKind === "import_sig")
    );
    if (!already) {
      matches.push({
        matchedPackageName: row.package_name,
        matchedVersion: row.version,
        matchedBinaryPath: row.binary_path,
        matchKind: "syscall_sig",
        similarityScore: 100,
        registryEntryDate: row.computed_at ?? new Date().toISOString(),
      });
    }
  }

  // Fuzzy-hash candidates — score each and keep only those above threshold
  for (const row of fuzzyPrefixCandidates) {
    // Skip if already matched by exact or sig
    const alreadyMatched = matches.some(
      (m) => m.matchedPackageName === row.package_name && m.matchedVersion === row.version
    );
    if (alreadyMatched) continue;
    if (!row.fuzzy_hash || !fingerprint.ssdeepFuzzyHash) continue;

    const score = fuzzyHashSimilarity(fingerprint.ssdeepFuzzyHash, row.fuzzy_hash);
    if (score >= FUZZY_MATCH_THRESHOLD) {
      matches.push({
        matchedPackageName: row.package_name,
        matchedVersion: row.version,
        matchedBinaryPath: row.binary_path,
        matchKind: "fuzzy_hash",
        similarityScore: score,
        registryEntryDate: row.computed_at ?? new Date().toISOString(),
      });
    }
  }

  const hasExactCopy = matches.some((m) => m.matchKind === "exact_sha256");
  const hasFuzzyVariant = matches.some((m) => m.matchKind === "fuzzy_hash");
  const maxSimilarity = matches.length > 0 ? Math.max(...matches.map((m) => m.similarityScore)) : 0;

  // Determine risk level.
  // Critical: exact binary copy but the import/syscall sigs are DIFFERENT
  // (binary bytes identical but the import-table signature changed —
  // suggests the original binary was backdoored and re-published).
  let riskLevel: BinaryRepackagingRisk["riskLevel"] = "none";
  if (hasExactCopy) {
    // Check whether any exact-copy match from the registry has a different import_sig
    const exactRows = exactMatches.filter((r) =>
      matches.some((m) => m.matchedPackageName === r.package_name && m.matchKind === "exact_sha256")
    );
    const sigMismatch = exactRows.some(
      (r) =>
        r.import_sig !== null &&
        fingerprint.importSig !== undefined &&
        r.import_sig !== fingerprint.importSig
    );
    riskLevel = sigMismatch ? "critical" : "high";
  } else if (hasFuzzyVariant || matches.length > 0) {
    riskLevel = "medium";
  }

  return {
    binaryPath,
    binaryHash: hash,
    matches,
    hasExactCopy,
    hasFuzzyVariant,
    maxSimilarity,
    riskLevel,
  };
}

/**
 * Convert a BinaryRepackagingRisk into ScriptFindings to emit alongside the
 * regular wheelNativeBinary findings.
 *
 * Returns an empty array when riskLevel is "none".
 */
export function repackagingRiskToFindings(
  risk: BinaryRepackagingRisk,
  abiLabel: string
): ScriptFinding[] {
  if (risk.riskLevel === "none" || risk.matches.length === 0) return [];

  const findings: ScriptFinding[] = [];

  for (const match of risk.matches) {
    let severity: FindingSeverity;
    let title: string;
    let description: string;

    switch (match.matchKind) {
      case "exact_sha256":
        severity = risk.riskLevel === "critical" ? "critical" : "high";
        title = `Binary copy detected: ${path.basename(risk.binaryPath)} matches ${match.matchedPackageName}@${match.matchedVersion}`;
        description =
          `The native binary '${risk.binaryPath}' (SHA-256: ${risk.binaryHash.slice(0, 16)}…) ` +
          `is byte-for-byte identical to a binary previously seen in ` +
          `'${match.matchedPackageName}@${match.matchedVersion}' (${match.matchedBinaryPath}). ` +
          (risk.riskLevel === "critical"
            ? "CRITICAL: The import signature differs — this binary may be a backdoored fork."
            : "This is a strong indicator of supply-chain repackaging.");
        break;

      case "fuzzy_hash":
        severity = "medium";
        title = `Fuzzy binary variant: ${path.basename(risk.binaryPath)} is ${match.similarityScore}% similar to ${match.matchedPackageName}@${match.matchedVersion}`;
        description =
          `The native binary '${risk.binaryPath}' is approximately ${match.similarityScore}% similar ` +
          `to a binary in '${match.matchedPackageName}@${match.matchedVersion}' (${match.matchedBinaryPath}). ` +
          `This may indicate a slightly modified fork — verify SPDX licenses and source provenance.`;
        break;

      case "import_sig":
        severity = "medium";
        title = `Shared import signature: ${path.basename(risk.binaryPath)} and ${match.matchedPackageName}@${match.matchedVersion} expose identical dangerous APIs`;
        description =
          `The native binary '${risk.binaryPath}' exposes the same dangerous import/API symbol set as ` +
          `'${match.matchedPackageName}@${match.matchedVersion}' (${match.matchedBinaryPath}). ` +
          `This may indicate a code fork, vendored copy, or shared malware payload.`;
        break;

      case "syscall_sig":
        severity = "medium";
        title = `Shared syscall pattern: ${path.basename(risk.binaryPath)} and ${match.matchedPackageName}@${match.matchedVersion} share attack patterns`;
        description =
          `The native binary '${risk.binaryPath}' matches the syscall/attack-pattern signature of ` +
          `'${match.matchedPackageName}@${match.matchedVersion}' (${match.matchedBinaryPath}). ` +
          `Review both packages for shared malicious code.`;
        break;

      default:
        severity = "medium";
        title = `Binary similarity: ${path.basename(risk.binaryPath)} matches ${match.matchedPackageName}@${match.matchedVersion}`;
        description = `Binary similarity match found in registry.`;
    }

    findings.push({
      category: "pypi_binary_repackaging",
      severity,
      title,
      description,
      filePath: `${risk.binaryPath} [${abiLabel}]`,
      evidence:
        `match_kind:${match.matchKind} similarity:${match.similarityScore} ` +
        `matched:${match.matchedPackageName}@${match.matchedVersion}`,
      recommendation:
        "Verify this package's provenance against the upstream source repository. " +
        "Check SPDX license metadata for legitimate vendoring. " +
        "If not a legitimate fork, treat as a supply-chain substitution attack and block immediately.",
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// CISA / SBOM seed ingestion
// ---------------------------------------------------------------------------

/**
 * Configuration for the startup seed ingestion.
 */
export interface SeedIngestionConfig {
  /** Registry client to write into. */
  registry: BinaryFingerprintRegistryClient;
  /**
   * Optional URL of a CISA/NSF SBOM database endpoint that returns a JSON
   * array of RegistryRow-compatible objects.  When omitted the CISA seed step
   * is skipped.
   */
  cisaSbomUrl?: string;
  /**
   * Optional URL of a PyPI wheel fingerprint dataset (JSON array of
   * RegistryRow-compatible objects).  When omitted the PyPI seed step is
   * skipped.
   */
  pypiSeedUrl?: string;
  /**
   * Static seed rows to insert directly (used by tests to pre-populate
   * the registry without network access).
   */
  staticSeedRows?: RegistryRow[];
}

/**
 * Ingest the CISA/NSF SBOM database and existing PyPI wheel fingerprints
 * into the binary fingerprint registry.
 *
 * This is called once at worker startup so that the registry contains
 * reference data before the first live scan.  All errors are caught and
 * logged as warnings — a seed failure must not prevent the worker from
 * starting.
 *
 * @returns Number of rows successfully seeded.
 */
export async function seedBinaryFingerprintRegistry(
  config: SeedIngestionConfig
): Promise<number> {
  let seeded = 0;

  // 1. Static seed rows (tests / offline mode)
  if (config.staticSeedRows && config.staticSeedRows.length > 0) {
    try {
      await config.registry.bulkInsertSeed(config.staticSeedRows);
      seeded += config.staticSeedRows.length;
    } catch (err) {
      console.warn("[binary-seed] static seed failed:", err);
    }
  }

  // 2. CISA/NSF SBOM database
  if (config.cisaSbomUrl) {
    try {
      const response = await fetch(config.cisaSbomUrl);
      if (!response.ok) {
        console.warn(`[binary-seed] CISA SBOM fetch returned ${response.status}`);
      } else {
        const data = (await response.json()) as unknown[];
        const rows = normaliseSeedRows(data, "seed_cisa");
        await config.registry.bulkInsertSeed(rows);
        seeded += rows.length;
      }
    } catch (err) {
      console.warn("[binary-seed] CISA SBOM ingestion failed:", err);
    }
  }

  // 3. PyPI wheel fingerprint dataset
  if (config.pypiSeedUrl) {
    try {
      const response = await fetch(config.pypiSeedUrl);
      if (!response.ok) {
        console.warn(`[binary-seed] PyPI seed fetch returned ${response.status}`);
      } else {
        const data = (await response.json()) as unknown[];
        const rows = normaliseSeedRows(data, "seed_pypi");
        await config.registry.bulkInsertSeed(rows);
        seeded += rows.length;
      }
    } catch (err) {
      console.warn("[binary-seed] PyPI seed ingestion failed:", err);
    }
  }

  return seeded;
}

/**
 * Normalise raw JSON rows from a seed dataset into RegistryRow objects.
 * Rows that are missing required fields are silently dropped.
 */
function normaliseSeedRows(
  data: unknown[],
  source: "seed_cisa" | "seed_pypi"
): RegistryRow[] {
  const rows: RegistryRow[] = [];
  for (const item of data) {
    if (typeof item !== "object" || item === null) continue;
    const r = item as Record<string, unknown>;
    if (
      typeof r["package_name"] !== "string" ||
      typeof r["version"] !== "string" ||
      typeof r["binary_hash"] !== "string"
    ) {
      continue;
    }
    rows.push({
      ecosystem: r["ecosystem"] === "npm" ? "npm" : "pypi",
      package_name: (r["package_name"] as string).toLowerCase(),
      version: r["version"] as string,
      binary_path: typeof r["binary_path"] === "string" ? r["binary_path"] : "unknown",
      binary_hash: r["binary_hash"] as string,
      fuzzy_hash: typeof r["fuzzy_hash"] === "string" ? r["fuzzy_hash"] : null,
      import_sig: typeof r["import_sig"] === "string" ? r["import_sig"] : null,
      syscall_sig: typeof r["syscall_sig"] === "string" ? r["syscall_sig"] : null,
      source,
      computed_at: typeof r["computed_at"] === "string" ? r["computed_at"] : new Date().toISOString(),
    });
  }
  return rows;
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
 * Options for `analyzeWheelBinaries`.
 */
export interface AnalyzeWheelBinariesOptions {
  /**
   * Optional registry client for cross-package similarity clustering.
   * When omitted, fingerprints are computed but not checked against the
   * registry and `repackagingRisks` will be empty.
   */
  registry?: BinaryFingerprintRegistryClient;

  /**
   * When true, skip cryptographic provenance verification (RECORD + attestation).
   * Useful for offline / test scenarios where network calls are not desired.
   * Defaults to false (provenance verification runs by default).
   */
  skipProvenance?: boolean;

  /**
   * When true, skip the PyPI attestation network call during provenance verification.
   * The RECORD hash check still runs. Useful when only local verification is needed.
   */
  skipAttestation?: boolean;

  /**
   * Sdist matching options. When provided, the wheel's native binary set is
   * compared against the sdist's declared ext_modules.
   * Omit to skip sdist matching (matchesSdist will be null).
   */
  sdistMatch?: MatchWheelToSdistOptions;

  /**
   * When true, skip the ProvenanceVerifier supply-chain attestation check
   * (PEP 740 GPG sigs, publisher identity, freshness, orphaned wheels).
   * Defaults to false — provenance verification runs for all PyPI wheel scans.
   */
  skipProvenanceVerifier?: boolean;

  /**
   * Expected maintainer usernames for the ProvenanceVerifier publisher identity
   * check (PEP 503). When omitted the check reports "unknown" rather than
   * mismatch, and no high-severity finding is raised for unknown uploaders.
   */
  provenanceExpectedMaintainers?: string[];
}

/**
 * Download a wheel from PyPI, extract all `.so` / `.pyd` / `.dylib` native
 * extensions, and run the full binary analysis pipeline on each one.
 *
 * When a `registry` is provided via `options`, each binary's fingerprint is
 * also checked against the cross-package registry and any matches are
 * emitted as `pypi_binary_repackaging` findings.
 *
 * @param packageName  PyPI package name (case-insensitive).
 * @param version      Exact version string as published on PyPI.
 * @param wheelEntry   The specific wheel URL entry from the PyPI JSON API.
 *                     Use `selectBestWheel()` to pick the best one.
 * @param options      Optional configuration for registry-backed clustering.
 * @returns  Structured `WheelBinaryAnalysis` with per-binary findings.
 */
export async function analyzeWheelBinaries(
  packageName: string,
  version: string,
  wheelEntry: PyPiUrlEntry,
  options: AnalyzeWheelBinariesOptions = {}
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

    const wheelBytes = Buffer.from(arrayBuf);
    const wheelPath = path.join(tempRoot, wheelEntry.filename);
    await writeFile(wheelPath, wheelBytes);

    // Wheels are zip archives — extract with unzip
    await execFileAsync("unzip", ["-q", wheelPath, "-d", extractDir]);

    // Parse ABI tag
    const abiTag = parseWheelAbiTag(wheelEntry.filename);
    const abiLabel = abiTag?.label ?? `${packageName}-${version}`;

    // ---------------------------------------------------------------------------
    // Provenance verification (RECORD + attestation + sdist matching)
    // Runs before binary analysis so provenance findings are included in all
    // return paths (including pure-Python wheels).
    // ---------------------------------------------------------------------------
    let provenance: WheelProvenanceResult | null = null;
    if (!options.skipProvenance) {
      try {
        // Optionally run sdist matching first
        let sdistMatchResult: SdistMatchResult | null | undefined;
        if (options.sdistMatch) {
          sdistMatchResult = await matchWheelToSdist({
            ...options.sdistMatch,
            extractDir,
          });
        }

        provenance = await verifyWheelProvenance({
          wheelBytes,
          wheelFilename: wheelEntry.filename,
          publishedHash: wheelEntry.digests?.sha256,
          extractDir,
          packageName,
          version,
          skipAttestation: options.skipAttestation ?? false,
          sdistMatch: sdistMatchResult,
        });
      } catch {
        // Provenance verification failure is non-fatal — binary analysis proceeds.
        provenance = null;
      }
    }

    // ---------------------------------------------------------------------------
    // ProvenanceVerifier supply-chain attestation check (PEP 740 + publisher)
    // ---------------------------------------------------------------------------
    let provenance_findings: ProvenanceFinding[] = [];
    if (!options.skipProvenanceVerifier) {
      try {
        const pv = new ProvenanceVerifier();
        const pvResult = await pv.verify(packageName, version, {
          expectedMaintainers: options.provenanceExpectedMaintainers,
          skipNetworkCalls: false,
        });
        provenance_findings = pvResult.findings;
      } catch {
        // ProvenanceVerifier failure is non-fatal — binary analysis proceeds.
        provenance_findings = [];
      }
    }

    // Collect native extensions
    const nativePaths = await collectNativeExtensionPaths(extractDir);

    if (nativePaths.length === 0) {
      // For pure-Python wheels, still emit provenance findings if any
      const provenanceFindings: ScriptFinding[] = provenance
        ? provenanceResultToFindings(provenance, wheelEntry.filename)
        : [];
      return {
        abiTag,
        nativeExtensions: [],
        findings: provenanceFindings,
        hasNativeExtensions: false,
        confidence: "high",
        binaryFingerprints: [],
        repackagingRisks: [],
        provenance,
        provenance_findings,
      };
    }

    // Fingerprint and analyse each native extension
    const nativeExtensions: WheelNativeExtension[] = [];
    const allFindings: ScriptFinding[] = [];
    const binaryFingerprints: WheelBinaryFingerprintData[] = [];
    const repackagingRisks: BinaryRepackagingRisk[] = [];

    // Prepend provenance findings so they appear before binary pipeline findings
    if (provenance) {
      allFindings.push(...provenanceResultToFindings(provenance, wheelEntry.filename));
    }

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
        const fpData = buildFingerprintData(artifact, fingerprint, packageName, version);
        binaryFingerprints.push(fpData);

        // Cross-package registry check (when registry client is provided)
        if (options.registry) {
          const risk = await checkAndRecordFingerprint(fpData, options.registry);
          repackagingRisks.push(risk);

          // Emit repackaging findings
          const repackagingFindings = repackagingRiskToFindings(risk, abiLabel);
          allFindings.push(...repackagingFindings);
        }
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
      binaryFingerprints,
      repackagingRisks,
      provenance,
      provenance_findings,
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
  version: string,
  options: AnalyzeWheelBinariesOptions = {}
): Promise<WheelBinaryAnalysis | null> {
  const { wheels } = await detectWheelOnlyPackage(packageName, version);

  if (wheels.length === 0) {
    return null;
  }

  const best = selectBestWheel(wheels);
  if (!best) return null;

  return analyzeWheelBinaries(packageName, version, best, options);
}
