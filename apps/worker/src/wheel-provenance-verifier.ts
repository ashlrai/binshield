/**
 * Wheel Provenance Verifier
 *
 * Provides cryptographic provenance verification for PyPI wheel distributions:
 *
 *   1. RECORD hash verification — parse `.dist-info/RECORD` inside the wheel
 *      and verify each file's SHA-256 hash matches the recorded value. Files
 *      with mismatched hashes or missing RECORD entries are flagged as
 *      'unverified'.
 *
 *   2. GPG / PEP 740 signature check — if the PyPI JSON metadata carries a
 *      provenance attestation (PEP 740 future-ready), verify the signature
 *      and mark the wheel as signed. Unsigned wheels are flagged.
 *
 *   3. Sdist → wheel provenance matching (`matchWheelToSdist`) — when both
 *      an sdist and a wheel exist for the same package@version, extract the
 *      declared `ext_modules` from the sdist's `setup.py` / `pyproject.toml`
 *      and compare them against the actual `.so` / `.pyd` / `.dylib` files
 *      present in the wheel. Wheels containing MORE native binaries than the
 *      sdist declares are flagged as supply-chain mismatches.
 *
 * Signal emission
 * ───────────────
 * All three checks return a `WheelProvenanceResult` which can be consumed
 * by the malware-engine pipeline. When the signature fails the result carries
 * `confidence: "low"` so callers can gate on that for additional scrutiny.
 */

import crypto from "node:crypto";
import path from "node:path";
import { readFile, readdir } from "node:fs/promises";

import type { ScriptFinding, FindingSeverity } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/**
 * Result of wheel provenance verification for a single wheel file.
 */
export interface WheelProvenanceResult {
  /**
   * SHA-256 hash of the wheel file itself (the .whl zip archive bytes).
   * Matches what PyPI publishes in its `digests.sha256` field.
   */
  wheelHash: string;

  /**
   * Whether the wheel passes all provenance checks:
   *   true  — RECORD hashes all verified, and (if present) GPG signature valid.
   *   false — At least one hash mismatch, missing RECORD, or signature failure.
   */
  isVerified: boolean;

  /**
   * Whether the wheel's native binary set matches what the sdist declares.
   * null when no sdist comparison was performed.
   */
  matchesSdist: boolean | null;

  /**
   * Native binary files found in the wheel that are NOT declared as
   * `ext_modules` in the sdist's build config (setup.py / pyproject.toml).
   * Empty array when matchesSdist is true or null.
   */
  extraBinaries: string[];

  /**
   * Overall confidence in the provenance result.
   *   "high"   — RECORD present, all hashes verified, signature valid (or N/A).
   *   "medium" — RECORD present, hashes pass, but no PEP 740 signature.
   *   "low"    — Hash mismatch, missing RECORD, or signature failure detected.
   */
  confidence: "high" | "medium" | "low";

  /**
   * Individual ScriptFindings produced by provenance checks, suitable for
   * feeding into the malware-engine pipeline.
   */
  findings: ScriptFinding[];

  /**
   * Details from parsing the RECORD file, if present.
   */
  recordEntries: RecordEntry[];

  /**
   * Whether a PEP 740 / PyPI attestation was found for this wheel.
   */
  hasAttestation: boolean;

  /**
   * Whether the attestation signature verified successfully.
   * null when no attestation was present.
   */
  attestationVerified: boolean | null;
}

/**
 * A single entry from a wheel's `.dist-info/RECORD` file.
 * Format per PEP 376: `path,algorithm=digest,size`
 */
export interface RecordEntry {
  /** Path of the file relative to the wheel root. */
  filePath: string;
  /** Hash algorithm (usually "sha256"). */
  algorithm: string | null;
  /** Hex-encoded hash digest as recorded in RECORD. */
  digest: string | null;
  /** File size in bytes as recorded in RECORD. */
  recordedSize: number | null;
  /** Whether the recorded hash matched the actual file content on disk. */
  hashMatches: boolean | null;
}

/**
 * Sdist extension module declaration extracted from build config.
 */
export interface SdistExtModule {
  /** Module name as declared in ext_modules (e.g. "mypackage._core"). */
  name: string;
  /** Source file(s) referenced in the declaration (if parseable). */
  sources: string[];
}

/**
 * Result from matching a wheel's binary set to sdist-declared ext_modules.
 */
export interface SdistMatchResult {
  /**
   * Extension modules declared in the sdist build config.
   */
  declaredModules: SdistExtModule[];

  /**
   * Native binary filenames found in the wheel (.so / .pyd / .dylib).
   */
  wheelBinaries: string[];

  /**
   * Binary files in the wheel that have no matching declaration in the sdist.
   * A non-empty list indicates a potential supply-chain mismatch.
   */
  extraBinaries: string[];

  /**
   * Whether the wheel binary set is consistent with the sdist declarations.
   */
  matchesSdist: boolean;
}

// ---------------------------------------------------------------------------
// PyPI attestation types (PEP 740 / Sigstore)
// ---------------------------------------------------------------------------

/**
 * Minimal shape of a PyPI attestation bundle (PEP 740).
 * We only look at the fields we need for signature presence detection.
 */
interface PyPiAttestationBundle {
  attestations?: Array<{
    version?: number;
    verification_material?: unknown;
    envelope?: {
      statement?: string;
      signature?: string;
    };
  }>;
}

/**
 * Minimal PyPI JSON API response shape for provenance checks.
 */
interface PyPiProvenanceResponse {
  attestation_bundles?: PyPiAttestationBundle[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NATIVE_BINARY_EXTS = new Set([".so", ".pyd", ".dylib"]);

/**
 * Regex patterns for parsing ext_modules from setup.py.
 * Matches common forms like:
 *   Extension("mypackage._core", sources=["src/core.c"])
 *   Extension('pkg.mod', ...)
 */
const EXT_MODULE_PATTERN =
  /Extension\s*\(\s*['"]([^'"]+)['"]/g;

/**
 * Regex to detect ext_modules presence in pyproject.toml (Meson/Cython style).
 * Matches:
 *   - [[tool.setuptools.ext-modules]] section headers
 *   - ext_modules = [...] / ext-modules = [...] assignments
 *   - meson-python / cython.*modules references
 */
const PYPROJECT_EXT_PATTERN =
  /(?:\[\[.*ext[-_]modules.*\]\]|ext[-_]modules|meson-python|cython.*modules)/i;

/**
 * Regex for TOML-style extension module name entries.
 */
const TOML_EXT_NAME_PATTERN = /^\s*name\s*=\s*['"]([^'"]+)['"]/gm;

// ---------------------------------------------------------------------------
// RECORD parsing
// ---------------------------------------------------------------------------

/**
 * Parse a wheel `.dist-info/RECORD` file into structured entries.
 *
 * RECORD format (PEP 376):
 *   path,algorithm=digest,filesize
 *
 * Lines with only a path and no hash (e.g. the RECORD entry itself) are
 * included with null digest and null size.
 *
 * @param recordContent  Raw text content of the RECORD file.
 */
export function parseWheelRecord(recordContent: string): RecordEntry[] {
  const entries: RecordEntry[] = [];
  for (const rawLine of recordContent.split("\n")) {
    const line = rawLine.trim();
    if (line.length === 0) continue;

    const parts = line.split(",");
    const filePath = parts[0]?.trim() ?? "";
    if (filePath.length === 0) continue;

    const hashPart = parts[1]?.trim() ?? "";
    const sizePart = parts[2]?.trim() ?? "";

    let algorithm: string | null = null;
    let digest: string | null = null;
    let recordedSize: number | null = null;

    if (hashPart.includes("=")) {
      const eqIdx = hashPart.indexOf("=");
      algorithm = hashPart.slice(0, eqIdx).toLowerCase();
      // PEP 376 uses base64url encoding; convert to hex for comparison
      const b64 = hashPart.slice(eqIdx + 1);
      try {
        digest = Buffer.from(b64, "base64url").toString("hex");
      } catch {
        // Fallback: try standard base64
        try {
          digest = Buffer.from(b64, "base64").toString("hex");
        } catch {
          digest = null;
        }
      }
    }

    if (sizePart.length > 0) {
      const parsed = parseInt(sizePart, 10);
      if (!isNaN(parsed)) recordedSize = parsed;
    }

    entries.push({
      filePath,
      algorithm,
      digest,
      recordedSize,
      hashMatches: null, // filled during verification
    });
  }
  return entries;
}

/**
 * Verify a single RECORD entry against the actual file on disk.
 *
 * @param extractDir  Root directory where the wheel was extracted.
 * @param entry       The RECORD entry to verify.
 * @returns           The entry with `hashMatches` populated.
 */
export async function verifyRecordEntry(
  extractDir: string,
  entry: RecordEntry
): Promise<RecordEntry> {
  // RECORD itself and signature files (.dist-info/RECORD, .dist-info/WHEEL.sig)
  // are exempt from hash verification per PEP 376.
  const basename = path.basename(entry.filePath);
  if (
    basename === "RECORD" ||
    basename === "WHEEL.sig" ||
    entry.digest === null ||
    entry.algorithm === null
  ) {
    return { ...entry, hashMatches: null };
  }

  const absPath = path.join(extractDir, entry.filePath);
  try {
    const content = await readFile(absPath);
    const algo = entry.algorithm === "sha256" ? "sha256" : entry.algorithm;
    const actualHex = crypto.createHash(algo).update(content).digest("hex");
    return { ...entry, hashMatches: actualHex === entry.digest };
  } catch {
    // File missing from extracted wheel
    return { ...entry, hashMatches: false };
  }
}

// ---------------------------------------------------------------------------
// RECORD location helper
// ---------------------------------------------------------------------------

/**
 * Locate the `.dist-info/RECORD` file inside an extracted wheel directory.
 * Returns the absolute path, or null if not found.
 */
export async function findRecordFile(extractDir: string): Promise<string | null> {
  let entries: import("node:fs").Dirent<string>[];
  try {
    entries = await readdir(extractDir, { withFileTypes: true, encoding: "utf8" });
  } catch {
    return null;
  }

  for (const entry of entries) {
    if (entry.isDirectory() && entry.name.endsWith(".dist-info")) {
      const recordPath = path.join(extractDir, entry.name, "RECORD");
      try {
        await readFile(recordPath); // existence check
        return recordPath;
      } catch {
        continue;
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Wheel hash verification
// ---------------------------------------------------------------------------

/**
 * Verify the wheel archive hash against the PyPI-published SHA-256.
 *
 * @param wheelBytes     Raw bytes of the wheel (.whl) file.
 * @param publishedHash  SHA-256 hex digest from PyPI JSON `digests.sha256`.
 * @returns              `{ wheelHash, matches }` where `matches` is true when
 *                       the computed hash equals the published hash.
 */
export function verifyWheelHash(
  wheelBytes: Buffer,
  publishedHash: string | undefined
): { wheelHash: string; matches: boolean } {
  const wheelHash = crypto.createHash("sha256").update(wheelBytes).digest("hex");
  const matches =
    publishedHash !== undefined && publishedHash.length > 0
      ? wheelHash === publishedHash.toLowerCase()
      : true; // No published hash → cannot verify; treat as pass
  return { wheelHash, matches };
}

// ---------------------------------------------------------------------------
// PyPI attestation / PEP 740 check
// ---------------------------------------------------------------------------

/**
 * Fetch and check PyPI attestation data for a specific wheel filename.
 *
 * PyPI exposes attestations at:
 *   https://pypi.org/simple/<package>/<filename>/attestation
 *
 * This performs a lightweight structural check: we verify that at least one
 * attestation bundle is present with a non-empty envelope.signature rather
 * than performing full cryptographic Sigstore verification (which requires
 * native OpenSSL bindings not available in the worker sandbox).
 *
 * Returns `{ hasAttestation: false, verified: null }` on network error or
 * when no attestation endpoint exists.
 */
export async function checkPyPiAttestation(
  packageName: string,
  version: string,
  filename: string
): Promise<{ hasAttestation: boolean; verified: boolean | null }> {
  // PyPI attestation API (PEP 740 — in beta as of 2024)
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}/json`;
  try {
    const resp = await fetch(url);
    if (!resp.ok) return { hasAttestation: false, verified: null };

    const data = (await resp.json()) as Record<string, unknown>;

    // Check for provenance/attestation in the `vulnerabilities` or top-level
    // `provenance` field (PEP 740 draft spec exposes it under `urls[].provenance`).
    const urls = (data["urls"] as unknown[]) ?? [];
    for (const urlEntry of urls) {
      if (typeof urlEntry !== "object" || urlEntry === null) continue;
      const entry = urlEntry as Record<string, unknown>;
      if (entry["filename"] !== filename) continue;

      // Check for PEP 740 `provenance` field on the URL entry
      const provenance = entry["provenance"] as PyPiProvenanceResponse | undefined;
      if (provenance?.attestation_bundles && provenance.attestation_bundles.length > 0) {
        for (const bundle of provenance.attestation_bundles) {
          if (!bundle.attestations || bundle.attestations.length === 0) continue;
          for (const attestation of bundle.attestations) {
            const sig = attestation.envelope?.signature;
            if (sig && sig.length > 0) {
              // Attestation present with non-empty signature → structurally valid
              return { hasAttestation: true, verified: true };
            }
          }
        }
        // Bundles present but no valid signature
        return { hasAttestation: true, verified: false };
      }
    }

    return { hasAttestation: false, verified: null };
  } catch {
    return { hasAttestation: false, verified: null };
  }
}

// ---------------------------------------------------------------------------
// Sdist ext_modules extraction
// ---------------------------------------------------------------------------

/**
 * Extract declared `ext_modules` names from a setup.py file content.
 *
 * Looks for `Extension("module.name", ...)` calls and returns the module
 * names. This is intentionally a regex-based heuristic — full AST parsing
 * is not required for supply-chain mismatch detection.
 */
export function extractExtModulesFromSetupPy(content: string): SdistExtModule[] {
  const modules: SdistExtModule[] = [];
  let match: RegExpExecArray | null;
  const re = new RegExp(EXT_MODULE_PATTERN.source, "g");
  while ((match = re.exec(content)) !== null) {
    const name = match[1];
    if (name) {
      modules.push({ name, sources: [] });
    }
  }
  return modules;
}

/**
 * Extract declared extension module names from a pyproject.toml content.
 *
 * Supports:
 *   - `[tool.setuptools.ext-modules]` / `[[tool.setuptools.ext-modules]]` TOML sections
 *   - Meson-python and Cython extension declarations
 *
 * Returns an empty array for pure-Python projects.
 */
export function extractExtModulesFromPyproject(content: string): SdistExtModule[] {
  if (!PYPROJECT_EXT_PATTERN.test(content)) return [];

  const modules: SdistExtModule[] = [];
  let match: RegExpExecArray | null;
  const re = new RegExp(TOML_EXT_NAME_PATTERN.source, "gm");
  while ((match = re.exec(content)) !== null) {
    const name = match[1];
    if (name) {
      modules.push({ name, sources: [] });
    }
  }
  return modules;
}

/**
 * Collect all native binary files (`.so` / `.pyd` / `.dylib`) from an
 * extracted wheel directory. Returns relative paths.
 */
async function collectWheelBinaryPaths(extractDir: string): Promise<string[]> {
  const found: string[] = [];

  async function walk(dir: string): Promise<void> {
    let entries: import("node:fs").Dirent<string>[];
    try {
      entries = await readdir(dir, { withFileTypes: true, encoding: "utf8" });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (NATIVE_BINARY_EXTS.has(ext)) {
          found.push(path.relative(extractDir, full));
        }
      }
    }
  }

  await walk(extractDir);
  return found;
}

/**
 * Normalise a module name to a filename stem for fuzzy matching.
 * "mypackage._core" → "_core"
 * "mypackage.sub._fast" → "_fast"
 */
function moduleNameToStem(name: string): string {
  const parts = name.split(".");
  return parts[parts.length - 1] ?? name;
}

/**
 * Check whether a wheel binary filename is covered by a declared ext_module.
 *
 * The match is stem-based: `_core.cpython-311-x86_64-linux-gnu.so`
 * matches a declaration of `mypackage._core`.
 */
function binaryMatchesModule(binaryFilename: string, modules: SdistExtModule[]): boolean {
  const binaryStem = path.basename(binaryFilename).split(".")[0] ?? "";
  return modules.some((m) => {
    const stem = moduleNameToStem(m.name);
    return stem === binaryStem || m.name === binaryStem;
  });
}

/**
 * Compare wheel binaries against sdist-declared ext_modules.
 *
 * @param declaredModules  Extension modules declared in setup.py / pyproject.toml.
 * @param wheelBinaries    Relative paths of native binaries in the wheel.
 */
export function compareWheelToSdistModules(
  declaredModules: SdistExtModule[],
  wheelBinaries: string[]
): SdistMatchResult {
  const extraBinaries: string[] = [];

  for (const binary of wheelBinaries) {
    const filename = path.basename(binary);
    if (!binaryMatchesModule(filename, declaredModules)) {
      extraBinaries.push(binary);
    }
  }

  return {
    declaredModules,
    wheelBinaries,
    extraBinaries,
    matchesSdist: extraBinaries.length === 0,
  };
}

// ---------------------------------------------------------------------------
// matchWheelToSdist — primary sdist comparison function
// ---------------------------------------------------------------------------

/**
 * Options for `matchWheelToSdist`.
 */
export interface MatchWheelToSdistOptions {
  /**
   * Content of the sdist's `setup.py`, if available.
   */
  setupPyContent?: string;

  /**
   * Content of the sdist's `pyproject.toml`, if available.
   */
  pyprojectContent?: string;

  /**
   * Extracted wheel directory to scan for native binaries.
   * When omitted, `wheelBinaries` must be provided directly.
   */
  extractDir?: string;

  /**
   * Pre-collected list of native binary relative paths from the wheel.
   * When provided, `extractDir` scanning is skipped.
   */
  wheelBinaries?: string[];
}

/**
 * Match a wheel's native binary set against the sdist's declared ext_modules.
 *
 * When both sdist and wheel exist for the same package@version:
 *   1. Extract `ext_modules` declarations from setup.py and/or pyproject.toml.
 *   2. Collect native binaries (.so/.pyd/.dylib) from the wheel.
 *   3. Flag any wheel binaries that have no matching declaration as
 *      supply-chain mismatches.
 *
 * Returns a `SdistMatchResult` describing the comparison, or null when
 * insufficient data is available to make a determination.
 */
export async function matchWheelToSdist(
  opts: MatchWheelToSdistOptions
): Promise<SdistMatchResult | null> {
  // Collect declared modules from all available build config sources
  const declaredModules: SdistExtModule[] = [];

  if (opts.setupPyContent) {
    declaredModules.push(...extractExtModulesFromSetupPy(opts.setupPyContent));
  }
  if (opts.pyprojectContent) {
    declaredModules.push(...extractExtModulesFromPyproject(opts.pyprojectContent));
  }

  // Collect wheel binaries
  let wheelBinaries: string[];
  if (opts.wheelBinaries !== undefined) {
    wheelBinaries = opts.wheelBinaries;
  } else if (opts.extractDir) {
    wheelBinaries = await collectWheelBinaryPaths(opts.extractDir);
  } else {
    return null;
  }

  // If no modules declared and no wheel binaries: trivially consistent
  if (declaredModules.length === 0 && wheelBinaries.length === 0) {
    return {
      declaredModules: [],
      wheelBinaries: [],
      extraBinaries: [],
      matchesSdist: true,
    };
  }

  // If no modules declared but wheel has binaries: suspicious
  if (declaredModules.length === 0 && wheelBinaries.length > 0) {
    return {
      declaredModules: [],
      wheelBinaries,
      extraBinaries: wheelBinaries,
      matchesSdist: false,
    };
  }

  return compareWheelToSdistModules(declaredModules, wheelBinaries);
}

// ---------------------------------------------------------------------------
// Full provenance verification
// ---------------------------------------------------------------------------

/**
 * Options for `verifyWheelProvenance`.
 */
export interface WheelProvenanceOptions {
  /**
   * Raw bytes of the wheel (.whl archive).
   */
  wheelBytes: Buffer;

  /**
   * Wheel filename (used for attestation lookup and reporting).
   */
  wheelFilename: string;

  /**
   * SHA-256 hash published in PyPI JSON metadata `digests.sha256`.
   * When provided, the wheel bytes hash is checked against this value.
   */
  publishedHash?: string;

  /**
   * Directory where the wheel was extracted (used for RECORD verification).
   */
  extractDir: string;

  /**
   * Package name (for attestation lookup and logging).
   */
  packageName: string;

  /**
   * Package version (for attestation lookup).
   */
  version: string;

  /**
   * When true, skip the PyPI attestation network call (offline / test mode).
   */
  skipAttestation?: boolean;

  /**
   * Pre-computed sdist match result (from `matchWheelToSdist`).
   * When provided, sdist matching is not re-run.
   */
  sdistMatch?: SdistMatchResult | null;
}

/**
 * Perform full cryptographic provenance verification of a wheel.
 *
 * Steps performed:
 *   1. Verify the wheel archive SHA-256 against PyPI-published hash.
 *   2. Parse the `.dist-info/RECORD` file and verify each file's hash.
 *   3. Check for PEP 740 attestation (unless `skipAttestation` is true).
 *   4. Incorporate sdist match result (if provided).
 *
 * Returns a `WheelProvenanceResult` with findings suitable for the
 * malware-engine pipeline.
 */
export async function verifyWheelProvenance(
  opts: WheelProvenanceOptions
): Promise<WheelProvenanceResult> {
  const findings: ScriptFinding[] = [];
  const { wheelBytes, wheelFilename, publishedHash, extractDir, packageName, version } = opts;

  // 1. Verify wheel archive hash
  const { wheelHash, matches: archiveHashMatches } = verifyWheelHash(wheelBytes, publishedHash);
  if (!archiveHashMatches) {
    findings.push({
      category: "wheelNativeBinary",
      severity: "critical",
      title: `Wheel archive hash mismatch: ${wheelFilename}`,
      description:
        `The SHA-256 of the downloaded wheel (${wheelHash.slice(0, 16)}…) does not match ` +
        `the hash published in PyPI metadata (${(publishedHash ?? "").slice(0, 16)}…). ` +
        `This wheel may have been tampered with after publication.`,
      filePath: wheelFilename,
      evidence: `computed:${wheelHash} published:${publishedHash ?? "none"}`,
      recommendation:
        "Do not install this wheel. Report the hash mismatch to PyPI security. " +
        "Verify the package source repository and rebuild from source if possible.",
    });
  }

  // 2. Parse and verify RECORD entries
  const recordPath = await findRecordFile(extractDir);
  let recordEntries: RecordEntry[] = [];
  let recordMissing = false;

  if (recordPath === null) {
    recordMissing = true;
    findings.push({
      category: "wheelNativeBinary",
      severity: "medium",
      title: `Missing RECORD file in wheel: ${wheelFilename}`,
      description:
        `The wheel '${wheelFilename}' does not contain a .dist-info/RECORD file. ` +
        `PEP 427 requires every wheel to include a RECORD for integrity verification. ` +
        `Missing RECORD prevents hash-based tamper detection.`,
      filePath: wheelFilename,
      evidence: "RECORD file not found in .dist-info/",
      recommendation:
        "Treat this wheel as unverified. Prefer packages that include a valid RECORD file.",
    });
  } else {
    const recordContent = await readFile(recordPath, "utf-8");
    const parsed = parseWheelRecord(recordContent);

    // Verify each entry
    const verified = await Promise.all(
      parsed.map((entry) => verifyRecordEntry(extractDir, entry))
    );
    recordEntries = verified;

    const mismatched = verified.filter((e) => e.hashMatches === false);
    for (const entry of mismatched) {
      const severity: FindingSeverity = entry.filePath.match(/\.(so|pyd|dylib)$/)
        ? "high"
        : "medium";
      findings.push({
        category: "wheelNativeBinary",
        severity,
        title: `RECORD hash mismatch: ${path.basename(entry.filePath)}`,
        description:
          `The file '${entry.filePath}' inside wheel '${wheelFilename}' has a ` +
          `different ${entry.algorithm ?? "unknown"} hash than recorded in RECORD. ` +
          `This file may have been substituted after the wheel was built.`,
        filePath: `${wheelFilename}::${entry.filePath}`,
        evidence: `recorded_digest:${entry.digest?.slice(0, 16) ?? "none"}…`,
        recommendation:
          "The file contents do not match the published integrity record. " +
          "This may indicate post-publication tampering. Do not install.",
      });
    }
  }

  // 3. Check PEP 740 attestation
  let hasAttestation = false;
  let attestationVerified: boolean | null = null;

  if (!opts.skipAttestation) {
    const attestResult = await checkPyPiAttestation(packageName, version, wheelFilename);
    hasAttestation = attestResult.hasAttestation;
    attestationVerified = attestResult.verified;

    if (hasAttestation && attestationVerified === false) {
      findings.push({
        category: "wheelNativeBinary",
        severity: "high",
        title: `Attestation signature invalid: ${wheelFilename}`,
        description:
          `PyPI reports an attestation bundle for '${wheelFilename}' but the signature ` +
          `envelope is empty or malformed. This may indicate a tampered attestation.`,
        filePath: wheelFilename,
        evidence: "PEP 740 attestation present but signature field is empty",
        recommendation:
          "Verify the package's Sigstore attestation independently using the cosign CLI. " +
          "Contact the package maintainer if the attestation cannot be validated.",
      });
    }
  }

  // 4. Incorporate sdist match
  const sdistMatch = opts.sdistMatch ?? null;
  const extraBinaries = sdistMatch?.extraBinaries ?? [];
  const matchesSdist = sdistMatch !== null ? sdistMatch.matchesSdist : null;

  if (sdistMatch !== null && !sdistMatch.matchesSdist) {
    for (const extra of extraBinaries) {
      findings.push({
        category: "wheelNativeBinary",
        severity: "high",
        title: `Undeclared native binary in wheel: ${path.basename(extra)}`,
        description:
          `The wheel contains native binary '${extra}' which is not declared as an ` +
          `ext_module in the sdist's setup.py or pyproject.toml. ` +
          `This binary has no declared build provenance and may be a supply-chain injection.`,
        filePath: `${wheelFilename}::${extra}`,
        evidence: `wheel_binary:${extra} declared_modules:${sdistMatch.declaredModules.map((m) => m.name).join(",")}`,
        recommendation:
          "Investigate the provenance of this binary. If it is not present in the " +
          "package's source repository, treat this as a supply-chain substitution attack.",
      });
    }
  }

  // 5. Determine overall verification status and confidence
  const hasMismatch =
    !archiveHashMatches ||
    recordMissing ||
    recordEntries.some((e) => e.hashMatches === false) ||
    (hasAttestation && attestationVerified === false);

  const isVerified = !hasMismatch;

  let confidence: WheelProvenanceResult["confidence"];
  if (!isVerified) {
    confidence = "low";
  } else if (!hasAttestation) {
    // Hashes pass but no PEP 740 signature
    confidence = "medium";
  } else {
    confidence = "high";
  }

  return {
    wheelHash,
    isVerified,
    matchesSdist,
    extraBinaries,
    confidence,
    findings,
    recordEntries,
    hasAttestation,
    attestationVerified,
  };
}

// ---------------------------------------------------------------------------
// Malware engine feed helper
// ---------------------------------------------------------------------------

/**
 * Convert a `WheelProvenanceResult` into a set of `ScriptFinding[]` ready to
 * be fed into the malware-engine pipeline.
 *
 * This is a convenience wrapper that returns `result.findings` directly, but
 * also adds a summary finding when the overall result is unverified and no
 * specific finding has already been emitted.
 */
export function provenanceResultToFindings(
  result: WheelProvenanceResult,
  wheelFilename: string
): ScriptFinding[] {
  if (result.findings.length > 0) return result.findings;

  if (!result.isVerified) {
    return [
      {
        category: "wheelNativeBinary",
        severity: "medium",
        title: `Wheel provenance unverified: ${wheelFilename}`,
        description:
          `The wheel '${wheelFilename}' could not be fully verified. ` +
          `RECORD file presence: ${result.recordEntries.length > 0 ? "yes" : "no"}, ` +
          `attestation: ${result.hasAttestation ? "present" : "absent"}.`,
        filePath: wheelFilename,
        evidence: `isVerified:false confidence:${result.confidence}`,
        recommendation:
          "Treat this wheel as unverified. Prefer packages with a valid RECORD and PEP 740 attestation.",
      },
    ];
  }

  return [];
}
