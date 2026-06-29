/**
 * PyPiWheelMetadataParser
 *
 * Parses PEP 427 / PEP 658 wheel dist-info metadata files extracted from a
 * wheel archive:
 *
 *   WHEEL    — build tag, wheel version, generator, root-is-purelib, tags
 *   RECORD   — file list with SHA-256 hashes and sizes (RFC 4180 CSV)
 *   METADATA — package metadata (PEP 241 / PEP 314 / PEP 566): Name, Version,
 *               Requires-Dist, Provides-Extra, Classifier, …
 *
 * The parser is intentionally offline-only: it reads from a directory tree
 * produced by extracting a wheel archive with `unzip`, rather than talking to
 * the network.  This lets it run as part of the binary analysis pipeline
 * immediately after `analyzeWheelBinaries` extracts the wheel.
 *
 * Extracted metadata is structured into `WheelDistInfo` and can be used by:
 *   • `PyPiCExtensionAnalyzer`  — to enumerate embedded .so/.pyd files
 *   • EPSS/CVE enrichment       — to resolve install_requires CVE candidates
 *   • Provenance verifier       — to cross-check RECORD hashes
 */

import path from "node:path";
import { readdir, readFile } from "node:fs/promises";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * A single file entry from the wheel's RECORD file.
 * Format per PEP 376: path,algorithm:hash,size
 */
export interface WheelRecordEntry {
  /** Relative path of the file inside the wheel (forward slashes). */
  filePath: string;
  /** Hash algorithm, e.g. "sha256". Empty string when no hash is recorded. */
  algorithm: string;
  /** Hex-encoded hash digest. Empty string when absent. */
  digest: string;
  /** File size in bytes. -1 when absent. */
  size: number;
}

/**
 * A single tag triplet from the wheel Tag header.
 * Per PEP 425: python-abi-platform  (e.g. cp311-cp311-linux_x86_64)
 */
export interface WheelTag {
  pythonTag: string;
  abiTag: string;
  platformTag: string;
}

/**
 * Parsed content of the WHEEL file inside a .dist-info directory.
 */
export interface WheelFileMetadata {
  /** Wheel-Version header value, e.g. "1.0". */
  wheelVersion: string;
  /** Generator header value, e.g. "poetry-core (1.9.0)". Empty string if absent. */
  generator: string;
  /** Root-Is-Purelib: "true" or "false". */
  rootIsPurelib: boolean;
  /**
   * Build tag — optional per PEP 427.  Empty string when not present.
   * A build tag disambiguates wheels built from the same source at the same
   * version (e.g. "1" for a rebuild).
   */
  buildTag: string;
  /** All Tag entries expanded into individual triplets. */
  tags: WheelTag[];
  /** Python implementation derived from the first tag (e.g. "cp", "pp"). */
  pythonImplementation: string;
  /**
   * Python version(s) derived from tag python components, e.g. ["311", "310"].
   * Deduplicated.
   */
  pythonVersions: string[];
  /**
   * Platform tags derived from Tag entries, e.g.
   * ["linux_x86_64", "manylinux_2_17_x86_64"].
   * Deduplicated.
   */
  platforms: string[];
}

/**
 * Parsed content of the METADATA file inside a .dist-info directory.
 * Follows PEP 241 / 314 / 566 / 643 email-header format.
 */
export interface WheelPackageMetadata {
  /** Metadata-Version header. */
  metadataVersion: string;
  /** Name header — canonical package name. */
  name: string;
  /** Version header — exact version string. */
  version: string;
  /** Summary header — one-line description. */
  summary: string;
  /** All Requires-Dist entries (PEP 508 dependency specifiers). */
  requiresDist: string[];
  /** All Provides-Extra entries. */
  providesExtra: string[];
  /** All Classifier entries. */
  classifiers: string[];
  /** Home-Page header. Empty string if absent. */
  homePage: string;
  /** Author / Author-email header. Empty string if absent. */
  author: string;
  /** License header. Empty string if absent. */
  license: string;
  /** All Project-URL entries (label, URL). */
  projectUrls: Array<{ label: string; url: string }>;
}

/**
 * Names and paths of native extension binaries (.so / .pyd / .dylib)
 * found in the RECORD file or by walking the extracted wheel tree.
 */
export interface EmbeddedBinary {
  /** Relative path from wheel root, forward-slash separated. */
  relativePath: string;
  /** Basename only, e.g. "_ssl.cpython-311-x86_64-linux-gnu.so". */
  filename: string;
  /** Extension: ".so", ".pyd", or ".dylib". */
  extension: ".so" | ".pyd" | ".dylib";
  /**
   * SHA-256 digest from the RECORD file, if present.
   * Empty string when the RECORD file doesn't list this file.
   */
  recordedDigest: string;
  /** File size from RECORD. -1 when absent. */
  recordedSize: number;
}

/**
 * Complete parsed dist-info metadata for a wheel archive.
 */
export interface WheelDistInfo {
  /** Name of the .dist-info directory, e.g. "numpy-1.26.4.dist-info". */
  distInfoDir: string;
  /** Parsed WHEEL file. null when the WHEEL file is missing or malformed. */
  wheelFile: WheelFileMetadata | null;
  /** Parsed METADATA file. null when METADATA is missing or malformed. */
  packageMetadata: WheelPackageMetadata | null;
  /** All entries from the RECORD file. Empty array when RECORD is absent. */
  recordEntries: WheelRecordEntry[];
  /**
   * Native extension binaries identified from RECORD + directory walk.
   * Populated by `parseWheelDistInfo` when `extractDir` is provided.
   */
  embeddedBinaries: EmbeddedBinary[];
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const NATIVE_EXTENSIONS = new Set([".so", ".pyd", ".dylib"]);

/**
 * Parse a PEP 376 RECORD CSV line into a WheelRecordEntry.
 * Format: path,algorithm:digest,size
 * Returns null for blank / comment lines.
 */
function parseRecordLine(line: string): WheelRecordEntry | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;

  // Simple CSV split — record entries should not have quoted commas in paths
  const parts = trimmed.split(",");
  if (parts.length < 1) return null;

  const filePath = (parts[0] ?? "").trim();
  const hashPart = (parts[1] ?? "").trim();
  const sizePart = (parts[2] ?? "").trim();

  let algorithm = "";
  let digest = "";
  if (hashPart.includes(":")) {
    const colonIdx = hashPart.indexOf(":");
    algorithm = hashPart.slice(0, colonIdx);
    digest = hashPart.slice(colonIdx + 1);
  }

  const size = sizePart ? parseInt(sizePart, 10) : -1;

  return {
    filePath,
    algorithm,
    digest,
    size: isNaN(size) ? -1 : size,
  };
}

/**
 * Parse the WHEEL file (email-header format) into WheelFileMetadata.
 */
function parseWheelFile(content: string): WheelFileMetadata {
  const lines = content.split(/\r?\n/);
  const headers: Record<string, string[]> = {};

  for (const line of lines) {
    const colonIdx = line.indexOf(":");
    if (colonIdx < 0) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    if (!headers[key]) headers[key] = [];
    headers[key]!.push(value);
  }

  const get = (key: string): string => (headers[key]?.[0] ?? "");
  const getAll = (key: string): string[] => headers[key] ?? [];

  const wheelVersion = get("wheel-version");
  const generator = get("generator");
  const rootIsPurelibStr = get("root-is-purelib").toLowerCase();
  const rootIsPurelib = rootIsPurelibStr === "true";
  const buildTag = get("build");

  // Parse Tag headers — may have multiple tags, each is "python-abi-platform"
  const tagStrings = getAll("tag");
  const tags: WheelTag[] = [];
  for (const tagStr of tagStrings) {
    const parts = tagStr.split("-");
    if (parts.length >= 3) {
      tags.push({
        pythonTag: parts[0]!,
        abiTag: parts[1]!,
        platformTag: parts.slice(2).join("-"),
      });
    }
  }

  // Derive implementation from the first python tag (e.g. "cp" from "cp311")
  const firstPythonTag = tags[0]?.pythonTag ?? "";
  const pythonImplementation = firstPythonTag.replace(/\d+$/, "");

  // Collect unique python version numbers (e.g. "311" from "cp311")
  const pythonVersions = [
    ...new Set(
      tags
        .map((t) => t.pythonTag.replace(/^[a-z]+/i, ""))
        .filter((v) => v.length > 0)
    ),
  ];

  // Collect unique platform tags
  const platforms = [...new Set(tags.map((t) => t.platformTag))];

  return {
    wheelVersion,
    generator,
    rootIsPurelib,
    buildTag,
    tags,
    pythonImplementation,
    pythonVersions,
    platforms,
  };
}

/**
 * Parse the METADATA file (email-header / RFC 822 format) into
 * WheelPackageMetadata.
 */
function parseMetadataFile(content: string): WheelPackageMetadata {
  const lines = content.split(/\r?\n/);
  const headers: Record<string, string[]> = {};

  let inDescription = false;

  for (const line of lines) {
    // Blank line after headers signals the start of the long description body
    if (line.trim() === "" && Object.keys(headers).length > 0) {
      inDescription = true;
      continue;
    }
    if (inDescription) continue;

    const colonIdx = line.indexOf(":");
    if (colonIdx < 0) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    if (!headers[key]) headers[key] = [];
    headers[key]!.push(value);
  }

  const get = (key: string): string => (headers[key]?.[0] ?? "");
  const getAll = (key: string): string[] => headers[key] ?? [];

  const projectUrls: Array<{ label: string; url: string }> = [];
  for (const urlEntry of getAll("project-url")) {
    const commaIdx = urlEntry.indexOf(",");
    if (commaIdx > 0) {
      projectUrls.push({
        label: urlEntry.slice(0, commaIdx).trim(),
        url: urlEntry.slice(commaIdx + 1).trim(),
      });
    }
  }

  return {
    metadataVersion: get("metadata-version"),
    name: get("name"),
    version: get("version"),
    summary: get("summary"),
    requiresDist: getAll("requires-dist"),
    providesExtra: getAll("provides-extra"),
    classifiers: getAll("classifier"),
    homePage: get("home-page"),
    author: get("author") || get("author-email"),
    license: get("license"),
    projectUrls,
  };
}

/**
 * Walk a directory tree and collect all native extension file paths.
 * Returns absolute paths.
 */
async function walkForNativeExtensions(root: string): Promise<string[]> {
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
        if (NATIVE_EXTENSIONS.has(ext)) {
          found.push(full);
        }
      }
    }
  }

  await walk(root);
  return found;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Locate the `.dist-info` directory inside an extracted wheel tree.
 *
 * Wheels contain exactly one `.dist-info` directory named
 * `{distribution}-{version}.dist-info`.  Returns the directory name
 * (relative to `extractDir`) or null when not found.
 */
export async function findDistInfoDir(extractDir: string): Promise<string | null> {
  let entries;
  try {
    entries = await readdir(extractDir, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (entry.isDirectory() && entry.name.endsWith(".dist-info")) {
      return entry.name;
    }
  }
  return null;
}

/**
 * Parse all dist-info metadata files from an extracted wheel directory.
 *
 * Reads `WHEEL`, `RECORD`, and `METADATA` from the `.dist-info` directory
 * found inside `extractDir`.  Native extension binaries are identified from
 * both the RECORD file entries and a filesystem walk of `extractDir`.
 *
 * All parse errors are handled gracefully: missing or malformed files result
 * in null fields on the returned `WheelDistInfo`, never thrown exceptions.
 *
 * @param extractDir  Absolute path to the directory containing the extracted
 *                    wheel archive contents.
 * @returns           Parsed dist-info metadata, or a minimal WheelDistInfo
 *                    when no .dist-info directory could be located.
 */
export async function parseWheelDistInfo(extractDir: string): Promise<WheelDistInfo> {
  const distInfoDirName = await findDistInfoDir(extractDir);

  if (!distInfoDirName) {
    return {
      distInfoDir: "",
      wheelFile: null,
      packageMetadata: null,
      recordEntries: [],
      embeddedBinaries: [],
    };
  }

  const distInfoPath = path.join(extractDir, distInfoDirName);

  // Parse WHEEL file
  let wheelFile: WheelFileMetadata | null = null;
  try {
    const content = await readFile(path.join(distInfoPath, "WHEEL"), "utf-8");
    wheelFile = parseWheelFile(content);
  } catch {
    // WHEEL file missing or unreadable — non-fatal
  }

  // Parse METADATA file
  let packageMetadata: WheelPackageMetadata | null = null;
  try {
    const content = await readFile(path.join(distInfoPath, "METADATA"), "utf-8");
    packageMetadata = parseMetadataFile(content);
  } catch {
    // METADATA file missing or unreadable — non-fatal
  }

  // Parse RECORD file
  const recordEntries: WheelRecordEntry[] = [];
  try {
    const content = await readFile(path.join(distInfoPath, "RECORD"), "utf-8");
    for (const line of content.split(/\r?\n/)) {
      const entry = parseRecordLine(line);
      if (entry) recordEntries.push(entry);
    }
  } catch {
    // RECORD file missing or unreadable — non-fatal
  }

  // Build a digest lookup from RECORD for binary enrichment
  const recordDigestByPath = new Map<string, { digest: string; algorithm: string; size: number }>();
  for (const entry of recordEntries) {
    recordDigestByPath.set(entry.filePath, {
      digest: entry.digest,
      algorithm: entry.algorithm,
      size: entry.size,
    });
  }

  // Identify embedded native binaries from RECORD first
  const binaryPaths = new Set<string>();
  const embeddedBinaries: EmbeddedBinary[] = [];

  for (const entry of recordEntries) {
    const ext = path.extname(entry.filePath).toLowerCase();
    if (NATIVE_EXTENSIONS.has(ext)) {
      const relativePath = entry.filePath.replace(/\\/g, "/");
      if (!binaryPaths.has(relativePath)) {
        binaryPaths.add(relativePath);
        const rec = recordDigestByPath.get(entry.filePath);
        embeddedBinaries.push({
          relativePath,
          filename: path.basename(relativePath),
          extension: ext as ".so" | ".pyd" | ".dylib",
          recordedDigest: rec?.digest ?? "",
          recordedSize: rec?.size ?? -1,
        });
      }
    }
  }

  // Also walk the filesystem to catch binaries not listed in RECORD
  try {
    const fsPaths = await walkForNativeExtensions(extractDir);
    for (const absPath of fsPaths) {
      const relativePath = path.relative(extractDir, absPath).replace(/\\/g, "/");
      if (!binaryPaths.has(relativePath)) {
        binaryPaths.add(relativePath);
        const ext = path.extname(relativePath).toLowerCase();
        const rec = recordDigestByPath.get(relativePath);
        embeddedBinaries.push({
          relativePath,
          filename: path.basename(relativePath),
          extension: ext as ".so" | ".pyd" | ".dylib",
          recordedDigest: rec?.digest ?? "",
          recordedSize: rec?.size ?? -1,
        });
      }
    }
  } catch {
    // Filesystem walk failure is non-fatal
  }

  return {
    distInfoDir: distInfoDirName,
    wheelFile,
    packageMetadata,
    recordEntries,
    embeddedBinaries,
  };
}

/**
 * Extract the package name portion from a `Requires-Dist` specifier.
 *
 * PEP 508 format: `name [extras] (version_spec) ; env_marker`
 * Version specifiers can use `>=`, `<=`, `==`, `!=`, `~=`, `>`, `<`, `,`.
 * This strips everything after the first space, bracket, parenthesis,
 * semicolon, or version comparator character.
 */
export function extractRequiresDistName(specifier: string): string {
  return specifier
    .split(/[\s\[\(;>=<!~,]/)[0]!
    .trim()
    .toLowerCase()
    .replace(/_/g, "-");
}

/**
 * Convenience: return all `Requires-Dist` package names (normalised)
 * from parsed wheel METADATA.
 */
export function listDependencyNames(metadata: WheelPackageMetadata): string[] {
  return metadata.requiresDist.map(extractRequiresDistName);
}
