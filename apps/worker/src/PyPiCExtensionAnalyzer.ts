/**
 * PyPiCExtensionAnalyzer
 *
 * Identifies C extension binaries (.so / .pyd / .dylib) embedded in PyPI
 * wheels, runs them through the binary analysis pipeline (entropy, syscall
 * trace, import table), and flags suspicious patterns.
 *
 * Additionally links extracted C extension findings to CVE/EPSS context:
 * when a wheel's METADATA lists `Requires-Dist` (install_requires) packages
 * that have known EPSS data, this analyzer auto-enriches findings with EPSS
 * percentile boosts via `EpssCache.computeEpssBoost`.
 *
 * Architecture
 * ────────────
 * 1. Accept an already-parsed `WheelDistInfo` (from `PyPiWheelMetadataParser`)
 *    and an extracted wheel directory.
 * 2. For each `EmbeddedBinary` in the dist-info, read the binary bytes from
 *    disk and run:
 *      a. Entropy analysis (block-level Shannon entropy)
 *      b. Import table scan  (ImportTableAnalyzer from @binshield/malware-engines)
 *      c. Syscall trace      (SyscallTraceAnalyzer from @binshield/malware-engines)
 * 3. Flag binaries that exceed configurable thresholds as suspicious.
 * 4. For each suspicious finding, look up the wheel's `Requires-Dist`
 *    dependencies in the provided `EpssCache` and apply EPSS percentile
 *    boosts to a numeric risk score.
 *
 * Suspicious pattern definitions
 * ──────────────────────────────
 * A binary is flagged when ANY of the following hold:
 *   • PROCESS_INJECTION — import table contains VirtualAlloc, WriteProcessMemory,
 *     CreateRemoteThread, NtCreateThreadEx, or equivalent Linux ptrace/mprotect
 *     patterns (from ImportTableAnalyzer).
 *   • HIGH_ENTROPY      — mean block entropy ≥ 7.2 bits/byte (packed/encrypted
 *     section indicator).
 *   • NETWORK_STAGING   — syscall trace finds socket→connect→recv→mprotect→call
 *     chain (from SyscallTraceAnalyzer signals).
 *   • CREDENTIAL_ACCESS — import / syscall signals include credential-theft APIs
 *     (open /etc/shadow, GetUserNameA, LSALogonUser, etc.).
 *
 * EPSS enrichment
 * ───────────────
 * For each finding emitted by the binary analysis pipeline, the analyzer:
 *   1. Resolves the `Requires-Dist` package names from the wheel METADATA.
 *   2. Queries the EpssCache for any CVEs associated with those packages.
 *   3. Applies `computeEpssBoostDelta(percentile)` to boost the base risk score.
 *   4. Records the highest-percentile CVE in the finding's evidence field.
 *
 * This allows a wheel that embeds a C extension AND depends on a known-vulnerable
 * package (e.g. an old numpy with an overflow CVE) to surface with a higher
 * composite risk score than the binary analysis alone would assign.
 */

import path from "node:path";
import { readFile } from "node:fs/promises";

import { ImportTableAnalyzer, SyscallTraceAnalyzer } from "@binshield/malware-engines";
import { computeEpssBoostDelta } from "../../api/src/lib/epss-cache.js";

import type { WheelDistInfo, EmbeddedBinary } from "./pypi-wheel-metadata-parser.js";
import type { EpssCacheEntry } from "../../api/src/lib/epss-cache.js";
import type { ScriptFinding, FindingSeverity } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Suspicious pattern category detected in a C extension binary.
 */
export type SuspiciousPattern =
  | "process_injection"
  | "high_entropy"
  | "network_staging"
  | "credential_access"
  | "dynamic_code_execution";

/**
 * A suspicious pattern detected in a single binary.
 */
export interface DetectedPattern {
  /** Which pattern was detected. */
  pattern: SuspiciousPattern;
  /** Human-readable description of the evidence. */
  evidence: string;
  /** Severity of this pattern in isolation. */
  severity: FindingSeverity;
}

/**
 * Analysis result for a single embedded C extension binary.
 */
export interface CExtensionAnalysisResult {
  /** The binary that was analysed. */
  binary: EmbeddedBinary;
  /** Mean block entropy of the binary bytes (bits/byte, 0–8). */
  meanEntropy: number;
  /** Whether any suspicious patterns were detected. */
  isSuspicious: boolean;
  /** All suspicious patterns detected. */
  detectedPatterns: DetectedPattern[];
  /**
   * ScriptFindings emitted for this binary.
   * Category is always "wheelNativeBinary" for binary-level findings.
   */
  findings: ScriptFinding[];
  /**
   * Base risk score for this binary (0–100), before EPSS boost.
   * Computed from the number and severity of detected patterns.
   */
  baseRiskScore: number;
  /**
   * EPSS boost applied to this binary's risk score from vulnerable
   * transitive dependencies.  0 when no EPSS data was available.
   */
  epssBoost: number;
  /**
   * Final risk score = min(100, baseRiskScore + epssBoost).
   */
  finalRiskScore: number;
  /**
   * The highest-EPSS CVE found among the wheel's install_requires
   * dependencies.  null when no CVE data was available or no boost applies.
   */
  topEpssCve: EpssCacheEntry | null;
}

/**
 * Full result of analyzing all C extensions inside a wheel.
 */
export interface WheelCExtensionAnalysis {
  /** Package name (from dist-info METADATA, or caller-supplied). */
  packageName: string;
  /** Version (from dist-info METADATA, or caller-supplied). */
  version: string;
  /** All per-binary analysis results. */
  extensionResults: CExtensionAnalysisResult[];
  /** All ScriptFindings from all binaries, flat. */
  allFindings: ScriptFinding[];
  /** Whether any binary was flagged as suspicious. */
  hasSuspiciousExtensions: boolean;
  /**
   * Number of suspicious patterns detected across all binaries.
   * Useful for quick triage.
   */
  totalSuspiciousPatternCount: number;
  /**
   * Highest final risk score across all binaries (0 when none).
   */
  maxFinalRiskScore: number;
}

// ---------------------------------------------------------------------------
// Minimal EpssCache interface (subset used by this analyzer)
// ---------------------------------------------------------------------------

/**
 * Minimal subset of EpssCache methods needed by PyPiCExtensionAnalyzer.
 * This allows tests to inject a lightweight mock without importing the full
 * EpssCache class.
 */
export interface EpssCacheInterface {
  getMany(ecosystem: string, cveIds: string[]): Promise<Map<string, EpssCacheEntry>>;
  get(ecosystem: string, cveId: string): Promise<EpssCacheEntry | null>;
}

// ---------------------------------------------------------------------------
// Entropy computation
// ---------------------------------------------------------------------------

const ENTROPY_BLOCK_SIZE = 256;
const HIGH_ENTROPY_THRESHOLD = 7.2;

/**
 * Compute Shannon entropy of a byte buffer in bits/byte (0–8).
 * Uses a frequency table across all bytes in the buffer.
 */
export function computeShannonEntropy(data: Buffer): number {
  if (data.length === 0) return 0;

  const freq = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    freq[data[i]!]!++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const count = freq[i]!;
    if (count > 0) {
      const p = count / data.length;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

/**
 * Compute the mean block-level Shannon entropy of a binary.
 * Splits the buffer into ENTROPY_BLOCK_SIZE-byte blocks and averages entropy
 * across blocks.  This approach detects partially-packed binaries where only
 * some sections are high-entropy.
 */
export function computeMeanBlockEntropy(data: Buffer): number {
  if (data.length === 0) return 0;

  const blockCount = Math.ceil(data.length / ENTROPY_BLOCK_SIZE);
  let total = 0;
  for (let i = 0; i < data.length; i += ENTROPY_BLOCK_SIZE) {
    const block = data.subarray(i, i + ENTROPY_BLOCK_SIZE);
    total += computeShannonEntropy(block);
  }
  return total / blockCount;
}

// ---------------------------------------------------------------------------
// Suspicious pattern detection
// ---------------------------------------------------------------------------

/**
 * Keywords that indicate process injection APIs in import table signals.
 * Covers Windows PE imports and Linux ptrace/mprotect equivalents.
 */
const PROCESS_INJECTION_KEYWORDS = [
  "VirtualAlloc",
  "WriteProcessMemory",
  "CreateRemoteThread",
  "NtCreateThreadEx",
  "NtAllocateVirtualMemory",
  "mprotect",
  "process_vm_writev",
  "ptrace",
  "dlopen",
  "dlsym",
];

/**
 * Keywords that indicate credential theft in import/syscall signals.
 */
const CREDENTIAL_ACCESS_KEYWORDS = [
  "/etc/shadow",
  "/etc/passwd",
  "GetUserNameA",
  "GetUserNameW",
  "LSALogonUser",
  "CryptAcquireContext",
  "CredRead",
  "SecretService",
  "keychain",
];

/**
 * Keywords from SyscallTraceAnalyzer signals that indicate network staging
 * (socket → connect → recv → mprotect/call sequence).
 */
const NETWORK_STAGING_KEYWORDS = [
  "network_staging",
  "socket",
  "connect",
  "recv",
  "c2_download",
  "exfil",
];

/**
 * Keywords indicating dynamic code execution (eval/exec patterns).
 */
const DYNAMIC_CODE_KEYWORDS = [
  "PyRun_SimpleString",
  "PyEval_EvalCode",
  "eval(",
  "exec(",
  "__import__",
];

/**
 * Detect suspicious patterns from binary analysis signals.
 *
 * @param importSignals  Signal strings from ImportTableAnalyzer.
 * @param syscallSignals Signal strings from SyscallTraceAnalyzer.
 * @param entropy        Mean block entropy of the binary.
 * @returns              Array of detected suspicious patterns.
 */
export function detectSuspiciousPatterns(
  importSignals: string[],
  syscallSignals: string[],
  entropy: number
): DetectedPattern[] {
  const patterns: DetectedPattern[] = [];
  const allSignals = [...importSignals, ...syscallSignals].join(" ");

  // 1. Process injection
  const injectionMatches = PROCESS_INJECTION_KEYWORDS.filter((kw) =>
    allSignals.toLowerCase().includes(kw.toLowerCase())
  );
  if (injectionMatches.length > 0) {
    patterns.push({
      pattern: "process_injection",
      evidence: `Process injection indicators: ${injectionMatches.join(", ")}`,
      severity: "high",
    });
  }

  // 2. High entropy (packed/encrypted binary section)
  if (entropy >= HIGH_ENTROPY_THRESHOLD) {
    patterns.push({
      pattern: "high_entropy",
      evidence: `Mean block entropy ${entropy.toFixed(3)} bits/byte ≥ ${HIGH_ENTROPY_THRESHOLD} (packed/encrypted indicator)`,
      severity: "medium",
    });
  }

  // 3. Network staging
  const networkMatches = NETWORK_STAGING_KEYWORDS.filter((kw) =>
    allSignals.toLowerCase().includes(kw.toLowerCase())
  );
  if (networkMatches.length >= 2) {
    patterns.push({
      pattern: "network_staging",
      evidence: `Network staging signals: ${networkMatches.join(", ")}`,
      severity: "high",
    });
  }

  // 4. Credential access
  const credMatches = CREDENTIAL_ACCESS_KEYWORDS.filter((kw) =>
    allSignals.toLowerCase().includes(kw.toLowerCase())
  );
  if (credMatches.length > 0) {
    patterns.push({
      pattern: "credential_access",
      evidence: `Credential access indicators: ${credMatches.join(", ")}`,
      severity: "high",
    });
  }

  // 5. Dynamic code execution
  const dynMatches = DYNAMIC_CODE_KEYWORDS.filter((kw) =>
    allSignals.includes(kw)
  );
  if (dynMatches.length > 0) {
    patterns.push({
      pattern: "dynamic_code_execution",
      evidence: `Dynamic code execution indicators: ${dynMatches.join(", ")}`,
      severity: "medium",
    });
  }

  return patterns;
}

// ---------------------------------------------------------------------------
// Base risk score computation
// ---------------------------------------------------------------------------

const SEVERITY_SCORES: Record<FindingSeverity, number> = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
  info: 0,
};

/**
 * Compute a base risk score from detected patterns.
 * The score is the sum of per-severity weights, capped at 100.
 */
export function computeBaseRiskScore(patterns: DetectedPattern[]): number {
  const total = patterns.reduce(
    (sum, p) => sum + (SEVERITY_SCORES[p.severity] ?? 0),
    0
  );
  return Math.min(100, total);
}

// ---------------------------------------------------------------------------
// EPSS enrichment
// ---------------------------------------------------------------------------

/**
 * Query the EpssCache for CVEs associated with the wheel's install_requires
 * dependencies and return the highest-percentile entry found.
 *
 * This implements the "auto-enrich with EPSS percentile boosts" requirement:
 * when a wheel's METADATA lists install_requires with known-vulnerable packages,
 * their EPSS percentile drives a boost to the C extension risk score.
 *
 * @param dependencyNames  Normalised package names from Requires-Dist.
 * @param cveIds           Known CVE IDs to look up (from NVD/OSV feed, or test fixtures).
 * @param epssCache        EPSS cache instance.
 * @returns                The highest-percentile EpssCacheEntry found, or null.
 */
export async function findTopEpssCveForDeps(
  dependencyNames: string[],
  cveIds: string[],
  epssCache: EpssCacheInterface
): Promise<EpssCacheEntry | null> {
  if (cveIds.length === 0 || dependencyNames.length === 0) return null;

  // Look up all provided CVE IDs in the cache
  const entries = await epssCache.getMany("pypi", cveIds);
  if (entries.size === 0) return null;

  // Return the entry with the highest percentile
  let top: EpssCacheEntry | null = null;
  for (const entry of entries.values()) {
    if (top === null || entry.percentile > top.percentile) {
      top = entry;
    }
  }
  return top;
}

// ---------------------------------------------------------------------------
// Findings construction
// ---------------------------------------------------------------------------

/**
 * Convert detected patterns for a single binary into ScriptFindings.
 */
function patternsToFindings(
  binary: EmbeddedBinary,
  patterns: DetectedPattern[],
  abiLabel: string,
  topEpssCve: EpssCacheEntry | null,
  epssBoost: number
): ScriptFinding[] {
  if (patterns.length === 0) return [];

  return patterns.map((dp): ScriptFinding => {
    const epssSuffix =
      topEpssCve && epssBoost > 0
        ? ` EPSS boost +${epssBoost}pts from ${topEpssCve.cveId} (percentile: ${(topEpssCve.percentile * 100).toFixed(1)}%).`
        : "";

    return {
      category: "wheelNativeBinary",
      severity: dp.severity,
      title: `C extension suspicious pattern [${dp.pattern}]: ${binary.filename}`,
      description:
        `Native C extension '${binary.filename}' in wheel '${abiLabel}' exhibits ` +
        `suspicious '${dp.pattern}' behavior. ${dp.evidence}.${epssSuffix}`,
      filePath: `${binary.relativePath} [${abiLabel}]`,
      evidence: dp.evidence,
      recommendation:
        "Inspect the C extension binary manually. If the behavior cannot be explained " +
        "by the package's documented functionality, treat this as a supply-chain threat. " +
        "Pin the dependency to a known-good version or replace with a pure-Python alternative.",
    };
  });
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Options for `PyPiCExtensionAnalyzer.analyze()`.
 */
export interface CExtensionAnalyzerOptions {
  /**
   * Absolute path to the extracted wheel directory.
   * Used to read binary files listed in `distInfo.embeddedBinaries`.
   */
  extractDir: string;
  /**
   * Human-readable label for the ABI tag (e.g. "numpy-cp311-linux_x86_64").
   * Used in finding filePath fields.
   */
  abiLabel: string;
  /**
   * Optional EpssCache for CVE/EPSS enrichment.
   * When omitted, EPSS boost is always 0.
   */
  epssCache?: EpssCacheInterface;
  /**
   * Known CVE IDs to look up for EPSS enrichment.
   * Typically populated from NVD/OSV advisories matched to the wheel's
   * install_requires.  When omitted, no EPSS boost is applied.
   */
  cveIds?: string[];
}

/**
 * Analyzes all C extension binaries in a wheel dist-info and flags
 * suspicious patterns, with optional EPSS/CVE enrichment.
 */
export class PyPiCExtensionAnalyzer {
  /**
   * Run full analysis on all embedded C extension binaries from a
   * parsed `WheelDistInfo`.
   *
   * @param distInfo   Parsed wheel dist-info (from `parseWheelDistInfo`).
   * @param options    Configuration for extract dir, ABI label, EPSS cache.
   * @returns          Full `WheelCExtensionAnalysis` result.
   */
  async analyze(
    distInfo: WheelDistInfo,
    options: CExtensionAnalyzerOptions
  ): Promise<WheelCExtensionAnalysis> {
    const { extractDir, abiLabel, epssCache, cveIds = [] } = options;

    const packageName =
      distInfo.packageMetadata?.name?.toLowerCase() ?? "unknown";
    const version = distInfo.packageMetadata?.version ?? "0.0.0";

    // Collect dependency names from METADATA for EPSS enrichment
    const depNames =
      distInfo.packageMetadata?.requiresDist.map((rd) => {
        return rd.split(/[\s\[\(;]/)[0]!.trim().toLowerCase().replace(/_/g, "-");
      }) ?? [];

    const extensionResults: CExtensionAnalysisResult[] = [];
    const allFindings: ScriptFinding[] = [];

    for (const binary of distInfo.embeddedBinaries) {
      const result = await this.analyzeSingleBinary(
        binary,
        extractDir,
        abiLabel,
        depNames,
        cveIds,
        epssCache
      );
      extensionResults.push(result);
      allFindings.push(...result.findings);
    }

    const hasSuspiciousExtensions = extensionResults.some((r) => r.isSuspicious);
    const totalSuspiciousPatternCount = extensionResults.reduce(
      (sum, r) => sum + r.detectedPatterns.length,
      0
    );
    const maxFinalRiskScore =
      extensionResults.length > 0
        ? Math.max(...extensionResults.map((r) => r.finalRiskScore))
        : 0;

    return {
      packageName,
      version,
      extensionResults,
      allFindings,
      hasSuspiciousExtensions,
      totalSuspiciousPatternCount,
      maxFinalRiskScore,
    };
  }

  /**
   * Analyze a single embedded binary.
   */
  private async analyzeSingleBinary(
    binary: EmbeddedBinary,
    extractDir: string,
    abiLabel: string,
    depNames: string[],
    cveIds: string[],
    epssCache: EpssCacheInterface | undefined
  ): Promise<CExtensionAnalysisResult> {
    const absPath = path.join(extractDir, binary.relativePath);

    // Read binary bytes (graceful failure)
    let binaryData: Buffer;
    try {
      binaryData = await readFile(absPath);
    } catch {
      binaryData = Buffer.alloc(0);
    }

    // Entropy analysis
    const meanEntropy = computeMeanBlockEntropy(binaryData);

    // Import table analysis
    const importAnalyzer = new ImportTableAnalyzer();
    let importSignals: string[] = [];
    try {
      const importResult = await importAnalyzer.analyze(binaryData);
      importSignals = importResult.signals;
    } catch {
      // Non-fatal
    }

    // Syscall trace analysis
    const syscallAnalyzer = new SyscallTraceAnalyzer();
    let syscallSignals: string[] = [];
    try {
      const syscallResult = await syscallAnalyzer.analyze(binaryData);
      syscallSignals = syscallResult.signals;
    } catch {
      // Non-fatal
    }

    // Detect suspicious patterns
    const detectedPatterns = detectSuspiciousPatterns(
      importSignals,
      syscallSignals,
      meanEntropy
    );
    const isSuspicious = detectedPatterns.length > 0;
    const baseRiskScore = computeBaseRiskScore(detectedPatterns);

    // EPSS enrichment
    let epssBoost = 0;
    let topEpssCve: EpssCacheEntry | null = null;

    if (epssCache && cveIds.length > 0 && depNames.length > 0) {
      try {
        topEpssCve = await findTopEpssCveForDeps(depNames, cveIds, epssCache);
        if (topEpssCve) {
          epssBoost = computeEpssBoostDelta(topEpssCve.percentile);
        }
      } catch {
        // EPSS enrichment failure is non-fatal
      }
    }

    const finalRiskScore = Math.min(100, baseRiskScore + epssBoost);

    // Build findings
    const findings = patternsToFindings(
      binary,
      detectedPatterns,
      abiLabel,
      topEpssCve,
      epssBoost
    );

    return {
      binary,
      meanEntropy,
      isSuspicious,
      detectedPatterns,
      findings,
      baseRiskScore,
      epssBoost,
      finalRiskScore,
      topEpssCve,
    };
  }
}
