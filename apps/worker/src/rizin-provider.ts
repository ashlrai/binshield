/**
 * Rizin Decompiler Provider
 *
 * Uses rizin (radare2 fork) for fast binary analysis. Lighter and faster
 * than Ghidra, used as a quick triage step. If rizin flags suspicious
 * indicators, the binary is escalated to Ghidra for full decompilation.
 *
 * Runs rizin in a Docker container with no network access.
 */

import { execFile } from "node:child_process";
import { writeFile, mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import type { DecompiledArtifact, FingerprintedArtifact, WorkerScanRequest } from "./types";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RizinAnalysisResult {
  imports: string[];
  exports: string[];
  strings: string[];
  sections: Array<{ name: string; size: number; entropy: number }>;
  functions: Array<{ name: string; offset: number; size: number }>;
  functionCount: number;
  isSuspicious: boolean;
  suspicionReasons: string[];
  entropy: number;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export class RizinDecompilerProvider {
  readonly name = "rizin-docker";
  private dockerAvailable: boolean | null = null;
  private readonly dockerImage: string;
  private readonly timeout: number;

  constructor(options?: { dockerImage?: string; timeout?: number }) {
    this.dockerImage = options?.dockerImage ?? "rizinorg/rizin:latest";
    this.timeout = options?.timeout ?? 120000; // 2 minutes
  }

  async isAvailable(): Promise<boolean> {
    if (this.dockerAvailable !== null) return this.dockerAvailable;
    try {
      await execFileAsync("docker", ["info"], { timeout: 5000 });
      this.dockerAvailable = true;
    } catch {
      this.dockerAvailable = false;
    }
    return this.dockerAvailable;
  }

  /**
   * Analyze a binary with rizin, returning a decompiled artifact.
   * Falls back to a stub result if Docker is unavailable so the scan
   * pipeline degrades gracefully rather than breaking.
   */
  async decompile(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<DecompiledArtifact> {
    const available = await this.isAvailable();
    if (!available) {
      return buildDockerUnavailableStub(input.artifact);
    }

    const analysis = await this.runRizin(input.artifact);

    return {
      pseudoSource: this.buildPseudoSource(analysis, input.artifact),
      imports: analysis.imports,
      strings: analysis.strings,
      functionCount: analysis.functionCount,
      callTargets: analysis.exports.slice(0, 50),
      confidence: 0.65,
    };
  }

  /**
   * Quick triage: determine if a binary warrants full Ghidra decompilation.
   */
  async triage(artifact: FingerprintedArtifact): Promise<{
    shouldEscalate: boolean;
    reasons: string[];
    analysis: RizinAnalysisResult;
  }> {
    const available = await this.isAvailable();
    if (!available) {
      return { shouldEscalate: true, reasons: ["rizin unavailable"], analysis: emptyAnalysis() };
    }

    const analysis = await this.runRizin(artifact);
    return {
      shouldEscalate: analysis.isSuspicious,
      reasons: analysis.suspicionReasons,
      analysis,
    };
  }

  private async runRizin(artifact: FingerprintedArtifact): Promise<RizinAnalysisResult> {
    const tmpDir = await mkdtemp(path.join(tmpdir(), "binshield-rizin-"));
    const binaryPath = path.join(tmpDir, "binary");
    const outputPath = path.join(tmpDir, "output.json");

    try {
      await writeFile(binaryPath, artifact.bytes);

      // rizin script that extracts analysis data as JSON
      const script = [
        "aaa",           // Analyze all
        "aflj",          // List functions as JSON -> functions
        "iij",           // List imports as JSON -> imports
        "iEj",           // List exports as JSON -> exports
        "izj",           // List strings as JSON -> strings
        "iSj",           // List sections as JSON -> sections
      ].join(";");

      // Run each command separately and collect output
      const commands = [
        { cmd: "aflj", key: "functions" },
        { cmd: "iij", key: "imports" },
        { cmd: "iEj", key: "exports" },
        { cmd: "izj", key: "strings" },
        { cmd: "iSj", key: "sections" },
      ];

      const results: Record<string, unknown[]> = {};

      for (const { cmd, key } of commands) {
        try {
          const { stdout } = await execFileAsync("docker", [
            "run", "--rm", "--network", "none",
            "--memory", "1g", "--cpus", "1.0",
            "-v", `${tmpDir}:/work:ro`,
            this.dockerImage,
            "rizin", "-q", "-c", `aaa;${cmd}`, "/work/binary",
          ], { timeout: this.timeout, maxBuffer: 10 * 1024 * 1024 });

          try {
            results[key] = JSON.parse(stdout.trim());
          } catch {
            results[key] = [];
          }
        } catch {
          results[key] = [];
        }
      }

      return this.parseResults(results);
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  }

  private parseResults(raw: Record<string, unknown[]>): RizinAnalysisResult {
    const functions = (raw.functions ?? []) as Array<{ name: string; offset: number; size: number }>;
    const imports = (raw.imports ?? []) as Array<{ name?: string; libname?: string }>;
    const exports = (raw.exports ?? []) as Array<{ name?: string }>;
    const strings = (raw.strings ?? []) as Array<{ string?: string; vaddr?: number }>;
    const sections = (raw.sections ?? []) as Array<{ name?: string; size?: number; entropy?: number }>;

    const importNames = imports
      .map((i) => i.name ?? i.libname ?? "")
      .filter(Boolean);
    const exportNames = exports
      .map((e) => e.name ?? "")
      .filter(Boolean);
    const stringValues = strings
      .map((s) => s.string ?? "")
      .filter(Boolean);
    const sectionData = sections.map((s) => ({
      name: s.name ?? "",
      size: s.size ?? 0,
      entropy: s.entropy ?? 0,
    }));

    // Calculate overall entropy
    const maxEntropy = sectionData.reduce((max, s) => Math.max(max, s.entropy), 0);

    // Determine suspicion
    const suspicionReasons: string[] = [];

    // High entropy sections
    if (maxEntropy > 7.5) {
      suspicionReasons.push(`High entropy section detected (${maxEntropy.toFixed(2)})`);
    }

    // Network-related imports
    const networkImports = importNames.filter((i) =>
      /socket|connect|send|recv|http|curl|dns|net/i.test(i)
    );
    if (networkImports.length > 0) {
      suspicionReasons.push(`Network imports: ${networkImports.slice(0, 5).join(", ")}`);
    }

    // Process manipulation imports
    const processImports = importNames.filter((i) =>
      /exec|spawn|fork|system|popen|CreateProcess|CreateRemoteThread/i.test(i)
    );
    if (processImports.length > 0) {
      suspicionReasons.push(`Process manipulation imports: ${processImports.slice(0, 5).join(", ")}`);
    }

    // Suspicious strings
    const suspiciousStrings = stringValues.filter((s) =>
      /password|secret|token|credential|\.ssh|\.aws|exfil|backdoor/i.test(s)
    );
    if (suspiciousStrings.length > 3) {
      suspicionReasons.push(`${suspiciousStrings.length} suspicious strings found`);
    }

    // Anti-analysis techniques
    const antiAnalysis = importNames.filter((i) =>
      /IsDebuggerPresent|ptrace|anti_debug|CheckRemoteDebugger/i.test(i)
    );
    if (antiAnalysis.length > 0) {
      suspicionReasons.push(`Anti-analysis techniques detected`);
    }

    return {
      imports: importNames,
      exports: exportNames,
      strings: stringValues.slice(0, 200),
      sections: sectionData,
      functions: functions.map((f) => ({ name: f.name, offset: f.offset, size: f.size })),
      functionCount: functions.length,
      isSuspicious: suspicionReasons.length > 0,
      suspicionReasons,
      entropy: maxEntropy,
    };
  }

  private buildPseudoSource(analysis: RizinAnalysisResult, artifact: FingerprintedArtifact): string {
    const lines: string[] = [
      `// Rizin analysis of ${artifact.filename}`,
      `// Format: ${artifact.format}, Architecture: ${artifact.architecture}`,
      `// Functions: ${analysis.functionCount}, Imports: ${analysis.imports.length}`,
      `// Entropy: ${analysis.entropy.toFixed(2)}`,
      "",
    ];

    if (analysis.suspicionReasons.length > 0) {
      lines.push("// SUSPICIOUS INDICATORS:");
      for (const reason of analysis.suspicionReasons) {
        lines.push(`//   - ${reason}`);
      }
      lines.push("");
    }

    // List imports
    if (analysis.imports.length > 0) {
      lines.push("// Imports:");
      for (const imp of analysis.imports.slice(0, 30)) {
        lines.push(`//   ${imp}`);
      }
      if (analysis.imports.length > 30) {
        lines.push(`//   ... and ${analysis.imports.length - 30} more`);
      }
      lines.push("");
    }

    // List functions
    if (analysis.functions.length > 0) {
      lines.push("// Functions:");
      for (const fn of analysis.functions.slice(0, 20)) {
        lines.push(`void ${fn.name}() { /* offset: 0x${fn.offset.toString(16)}, size: ${fn.size} */ }`);
      }
      if (analysis.functions.length > 20) {
        lines.push(`// ... and ${analysis.functions.length - 20} more functions`);
      }
    }

    return lines.join("\n");
  }
}

/**
 * Build a stub DecompiledArtifact when Docker is unavailable.
 * Mirrors the heuristic used by LocalHeuristicDecompilerProvider in providers.ts:
 * infer imports from filename/magic bytes, extract strings from the artifact.
 */
function buildDockerUnavailableStub(artifact: FingerprintedArtifact): DecompiledArtifact {
  const haystack = [artifact.filename, ...artifact.strings, ...artifact.interestingStrings]
    .join(" ")
    .toLowerCase();

  const imports = new Set<string>();
  if (/napi|node_module_register|node_api|uv_/.test(haystack)) {
    imports.add("napi_register_module_v1");
    imports.add("uv_queue_work");
  }
  if (/(http|https|curl|socket|connect|dns)/.test(haystack)) {
    imports.add("connect");
    imports.add("getaddrinfo");
  }
  if (/(crypto|hash|sha|bcrypt|argon2|evp_)/.test(haystack)) {
    imports.add("EVP_DigestInit_ex");
    imports.add("EVP_DigestUpdate");
  }
  if (/(fs|open|read|write|unlink|tmp|cache)/.test(haystack)) {
    imports.add("open");
    imports.add("read");
    imports.add("write");
  }
  if (artifact.format === "WASM") {
    imports.add("wasm32_runtime_call");
  }

  const importList = Array.from(imports);
  const hex = Buffer.from(artifact.bytes.slice(0, 48)).toString("hex");
  const stringWeight = artifact.strings.length + artifact.interestingStrings.length;
  const sizeWeight = Math.max(1, Math.round(artifact.fileSize / 4096));
  const functionCount = Math.max(1, Math.min(180, stringWeight + importList.length + sizeWeight));

  const pseudoSource = [
    `// Rizin stub (Docker unavailable) for ${artifact.relativePath}`,
    `// sha256=${artifact.sha256}`,
    `// kind=${artifact.kind} format=${artifact.format} arch=${artifact.architecture}`,
    `// head=${hex}`,
    `int binshield_entry(void) {`,
    `  return 0;`,
    `}`,
    "",
    "// extracted strings",
    ...artifact.interestingStrings.map((s) => `// ${s}`),
  ].join("\n");

  return {
    pseudoSource,
    imports: importList,
    strings: artifact.interestingStrings,
    functionCount,
    callTargets: importList,
    confidence: 0.3, // lower than live rizin (0.65) — Docker was unavailable
  };
}

function emptyAnalysis(): RizinAnalysisResult {
  return {
    imports: [],
    exports: [],
    strings: [],
    sections: [],
    functions: [],
    functionCount: 0,
    isSuspicious: false,
    suspicionReasons: [],
    entropy: 0,
  };
}
