import { emptyBehaviorSummary } from "@binshield/analysis-types";

import type {
  ClassifiedArtifact,
  ClassifierProvider,
  DecompiledArtifact,
  DecompilerProvider,
  FingerprintedArtifact,
  ScriptAnalysisInput,
  ScriptAnalyzerProvider,
  WorkerScanRequest
} from "./types";
import { collapseConfidence } from "./types";
import { AnalyzerRegistry } from "./malware-analyzer.js";
import { summarizeBinaryText } from "./fingerprint";
import { extractTokenHints as tokenHintsFromStrings } from "./fingerprint";
import { ManifestAnalyzer, mergeManifestAnalysis } from "./manifest-analyzer";

function createBasePreview(artifact: FingerprintedArtifact): string {
  const hex = Buffer.from(artifact.bytes.slice(0, 48)).toString("hex");
  return [
    `// BinShield fallback decompilation for ${artifact.relativePath}`,
    `// sha256=${artifact.sha256}`,
    `// kind=${artifact.kind} format=${artifact.format} arch=${artifact.architecture}`,
    `// head=${hex}`,
    `int binshield_entry(void) {`,
    `  return 0;`,
    `}`
  ].join("\n");
}

function buildImports(artifact: FingerprintedArtifact): string[] {
  const haystack = [artifact.filename, ...artifact.strings, ...artifact.interestingStrings].join(" ").toLowerCase();
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

  return Array.from(imports);
}

function inferFunctionCount(artifact: FingerprintedArtifact, imports: string[]): number {
  const stringWeight = artifact.strings.length + artifact.interestingStrings.length;
  const importWeight = imports.length;
  const sizeWeight = Math.max(1, Math.round(artifact.fileSize / 4096));
  return Math.max(1, Math.min(180, stringWeight + importWeight + sizeWeight));
}

function inferCallTargets(imports: string[], artifact: FingerprintedArtifact): string[] {
  const targets = new Set<string>(imports);
  const interesting = artifact.interestingStrings.filter((entry) => /[A-Za-z0-9_./-]+/.test(entry));

  for (const value of interesting) {
    if (/https?:\/\//.test(value)) {
      targets.add("network_request");
    }
    if (/spawn|exec|system/i.test(value)) {
      targets.add("process_spawn");
    }
    if (/tmp|cache|read|write|unlink|open/i.test(value)) {
      targets.add("filesystem_access");
    }
  }

  return Array.from(targets);
}

export class LocalHeuristicDecompilerProvider implements DecompilerProvider {
  readonly name = "local-heuristic";

  async decompile(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<DecompiledArtifact> {
    const imports = buildImports(input.artifact);
    const functionCount = inferFunctionCount(input.artifact, imports);
    const callTargets = inferCallTargets(imports, input.artifact);
    const textPreview = summarizeBinaryText(input.artifact.bytes);

    return {
      pseudoSource: [
        createBasePreview(input.artifact),
        "",
        "// extracted strings",
        ...input.artifact.interestingStrings.map((value) => `// ${value}`),
        "",
        "/*",
        textPreview,
        "*/"
      ].join("\n"),
      imports,
      strings: input.artifact.interestingStrings,
      functionCount,
      callTargets,
      confidence: input.artifact.kind === "unknown" ? 0.55 : 0.8
    };
  }
}

export class GhidraCommandDecompilerProvider implements DecompilerProvider {
  readonly name = "ghidra-command";

  constructor(private readonly command = process.env.BINSHIELD_GHIDRA_COMMAND ?? "") {}

  async decompile(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<DecompiledArtifact> {
    if (!this.command) {
      throw new Error("Ghidra command not configured");
    }

    throw new Error(
      `Ghidra command provider is configured (${this.command}) but the local adapter is not implemented in this workspace.`
    );
  }
}

export class HttpDecompilerProvider implements DecompilerProvider {
  readonly name = "http-decompiler";

  constructor(private readonly endpoint = process.env.BINSHIELD_DECOMPILER_URL ?? "") {}

  async decompile(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<DecompiledArtifact> {
    if (!this.endpoint) {
      throw new Error("Decompiler endpoint not configured");
    }

    const response = await fetch(this.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        packageName: input.packageRequest.packageName,
        version: input.packageRequest.version,
        artifact: {
          filename: input.artifact.filename,
          relativePath: input.artifact.relativePath,
          sha256: input.artifact.sha256,
          format: input.artifact.format,
          architecture: input.artifact.architecture,
          strings: input.artifact.interestingStrings
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Decompiler endpoint returned ${response.status}`);
    }

    const payload = (await response.json()) as Partial<DecompiledArtifact>;
    if (!payload.pseudoSource || !Array.isArray(payload.imports)) {
      throw new Error("Decompiler endpoint returned an invalid payload");
    }

    return {
      pseudoSource: payload.pseudoSource,
      imports: payload.imports,
      strings: Array.isArray(payload.strings) ? payload.strings : input.artifact.interestingStrings,
      functionCount: typeof payload.functionCount === "number" ? payload.functionCount : inferFunctionCount(input.artifact, payload.imports),
      callTargets: Array.isArray(payload.callTargets) ? payload.callTargets : payload.imports,
      confidence: typeof payload.confidence === "number" ? payload.confidence : 0.7
    };
  }
}

function buildBehaviorSummary(artifact: FingerprintedArtifact, decompiled: DecompiledArtifact) {
  const behaviors = emptyBehaviorSummary();
  const allStrings = [...artifact.interestingStrings, ...decompiled.strings, ...decompiled.callTargets, ...decompiled.imports];
  const joined = allStrings.join(" ").toLowerCase();

  const setBehavior = (key: keyof typeof behaviors, details: string[]) => {
    if (details.length > 0) {
      behaviors[key] = { detected: true, details };
    }
  };

  const networkDetails = artifact.interestingStrings.filter((value) => /https?:\/\//i.test(value) || /connect|socket|dns|curl|fetch/i.test(value));
  const filesystemDetails = artifact.interestingStrings.filter((value) => /\/tmp|\/var|cache|read|write|open|unlink|mkdir|fs_/i.test(value));
  const processDetails = artifact.interestingStrings.filter((value) => /spawn|exec|fork|system|child_process/i.test(value));
  const cryptoDetails = artifact.interestingStrings.filter((value) => /crypto|hash|sha|md5|bcrypt|argon2|evp_|aes|rsa|urandom/i.test(value));
  const obfuscationDetails = artifact.interestingStrings.filter((value) => /base64|xor|packed|obfus|eval|atob|fromcharcode/i.test(value));
  const exfiltrationDetails = artifact.interestingStrings.filter((value) => /token|secret|password|auth|cookie|telemetry|upload|exfil|beacon|env/i.test(value));

  setBehavior("network", networkDetails);
  setBehavior("filesystem", filesystemDetails);
  setBehavior("process", processDetails);
  setBehavior("crypto", cryptoDetails);
  setBehavior("obfuscation", obfuscationDetails);
  setBehavior("dataExfiltration", exfiltrationDetails.length > 0 && networkDetails.length > 0 ? exfiltrationDetails : []);

  if (!behaviors.network.detected && /fetch|request|http|socket/i.test(joined)) {
    behaviors.network = {
      detected: true,
      details: ["Heuristic network indicators present in imports or strings."]
    };
  }
  if (!behaviors.filesystem.detected && /tmp|cache|fs_|open|read|write/i.test(joined)) {
    behaviors.filesystem = {
      detected: true,
      details: ["Heuristic filesystem access indicators present in imports or strings."]
    };
  }
  if (!behaviors.process.detected && /spawn|exec|fork|system/i.test(joined)) {
    behaviors.process = {
      detected: true,
      details: ["Heuristic process-spawn indicators present in imports or strings."]
    };
  }
  if (!behaviors.crypto.detected && /crypto|hash|sha|md5|bcrypt|argon2|evp_/i.test(joined)) {
    behaviors.crypto = {
      detected: true,
      details: ["Heuristic crypto indicators present in imports or strings."]
    };
  }

  return behaviors;
}

export class LocalHeuristicClassifierProvider implements ClassifierProvider {
  readonly name = "local-heuristic";

  async classify(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
    decompiled: DecompiledArtifact;
  }): Promise<ClassifiedArtifact> {
    const behaviors = buildBehaviorSummary(input.artifact, input.decompiled);
    const findings: ClassifiedArtifact["findings"] = [];

    if (behaviors.network.detected) {
      findings.push({
        severity: "medium",
        title: "Network-capable binary",
        description: "The artifact contains network-oriented symbols or strings.",
        location: input.artifact.relativePath,
        recommendation: "Validate outbound destinations and confirm network usage is expected."
      });
    }

    if (behaviors.filesystem.detected) {
      findings.push({
        severity: "info",
        title: "Filesystem access",
        description: "The artifact touches paths, temp directories, or file APIs.",
        location: input.artifact.relativePath,
        recommendation: "Review file I/O for safe handling of paths and permissions."
      });
    }

    if (behaviors.process.detected) {
      findings.push({
        severity: "high",
        title: "Process-spawn behavior",
        description: "The artifact references child process or execution primitives.",
        location: input.artifact.relativePath,
        recommendation: "Confirm subprocess execution is required and constrained."
      });
    }

    if (behaviors.dataExfiltration.detected) {
      findings.push({
        severity: "critical",
        title: "Potential data exfiltration",
        description: "The artifact combines network indicators with secrets or telemetry-related strings.",
        location: input.artifact.relativePath,
        recommendation: "Block until the data flow is validated and documented."
      });
    }

    if (behaviors.obfuscation.detected) {
      findings.push({
        severity: "medium",
        title: "Obfuscation indicators",
        description: "The artifact contains packed or encoded string hints.",
        location: input.artifact.relativePath,
        recommendation: "Inspect the code path for hidden or dynamically loaded behavior."
      });
    }

    if (behaviors.crypto.detected) {
      findings.push({
        severity: "info",
        title: "Cryptographic operations",
        description: "The artifact references common crypto primitives.",
        location: input.artifact.relativePath,
        recommendation: "Confirm the implementation uses approved cryptographic libraries."
      });
    }

    const summaryParts = [
      input.artifact.filename,
      behaviors.network.detected ? "network-capable" : "network-silent",
      behaviors.filesystem.detected ? "filesystem-aware" : "filesystem-light",
      behaviors.process.detected ? "process-spawning" : "process-free"
    ];

    return {
      summary: `${summaryParts.join(", ")} binary with ${input.decompiled.functionCount} inferred functions.`,
      explanation: [
        `Local heuristic classifier (`,
        this.name,
        `) inferred behavior from strings, imports, and the decompiled preview.`,
        input.decompiled.pseudoSource.slice(0, 240)
      ].join(""),
      sourceMatchConfidence: collapseConfidence([
        input.artifact.kind === "unknown" ? "low" : "medium",
        input.decompiled.confidence >= 0.85 ? "high" : input.decompiled.confidence >= 0.6 ? "medium" : "low"
      ]),
      behaviors,
      findings,
      riskNotes: tokenHintsFromStrings([...input.artifact.interestingStrings, ...input.decompiled.strings])
    };
  }
}

export class HttpClassifierProvider implements ClassifierProvider {
  readonly name = "http-classifier";

  constructor(private readonly endpoint = process.env.BINSHIELD_CLASSIFIER_URL ?? "") {}

  async classify(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
    decompiled: DecompiledArtifact;
  }): Promise<ClassifiedArtifact> {
    if (!this.endpoint) {
      throw new Error("Classifier endpoint not configured");
    }

    const response = await fetch(this.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        packageName: input.packageRequest.packageName,
        version: input.packageRequest.version,
        artifact: {
          filename: input.artifact.filename,
          sha256: input.artifact.sha256,
          format: input.artifact.format,
          architecture: input.artifact.architecture,
          interestingStrings: input.artifact.interestingStrings
        },
        decompiled: {
          pseudoSource: input.decompiled.pseudoSource,
          imports: input.decompiled.imports,
          callTargets: input.decompiled.callTargets
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Classifier endpoint returned ${response.status}`);
    }

    const payload = (await response.json()) as Partial<ClassifiedArtifact>;
    if (!payload.summary || !payload.explanation || !payload.behaviors) {
      throw new Error("Classifier endpoint returned an invalid payload");
    }

    return {
      summary: payload.summary,
      explanation: payload.explanation,
      sourceMatchConfidence: payload.sourceMatchConfidence ?? "medium",
      behaviors: payload.behaviors,
      findings: Array.isArray(payload.findings) ? payload.findings : [],
      riskNotes: Array.isArray(payload.riskNotes) ? payload.riskNotes : []
    };
  }
}

export class CompositeDecompilerProvider implements DecompilerProvider {
  readonly name = "composite-decompiler";

  constructor(private readonly providers: DecompilerProvider[]) {}

  async decompile(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<DecompiledArtifact> {
    const errors: string[] = [];

    for (const provider of this.providers) {
      try {
        return await provider.decompile(input);
      } catch (error) {
        errors.push(`${provider.name}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    throw new Error(`No decompiler provider succeeded. ${errors.join("; ")}`);
  }
}

export class CompositeClassifierProvider implements ClassifierProvider {
  readonly name = "composite-classifier";

  constructor(private readonly providers: ClassifierProvider[]) {}

  async classify(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
    decompiled: DecompiledArtifact;
  }): Promise<ClassifiedArtifact> {
    const errors: string[] = [];

    for (const provider of this.providers) {
      try {
        return await provider.classify(input);
      } catch (error) {
        errors.push(`${provider.name}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    throw new Error(`No classifier provider succeeded. ${errors.join("; ")}`);
  }
}

export function createDefaultDecompilerProvider(): DecompilerProvider {
  return new CompositeDecompilerProvider([
    new GhidraCommandDecompilerProvider(),
    new HttpDecompilerProvider(),
    new LocalHeuristicDecompilerProvider()
  ]);
}

export function createDefaultClassifierProvider(): ClassifierProvider {
  return new CompositeClassifierProvider([
    new HttpClassifierProvider(),
    new LocalHeuristicClassifierProvider()
  ]);
}

/**
 * Creates providers with Ghidra Docker and Grok AI enabled.
 * Use this in the daemon where real analysis infrastructure is available.
 */
export async function createLiveDecompilerProvider(): Promise<DecompilerProvider> {
  const { GhidraDockerDecompilerProvider } = await import("./ghidra-provider");
  return new CompositeDecompilerProvider([
    new GhidraDockerDecompilerProvider(),
    new GhidraCommandDecompilerProvider(),
    new HttpDecompilerProvider(),
    new LocalHeuristicDecompilerProvider()
  ]);
}

export async function createLiveClassifierProvider(): Promise<ClassifierProvider> {
  const { GrokClassifierProvider } = await import("./grok-classifier");
  return new CompositeClassifierProvider([
    new GrokClassifierProvider(),
    new HttpClassifierProvider(),
    new LocalHeuristicClassifierProvider()
  ]);
}

// ---------------------------------------------------------------------------
// Script analyzer providers (install-script / manifest analysis)
// ---------------------------------------------------------------------------

/** Deterministic heuristic install-script analyzer — always succeeds. */
export class HeuristicScriptAnalyzerProvider implements ScriptAnalyzerProvider {
  readonly name = "heuristic-script";

  private readonly analyzer = new ManifestAnalyzer();

  analyze(input: ScriptAnalysisInput) {
    return this.analyzer.analyze(input);
  }
}

/**
 * Runs the heuristic analyzer, then — only when the package actually has
 * install scripts or the heuristic already flagged something — layers the AI
 * analyzer on top. This gate keeps Grok spend proportional to real risk:
 * the vast majority of packages have no install scripts and never hit the AI.
 * An AI failure degrades gracefully to the heuristic floor.
 */
export class CompositeScriptAnalyzerProvider implements ScriptAnalyzerProvider {
  readonly name = "composite-script-analyzer";

  constructor(
    private readonly heuristic: ScriptAnalyzerProvider,
    private readonly ai?: ScriptAnalyzerProvider
  ) {}

  async analyze(input: ScriptAnalysisInput) {
    const heuristicResult = await this.heuristic.analyze(input);
    if (!this.ai) {
      return heuristicResult;
    }

    const shouldUseAi = heuristicResult.hasInstallScripts || heuristicResult.findings.length > 0;
    if (!shouldUseAi) {
      return heuristicResult;
    }

    try {
      const aiResult = await this.ai.analyze(input);
      return mergeManifestAnalysis(heuristicResult, aiResult);
    } catch (error) {
      console.warn(
        `[script-analyzer] AI pass failed, using heuristic floor: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
      return heuristicResult;
    }
  }
}

export function createDefaultScriptAnalyzerProvider(): ScriptAnalyzerProvider {
  return new CompositeScriptAnalyzerProvider(new HeuristicScriptAnalyzerProvider());
}

/**
 * Script analyzer with the Grok AI pass enabled. Use this in the daemon where
 * real analysis infrastructure (an xAI key) is available.
 */
export async function createLiveScriptAnalyzerProvider(): Promise<ScriptAnalyzerProvider> {
  const { GrokScriptAnalyzerProvider } = await import("./grok-script-classifier");
  return new CompositeScriptAnalyzerProvider(
    new HeuristicScriptAnalyzerProvider(),
    new GrokScriptAnalyzerProvider()
  );
}

// ---------------------------------------------------------------------------
// MalwareAnalyzerProvider — AnalyzerRegistry integration
// ---------------------------------------------------------------------------

export interface MalwareAnalysis {
  findings: import("@binshield/analysis-types").Finding[];
  behaviorSignals: Partial<import("@binshield/analysis-types").BehaviorSummary>;
  confidence: number;
  analyzerVersions: Record<string, string>;
}

/**
 * Provider that wraps `AnalyzerRegistry` so callers don't need to import the
 * registry directly.  The registry is lazily initialised with all three
 * built-in analyzers on first use.
 *
 * Usage (binary pipeline):
 *   const provider = new MalwareAnalyzerProvider();
 *   const result = await provider.analyze(artifact, request.analyzerFilter);
 *   // result.analyzerVersions → persist in BinaryAnalysis.analyzerVersions
 */
export class MalwareAnalyzerProvider {
  private registry: AnalyzerRegistry | null = null;

  /** Lazily initialise the registry with all built-in analyzers. */
  private async getRegistry(analyzerFilter?: string[]): Promise<AnalyzerRegistry> {
    if (!this.registry) {
      this.registry = await AnalyzerRegistry.createDefault(analyzerFilter);
    } else if (analyzerFilter && analyzerFilter.length > 0) {
      // Per-call filter: create an ephemeral registry scoped to this call.
      return AnalyzerRegistry.createDefault(analyzerFilter);
    }
    return this.registry;
  }

  async analyze(
    artifact: FingerprintedArtifact,
    analyzerFilter?: string[]
  ): Promise<MalwareAnalysis> {
    const registry = await this.getRegistry(analyzerFilter);
    const merged = await registry.analyze(artifact, analyzerFilter);
    return {
      findings: merged.findings,
      behaviorSignals: merged.behaviorSignals,
      confidence: merged.confidence,
      analyzerVersions: merged.analyzerVersions
    };
  }
}

/** Create a `MalwareAnalyzerProvider` pre-loaded with all built-in analyzers. */
export async function createMalwareAnalyzerProvider(): Promise<MalwareAnalyzerProvider> {
  const provider = new MalwareAnalyzerProvider();
  // Eagerly warm the registry so the first scan has no lazy-init latency.
  await (provider as unknown as { getRegistry: () => Promise<AnalyzerRegistry> }).getRegistry();
  return provider;
}
