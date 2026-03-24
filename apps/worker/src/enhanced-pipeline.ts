/**
 * Enhanced Analysis Pipeline
 *
 * Orchestrates multi-tool binary analysis: Rizin (quick triage) -> Ghidra
 * (deep decompilation if suspicious), YARA (pattern matching), and entropy
 * analysis. Merges all signals into a unified result with confidence scoring.
 *
 * Pipeline flow:
 *   1. Fingerprint (sha256, magic bytes, format detection)
 *   2. PARALLEL:
 *      a. Rizin quick analysis -> if suspicious -> Ghidra deep decompilation
 *      b. YARA rule scanning
 *   3. Merge all signals
 *   4. AI Classification (Grok) — with enriched input from all tools
 *   5. Risk Scoring (enhanced with multi-tool confidence)
 */

import type { BehaviorSummary, Finding } from "@binshield/analysis-types";
import type {
  ClassifiedArtifact,
  DecompiledArtifact,
  FingerprintedArtifact,
  DecompilerProvider,
  ClassifierProvider,
  WorkerScanRequest,
} from "./types";
import { RizinDecompilerProvider } from "./rizin-provider";
import { YaraScanner } from "./yara-scanner";
import type { YaraScanResult } from "./yara-scanner";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EnhancedAnalysisResult {
  decompiled: DecompiledArtifact;
  classified: ClassifiedArtifact;
  yaraResult: YaraScanResult;
  confidenceBreakdown: ConfidenceBreakdown;
}

export interface ConfidenceBreakdown {
  rizin: number;
  ghidra: number;
  yara: number;
  ai: number;
  overall: number;
}

interface ToolWeights {
  rizin: number;
  ghidra: number;
  yara: number;
  ai: number;
}

const DEFAULT_WEIGHTS: ToolWeights = {
  rizin: 0.15,
  ghidra: 0.35,
  yara: 0.25,
  ai: 0.25,
};

// ---------------------------------------------------------------------------
// Enhanced Pipeline
// ---------------------------------------------------------------------------

export class EnhancedAnalysisPipeline {
  private readonly rizin: RizinDecompilerProvider;
  private readonly yara: YaraScanner;
  private readonly ghidraDecompiler: DecompilerProvider;
  private readonly classifier: ClassifierProvider;
  private readonly weights: ToolWeights;

  constructor(options: {
    ghidraDecompiler: DecompilerProvider;
    classifier: ClassifierProvider;
    weights?: Partial<ToolWeights>;
  }) {
    this.rizin = new RizinDecompilerProvider();
    this.yara = new YaraScanner();
    this.ghidraDecompiler = options.ghidraDecompiler;
    this.classifier = options.classifier;
    this.weights = { ...DEFAULT_WEIGHTS, ...options.weights };
  }

  /**
   * Run the full enhanced analysis pipeline on a single artifact.
   */
  async analyze(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<EnhancedAnalysisResult> {
    // Step 1: Run Rizin triage and YARA scan in parallel
    const [triageResult, yaraResult] = await Promise.allSettled([
      this.rizin.triage(input.artifact),
      this.yara.scan(input.artifact),
    ]);

    const triage = triageResult.status === "fulfilled"
      ? triageResult.value
      : { shouldEscalate: true, reasons: ["rizin failed"], analysis: null };

    const yara = yaraResult.status === "fulfilled"
      ? yaraResult.value
      : { matches: [], findings: [], behaviorSignals: {}, confidence: 0 };

    // Step 2: Decompile — use Ghidra if suspicious or if rizin failed, else use rizin output
    let decompiled: DecompiledArtifact;
    let ghidraConfidence = 0;
    let rizinConfidence = 0;

    if (triage.shouldEscalate || !triage.analysis) {
      // Full Ghidra decompilation
      try {
        decompiled = await this.ghidraDecompiler.decompile(input);
        ghidraConfidence = decompiled.confidence;
      } catch {
        // Ghidra failed — use rizin output if available, else minimal
        if (triage.analysis) {
          decompiled = {
            pseudoSource: `// Rizin analysis (Ghidra unavailable)\n// Functions: ${triage.analysis.functionCount}`,
            imports: triage.analysis.imports,
            strings: triage.analysis.strings.slice(0, 100),
            functionCount: triage.analysis.functionCount,
            callTargets: triage.analysis.exports.slice(0, 30),
            confidence: 0.5,
          };
          rizinConfidence = 0.5;
        } else {
          decompiled = {
            pseudoSource: "// Analysis tools unavailable",
            imports: [],
            strings: input.artifact.strings,
            functionCount: 0,
            callTargets: [],
            confidence: 0.2,
          };
        }
      }
    } else {
      // Rizin found nothing suspicious — use rizin output directly
      decompiled = {
        pseudoSource: `// Rizin analysis (low risk — Ghidra skipped)\n// Functions: ${triage.analysis.functionCount}`,
        imports: triage.analysis.imports,
        strings: triage.analysis.strings.slice(0, 100),
        functionCount: triage.analysis.functionCount,
        callTargets: triage.analysis.exports.slice(0, 30),
        confidence: 0.65,
      };
      rizinConfidence = 0.65;
    }

    // Enrich decompiled data with rizin findings if available
    if (triage.analysis) {
      rizinConfidence = Math.max(rizinConfidence, 0.5);
      // Merge imports from both sources
      const importSet = new Set([...decompiled.imports, ...triage.analysis.imports]);
      decompiled = { ...decompiled, imports: Array.from(importSet) };
    }

    // Step 3: AI Classification with enriched input
    let classified: ClassifiedArtifact;
    let aiConfidence = 0;

    try {
      classified = await this.classifier.classify({
        ...input,
        decompiled,
      });
      aiConfidence = classified.sourceMatchConfidence === "high" ? 0.9
        : classified.sourceMatchConfidence === "medium" ? 0.7 : 0.4;
    } catch {
      // AI unavailable — build classification from tool signals only
      classified = this.buildFallbackClassification(decompiled, yara, triage.analysis?.suspicionReasons ?? []);
      aiConfidence = 0;
    }

    // Step 4: Merge YARA findings into classified output
    classified = this.mergeYaraIntoClassification(classified, yara);

    // Step 5: Calculate confidence breakdown
    const confidenceBreakdown = this.calculateConfidence({
      rizin: rizinConfidence,
      ghidra: ghidraConfidence,
      yara: yara.confidence,
      ai: aiConfidence,
    });

    return {
      decompiled,
      classified,
      yaraResult: yara,
      confidenceBreakdown,
    };
  }

  /**
   * Merge YARA scan results into the AI classification output.
   */
  private mergeYaraIntoClassification(
    classified: ClassifiedArtifact,
    yara: YaraScanResult,
  ): ClassifiedArtifact {
    // Add YARA findings
    const mergedFindings = [...classified.findings];
    for (const finding of yara.findings) {
      // Avoid duplicates
      if (!mergedFindings.some((f) => f.title === finding.title)) {
        mergedFindings.push(finding);
      }
    }

    // Merge behavior signals
    const mergedBehaviors = { ...classified.behaviors };
    for (const [key, value] of Object.entries(yara.behaviorSignals)) {
      const behaviorKey = key as keyof BehaviorSummary;
      const yaraSignal = value as { detected: boolean; details: string[] };
      const existing = mergedBehaviors[behaviorKey];

      if (yaraSignal.detected) {
        if (existing?.detected) {
          // Merge details
          const existingDetails = new Set(existing.details);
          for (const detail of yaraSignal.details) {
            existingDetails.add(detail);
          }
          mergedBehaviors[behaviorKey] = {
            detected: true,
            details: Array.from(existingDetails),
          };
        } else {
          mergedBehaviors[behaviorKey] = yaraSignal;
        }
      }
    }

    // Add YARA match info to risk notes
    const riskNotes = [...classified.riskNotes];
    if (yara.matches.length > 0) {
      riskNotes.push(
        `YARA: ${yara.matches.length} rule(s) matched: ${yara.matches.map((m) => m.rule).join(", ")}`,
      );
    }

    return {
      ...classified,
      findings: mergedFindings,
      behaviors: mergedBehaviors,
      riskNotes,
    };
  }

  /**
   * Build a classification when AI is unavailable, using tool signals only.
   */
  private buildFallbackClassification(
    decompiled: DecompiledArtifact,
    yara: YaraScanResult,
    suspicionReasons: string[],
  ): ClassifiedArtifact {
    const behaviors: BehaviorSummary = {
      network: { detected: false, details: [] },
      filesystem: { detected: false, details: [] },
      process: { detected: false, details: [] },
      crypto: { detected: false, details: [] },
      obfuscation: { detected: false, details: [] },
      dataExfiltration: { detected: false, details: [] },
    };

    // Detect behaviors from imports
    for (const imp of decompiled.imports) {
      if (/socket|http|curl|connect|send|recv|dns/i.test(imp)) {
        behaviors.network.detected = true;
        behaviors.network.details.push(imp);
      }
      if (/file|open|read|write|fopen|mkdir|stat/i.test(imp)) {
        behaviors.filesystem.detected = true;
        behaviors.filesystem.details.push(imp);
      }
      if (/exec|spawn|fork|system|popen|process/i.test(imp)) {
        behaviors.process.detected = true;
        behaviors.process.details.push(imp);
      }
      if (/crypto|aes|sha|md5|hmac|bcrypt|argon|hash/i.test(imp)) {
        behaviors.crypto.detected = true;
        behaviors.crypto.details.push(imp);
      }
    }

    // Merge YARA signals
    for (const [key, value] of Object.entries(yara.behaviorSignals)) {
      const behaviorKey = key as keyof BehaviorSummary;
      const yaraSignal = value as { detected: boolean; details: string[] };
      if (yaraSignal.detected) {
        behaviors[behaviorKey] = {
          detected: true,
          details: [...behaviors[behaviorKey].details, ...yaraSignal.details],
        };
      }
    }

    return {
      summary: suspicionReasons.length > 0
        ? `Binary flagged with ${suspicionReasons.length} suspicious indicator(s)`
        : "Binary analyzed with heuristic tools (AI classification unavailable)",
      explanation: suspicionReasons.join("; ") || "No significant concerns detected by automated analysis.",
      sourceMatchConfidence: "low",
      behaviors,
      findings: [...yara.findings],
      riskNotes: suspicionReasons.map((r) => `Rizin: ${r}`),
    };
  }

  /**
   * Calculate overall confidence from individual tool confidences.
   */
  private calculateConfidence(toolConfidences: Record<keyof ToolWeights, number>): ConfidenceBreakdown {
    let overall = 0;
    let totalWeight = 0;

    for (const [tool, weight] of Object.entries(this.weights)) {
      const confidence = toolConfidences[tool as keyof ToolWeights] ?? 0;
      if (confidence > 0) {
        overall += confidence * weight;
        totalWeight += weight;
      }
    }

    // Normalize
    overall = totalWeight > 0 ? overall / totalWeight : 0;

    return {
      rizin: toolConfidences.rizin,
      ghidra: toolConfidences.ghidra,
      yara: toolConfidences.yara,
      ai: toolConfidences.ai,
      overall: Math.round(overall * 100) / 100,
    };
  }
}
