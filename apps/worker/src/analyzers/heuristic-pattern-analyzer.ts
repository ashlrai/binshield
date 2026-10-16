/**
 * HeuristicPatternAnalyzer — MalwareAnalyzer plugin wrapping threat-patterns.ts
 *
 * Applies the deterministic script threat ruleset from `threat-patterns.ts` to
 * the binary's extracted strings. The analyzer name "heuristic" maps to the
 * `--analyzers=heuristic` CLI flag.
 *
 * Note: the threat-patterns ruleset was originally designed for install-script
 * source text. When applied to binary strings it uses a best-effort string join
 * so that patterns that appear in binary string tables are still caught.
 */

import type { BehaviorSummary, FindingSeverity } from "@binshield/analysis-types";
import type { AnalysisResult, MalwareAnalyzer } from "../malware-analyzer.js";
import type { FingerprintedArtifact } from "../types.js";
import { evaluateScriptPatterns, getPatternVersion } from "../threat-patterns.js";

/** Map ScriptThreatCategory → BehaviorSummary key (best-effort). */
const CATEGORY_TO_BEHAVIOR: Partial<Record<string, keyof BehaviorSummary>> = {
  remoteCodeExecution: "process",
  reverseShell: "process",
  environmentTheft: "dataExfiltration",
  scriptInjection: "obfuscation",
  obfuscation: "obfuscation",
  wiper: "filesystem"
};

export class HeuristicPatternAnalyzer implements MalwareAnalyzer {
  name(): string {
    return "heuristic";
  }

  version(): string {
    // Delegate to the pattern-set version so bumping the JSON automatically
    // bumps the recorded analyzer version for traceability.
    return getPatternVersion();
  }

  async analyze(artifact: FingerprintedArtifact): Promise<AnalysisResult> {
    // Combine all string sources into a single block for pattern matching.
    const text = [...artifact.strings, ...artifact.interestingStrings].join("\n");
    const hits = evaluateScriptPatterns(text);

    const findings = hits.map((hit) => ({
      severity: hit.rule.severity as FindingSeverity,
      title: `Heuristic: ${hit.rule.title}`,
      description: hit.rule.description,
      location: artifact.filename,
      recommendation: hit.rule.recommendation
    }));

    // Build behavior signals from matched categories.
    const behaviorSignals: Partial<BehaviorSummary> = {};
    for (const hit of hits) {
      const behaviorKey = CATEGORY_TO_BEHAVIOR[hit.rule.category];
      if (!behaviorKey) continue;
      const existing = behaviorSignals[behaviorKey];
      if (existing) {
        existing.details.push(`Heuristic: ${hit.rule.id}`);
      } else {
        (behaviorSignals as Record<string, unknown>)[behaviorKey] = {
          detected: true,
          details: [`Heuristic: ${hit.rule.id}`]
        };
      }
    }

    return {
      analyzerName: this.name(),
      analyzerVersion: this.version(),
      findings,
      behaviorSignals,
      confidence: hits.length > 0 ? 0.75 : 0.5,
      metadata: {
        hitCount: hits.length,
        matchedRuleIds: hits.map((h) => h.rule.id)
      }
    };
  }
}
