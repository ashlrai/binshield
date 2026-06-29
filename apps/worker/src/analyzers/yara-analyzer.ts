/**
 * YaraAnalyzer — MalwareAnalyzer plugin wrapping the existing YaraScanner.
 *
 * Delegates to `yara-scanner.ts` which tries Docker YARA first, then falls
 * back to the built-in heuristic rules. The analyzer name "yara" maps to the
 * `--analyzers=yara` CLI flag.
 */

import type { AnalysisResult, MalwareAnalyzer } from "../malware-analyzer.js";
import type { FingerprintedArtifact } from "../types.js";
import { YaraScanner } from "../yara-scanner.js";

const YARA_ANALYZER_VERSION = "1.0.0";

export class YaraAnalyzer implements MalwareAnalyzer {
  private readonly scanner = new YaraScanner();

  name(): string {
    return "yara";
  }

  version(): string {
    return YARA_ANALYZER_VERSION;
  }

  async analyze(artifact: FingerprintedArtifact): Promise<AnalysisResult> {
    const result = await this.scanner.scan(artifact);

    return {
      analyzerName: this.name(),
      analyzerVersion: this.version(),
      findings: result.findings,
      behaviorSignals: result.behaviorSignals,
      confidence: result.confidence,
      metadata: {
        matchCount: result.matches.length,
        matchedRules: result.matches.map((m) => m.rule)
      }
    };
  }
}
