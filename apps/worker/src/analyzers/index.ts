/**
 * Barrel export for built-in MalwareAnalyzer plugins.
 * Third-party plugins can register directly with AnalyzerRegistry.getInstance().
 */
export { YaraAnalyzer } from "./yara-analyzer.js";
export { HeuristicPatternAnalyzer } from "./heuristic-pattern-analyzer.js";
export { StringSignatureAnalyzer } from "./string-signature-analyzer.js";
export { BehaviorCorrelationAnalyzer } from "./behavior-correlation-analyzer.js";
