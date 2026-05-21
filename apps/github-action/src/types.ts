import type { PackageAnalysis, RiskLevel } from "@binshield/analysis-types";

export type CommentMode = "summary" | "pr-comment" | "both" | "off";
export type ScanMode = "native-only" | "all-dependencies";

export interface DiscoveredPackage {
  name: string;
  version: string;
  path: string;
  source: "lockfile";
  nativeCandidate: boolean;
  reason?: string;
}

export interface GitHubActionConfig {
  apiBaseUrl: string;
  apiKey?: string;
  githubToken?: string;
  failOn: RiskLevel | "never";
  commentMode: CommentMode;
  scanMode: ScanMode;
  workingDirectory: string;
  includeDevDependencies: boolean;
  registerDependencies: boolean;
  pollIntervalMs: number;
  timeoutMs: number;
  maxTargets: number;
}

export interface ScanOutcome {
  target: DiscoveredPackage;
  analysis?: PackageAnalysis;
  error?: string;
}
