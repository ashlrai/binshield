import type { PackageAnalysis, PackageDiff, SearchResult } from "@binshield/analysis-types";
import { sampleAnalyses, sampleDiff } from "@binshield/analysis-types";

export async function getFeaturedPackages(): Promise<SearchResult[]> {
  return sampleAnalyses.map((analysis) => ({
    ecosystem: analysis.ecosystem,
    packageName: analysis.packageName,
    latestVersion: analysis.version,
    riskLevel: analysis.riskLevel,
    riskScore: analysis.riskScore,
    summary: analysis.summary,
    binaryCount: analysis.binaryCount
  }));
}

export async function getPackageAnalysis(name: string): Promise<PackageAnalysis | undefined> {
  return sampleAnalyses.find((analysis) => analysis.packageName === name);
}

export async function getPackageDiff(_name: string): Promise<PackageDiff> {
  return sampleDiff;
}
