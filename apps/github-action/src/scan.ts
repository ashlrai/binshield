import type { PackageAnalysis, RiskLevel, ScanJob, SearchResult } from "@binshield/analysis-types";

const thresholdOrder: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

export function shouldFail(level: RiskLevel, threshold: RiskLevel | "never") {
  if (threshold === "never") {
    return false;
  }

  return thresholdOrder.indexOf(level) >= thresholdOrder.indexOf(threshold);
}

export function renderComment(analyses: PackageAnalysis[]) {
  const rows = analyses
    .map(
      (analysis) =>
        `| ${analysis.packageName}@${analysis.version} | ${analysis.binaries
          .map((binary) => binary.filename)
          .join(", ")} | ${analysis.riskLevel.toUpperCase()} (${analysis.riskScore}) | ${analysis.summary} |`
    )
    .join("\n");

  return `## BinShield - Binary Dependency Scan

**${analyses.length} package analyses completed**

| Package | Binary | Risk | Summary |
|---------|--------|------|---------|
${rows}
`;
}

export async function runPackageScan(
  baseUrl: string,
  request: { ecosystem: "npm"; packageName: string; version: string }
): Promise<PackageAnalysis> {
  const response = await fetch(`${baseUrl}/scans/packages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(request)
  });

  const job = (await response.json()) as ScanJob;
  if (job.result) {
    return job.result;
  }

  const poll = await fetch(`${baseUrl}/scans/${job.id}`);
  const completed = (await poll.json()) as ScanJob;
  if (!completed.result) {
    throw new Error(`Scan ${job.id} did not produce a result`);
  }

  return completed.result;
}

export async function searchPackages(baseUrl: string, q: string): Promise<SearchResult[]> {
  const response = await fetch(`${baseUrl}/packages/search?q=${encodeURIComponent(q)}`);
  const body = (await response.json()) as { items: SearchResult[] };
  return body.items;
}
