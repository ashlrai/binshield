/**
 * Compliance Report Generator
 *
 * Generates structured compliance reports for SOC 2, ISO 27001, and EU CRA.
 * Produces HTML reports that can be rendered as PDFs.
 *
 * Report types:
 *  - soc2: Binary supply chain controls evidence
 *  - iso27001: Asset inventory and vulnerability management
 *  - cra: Software bill of materials + risk assessment
 *  - custom: User-defined scope
 */

import type { PackageAnalysis, Finding } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReportRequest {
  orgId: string;
  reportType: "soc2" | "iso27001" | "cra" | "custom";
  title?: string;
  scope: ReportScope;
}

export interface ReportScope {
  /** Include all packages for this org. */
  allPackages?: boolean;
  /** Specific package names to include. */
  packageNames?: string[];
  /** Repos to include. */
  repoIds?: string[];
  /** Date range for scans. */
  fromDate?: string;
  toDate?: string;
}

export interface ComplianceReport {
  id: string;
  orgId: string;
  reportType: string;
  title: string;
  status: "generating" | "ready" | "failed";
  scope: ReportScope;
  summary: ReportSummary;
  html: string;
  generatedAt: string;
}

export interface ReportSummary {
  totalPackages: number;
  totalBinaries: number;
  riskDistribution: Record<string, number>;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  averageRiskScore: number;
  maxRiskScore: number;
  advisoryCount?: number;
  complianceScore: number;
}

// ---------------------------------------------------------------------------
// Report Generation
// ---------------------------------------------------------------------------

function computeSummary(analyses: PackageAnalysis[]): ReportSummary {
  const riskDistribution: Record<string, number> = {
    none: 0, low: 0, medium: 0, high: 0, critical: 0,
  };

  let totalRisk = 0;
  let maxRisk = 0;
  let totalBinaries = 0;
  let criticalFindings = 0;
  let highFindings = 0;
  let mediumFindings = 0;
  let lowFindings = 0;
  let infoFindings = 0;

  for (const analysis of analyses) {
    riskDistribution[analysis.riskLevel] = (riskDistribution[analysis.riskLevel] ?? 0) + 1;
    totalRisk += analysis.riskScore;
    if (analysis.riskScore > maxRisk) maxRisk = analysis.riskScore;
    totalBinaries += analysis.binaryCount;

    for (const binary of analysis.binaries) {
      for (const finding of binary.findings) {
        switch (finding.severity) {
          case "critical": criticalFindings++; break;
          case "high": highFindings++; break;
          case "medium": mediumFindings++; break;
          case "low": lowFindings++; break;
          default: infoFindings++; break;
        }
      }
    }
  }

  const averageRiskScore = analyses.length > 0 ? Math.round(totalRisk / analyses.length) : 0;

  // Compliance score: inverse of risk (100 = no risk, 0 = all critical)
  const complianceScore = Math.max(0, Math.min(100,
    100 - Math.round(
      (criticalFindings * 20 + highFindings * 10 + mediumFindings * 3 + lowFindings * 1)
      / Math.max(1, analyses.length)
    )
  ));

  return {
    totalPackages: analyses.length,
    totalBinaries,
    riskDistribution,
    criticalFindings,
    highFindings,
    mediumFindings,
    lowFindings,
    infoFindings,
    averageRiskScore,
    maxRiskScore: maxRisk,
    complianceScore,
  };
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityBadge(severity: string): string {
  const colors: Record<string, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#d97706",
    low: "#2563eb",
    info: "#6b7280",
    none: "#22c55e",
  };
  const color = colors[severity] ?? colors.info;
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;background:${color};color:white;font-size:12px;font-weight:600;text-transform:uppercase;">${escapeHtml(severity)}</span>`;
}

// ---------------------------------------------------------------------------
// HTML Templates
// ---------------------------------------------------------------------------

function generateBaseHtml(
  reportType: string,
  title: string,
  orgName: string,
  summary: ReportSummary,
  analyses: PackageAnalysis[],
  generatedAt: string,
): string {
  const typeLabels: Record<string, string> = {
    soc2: "SOC 2 Type II — Supply Chain Binary Controls",
    iso27001: "ISO 27001 — Binary Asset Inventory & Vulnerability Management",
    cra: "EU Cyber Resilience Act — Software Bill of Materials",
    custom: "Custom Security Assessment",
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a2e; line-height: 1.6; padding: 40px; max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 28px; margin-bottom: 4px; }
  h2 { font-size: 20px; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; }
  h3 { font-size: 16px; margin: 20px 0 8px; }
  .header { margin-bottom: 32px; }
  .subtitle { color: #6b7280; font-size: 14px; margin-bottom: 16px; }
  .meta { display: flex; gap: 24px; font-size: 13px; color: #6b7280; margin-bottom: 24px; }
  .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
  .metric { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; text-align: center; }
  .metric-value { font-size: 32px; font-weight: 700; }
  .metric-label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 14px; }
  th { text-align: left; padding: 10px 12px; background: #f3f4f6; border-bottom: 2px solid #d1d5db; font-weight: 600; }
  td { padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }
  tr:hover td { background: #f9fafb; }
  .score-bar { display: inline-block; height: 8px; border-radius: 4px; }
  .finding { padding: 12px 16px; margin: 8px 0; border-left: 4px solid; border-radius: 0 8px 8px 0; background: #fafafa; }
  .finding-critical { border-left-color: #dc2626; }
  .finding-high { border-left-color: #ea580c; }
  .finding-medium { border-left-color: #d97706; }
  .finding-low { border-left-color: #2563eb; }
  .finding-info { border-left-color: #6b7280; }
  .compliance-score { font-size: 48px; font-weight: 800; }
  .compliance-good { color: #16a34a; }
  .compliance-fair { color: #d97706; }
  .compliance-poor { color: #dc2626; }
  .footer { margin-top: 48px; padding-top: 24px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; }
  @media print { body { padding: 20px; } .metrics { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<div class="header">
  <h1>${escapeHtml(title)}</h1>
  <div class="subtitle">${escapeHtml(typeLabels[reportType] ?? reportType)}</div>
  <div class="meta">
    <span>Organization: <strong>${escapeHtml(orgName)}</strong></span>
    <span>Generated: <strong>${new Date(generatedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</strong></span>
    <span>Report ID: <strong>${escapeHtml(title.slice(0, 8))}</strong></span>
  </div>
</div>

<h2>Executive Summary</h2>
<div class="metrics">
  <div class="metric">
    <div class="metric-value ${summary.complianceScore >= 80 ? "compliance-good" : summary.complianceScore >= 50 ? "compliance-fair" : "compliance-poor"}">${summary.complianceScore}</div>
    <div class="metric-label">Compliance Score</div>
  </div>
  <div class="metric">
    <div class="metric-value">${summary.totalPackages}</div>
    <div class="metric-label">Packages Scanned</div>
  </div>
  <div class="metric">
    <div class="metric-value">${summary.totalBinaries}</div>
    <div class="metric-label">Binaries Analyzed</div>
  </div>
  <div class="metric">
    <div class="metric-value">${summary.criticalFindings + summary.highFindings}</div>
    <div class="metric-label">Critical/High Findings</div>
  </div>
</div>

<h2>Risk Distribution</h2>
<table>
  <thead><tr><th>Risk Level</th><th>Count</th><th>Percentage</th></tr></thead>
  <tbody>
${Object.entries(summary.riskDistribution).map(([level, count]) =>
  `    <tr><td>${severityBadge(level)}</td><td>${count}</td><td>${summary.totalPackages > 0 ? Math.round((count / summary.totalPackages) * 100) : 0}%</td></tr>`
).join("\n")}
  </tbody>
</table>

<h2>Findings Summary</h2>
<table>
  <thead><tr><th>Severity</th><th>Count</th></tr></thead>
  <tbody>
    <tr><td>${severityBadge("critical")}</td><td>${summary.criticalFindings}</td></tr>
    <tr><td>${severityBadge("high")}</td><td>${summary.highFindings}</td></tr>
    <tr><td>${severityBadge("medium")}</td><td>${summary.mediumFindings}</td></tr>
    <tr><td>${severityBadge("low")}</td><td>${summary.lowFindings}</td></tr>
    <tr><td>${severityBadge("info")}</td><td>${summary.infoFindings}</td></tr>
  </tbody>
</table>

<h2>Package Inventory</h2>
<table>
  <thead><tr><th>Package</th><th>Version</th><th>Risk Score</th><th>Risk Level</th><th>Binaries</th><th>Findings</th></tr></thead>
  <tbody>
${analyses.map((a) => {
  const findingCount = a.binaries.reduce((sum, b) => sum + b.findings.length, 0);
  return `    <tr><td><strong>${escapeHtml(a.packageName)}</strong></td><td>${escapeHtml(a.version)}</td><td>${a.riskScore}</td><td>${severityBadge(a.riskLevel)}</td><td>${a.binaryCount}</td><td>${findingCount}</td></tr>`;
}).join("\n")}
  </tbody>
</table>

${generateFindingsSection(analyses)}

${generateComplianceSection(reportType, summary)}

<div class="footer">
  <p>Generated by BinShield (binshield.dev) | AshlrAI Inc.</p>
  <p>This report is generated automatically from binary analysis data. It should be reviewed by qualified security personnel before use in compliance submissions.</p>
</div>
</body>
</html>`;
}

function generateFindingsSection(analyses: PackageAnalysis[]): string {
  const allFindings: Array<Finding & { packageName: string; binaryFile: string }> = [];

  for (const analysis of analyses) {
    for (const binary of analysis.binaries) {
      for (const finding of binary.findings) {
        allFindings.push({
          ...finding,
          packageName: analysis.packageName,
          binaryFile: binary.filename,
        });
      }
    }
  }

  // Sort by severity
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  if (allFindings.length === 0) {
    return "<h2>Detailed Findings</h2><p>No security findings detected.</p>";
  }

  // Show top 50 findings
  const displayed = allFindings.slice(0, 50);

  return `<h2>Detailed Findings</h2>
${displayed.map((f) => `
<div class="finding finding-${f.severity}">
  <strong>${severityBadge(f.severity)} ${escapeHtml(f.title)}</strong>
  <div style="margin-top:4px;font-size:13px;color:#374151;">${escapeHtml(f.description)}</div>
  <div style="margin-top:4px;font-size:12px;color:#6b7280;">Package: ${escapeHtml(f.packageName)} | Binary: ${escapeHtml(f.binaryFile)}${f.location ? ` | Location: ${escapeHtml(f.location)}` : ""}</div>
  ${f.recommendation ? `<div style="margin-top:4px;font-size:12px;color:#2563eb;">Recommendation: ${escapeHtml(f.recommendation)}</div>` : ""}
</div>`).join("\n")}
${allFindings.length > 50 ? `<p style="color:#6b7280;font-size:13px;">... and ${allFindings.length - 50} more findings</p>` : ""}`;
}

function generateComplianceSection(reportType: string, summary: ReportSummary): string {
  switch (reportType) {
    case "soc2":
      return `
<h2>SOC 2 Controls Evidence</h2>
<h3>CC6.1 — Logical and Physical Access Controls</h3>
<p>All native binary dependencies have been catalogued and analyzed for access control behaviors. ${summary.totalBinaries} binaries across ${summary.totalPackages} packages were assessed for unauthorized access patterns.</p>

<h3>CC7.1 — System Operations Monitoring</h3>
<p>BinShield continuously monitors binary dependencies for behavioral changes, including network access, filesystem operations, process spawning, and data exfiltration indicators.</p>

<h3>CC7.2 — Security Incident Monitoring</h3>
<p>${summary.criticalFindings} critical and ${summary.highFindings} high-severity findings require review. All findings are tracked with full audit trails.</p>

<h3>CC8.1 — Change Management</h3>
<p>Version-level analysis enables detection of behavioral changes between package versions. Binary diff analysis provides evidence of supply chain integrity.</p>`;

    case "iso27001":
      return `
<h2>ISO 27001 Controls Mapping</h2>
<h3>A.8 — Asset Management</h3>
<p>Complete inventory of ${summary.totalPackages} native binary packages with ${summary.totalBinaries} individual binaries. Each asset is classified by risk level and behavioral profile.</p>

<h3>A.12 — Operations Security</h3>
<p>Automated binary analysis provides continuous vulnerability assessment. ${summary.criticalFindings + summary.highFindings} items require remediation attention.</p>

<h3>A.14 — System Acquisition, Development and Maintenance</h3>
<p>Supply chain binary analysis ensures third-party components meet security requirements. Risk scores and behavioral analysis provide evidence for vendor risk assessment.</p>

<h3>A.18 — Compliance</h3>
<p>This report demonstrates compliance with information security requirements for software supply chain management. Compliance score: ${summary.complianceScore}/100.</p>`;

    case "cra":
      return `
<h2>EU Cyber Resilience Act (CRA) Compliance</h2>
<h3>Article 10 — Obligations of Manufacturers</h3>
<p>Software bill of materials (SBOM) has been generated for all ${summary.totalPackages} native binary dependencies. Each component is assessed for known vulnerabilities and behavioral risks.</p>

<h3>Article 11 — Vulnerability Handling</h3>
<p>${summary.criticalFindings + summary.highFindings + summary.mediumFindings} security findings identified across the supply chain. Findings are categorized by severity with remediation recommendations.</p>

<h3>Annex I — Essential Requirements</h3>
<p>Binary behavioral analysis covers: network access, filesystem operations, process management, cryptographic operations, obfuscation detection, and data exfiltration indicators.</p>

<h3>Annex II — SBOM Information</h3>
<p>CycloneDX SBOMs are available for each analyzed package. Combined SBOM covers ${summary.totalBinaries} native binaries with full dependency trees.</p>`;

    default:
      return "";
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function generateReport(
  reportType: string,
  title: string,
  orgName: string,
  analyses: PackageAnalysis[],
): { summary: ReportSummary; html: string } {
  const summary = computeSummary(analyses);
  const generatedAt = new Date().toISOString();
  const html = generateBaseHtml(reportType, title, orgName, summary, analyses, generatedAt);
  return { summary, html };
}
