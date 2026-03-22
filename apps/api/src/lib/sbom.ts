import crypto from "node:crypto";
import type { PackageAnalysis, Finding, FindingSeverity } from "@binshield/analysis-types";

function mapSeverityToRating(severity: FindingSeverity): { severity: string; method: { value: string } } {
  const severityMap: Record<FindingSeverity, string> = {
    info: "info",
    low: "low",
    medium: "medium",
    high: "high",
    critical: "critical"
  };

  return {
    severity: severityMap[severity],
    method: { value: "other" }
  };
}

function buildVulnerability(finding: Finding, binaryId: string, index: number) {
  return {
    "bom-ref": `vuln-${binaryId}-${index}`,
    id: `BSHLD-${binaryId}-${index}`,
    description: finding.description,
    detail: finding.title,
    recommendation: finding.recommendation,
    source: {
      name: "BinShield",
      url: "https://binshield.io"
    },
    ratings: [mapSeverityToRating(finding.severity)],
    affects: [
      {
        ref: binaryId
      }
    ]
  };
}

export function generateCycloneDxSbom(analysis: PackageAnalysis): object {
  const mainComponentRef = `pkg:${analysis.ecosystem}/${analysis.packageName}@${analysis.version}`;

  const binaryComponents = analysis.binaries.map((binary) => {
    const hashes = binary.fingerprint
      ? [{ alg: "SHA-256", content: binary.fingerprint.sha256 }]
      : [];

    const properties: { name: string; value: string }[] = [];
    for (const [behaviorName, signal] of Object.entries(binary.behaviors)) {
      if (signal.detected) {
        properties.push({
          name: `binshield:behavior:${behaviorName}`,
          value: signal.details.join("; ")
        });
      }
    }

    properties.push(
      { name: "binshield:riskScore", value: String(binary.riskScore) },
      { name: "binshield:riskLevel", value: binary.riskLevel },
      { name: "binshield:format", value: binary.format },
      { name: "binshield:architecture", value: binary.architecture }
    );

    return {
      type: "file",
      "bom-ref": binary.id,
      name: binary.filename,
      hashes,
      properties
    };
  });

  const vulnerabilities: object[] = [];
  for (const binary of analysis.binaries) {
    for (let i = 0; i < binary.findings.length; i++) {
      vulnerabilities.push(buildVulnerability(binary.findings[i], binary.id, i));
    }
  }

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: "application",
            name: "BinShield",
            version: "1.0.0"
          }
        ]
      },
      component: {
        type: "library",
        "bom-ref": mainComponentRef,
        name: analysis.packageName,
        version: analysis.version,
        purl: mainComponentRef,
        properties: [
          { name: "binshield:ecosystem", value: analysis.ecosystem },
          { name: "binshield:riskScore", value: String(analysis.riskScore) },
          { name: "binshield:riskLevel", value: analysis.riskLevel },
          { name: "binshield:sourceMatchConfidence", value: analysis.sourceMatchConfidence }
        ]
      }
    },
    components: binaryComponents,
    vulnerabilities
  };
}
