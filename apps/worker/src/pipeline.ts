import type { BinaryAnalysis, PackageAnalysis, ScanRequest } from "@binshield/analysis-types";
import { emptyBehaviorSummary } from "@binshield/analysis-types";
import { scoreBinary, aggregatePackageRisk } from "@binshield/risk-engine";

interface DecompiledArtifact {
  imports: string[];
  strings: string[];
  preview: string;
  functionCount: number;
}

export class ExtractionService {
  async extractBinaries(request: ScanRequest) {
    return [
      {
        filename: `${request.packageName}.node`,
        architecture: "x86_64",
        format: "ELF" as const,
        fileSize: 184_320
      }
    ];
  }
}

export class GhidraService {
  async decompile(binaryName: string): Promise<DecompiledArtifact> {
    return {
      imports: ["uv_queue_work", "napi_create_function", "open"],
      strings: ["/dev/urandom", "binshield-simulated-analysis", binaryName],
      preview: `int entry_${binaryName.replace(/\W/g, "_")}(void) { return 0; }`,
      functionCount: 34
    };
  }
}

export class AiAnalysisService {
  async classify(binaryName: string, artifact: DecompiledArtifact) {
    const behaviors = emptyBehaviorSummary();
    const findings = [];

    if (artifact.strings.some((value) => value.includes("urandom"))) {
      behaviors.filesystem = {
        detected: true,
        details: ["Reads /dev/urandom for entropy during startup."]
      };
      behaviors.crypto = {
        detected: true,
        details: ["Entropy access is consistent with cryptographic setup."]
      };
      findings.push({
        severity: "info" as const,
        title: "Entropy source access",
        description: `${binaryName} reads an OS entropy device.`,
        location: "entrypoint",
        recommendation: "Treat as expected when crypto primitives are present."
      });
    }

    return {
      summary: `${binaryName} exhibits expected native addon initialization and no suspicious network behavior.`,
      explanation:
        "Simulated classifier result from the worker pipeline. Replace this service with a provider-backed Claude adapter for production.",
      behaviors,
      findings
    };
  }
}

export class AnalysisPipeline {
  constructor(
    private extraction = new ExtractionService(),
    private ghidra = new GhidraService(),
    private ai = new AiAnalysisService()
  ) {}

  async analyze(request: ScanRequest): Promise<PackageAnalysis> {
    const extracted = await this.extraction.extractBinaries(request);
    const binaries: BinaryAnalysis[] = [];

    for (const binary of extracted) {
      const decompiled = await this.ghidra.decompile(binary.filename);
      const aiResult = await this.ai.classify(binary.filename, decompiled);
      const scored = scoreBinary({
        behaviors: aiResult.behaviors,
        findings: aiResult.findings,
        importCount: decompiled.imports.length,
        functionCount: decompiled.functionCount
      });

      binaries.push({
        id: `${request.packageName}_${binary.filename}`,
        filename: binary.filename,
        architecture: binary.architecture,
        format: binary.format,
        fileSize: binary.fileSize,
        functionCount: decompiled.functionCount,
        importCount: decompiled.imports.length,
        riskScore: scored.riskScore,
        riskLevel: scored.riskLevel,
        decompiledPreview: decompiled.preview,
        aiExplanation: aiResult.explanation,
        imports: decompiled.imports,
        strings: decompiled.strings,
        behaviors: aiResult.behaviors,
        findings: aiResult.findings
      });
    }

    const aggregate = aggregatePackageRisk(binaries);

    return {
      id: `${request.packageName}_${request.version}`,
      ecosystem: request.ecosystem,
      packageName: request.packageName,
      version: request.version,
      status: "complete",
      riskScore: aggregate.riskScore,
      riskLevel: aggregate.riskLevel,
      summary: binaries[0]?.aiExplanation ?? "No binaries discovered.",
      sourceMatchConfidence: "medium",
      binaryCount: binaries.length,
      totalBinarySize: binaries.reduce((total, binary) => total + binary.fileSize, 0),
      aiModel: "claude-simulated",
      createdAt: new Date().toISOString(),
      binaries
    };
  }
}
