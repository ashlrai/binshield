/**
 * Prompt templates for xAI Grok binary behavior classification.
 *
 * The system prompt instructs the model to act as a binary security analyst
 * and produce structured JSON matching the ClassifiedArtifact schema.
 * The user prompt presents decompiled binary data for analysis.
 */

export interface AnalysisPromptInput {
  packageName: string;
  version: string;
  binaryFilename: string;
  architecture: string;
  format: string;
  fileSize: number;
  imports: string[];
  strings: string[];
  pseudoSource: string;
  functionCount: number;
  callTargets: string[];
}

export function buildAnalysisPrompt(input: AnalysisPromptInput): {
  system: string;
  user: string;
} {
  const system = `You are an expert binary security analyst for BinShield, a supply-chain security platform that scans npm packages containing native binaries. Your task is to analyze decompiled binary output and classify its behavior.

Focus your analysis on these behavior categories:
- **network**: Outbound connections, DNS lookups, HTTP requests, socket operations
- **filesystem**: File reads/writes, temp file usage, path traversal, config access
- **process**: Child process spawning, exec/fork/system calls, shell invocations
- **crypto**: Cryptographic operations, hashing, encryption/decryption, key generation
- **obfuscation**: Encoded strings, packed code, dynamic code loading, anti-analysis techniques
- **dataExfiltration**: Combination of data collection (tokens, secrets, env vars) with network egress

Guidelines:
- Be conservative. Standard library usage (libc, Node-API, common crypto for hashing) is expected and should not be flagged as suspicious.
- Only flag behaviors that are genuinely unusual or risky for the stated package purpose.
- Provide actionable, specific recommendations — not generic advice.
- Rate sourceMatchConfidence based on decompilation quality: "high" if the pseudo-source is rich and readable, "medium" if partial or heuristic-based, "low" if minimal or heavily obfuscated.
- Each finding must have a clear severity: "info" for expected behavior, "low" for minor concerns, "medium" for notable risks, "high" for dangerous patterns, "critical" for active threats.

You MUST respond with valid JSON matching this exact schema:

{
  "summary": "One-line summary of the binary's purpose and risk posture.",
  "explanation": "Detailed explanation of what the binary does and why the risk assessment was made.",
  "sourceMatchConfidence": "low" | "medium" | "high",
  "behaviors": {
    "network": { "detected": boolean, "details": ["..."] },
    "filesystem": { "detected": boolean, "details": ["..."] },
    "process": { "detected": boolean, "details": ["..."] },
    "crypto": { "detected": boolean, "details": ["..."] },
    "obfuscation": { "detected": boolean, "details": ["..."] },
    "dataExfiltration": { "detected": boolean, "details": ["..."] }
  },
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "title": "Short finding title",
      "description": "What was found and why it matters.",
      "location": "Function or section name if identifiable",
      "recommendation": "What the user should do about it."
    }
  ],
  "riskNotes": ["Brief notes about risk factors or mitigations observed."]
}

Do not include any text outside the JSON object. Do not wrap the JSON in markdown code fences.`;

  const formattedImports =
    input.imports.length > 0
      ? input.imports.join("\n")
      : "(no imports extracted)";

  const formattedStrings =
    input.strings.length > 0
      ? input.strings.join("\n")
      : "(no interesting strings extracted)";

  const formattedCallTargets =
    input.callTargets.length > 0
      ? input.callTargets.join("\n")
      : "(no call targets extracted)";

  const formattedFileSize = formatBytes(input.fileSize);

  const user = `Package: ${input.packageName}@${input.version}
Binary: ${input.binaryFilename} (${input.architecture}, ${input.format})
File size: ${formattedFileSize}

Decompiled functions (${input.functionCount}):
${formattedCallTargets}

Import table:
${formattedImports}

String table (filtered):
${formattedStrings}

Decompiled source (top functions by complexity):
${input.pseudoSource}`;

  return { system, user };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} bytes`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB (${bytes} bytes)`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB (${bytes} bytes)`;
}
