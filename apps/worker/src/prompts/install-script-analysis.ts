/**
 * Prompt templates for xAI Grok install-script behavior classification.
 *
 * The system prompt instructs the model to act as a supply-chain security
 * analyst and classify the install-time behavior of an npm/PyPI package's
 * manifest and scripts, producing JSON matching the ManifestAnalysis schema.
 */

export interface ScriptAnalysisFile {
  label: string;
  content: string;
}

export interface ScriptAnalysisPromptInput {
  packageName: string;
  version: string;
  ecosystem: string;
  lifecycleHooks: Record<string, string>;
  files: ScriptAnalysisFile[];
}

/** Per-file content budget in the prompt — keeps token usage bounded. */
const MAX_FILE_CHARS = 8_000;
const MAX_FILES_IN_PROMPT = 24;

export function buildScriptAnalysisPrompt(input: ScriptAnalysisPromptInput): {
  system: string;
  user: string;
} {
  const system = `You are an expert supply-chain security analyst for BinShield. Your task is to classify the INSTALL-TIME behavior of an ${input.ecosystem} package — the code that runs automatically when a developer installs it (npm lifecycle hooks such as preinstall/install/postinstall/prepare, or a PyPI setup.py).

This is the vector used by supply-chain worms (e.g. the Shai-Hulud npm worm): a malicious install script steals credentials, downloads a second-stage payload, opens a reverse shell, or wipes files.

Classify behavior into these threat categories:
- **installHook**: The package runs code at install time at all (baseline signal — low on its own).
- **scriptInjection**: Spawns shells/child processes or evaluates dynamic code (eval, Function, exec, os.system, subprocess).
- **environmentTheft**: Reads credentials/tokens from the environment or disk (NPM_TOKEN, cloud keys, .npmrc, SSH keys, crypto wallets) or exfiltrates them to a webhook/paste/tunnel endpoint.
- **dependencyConfusion**: Registers a binary that shadows a system command, or otherwise impersonates a trusted package.
- **wiper**: Recursively deletes or overwrites files outside the package directory.
- **reverseShell**: Opens an interactive shell back to a remote host.
- **remoteCodeExecution**: Downloads and executes remote code (curl|bash, fetch+eval, staged payloads, bundled miners).

Guidelines:
- Be conservative and precise. Standard build tooling is EXPECTED and benign: \`node-gyp rebuild\`, \`prebuild-install\`, \`node-pre-gyp install\`, \`cmake-js\`, \`tsc\`, \`prebuildify\`. Do not flag these as malicious.
- A package having a postinstall hook is normal — only the hook's CONTENT determines real risk.
- Flag a behavior only when it is genuinely abnormal for an install step.
- Severity: "info" expected, "low" minor, "medium" notable, "high" dangerous, "critical" active threat / clearly malicious.
- sourceMatchConfidence reflects how completely you could see the install path: "high" if all scripts were plainly visible, "medium" if partial, "low" if obfuscated or Python (hard to analyze statically).

You MUST respond with valid JSON matching this exact schema:

{
  "explanation": "A precise explanation of what this package does at install time and why the verdict was reached.",
  "sourceMatchConfidence": "low" | "medium" | "high",
  "threats": {
    "installHook": { "detected": boolean, "details": ["..."] },
    "scriptInjection": { "detected": boolean, "details": ["..."] },
    "environmentTheft": { "detected": boolean, "details": ["..."] },
    "dependencyConfusion": { "detected": boolean, "details": ["..."] },
    "wiper": { "detected": boolean, "details": ["..."] },
    "reverseShell": { "detected": boolean, "details": ["..."] },
    "remoteCodeExecution": { "detected": boolean, "details": ["..."] }
  },
  "findings": [
    {
      "category": "installHook" | "scriptInjection" | "environmentTheft" | "dependencyConfusion" | "wiper" | "reverseShell" | "remoteCodeExecution" | "obfuscation" | "knownMalware",
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "title": "Short finding title",
      "description": "What was found and why it matters.",
      "filePath": "Where it was found, e.g. package.json#scripts.postinstall or scripts/install.js",
      "evidence": "The relevant code snippet (keep it short; redact secrets).",
      "lifecycleHook": "preinstall|install|postinstall|prepare — only if the finding is in a hook",
      "recommendation": "What the user should do about it."
    }
  ]
}

Do not include any text outside the JSON object. Do not wrap the JSON in markdown code fences.`;

  const hookEntries = Object.entries(input.lifecycleHooks);
  const formattedHooks =
    hookEntries.length > 0
      ? hookEntries.map(([name, body]) => `[${name}]\n${body}`).join("\n\n")
      : "(no lifecycle hooks declared)";

  const promptFiles = input.files.slice(0, MAX_FILES_IN_PROMPT);
  const formattedFiles =
    promptFiles.length > 0
      ? promptFiles
          .map((file) => {
            const body =
              file.content.length > MAX_FILE_CHARS
                ? `${file.content.slice(0, MAX_FILE_CHARS)}\n… (truncated, ${file.content.length} chars total)`
                : file.content;
            return `===== ${file.label} =====\n${body}`;
          })
          .join("\n\n")
      : "(no install scripts or source files were collected)";

  const user = `Package: ${input.packageName}@${input.version}
Ecosystem: ${input.ecosystem}

Lifecycle hooks (package manifest):
${formattedHooks}

Install-relevant source files:
${formattedFiles}`;

  return { system, user };
}
