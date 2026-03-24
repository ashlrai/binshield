/**
 * YARA Rule Scanner
 *
 * Scans binary artifacts against YARA rules to detect known malware patterns,
 * suspicious behaviors, and security-relevant indicators.
 *
 * Uses Docker to run YARA in an isolated container, falling back to a
 * built-in heuristic scanner when Docker/YARA is unavailable.
 */

import { execFile } from "node:child_process";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import type { Finding, BehaviorSummary } from "@binshield/analysis-types";
import type { FingerprintedArtifact } from "./types";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Record<string, string>;
  strings: Array<{ identifier: string; offset: number; data: string }>;
}

export interface YaraScanResult {
  matches: YaraMatch[];
  findings: Finding[];
  behaviorSignals: Partial<BehaviorSummary>;
  confidence: number;
}

// ---------------------------------------------------------------------------
// Built-in YARA-style Rules (for when YARA binary is unavailable)
// ---------------------------------------------------------------------------

interface HeuristicRule {
  name: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  tags: string[];
  /** String patterns to match (case-insensitive). */
  patterns: RegExp[];
  /** Minimum number of patterns that must match. */
  minMatches: number;
  /** Behavior category this rule maps to. */
  behaviorCategory?: keyof BehaviorSummary;
}

const HEURISTIC_RULES: HeuristicRule[] = [
  // Crypto mining
  {
    name: "CryptoMiner_Strings",
    description: "Strings associated with cryptocurrency mining",
    severity: "critical",
    tags: ["miner", "malware"],
    patterns: [/stratum\+tcp/i, /xmrig/i, /monero/i, /coinhive/i, /cryptonight/i, /hashrate/i],
    minMatches: 2,
    behaviorCategory: "crypto",
  },
  // Reverse shells
  {
    name: "ReverseShell_Indicators",
    description: "Patterns commonly found in reverse shells",
    severity: "critical",
    tags: ["shell", "backdoor"],
    patterns: [/\/bin\/sh\s*-i/i, /\/bin\/bash\s*-c/i, /socket\(.*SOCK_STREAM/i, /connect\(.*\d+\.\d+\.\d+\.\d+/i, /exec\(.*sh/i],
    minMatches: 2,
    behaviorCategory: "process",
  },
  // Data exfiltration
  {
    name: "DataExfiltration_Patterns",
    description: "Patterns suggesting data exfiltration capabilities",
    severity: "high",
    tags: ["exfiltration"],
    patterns: [/discord\.com\/api\/webhooks/i, /hooks\.slack\.com/i, /telegram\.org\/bot/i, /\.ngrok\./i, /pastebin\.com/i],
    minMatches: 1,
    behaviorCategory: "dataExfiltration",
  },
  // Obfuscation
  {
    name: "Obfuscation_Indicators",
    description: "Binary appears to use obfuscation techniques",
    severity: "medium",
    tags: ["obfuscation", "packer"],
    patterns: [/UPX!/i, /MPRESS/i, /\.enigma/i, /themida/i, /\x00{100,}/],
    minMatches: 1,
    behaviorCategory: "obfuscation",
  },
  // Keylogger patterns
  {
    name: "Keylogger_Strings",
    description: "Strings associated with keylogging",
    severity: "high",
    tags: ["keylogger", "spyware"],
    patterns: [/GetAsyncKeyState/i, /SetWindowsHookEx/i, /keyboard_event/i, /keylog/i],
    minMatches: 2,
  },
  // Environment variable theft
  {
    name: "EnvTheft_Patterns",
    description: "Attempts to read sensitive environment variables",
    severity: "high",
    tags: ["credential-theft"],
    patterns: [/AWS_SECRET_ACCESS_KEY/i, /GITHUB_TOKEN/i, /NPM_TOKEN/i, /DATABASE_URL/i, /PRIVATE_KEY/i, /API_KEY/i],
    minMatches: 3,
    behaviorCategory: "dataExfiltration",
  },
  // Process injection
  {
    name: "ProcessInjection_APIs",
    description: "APIs used for process injection",
    severity: "high",
    tags: ["injection"],
    patterns: [/VirtualAllocEx/i, /WriteProcessMemory/i, /CreateRemoteThread/i, /NtCreateThreadEx/i],
    minMatches: 2,
    behaviorCategory: "process",
  },
  // DNS tunneling
  {
    name: "DNS_Tunneling",
    description: "Indicators of DNS tunneling for C2 communication",
    severity: "high",
    tags: ["c2", "dns"],
    patterns: [/dns.*tunnel/i, /iodine/i, /dnscat/i, /dns2tcp/i],
    minMatches: 1,
    behaviorCategory: "network",
  },
  // Suspicious file operations
  {
    name: "Suspicious_FileOps",
    description: "Suspicious file system operations",
    severity: "medium",
    tags: ["filesystem"],
    patterns: [/\/etc\/passwd/i, /\/etc\/shadow/i, /\.ssh\/id_rsa/i, /\.gnupg/i, /\.aws\/credentials/i, /\.npmrc/i],
    minMatches: 2,
    behaviorCategory: "filesystem",
  },
  // Network reconnaissance
  {
    name: "Network_Recon",
    description: "Network scanning and reconnaissance indicators",
    severity: "medium",
    tags: ["recon", "network"],
    patterns: [/nmap/i, /masscan/i, /port.*scan/i, /SYN_SENT/i],
    minMatches: 1,
    behaviorCategory: "network",
  },
  // Suspicious URLs
  {
    name: "Suspicious_URLs",
    description: "URLs pointing to known malicious infrastructure",
    severity: "medium",
    tags: ["network", "ioc"],
    patterns: [/bit\.ly/i, /tinyurl\.com/i, /t\.co\//i, /raw\.githubusercontent\.com.*\.sh/i],
    minMatches: 1,
    behaviorCategory: "network",
  },
  // Packed/encrypted content
  {
    name: "HighEntropy_Section",
    description: "Sections with very high entropy suggesting encryption or packing",
    severity: "medium",
    tags: ["packer", "encryption"],
    patterns: [/This program cannot be run in DOS mode/i], // PE header (combined with entropy check)
    minMatches: 0, // Uses special entropy check instead
    behaviorCategory: "obfuscation",
  },
];

// ---------------------------------------------------------------------------
// Scanner Implementation
// ---------------------------------------------------------------------------

export class YaraScanner {
  private dockerAvailable: boolean | null = null;

  /**
   * Scan a binary artifact with YARA rules.
   * Attempts Docker-based YARA first, falls back to heuristic patterns.
   */
  async scan(artifact: FingerprintedArtifact): Promise<YaraScanResult> {
    // Try Docker YARA if available
    if (this.dockerAvailable !== false) {
      try {
        return await this.scanWithDocker(artifact);
      } catch {
        this.dockerAvailable = false;
      }
    }

    // Fallback to heuristic scanning
    return this.scanWithHeuristics(artifact);
  }

  /**
   * Run YARA rules via Docker container.
   */
  private async scanWithDocker(artifact: FingerprintedArtifact): Promise<YaraScanResult> {
    const tmpDir = await mkdtemp(path.join(tmpdir(), "binshield-yara-"));
    const binaryPath = path.join(tmpDir, artifact.filename);

    try {
      await writeFile(binaryPath, artifact.bytes);

      const { stdout } = await execFileAsync("docker", [
        "run", "--rm", "--network", "none",
        "--memory", "512m", "--cpus", "1.0",
        "-v", `${tmpDir}:/scan:ro`,
        "blacktop/yara:latest",
        "-r", "/rules/", `/scan/${artifact.filename}`,
        "-j", // JSON output
      ], { timeout: 60000 });

      const matches = this.parseYaraOutput(stdout);
      return this.yaraMatchesToResult(matches, artifact);
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  }

  private parseYaraOutput(output: string): YaraMatch[] {
    const matches: YaraMatch[] = [];
    for (const line of output.trim().split("\n")) {
      if (!line) continue;
      try {
        const parsed = JSON.parse(line) as YaraMatch;
        matches.push(parsed);
      } catch {
        // Try plain text format: "rule_name path"
        const parts = line.split(" ");
        if (parts.length >= 1) {
          matches.push({
            rule: parts[0],
            namespace: "default",
            tags: [],
            meta: {},
            strings: [],
          });
        }
      }
    }
    return matches;
  }

  /**
   * Convert Docker YARA matches to a YaraScanResult.
   */
  private yaraMatchesToResult(matches: YaraMatch[], artifact: FingerprintedArtifact): YaraScanResult {
    const findings: Finding[] = matches.map((m) => {
      const severity = m.tags.includes("malware") || m.tags.includes("backdoor") ? "critical"
        : m.tags.includes("exfiltration") || m.tags.includes("shell") ? "high"
        : m.tags.includes("obfuscation") || m.tags.includes("packer") ? "medium"
        : "low";
      return {
        severity,
        title: `YARA: ${m.rule}`,
        description: m.meta.description ?? `Matched YARA rule ${m.rule}`,
        location: artifact.filename,
        recommendation: "Review this binary for the flagged patterns.",
      };
    });

    return {
      matches,
      findings,
      behaviorSignals: {},
      confidence: matches.length > 0 ? 0.85 : 0.5,
    };
  }

  /**
   * Heuristic pattern scanning (no Docker required).
   * Searches binary strings for patterns defined in HEURISTIC_RULES.
   */
  private scanWithHeuristics(artifact: FingerprintedArtifact): YaraScanResult {
    const allStrings = [...artifact.strings, ...artifact.interestingStrings].join("\n");
    const matchedRules: Array<{ rule: HeuristicRule; matchCount: number }> = [];

    for (const rule of HEURISTIC_RULES) {
      // Special case: entropy check
      if (rule.name === "HighEntropy_Section") {
        const entropy = this.calculateEntropy(artifact.bytes);
        if (entropy > 7.5) {
          matchedRules.push({ rule, matchCount: 1 });
        }
        continue;
      }

      let matchCount = 0;
      for (const pattern of rule.patterns) {
        if (pattern.test(allStrings)) {
          matchCount++;
        }
      }

      if (matchCount >= rule.minMatches) {
        matchedRules.push({ rule, matchCount });
      }
    }

    // Convert matched rules to findings
    const findings: Finding[] = matchedRules.map(({ rule }) => ({
      severity: rule.severity,
      title: `YARA: ${rule.name}`,
      description: rule.description,
      location: artifact.filename,
      recommendation: rule.severity === "critical"
        ? "This binary matches patterns associated with malicious software. Investigate immediately."
        : rule.severity === "high"
          ? "This binary contains suspicious patterns. Review the binary and its source carefully."
          : "Review this binary for potential security concerns.",
    }));

    // Build behavior signals from matched rules
    const behaviorSignals: Partial<BehaviorSummary> = {};
    for (const { rule } of matchedRules) {
      if (rule.behaviorCategory) {
        const existing = behaviorSignals[rule.behaviorCategory] as
          | { detected: boolean; details: string[] }
          | undefined;
        if (existing) {
          existing.details.push(`YARA: ${rule.name}`);
        } else {
          (behaviorSignals as Record<string, unknown>)[rule.behaviorCategory] = {
            detected: true,
            details: [`YARA: ${rule.name}`],
          };
        }
      }
    }

    return {
      matches: matchedRules.map(({ rule }) => ({
        rule: rule.name,
        namespace: "binshield-heuristic",
        tags: rule.tags,
        meta: { description: rule.description },
        strings: [],
      })),
      findings,
      behaviorSignals,
      confidence: matchedRules.length > 0 ? 0.7 : 0.5,
    };
  }

  /**
   * Calculate Shannon entropy of binary data.
   * High entropy (>7.5) suggests encryption, compression, or packing.
   */
  private calculateEntropy(data: Uint8Array): number {
    if (data.length === 0) return 0;

    const freq = new Uint32Array(256);
    for (const byte of data) {
      freq[byte]++;
    }

    let entropy = 0;
    const len = data.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }
}
