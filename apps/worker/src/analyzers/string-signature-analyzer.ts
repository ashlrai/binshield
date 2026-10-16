/**
 * StringSignatureAnalyzer — fast regex-based string signature scanner
 *
 * Provides a lightweight, zero-dependency scanner for common malware string
 * indicators that do not require YARA or script-pattern parsing. Covers:
 *   • Cryptominer strings (stratum+tcp, xmrig, pool endpoints, hashrate)
 *   • Botnet C&C domains and infrastructure (known bad TLDs, DGA patterns)
 *   • Known malware family indicators (Mirai, Emotet, TrickBot, Cobalt Strike,
 *     Sliver, njRAT, AsyncRAT, Lazarus/APT indicators)
 *   • Credential harvesting (cloud service token patterns, SSH key exfil)
 *   • Suspicious process injection APIs
 *   • Anti-sandbox / anti-analysis evasion strings
 *
 * The analyzer name "string-sig" maps to the `--analyzers=string-sig` CLI flag.
 *
 * Performance: O(N × M) where N = combined string length and M = rule count.
 * All patterns use compiled RegExp objects (no `g` flag) so `.test()` is
 * stateless and safe for concurrent calls.
 */

import type { BehaviorSummary, Finding, FindingSeverity } from "@binshield/analysis-types";
import type { AnalysisResult, MalwareAnalyzer } from "../malware-analyzer.js";
import type { FingerprintedArtifact } from "../types.js";

const STRING_SIG_VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// Signature rule type
// ---------------------------------------------------------------------------

interface StringSignatureRule {
  id: string;
  description: string;
  severity: FindingSeverity;
  /** At least one of these must match for the rule to fire. */
  patterns: RegExp[];
  /** Minimum number of patterns that must match (default 1). */
  minMatches: number;
  /** BehaviorSummary key this finding maps to. */
  behaviorCategory?: keyof BehaviorSummary;
  recommendation: string;
}

// ---------------------------------------------------------------------------
// Signature rules
// ---------------------------------------------------------------------------

const STRING_SIGNATURE_RULES: StringSignatureRule[] = [
  // ── Cryptominers ──────────────────────────────────────────────────────────
  {
    id: "SS_CryptoMiner_Stratum",
    description: "Stratum mining protocol endpoint present in binary strings",
    severity: "critical",
    patterns: [/stratum\+tcp:\/\//i, /stratum\+ssl:\/\//i, /stratum\+tls:\/\//i],
    minMatches: 1,
    behaviorCategory: "network",
    recommendation: "Binary contains mining protocol strings. Treat as cryptominer and remove immediately."
  },
  {
    id: "SS_CryptoMiner_XMRig",
    description: "XMRig or Monero mining indicators in binary strings",
    severity: "critical",
    patterns: [/xmrig/i, /monero[- _]wallet/i, /xmr\.pool\./i, /coinhive\.com/i, /cryptonight/i, /--donate-level/i],
    minMatches: 1,
    behaviorCategory: "crypto",
    recommendation: "Binary references XMRig / Monero mining components. Remove and investigate infection vector."
  },
  {
    id: "SS_CryptoMiner_Generic",
    description: "Generic cryptocurrency mining strings",
    severity: "high",
    patterns: [
      /mining[- _]pool/i,
      /hashrate[^a-z]/i,
      /getwork\b/i,
      /ethash/i,
      /kawpow/i,
      /nicehash\.com/i,
      /2miners\.com/i,
      /nanopool\.org/i
    ],
    minMatches: 2,
    behaviorCategory: "crypto",
    recommendation: "Multiple cryptocurrency mining indicators detected. Verify binary is not a cryptominer."
  },

  // ── Botnet C&C / known bad infrastructure ─────────────────────────────────
  {
    id: "SS_Botnet_MiraiStrings",
    description: "Mirai botnet family string indicators",
    severity: "critical",
    patterns: [
      /mirai/i,
      /\/bin\/busybox\s+MIRAI/,
      /table_unlock_val/i,
      /scanner_init/i,
      /attack_kill_all/i
    ],
    minMatches: 1,
    behaviorCategory: "network",
    recommendation: "Binary contains Mirai botnet strings. Treat as actively malicious."
  },
  {
    id: "SS_Botnet_DGA",
    description: "Potential domain generation algorithm (DGA) or hardcoded C&C domain patterns",
    severity: "high",
    patterns: [
      /[a-z]{8,16}\.(tk|ml|ga|cf|gq)(?:\/|$)/i,
      /[a-z]{12,20}\.xyz(?:\/|$)/i,
      /[a-z]{8,18}\.top\/[a-z0-9]{4,}/i,
      /\b(?:185\.|91\.|194\.|45\.|23\.)\d{1,3}\.\d{1,3}\.\d{1,3}\/[a-z0-9]{4,}/i
    ],
    minMatches: 1,
    behaviorCategory: "network",
    recommendation: "Binary references suspicious domain patterns consistent with DGA or C&C infrastructure."
  },
  {
    id: "SS_Botnet_IRC_CC",
    description: "IRC-based botnet C&C channel strings",
    severity: "high",
    patterns: [
      /PRIVMSG\s+#[a-z0-9_-]+\s+:/i,
      /JOIN\s+#[a-z0-9_-]+\s+:/i,
      /irc\..*\.(net|org|ru|cc)\b/i,
      /bot\.?nick\b/i
    ],
    minMatches: 2,
    behaviorCategory: "network",
    recommendation: "Binary contains IRC botnet communication patterns."
  },

  // ── Known malware families ────────────────────────────────────────────────
  {
    id: "SS_Malware_CobaltStrike",
    description: "Cobalt Strike beacon / stager string indicators",
    severity: "critical",
    patterns: [
      /cobalt.?strike/i,
      /beacon\.(?:dll|exe|bin)/i,
      /ReflectiveLoader/i,
      /MeterPreter/i,
      /cs\.profile/i,
      /malleable.*c2/i
    ],
    minMatches: 1,
    behaviorCategory: "process",
    recommendation: "Binary contains Cobalt Strike indicators. Treat as active intrusion tooling."
  },
  {
    id: "SS_Malware_Sliver",
    description: "Sliver C2 framework string indicators",
    severity: "critical",
    patterns: [
      /sliver[- _](?:implant|server|client)/i,
      /sliverarmory\.com/i,
      /\bsliver\b.*(?:mtls|wg|dns|https)/i
    ],
    minMatches: 1,
    behaviorCategory: "network",
    recommendation: "Binary contains Sliver C2 framework indicators. Treat as active intrusion tooling."
  },
  {
    id: "SS_Malware_AsyncRAT",
    description: "AsyncRAT / njRAT remote access trojan string indicators",
    severity: "critical",
    patterns: [
      /AsyncRAT/i,
      /njRAT/i,
      /QuasarRAT/i,
      /DCRat/i,
      /NjW0rm/i,
      /GhostRAT/i,
      /RemcosRAT/i
    ],
    minMatches: 1,
    behaviorCategory: "network",
    recommendation: "Binary contains RAT family strings. Treat as remote access trojan."
  },
  {
    id: "SS_Malware_Emotet_TrickBot",
    description: "Emotet / TrickBot banking trojan string indicators",
    severity: "critical",
    patterns: [
      /emotet/i,
      /trickbot/i,
      /bazarloader/i,
      /qakbot/i,
      /icedid/i,
      /SystemBC/i
    ],
    minMatches: 1,
    behaviorCategory: "dataExfiltration",
    recommendation: "Binary contains banking trojan indicators. Isolate and investigate immediately."
  },
  {
    id: "SS_Malware_Lazarus",
    description: "Lazarus Group / APT38 malware string indicators",
    severity: "critical",
    patterns: [
      /\bLazarus\b/i,
      /AppleJeus/i,
      /BlindingCan/i,
      /MATA[- _]framework/i,
      /DTrack/i
    ],
    minMatches: 1,
    behaviorCategory: "dataExfiltration",
    recommendation: "Binary contains APT38/Lazarus Group indicators. Escalate to security team immediately."
  },

  // ── Credential harvesting ─────────────────────────────────────────────────
  {
    id: "SS_CredHarvest_CloudTokens",
    description: "Cloud provider credential or token exfiltration strings",
    severity: "high",
    patterns: [
      /AKIA[0-9A-Z]{16}/,          // AWS access key prefix
      /AIza[0-9A-Za-z_-]{35}/,     // GCP API key prefix
      /ya29\.[0-9A-Za-z_-]{68,}/,  // GCP OAuth token
      /ghp_[A-Za-z0-9]{36}/,       // GitHub personal access token
      /ghs_[A-Za-z0-9]{36}/        // GitHub service account token
    ],
    minMatches: 1,
    behaviorCategory: "dataExfiltration",
    recommendation: "Binary contains embedded cloud credential patterns. Rotate credentials and investigate."
  },
  {
    id: "SS_CredHarvest_SSHExfil",
    description: "SSH private key or authorized_keys exfiltration",
    severity: "high",
    patterns: [
      /BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY/i,
      /\.ssh\/authorized_keys/i,
      /\.ssh\/id_(?:rsa|ecdsa|ed25519)/i,
      /ssh-keygen.*-f/i
    ],
    minMatches: 1,
    behaviorCategory: "dataExfiltration",
    recommendation: "Binary references SSH key material. Investigate for credential theft."
  },

  // ── Anti-analysis / anti-sandbox evasion ──────────────────────────────────
  {
    id: "SS_AntiAnalysis_VmDetect",
    description: "Virtual machine or sandbox detection strings",
    severity: "medium",
    patterns: [
      /vmware/i,
      /VirtualBox/i,
      /SbieDll\.dll/i,     // Sandboxie
      /wine_get_version/i, // Wine
      /VBOX_E_/i,
      /\bHaRu_Dbg\b/i
    ],
    minMatches: 2,
    behaviorCategory: "obfuscation",
    recommendation: "Binary attempts to detect analysis environments. Indicates evasive malware."
  },
  {
    id: "SS_AntiAnalysis_DebuggerDetect",
    description: "Debugger detection API or string indicators",
    severity: "medium",
    patterns: [
      /IsDebuggerPresent/i,
      /CheckRemoteDebuggerPresent/i,
      /NtQueryInformationProcess/i,
      /OutputDebugString/i,
      /anti[- _]?debug/i
    ],
    minMatches: 2,
    behaviorCategory: "obfuscation",
    recommendation: "Binary performs debugger detection. Likely contains hidden malicious logic."
  },

  // ── Ransomware indicators ─────────────────────────────────────────────────
  {
    id: "SS_Ransomware_Indicators",
    description: "Ransomware behavior string indicators",
    severity: "critical",
    patterns: [
      /Your files have been encrypted/i,
      /Send Bitcoin to/i,
      /\.onion.*decrypt/i,
      /ransom(?:note|demand|ware)/i,
      /CryptEncrypt.*CryptDecrypt/i,
      /vssadmin\s+delete\s+shadows/i
    ],
    minMatches: 1,
    behaviorCategory: "filesystem",
    recommendation: "Binary contains ransomware strings. Do not execute; isolate and report."
  },

  // ── Supply-chain specific indicators ─────────────────────────────────────
  {
    id: "SS_SupplyChain_PackageHijack",
    description: "Package manager credential or registry token theft strings",
    severity: "critical",
    patterns: [
      /\.npmrc/i,
      /NPM_TOKEN/i,
      /PYPI_TOKEN/i,
      /registry\.npmjs\.org.*authToken/i,
      /npm login.*--auth-type/i
    ],
    minMatches: 2,
    behaviorCategory: "dataExfiltration",
    recommendation: "Binary attempts to steal package manager credentials. Block and investigate supply-chain compromise."
  }
];

// ---------------------------------------------------------------------------
// Analyzer implementation
// ---------------------------------------------------------------------------

export class StringSignatureAnalyzer implements MalwareAnalyzer {
  name(): string {
    return "string-sig";
  }

  version(): string {
    return STRING_SIG_VERSION;
  }

  async analyze(artifact: FingerprintedArtifact): Promise<AnalysisResult> {
    // Combine all string sources into one block for matching.
    const combined = [...artifact.strings, ...artifact.interestingStrings].join("\n");

    const findings: Finding[] = [];
    const behaviorSignals: Partial<BehaviorSummary> = {};
    const matchedRuleIds: string[] = [];

    for (const rule of STRING_SIGNATURE_RULES) {
      let matchCount = 0;
      for (const pattern of rule.patterns) {
        if (pattern.test(combined)) {
          matchCount++;
          if (matchCount >= rule.minMatches) break;
        }
      }

      if (matchCount < rule.minMatches) continue;

      matchedRuleIds.push(rule.id);

      findings.push({
        severity: rule.severity,
        title: `StringSig: ${rule.id}`,
        description: rule.description,
        location: artifact.filename,
        recommendation: rule.recommendation
      });

      // Update behavior signals.
      if (rule.behaviorCategory) {
        const key = rule.behaviorCategory;
        const existing = behaviorSignals[key];
        if (existing) {
          existing.details.push(`StringSig: ${rule.id}`);
        } else {
          (behaviorSignals as Record<string, unknown>)[key] = {
            detected: true,
            details: [`StringSig: ${rule.id}`]
          };
        }
      }
    }

    return {
      analyzerName: this.name(),
      analyzerVersion: this.version(),
      findings,
      behaviorSignals,
      confidence: matchedRuleIds.length > 0 ? 0.8 : 0.5,
      metadata: {
        matchedRuleCount: matchedRuleIds.length,
        matchedRuleIds
      }
    };
  }
}
