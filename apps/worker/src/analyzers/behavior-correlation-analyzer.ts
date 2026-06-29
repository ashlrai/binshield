/**
 * BehaviorCorrelationAnalyzer — coordinated attack pattern detector
 *
 * Unlike single-signal analyzers (YARA rules, string signatures), this
 * analyzer detects *combinations* of malicious behaviors that together
 * indicate a coordinated, sophisticated attack. The core insight is that
 * sophisticated malware is designed to look innocuous in any single
 * dimension — it is the correlation across dimensions that reveals intent.
 *
 * Attack profiles covered:
 *   1. Exfiltration + C2      — credential-stealing APIs + network beacon strings
 *   2. Persistence + Wiper    — registry/file persistence APIs + deletion patterns
 *   3. Injection + Spawn      — process injection APIs + process creation APIs
 *   4. Crypto Stealing        — wallet address patterns + crypto-library imports
 *
 * Scoring:
 *   Each profile scores [0, 1] based on how many of its constituent signal
 *   groups are present. A profile with confidence > 0.7 fires `detected: true`
 *   and emits a human-readable signal describing the attack chain.
 *
 * Analyzer name: "behavior-correlation"
 * CLI flag:      --analyzers=behavior-correlation
 */

import type { BehaviorSummary, Finding, FindingSeverity } from "@binshield/analysis-types";
import type { AnalysisResult, MalwareAnalyzer } from "../malware-analyzer.js";
import type { FingerprintedArtifact } from "../types.js";

const BEHAVIOR_CORRELATION_VERSION = "1.0.0";

/** Confidence threshold above which a profile is considered detected. */
const DETECTION_THRESHOLD = 0.7;

// ---------------------------------------------------------------------------
// Signal-group definitions
// Each group is a list of patterns; the group "fires" when at least one
// pattern in the list matches the combined string content of the artifact.
// ---------------------------------------------------------------------------

/** Returns true if any pattern in the list matches the text. */
function anyMatch(patterns: RegExp[], text: string): boolean {
  return patterns.some((p) => p.test(text));
}

// --- Exfiltration + C2 ---

const CREDENTIAL_STEALING_APIS: RegExp[] = [
  /LsaRetrievePrivateData/i,
  /LsaOpenPolicy/i,
  /SamQueryInformationUser/i,
  /CryptUnprotectData/i,
  /CryptAcquireContext/i,
  /NtlmHashEntryNative/i,
  /MiniDumpWriteDump/i,
  /ReadProcessMemory/i,
  /NtReadVirtualMemory/i,
  /getpwuid/i,
  /getspnam/i,
  // Browser credential DB
  /sqlite3_open/i,
];

const NETWORK_BEACON_STRINGS: RegExp[] = [
  // Winsock network APIs
  /\bWSAStartup\b/,
  /\bconnect\s*\(/,
  /\bsend\s*\(/,
  /\brecv\s*\(/,
  /\bsocket\s*\(/,
  // curl/wget style exfil
  /exfil/i,
  /\bcurl\b.*https?:\/\//i,
  /discord(?:app)?\.com\/api\/webhooks/i,
  /hooks\.slack\.com/i,
  /api\.telegram\.org\/bot/i,
  // Raw network socket creation (POSIX)
  /\bAF_INET\b/,
  /\bSOCK_STREAM\b/,
];

// --- Persistence + Wiper ---

const PERSISTENCE_APIS: RegExp[] = [
  // Windows registry persistence
  /RegSetValueEx/i,
  /RegCreateKey/i,
  /RegOpenKey/i,
  /HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
  /HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/i,
  // Startup folder / scheduled task
  /schtasks/i,
  /at\.exe/i,
  /Startup\\/i,
  // POSIX crontab / rc.local
  /crontab/i,
  /rc\.local/i,
  /\.bash_profile/i,
  /\.bashrc/i,
  /systemd.*enable/i,
];

const FILE_DELETION_PATTERNS: RegExp[] = [
  // Windows shadow copy / backup destruction
  /vssadmin\s+delete\s+shadows/i,
  /wbadmin\s+delete/i,
  /bcdedit.*recoveryenabled\s+no/i,
  // Secure wipe / overwrite
  /\bDeleteFileW?\b/i,
  /\bRemoveDirectoryW?\b/i,
  /shred\s+-/i,
  /rm\s+-rf\b/i,
  /unlink\s*\(/,
  // Extension-appending ransomware pattern
  /\.encrypted/i,
  /\.locked/i,
  /\.crypt$/i,
];

// --- Injection + Process Spawn ---

const INJECTION_APIS: RegExp[] = [
  /CreateRemoteThread/i,
  /CreateRemoteThreadEx/i,
  /NtCreateThreadEx/i,
  /RtlCreateUserThread/i,
  /WriteProcessMemory/i,
  /NtWriteVirtualMemory/i,
  /VirtualAllocEx/i,
  /NtAllocateVirtualMemory/i,
  /SetWindowsHookEx/i,
  /QueueUserAPC/i,
  /NtQueueApcThread/i,
  // POSIX injection
  /\bptrace\b/,
  /process_vm_writev/i,
  /dlopen\s*\(/,
];

const PROCESS_SPAWN_APIS: RegExp[] = [
  // Windows process creation
  /CreateProcess/i,
  /CreateProcessAsUser/i,
  /ShellExecute/i,
  /WinExec/i,
  /NtCreateProcess/i,
  // POSIX process creation
  /\bfork\s*\(\s*\)/,
  /\bexecve?\s*\(/,
  /\bexeclp?\s*\(/,
  /\bpopen\s*\(/,
  /\bsystem\s*\(/,
  // Scripting engine spawn
  /cmd\.exe/i,
  /powershell/i,
];

// --- Crypto Stealing ---

const CRYPTO_WALLET_PATTERNS: RegExp[] = [
  // Bitcoin address (Base58, bech32)
  /\b(?:1[A-HJ-NP-Za-km-z1-9]{25,34}|3[A-HJ-NP-Za-km-z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/,
  // Ethereum
  /\b0x[a-fA-F0-9]{40}\b/,
  // Monero
  /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/,
  // Generic wallet-related strings
  /wallet\.dat/i,
  /keystore.*ethereum/i,
  /mnemonic(?:\s+phrase)?/i,
  /seed phrase/i,
  /private key/i,
];

const CRYPTO_LIBRARY_IMPORTS: RegExp[] = [
  /libcrypto/i,
  /openssl/i,
  /BCryptOpenAlgorithmProvider/i,
  /CryptAcquireContext/i,
  /CryptEncrypt/i,
  /CryptDecrypt/i,
  // Blockchain / wallet libraries
  /libbitcoin/i,
  /bitcoin.*core/i,
  /go-ethereum/i,
  /web3/i,
  /ethers/i,
  /monero.*wallet/i,
];

// ---------------------------------------------------------------------------
// Attack profile definitions
// ---------------------------------------------------------------------------

interface AttackProfile {
  /** Short identifier for the profile. */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Severity of findings when this profile fires. */
  severity: FindingSeverity;
  /** BehaviorSummary key this maps to. */
  behaviorCategory: keyof BehaviorSummary;
  /**
   * Signal groups. Each entry is a pair: [label, patterns].
   * The profile score = (number of groups that fire) / (total groups).
   */
  signalGroups: Array<{ label: string; patterns: RegExp[] }>;
  /** Human-readable description of what correlated risk this profile indicates. */
  signalDescription(matchedGroups: string[]): string;
}

const ATTACK_PROFILES: AttackProfile[] = [
  {
    id: "CORR_ExfilC2",
    name: "Exfiltration + C2",
    severity: "critical",
    behaviorCategory: "dataExfiltration",
    signalGroups: [
      { label: "credential-stealing APIs", patterns: CREDENTIAL_STEALING_APIS },
      { label: "network beacon / exfil strings", patterns: NETWORK_BEACON_STRINGS },
    ],
    signalDescription: (groups) =>
      `Exfiltration + C2 pattern detected (${groups.join(", ")}); ` +
      "credential-stealing API combined with network exfil — high risk of data theft"
  },
  {
    id: "CORR_PersistWiper",
    name: "Persistence + Wiper",
    severity: "critical",
    behaviorCategory: "filesystem",
    signalGroups: [
      { label: "persistence APIs / registry writes", patterns: PERSISTENCE_APIS },
      { label: "file deletion / wiper patterns", patterns: FILE_DELETION_PATTERNS },
    ],
    signalDescription: (groups) =>
      `Persistence + wiper pattern detected (${groups.join(", ")}); ` +
      "registry/boot persistence combined with file-deletion — ransomware or destructive malware risk"
  },
  {
    id: "CORR_InjectSpawn",
    name: "Injection + Process Spawn",
    severity: "critical",
    behaviorCategory: "process",
    signalGroups: [
      { label: "process injection APIs", patterns: INJECTION_APIS },
      { label: "process spawn / execution APIs", patterns: PROCESS_SPAWN_APIS },
    ],
    signalDescription: (groups) =>
      `Injection + process spawning pattern detected (${groups.join(", ")}); ` +
      "memory injection combined with process creation — credential stealing / privilege escalation risk"
  },
  {
    id: "CORR_CryptoStealing",
    name: "Crypto Stealing",
    severity: "high",
    behaviorCategory: "crypto",
    signalGroups: [
      { label: "cryptocurrency wallet address patterns", patterns: CRYPTO_WALLET_PATTERNS },
      { label: "crypto library imports", patterns: CRYPTO_LIBRARY_IMPORTS },
    ],
    signalDescription: (groups) =>
      `Crypto-stealing pattern detected (${groups.join(", ")}); ` +
      "wallet address combined with crypto-library imports — cryptocurrency theft risk"
  }
];

// ---------------------------------------------------------------------------
// Analyzer implementation
// ---------------------------------------------------------------------------

/**
 * Profile evaluation result.
 */
interface ProfileEvaluation {
  profile: AttackProfile;
  /** Fraction of signal groups that fired [0, 1]. */
  score: number;
  /** Labels of groups that fired. */
  matchedGroupLabels: string[];
  /** Whether this profile exceeds the detection threshold. */
  detected: boolean;
}

function evaluateProfile(profile: AttackProfile, text: string): ProfileEvaluation {
  const matchedGroupLabels: string[] = [];

  for (const group of profile.signalGroups) {
    if (anyMatch(group.patterns, text)) {
      matchedGroupLabels.push(group.label);
    }
  }

  const score = profile.signalGroups.length === 0
    ? 0
    : matchedGroupLabels.length / profile.signalGroups.length;

  return {
    profile,
    score,
    matchedGroupLabels,
    detected: score > DETECTION_THRESHOLD
  };
}

export class BehaviorCorrelationAnalyzer implements MalwareAnalyzer {
  name(): string {
    return "behavior-correlation";
  }

  version(): string {
    return BEHAVIOR_CORRELATION_VERSION;
  }

  async analyze(artifact: FingerprintedArtifact): Promise<AnalysisResult> {
    // Combine all string sources into one block for matching.
    const combined = [...artifact.strings, ...artifact.interestingStrings].join("\n");

    const findings: Finding[] = [];
    const behaviorSignals: Partial<BehaviorSummary> = {};
    const matchedProfileIds: string[] = [];
    const profileScores: Record<string, number> = {};

    for (const profile of ATTACK_PROFILES) {
      const evaluation = evaluateProfile(profile, combined);
      profileScores[profile.id] = evaluation.score;

      if (!evaluation.detected) continue;

      matchedProfileIds.push(profile.id);

      const signalText = profile.signalDescription(evaluation.matchedGroupLabels);

      findings.push({
        severity: profile.severity,
        title: `BehaviorCorrelation: ${profile.id}`,
        description: signalText,
        location: artifact.filename,
        recommendation:
          `Correlated ${profile.name} attack pattern detected with ` +
          `${(evaluation.score * 100).toFixed(0)}% signal strength. ` +
          "Treat as high-sophistication malware; investigate all matched signal groups and block execution."
      });

      // Update behavior signals.
      const key = profile.behaviorCategory;
      const existing = behaviorSignals[key];
      if (existing) {
        existing.details.push(`BehaviorCorrelation: ${profile.id}`);
      } else {
        (behaviorSignals as Record<string, unknown>)[key] = {
          detected: true,
          details: [`BehaviorCorrelation: ${profile.id}`]
        };
      }
    }

    // Confidence: max profile score among detected profiles,
    // or max overall score when nothing fires.
    const scores = Object.values(profileScores);
    const maxScore = scores.length > 0 ? Math.max(...scores) : 0;
    const confidence = matchedProfileIds.length > 0 ? maxScore : Math.min(maxScore, 0.4);

    return {
      analyzerName: this.name(),
      analyzerVersion: this.version(),
      findings,
      behaviorSignals,
      confidence,
      metadata: {
        matchedProfileIds,
        profileScores
      }
    };
  }
}
