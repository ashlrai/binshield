/**
 * Install-script threat ruleset.
 *
 * Heuristic, deterministic, network-free pattern matching for JavaScript /
 * Python / shell install-script source — the vector used by npm/PyPI
 * supply-chain worms (malicious postinstall hooks, setup.py code). This is the
 * source-text counterpart of the binary YARA ruleset in `yara-scanner.ts`.
 *
 * Rules are intentionally conservative: bare `process.env` or a lone
 * `child_process` import is not flagged — only patterns that are genuinely
 * abnormal for a package's install phase.
 */

import type { FindingSeverity, ScriptThreatCategory } from "@binshield/analysis-types";

export interface ScriptPatternRule {
  id: string;
  category: ScriptThreatCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  recommendation: string;
  /** Patterns to test. Defined without the `g` flag so `.exec` stays stateless. */
  patterns: RegExp[];
  /** Minimum distinct patterns that must match for the rule to fire. */
  minMatches: number;
}

export const SCRIPT_PATTERN_RULES: ScriptPatternRule[] = [
  {
    id: "remote-shell-pipe",
    category: "remoteCodeExecution",
    severity: "critical",
    title: "Remote payload piped into a shell",
    description:
      "Downloads a remote resource and pipes it straight into a shell or runtime interpreter, executing attacker-controlled code during installation.",
    recommendation: "Treat this package as malicious. Do not install it and report it to the registry.",
    patterns: [
      /\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:sudo\s+)?(?:ba|z|d|a|c)?sh\b/i,
      /\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:node|python[23]?|perl|ruby)\b/i,
      /\biwr\b[^\n|]{0,240}\|\s*iex\b/i,
      /Invoke-WebRequest[^\n]{0,240}\|\s*Invoke-Expression/i
    ],
    minMatches: 1
  },
  {
    id: "remote-fetch-eval",
    category: "remoteCodeExecution",
    severity: "critical",
    title: "Remote code fetched and evaluated",
    description:
      "Fetches a remote resource and evaluates it with eval(), Function(), or vm — the staged-payload pattern of supply-chain malware.",
    recommendation: "Treat this package as malicious. Block installation immediately.",
    patterns: [
      /eval\s*\(\s*(?:await\s+)?(?:fetch|require\s*\(\s*['"]https?:)/i,
      /new\s+Function\s*\([^)]{0,120}(?:fetch|https?:\/\/|atob)/i,
      /exec\s*\(\s*(?:await\s+)?(?:requests?\.(?:get|post)|urllib|urlopen)/i,
      /(?:vm\.runInNewContext|vm\.runInThisContext)\s*\([^)]{0,80}(?:fetch|http)/i
    ],
    minMatches: 1
  },
  {
    id: "shell-exec-in-install",
    category: "scriptInjection",
    severity: "high",
    title: "Shell command execution",
    description:
      "Spawns a shell or child process. Legitimate for build steps (node-gyp) but a common malware primitive when combined with network or environment access.",
    recommendation: "Confirm every spawned command is a known build tool and not attacker-controlled.",
    patterns: [
      /child_process['"]?\s*\)?\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile)\s*\(/i,
      /\brequire\s*\(\s*['"]child_process['"]\s*\)/i,
      /\bos\.system\s*\(/i,
      /\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(/i,
      /\bos\.popen\s*\(/i
    ],
    minMatches: 1
  },
  {
    id: "dynamic-code-eval",
    category: "scriptInjection",
    severity: "medium",
    title: "Dynamic code evaluation",
    description: "Evaluates strings as code (eval / Function / exec / compile), which can hide malicious behavior from static review.",
    recommendation: "Review what is being evaluated; dynamic evaluation is rarely needed in an install script.",
    patterns: [
      /\beval\s*\(/i,
      /new\s+Function\s*\(/i,
      /\b(?:exec|compile)\s*\(\s*(?:["'`]|[A-Za-z_])/,
      /\bGLOBAL\b|\bglobalThis\s*\[/i
    ],
    minMatches: 1
  },
  {
    id: "env-secret-harvest",
    category: "environmentTheft",
    severity: "high",
    title: "Sensitive environment variable access",
    description:
      "Reads named credentials from the environment (npm/registry tokens, cloud keys, CI secrets). Install scripts have no legitimate need for these.",
    recommendation: "Block installation. Rotate any credentials exposed to the install environment.",
    patterns: [
      /\b(?:NPM_TOKEN|NPM_AUTH_TOKEN|NODE_AUTH_TOKEN)\b/,
      /\bAWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)\b/,
      /\b(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN)\b/,
      /\b(?:STRIPE_SECRET_KEY|TWILIO_AUTH_TOKEN|SLACK_TOKEN|DIGITALOCEAN_TOKEN)\b/
    ],
    minMatches: 1
  },
  {
    id: "env-enumeration",
    category: "environmentTheft",
    severity: "high",
    title: "Bulk environment variable enumeration",
    description: "Serializes or enumerates the entire process environment — a common precursor to credential exfiltration.",
    recommendation: "Block installation; enumerating all environment variables in an install hook is not legitimate.",
    patterns: [
      /JSON\.stringify\s*\(\s*process\.env\b/i,
      /Object\.(?:keys|entries|values|assign)\s*\(\s*\{?\s*\.{0,3}\s*process\.env\b/i,
      /\{\s*\.\.\.\s*process\.env\s*\}/i,
      /\bdict\s*\(\s*os\.environ\s*\)|\bos\.environ\.copy\s*\(\)|json\.dumps\s*\(\s*dict\s*\(\s*os\.environ/i
    ],
    minMatches: 1
  },
  {
    id: "credential-file-access",
    category: "environmentTheft",
    severity: "high",
    title: "Credential file access",
    description: "Reads on-disk credential stores (.npmrc, SSH keys, cloud credentials, browser/crypto-wallet data).",
    recommendation: "Block installation. An install script reading credential files is exfiltration behavior.",
    patterns: [
      /\.npmrc\b|\.pypirc\b/,
      /\.ssh\/(?:id_(?:rsa|ed25519|ecdsa)|authorized_keys)/i,
      /\.aws\/credentials|\.config\/gcloud|\.kube\/config/i,
      /(?:wallet\.dat|keystore|\.ethereum|\.electrum|Local Storage\/leveldb|\.config\/solana)/i
    ],
    minMatches: 1
  },
  {
    id: "exfil-endpoint",
    category: "environmentTheft",
    severity: "high",
    title: "Exfiltration endpoint",
    description: "Posts data to a webhook, paste service, or tunnel endpoint commonly used to receive stolen secrets.",
    recommendation: "Block installation and inspect what data is sent to the external endpoint.",
    patterns: [
      /discord(?:app)?\.com\/api\/webhooks/i,
      /hooks\.slack\.com|api\.telegram\.org\/bot/i,
      /(?:pastebin\.com|paste\.ee|pastes?\.io|transfer\.sh|0x0\.st)/i,
      /\b[a-z0-9-]+\.(?:ngrok\.(?:io|app)|burpcollaborator\.net|interactsh\.com|oast\.(?:fun|live|site|pro))\b/i
    ],
    minMatches: 1
  },
  {
    id: "filesystem-wiper",
    category: "wiper",
    severity: "critical",
    title: "Destructive filesystem operation",
    description: "Recursively deletes or overwrites files outside the package directory — destructive-payload behavior.",
    recommendation: "Treat this package as malicious. Do not install it.",
    patterns: [
      /\brm\s+-[rRfd]{1,3}[a-zA-Z]*\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$)|~|\$HOME|\/\*|\/root|\/home)/i,
      /fs\.(?:rm|rmdir|rmSync)\s*\([^)]{0,160}recursive\s*:\s*true/i,
      /shutil\.rmtree\s*\(\s*(?:os\.path\.expanduser\(['"]~|['"]\/)/i,
      /\b(?:del|rd)\s+\/[sqf]\b|format\s+[a-z]:|mkfs\.|dd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\//i
    ],
    minMatches: 1
  },
  {
    id: "reverse-shell",
    category: "reverseShell",
    severity: "critical",
    title: "Reverse shell",
    description: "Opens an interactive shell back to a remote host, granting an attacker remote control of the install machine.",
    recommendation: "Treat this package as malicious. Do not install it and report it to the registry.",
    patterns: [
      /(?:ba|z|c)?sh\s+-i\s+(?:>|&)?[^\n]{0,40}\/dev\/tcp\//i,
      /\bnc(?:at)?\b[^\n]{0,80}(?:-e|--exec|-c)\b[^\n]{0,40}(?:ba|z|c)?sh/i,
      /socket\.socket\([^)]*\)[^\n]{0,400}(?:dup2|os\.dup2|subprocess)/i,
      /net\.(?:connect|createConnection)\s*\([^)]{0,120}\)[^\n]{0,200}child_process/i
    ],
    minMatches: 1
  },
  {
    id: "obfuscated-blob",
    category: "obfuscation",
    severity: "medium",
    title: "Obfuscated or encoded payload",
    description: "Contains large encoded blobs or character-code construction used to hide a payload from static review.",
    recommendation: "Decode and review the hidden content before trusting this package.",
    patterns: [
      /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/]{120,}={0,2}['"]\s*,\s*['"]base64['"]/i,
      /\batob\s*\(\s*['"][A-Za-z0-9+/]{120,}/i,
      /(?:String\.fromCharCode\s*\(\s*\d[\d,\s]{60,})/i,
      /(?:\\x[0-9a-f]{2}){24,}|(?:\\u[0-9a-f]{4}){16,}/i
    ],
    minMatches: 1
  },
  {
    id: "obfuscated-base64-exec",
    category: "remoteCodeExecution",
    severity: "high",
    title: "Encoded payload decoded and executed",
    description: "Decodes a base64 / hex blob and immediately executes or evaluates it — staged malware hiding its true payload.",
    recommendation: "Treat this package as malicious until the decoded payload is proven benign.",
    patterns: [
      /(?:eval|exec|Function|child_process)[^\n]{0,80}(?:atob|Buffer\.from|base64\.b64decode)/i,
      /base64\.b64decode\s*\([^)]{0,80}\)[^\n]{0,40}(?:exec|eval|compile)/i,
      /(?:atob|Buffer\.from)[^\n]{0,80}(?:eval|new\s+Function|child_process)/i
    ],
    minMatches: 1
  },
  {
    id: "crypto-miner",
    category: "remoteCodeExecution",
    severity: "high",
    title: "Cryptocurrency miner",
    description: "References cryptocurrency-mining infrastructure — a common monetization payload for compromised packages.",
    recommendation: "Block installation; the package bundles or downloads a cryptocurrency miner.",
    patterns: [/stratum\+tcp:\/\//i, /\bxmrig\b|cryptonight|\bminerd\b/i, /pool\.(?:minexmr|supportxmr|nanopool)\./i],
    minMatches: 1
  },
  {
    id: "process-persistence",
    category: "scriptInjection",
    severity: "high",
    title: "Persistence mechanism",
    description: "Installs a cron job, systemd unit, or shell-profile hook so code keeps running after installation.",
    recommendation: "Block installation; install scripts should not register background persistence.",
    patterns: [
      /\bcrontab\s+-|\/etc\/cron\.|\/etc\/systemd\/system\//i,
      />>\s*~?\/?\.(?:bashrc|zshrc|bash_profile|profile)\b/i,
      /\bLaunchAgents\b|\bLaunchDaemons\b/,
      /reg\s+add\b[^\n]{0,80}\\Run\b/i
    ],
    minMatches: 1
  }
];

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export interface PatternHit {
  rule: ScriptPatternRule;
  matchedPatterns: number;
  evidence: string;
}

const SECRET_LIKE: RegExp[] = [
  /\b(?:xai|sk|pk|rk|ghp|gho|ghu|ghs|ghr|github_pat|npm|AKIA|ASIA)[-_][A-Za-z0-9_-]{12,}/g,
  /\bBearer\s+[A-Za-z0-9._-]{16,}/gi,
  /\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b[A-Fa-f0-9]{40,}\b/g
];

/** Truncate and scrub token-like strings from an evidence snippet before it is persisted or surfaced. */
export function redactEvidence(snippet: string): string {
  let cleaned = snippet.replace(/\s+/g, " ").trim();
  for (const pattern of SECRET_LIKE) {
    cleaned = cleaned.replace(pattern, "[REDACTED]");
  }
  if (cleaned.length > 240) {
    cleaned = `${cleaned.slice(0, 240)}…`;
  }
  return cleaned;
}

/** Return the source line containing the character at `index`. */
function lineAt(text: string, index: number): string {
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);
  return text.slice(start, end === -1 ? undefined : end);
}

/**
 * Evaluate every rule against a block of script source. Returns one hit per
 * rule whose `minMatches` threshold is met, with a redacted evidence snippet.
 */
export function evaluateScriptPatterns(text: string): PatternHit[] {
  if (!text) {
    return [];
  }

  const hits: PatternHit[] = [];
  for (const rule of SCRIPT_PATTERN_RULES) {
    let matched = 0;
    let evidence = "";

    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      const result = pattern.exec(text);
      if (result) {
        matched += 1;
        if (!evidence) {
          evidence = redactEvidence(lineAt(text, result.index));
        }
      }
    }

    if (matched >= rule.minMatches) {
      hits.push({ rule, matchedPatterns: matched, evidence });
    }
  }

  return hits;
}
