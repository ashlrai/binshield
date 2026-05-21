import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export interface BinShieldConfig {
  apiKey?: string;
  apiUrl?: string;
}

export const CONFIG_DIR = join(homedir(), ".binshield");
export const CONFIG_FILE = join(CONFIG_DIR, "config.json");
export const DEFAULT_API_URL = "https://api.binshield.dev";

export function readConfig(): BinShieldConfig {
  if (!existsSync(CONFIG_FILE)) return {};

  try {
    const raw = readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(raw) as BinShieldConfig;
  } catch {
    return {};
  }
}

export function writeConfig(config: BinShieldConfig): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }

  const path = CONFIG_FILE;
  writeFileSync(path, JSON.stringify(config, null, 2) + "\n", {
    encoding: "utf-8",
    mode: 0o600,
  });

  // Ensure mode is 600 even on systems where writeFileSync ignores mode
  try {
    chmodSync(path, 0o600);
  } catch {
    // Best-effort
  }
}

/**
 * Resolve the API key using the precedence chain:
 *   CLI flag → BINSHIELD_API_KEY env var → ~/.binshield/config.json
 */
export function resolveApiKey(flagValue?: string): string | undefined {
  return flagValue ?? process.env.BINSHIELD_API_KEY ?? readConfig().apiKey;
}

/**
 * Resolve the API base URL using the precedence chain:
 *   CLI flag → BINSHIELD_API_URL env var → ~/.binshield/config.json → production default
 */
export function resolveApiUrl(flagValue?: string): string {
  return (
    flagValue ??
    process.env.BINSHIELD_API_URL ??
    readConfig().apiUrl ??
    DEFAULT_API_URL
  );
}
