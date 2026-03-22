import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export interface BinShieldConfig {
  apiKey?: string;
  apiUrl?: string;
}

const CONFIG_DIR = join(homedir(), ".binshield");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

export function readConfig(): BinShieldConfig {
  if (!existsSync(CONFIG_FILE)) {
    return {};
  }

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

  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2) + "\n", {
    encoding: "utf-8",
    mode: 0o600,
  });
}

/**
 * Resolve the API key from environment variable or config file.
 * Environment variable takes precedence.
 */
export function resolveApiKey(): string | undefined {
  return process.env.BINSHIELD_API_KEY ?? readConfig().apiKey;
}

/**
 * Resolve the API base URL from environment variable or config file.
 * Falls back to the production default.
 */
export function resolveApiUrl(): string {
  return (
    process.env.BINSHIELD_API_URL ??
    readConfig().apiUrl ??
    "https://api.binshield.dev"
  );
}
