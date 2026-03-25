import type { Ecosystem } from "./types";

const VALID_ECOSYSTEMS: readonly string[] = ["npm", "pypi", "crates", "go"];
const VALID_REPORT_TYPES: readonly string[] = ["soc2", "iso27001", "cra", "custom"];
const VALID_CHANNELS: readonly string[] = ["email", "slack", "webhook"];
const VALID_ROLES: readonly string[] = ["admin", "member", "viewer"];

export function validateEcosystem(value: string): value is Ecosystem {
  return VALID_ECOSYSTEMS.includes(value);
}

export function validateVersion(value: string): boolean {
  return /^v?\d+\.\d+\.\d+/.test(value) && value.length <= 128;
}

export function validatePagination(
  limitRaw: unknown,
  offsetRaw: unknown,
): { limit: number; offset: number } | string {
  const limit = Number(limitRaw ?? 20);
  const offset = Number(offsetRaw ?? 0);
  if (!Number.isFinite(limit) || limit < 1 || limit > 100) return "limit must be 1-100";
  if (!Number.isFinite(offset) || offset < 0) return "offset must be >= 0";
  return { limit: Math.floor(limit), offset: Math.floor(offset) };
}

export function validateReportType(value: string): boolean {
  return VALID_REPORT_TYPES.includes(value);
}

export function validateChannel(value: string): boolean {
  return VALID_CHANNELS.includes(value);
}

export function validateRole(value: string): boolean {
  return VALID_ROLES.includes(value);
}

export function validateEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

export function validateStringLength(
  value: unknown,
  field: string,
  max: number,
): string | null {
  if (typeof value !== "string") return `${field} must be a string`;
  if (value.length === 0) return `${field} must not be empty`;
  if (value.length > max) return `${field} must be at most ${max} characters`;
  return null;
}

/**
 * Detect lockfile format from filename and content.
 * Returns null for unrecognized formats.
 */
export function detectLockfileFormat(
  filename: string,
  content: string,
): "npm" | "yarn-v1" | "yarn-berry" | "pnpm" | null {
  const basename = filename.split("/").pop() ?? filename;

  if (basename === "pnpm-lock.yaml") return "pnpm";
  if (basename === "package-lock.json" || basename === "npm-shrinkwrap.json") return "npm";
  if (basename === "yarn.lock") {
    return content.includes("__metadata:") || content.includes('"__metadata"')
      ? "yarn-berry"
      : "yarn-v1";
  }

  // Content-based fallback for ambiguous filenames
  try {
    const parsed = JSON.parse(content);
    if (parsed.lockfileVersion !== undefined) return "npm";
  } catch {
    if (content.startsWith("lockfileVersion:")) return "pnpm";
    if (content.includes("# yarn lockfile")) return "yarn-v1";
  }

  return null;
}
