/**
 * Trusted-package allowlist for install-script analysis.
 *
 * These are well-known packages whose install scripts are expected to run
 * build tooling (typically `node-gyp rebuild` or equivalent). When a package
 * on this list emits only the baseline "Package runs install-time scripts"
 * installHook finding (severity: low), we demote it to `info` severity so
 * routine native-addon build noise doesn't pollute the risk dashboard.
 *
 * CRITICAL RULE: This allowlist ONLY quiets the benign-installHook baseline.
 * It NEVER suppresses:
 *   - High/critical findings from pattern-rule hits
 *   - Typosquat findings (dependencyConfusion / typosquat source)
 *   - knownMalware findings
 * Those must always surface regardless of allowlist status.
 */

import type { FindingSeverity, ScriptFinding } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Allowlisted packages — curated set of well-known native addons and build
// tools that legitimately run install scripts.
// ---------------------------------------------------------------------------

export const TRUSTED_PACKAGES: ReadonlySet<string> = new Set([
  // Native addon build toolchain
  "node-gyp",
  "node-pre-gyp",
  "prebuild",
  "prebuild-install",
  "node-addon-api",
  "nan",
  "bindings",

  // SQLite bindings — always run node-gyp
  "sqlite3",
  "better-sqlite3",
  "sql.js",

  // Image processing
  "sharp",
  "canvas",
  "node-canvas",
  "jimp",

  // Crypto / argon
  "argon2",
  "bcrypt",
  "bcryptjs",

  // Native fs / io
  "fsevents",
  "chokidar",
  "graceful-fs",
  "klaw",

  // Compression (native bindings)
  "zlib",
  "lz4",
  "snappy",

  // Database native drivers
  "pg",
  "pg-native",
  "mysql",
  "mysql2",
  "oracledb",
  "tedious",

  // gRPC / protobuf
  "@grpc/grpc-js",
  "grpc",
  "protobufjs",

  // Serialisation (native)
  "msgpackr",
  "cbor",
  "flatbuffers",

  // Networking
  "node-libcurl",
  "node-fetch",
  "undici",

  // Misc well-known native addons
  "ref-napi",
  "ffi-napi",
  "kerberos",
  "cpu-features",
  "ssh2",
  "node-pty",
  "serialport",
  "@serialport/stream",
  "usb",
  "usbdetect",

  // Build helpers that only invoke node-gyp
  "node-gyp-build",
  "@mapbox/node-pre-gyp",

  // Monorepo tooling that runs postinstall for setup
  "husky",
  "is-ci",

  // TypeScript / transpilation helpers
  "esbuild",
  "tsx",
  "ts-node",

  // Test runners (some have postinstall for binary fetches — Playwright, etc.)
  "playwright",
  "playwright-core",
  "@playwright/test",
  "puppeteer",
  "puppeteer-core",
  "cypress"
]);

// ---------------------------------------------------------------------------
// Allowlist check
// ---------------------------------------------------------------------------

/** Return true if `packageName` is on the trusted allowlist. */
export function isTrustedPackage(packageName: string): boolean {
  if (!packageName) return false;
  return TRUSTED_PACKAGES.has(packageName.toLowerCase());
}

// ---------------------------------------------------------------------------
// Severity demotion
// ---------------------------------------------------------------------------

/**
 * Demote installHook findings for allowlisted packages.
 *
 * ONLY demotes findings where:
 *   - `category === "installHook"` AND
 *   - `severity` is "low" or "medium" (the benign-baseline severity range)
 *
 * High/critical findings, typosquat / dependencyConfusion findings triggered
 * by the name check, knownMalware, and all other categories are left untouched.
 */
export function applyTrustedPackageDemotion(
  findings: ScriptFinding[],
  packageName: string
): ScriptFinding[] {
  if (!isTrustedPackage(packageName)) {
    return findings;
  }

  return findings.map((finding) => {
    // Only touch the benign-baseline installHook finding (low/medium).
    // Never suppress high/critical, knownMalware, dependencyConfusion, or
    // any other category — those fire for real malicious content and must
    // remain visible even for allowlisted packages.
    if (
      finding.category === "installHook" &&
      (finding.severity === "low" || finding.severity === "medium")
    ) {
      const demoted: ScriptFinding = {
        ...finding,
        severity: "info" as FindingSeverity,
        description:
          finding.description +
          " [Severity demoted: package is on the trusted allowlist of known-benign native addons.]"
      };
      return demoted;
    }
    return finding;
  });
}
