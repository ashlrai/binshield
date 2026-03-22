/**
 * Top npm packages that ship native binary addons (.node, .so, .dylib, .wasm).
 * Used by the seeding pipeline to pre-populate the public analysis database.
 */

export interface NativePackageEntry {
  name: string;
  description: string;
  category: "crypto" | "image" | "database" | "system" | "compute" | "encoding" | "network";
}

export const nativePackages: NativePackageEntry[] = [
  // Crypto & hashing
  { name: "bcrypt", description: "Password hashing using bcrypt", category: "crypto" },
  { name: "argon2", description: "Argon2 password hashing", category: "crypto" },
  { name: "sodium-native", description: "Libsodium bindings", category: "crypto" },
  { name: "keytar", description: "OS keychain access", category: "crypto" },

  // Image processing
  { name: "sharp", description: "High-performance image processing", category: "image" },
  { name: "canvas", description: "Cairo-backed Canvas implementation", category: "image" },
  { name: "node-screenshots", description: "Cross-platform screenshots", category: "image" },

  // Database
  { name: "sqlite3", description: "SQLite3 bindings", category: "database" },
  { name: "better-sqlite3", description: "Synchronous SQLite3 bindings", category: "database" },
  { name: "pg-native", description: "Native PostgreSQL client", category: "database" },
  { name: "lmdb", description: "Lightning memory-mapped database", category: "database" },

  // System & OS
  { name: "fsevents", description: "macOS file system events", category: "system" },
  { name: "node-pty", description: "Pseudoterminal bindings", category: "system" },
  { name: "cpu-features", description: "CPU feature detection", category: "system" },
  { name: "drivelist", description: "List OS disk drives", category: "system" },
  { name: "usb", description: "USB device access", category: "system" },

  // Compute & ML
  { name: "isolated-vm", description: "Isolated V8 virtual machines", category: "compute" },
  { name: "node-gyp", description: "Native addon build tool", category: "compute" },
  { name: "re2", description: "RE2 regex engine bindings", category: "compute" },

  // Encoding & serialization
  { name: "msgpackr", description: "MessagePack serialization", category: "encoding" },
  { name: "bufferutil", description: "WebSocket buffer utilities", category: "encoding" },
  { name: "utf-8-validate", description: "WebSocket UTF-8 validation", category: "encoding" },

  // Network
  { name: "node-sass", description: "LibSass bindings", category: "network" },
  { name: "ffi-napi", description: "Foreign function interface", category: "system" },
  { name: "ref-napi", description: "Native reference types", category: "system" }
];

export function getPackagesByCategory(category: NativePackageEntry["category"]): NativePackageEntry[] {
  return nativePackages.filter((pkg) => pkg.category === category);
}
