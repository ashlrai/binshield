/**
 * Shared native binary detection logic.
 *
 * Used by the discovery engine, lockfile scanner, and feed follower
 * to determine if an npm package contains native binaries.
 */

/** Known packages that contain native binaries. */
export const KNOWN_NATIVE_PACKAGES = new Set([
  "bcrypt", "argon2", "sodium-native", "keytar", "sharp", "canvas",
  "@napi-rs/image", "better-sqlite3", "sqlite3", "pg-native", "lmdb",
  "leveldown", "rocksdb", "duckdb", "libsql", "esbuild", "@swc/core",
  "lightningcss", "@biomejs/biome", "node-sass", "fsevents", "turbo",
  "zeromq", "grpc", "ssh2", "node-pty", "serialport", "usb", "node-hid",
  "ffi-napi", "ref-napi", "cpu-features", "systeminformation",
  "@tensorflow/tfjs-node", "onnxruntime-node", "re2", "oniguruma",
  "msgpackr", "snappy", "lz4", "node-zstd", "zlib-sync",
  "ffmpeg-static", "@discordjs/opus", "node-opus", "speaker",
  "node-canvas", "gl", "headless-gl", "node-addon-api",
  "cld", "node-webrtc", "unix-dgram", "bufferutil", "utf-8-validate",
]);

/** Dependency names that indicate native addon compilation. */
export const NATIVE_BUILD_DEPS = new Set([
  "node-gyp", "node-pre-gyp", "prebuild-install", "prebuild",
  "node-gyp-build", "@mapbox/node-pre-gyp", "cmake-js",
  "napi-rs", "node-addon-api", "nan",
]);

/** Prefixes that indicate platform-specific binary distribution packages. */
export const PLATFORM_PREFIXES = [
  "@esbuild/", "@swc/core-", "@rollup/rollup-", "@biomejs/cli-",
  "lightningcss-", "@napi-rs/", "turbo-", "@parcel/watcher-",
  "@next/swc-", "@tailwindcss/oxide-",
];

/** Suffixes that indicate platform-specific packages. */
export const PLATFORM_SUFFIXES = [
  "-linux-x64-gnu", "-linux-arm64-gnu", "-darwin-arm64", "-darwin-x64",
  "-win32-x64-msvc", "-linux-x64-musl", "-linux-arm64-musl",
  "-freebsd-x64", "-android-arm64",
];

/**
 * Check if a package name or its dependencies indicate native binaries.
 */
export function isNativePackage(name: string, dependencies?: Record<string, string>): boolean {
  if (KNOWN_NATIVE_PACKAGES.has(name)) return true;
  if (PLATFORM_PREFIXES.some((prefix) => name.startsWith(prefix))) return true;
  if (PLATFORM_SUFFIXES.some((suffix) => name.endsWith(suffix))) return true;
  if (dependencies) {
    for (const dep of Object.keys(dependencies)) {
      if (NATIVE_BUILD_DEPS.has(dep)) return true;
    }
  }
  return false;
}

/**
 * Check if a package.json has native binary indicators.
 */
export function hasNativeIndicators(pkg: {
  name: string;
  gypfile?: boolean;
  files?: string[];
  binary?: Record<string, unknown>;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}): boolean {
  if (isNativePackage(pkg.name)) return true;
  if (pkg.gypfile) return true;
  if (pkg.files?.some((f) => f === "binding.gyp" || f.endsWith("/binding.gyp"))) return true;
  if (pkg.binary) return true;

  const allDeps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies };
  for (const dep of Object.keys(allDeps)) {
    if (NATIVE_BUILD_DEPS.has(dep)) return true;
  }

  const installScript = pkg.scripts?.install ?? pkg.scripts?.postinstall ?? "";
  if (/node-gyp|prebuild|cmake-js|napi/i.test(installScript)) return true;

  return false;
}
