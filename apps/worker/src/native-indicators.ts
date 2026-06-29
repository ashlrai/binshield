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
 * Python native extension file extensions (.so, .pyd on Windows, .dylib on macOS).
 * Also matches CPython ABI-tagged filenames like `_ssl.cpython-311-x86_64-linux-gnu.so`.
 */
export const PYTHON_NATIVE_EXTENSIONS = [".so", ".pyd", ".dylib"];

/**
 * Regex matching CPython ABI tags embedded in wheel filenames.
 * Examples:
 *   numpy-1.26.4-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
 *   cryptography-41.0.5-cp311-cp311-linux_x86_64.whl
 *
 * The tag format is: {python}-{abi}-{platform}
 * where python starts with "cp" (CPython), "pp" (PyPy), or "cp3" etc.
 */
export const PYPI_ABI_TAG_RE =
  /-(cp\d+|pp\d+|cp3\d*|py\d+)-(cp\d+|abi3|none)-(linux_\w+|manylinux[\w.]+|musllinux_\w+|macosx_[\w.]+|win\w*|aarch64|x86_64)\./i;

/**
 * Returns true if a wheel filename contains a CPython/PyPy ABI tag indicating
 * it ships compiled native extensions for a specific platform.
 */
export function hasPyPiAbiTag(filename: string): boolean {
  return PYPI_ABI_TAG_RE.test(filename);
}

/**
 * Returns true if a file path looks like a Python native extension binary
 * (.so / .pyd / .dylib), optionally with a CPython ABI suffix such as
 * `_ssl.cpython-311-x86_64-linux-gnu.so`.
 */
export function isPythonNativeExtension(filename: string): boolean {
  const ext = filename.toLowerCase();
  if (PYTHON_NATIVE_EXTENSIONS.some((e) => ext.endsWith(e))) return true;
  // Match CPython ABI-tagged shared objects: foo.cpython-311-x86_64-linux-gnu.so
  if (/\.cpython-\d+-[\w-]+\.so$/i.test(filename)) return true;
  // Match PyPy ABI-tagged: foo.pypy311-pp73-x86_64-linux-gnu.so
  if (/\.pypy\d+-pp\d+-[\w-]+\.so$/i.test(filename)) return true;
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

/** npm lifecycle hooks that execute automatically during `npm install`. */
export const AUTO_RUN_LIFECYCLE_HOOKS = ["preinstall", "install", "postinstall", "prepare"];

/**
 * Check if a package declares install-time lifecycle scripts. These execute
 * code automatically on `npm install` and are the npm supply-chain worm
 * vector — worth analyzing even when the package ships no native binary.
 */
export function hasInstallScripts(pkg: { scripts?: Record<string, string> }): boolean {
  if (!pkg.scripts) {
    return false;
  }
  return AUTO_RUN_LIFECYCLE_HOOKS.some((hook) => {
    const body = pkg.scripts?.[hook];
    return typeof body === "string" && body.trim().length > 0;
  });
}
