/**
 * Curated seed list of known npm packages containing native binaries.
 *
 * Used by the PackageDiscoveryEngine to bootstrap the discovered_packages
 * table without hitting external APIs. Each entry is annotated with a
 * category so enrichment and priority scoring can factor in domain context.
 */

export interface SeedPackage {
  name: string;
  category: string;
  description: string;
  platforms?: string[];
}

export const NATIVE_PACKAGE_SEED_LIST: SeedPackage[] = [
  // ---------------------------------------------------------------------------
  // Crypto & Hashing
  // ---------------------------------------------------------------------------
  { name: "bcrypt", category: "crypto", description: "bcrypt password hashing" },
  { name: "argon2", category: "crypto", description: "Argon2 password hashing" },
  { name: "sodium-native", category: "crypto", description: "libsodium bindings" },
  { name: "keytar", category: "crypto", description: "System keychain access" },
  { name: "node-seal", category: "crypto", description: "Microsoft SEAL homomorphic encryption" },
  { name: "secp256k1", category: "crypto", description: "secp256k1 elliptic curve bindings" },
  { name: "bigint-buffer", category: "crypto", description: "BigInt buffer serialization (native)" },
  { name: "ed25519-supercop", category: "crypto", description: "Ed25519 signatures" },
  { name: "blake3", category: "crypto", description: "BLAKE3 hashing" },
  { name: "@aspect-build/rules_ts", category: "crypto", description: "Aspect TypeScript rules (native)" },

  // ---------------------------------------------------------------------------
  // Image Processing
  // ---------------------------------------------------------------------------
  { name: "sharp", category: "image", description: "High-performance image processing (libvips)" },
  { name: "canvas", category: "image", description: "Cairo-backed Canvas for Node.js" },
  { name: "@napi-rs/image", category: "image", description: "NAPI-RS image processing" },
  { name: "imagemagick-native", category: "image", description: "ImageMagick bindings" },
  { name: "node-images", category: "image", description: "Cross-platform image codec" },
  { name: "lwip", category: "image", description: "Lightweight image processor" },
  { name: "pngquant-bin", category: "image", description: "pngquant binary wrapper" },
  { name: "gifsicle", category: "image", description: "gifsicle binary wrapper" },
  { name: "mozjpeg", category: "image", description: "mozjpeg binary wrapper" },
  { name: "optipng-bin", category: "image", description: "OptiPNG binary wrapper" },
  { name: "cwebp-bin", category: "image", description: "WebP encoder binary" },
  { name: "node-exiftool", category: "image", description: "ExifTool wrapper" },
  { name: "svg2img", category: "image", description: "SVG to image conversion (native)" },
  { name: "pixelmatch", category: "image", description: "Pixel-level image comparison" },
  { name: "pngjs", category: "image", description: "Pure JS PNG (optional native)" },
  { name: "jpeg-js", category: "image", description: "JPEG codec" },
  { name: "probe-image-size", category: "image", description: "Image size detection" },

  // ---------------------------------------------------------------------------
  // Database
  // ---------------------------------------------------------------------------
  { name: "better-sqlite3", category: "database", description: "Fastest SQLite3 binding" },
  { name: "sqlite3", category: "database", description: "Asynchronous SQLite3 bindings" },
  { name: "pg-native", category: "database", description: "Native libpq PostgreSQL driver" },
  { name: "lmdb", category: "database", description: "Lightning Memory-Mapped Database" },
  { name: "leveldown", category: "database", description: "LevelDB binding" },
  { name: "rocksdb", category: "database", description: "RocksDB binding" },
  { name: "hiredis", category: "database", description: "Official Redis C client binding" },
  { name: "duckdb", category: "database", description: "DuckDB embedded analytics DB" },
  { name: "libsql", category: "database", description: "libSQL / Turso native driver" },
  { name: "classic-level", category: "database", description: "LevelDB successor (classic-level)" },
  { name: "lmdb-store", category: "database", description: "LMDB key-value store" },
  { name: "realm", category: "database", description: "Realm mobile database" },
  { name: "ioredis", category: "database", description: "Redis client (optional hiredis)" },
  { name: "mongoclient-native", category: "database", description: "MongoDB native driver layer" },
  { name: "duckdb-async", category: "database", description: "Async DuckDB binding" },
  { name: "sql.js", category: "database", description: "SQLite compiled to WebAssembly" },

  // ---------------------------------------------------------------------------
  // Build Tools & Bundlers
  // ---------------------------------------------------------------------------
  { name: "esbuild", category: "build-tools", description: "Go-based JavaScript bundler" },
  { name: "@swc/core", category: "build-tools", description: "Rust-based JS/TS compiler" },
  { name: "lightningcss", category: "build-tools", description: "Rust-based CSS parser/transformer" },
  { name: "@biomejs/biome", category: "build-tools", description: "Rust linter and formatter" },
  { name: "@parcel/css", category: "build-tools", description: "Parcel CSS transformer" },
  { name: "node-sass", category: "build-tools", description: "LibSass bindings" },
  { name: "fsevents", category: "build-tools", description: "macOS file events (native)" },
  { name: "turbo", category: "build-tools", description: "Turborepo build orchestrator" },

  // esbuild platform packages
  { name: "@esbuild/aix-ppc64", category: "build-tools", description: "esbuild AIX ppc64", platforms: ["aix"] },
  { name: "@esbuild/android-arm", category: "build-tools", description: "esbuild Android ARM", platforms: ["android"] },
  { name: "@esbuild/android-arm64", category: "build-tools", description: "esbuild Android ARM64", platforms: ["android"] },
  { name: "@esbuild/android-x64", category: "build-tools", description: "esbuild Android x64", platforms: ["android"] },
  { name: "@esbuild/darwin-arm64", category: "build-tools", description: "esbuild macOS ARM64", platforms: ["darwin"] },
  { name: "@esbuild/darwin-x64", category: "build-tools", description: "esbuild macOS x64", platforms: ["darwin"] },
  { name: "@esbuild/freebsd-arm64", category: "build-tools", description: "esbuild FreeBSD ARM64", platforms: ["freebsd"] },
  { name: "@esbuild/freebsd-x64", category: "build-tools", description: "esbuild FreeBSD x64", platforms: ["freebsd"] },
  { name: "@esbuild/linux-arm", category: "build-tools", description: "esbuild Linux ARM", platforms: ["linux"] },
  { name: "@esbuild/linux-arm64", category: "build-tools", description: "esbuild Linux ARM64", platforms: ["linux"] },
  { name: "@esbuild/linux-ia32", category: "build-tools", description: "esbuild Linux ia32", platforms: ["linux"] },
  { name: "@esbuild/linux-loong64", category: "build-tools", description: "esbuild Linux loong64", platforms: ["linux"] },
  { name: "@esbuild/linux-mips64el", category: "build-tools", description: "esbuild Linux mips64el", platforms: ["linux"] },
  { name: "@esbuild/linux-ppc64", category: "build-tools", description: "esbuild Linux ppc64", platforms: ["linux"] },
  { name: "@esbuild/linux-riscv64", category: "build-tools", description: "esbuild Linux riscv64", platforms: ["linux"] },
  { name: "@esbuild/linux-s390x", category: "build-tools", description: "esbuild Linux s390x", platforms: ["linux"] },
  { name: "@esbuild/linux-x64", category: "build-tools", description: "esbuild Linux x64", platforms: ["linux"] },
  { name: "@esbuild/netbsd-x64", category: "build-tools", description: "esbuild NetBSD x64", platforms: ["netbsd"] },
  { name: "@esbuild/openbsd-arm64", category: "build-tools", description: "esbuild OpenBSD ARM64", platforms: ["openbsd"] },
  { name: "@esbuild/openbsd-x64", category: "build-tools", description: "esbuild OpenBSD x64", platforms: ["openbsd"] },
  { name: "@esbuild/sunos-x64", category: "build-tools", description: "esbuild SunOS x64", platforms: ["sunos"] },
  { name: "@esbuild/win32-arm64", category: "build-tools", description: "esbuild Windows ARM64", platforms: ["win32"] },
  { name: "@esbuild/win32-ia32", category: "build-tools", description: "esbuild Windows ia32", platforms: ["win32"] },
  { name: "@esbuild/win32-x64", category: "build-tools", description: "esbuild Windows x64", platforms: ["win32"] },

  // SWC platform packages
  { name: "@swc/core-darwin-arm64", category: "build-tools", description: "SWC macOS ARM64", platforms: ["darwin"] },
  { name: "@swc/core-darwin-x64", category: "build-tools", description: "SWC macOS x64", platforms: ["darwin"] },
  { name: "@swc/core-linux-arm-gnueabihf", category: "build-tools", description: "SWC Linux ARM gnueabihf", platforms: ["linux"] },
  { name: "@swc/core-linux-arm64-gnu", category: "build-tools", description: "SWC Linux ARM64 GNU", platforms: ["linux"] },
  { name: "@swc/core-linux-arm64-musl", category: "build-tools", description: "SWC Linux ARM64 musl", platforms: ["linux"] },
  { name: "@swc/core-linux-x64-gnu", category: "build-tools", description: "SWC Linux x64 GNU", platforms: ["linux"] },
  { name: "@swc/core-linux-x64-musl", category: "build-tools", description: "SWC Linux x64 musl", platforms: ["linux"] },
  { name: "@swc/core-win32-arm64-msvc", category: "build-tools", description: "SWC Windows ARM64", platforms: ["win32"] },
  { name: "@swc/core-win32-ia32-msvc", category: "build-tools", description: "SWC Windows ia32", platforms: ["win32"] },
  { name: "@swc/core-win32-x64-msvc", category: "build-tools", description: "SWC Windows x64", platforms: ["win32"] },

  // Rollup platform packages
  { name: "@rollup/rollup-android-arm-eabi", category: "build-tools", description: "Rollup Android ARM", platforms: ["android"] },
  { name: "@rollup/rollup-android-arm64", category: "build-tools", description: "Rollup Android ARM64", platforms: ["android"] },
  { name: "@rollup/rollup-darwin-arm64", category: "build-tools", description: "Rollup macOS ARM64", platforms: ["darwin"] },
  { name: "@rollup/rollup-darwin-x64", category: "build-tools", description: "Rollup macOS x64", platforms: ["darwin"] },
  { name: "@rollup/rollup-freebsd-arm64", category: "build-tools", description: "Rollup FreeBSD ARM64", platforms: ["freebsd"] },
  { name: "@rollup/rollup-freebsd-x64", category: "build-tools", description: "Rollup FreeBSD x64", platforms: ["freebsd"] },
  { name: "@rollup/rollup-linux-arm-gnueabihf", category: "build-tools", description: "Rollup Linux ARM gnueabihf", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-arm-musleabihf", category: "build-tools", description: "Rollup Linux ARM musleabihf", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-arm64-gnu", category: "build-tools", description: "Rollup Linux ARM64 GNU", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-arm64-musl", category: "build-tools", description: "Rollup Linux ARM64 musl", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-loong64-gnu", category: "build-tools", description: "Rollup Linux loong64 GNU", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-powerpc64le-gnu", category: "build-tools", description: "Rollup Linux ppc64le GNU", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-riscv64-gnu", category: "build-tools", description: "Rollup Linux riscv64 GNU", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-s390x-gnu", category: "build-tools", description: "Rollup Linux s390x GNU", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-x64-gnu", category: "build-tools", description: "Rollup Linux x64 GNU", platforms: ["linux"] },
  { name: "@rollup/rollup-linux-x64-musl", category: "build-tools", description: "Rollup Linux x64 musl", platforms: ["linux"] },
  { name: "@rollup/rollup-win32-arm64-msvc", category: "build-tools", description: "Rollup Windows ARM64", platforms: ["win32"] },
  { name: "@rollup/rollup-win32-ia32-msvc", category: "build-tools", description: "Rollup Windows ia32", platforms: ["win32"] },
  { name: "@rollup/rollup-win32-x64-msvc", category: "build-tools", description: "Rollup Windows x64", platforms: ["win32"] },

  // Biome platform packages
  { name: "@biomejs/cli-darwin-arm64", category: "build-tools", description: "Biome CLI macOS ARM64", platforms: ["darwin"] },
  { name: "@biomejs/cli-darwin-x64", category: "build-tools", description: "Biome CLI macOS x64", platforms: ["darwin"] },
  { name: "@biomejs/cli-linux-arm64", category: "build-tools", description: "Biome CLI Linux ARM64", platforms: ["linux"] },
  { name: "@biomejs/cli-linux-arm64-musl", category: "build-tools", description: "Biome CLI Linux ARM64 musl", platforms: ["linux"] },
  { name: "@biomejs/cli-linux-x64", category: "build-tools", description: "Biome CLI Linux x64", platforms: ["linux"] },
  { name: "@biomejs/cli-linux-x64-musl", category: "build-tools", description: "Biome CLI Linux x64 musl", platforms: ["linux"] },
  { name: "@biomejs/cli-win32-arm64", category: "build-tools", description: "Biome CLI Windows ARM64", platforms: ["win32"] },
  { name: "@biomejs/cli-win32-x64", category: "build-tools", description: "Biome CLI Windows x64", platforms: ["win32"] },

  // LightningCSS platform packages
  { name: "lightningcss-darwin-arm64", category: "build-tools", description: "LightningCSS macOS ARM64", platforms: ["darwin"] },
  { name: "lightningcss-darwin-x64", category: "build-tools", description: "LightningCSS macOS x64", platforms: ["darwin"] },
  { name: "lightningcss-freebsd-x64", category: "build-tools", description: "LightningCSS FreeBSD x64", platforms: ["freebsd"] },
  { name: "lightningcss-linux-arm-gnueabihf", category: "build-tools", description: "LightningCSS Linux ARM gnueabihf", platforms: ["linux"] },
  { name: "lightningcss-linux-arm64-gnu", category: "build-tools", description: "LightningCSS Linux ARM64 GNU", platforms: ["linux"] },
  { name: "lightningcss-linux-arm64-musl", category: "build-tools", description: "LightningCSS Linux ARM64 musl", platforms: ["linux"] },
  { name: "lightningcss-linux-x64-gnu", category: "build-tools", description: "LightningCSS Linux x64 GNU", platforms: ["linux"] },
  { name: "lightningcss-linux-x64-musl", category: "build-tools", description: "LightningCSS Linux x64 musl", platforms: ["linux"] },
  { name: "lightningcss-win32-arm64-msvc", category: "build-tools", description: "LightningCSS Windows ARM64", platforms: ["win32"] },
  { name: "lightningcss-win32-x64-msvc", category: "build-tools", description: "LightningCSS Windows x64", platforms: ["win32"] },

  // Turbo platform packages
  { name: "turbo-darwin-64", category: "build-tools", description: "Turbo macOS x64", platforms: ["darwin"] },
  { name: "turbo-darwin-arm64", category: "build-tools", description: "Turbo macOS ARM64", platforms: ["darwin"] },
  { name: "turbo-linux-64", category: "build-tools", description: "Turbo Linux x64", platforms: ["linux"] },
  { name: "turbo-linux-arm64", category: "build-tools", description: "Turbo Linux ARM64", platforms: ["linux"] },
  { name: "turbo-windows-64", category: "build-tools", description: "Turbo Windows x64", platforms: ["win32"] },
  { name: "turbo-windows-arm64", category: "build-tools", description: "Turbo Windows ARM64", platforms: ["win32"] },

  // ---------------------------------------------------------------------------
  // NAPI-RS ecosystem
  // ---------------------------------------------------------------------------
  { name: "@napi-rs/canvas", category: "image", description: "NAPI-RS canvas (Skia)" },
  { name: "@napi-rs/snappy", category: "compression", description: "NAPI-RS snappy compression" },
  { name: "@napi-rs/bcrypt", category: "crypto", description: "NAPI-RS bcrypt" },
  { name: "@napi-rs/crc32", category: "crypto", description: "NAPI-RS CRC32" },
  { name: "@napi-rs/jieba", category: "text-processing", description: "NAPI-RS Chinese text segmentation" },
  { name: "@napi-rs/pinyin", category: "text-processing", description: "NAPI-RS pinyin conversion" },
  { name: "@napi-rs/clipboard", category: "system", description: "NAPI-RS clipboard access" },
  { name: "@napi-rs/lzma", category: "compression", description: "NAPI-RS LZMA compression" },
  { name: "@napi-rs/tar", category: "compression", description: "NAPI-RS tar archive" },
  { name: "@napi-rs/keyring", category: "security", description: "NAPI-RS keyring access" },

  // ---------------------------------------------------------------------------
  // Compression
  // ---------------------------------------------------------------------------
  { name: "zlib-sync", category: "compression", description: "Synchronous zlib bindings" },
  { name: "snappy", category: "compression", description: "Google Snappy compression" },
  { name: "lz4", category: "compression", description: "LZ4 compression bindings" },
  { name: "brotli-wasm", category: "compression", description: "Brotli in WebAssembly" },
  { name: "zstd-codec", category: "compression", description: "Zstandard compression" },
  { name: "node-zstd", category: "compression", description: "Zstandard native bindings" },
  { name: "minizip-asm", category: "compression", description: "Minizip in asm.js/wasm" },
  { name: "lz4-napi", category: "compression", description: "LZ4 via NAPI" },
  { name: "node-lz4", category: "compression", description: "LZ4 native bindings" },
  { name: "@aspect-build/rules_js", category: "compression", description: "Aspect JS rules (native)" },
  { name: "fast-zlib", category: "compression", description: "Fast zlib compression" },

  // ---------------------------------------------------------------------------
  // Networking
  // ---------------------------------------------------------------------------
  { name: "zeromq", category: "networking", description: "ZeroMQ messaging library" },
  { name: "@grpc/grpc-js", category: "networking", description: "gRPC for Node.js" },
  { name: "grpc", category: "networking", description: "gRPC native bindings (deprecated)" },
  { name: "node-libcurl", category: "networking", description: "libcurl bindings" },
  { name: "ssh2", category: "networking", description: "SSH2 client/server" },
  { name: "dns-packet", category: "networking", description: "DNS packet encoder/decoder" },
  { name: "bufferutil", category: "networking", description: "WebSocket buffer utilities (native)" },
  { name: "utf-8-validate", category: "networking", description: "WebSocket UTF-8 validation (native)" },
  { name: "node-datachannel", category: "networking", description: "WebRTC DataChannel" },
  { name: "uws", category: "networking", description: "uWebSockets native binding" },

  // ---------------------------------------------------------------------------
  // Audio & Video
  // ---------------------------------------------------------------------------
  { name: "fluent-ffmpeg", category: "audio-video", description: "FFmpeg command builder" },
  { name: "ffmpeg-static", category: "audio-video", description: "Static FFmpeg binary" },
  { name: "node-opus", category: "audio-video", description: "Opus audio codec" },
  { name: "@discordjs/opus", category: "audio-video", description: "Opus for Discord.js" },
  { name: "speaker", category: "audio-video", description: "PCM audio output" },
  { name: "node-wav", category: "audio-video", description: "WAV audio read/write" },
  { name: "node-webrtc", category: "audio-video", description: "WebRTC native implementation" },
  { name: "prism-media", category: "audio-video", description: "Media transcoding for Discord" },
  { name: "node-lame", category: "audio-video", description: "LAME MP3 encoder bindings" },
  { name: "ffprobe-static", category: "audio-video", description: "Static ffprobe binary" },
  { name: "@vscode/vscode-languagedetection", category: "audio-video", description: "VSCode language detection" },
  { name: "sodium", category: "audio-video", description: "Voice encryption for Discord bots" },

  // ---------------------------------------------------------------------------
  // System & OS
  // ---------------------------------------------------------------------------
  { name: "cpu-features", category: "system", description: "CPU feature detection" },
  { name: "systeminformation", category: "system", description: "System & OS information" },
  { name: "node-os-utils", category: "system", description: "OS utility functions" },
  { name: "usb", category: "system", description: "USB device access" },
  { name: "serialport", category: "system", description: "Serial port communication" },
  { name: "node-hid", category: "system", description: "HID device access" },
  { name: "ffi-napi", category: "system", description: "Foreign function interface (NAPI)" },
  { name: "ref-napi", category: "system", description: "C pointer/reference types (NAPI)" },
  { name: "node-pty", category: "system", description: "Pseudoterminal bindings" },
  { name: "unix-dgram", category: "system", description: "Unix datagram sockets" },
  { name: "win-info", category: "system", description: "Windows system info" },
  { name: "active-win", category: "system", description: "Active window detection" },
  { name: "native-keymap", category: "system", description: "OS keyboard layout" },
  { name: "windows-process-tree", category: "system", description: "Windows process tree" },
  { name: "drivelist", category: "system", description: "List connected drives" },
  { name: "node-notifier", category: "system", description: "Desktop notifications" },
  { name: "macos-alias", category: "system", description: "macOS alias resolution" },
  { name: "nsfw", category: "system", description: "File watcher (native)" },
  { name: "node-window-manager", category: "system", description: "Window management" },
  { name: "@vscode/spdlog", category: "system", description: "spdlog logger for VS Code" },
  { name: "native-is-elevated", category: "system", description: "Check if process is elevated" },
  { name: "node-mac-permissions", category: "system", description: "macOS permission checks" },
  { name: "registry-js", category: "system", description: "Windows Registry access" },

  // ---------------------------------------------------------------------------
  // Machine Learning
  // ---------------------------------------------------------------------------
  { name: "@tensorflow/tfjs-node", category: "machine-learning", description: "TensorFlow.js native backend" },
  { name: "@tensorflow/tfjs-node-gpu", category: "machine-learning", description: "TensorFlow.js GPU backend" },
  { name: "onnxruntime-node", category: "machine-learning", description: "ONNX Runtime for Node.js" },
  { name: "@xenova/transformers", category: "machine-learning", description: "Hugging Face Transformers (native)" },
  { name: "node-nlp", category: "machine-learning", description: "NLP library (native)" },
  { name: "tokenizers", category: "machine-learning", description: "Hugging Face tokenizers" },
  { name: "onnxruntime-web", category: "machine-learning", description: "ONNX Runtime WebAssembly" },

  // ---------------------------------------------------------------------------
  // Serialization
  // ---------------------------------------------------------------------------
  { name: "msgpackr", category: "serialization", description: "MessagePack (native optional)" },
  { name: "protobufjs", category: "serialization", description: "Protocol Buffers (native optional)" },
  { name: "flatbuffers", category: "serialization", description: "FlatBuffers serialization" },
  { name: "cbor", category: "serialization", description: "CBOR codec (native optional)" },
  { name: "avsc", category: "serialization", description: "Avro serialization" },
  { name: "msgpackr-extract", category: "serialization", description: "msgpackr native extractor" },
  { name: "cbor-extract", category: "serialization", description: "CBOR native extractor" },

  // ---------------------------------------------------------------------------
  // Graphics & 3D
  // ---------------------------------------------------------------------------
  { name: "gl", category: "graphics", description: "OpenGL bindings (headless)" },
  { name: "headless-gl", category: "graphics", description: "Headless WebGL" },
  { name: "node-canvas", category: "graphics", description: "Canvas implementation" },
  { name: "regl", category: "graphics", description: "WebGL command buffers" },
  { name: "node-raylib", category: "graphics", description: "Raylib game library bindings" },

  // ---------------------------------------------------------------------------
  // Text Processing
  // ---------------------------------------------------------------------------
  { name: "re2", category: "text-processing", description: "Google RE2 regex engine" },
  { name: "cld", category: "text-processing", description: "Compact Language Detector" },
  { name: "node-icu-charset-detector", category: "text-processing", description: "ICU charset detection" },
  { name: "icu4c-data", category: "text-processing", description: "ICU data files" },
  { name: "oniguruma", category: "text-processing", description: "Oniguruma regex engine" },
  { name: "vscode-oniguruma", category: "text-processing", description: "Oniguruma for VS Code" },
  { name: "tree-sitter", category: "text-processing", description: "Incremental parser generator" },
  { name: "tree-sitter-javascript", category: "text-processing", description: "Tree-sitter JS grammar" },
  { name: "tree-sitter-typescript", category: "text-processing", description: "Tree-sitter TS grammar" },
  { name: "tree-sitter-python", category: "text-processing", description: "Tree-sitter Python grammar" },
  { name: "tree-sitter-rust", category: "text-processing", description: "Tree-sitter Rust grammar" },
  { name: "tree-sitter-go", category: "text-processing", description: "Tree-sitter Go grammar" },
  { name: "tree-sitter-c", category: "text-processing", description: "Tree-sitter C grammar" },
  { name: "tree-sitter-cpp", category: "text-processing", description: "Tree-sitter C++ grammar" },
  { name: "tree-sitter-json", category: "text-processing", description: "Tree-sitter JSON grammar" },

  // ---------------------------------------------------------------------------
  // Security
  // ---------------------------------------------------------------------------
  { name: "node-rdrand", category: "security", description: "RDRAND hardware RNG" },
  { name: "node-forge-native", category: "security", description: "Node Forge native acceleration" },
  { name: "credential-plus-bcrypt", category: "security", description: "bcrypt credential plugin" },

  // ---------------------------------------------------------------------------
  // Electron / Desktop
  // ---------------------------------------------------------------------------
  { name: "electron", category: "system", description: "Desktop app framework (Chromium + Node)" },
  { name: "electron-rebuild", category: "system", description: "Rebuild native modules for Electron" },
  { name: "robotjs", category: "system", description: "Desktop automation (mouse, keyboard)" },
  { name: "iohook", category: "system", description: "Global input hook (keyboard, mouse)" },
  { name: "screenshot-desktop", category: "system", description: "Desktop screenshot capture" },
  { name: "node-global-key-listener", category: "system", description: "Global keyboard listener" },

  // ---------------------------------------------------------------------------
  // Miscellaneous native modules
  // ---------------------------------------------------------------------------
  { name: "node-gyp", category: "build-tools", description: "Node.js native addon build tool" },
  { name: "node-pre-gyp", category: "build-tools", description: "Binary deployment tool for native addons" },
  { name: "@mapbox/node-pre-gyp", category: "build-tools", description: "Mapbox fork of node-pre-gyp" },
  { name: "prebuild-install", category: "build-tools", description: "Install prebuilt native addons" },
  { name: "prebuild", category: "build-tools", description: "Build prebuilt native addons" },
  { name: "cmake-js", category: "build-tools", description: "CMake-based native addon build tool" },
  { name: "node-addon-api", category: "build-tools", description: "N-API C++ wrappers" },
  { name: "napi-rs", category: "build-tools", description: "Rust NAPI bindings" },
  { name: "node-gyp-build", category: "build-tools", description: "Load prebuilt native addons" },

  // Additional well-known native modules
  { name: "weak-napi", category: "system", description: "Weak references via NAPI" },
  { name: "integer", category: "system", description: "Native 64-bit integer support" },
  { name: "farmhash", category: "crypto", description: "FarmHash native bindings" },
  { name: "xxhash", category: "crypto", description: "xxHash native bindings" },
  { name: "xxhash-addon", category: "crypto", description: "xxHash addon" },
  { name: "murmurhash-native", category: "crypto", description: "MurmurHash native bindings" },
  { name: "dtrace-provider", category: "system", description: "DTrace probes" },
  { name: "microtime", category: "system", description: "Microsecond time resolution" },
  { name: "kerberos", category: "networking", description: "Kerberos authentication" },
  { name: "node-expat", category: "text-processing", description: "Expat XML parser bindings" },
  { name: "libxmljs", category: "text-processing", description: "libxml2 bindings" },
  { name: "libxmljs2", category: "text-processing", description: "libxml2 bindings (maintained fork)" },
  { name: "node-sass", category: "build-tools", description: "LibSass bindings (deprecated)" },
  { name: "sass-embedded", category: "build-tools", description: "Embedded Dart Sass" },
  { name: "sass-embedded-darwin-arm64", category: "build-tools", description: "Sass embedded macOS ARM64", platforms: ["darwin"] },
  { name: "sass-embedded-darwin-x64", category: "build-tools", description: "Sass embedded macOS x64", platforms: ["darwin"] },
  { name: "sass-embedded-linux-arm64", category: "build-tools", description: "Sass embedded Linux ARM64", platforms: ["linux"] },
  { name: "sass-embedded-linux-x64", category: "build-tools", description: "Sass embedded Linux x64", platforms: ["linux"] },
  { name: "sass-embedded-win32-x64", category: "build-tools", description: "Sass embedded Windows x64", platforms: ["win32"] },

  // More platform-specific packages
  { name: "@next/swc-darwin-arm64", category: "build-tools", description: "Next.js SWC macOS ARM64", platforms: ["darwin"] },
  { name: "@next/swc-darwin-x64", category: "build-tools", description: "Next.js SWC macOS x64", platforms: ["darwin"] },
  { name: "@next/swc-linux-arm64-gnu", category: "build-tools", description: "Next.js SWC Linux ARM64 GNU", platforms: ["linux"] },
  { name: "@next/swc-linux-arm64-musl", category: "build-tools", description: "Next.js SWC Linux ARM64 musl", platforms: ["linux"] },
  { name: "@next/swc-linux-x64-gnu", category: "build-tools", description: "Next.js SWC Linux x64 GNU", platforms: ["linux"] },
  { name: "@next/swc-linux-x64-musl", category: "build-tools", description: "Next.js SWC Linux x64 musl", platforms: ["linux"] },
  { name: "@next/swc-win32-arm64-msvc", category: "build-tools", description: "Next.js SWC Windows ARM64", platforms: ["win32"] },
  { name: "@next/swc-win32-ia32-msvc", category: "build-tools", description: "Next.js SWC Windows ia32", platforms: ["win32"] },
  { name: "@next/swc-win32-x64-msvc", category: "build-tools", description: "Next.js SWC Windows x64", platforms: ["win32"] },

  // Sharp platform packages
  { name: "@img/sharp-darwin-arm64", category: "image", description: "Sharp macOS ARM64", platforms: ["darwin"] },
  { name: "@img/sharp-darwin-x64", category: "image", description: "Sharp macOS x64", platforms: ["darwin"] },
  { name: "@img/sharp-linux-arm", category: "image", description: "Sharp Linux ARM", platforms: ["linux"] },
  { name: "@img/sharp-linux-arm64", category: "image", description: "Sharp Linux ARM64", platforms: ["linux"] },
  { name: "@img/sharp-linux-x64", category: "image", description: "Sharp Linux x64", platforms: ["linux"] },
  { name: "@img/sharp-linuxmusl-arm64", category: "image", description: "Sharp Linux musl ARM64", platforms: ["linux"] },
  { name: "@img/sharp-linuxmusl-x64", category: "image", description: "Sharp Linux musl x64", platforms: ["linux"] },
  { name: "@img/sharp-win32-ia32", category: "image", description: "Sharp Windows ia32", platforms: ["win32"] },
  { name: "@img/sharp-win32-x64", category: "image", description: "Sharp Windows x64", platforms: ["win32"] },

  // Prisma engines
  { name: "@prisma/engines", category: "database", description: "Prisma query engine binaries" },
  { name: "@prisma/client", category: "database", description: "Prisma ORM client" },
  { name: "prisma", category: "database", description: "Prisma CLI" },
  { name: "@prisma/engines-version", category: "database", description: "Prisma engine version" },

  // Additional napi-rs packages
  { name: "@napi-rs/simple-git", category: "system", description: "NAPI-RS git bindings" },
  { name: "@napi-rs/argon2", category: "crypto", description: "NAPI-RS Argon2 hashing" },
  { name: "@napi-rs/xxhash", category: "crypto", description: "NAPI-RS xxHash" },
  { name: "@napi-rs/cross-env", category: "system", description: "NAPI-RS cross-env" },
  { name: "@napi-rs/wasm-runtime", category: "system", description: "NAPI-RS wasm runtime" },

  // Playwright / Puppeteer native pieces
  { name: "playwright", category: "system", description: "Browser automation (bundles Chromium/FF/WebKit)" },
  { name: "puppeteer", category: "system", description: "Chrome automation (bundles Chromium)" },
];

/** All unique categories present in the seed list. */
export const SEED_CATEGORIES = [
  ...new Set(NATIVE_PACKAGE_SEED_LIST.map((p) => p.category)),
].sort();
