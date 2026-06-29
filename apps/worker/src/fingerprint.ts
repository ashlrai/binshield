import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

import type { BinaryFormat } from "@binshield/analysis-types";

import type { FingerprintedArtifact } from "./types";

const TEXT_RE = /[ -~]{4,}/g;
const INTERESTING_RE = /(https?:\/\/[^\s"'`]+|\/[A-Za-z0-9_./-]+|[A-Za-z0-9_./-]+\.(?:json|node|so|dll|dylib|wasm)|process\.env\.[A-Z0-9_]+|spawn\([^)]+\)|exec\([^)]+\))/;

function detectFormat(bytes: Uint8Array, filename: string): BinaryFormat {
  const ext = path.extname(filename).toLowerCase();
  const header = Array.from(bytes.slice(0, 8));

  if (header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46) {
    return "ELF";
  }
  if (header[0] === 0x4d && header[1] === 0x5a) {
    return "PE";
  }
  if (
    header[0] === 0xfe && header[1] === 0xed && header[2] === 0xfa && header[3] === 0xcf ||
    header[0] === 0xcf && header[1] === 0xfa && header[2] === 0xed && header[3] === 0xfe
  ) {
    return "Mach-O";
  }
  if (
    header[0] === 0x00 &&
    header[1] === 0x61 &&
    header[2] === 0x73 &&
    header[3] === 0x6d
  ) {
    return "WASM";
  }
  if (ext === ".node" || ext === ".so") {
    return "ELF";
  }
  if (ext === ".dll") {
    return "PE";
  }
  if (ext === ".dylib") {
    return "Mach-O";
  }
  if (ext === ".wasm") {
    return "WASM";
  }

  return "unknown";
}

function extractStrings(bytes: Uint8Array, minLength = 4): string[] {
  const text = Buffer.from(bytes).toString("latin1");
  const matches = text.match(TEXT_RE) ?? [];
  const normalized = matches
    .map((match) => match.replace(/\u0000/g, "").trim())
    .filter((match) => match.length >= minLength);

  return Array.from(new Set(normalized));
}

function interestingStrings(strings: string[]): string[] {
  return Array.from(
    new Set(
      strings.filter((value) =>
        INTERESTING_RE.test(value) ||
        /(?:urandom|token|secret|password|auth|telemetry|upload|download|connect|socket|http|https|curl|spawn|exec|tmp|cache)/i.test(value)
      )
    )
  );
}

function detectArchitecture(filename: string, relativePath: string, strings: string[], format: BinaryFormat): string {
  const haystack = [filename, relativePath, ...strings].join(" ").toLowerCase();

  if (format === "WASM") {
    return "wasm32";
  }
  if (haystack.includes("arm64") || haystack.includes("aarch64")) {
    return "arm64";
  }
  if (haystack.includes("x64") || haystack.includes("amd64") || haystack.includes("x86_64")) {
    return "x86_64";
  }
  if (haystack.includes("ia32") || haystack.includes("x86")) {
    return "x86";
  }

  return "unknown";
}

function classifyKind(filename: string, relativePath: string, strings: string[], format: BinaryFormat): FingerprintedArtifact["kind"] {
  const haystack = [filename, relativePath, ...strings].join(" ").toLowerCase();
  if (format === "WASM") {
    return "wasm";
  }
  if (haystack.includes("node") || haystack.includes("napi") || haystack.includes("addon")) {
    return "native-addon";
  }
  if (format === "ELF" || format === "PE" || format === "Mach-O") {
    return "shared-library";
  }
  if (strings.length > 0) {
    return "binary";
  }
  return "unknown";
}

export function buildArtifactHash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function fingerprintBytes(filename: string, relativePath: string, bytes: Uint8Array): FingerprintedArtifact {
  const strings = extractStrings(bytes);
  const format = detectFormat(bytes, filename);
  return {
    filename,
    absolutePath: relativePath,
    relativePath,
    fileSize: bytes.byteLength,
    sha256: buildArtifactHash(bytes),
    format,
    architecture: detectArchitecture(filename, relativePath, strings, format),
    kind: classifyKind(filename, relativePath, strings, format),
    bytes,
    strings,
    interestingStrings: interestingStrings(strings)
  };
}

export async function fingerprintFile(filePath: string, relativePath?: string): Promise<FingerprintedArtifact> {
  const bytes = await readFile(filePath);
  return {
    ...fingerprintBytes(path.basename(filePath), relativePath ?? filePath, bytes),
    absolutePath: filePath
  };
}

export function isCandidateBinary(fileName: string): boolean {
  const ext = path.extname(fileName).toLowerCase();
  // .pyd is the Windows Python extension DLL equivalent; also catch CPython
  // ABI-tagged .so files like `_ssl.cpython-311-x86_64-linux-gnu.so`.
  return [".node", ".so", ".dll", ".dylib", ".wasm", ".pyd"].includes(ext);
}

export function summarizeBinaryText(bytes: Uint8Array, limit = 12): string {
  const text = Buffer.from(bytes).toString("utf8");
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, limit);

  if (lines.length > 0) {
    return lines.join("\n");
  }

  return Buffer.from(bytes.slice(0, 160)).toString("hex");
}

export function extractTokenHints(strings: string[]): string[] {
  const hints = new Set<string>();

  for (const value of strings) {
    if (/https?:\/\//i.test(value)) {
      hints.add("network");
    }
    if (/(\/tmp|\/var|cache|temp|tmp|readFile|writeFile|open|unlink|mkdir)/i.test(value)) {
      hints.add("filesystem");
    }
    if (/(spawn|exec|fork|child_process|system\()/i.test(value)) {
      hints.add("process");
    }
    if (/(crypto|hash|sha|md5|bcrypt|argon2|evp_|aes|rsa|urandom)/i.test(value)) {
      hints.add("crypto");
    }
    if (/(base64|xor|pack|obfus|eval|fromcharcode|atob)/i.test(value)) {
      hints.add("obfuscation");
    }
    if (/(token|secret|password|auth|cookie|telemetry|upload|exfil|beacon)/i.test(value)) {
      hints.add("dataExfiltration");
    }
  }

  return Array.from(hints);
}
