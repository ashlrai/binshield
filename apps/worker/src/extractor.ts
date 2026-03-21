import path from "node:path";
import { readdir } from "node:fs/promises";

import type { BinaryExtractor, FingerprintedArtifact } from "./types";
import { fingerprintFile, isCandidateBinary } from "./fingerprint";

async function walkDirectory(rootDir: string, currentDir = rootDir, results: string[] = []): Promise<string[]> {
  const entries = await readdir(currentDir, { withFileTypes: true });

  for (const entry of entries) {
    const absolute = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      await walkDirectory(rootDir, absolute, results);
      continue;
    }
    if (entry.isFile() && isCandidateBinary(entry.name)) {
      results.push(absolute);
    }
  }

  return results;
}

export class FileSystemBinaryExtractor implements BinaryExtractor {
  readonly name = "filesystem";

  async discover(packageRoot: string): Promise<FingerprintedArtifact[]> {
    const candidateFiles = await walkDirectory(packageRoot);
    const fingerprints: FingerprintedArtifact[] = [];

    for (const filePath of candidateFiles) {
      const relativePath = path.relative(packageRoot, filePath);
      fingerprints.push(await fingerprintFile(filePath, relativePath));
    }

    return fingerprints;
  }
}
