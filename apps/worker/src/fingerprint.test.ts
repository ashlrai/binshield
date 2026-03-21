import path from "node:path";

import { describe, expect, it } from "vitest";

import { fingerprintFile, isCandidateBinary, summarizeBinaryText } from "./fingerprint";

describe("fingerprinting", () => {
  it("recognizes candidate binary extensions", () => {
    expect(isCandidateBinary("addon.node")).toBe(true);
    expect(isCandidateBinary("text.txt")).toBe(false);
  });

  it("fingerprints fixture artifacts", async () => {
    const filePath = path.resolve(new URL("../fixtures/sample-package/prebuilds/linux-x64/binshield-addon.node", import.meta.url).pathname);
    const artifact = await fingerprintFile(filePath, "prebuilds/linux-x64/binshield-addon.node");

    expect(artifact.format).toBe("ELF");
    expect(artifact.architecture).toBe("x86_64");
    expect(artifact.interestingStrings).toEqual(
      expect.arrayContaining(["https://telemetry.example.invalid/collect", "/tmp/binshield-cache", "process.env.BINSHIELD_TOKEN"])
    );
  });

  it("summarizes binary text", () => {
    const preview = summarizeBinaryText(new TextEncoder().encode("line1\nline2\nline3"));
    expect(preview).toContain("line1");
  });
});
