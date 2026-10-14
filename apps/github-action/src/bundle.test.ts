import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

describe("github action bundle", () => {
  it("ships a self-contained runtime entrypoint", () => {
    const bundle = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), "../dist/index.cjs"),
      "utf8",
    );
    expect(bundle.length).toBeGreaterThan(10_000);
    expect(bundle).not.toMatch(/from\s+["']@actions\/(?:core|github)["']/);
    expect(bundle).not.toMatch(/require\(["']@actions\/(?:core|github)["']\)/);
  });

  it("declares the CommonJS bundle as the action entrypoint", () => {
    const manifest = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), "../action.yml"),
      "utf8",
    );
    expect(manifest).toContain('main: "dist/index.cjs"');
  });
});
