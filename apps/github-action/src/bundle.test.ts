import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

it("starts the committed action artifact on a dependency-free npm fixture with no credentials", () => {
  const manifest = readFileSync(new URL("../action.yml", import.meta.url), "utf8");
  expect(manifest).toMatch(/^  main: "dist\/index\.cjs"$/m);
  const root = mkdtempSync(join(tmpdir(), "binshield-bundle-"));
  try {
    const entry = join(root, "index.cjs");
    copyFileSync(new URL("../dist/index.cjs", import.meta.url), entry);
    const pkg = { name: "binshield-smoke", version: "0.0.0" };
    writeFileSync(join(root, "package.json"), JSON.stringify(pkg));
    writeFileSync(join(root, "package-lock.json"), JSON.stringify({
      ...pkg, lockfileVersion: 3, packages: { "": pkg }
    }));
    const result = spawnSync(process.execPath, [entry], {
      cwd: root, encoding: "utf8", timeout: 5_000,
      env: { GITHUB_WORKSPACE: root, SystemRoot: process.env.SystemRoot }
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("did not find any native candidate dependencies");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
