import { build } from "esbuild";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// The action package is ESM, but GitHub Actions runs this self-contained
// runtime bundle through Node's CommonJS loader.
const output = resolve(appDir, "dist/index.cjs");

mkdirSync(dirname(output), { recursive: true });
await build({
  entryPoints: [resolve(appDir, "dist/apps/github-action/src/index.js")],
  outfile: output,
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node20",
  sourcemap: false,
  legalComments: "none",
});
