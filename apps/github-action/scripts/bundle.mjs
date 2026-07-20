import { build } from "esbuild";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const output = resolve(appDir, "dist/index.js");

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
