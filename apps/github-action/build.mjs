import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { isBuiltin } from "node:module";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const cwd = fileURLToPath(new URL(".", import.meta.url));
const bundle = await build({
  absWorkingDir: cwd,
  entryPoints: ["src/index.ts"],
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node20",
  // Escape multiline strings so literal trailing spaces do not leak into the dist diff.
  supported: { "template-literal": false },
  outfile: "dist/index.cjs",
  metafile: true,
  minify: true,
  legalComments: "eof",
  write: false
});

for (const { imports } of Object.values(bundle.metafile.outputs)) {
  for (const dep of imports) {
    if (!dep.external || !isBuiltin(dep.path)) {
      throw new Error(`Action bundle is not self-contained: ${dep.path}`);
    }
  }
}

// Include complete upstream notices for every bundled dependency, including
// packages with licenses in distribution files rather than inline comments.
const notices = new Map();
for (const input of Object.keys(bundle.metafile.inputs)) {
  const absolute = resolve(cwd, input);
  if (!absolute.includes(`${sep}node_modules${sep}`)) continue;
  let found = false;
  for (let dir = dirname(absolute); dir.includes(`${sep}node_modules${sep}`); dir = dirname(dir)) {
    const manifestPath = join(dir, "package.json");
    if (!existsSync(manifestPath)) continue;
    const { name, version, license } = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (!name || !version) continue;
    found = true;
    const id = `${name}@${version}`;
    if (!notices.has(id)) {
      const files = readdirSync(dir).filter((file) => /^(license|copying|notice)(\.[a-z]+)?$/i.test(file)).sort();
      if (files.length === 0) throw new Error(`Missing upstream license for bundled ${id}`);
      const text = files.map((file) => readFileSync(join(dir, file), "utf8").replace(/\r\n/g, "\n").trim()).join("\n\n");
      notices.set(id, `## ${id} (${license ?? "see license text"})\n\n${text}`);
    }
    break;
  }
  if (!found) throw new Error(`Missing package metadata for bundled input ${input}`);
}

const dist = join(cwd, "dist");
mkdirSync(dist, { recursive: true });
for (const file of bundle.outputFiles) writeFileSync(file.path, file.contents);
writeFileSync(join(dist, "THIRD_PARTY_NOTICES.txt"),
  "# Licenses for dependencies bundled in index.cjs\n\n" +
  [...notices.keys()].sort().map((id) => notices.get(id)).join("\n\n") + "\n");
