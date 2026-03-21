import { readFile } from "node:fs/promises";
import path from "node:path";

import { readEnv } from "@binshield/config";

import { AnalysisPipeline } from "./pipeline";

async function main() {
  const env = readEnv();
  const pipeline = new AnalysisPipeline();
  const packageRoot =
    process.env.BINSHIELD_PACKAGE_ROOT ??
    path.resolve(new URL("../fixtures/sample-package", import.meta.url).pathname);

  const manifest = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8")) as {
    name?: string;
    version?: string;
  };

  const result = await pipeline.run({
    ecosystem: "npm",
    packageName: manifest.name ?? "binshield-fixture-addon",
    version: manifest.version ?? "1.0.0",
    packageRoot,
    packageSource: "directory"
  });

  console.log(
    JSON.stringify(
      {
        service: "binshield-worker",
        ghidraImage: env.ghidraImage,
        job: result.job,
        analysis: result.analysis
      },
      null,
      2
    )
  );
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
