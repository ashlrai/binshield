import { readEnv } from "@binshield/config";

import { AnalysisPipeline } from "./pipeline";

async function main() {
  const env = readEnv();
  const pipeline = new AnalysisPipeline();
  const sample = await pipeline.analyze({
    ecosystem: "npm",
    packageName: "bcrypt",
    version: "5.1.1"
  });

  console.log(
    JSON.stringify(
      {
        service: "binshield-worker",
        ghidraImage: env.ghidraImage,
        sample
      },
      null,
      2
    )
  );
}

void main();
