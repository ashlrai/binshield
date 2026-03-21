import * as core from "@actions/core";
import * as github from "@actions/github";

import { renderComment, runPackageScan, shouldFail } from "./scan";

async function main() {
  const apiBaseUrl = core.getInput("api-base-url");
  const failOn = core.getInput("fail-on") as "critical" | "high" | "medium" | "low" | "never";

  const targets = [
    { ecosystem: "npm" as const, packageName: "bcrypt", version: "5.1.1" },
    { ecosystem: "npm" as const, packageName: "sharp", version: "0.33.2" }
  ];

  const analyses = [];
  for (const target of targets) {
    analyses.push(await runPackageScan(apiBaseUrl, target));
  }

  const comment = renderComment(analyses);
  core.summary.addRaw(comment).write();

  const failing = analyses.find((analysis) => shouldFail(analysis.riskLevel, failOn));
  if (failing) {
    core.setFailed(`${failing.packageName}@${failing.version} exceeded the ${failOn} threshold.`);
  }

  const { context } = github;
  core.info(`Processed ${analyses.length} analyses for workflow ${context.workflow}.`);
}

void main().catch((error) => {
  core.setFailed(error instanceof Error ? error.message : "Unknown BinShield action failure");
});
