import * as core from "@actions/core";
import * as github from "@actions/github";

import type { ScanOutcome } from "./types";
import { renderComment, shouldPublishComment, shouldPublishSummary } from "./report";

export async function publishResults(
  commentMode: "summary" | "pr-comment" | "both" | "off",
  githubToken: string | undefined,
  outcomes: ScanOutcome[]
) {
  if (shouldPublishSummary(commentMode)) {
    await core.summary.addRaw(renderComment(outcomes)).write();
  }

  if (!shouldPublishComment(commentMode) || !githubToken) {
    return;
  }

  const context = github.context;
  const pullRequestNumber = context.payload.pull_request?.number ?? context.issue.number;
  if (!pullRequestNumber) {
    return;
  }

  const octokit = github.getOctokit(githubToken);
  await octokit.rest.issues.createComment({
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: pullRequestNumber,
    body: renderComment(outcomes)
  });
}
