import * as core from "@actions/core";
import * as github from "@actions/github";
import { renderComment, shouldPublishComment, shouldPublishSummary } from "./report";
export async function publishResults(commentMode, githubToken, outcomes) {
    if (shouldPublishSummary(commentMode)) {
        await core.summary.addRaw(renderComment(outcomes)).write();
    }
    if (!shouldPublishComment(commentMode) || !githubToken) {
        if (shouldPublishComment(commentMode) && !githubToken) {
            core.warning("BinShield was asked to post a PR comment, but no github-token was provided. Summary output was still written.");
        }
        return;
    }
    const context = github.context;
    const pullRequestNumber = context.payload.pull_request?.number ?? context.issue.number;
    if (!pullRequestNumber) {
        core.notice("BinShield skipped PR comment because the workflow is not running on a pull request.");
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
