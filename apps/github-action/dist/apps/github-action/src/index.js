import * as core from "@actions/core";
import * as github from "@actions/github";
import path from "node:path";
import { BinShieldClient, scanTarget } from "./client";
import { discoverTargets } from "./discovery";
import { publishResults } from "./github";
import { buildFailureMessage, summarize } from "./report";
function readIntInput(name, fallback) {
    const raw = core.getInput(name);
    if (!raw) {
        return fallback;
    }
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}
function readBoolInput(name, fallback) {
    const raw = core.getInput(name);
    if (!raw) {
        return fallback;
    }
    return raw.toLowerCase() === "true";
}
function readConfig() {
    const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
    return {
        apiBaseUrl: core.getInput("api-base-url") || "http://localhost:4000",
        apiKey: core.getInput("api-key") || undefined,
        githubToken: core.getInput("github-token") || process.env.GITHUB_TOKEN || undefined,
        failOn: (core.getInput("fail-on") || "high"),
        commentMode: (core.getInput("comment-mode") || "summary"),
        scanMode: (core.getInput("scan-mode") || "native-only"),
        workingDirectory: path.resolve(workspace, core.getInput("working-directory") || "."),
        includeDevDependencies: readBoolInput("include-dev-dependencies", false),
        pollIntervalMs: readIntInput("poll-interval-ms", 1500),
        timeoutMs: readIntInput("timeout-ms", 120000),
        maxTargets: readIntInput("max-targets", 50)
    };
}
async function main() {
    const config = readConfig();
    const targets = await discoverTargets(config.workingDirectory, config.scanMode, config.includeDevDependencies);
    if (targets.length === 0) {
        core.notice("BinShield did not find any native candidate dependencies to scan.");
        return;
    }
    const client = new BinShieldClient({
        apiBaseUrl: config.apiBaseUrl,
        apiKey: config.apiKey,
        pollIntervalMs: config.pollIntervalMs,
        timeoutMs: config.timeoutMs
    });
    const selected = targets.slice(0, config.maxTargets);
    const outcomes = [];
    for (const target of selected) {
        const result = await scanTarget(client, target, {
            ecosystem: "npm",
            packageName: target.name,
            version: target.version,
            repo: github.context.repo.owner && github.context.repo.repo ? `${github.context.repo.owner}/${github.context.repo.repo}` : undefined
        });
        outcomes.push(result);
    }
    await publishResults(config.commentMode, config.githubToken, outcomes);
    const summary = summarize(outcomes);
    core.info(`Processed ${summary.successful} analyses with ${summary.failures} failures. Highest risk: ${summary.highest}.`);
    // Set outputs for downstream steps
    core.setOutput("total-scanned", String(outcomes.length));
    core.setOutput("highest-risk", summary.highest);
    const failureMessage = buildFailureMessage(outcomes, config.failOn);
    if (failureMessage) {
        core.setOutput("failed", "true");
        core.setFailed(failureMessage);
    }
    else {
        core.setOutput("failed", "false");
    }
}
void main().catch((error) => {
    core.setFailed(error instanceof Error ? error.message : "Unknown BinShield action failure");
});
