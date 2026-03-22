const thresholdOrder = ["none", "low", "medium", "high", "critical"];
export function shouldFail(level, threshold) {
    if (threshold === "never") {
        return false;
    }
    return thresholdOrder.indexOf(level) >= thresholdOrder.indexOf(threshold);
}
export function renderComment(analyses) {
    const rows = analyses
        .map((analysis) => `| ${analysis.packageName}@${analysis.version} | ${analysis.binaries
        .map((binary) => binary.filename)
        .join(", ")} | ${analysis.riskLevel.toUpperCase()} (${analysis.riskScore}) | ${analysis.summary} |`)
        .join("\n");
    return `## BinShield - Binary Dependency Scan

**${analyses.length} package analyses completed**

| Package | Binary | Risk | Summary |
|---------|--------|------|---------|
${rows}
`;
}
export async function runPackageScan(baseUrl, request) {
    const response = await fetch(`${baseUrl}/scans/packages`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(request)
    });
    const job = (await response.json());
    if (job.result) {
        return job.result;
    }
    const poll = await fetch(`${baseUrl}/scans/${job.id}`);
    const completed = (await poll.json());
    if (!completed.result) {
        throw new Error(`Scan ${job.id} did not produce a result`);
    }
    return completed.result;
}
export async function searchPackages(baseUrl, q) {
    const response = await fetch(`${baseUrl}/packages/search?q=${encodeURIComponent(q)}`);
    const body = (await response.json());
    return body.items;
}
