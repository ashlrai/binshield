const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function authHeaders(apiKey) {
    const headers = {
        "Content-Type": "application/json"
    };
    if (apiKey) {
        headers.Authorization = `Bearer ${apiKey}`;
    }
    return headers;
}
export class BinShieldClient {
    options;
    constructor(options) {
        this.options = options;
    }
    async submitScan(target) {
        const response = await fetch(`${this.options.apiBaseUrl}/scans/packages`, {
            method: "POST",
            headers: authHeaders(this.options.apiKey),
            body: JSON.stringify(target)
        });
        if (!response.ok) {
            throw new Error(`BinShield API rejected scan submission: ${response.status} ${response.statusText}`);
        }
        return (await response.json());
    }
    async waitForResult(job) {
        if (job.result) {
            return job.result;
        }
        const startedAt = Date.now();
        let current = job;
        let delay = this.options.pollIntervalMs;
        while (Date.now() - startedAt < this.options.timeoutMs) {
            const response = await fetch(`${this.options.apiBaseUrl}/scans/${current.id}`, {
                headers: authHeaders(this.options.apiKey)
            });
            if (!response.ok) {
                throw new Error(`BinShield API polling failed: ${response.status} ${response.statusText}`);
            }
            current = (await response.json());
            if (current.status === "failed") {
                throw new Error(current.error ?? `Scan ${current.id} failed`);
            }
            if (current.result) {
                return current.result;
            }
            await sleep(delay);
            delay = Math.min(Math.round(delay * 1.5), 5000);
        }
        throw new Error(`Timed out waiting for scan ${job.id} after ${this.options.timeoutMs}ms`);
    }
    async registerDependencies(dependencies) {
        const response = await fetch(`${this.options.apiBaseUrl}/dependency-registration`, {
            method: "POST",
            headers: authHeaders(this.options.apiKey),
            body: JSON.stringify({ dependencies })
        });
        if (!response.ok) {
            throw new Error(`BinShield API rejected dependency registration: ${response.status} ${response.statusText}`);
        }
        const data = (await response.json());
        return data.registered ?? 0;
    }
}
export async function scanTarget(client, target, request) {
    try {
        const job = await client.submitScan(request);
        const analysis = await client.waitForResult(job);
        return { target, analysis };
    }
    catch (error) {
        return { target, error: error instanceof Error ? error.message : "Unknown scan failure" };
    }
}
