import { readFile } from "node:fs/promises";
import path from "node:path";

import { readEnv } from "@binshield/config";

import { AnalysisPipeline } from "./pipeline";
import { WorkerDaemon } from "./daemon";

async function runCli() {
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

async function runDaemon() {
  const env = readEnv();

  const supabaseUrl = process.env.SUPABASE_URL ?? env.supabaseUrl;
  const supabaseServiceRoleKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ?? env.supabaseServiceRoleKey;

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error(
      "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set for daemon mode",
    );
  }

  const daemon = new WorkerDaemon({
    supabaseUrl,
    supabaseServiceRoleKey,
    pollIntervalMs: Number(process.env.BINSHIELD_POLL_INTERVAL_MS ?? 5000),
    maxConcurrent: Number(process.env.BINSHIELD_MAX_CONCURRENT ?? 2),
    resendApiKey: process.env.RESEND_API_KEY ?? env.resendApiKey ?? "",
    fromEmail: process.env.BINSHIELD_SMTP_FROM_EMAIL ?? env.smtpFromEmail ?? "alerts@binshield.dev",
  });

  await daemon.start();
}

async function main() {
  const mode = process.env.BINSHIELD_WORKER_MODE ?? "cli";

  if (mode === "daemon") {
    await runDaemon();
  } else {
    await runCli();
  }
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
