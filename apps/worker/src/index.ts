import { readFile } from "node:fs/promises";
import path from "node:path";

import { readEnv } from "@binshield/config";

import { AnalysisPipeline } from "./pipeline";
import { WorkerDaemon } from "./daemon";
import { FeedFollower } from "./feed-follower";
import { EpssFeedIngester } from "./epss-feed-ingester";

function requireSupabase() {
  const env = readEnv();
  const supabaseUrl = process.env.SUPABASE_URL ?? env.supabaseUrl;
  const supabaseServiceRoleKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ?? env.supabaseServiceRoleKey;

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error(
      "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set for this mode",
    );
  }

  return { env, supabaseUrl, supabaseServiceRoleKey };
}

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
  const { env, supabaseUrl, supabaseServiceRoleKey } = requireSupabase();

  const daemon = new WorkerDaemon({
    supabaseUrl,
    supabaseServiceRoleKey,
    pollIntervalMs: Number(process.env.BINSHIELD_POLL_INTERVAL_MS ?? 5000),
    maxConcurrent: Number(process.env.BINSHIELD_MAX_CONCURRENT ?? 2),
    sendgridApiKey: process.env.SENDGRID_API_KEY ?? env.sendgridApiKey ?? "",
    fromEmail: process.env.BINSHIELD_SMTP_FROM_EMAIL ?? env.smtpFromEmail ?? "support@ashlr.ai",
  });

  await daemon.start();
}

async function runFeed() {
  const { supabaseUrl, supabaseServiceRoleKey } = requireSupabase();

  const follower = new FeedFollower({
    supabaseUrl,
    supabaseServiceRoleKey,
    pollIntervalMs: Number(process.env.BINSHIELD_FEED_POLL_MS ?? 10000),
    batchSize: Number(process.env.BINSHIELD_FEED_BATCH_SIZE ?? 100),
    minDownloads: Number(process.env.BINSHIELD_FEED_MIN_DOWNLOADS ?? 100),
  });

  await follower.start();
}

async function runEpss() {
  const { supabaseUrl, supabaseServiceRoleKey } = requireSupabase();

  const ingester = new EpssFeedIngester({
    supabaseUrl,
    supabaseServiceRoleKey,
    topN: Number(process.env.EPSS_TOP_N ?? 10_000),
    pollIntervalMs: Number(process.env.EPSS_POLL_INTERVAL_MS ?? 21_600_000),
  });

  const controller = new AbortController();
  process.on("SIGTERM", () => controller.abort());
  process.on("SIGINT", () => controller.abort());

  console.log("[BinShield EPSS] Starting EPSS feed ingester daemon");
  await ingester.startPolling(controller.signal);
}

async function runCrawl() {
  const { supabaseUrl, supabaseServiceRoleKey } = requireSupabase();

  // Dynamic import to avoid loading discovery engine in other modes
  const { PackageCrawler } = await import("./crawler");

  const crawler = new PackageCrawler({
    supabaseUrl,
    supabaseServiceRoleKey,
    batchSize: Number(process.env.BINSHIELD_CRAWL_BATCH_SIZE ?? 10),
    delayBetweenBatches: Number(process.env.BINSHIELD_CRAWL_DELAY ?? 2000),
    maxPackages: Number(process.env.BINSHIELD_CRAWL_MAX ?? 100),
  });

  const source = (process.env.BINSHIELD_CRAWL_SOURCE ?? "seed-list") as "seed-list" | "npm-registry";
  console.log(`[BinShield Crawler] Starting crawl from source: ${source}`);
  const result = await crawler.runCrawl(source);
  console.log(`[BinShield Crawler] Done:`, JSON.stringify(result, null, 2));
}

async function main() {
  const mode = process.env.BINSHIELD_WORKER_MODE ?? "cli";

  switch (mode) {
    case "daemon":
      await runDaemon();
      break;
    case "feed":
      await runFeed();
      break;
    case "epss":
      await runEpss();
      break;
    case "crawl":
      await runCrawl();
      break;
    default:
      await runCli();
      break;
  }
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
