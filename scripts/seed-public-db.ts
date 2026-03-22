#!/usr/bin/env tsx
/**
 * BinShield Public Database Seeder
 *
 * Downloads real npm packages, runs them through the analysis pipeline,
 * and stores results in Supabase. Resumable — skips packages already analyzed.
 *
 * Usage:
 *   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... tsx scripts/seed-public-db.ts
 *   BINSHIELD_SEED_LIMIT=5 tsx scripts/seed-public-db.ts   # Seed only first 5
 *   BINSHIELD_SEED_PACKAGE=bcrypt tsx scripts/seed-public-db.ts  # Seed single package
 */

import { nativePackages } from "./npm-native-packages";

interface SeedConfig {
  supabaseUrl: string;
  supabaseServiceRoleKey: string;
  limit: number;
  singlePackage?: string;
}

function readConfig(): SeedConfig {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
    process.exit(1);
  }

  return {
    supabaseUrl,
    supabaseServiceRoleKey,
    limit: Number(process.env.BINSHIELD_SEED_LIMIT ?? nativePackages.length),
    singlePackage: process.env.BINSHIELD_SEED_PACKAGE
  };
}

function headers(serviceRoleKey: string) {
  return {
    apikey: serviceRoleKey,
    authorization: `Bearer ${serviceRoleKey}`,
    "content-type": "application/json",
    Prefer: "return=representation"
  };
}

async function supabaseRequest<T>(config: SeedConfig, path: string, init: RequestInit = {}): Promise<T> {
  const url = `${config.supabaseUrl}/rest/v1${path}`;
  const res = await fetch(url, {
    ...init,
    headers: { ...headers(config.supabaseServiceRoleKey), ...(init.headers as Record<string, string> ?? {}) }
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Supabase ${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

async function isAlreadyAnalyzed(config: SeedConfig, packageName: string): Promise<boolean> {
  const rows = await supabaseRequest<Array<{ id: string }>>(
    config,
    `/packages?select=id&ecosystem=eq.npm&name=eq.${encodeURIComponent(packageName)}`
  );
  return rows.length > 0;
}

async function getLatestVersion(packageName: string): Promise<string> {
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`);
  if (!res.ok) throw new Error(`npm registry returned ${res.status} for ${packageName}`);
  const data = (await res.json()) as { version: string };
  return data.version;
}

async function submitAndWaitForAnalysis(
  config: SeedConfig,
  packageName: string,
  version: string
): Promise<{ id: string; status: string; risk_score: number; risk_level: string } | null> {
  // Check if the worker has already processed this via the analysis_jobs table
  // For seeding, we insert a job and let the daemon pick it up
  const [job] = await supabaseRequest<Array<{ id: string; status: string }>>(
    config,
    `/analysis_jobs?select=*`,
    {
      method: "POST",
      body: JSON.stringify({
        ecosystem: "npm",
        package_name: packageName,
        version,
        status: "queued",
        requested_at: new Date().toISOString()
      })
    }
  );

  console.log(`  [queued] Job ${job.id} for ${packageName}@${version}`);

  // Poll for completion (the worker daemon will pick it up)
  const maxWait = 10 * 60 * 1000; // 10 minutes
  const pollInterval = 5000; // 5 seconds
  const startTime = Date.now();

  while (Date.now() - startTime < maxWait) {
    await new Promise((r) => setTimeout(r, pollInterval));

    const [current] = await supabaseRequest<Array<{ id: string; status: string; error?: string }>>(
      config,
      `/analysis_jobs?select=*&id=eq.${job.id}`
    );

    if (current.status === "complete") {
      // Find the analysis result
      const packages = await supabaseRequest<Array<{ id: string }>>(
        config,
        `/packages?select=id&ecosystem=eq.npm&name=eq.${encodeURIComponent(packageName)}`
      );
      if (packages.length > 0) {
        const analyses = await supabaseRequest<Array<{ id: string; risk_score: number; risk_level: string }>>(
          config,
          `/analyses?select=id,risk_score,risk_level&package_id=eq.${packages[0].id}&version=eq.${encodeURIComponent(version)}`
        );
        if (analyses.length > 0) {
          return { ...analyses[0], status: "complete" };
        }
      }
      return { id: job.id, status: "complete", risk_score: 0, risk_level: "none" };
    }

    if (current.status === "failed") {
      console.log(`  [failed] ${packageName}@${version}: ${current.error ?? "unknown error"}`);
      return null;
    }

    const elapsed = Math.round((Date.now() - startTime) / 1000);
    process.stdout.write(`\r  [${current.status}] Waiting... ${elapsed}s`);
  }

  console.log(`\n  [timeout] ${packageName}@${version} exceeded 10 minute limit`);
  return null;
}

async function seedDirectly(config: SeedConfig, packageName: string, version: string): Promise<boolean> {
  // If no worker daemon is running, we can seed by inserting the job as queued
  // and printing instructions
  const alreadyQueued = await supabaseRequest<Array<{ id: string; status: string }>>(
    config,
    `/analysis_jobs?select=id,status&ecosystem=eq.npm&package_name=eq.${encodeURIComponent(packageName)}&version=eq.${encodeURIComponent(version)}`
  );

  if (alreadyQueued.length > 0) {
    const existing = alreadyQueued[0];
    if (existing.status === "complete") {
      console.log(`  [skip] Already complete`);
      return true;
    }
    console.log(`  [exists] Job ${existing.id} status: ${existing.status}`);
    return existing.status === "complete";
  }

  // Queue the job
  const [job] = await supabaseRequest<Array<{ id: string }>>(
    config,
    `/analysis_jobs?select=*`,
    {
      method: "POST",
      body: JSON.stringify({
        ecosystem: "npm",
        package_name: packageName,
        version,
        status: "queued",
        requested_at: new Date().toISOString()
      })
    }
  );

  console.log(`  [queued] Job ${job.id}`);
  return false;
}

async function main() {
  const config = readConfig();

  console.log("=== BinShield Public Database Seeder ===");
  console.log(`Supabase: ${config.supabaseUrl}`);
  console.log(`Packages to seed: ${config.singlePackage ?? `${config.limit} of ${nativePackages.length}`}`);
  console.log();

  const packages = config.singlePackage
    ? nativePackages.filter((pkg) => pkg.name === config.singlePackage)
    : nativePackages.slice(0, config.limit);

  if (packages.length === 0) {
    console.error(`No packages found matching: ${config.singlePackage}`);
    process.exit(1);
  }

  let seeded = 0;
  let skipped = 0;
  let queued = 0;
  let failed = 0;

  for (const pkg of packages) {
    console.log(`[${seeded + skipped + queued + failed + 1}/${packages.length}] ${pkg.name} (${pkg.category})`);

    try {
      // Check if already analyzed
      const exists = await isAlreadyAnalyzed(config, pkg.name);
      if (exists) {
        console.log("  [skip] Already in database");
        skipped++;
        continue;
      }

      // Get latest version from npm
      const version = await getLatestVersion(pkg.name);
      console.log(`  [version] ${version}`);

      // Queue the analysis job
      const result = await seedDirectly(config, pkg.name, version);
      if (result) {
        seeded++;
      } else {
        queued++;
      }
    } catch (error) {
      console.log(`  [error] ${error instanceof Error ? error.message : String(error)}`);
      failed++;
    }
  }

  console.log();
  console.log("=== Seeding Summary ===");
  console.log(`  Seeded:  ${seeded}`);
  console.log(`  Skipped: ${skipped}`);
  console.log(`  Queued:  ${queued}`);
  console.log(`  Failed:  ${failed}`);

  if (queued > 0) {
    console.log();
    console.log("Jobs are queued in Supabase. Start the worker daemon to process them:");
    console.log("  BINSHIELD_WORKER_MODE=daemon pnpm --filter @binshield/worker dev");
  }
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
