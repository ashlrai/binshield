/**
 * Seed script: inserts all sample analyses from @binshield/analysis-types
 * into Supabase so the production site shows real data.
 *
 * Usage:
 *   SUPABASE_URL=https://... SUPABASE_SERVICE_ROLE_KEY=eyJ... npx tsx apps/worker/src/seed.ts
 *
 * Or via pnpm:
 *   pnpm --filter @binshield/worker seed
 */

import { sampleAnalyses } from "@binshield/analysis-types";
import { SupabaseWorkerStore } from "./supabase-store";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL ?? process.env.BINSHIELD_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.BINSHIELD_SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("Missing SUPABASE_URL and/or SUPABASE_SERVICE_ROLE_KEY environment variables.");
    console.error("Set these in apps/worker/.env or pass them directly.");
    process.exit(1);
  }

  const store = new SupabaseWorkerStore({ supabaseUrl, supabaseServiceRoleKey: serviceRoleKey });

  console.log(`Seeding ${sampleAnalyses.length} sample analyses into Supabase...`);
  console.log(`Target: ${supabaseUrl}\n`);

  let success = 0;
  let skipped = 0;

  for (const analysis of sampleAnalyses) {
    const label = `${analysis.packageName}@${analysis.version}`;
    try {
      const analysisId = await store.persistAnalysis(analysis);
      console.log(`  [OK] ${label} → ${analysisId}`);
      success++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // If it's a duplicate (409 conflict), skip gracefully
      if (msg.includes("409") || msg.includes("duplicate") || msg.includes("already exists")) {
        console.log(`  [SKIP] ${label} — already exists`);
        skipped++;
      } else {
        console.error(`  [FAIL] ${label} — ${msg}`);
      }
    }
  }

  console.log(`\nDone: ${success} seeded, ${skipped} skipped, ${sampleAnalyses.length - success - skipped} failed.`);
}

main().catch((err) => {
  console.error("Seed script failed:", err);
  process.exit(1);
});
