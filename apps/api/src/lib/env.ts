export interface ApiEnv {
  port: number;
  mode: "local" | "supabase";
  demoApiKey: string;
  supabaseUrl?: string;
  supabaseServiceRoleKey?: string;
  supabaseAnonKey?: string;
  publicAppUrl: string;
  defaultFailOn: "critical" | "high" | "medium" | "low" | "never";
}

export function readApiEnv(source: NodeJS.ProcessEnv = process.env): ApiEnv {
  const supabaseUrl = source.SUPABASE_URL ?? source.BINSHIELD_SUPABASE_URL;
  const supabaseServiceRoleKey = source.SUPABASE_SERVICE_ROLE_KEY ?? source.BINSHIELD_SUPABASE_SERVICE_ROLE_KEY;
  const supabaseAnonKey = source.SUPABASE_ANON_KEY ?? source.BINSHIELD_SUPABASE_ANON_KEY;

  return {
    port: Number(source.PORT ?? 4000),
    mode: supabaseUrl && supabaseServiceRoleKey ? "supabase" : "local",
    demoApiKey: source.BINSHIELD_DEMO_API_KEY ?? "binshield-dev-key",
    supabaseUrl,
    supabaseServiceRoleKey,
    supabaseAnonKey,
    publicAppUrl: source.BINSHIELD_PUBLIC_APP_URL ?? "http://localhost:3000",
    defaultFailOn: (source.BINSHIELD_DEFAULT_FAIL_ON as ApiEnv["defaultFailOn"]) ?? "high"
  };
}
