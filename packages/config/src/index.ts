export interface EnvShape {
  publicAppUrl: string;
  apiBaseUrl: string;
  supabaseUrl: string;
  supabaseAnonKey: string;
  supabaseServiceRoleKey: string;
  ghidraImage: string;
  ghidraTimeoutMs: number;
  ghidraMemoryLimit: string;
  ghidraCpuLimit: string;
  xaiApiKey: string;
  xaiModel: string;
  xaiTimeoutMs: number;
  stripeSecretKey: string;
  stripePublishableKey: string;
  stripeWebhookSecret: string;
  stripePriceIds: Record<string, string>;
  githubActionToken: string;
  smtpFromEmail: string;
  defaultFailOn: "critical" | "high" | "medium" | "low" | "never";
}

export function readEnv(source: NodeJS.ProcessEnv = process.env): EnvShape {
  return {
    publicAppUrl: source.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000",
    apiBaseUrl: source.BINSHIELD_API_BASE_URL ?? "http://localhost:4000",
    supabaseUrl: source.NEXT_PUBLIC_SUPABASE_URL ?? "https://example.supabase.co",
    supabaseAnonKey: source.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "dev-anon-key",
    supabaseServiceRoleKey: source.SUPABASE_SERVICE_ROLE_KEY ?? "dev-service-role-key",
    ghidraImage: source.BINSHIELD_GHIDRA_IMAGE ?? "ghcr.io/ashlrai/binshield-ghidra:latest",
    ghidraTimeoutMs: Number(source.BINSHIELD_GHIDRA_TIMEOUT_MS ?? 300000),
    ghidraMemoryLimit: source.BINSHIELD_GHIDRA_MEMORY_LIMIT ?? "4g",
    ghidraCpuLimit: source.BINSHIELD_GHIDRA_CPU_LIMIT ?? "2",
    xaiApiKey: source.XAI_API_KEY ?? "",
    xaiModel: source.XAI_MODEL ?? "grok-4-1-fast-reasoning",
    xaiTimeoutMs: Number(source.XAI_TIMEOUT_MS ?? 60000),
    stripeSecretKey: source.STRIPE_SECRET_KEY ?? "sk_test_placeholder",
    stripePublishableKey: source.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY ?? "pk_test_placeholder",
    stripeWebhookSecret: source.STRIPE_WEBHOOK_SECRET ?? "whsec_placeholder",
    stripePriceIds: {
      pro: source.STRIPE_PRICE_PRO ?? "price_pro_placeholder",
      team: source.STRIPE_PRICE_TEAM ?? "price_team_placeholder",
      enterprise: source.STRIPE_PRICE_ENTERPRISE ?? "price_enterprise_placeholder"
    },
    githubActionToken: source.GITHUB_TOKEN ?? "dev-github-token",
    smtpFromEmail: source.BINSHIELD_SMTP_FROM_EMAIL ?? "alerts@binshield.dev",
    defaultFailOn: (source.BINSHIELD_DEFAULT_FAIL_ON as EnvShape["defaultFailOn"]) ?? "high"
  };
}

export const productCopy = {
  name: "BinShield",
  tagline: "Binary supply-chain security for the dependencies everyone else ignores.",
  description:
    "Decompile native package binaries, classify risky behaviors, and enforce policy before machine code reaches production."
};

export const pricingCopy = [
  { plan: "free", price: "$0", headline: "Public database and lightweight CI coverage." },
  { plan: "pro", price: "$149/mo", headline: "Launch team-grade scanning, watchlists, and API access." },
  { plan: "team", price: "$499/mo", headline: "Shared visibility, stronger limits, and centralized operations." },
  { plan: "enterprise", price: "Custom", headline: "High-volume workflows, compliance controls, and dedicated support." }
] as const;
