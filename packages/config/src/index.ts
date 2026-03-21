export interface EnvShape {
  publicAppUrl: string;
  apiBaseUrl: string;
  supabaseUrl: string;
  supabaseAnonKey: string;
  supabaseServiceRoleKey: string;
  ghidraImage: string;
  stripeSecretKey: string;
  stripePublishableKey: string;
  stripeWebhookSecret: string;
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
    stripeSecretKey: source.STRIPE_SECRET_KEY ?? "sk_test_placeholder",
    stripePublishableKey: source.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY ?? "pk_test_placeholder",
    stripeWebhookSecret: source.STRIPE_WEBHOOK_SECRET ?? "whsec_placeholder",
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
