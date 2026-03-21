export interface EnvShape {
  publicAppUrl: string;
  apiBaseUrl: string;
  supabaseUrl: string;
  supabaseAnonKey: string;
  ghidraImage: string;
  defaultFailOn: "critical" | "high" | "medium" | "low" | "never";
}

export function readEnv(source: NodeJS.ProcessEnv = process.env): EnvShape {
  return {
    publicAppUrl: source.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000",
    apiBaseUrl: source.BINSHIELD_API_BASE_URL ?? "http://localhost:4000",
    supabaseUrl: source.NEXT_PUBLIC_SUPABASE_URL ?? "https://example.supabase.co",
    supabaseAnonKey: source.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "dev-anon-key",
    ghidraImage: source.BINSHIELD_GHIDRA_IMAGE ?? "ghcr.io/ashlrai/binshield-ghidra:latest",
    defaultFailOn: (source.BINSHIELD_DEFAULT_FAIL_ON as EnvShape["defaultFailOn"]) ?? "high"
  };
}

export const productCopy = {
  name: "BinShield",
  tagline: "Binary supply-chain security for the dependencies everyone else ignores.",
  description:
    "Decompile native package binaries, classify risky behaviors, and enforce policy before machine code reaches production."
};
