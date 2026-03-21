# Launch Checklist

- Replace the in-memory API store with Supabase-backed repositories.
- Replace the simulated worker adapters with:
  - package tarball fetch + extraction
  - Ghidra container execution
  - provider-backed LLM classification
- Add API key auth middleware and org-aware RLS claims.
- Move GitHub Action target discovery from hard-coded packages to lockfile parsing.
- Stand up Railway workers plus Redis and configure dead-letter handling.
- Seed the public database with the top npm native-binary packages.
- Add Stripe only after entitlement and feature-flag behavior is verified.
