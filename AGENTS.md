# BinShield agent instructions

## Article 1: Full autonomy, always forward

Follow the [Ashlr Fleet Constitution, Article 1](https://github.com/ashlrai/phantom/blob/master/AGENTS.md#article-1-full-autonomy-always-forward). Agents may open and land BinShield PRs when their standing scope allows and the required `ashlr/verify` and `verify` checks pass. Arm GitHub auto-merge when the repository supports it. Honor Security GATES v3, the fleet hold list, and GitHub protections. No force-push to default branches, admin overrides, billing changes, secret disclosure, or making private material public.

## Verify and release

- Branch from `main` and follow [CONTRIBUTING.md](CONTRIBUTING.md). Install with `pnpm install --frozen-lockfile` and run `pnpm check` before opening the PR.
- If the GitHub Action changes, rebuild and commit its bundle as described in the contributor guide.
- Release from the verified default branch through the [Release workflow](.github/workflows/release.yml). An authorized agent can run `gh workflow run release.yml -R ashlrai/binshield --ref main -f version=<X.Y.Z>`. The workflow validates the workspace and Action bundle before creating the GitHub release.
- The [Marketplace mirror procedure](CONTRIBUTING.md) has its own maintainer step. The [website](apps/web) uses the repository's [Vercel build configuration](apps/web/vercel.json).
