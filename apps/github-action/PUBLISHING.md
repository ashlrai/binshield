# Publishing BinShield to the GitHub Marketplace

Follow these steps in order. Steps marked **[human]** require a browser and a GitHub account with Marketplace permissions.

---

## Prerequisites

- [ ] You are an admin of `github.com/ashlrai/binshield`
- [ ] The `main` branch is green (CI passes, `dist/` is committed and fresh — see step 1)
- [ ] You have accepted (or will accept) the GitHub Marketplace Developer Agreement during step 4

---

## Step 1 — Ensure `dist/` is committed and fresh

The action runs from the compiled bundle in `dist/`. It must be committed to the repo.

```bash
# From the repo root
pnpm --filter @binshield/github-action build

# Verify the output changed (or is already up to date)
git diff --stat apps/github-action/dist/

# If there are changes, commit them before cutting the release
git add apps/github-action/dist/
git commit -m "chore: rebuild github-action dist for release"
git push
```

---

## Step 2 — Tag the release

```bash
git tag v1.0.0
git push origin v1.0.0
```

Use semver. The Marketplace will show this tag as the version users pin to. After `v1.0.0` is published, also push a floating `v1` tag so users can write `@v1`:

```bash
git tag -f v1
git push -f origin v1
```

---

## Step 3 — Create a GitHub Release **[human]**

1. Go to `https://github.com/ashlrai/binshield/releases/new`
2. Select the `v1.0.0` tag you just pushed
3. Set the release title: **BinShield Supply Chain Scanner v1.0.0**
4. Write release notes (what threats it catches, changelog)
5. **Do not publish yet** — proceed to step 4 first

---

## Step 4 — Publish to the GitHub Marketplace **[human]**

On the "Create release" page (before clicking "Publish release"):

1. Check the box **"Publish this Action to the GitHub Marketplace"**
   - GitHub validates `action.yml` exists and the `name` field is unique on the Marketplace
   - If the name is already taken, change `name:` in `action.yml`, rebuild, recommit, and re-tag
2. **Accept the GitHub Marketplace Developer Agreement** when prompted (one-time)
3. Under **Primary Category**, select: **Security**
4. Under **Secondary Category** (optional), select: **Continuous integration**
5. Click **"Publish release"**

---

## Step 5 — Verify the listing **[human]**

1. Go to `https://github.com/marketplace/actions/binshield-supply-chain-scanner`
   - The slug is derived from the `name:` field in `action.yml` (lowercase, spaces → hyphens)
2. Confirm the description, branding icon/color, inputs, and outputs render correctly
3. Test the installable reference from the Marketplace listing page works in a sample repo:
   ```yaml
   uses: ashlrai/binshield/apps/github-action@v1
   ```

---

## Updating after the initial release

For patch and minor releases:

```bash
# Rebuild dist
pnpm --filter @binshield/github-action build
git add apps/github-action/dist/
git commit -m "chore: rebuild dist"

# Tag the new version
git tag v1.0.1
git push origin v1.0.1

# Move the floating v1 tag
git tag -f v1
git push -f origin v1

# Create a GitHub Release — it will automatically update the Marketplace listing
```

---

## Notes

- The action lives at `apps/github-action/` in the monorepo. Users reference it as `ashlrai/binshield/apps/github-action@v1` — this is the correct subdirectory syntax for GitHub Actions.
- `@main` works at any time (before or after a tag) and always tracks the latest commit on `main`.
- The `dist/` directory must be checked in. GitHub Actions runner does not run `npm install` or build steps — it executes `dist/apps/github-action/src/index.js` directly as declared in `action.yml`.
