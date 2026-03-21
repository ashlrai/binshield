# BinShield GitHub Action

This action scans npm dependencies by discovering packages from `package-lock.json` or `npm-shrinkwrap.json`, submits them to the BinShield API, and renders results in the workflow summary or PR comments.

The report format is intentionally security-native:

- each row includes risk, evidence cues, and a remediation hint
- failures combine scan errors and threshold violations into one actionable message
- summary output mirrors the PR comment so teams see the same signal in both places

## Inputs

- `api-base-url`: BinShield API URL, default `http://localhost:4000`
- `api-key`: optional API key for authenticated scan submission
- `github-token`: optional token used when `comment-mode` enables PR comments
- `working-directory`: repo path to inspect, default `.`
- `scan-mode`: `native-only` or `all-dependencies`, default `native-only`
- `include-dev-dependencies`: include dev dependencies from the lockfile, default `false`
- `fail-on`: `critical`, `high`, `medium`, `low`, or `never`
- `comment-mode`: `summary`, `pr-comment`, `both`, or `off`
- `poll-interval-ms`: polling delay, default `1500`
- `timeout-ms`: polling timeout, default `120000`
- `max-targets`: cap on discovered dependency targets, default `50`

## Behavior

- The action prefers lockfile data over hard-coded package names.
- Native-package detection is heuristic by default, but `scan-mode: all-dependencies` forces all discovered packages to be scanned.
- PR comments are only posted when `comment-mode` allows them and a `github-token` is available.
- If a PR comment is requested without a token, the action still writes the summary and emits a warning rather than failing silently.
