-- Watchlist proactive enforcement columns.
--
-- Adds two optional columns to `watchlists` that power the closed-loop
-- dependency-confusion and typosquat alerting feature:
--
--   internal_package_pattern  — a regex (stored as text) that identifies this
--     org's internal/private package names, e.g. `@acme/.*`.  When a scanned
--     lockfile contains a package matching this pattern that was NOT resolved
--     from one of the org's trusted sources, a `dependency_confusion` alert
--     fires with CRITICAL severity.
--
--   trusted_domains  — a jsonb array of trusted npm scope prefixes or registry
--     hostnames from which the org's internal packages are allowed to be
--     resolved, e.g. `["@acme", "npm.acme.internal"]`.  A package that matches
--     the internal pattern AND comes from one of these sources is considered
--     legitimate and does NOT trigger an alert.

alter table watchlists
  add column if not exists internal_package_pattern text,
  add column if not exists trusted_domains jsonb;

comment on column watchlists.internal_package_pattern is
  'Regex matching this org''s internal package names (e.g. @myorg/.*). '
  'When a scanned package matches but is not from a trusted source a '
  'dependency_confusion CRITICAL alert fires.';

comment on column watchlists.trusted_domains is
  'JSON array of trusted npm scope prefixes or registry hostnames '
  '(e.g. ["@myorg", "npm.myorg.internal"]) that are allowed to serve '
  'packages matching internal_package_pattern.';
