-- SBOM Provenance Audit Log
--
-- Stores the results of every POST /sbom/verify-provenance request so that
-- organisations can audit their supply-chain verification history.
--
-- Each row captures:
--   package_format     — 'npm' or 'pypi'
--   is_valid           — whether all dependency checks passed
--   check_count        — total number of dependencies checked
--   failed_check_count — number of checks that found issues
--   risk_level         — aggregate risk: none | low | medium | high | critical
--   checks             — full per-dependency check results (jsonb array)
--   recommendations    — list of remediation suggestions (jsonb array)
--   created_at         — timestamp of the verification request

create table if not exists sbom_provenance_audit_log (
  id                 uuid         primary key default gen_random_uuid(),
  package_format     text         not null
    check (package_format in ('npm', 'pypi')),
  is_valid           boolean      not null default false,
  check_count        integer      not null default 0,
  failed_check_count integer      not null default 0,
  risk_level         text         not null default 'none'
    check (risk_level in ('none', 'low', 'medium', 'high', 'critical')),
  checks             jsonb        not null default '[]'::jsonb,
  recommendations    jsonb        not null default '[]'::jsonb,
  created_at         timestamptz  not null default now()
);

-- Efficiently find all failed verifications
create index if not exists sbom_provenance_audit_log_failed_idx
  on sbom_provenance_audit_log (created_at desc)
  where is_valid = false;

-- Filter by risk level
create index if not exists sbom_provenance_audit_log_risk_idx
  on sbom_provenance_audit_log (risk_level, created_at desc);

-- Filter by ecosystem
create index if not exists sbom_provenance_audit_log_format_idx
  on sbom_provenance_audit_log (package_format, created_at desc);

comment on table sbom_provenance_audit_log is
  'Audit trail of SBOM provenance verification results. '
  'Each row represents one POST /sbom/verify-provenance call and records '
  'the per-dependency check outcomes, aggregate risk level, and recommendations.';

comment on column sbom_provenance_audit_log.checks is
  'JSON array of ProvenanceCheck objects — one per dependency examined.';

comment on column sbom_provenance_audit_log.recommendations is
  'JSON array of human-readable remediation recommendations.';
