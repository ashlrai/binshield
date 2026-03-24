-- BinShield Platform Expansion Migration
-- Adds tables for: usage tracking, package discovery, vulnerability advisories,
-- lockfile scanning, live ecosystem feed, and compliance reporting.

-- ---------------------------------------------------------------------------
-- Phase 1: Usage tracking for entitlement enforcement
-- ---------------------------------------------------------------------------

create table if not exists usage_records (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  period_start timestamptz not null,
  period_end timestamptz not null,
  scan_count integer not null default 0,
  repo_count integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, period_start)
);

create index if not exists usage_records_org_period_idx on usage_records (org_id, period_start);

drop trigger if exists usage_records_set_updated_at on usage_records;
create trigger usage_records_set_updated_at
before update on usage_records
for each row execute function set_updated_at();

alter table usage_records enable row level security;

drop policy if exists usage_records_org_access on usage_records;
create policy usage_records_org_access
on usage_records
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

-- Organization invitations
create table if not exists org_invitations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  email text not null,
  role text not null default 'member',
  token text not null unique,
  invited_by uuid,
  accepted_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists org_invitations_token_idx on org_invitations (token);
create index if not exists org_invitations_org_idx on org_invitations (org_id);

alter table org_invitations enable row level security;

drop policy if exists org_invitations_access on org_invitations;
create policy org_invitations_access
on org_invitations
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

-- Audit log
create table if not exists audit_log (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  user_id uuid,
  action text not null,
  resource_type text not null,
  resource_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists audit_log_org_idx on audit_log (org_id, created_at desc);

alter table audit_log enable row level security;

drop policy if exists audit_log_org_access on audit_log;
create policy audit_log_org_access
on audit_log
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- Phase 2: Package discovery and enrichment
-- ---------------------------------------------------------------------------

-- Expand packages table with enrichment columns
alter table packages add column if not exists weekly_downloads bigint default 0;
alter table packages add column if not exists github_stars integer default 0;
alter table packages add column if not exists github_repo_url text;
alter table packages add column if not exists maintainer_count integer default 0;
alter table packages add column if not exists last_published_at timestamptz;
alter table packages add column if not exists category text;
alter table packages add column if not exists description text;

-- Track crawler runs
create table if not exists crawler_runs (
  id uuid primary key default gen_random_uuid(),
  source text not null,
  status text not null default 'running',
  packages_discovered integer default 0,
  packages_queued integer default 0,
  packages_scanned integer default 0,
  errors jsonb not null default '[]'::jsonb,
  started_at timestamptz not null default now(),
  completed_at timestamptz
);

alter table crawler_runs enable row level security;

drop policy if exists crawler_runs_service_only on crawler_runs;
create policy crawler_runs_service_only
on crawler_runs
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

-- Track discovered native packages (before scanning)
create table if not exists discovered_packages (
  id uuid primary key default gen_random_uuid(),
  ecosystem text not null,
  name text not null,
  latest_version text,
  discovery_source text not null,
  native_indicators jsonb not null default '{}'::jsonb,
  weekly_downloads bigint default 0,
  priority_score integer default 0,
  scan_status text not null default 'pending',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (ecosystem, name)
);

create index if not exists discovered_packages_status_idx on discovered_packages (scan_status, priority_score desc);
create index if not exists discovered_packages_ecosystem_idx on discovered_packages (ecosystem, name);

drop trigger if exists discovered_packages_set_updated_at on discovered_packages;
create trigger discovered_packages_set_updated_at
before update on discovered_packages
for each row execute function set_updated_at();

alter table discovered_packages enable row level security;

drop policy if exists discovered_packages_public_read on discovered_packages;
create policy discovered_packages_public_read
on discovered_packages
for select
using (true);

drop policy if exists discovered_packages_service_write on discovered_packages;
create policy discovered_packages_service_write
on discovered_packages
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- Phase 3: Vulnerability advisories
-- ---------------------------------------------------------------------------

create table if not exists advisories (
  id uuid primary key default gen_random_uuid(),
  source text not null,
  source_id text not null,
  title text not null,
  description text,
  severity text,
  cvss_score decimal(3,1),
  cvss_vector text,
  cwe_ids text[] not null default '{}'::text[],
  published_at timestamptz,
  updated_at timestamptz,
  withdrawn_at timestamptz,
  "references" jsonb not null default '[]'::jsonb,
  raw_data jsonb,
  created_at timestamptz not null default now(),
  unique (source, source_id)
);

create index if not exists advisories_source_idx on advisories (source, source_id);
create index if not exists advisories_severity_idx on advisories (severity);
create index if not exists advisories_published_idx on advisories (published_at desc);

alter table advisories enable row level security;

drop policy if exists advisories_public_read on advisories;
create policy advisories_public_read
on advisories
for select
using (true);

drop policy if exists advisories_service_write on advisories;
create policy advisories_service_write
on advisories
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

-- Junction table linking advisories to affected packages
create table if not exists package_advisories (
  id uuid primary key default gen_random_uuid(),
  advisory_id uuid not null references advisories(id) on delete cascade,
  ecosystem text not null,
  package_name text not null,
  vulnerable_range text,
  patched_version text,
  created_at timestamptz not null default now()
);

create index if not exists pkg_advisory_lookup_idx on package_advisories (ecosystem, package_name);
create index if not exists pkg_advisory_advisory_idx on package_advisories (advisory_id);

alter table package_advisories enable row level security;

drop policy if exists package_advisories_public_read on package_advisories;
create policy package_advisories_public_read
on package_advisories
for select
using (true);

drop policy if exists package_advisories_service_write on package_advisories;
create policy package_advisories_service_write
on package_advisories
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

-- Track when advisories were last synced for each package
create table if not exists advisory_sync_state (
  ecosystem text not null,
  package_name text not null,
  last_synced_at timestamptz not null default now(),
  advisory_count integer not null default 0,
  primary key (ecosystem, package_name)
);

alter table advisory_sync_state enable row level security;

drop policy if exists advisory_sync_service_only on advisory_sync_state;
create policy advisory_sync_service_only
on advisory_sync_state
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- Phase 5: Lockfile scanning
-- ---------------------------------------------------------------------------

create table if not exists lockfile_scans (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  repo_id uuid references repos(id) on delete set null,
  filename text not null,
  format text not null,
  total_dependencies integer not null default 0,
  native_dependencies integer not null default 0,
  aggregate_risk_score integer not null default 0,
  aggregate_risk_level text not null default 'none',
  status text not null default 'processing',
  results jsonb,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

create index if not exists lockfile_scans_org_idx on lockfile_scans (org_id, created_at desc);

alter table lockfile_scans enable row level security;

drop policy if exists lockfile_scans_org_access on lockfile_scans;
create policy lockfile_scans_org_access
on lockfile_scans
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- Phase 6: Live ecosystem feed
-- ---------------------------------------------------------------------------

create table if not exists feed_state (
  id text primary key default 'npm',
  last_seq text not null default '0',
  packages_processed bigint not null default 0,
  native_packages_found bigint not null default 0,
  updated_at timestamptz not null default now()
);

alter table feed_state enable row level security;

drop policy if exists feed_state_service_only on feed_state;
create policy feed_state_service_only
on feed_state
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

create table if not exists feed_events (
  id uuid primary key default gen_random_uuid(),
  ecosystem text not null,
  package_name text not null,
  version text not null,
  event_type text not null,
  risk_score integer,
  risk_level text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists feed_events_time_idx on feed_events (created_at desc);
create index if not exists feed_events_risk_idx on feed_events (risk_level, created_at desc);

alter table feed_events enable row level security;

drop policy if exists feed_events_public_read on feed_events;
create policy feed_events_public_read
on feed_events
for select
using (true);

drop policy if exists feed_events_service_write on feed_events;
create policy feed_events_service_write
on feed_events
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- Phase 7: Compliance reports
-- ---------------------------------------------------------------------------

create table if not exists compliance_reports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  report_type text not null,
  title text not null,
  status text not null default 'generating',
  scope jsonb not null default '{}'::jsonb,
  summary jsonb not null default '{}'::jsonb,
  file_url text,
  created_at timestamptz not null default now(),
  generated_at timestamptz
);

create index if not exists compliance_reports_org_idx on compliance_reports (org_id, created_at desc);

alter table compliance_reports enable row level security;

drop policy if exists compliance_reports_org_access on compliance_reports;
create policy compliance_reports_org_access
on compliance_reports
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');
