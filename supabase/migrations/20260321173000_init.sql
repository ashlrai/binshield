create extension if not exists pgcrypto;

create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  plan text not null default 'free',
  billing_status text not null default 'trialing',
  stripe_customer_id text,
  stripe_subscription_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists organization_members (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  user_id uuid not null,
  role text not null default 'member',
  created_at timestamptz not null default now(),
  unique (org_id, user_id)
);

create table if not exists packages (
  id uuid primary key default gen_random_uuid(),
  ecosystem text not null,
  name text not null,
  latest_analyzed_version text,
  total_versions_analyzed integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (ecosystem, name)
);

create table if not exists analyses (
  id uuid primary key default gen_random_uuid(),
  package_id uuid not null references packages(id) on delete cascade,
  version text not null,
  status text not null,
  risk_score integer not null default 0,
  risk_level text not null default 'none',
  summary text not null default '',
  source_match_confidence text not null default 'medium',
  behaviors jsonb not null default '{}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  binary_count integer not null default 0,
  total_binary_size bigint not null default 0,
  ghidra_version text,
  ai_model text,
  analysis_duration_ms integer,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (package_id, version)
);

create table if not exists binary_artifacts (
  id uuid primary key default gen_random_uuid(),
  sha256 text not null unique,
  filename text not null,
  architecture text,
  format text,
  file_size bigint not null,
  decompiled_preview text,
  imports jsonb not null default '[]'::jsonb,
  strings jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists binaries (
  id uuid primary key default gen_random_uuid(),
  analysis_id uuid not null references analyses(id) on delete cascade,
  artifact_id uuid references binary_artifacts(id),
  filename text not null,
  architecture text,
  format text,
  file_size bigint not null,
  function_count integer not null default 0,
  import_count integer not null default 0,
  risk_score integer not null default 0,
  risk_level text not null default 'none',
  ai_explanation text not null default '',
  behaviors jsonb not null default '{}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists repos (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  github_repo text not null,
  native_dep_count integer not null default 0,
  aggregate_risk_score integer not null default 0,
  last_scan_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, github_repo)
);

create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  label text not null,
  prefix text not null,
  hashed_key text not null unique,
  scopes text[] not null default '{}'::text[],
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

create table if not exists watchlists (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  name text not null,
  channel text not null check (channel in ('email', 'slack', 'webhook')),
  destination text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists watchlist_packages (
  id uuid primary key default gen_random_uuid(),
  watchlist_id uuid not null references watchlists(id) on delete cascade,
  ecosystem text not null,
  package_name text not null,
  version text,
  created_at timestamptz not null default now(),
  unique (watchlist_id, ecosystem, package_name, version)
);

create table if not exists subscriptions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  provider text not null default 'manual',
  customer_id text,
  subscription_id text,
  plan text not null default 'free',
  status text not null default 'trialing',
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id)
);

create table if not exists billing_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  event_type text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists email_alerts (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  watchlist_id uuid references watchlists(id) on delete set null,
  package_name text not null,
  ecosystem text not null,
  version text,
  channel text not null default 'email',
  destination text not null,
  status text not null default 'queued',
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  delivered_at timestamptz
);

create table if not exists analysis_jobs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references organizations(id) on delete set null,
  ecosystem text not null,
  package_name text not null,
  version text not null,
  status text not null,
  error text,
  requested_at timestamptz not null default now(),
  completed_at timestamptz
);

create table if not exists repo_scans (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  repo_id uuid not null references repos(id) on delete cascade,
  analysis_job_id uuid references analysis_jobs(id) on delete set null,
  status text not null default 'queued',
  scanned_at timestamptz,
  created_at timestamptz not null default now()
);

create or replace function set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists organizations_set_updated_at on organizations;
create trigger organizations_set_updated_at
before update on organizations
for each row execute function set_updated_at();

drop trigger if exists packages_set_updated_at on packages;
create trigger packages_set_updated_at
before update on packages
for each row execute function set_updated_at();

drop trigger if exists analyses_set_updated_at on analyses;
create trigger analyses_set_updated_at
before update on analyses
for each row execute function set_updated_at();

drop trigger if exists repos_set_updated_at on repos;
create trigger repos_set_updated_at
before update on repos
for each row execute function set_updated_at();

drop trigger if exists watchlists_set_updated_at on watchlists;
create trigger watchlists_set_updated_at
before update on watchlists
for each row execute function set_updated_at();

drop trigger if exists subscriptions_set_updated_at on subscriptions;
create trigger subscriptions_set_updated_at
before update on subscriptions
for each row execute function set_updated_at();

create index if not exists packages_ecosystem_name_idx on packages (ecosystem, name);
create index if not exists analyses_package_version_idx on analyses (package_id, version);
create index if not exists repos_org_repo_idx on repos (org_id, github_repo);
create index if not exists api_keys_hashed_key_idx on api_keys (hashed_key);
create index if not exists watchlists_org_idx on watchlists (org_id);
create index if not exists watchlist_packages_watchlist_idx on watchlist_packages (watchlist_id);
create index if not exists subscriptions_org_idx on subscriptions (org_id);
create index if not exists billing_events_org_idx on billing_events (org_id);
create index if not exists email_alerts_org_idx on email_alerts (org_id);
create index if not exists analysis_jobs_org_idx on analysis_jobs (org_id);
create index if not exists repo_scans_org_idx on repo_scans (org_id);

alter table organizations enable row level security;
alter table organization_members enable row level security;
alter table packages enable row level security;
alter table analyses enable row level security;
alter table binaries enable row level security;
alter table binary_artifacts enable row level security;
alter table repos enable row level security;
alter table api_keys enable row level security;
alter table watchlists enable row level security;
alter table watchlist_packages enable row level security;
alter table subscriptions enable row level security;
alter table billing_events enable row level security;
alter table email_alerts enable row level security;
alter table analysis_jobs enable row level security;
alter table repo_scans enable row level security;

create or replace function is_org_member(target_org uuid)
returns boolean
language sql
stable
as $$
  select exists (
    select 1
    from organization_members
    where org_id = target_org
      and user_id = auth.uid()
  );
$$;

drop policy if exists organizations_read_own on organizations;
create policy organizations_read_own
on organizations
for select
using (is_org_member(id) or auth.role() = 'service_role');

drop policy if exists organizations_write_service on organizations;
create policy organizations_write_service
on organizations
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

drop policy if exists organization_members_access on organization_members;
create policy organization_members_access
on organization_members
for select
using (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists organization_members_write_service on organization_members;
create policy organization_members_write_service
on organization_members
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

drop policy if exists packages_public_read on packages;
create policy packages_public_read
on packages
for select
using (true);

drop policy if exists packages_service_write on packages;
create policy packages_service_write
on packages
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

drop policy if exists analyses_public_read on analyses;
create policy analyses_public_read
on analyses
for select
using (true);

drop policy if exists analyses_service_write on analyses;
create policy analyses_service_write
on analyses
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

drop policy if exists binaries_public_read on binaries;
create policy binaries_public_read
on binaries
for select
using (true);

drop policy if exists binaries_service_write on binaries;
create policy binaries_service_write
on binaries
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

drop policy if exists binary_artifacts_service_only on binary_artifacts;
create policy binary_artifacts_service_only
on binary_artifacts
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

drop policy if exists repos_org_access on repos;
create policy repos_org_access
on repos
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists api_keys_org_access on api_keys;
create policy api_keys_org_access
on api_keys
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists watchlists_org_access on watchlists;
create policy watchlists_org_access
on watchlists
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists watchlist_packages_org_access on watchlist_packages;
create policy watchlist_packages_org_access
on watchlist_packages
for all
using (
  exists (
    select 1
    from watchlists
    where watchlists.id = watchlist_packages.watchlist_id
      and is_org_member(watchlists.org_id)
  )
  or auth.role() = 'service_role'
)
with check (
  exists (
    select 1
    from watchlists
    where watchlists.id = watchlist_packages.watchlist_id
      and is_org_member(watchlists.org_id)
  )
  or auth.role() = 'service_role'
);

drop policy if exists subscriptions_org_access on subscriptions;
create policy subscriptions_org_access
on subscriptions
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists billing_events_org_access on billing_events;
create policy billing_events_org_access
on billing_events
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists email_alerts_org_access on email_alerts;
create policy email_alerts_org_access
on email_alerts
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists analysis_jobs_org_access on analysis_jobs;
create policy analysis_jobs_org_access
on analysis_jobs
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

drop policy if exists repo_scans_org_access on repo_scans;
create policy repo_scans_org_access
on repo_scans
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');
