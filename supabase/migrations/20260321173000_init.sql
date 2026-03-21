create extension if not exists pgcrypto;

create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  plan text not null default 'free',
  stripe_customer_id text,
  created_at timestamptz not null default now()
);

create table if not exists packages (
  id uuid primary key default gen_random_uuid(),
  ecosystem text not null,
  name text not null,
  latest_analyzed_version text,
  total_versions_analyzed integer not null default 0,
  created_at timestamptz not null default now(),
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
  behaviors jsonb not null default '{}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  binary_count integer not null default 0,
  total_binary_size bigint not null default 0,
  ghidra_version text,
  ai_model text,
  analysis_duration_ms integer,
  created_at timestamptz not null default now(),
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
  created_at timestamptz not null default now()
);

create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  label text not null,
  hashed_key text not null,
  created_at timestamptz not null default now()
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

alter table organizations enable row level security;
alter table repos enable row level security;
alter table api_keys enable row level security;

create policy if not exists "org members can read organizations"
on organizations for select
using (true);

create policy if not exists "org members can read repos"
on repos for select
using (true);

create policy if not exists "org members can read api keys"
on api_keys for select
using (true);
