-- Proactive alert loop.
--
-- Closes the loop from "a malicious package was discovered" to "the orgs that
-- depend on it are warned." Three tables:
--
--   lockfile_dependencies — a normalized index of every dependency seen in an
--     org's lockfile scans (including transitive deps), so a flagged package
--     can be matched back to affected orgs in one indexed query.
--   notification_channels — per-org delivery channels (email/Slack/webhook).
--   alerts               — delivery ledger; its unique index is also the
--     dedup key so an org is never alerted twice for the same package@version.
--
-- This migration also deprecates `email_alerts` (left in place, read-only
-- legacy) in favour of `alerts`.

-- ---------------------------------------------------------------------------
-- lockfile_dependencies
-- ---------------------------------------------------------------------------

create table if not exists lockfile_dependencies (
  id uuid primary key default gen_random_uuid(),
  lockfile_scan_id uuid references lockfile_scans(id) on delete cascade,
  org_id uuid not null references organizations(id) on delete cascade,
  repo_id uuid references repos(id) on delete set null,
  ecosystem text not null,
  package_name text not null,
  version text not null,
  is_native boolean not null default false,
  is_direct boolean not null default false,
  source text not null default 'lockfile-scan',
  created_at timestamptz not null default now()
);

create index if not exists lockfile_deps_lookup_idx on lockfile_dependencies (ecosystem, package_name);
create index if not exists lockfile_deps_org_idx on lockfile_dependencies (org_id);
create index if not exists lockfile_deps_scan_idx on lockfile_dependencies (lockfile_scan_id);

alter table lockfile_dependencies enable row level security;

drop policy if exists lockfile_dependencies_org_access on lockfile_dependencies;
create policy lockfile_dependencies_org_access
on lockfile_dependencies
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- notification_channels
-- ---------------------------------------------------------------------------

create table if not exists notification_channels (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  channel text not null check (channel in ('email', 'slack', 'webhook')),
  destination text not null,
  secret text,
  enabled boolean not null default true,
  min_risk_level text not null default 'high' check (min_risk_level in ('low', 'medium', 'high', 'critical')),
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, channel, destination)
);

create index if not exists notification_channels_org_idx on notification_channels (org_id);

drop trigger if exists notification_channels_set_updated_at on notification_channels;
create trigger notification_channels_set_updated_at
before update on notification_channels
for each row execute function set_updated_at();

alter table notification_channels enable row level security;

drop policy if exists notification_channels_org_access on notification_channels;
create policy notification_channels_org_access
on notification_channels
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- alerts (delivery ledger + dedup key)
-- ---------------------------------------------------------------------------

create table if not exists alerts (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  ecosystem text not null,
  package_name text not null,
  version text not null,
  risk_level text not null,
  risk_score integer not null default 0,
  match_reason text not null check (match_reason in ('watchlist', 'lockfile')),
  watchlist_id uuid references watchlists(id) on delete set null,
  lockfile_scan_id uuid references lockfile_scans(id) on delete set null,
  channel text not null,
  destination text not null,
  status text not null default 'pending' check (status in ('pending', 'sent', 'failed', 'suppressed')),
  error text,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  delivered_at timestamptz
);

-- One alert per (org, package@version, channel, destination) — the dedup key.
create unique index if not exists alerts_dedup_idx
  on alerts (org_id, ecosystem, package_name, version, channel, destination);
create index if not exists alerts_org_idx on alerts (org_id, created_at desc);

alter table alerts enable row level security;

drop policy if exists alerts_org_access on alerts;
create policy alerts_org_access
on alerts
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');
