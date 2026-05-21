-- Finding suppressions.
--
-- Lets an org permanently suppress a false-positive finding so it never
-- surfaces again on the dashboard, GitHub Action output, or API responses.
-- Suppression can be scoped to a single version (version IS NOT NULL) or
-- to all versions of a package (version IS NULL).  Category and title
-- filters are both optional — if both are NULL the suppression matches
-- any finding on the matched package.

create table if not exists finding_suppressions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  ecosystem text not null,
  package_name text not null,
  version text,                     -- NULL = all versions
  finding_category text,            -- NULL = any category
  finding_title text,               -- NULL = any title
  reason text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists finding_suppressions_org_idx
  on finding_suppressions (org_id);

create index if not exists finding_suppressions_lookup_idx
  on finding_suppressions (org_id, ecosystem, package_name);

alter table finding_suppressions enable row level security;

drop policy if exists finding_suppressions_org_access on finding_suppressions;
create policy finding_suppressions_org_access
on finding_suppressions
for all
using (is_org_member(org_id) or auth.role() = 'service_role')
with check (is_org_member(org_id) or auth.role() = 'service_role');
