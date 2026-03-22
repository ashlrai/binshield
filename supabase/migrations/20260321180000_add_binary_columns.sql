-- Add columns to binaries table that the API SupabaseRepository expects
-- but were missing from the initial schema (stored in binary_artifacts instead).

alter table binaries
  add column if not exists decompiled_preview text not null default '';

alter table binaries
  add column if not exists imports jsonb not null default '[]'::jsonb;

alter table binaries
  add column if not exists strings jsonb not null default '[]'::jsonb;
