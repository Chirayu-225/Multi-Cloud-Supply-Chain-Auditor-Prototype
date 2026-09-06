-- Run this in the Supabase SQL Editor (Dashboard > SQL Editor > New query)

create table if not exists scan_results (
    id bigint generated always as identity primary key,
    object_key text not null,
    risk_score integer not null,
    findings jsonb not null,
    scanned_at timestamptz not null default now()
);

-- Allow the dashboard to read results via the public REST API (anon key,
-- read-only). Writes are done with the service_role key from the backend,
-- which bypasses RLS, so this policy only needs to cover SELECT.
alter table scan_results enable row level security;

create policy "Allow public read of scan results"
  on scan_results for select
  using (true);
