-- Multi-Cloud AI Supply Chain Auditor — database setup.
-- Run in the Supabase SQL Editor. Safe to re-run.

-- ---------------------------------------------------------------------------
-- 1. Storage bucket: private, size-capped
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit)
values ('supply-chain-artifacts', 'supply-chain-artifacts', false, 52428800)  -- 50 MiB
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit;

-- The dashboard uploads with the anon key, so anon may INSERT into this
-- bucket only — no listing, reading, overwriting or deleting.
-- Review Dashboard > Storage > Policies and drop any broader policy you
-- created by hand earlier.
drop policy if exists "anon upload to supply-chain-artifacts" on storage.objects;
create policy "anon upload to supply-chain-artifacts"
  on storage.objects for insert to anon
  with check (
    bucket_id = 'supply-chain-artifacts'
    and octet_length(name) <= 200
    and name ~ '^[A-Za-z0-9._-]+$'          -- no folders, no odd characters
  );

-- ---------------------------------------------------------------------------
-- 2. Results
-- ---------------------------------------------------------------------------
create table if not exists scan_results (
    id bigint generated always as identity primary key,
    object_key text not null,
    risk_score integer not null,
    findings jsonb not null,
    scanned_at timestamptz not null default now()
);
alter table scan_results add column if not exists job_id bigint;
alter table scan_results add column if not exists sha256 text;

alter table scan_results enable row level security;
drop policy if exists "Allow public read of scan results" on scan_results;
create policy "Allow public read of scan results"
  on scan_results for select to anon, authenticated
  using (true);

-- ---------------------------------------------------------------------------
-- 3. Durable job queue
-- ---------------------------------------------------------------------------
create table if not exists scan_jobs (
    id bigint generated always as identity primary key,
    bucket text not null,
    object_key text not null,
    status text not null default 'pending'
        check (status in ('pending', 'running', 'done', 'failed')),
    attempts integer not null default 0,
    last_error text,
    created_at timestamptz not null default now(),
    claimed_at timestamptz,
    finished_at timestamptz,
    unique (bucket, object_key)
);
create index if not exists scan_jobs_status_idx on scan_jobs (status, created_at);

alter table scan_jobs enable row level security;
drop policy if exists "Allow public read of scan jobs" on scan_jobs;
create policy "Allow public read of scan jobs"
  on scan_jobs for select to anon, authenticated
  using (true);

-- A file landing in the bucket creates a job — inside the same
-- transaction, so the job can't be lost even if nothing else is running.
create or replace function enqueue_scan_job()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.bucket_id = 'supply-chain-artifacts' then
    insert into scan_jobs (bucket, object_key)
    values (new.bucket_id, new.name)
    on conflict (bucket, object_key) do update
      set status = 'pending', attempts = 0, last_error = null,
          claimed_at = null, finished_at = null;
  end if;
  return new;
end $$;

drop trigger if exists on_artifact_uploaded on storage.objects;
create trigger on_artifact_uploaded
  after insert on storage.objects
  for each row execute function enqueue_scan_job();

-- Claim the oldest runnable job. Also reclaims jobs stuck in 'running'
-- (worker crashed mid-scan) and gives up on ones that keep failing.
create or replace function claim_scan_job(max_attempts integer default 3, stale_after interval default '10 minutes')
returns setof scan_jobs language plpgsql security definer set search_path = public as $$
begin
  update scan_jobs
     set status = 'failed', finished_at = now(),
         last_error = coalesce(last_error, 'Gave up after repeated stalls')
   where status = 'running'
     and claimed_at < now() - stale_after
     and attempts >= max_attempts;

  return query
  update scan_jobs j
     set status = 'running', attempts = j.attempts + 1, claimed_at = now()
   where j.id = (
       select id from scan_jobs
        where attempts < max_attempts
          and (status = 'pending'
               or (status = 'running' and claimed_at < now() - stale_after))
        order by created_at
        for update skip locked
        limit 1)
  returning j.*;
end $$;

create or replace function complete_scan_job(p_job_id bigint, p_sha256 text, p_risk_score integer, p_findings jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare v_key text;
begin
  update scan_jobs set status = 'done', finished_at = now(), last_error = null
   where id = p_job_id
  returning object_key into v_key;
  if v_key is null then
    raise exception 'Unknown job %', p_job_id;
  end if;
  insert into scan_results (job_id, object_key, sha256, risk_score, findings)
  values (p_job_id, v_key, p_sha256, p_risk_score, p_findings);
end $$;

create or replace function fail_scan_job(p_job_id bigint, p_error text, p_max_attempts integer default 3)
returns void language plpgsql security definer set search_path = public as $$
begin
  update scan_jobs
     set status = case when attempts >= p_max_attempts then 'failed' else 'pending' end,
         last_error = p_error,
         finished_at = case when attempts >= p_max_attempts then now() else null end
   where id = p_job_id;
end $$;

-- Only the backend (service_role) may drive the queue.
revoke all on function claim_scan_job(integer, interval) from public, anon, authenticated;
revoke all on function complete_scan_job(bigint, text, integer, jsonb) from public, anon, authenticated;
revoke all on function fail_scan_job(bigint, text, integer) from public, anon, authenticated;
revoke all on function enqueue_scan_job() from public, anon, authenticated;
grant execute on function claim_scan_job(integer, interval) to service_role;
grant execute on function complete_scan_job(bigint, text, integer, jsonb) to service_role;
grant execute on function fail_scan_job(bigint, text, integer) to service_role;

-- ---------------------------------------------------------------------------
-- 4. Webhook (Dashboard > Database > Webhooks)
--    Table: public.scan_jobs   Events: INSERT   Type: Supabase Edge Function
--    Function: storage-trigger  Add the service-role Authorization header.
-- ---------------------------------------------------------------------------
