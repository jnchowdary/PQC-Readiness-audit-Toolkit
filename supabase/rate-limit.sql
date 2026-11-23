-- Diarka PQC Quick Check: rate limit for the instant check (/api/pqc-check).
-- Run once in Supabase: SQL Editor > New query > paste > Run.
-- Safe to run again: it only creates what is missing and replaces the function.

-- One row per instant check. The IP address is stored only as a salted hash.
-- The domain checked is kept for 30 days: useful to see what people check,
-- even when they don't ask for a report. Older rows are deleted by the daily
-- keep-alive job (api/keepalive.js).
create table if not exists public.scan_events (
  id          bigint generated always as identity primary key,
  created_at  timestamptz not null default now(),
  ip_hash     text not null,
  domain      text not null
);

create index if not exists scan_events_ip_recent on public.scan_events (ip_hash, created_at);
create index if not exists scan_events_recent    on public.scan_events (created_at);

alter table public.scan_events enable row level security;

-- Checks the limits and records the scan in one step.
-- Returns 'OK', 'IP_BURST', 'IP_DAILY' or 'GLOBAL'.
create or replace function public.allow_scan(
  p_ip text, p_domain text,
  p_per_10min int, p_per_day int, p_global_hour int
) returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  n int;
begin
  -- Serialise checks for the same visitor so two parallel requests can't both slip under the limit.
  perform pg_advisory_xact_lock(hashtext(p_ip));

  select count(*) into n from scan_events
   where ip_hash = p_ip and created_at > now() - interval '10 minutes';
  if n >= p_per_10min then return 'IP_BURST'; end if;

  select count(*) into n from scan_events
   where ip_hash = p_ip and created_at > now() - interval '1 day';
  if n >= p_per_day then return 'IP_DAILY'; end if;

  select count(*) into n from scan_events
   where created_at > now() - interval '1 hour';
  if n >= p_global_hour then return 'GLOBAL'; end if;

  insert into scan_events (ip_hash, domain) values (p_ip, left(p_domain, 253));
  return 'OK';
end;
$$;

-- Only the server's secret key may use these. The public key gets nothing.
revoke all on table public.scan_events from anon, authenticated;
grant select, delete on table public.scan_events to service_role;
revoke execute on function public.allow_scan(text, text, int, int, int) from public, anon, authenticated;
grant execute on function public.allow_scan(text, text, int, int, int) to service_role;
