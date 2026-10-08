-- מיפוי עצמי – הקמת טבלאות ב-Supabase (מריצים פעם אחת ב-SQL Editor)
create extension if not exists pgcrypto with schema extensions;
create table if not exists public.sm_responses(
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  data jsonb not null,
  constraint sm_responses_size check (pg_column_size(data) < 60000),
  constraint sm_responses_obj check (jsonb_typeof(data) = 'object'));
create index if not exists sm_responses_created_idx on public.sm_responses(created_at);
create table if not exists public.sm_config(key text primary key, value jsonb not null, updated_at timestamptz not null default now());
create schema if not exists sm_private;
revoke all on schema sm_private from public, anon, authenticated;
create table if not exists sm_private.secrets(id int primary key default 1 check (id = 1), pass_hash text not null);
alter table public.sm_responses enable row level security;
alter table public.sm_config enable row level security;
drop policy if exists sm_responses_read on public.sm_responses;
drop policy if exists sm_responses_insert on public.sm_responses;
drop policy if exists sm_config_read on public.sm_config;
create policy sm_responses_read on public.sm_responses for select to anon, authenticated using (true);
create policy sm_responses_insert on public.sm_responses for insert to anon, authenticated
  with check (jsonb_typeof(data) = 'object' and coalesce(length(data->>'name'),0) between 1 and 120 and coalesce(length(data->>'className'),0) between 1 and 80);
create policy sm_config_read on public.sm_config for select to anon, authenticated using (true);
revoke update, delete, truncate on public.sm_responses from anon, authenticated;
revoke insert, update, delete, truncate on public.sm_config from anon, authenticated;
create or replace function public.sm_check_password(p_pass text) returns boolean language sql security definer set search_path = '' as $$
  select exists(select 1 from sm_private.secrets s where s.pass_hash = extensions.crypt(coalesce(p_pass,''), s.pass_hash)); $$;
create or replace function public.sm_delete_response(p_pass text, p_id uuid) returns boolean language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_password(p_pass) then return false; end if; delete from public.sm_responses where id = p_id; return true; end $$;
create or replace function public.sm_save_config(p_pass text, p_key text, p_value jsonb) returns boolean language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_password(p_pass) then return false; end if; if p_key not in ('texts') then return false; end if;
  insert into public.sm_config(key, value, updated_at) values (p_key, p_value, now()) on conflict (key) do update set value = excluded.value, updated_at = now(); return true; end $$;
create or replace function public.sm_set_password(p_old text, p_new text) returns boolean language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_password(p_old) then return false; end if; if length(coalesce(p_new,'')) < 6 then return false; end if;
  update sm_private.secrets set pass_hash = extensions.crypt(p_new, extensions.gen_salt('bf')) where id = 1; return true; end $$;
revoke all on function public.sm_check_password(text) from public;
revoke all on function public.sm_delete_response(text, uuid) from public;
revoke all on function public.sm_save_config(text, text, jsonb) from public;
revoke all on function public.sm_set_password(text, text) from public;
grant execute on function public.sm_check_password(text) to anon, authenticated;
grant execute on function public.sm_delete_response(text, uuid) to anon, authenticated;
grant execute on function public.sm_save_config(text, text, jsonb) to anon, authenticated;
grant execute on function public.sm_set_password(text, text) to anon, authenticated;
insert into sm_private.secrets(id, pass_hash) values (1, extensions.crypt('Orim-2026', extensions.gen_salt('bf'))) on conflict (id) do nothing;
