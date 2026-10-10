-- שאלונים מותאמים – תמונות מוגנות בקוד צוות, ושמירת נוסחים (מריצים פעם אחת ב-SQL Editor)
alter table sm_private.secrets add column if not exists staff_hash text;
update sm_private.secrets set staff_hash = extensions.crypt('2026', extensions.gen_salt('bf')) where id = 1 and staff_hash is null;

create table if not exists public.sm_photos(
  cls text not null, name text not null, slot text not null,
  data text not null, updated_at timestamptz not null default now(),
  primary key (cls, name, slot),
  constraint sm_photos_size check (length(data) < 450000),
  constraint sm_photos_img check (data like 'data:image/jpeg;base64,%'));
alter table public.sm_photos enable row level security;
revoke all on public.sm_photos from anon, authenticated;

create or replace function public.sm_check_staff(p_code text) returns boolean language sql security definer set search_path = '' as $$
  select exists(select 1 from sm_private.secrets s where
    (s.staff_hash is not null and s.staff_hash = extensions.crypt(coalesce(p_code,''), s.staff_hash))
    or s.pass_hash = extensions.crypt(coalesce(p_code,''), s.pass_hash)); $$;

create or replace function public.sm_photos_get(p_code text, p_cls text, p_name text)
returns table(slot text, data text) language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_staff(p_code) then return; end if;
  return query select p.slot, p.data from public.sm_photos p where p.cls = p_cls and (p.name = p_name or p.name = '__class'); end $$;

create or replace function public.sm_photos_counts(p_code text, p_cls text)
returns table(name text, n bigint) language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_staff(p_code) then return; end if;
  return query select p.name, count(*) from public.sm_photos p where p.cls = p_cls group by p.name; end $$;

create or replace function public.sm_photo_set(p_code text, p_cls text, p_name text, p_slot text, p_data text)
returns boolean language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_staff(p_code) then return false; end if;
  if length(coalesce(p_cls,'')) not between 1 and 80 or length(coalesce(p_name,'')) not between 1 and 120 or length(coalesce(p_slot,'')) not between 1 and 40 then return false; end if;
  if p_data is null then delete from public.sm_photos where cls = p_cls and name = p_name and slot = p_slot; return true; end if;
  insert into public.sm_photos(cls, name, slot, data, updated_at) values (p_cls, p_name, p_slot, p_data, now())
    on conflict (cls, name, slot) do update set data = excluded.data, updated_at = now();
  return true; end $$;

create or replace function public.sm_set_staff_code(p_admin text, p_new text) returns boolean language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_password(p_admin) then return false; end if; if length(coalesce(p_new,'')) < 4 then return false; end if;
  update sm_private.secrets set staff_hash = extensions.crypt(p_new, extensions.gen_salt('bf')) where id = 1; return true; end $$;

create or replace function public.sm_save_config(p_pass text, p_key text, p_value jsonb) returns boolean language plpgsql security definer set search_path = '' as $$
begin if not public.sm_check_password(p_pass) then return false; end if; if p_key not in ('texts','adapted') then return false; end if;
  insert into public.sm_config(key, value, updated_at) values (p_key, p_value, now()) on conflict (key) do update set value = excluded.value, updated_at = now(); return true; end $$;

revoke all on function public.sm_check_staff(text) from public;
revoke all on function public.sm_photos_get(text, text, text) from public;
revoke all on function public.sm_photos_counts(text, text) from public;
revoke all on function public.sm_photo_set(text, text, text, text, text) from public;
revoke all on function public.sm_set_staff_code(text, text) from public;
grant execute on function public.sm_check_staff(text) to anon, authenticated;
grant execute on function public.sm_photos_get(text, text, text) to anon, authenticated;
grant execute on function public.sm_photos_counts(text, text) to anon, authenticated;
grant execute on function public.sm_photo_set(text, text, text, text, text) to anon, authenticated;
grant execute on function public.sm_set_staff_code(text, text) to anon, authenticated;
