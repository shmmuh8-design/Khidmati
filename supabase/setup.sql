-- خدماتي: قاعدة بيانات مقدّمي الخدمة — انسخ الملف كامل والصقه في SQL Editor (نفس مشروع سُقيا) واضغط Run
-- يستخدم نفس رمز المدير حق سُقيا (جدول app_admin).
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.kh_providers (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  name        text not null check (char_length(name) between 2 and 70),
  cr          text not null check (cr ~ '^[0-9]{4,12}$'),
  phone       text not null unique check (phone ~ '^[0-9]{10,15}$'),
  cats        text[] not null check (cardinality(cats) between 1 and 10),
  areas       text[] not null check (cardinality(areas) between 1 and 80),
  fee         numeric(6,3) not null default 0 check (fee >= 0 and fee < 1000),
  hours       text check (char_length(hours) <= 60),
  note        text check (char_length(note) <= 160),
  available   boolean not null default true,
  status      text not null default 'approved' check (status in ('approved','blocked')),
  trial_until timestamptz not null default now() + interval '30 days',
  paid_until  timestamptz,
  code_hash   text not null
);
create table if not exists public.kh_ratings (
  provider_id uuid not null references public.kh_providers(id) on delete cascade,
  device      text not null check (char_length(device) between 8 and 64),
  stars       int  not null check (stars between 1 and 5),
  created_at  timestamptz not null default now(),
  primary key (provider_id, device)
);
create table if not exists public.kh_reports (
  id          bigserial primary key,
  provider_id uuid references public.kh_providers(id) on delete cascade,
  reason      text not null default '',
  created_at  timestamptz not null default now()
);
alter table public.kh_providers enable row level security;
alter table public.kh_ratings   enable row level security;
alter table public.kh_reports   enable row level security;
revoke all on public.kh_providers, public.kh_ratings, public.kh_reports from anon, authenticated;

-- helpers --------------------------------------------------------------
create or replace function public._kh_active_until(p public.kh_providers) returns timestamptz
language sql immutable as $$ select greatest(p.trial_until, coalesce(p.paid_until, p.trial_until)) $$;

create or replace function public._kh_provider(p_phone text, p_code text) returns public.kh_providers
language plpgsql security definer set search_path = public, extensions as $$
declare d kh_providers;
begin
  select * into d from kh_providers where phone = p_phone;
  if d.id is null or d.code_hash <> crypt(upper(coalesce(p_code,'')), d.code_hash) then
    perform pg_sleep(1);
    raise exception 'الرقم أو رمز الدخول غلط';
  end if;
  return d;
end $$;

create or replace function public._kh_check(p_cats text[], p_areas text[]) returns void
language plpgsql immutable as $$
begin
  if not (p_cats <@ array['ac','elec','plumb','carp','paint','clean','pest','sat','lock','reno']) then
    raise exception 'نوع الخدمة غير صحيح';
  end if;
  if cardinality(p_areas) < 1 then raise exception 'اختار ولاية وحدة على الأقل'; end if;
end $$;

-- public: list active providers (with rating) ---------------------------------
create or replace function public.kh_list()
returns table(id uuid, name text, phone text, cats text[], areas text[], fee numeric, hours text, note text, available boolean, rating numeric, votes int)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.phone, p.cats, p.areas, p.fee, p.hours, p.note, p.available,
         round(coalesce(avg(r.stars), 0), 1), count(r.stars)::int
  from kh_providers p left join kh_ratings r on r.provider_id = p.id
  where p.status = 'approved' and _kh_active_until(p) > now()
  group by p.id order by p.available desc, p.created_at
$$;

-- public: rate (one rating per device per provider, can be changed) / report ----
create or replace function public.kh_rate(p_id uuid, p_device text, p_stars int)
returns void language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from kh_ratings where device = p_device and created_at > now() - interval '1 day') > 20 then
    raise exception 'تقييمات كثير اليوم';
  end if;
  insert into kh_ratings(provider_id, device, stars) values (p_id, p_device, p_stars)
  on conflict (provider_id, device) do update set stars = excluded.stars, created_at = now();
end $$;

create or replace function public.kh_report(p_id uuid, p_reason text)
returns void language sql security definer set search_path = public as $$
  insert into kh_reports(provider_id, reason) values (p_id, left(coalesce(p_reason, ''), 500));
$$;

-- provider: register -> returns a login code (shown once) ---------------------
create or replace function public.kh_register(p_name text, p_cr text, p_phone text, p_cats text[], p_areas text[], p_fee numeric, p_hours text, p_note text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_code text;
begin
  if exists (select 1 from kh_providers where phone = p_phone) then
    raise exception 'هذا الرقم مسجّل من قبل — ادخل برمز الدخول حقك';
  end if;
  if (select count(*) from kh_providers where created_at > now() - interval '1 hour') > 30 then
    raise exception 'ضغط تسجيلات كثير، حاول بعد شوي';
  end if;
  perform _kh_check(p_cats, p_areas);
  v_code := upper(substr(encode(gen_random_bytes(6), 'hex'), 1, 8));
  insert into kh_providers(name, cr, phone, cats, areas, fee, hours, note, code_hash)
  values (trim(p_name), p_cr, p_phone, p_cats, p_areas, coalesce(p_fee, 0), nullif(trim(p_hours), ''), nullif(trim(p_note), ''), crypt(v_code, gen_salt('bf')));
  return json_build_object('code', v_code);
end $$;

-- provider: view / edit own record ------------------------------------------
create or replace function public.kh_me(p_phone text, p_code text)
returns json language plpgsql security definer set search_path = public as $$
declare d kh_providers := _kh_provider(p_phone, p_code);
begin
  return json_build_object('id', d.id, 'name', d.name, 'cr', d.cr, 'phone', d.phone, 'cats', d.cats, 'areas', d.areas,
    'fee', d.fee, 'hours', d.hours, 'note', d.note, 'available', d.available, 'status', d.status,
    'trial_until', d.trial_until, 'paid_until', d.paid_until, 'active_until', _kh_active_until(d),
    'rating', (select round(coalesce(avg(stars), 0), 1) from kh_ratings where provider_id = d.id),
    'votes', (select count(*) from kh_ratings where provider_id = d.id));
end $$;

create or replace function public.kh_update(p_phone text, p_code text, p_name text, p_cats text[], p_areas text[], p_fee numeric, p_hours text, p_note text, p_available boolean)
returns json language plpgsql security definer set search_path = public as $$
declare d kh_providers := _kh_provider(p_phone, p_code);
begin
  perform _kh_check(p_cats, p_areas);
  update kh_providers set name = trim(p_name), cats = p_cats, areas = p_areas, fee = coalesce(p_fee, 0),
    hours = nullif(trim(p_hours), ''), note = nullif(trim(p_note), ''), available = p_available, updated_at = now()
  where id = d.id;
  return kh_me(p_phone, p_code);
end $$;

create or replace function public.kh_set_available(p_phone text, p_code text, p_available boolean)
returns json language plpgsql security definer set search_path = public as $$
declare d kh_providers := _kh_provider(p_phone, p_code);
begin
  update kh_providers set available = p_available, updated_at = now() where id = d.id;
  return kh_me(p_phone, p_code);
end $$;

create or replace function public.kh_delete(p_phone text, p_code text)
returns json language plpgsql security definer set search_path = public as $$
declare d kh_providers := _kh_provider(p_phone, p_code);
begin
  delete from kh_providers where id = d.id;
  return json_build_object('ok', true);
end $$;

-- admin (نفس رمز مدير سُقيا) --------------------------------------------------
create or replace function public.kh_admin_list(p_pass text)
returns table(id uuid, created_at timestamptz, name text, cr text, phone text, cats text[], areas text[], fee numeric, available boolean, status text,
              trial_until timestamptz, paid_until timestamptz, active_until timestamptz, reports int, rating numeric, votes int)
language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  return query select p.id, p.created_at, p.name, p.cr, p.phone, p.cats, p.areas, p.fee, p.available, p.status,
      p.trial_until, p.paid_until, _kh_active_until(p),
      (select count(*)::int from kh_reports x where x.provider_id = p.id),
      (select round(coalesce(avg(r.stars), 0), 1) from kh_ratings r where r.provider_id = p.id),
      (select count(*)::int from kh_ratings r where r.provider_id = p.id)
    from kh_providers p order by _kh_active_until(p) asc;
end $$;

-- تجديد الاشتراك بعد ما يدفع: يضيف شهور من تاريخ الانتهاء (أو من اليوم لو منتهي)
create or replace function public.kh_admin_extend(p_pass text, p_id uuid, p_months int)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  if p_months not between -12 and 24 or p_months = 0 then raise exception 'عدد الشهور غير صحيح'; end if;
  update kh_providers p set paid_until = greatest(now(), _kh_active_until(p)) + make_interval(months => p_months), updated_at = now()
  where p.id = p_id;
end $$;

create or replace function public.kh_admin_set_status(p_pass text, p_id uuid, p_status text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  if p_status not in ('approved','blocked') then raise exception 'حالة غير صحيحة'; end if;
  update kh_providers set status = p_status, updated_at = now() where id = p_id;
end $$;

create or replace function public.kh_admin_delete(p_pass text, p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  delete from kh_providers where id = p_id;
end $$;

create or replace function public.kh_admin_reports(p_pass text)
returns table(id bigint, created_at timestamptz, provider text, phone text, reason text)
language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  return query select r.id, r.created_at, p.name, p.phone, r.reason
    from kh_reports r left join kh_providers p on p.id = r.provider_id order by r.created_at desc limit 200;
end $$;

-- who may call what ---------------------------------------------------------
revoke all on function public._kh_provider(text, text), public._kh_check(text[], text[]), public._kh_active_until(public.kh_providers) from public, anon, authenticated;
grant execute on function
  public.kh_list(), public.kh_rate(uuid, text, int), public.kh_report(uuid, text),
  public.kh_register(text, text, text, text[], text[], numeric, text, text),
  public.kh_me(text, text),
  public.kh_update(text, text, text, text[], text[], numeric, text, text, boolean),
  public.kh_set_available(text, text, boolean), public.kh_delete(text, text),
  public.kh_admin_list(text), public.kh_admin_extend(text, uuid, int), public.kh_admin_set_status(text, uuid, text),
  public.kh_admin_delete(text, uuid), public.kh_admin_reports(text)
to anon, authenticated;
