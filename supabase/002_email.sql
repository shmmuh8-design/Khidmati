-- خدماتي: إيميل المؤسسة (اختياري) — الصقه في SQL Editor واضغط Run
alter table public.kh_providers add column if not exists email text
  check (email is null or (char_length(email) <= 120 and email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'));

drop function if exists public.kh_list();
create function public.kh_list()
returns table(id uuid, name text, phone text, email text, cats text[], areas text[], fee numeric, hours text, note text, available boolean, rating numeric, votes int)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.phone, p.email, p.cats, p.areas, p.fee, p.hours, p.note, p.available,
         round(coalesce(avg(r.stars), 0), 1), count(r.stars)::int
  from kh_providers p left join kh_ratings r on r.provider_id = p.id
  where p.status = 'approved' and _kh_active_until(p) > now()
  group by p.id order by p.available desc, p.created_at
$$;

drop function if exists public.kh_register(text, text, text, text[], text[], numeric, text, text);
create function public.kh_register(p_name text, p_cr text, p_phone text, p_cats text[], p_areas text[], p_fee numeric, p_hours text, p_note text, p_email text default null)
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
  insert into kh_providers(name, cr, phone, email, cats, areas, fee, hours, note, code_hash)
  values (trim(p_name), p_cr, p_phone, nullif(lower(trim(p_email)), ''), p_cats, p_areas, coalesce(p_fee, 0), nullif(trim(p_hours), ''), nullif(trim(p_note), ''), crypt(v_code, gen_salt('bf')));
  return json_build_object('code', v_code);
end $$;

create or replace function public.kh_me(p_phone text, p_code text)
returns json language plpgsql security definer set search_path = public as $$
declare d kh_providers := _kh_provider(p_phone, p_code);
begin
  return json_build_object('id', d.id, 'name', d.name, 'cr', d.cr, 'phone', d.phone, 'email', d.email, 'cats', d.cats, 'areas', d.areas,
    'fee', d.fee, 'hours', d.hours, 'note', d.note, 'available', d.available, 'status', d.status,
    'trial_until', d.trial_until, 'paid_until', d.paid_until, 'active_until', _kh_active_until(d),
    'rating', (select round(coalesce(avg(stars), 0), 1) from kh_ratings where provider_id = d.id),
    'votes', (select count(*) from kh_ratings where provider_id = d.id));
end $$;

drop function if exists public.kh_update(text, text, text, text[], text[], numeric, text, text, boolean);
create function public.kh_update(p_phone text, p_code text, p_name text, p_cats text[], p_areas text[], p_fee numeric, p_hours text, p_note text, p_available boolean, p_email text default null)
returns json language plpgsql security definer set search_path = public as $$
declare d kh_providers := _kh_provider(p_phone, p_code);
begin
  perform _kh_check(p_cats, p_areas);
  update kh_providers set name = trim(p_name), cats = p_cats, areas = p_areas, fee = coalesce(p_fee, 0), email = nullif(lower(trim(p_email)), ''),
    hours = nullif(trim(p_hours), ''), note = nullif(trim(p_note), ''), available = p_available, updated_at = now()
  where id = d.id;
  return kh_me(p_phone, p_code);
end $$;

drop function if exists public.kh_admin_list(text);
create function public.kh_admin_list(p_pass text)
returns table(id uuid, created_at timestamptz, name text, cr text, phone text, email text, cats text[], areas text[], fee numeric, available boolean, status text,
              trial_until timestamptz, paid_until timestamptz, active_until timestamptz, reports int, rating numeric, votes int)
language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  return query select p.id, p.created_at, p.name, p.cr, p.phone, p.email, p.cats, p.areas, p.fee, p.available, p.status,
      p.trial_until, p.paid_until, _kh_active_until(p),
      (select count(*)::int from kh_reports x where x.provider_id = p.id),
      (select round(coalesce(avg(r.stars), 0), 1) from kh_ratings r where r.provider_id = p.id),
      (select count(*)::int from kh_ratings r where r.provider_id = p.id)
    from kh_providers p order by _kh_active_until(p) asc;
end $$;

revoke all on function public.kh_list(), public.kh_register(text, text, text, text[], text[], numeric, text, text, text),
  public.kh_update(text, text, text, text[], text[], numeric, text, text, boolean, text), public.kh_admin_list(text) from public;
grant execute on function public.kh_list(), public.kh_register(text, text, text, text[], text[], numeric, text, text, text),
  public.kh_update(text, text, text, text[], text[], numeric, text, text, boolean, text), public.kh_admin_list(text) to anon, authenticated;
