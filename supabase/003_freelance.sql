-- خدماتي: الفني المستقل العماني — الصقه في SQL Editor (Database مو Logs) واضغط Run. تقدر تشغّله أكثر من مرة بدون مشاكل.
-- الفني المستقل: بدون سجل تجاري، يطلع للزبائن بعد موافقة المدير، وشهره المجاني يبدأ من يوم الموافقة.

alter table public.kh_providers add column if not exists kind text not null default 'company';
alter table public.kh_providers drop constraint if exists kh_providers_kind_check;
alter table public.kh_providers add constraint kh_providers_kind_check check (kind in ('company','freelance'));

alter table public.kh_providers alter column cr drop not null;
alter table public.kh_providers drop constraint if exists kh_providers_cr_needed;
alter table public.kh_providers add constraint kh_providers_cr_needed check (kind = 'freelance' or cr is not null);

alter table public.kh_providers drop constraint if exists kh_providers_status_check;
alter table public.kh_providers add constraint kh_providers_status_check check (status in ('approved','blocked','pending'));

drop function if exists public.kh_list();
create function public.kh_list()
returns table(id uuid, name text, phone text, email text, cats text[], areas text[], fee numeric, hours text, note text, available boolean, rating numeric, votes int, kind text)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.phone, p.email, p.cats, p.areas, p.fee, p.hours, p.note, p.available,
         round(coalesce(avg(r.stars), 0), 1), count(r.stars)::int, p.kind
  from kh_providers p left join kh_ratings r on r.provider_id = p.id
  where p.status = 'approved' and _kh_active_until(p) > now()
  group by p.id order by p.available desc, p.created_at
$$;

drop function if exists public.kh_register(text, text, text, text[], text[], numeric, text, text);
drop function if exists public.kh_register(text, text, text, text[], text[], numeric, text, text, text);
drop function if exists public.kh_register(text, text, text, text[], text[], numeric, text, text, text, text);
create function public.kh_register(p_name text, p_cr text, p_phone text, p_cats text[], p_areas text[], p_fee numeric, p_hours text, p_note text, p_email text default null, p_kind text default 'company')
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_code text; v_kind text := coalesce(p_kind, 'company');
begin
  if v_kind not in ('company','freelance') then raise exception 'نوع الحساب غير صحيح'; end if;
  if v_kind = 'company' and coalesce(p_cr, '') !~ '^[0-9]{4,12}$' then raise exception 'رقم السجل التجاري مو صحيح'; end if;
  if exists (select 1 from kh_providers where phone = p_phone) then
    raise exception 'هذا الرقم مسجّل من قبل — ادخل برمز الدخول حقك';
  end if;
  if (select count(*) from kh_providers where created_at > now() - interval '1 hour') > 30 then
    raise exception 'ضغط تسجيلات كثير، حاول بعد شوي';
  end if;
  perform _kh_check(p_cats, p_areas);
  v_code := upper(substr(encode(gen_random_bytes(6), 'hex'), 1, 8));
  insert into kh_providers(kind, name, cr, phone, email, cats, areas, fee, hours, note, status, code_hash)
  values (v_kind, trim(p_name), case when v_kind = 'company' then p_cr end, p_phone, nullif(lower(trim(p_email)), ''), p_cats, p_areas,
          coalesce(p_fee, 0), nullif(trim(p_hours), ''), nullif(trim(p_note), ''),
          case when v_kind = 'freelance' then 'pending' else 'approved' end, crypt(v_code, gen_salt('bf')));
  return json_build_object('code', v_code);
end $$;

create or replace function public.kh_me(p_phone text, p_code text)
returns json language plpgsql security definer set search_path = public as $$
declare d kh_providers := _kh_provider(p_phone, p_code);
begin
  return json_build_object('id', d.id, 'kind', d.kind, 'name', d.name, 'cr', d.cr, 'phone', d.phone, 'email', d.email, 'cats', d.cats, 'areas', d.areas,
    'fee', d.fee, 'hours', d.hours, 'note', d.note, 'available', d.available, 'status', d.status,
    'trial_until', d.trial_until, 'paid_until', d.paid_until, 'active_until', _kh_active_until(d),
    'rating', (select round(coalesce(avg(stars), 0), 1) from kh_ratings where provider_id = d.id),
    'votes', (select count(*) from kh_ratings where provider_id = d.id));
end $$;

drop function if exists public.kh_admin_list(text);
create function public.kh_admin_list(p_pass text)
returns table(id uuid, created_at timestamptz, name text, cr text, phone text, email text, cats text[], areas text[], fee numeric, available boolean, status text,
              trial_until timestamptz, paid_until timestamptz, active_until timestamptz, reports int, rating numeric, votes int, kind text)
language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  return query select p.id, p.created_at, p.name, p.cr, p.phone, p.email, p.cats, p.areas, p.fee, p.available, p.status,
      p.trial_until, p.paid_until, _kh_active_until(p),
      (select count(*)::int from kh_reports x where x.provider_id = p.id),
      (select round(coalesce(avg(r.stars), 0), 1) from kh_ratings r where r.provider_id = p.id),
      (select count(*)::int from kh_ratings r where r.provider_id = p.id),
      p.kind
    from kh_providers p order by (p.status = 'pending') desc, _kh_active_until(p) asc;
end $$;

create or replace function public.kh_admin_set_status(p_pass text, p_id uuid, p_status text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _check_admin(p_pass);
  if p_status not in ('approved','blocked') then raise exception 'حالة غير صحيحة'; end if;
  -- أول موافقة على فني مستقل: شهره المجاني يبدأ من اليوم
  update kh_providers set trial_until = now() + interval '30 days' where id = p_id and status = 'pending' and p_status = 'approved';
  update kh_providers set status = p_status, updated_at = now() where id = p_id;
end $$;

revoke all on function public.kh_list(), public.kh_register(text, text, text, text[], text[], numeric, text, text, text, text),
  public.kh_admin_list(text) from public;
grant execute on function public.kh_list(), public.kh_register(text, text, text, text[], text[], numeric, text, text, text, text),
  public.kh_me(text, text), public.kh_admin_list(text), public.kh_admin_set_status(text, uuid, text) to anon, authenticated;
