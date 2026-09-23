-- Sunampe ERM 2026 · Informes privados (solo lectura)
-- Crea la tabla donde se guarda el informe de auditoría y la lista de lectores autorizados.
-- Nadie puede crear, modificar ni borrar informes desde la app: solo desde el SQL Editor.
-- Ejecutar UNA vez en Supabase → SQL Editor. Es seguro volver a ejecutarlo.

create or replace function public.es_administrador()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfiles where id = auth.uid() and rol = 'administrador' and activo);
$$;

create table if not exists public.informes (
  clave          text primary key,
  titulo         text not null,
  contenido      text not null,
  actualizado_at timestamptz not null default now()
);
create table if not exists public.informe_lectores (
  usuario uuid primary key references auth.users(id) on delete cascade,
  agregado_at timestamptz not null default now()
);
alter table public.informes enable row level security;
alter table public.informe_lectores enable row level security;

-- La app solo puede LEER; no se otorgan permisos de escritura
revoke insert, update, delete on public.informes, public.informe_lectores from anon, authenticated;
grant select on public.informes to authenticated;

-- ¿El usuario actual puede leer informes? (administrador activo o lector autorizado)
create or replace function public.puede_leer_informes()
returns boolean language sql stable security definer set search_path = public as $$
  select public.es_administrador() or exists (select 1 from public.informe_lectores where usuario = auth.uid());
$$;

drop policy if exists informes_leer_autorizados on public.informes;
create policy informes_leer_autorizados on public.informes for select to authenticated
  using (public.puede_leer_informes());

-- Gestión de lectores desde la app (solo administradores activos)
create or replace function public.listar_lectores()
returns table(email text, agregado_at timestamptz) language plpgsql stable security definer set search_path = public as $$
begin
  if not public.es_administrador() then raise exception 'Solo un administrador puede ver la lista de lectores'; end if;
  return query select u.email::text, l.agregado_at from public.informe_lectores l join auth.users u on u.id = l.usuario order by u.email;
end $$;

create or replace function public.agregar_lector(correo text)
returns text language plpgsql security definer set search_path = public as $$
declare uid uuid;
begin
  if not public.es_administrador() then raise exception 'Solo un administrador puede agregar lectores'; end if;
  select id into uid from auth.users where lower(email) = lower(trim(correo));
  if uid is null then raise exception 'No hay ningún usuario de la app con ese DNI o correo (%)', trim(correo); end if;
  insert into public.informe_lectores (usuario) values (uid) on conflict do nothing;
  return trim(correo);
end $$;

create or replace function public.quitar_lector(correo text)
returns text language plpgsql security definer set search_path = public as $$
begin
  if not public.es_administrador() then raise exception 'Solo un administrador puede quitar lectores'; end if;
  delete from public.informe_lectores where usuario in (select id from auth.users where lower(email) = lower(trim(correo)));
  return trim(correo);
end $$;

revoke execute on function public.listar_lectores(), public.agregar_lector(text), public.quitar_lector(text) from public, anon;
grant execute on function public.listar_lectores(), public.agregar_lector(text), public.quitar_lector(text) to authenticated;
