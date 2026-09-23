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

-- Para autorizar a un lector (ejecutar aparte, con su correo):
--   insert into public.informe_lectores (usuario) select id from auth.users where email = 'correo@ejemplo.com' on conflict do nothing;
-- Para quitarle el acceso:
--   delete from public.informe_lectores where usuario = (select id from auth.users where email = 'correo@ejemplo.com');
-- Para ver quiénes tienen acceso:
--   select u.email, l.agregado_at from public.informe_lectores l join auth.users u on u.id = l.usuario;
