-- Sunampe ERM 2026 · Datos compartidos entre operadores
-- Ejecutar UNA vez en Supabase → SQL Editor. Es seguro volver a ejecutarlo.

-- 1) Electores por colegio
alter table public.locales add column if not exists electores integer;

-- 2) Personeros, asistencia, muestra del conteo rápido y cortes, compartidos
create table if not exists public.datos_compartidos (
  clave           text primary key,
  valor           jsonb,
  actualizado_por uuid references auth.users(id),
  actualizado_at  timestamptz not null default now()
);
alter table public.datos_compartidos enable row level security;

-- Función auxiliar: ¿el usuario actual es administrador activo?
create or replace function public.es_administrador()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.perfiles
    where id = auth.uid() and rol = 'administrador' and activo
  );
$$;

grant select on public.datos_compartidos to authenticated;
grant insert, update on public.datos_compartidos to authenticated;
grant update on public.mesas, public.locales to authenticated;

do $$
begin
  -- Todos los usuarios con sesión pueden ver los datos compartidos
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='datos_compartidos' and policyname='compartidos_leer') then
    create policy compartidos_leer on public.datos_compartidos for select to authenticated using (true);
  end if;
  -- Solo administradores pueden escribirlos
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='datos_compartidos' and policyname='compartidos_insertar') then
    create policy compartidos_insertar on public.datos_compartidos for insert to authenticated with check (public.es_administrador());
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='datos_compartidos' and policyname='compartidos_actualizar') then
    create policy compartidos_actualizar on public.datos_compartidos for update to authenticated using (public.es_administrador()) with check (public.es_administrador());
  end if;
  -- Administradores pueden editar colegios y mesas desde Configuración
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='mesas' and policyname='mesas_admin_editar') then
    create policy mesas_admin_editar on public.mesas for update to authenticated using (public.es_administrador()) with check (public.es_administrador());
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='locales' and policyname='locales_admin_editar') then
    create policy locales_admin_editar on public.locales for update to authenticated using (public.es_administrador()) with check (public.es_administrador());
  end if;
end $$;
