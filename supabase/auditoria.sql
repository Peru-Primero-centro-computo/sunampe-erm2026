-- Sunampe ERM 2026 · Historial de auditoría de actas y votos (en el servidor)
-- Guarda automáticamente QUIÉN cambió QUÉ y CUÁNDO en las tablas actas y acta_votos,
-- con la versión anterior y la nueva. Nadie puede modificar ni borrar este historial
-- desde la app. Ejecutar UNA vez en Supabase → SQL Editor. Es seguro volver a ejecutarlo.

create table if not exists public.auditoria (
  id        bigserial primary key,
  tabla     text        not null,
  accion    text        not null,            -- INSERT, UPDATE o DELETE
  fila_id   text,
  antes     jsonb,
  despues   jsonb,
  usuario   uuid        default auth.uid(),
  fecha     timestamptz not null default now()
);
create index if not exists auditoria_fecha_idx on public.auditoria (fecha desc);
alter table public.auditoria enable row level security;

create or replace function public.registrar_auditoria()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.auditoria (tabla, accion, fila_id, antes, despues)
  values (
    tg_table_name,
    tg_op,
    coalesce(case when tg_op = 'DELETE' then to_jsonb(old)->>'id' else to_jsonb(new)->>'id' end, ''),
    case when tg_op in ('UPDATE','DELETE') then to_jsonb(old) end,
    case when tg_op in ('INSERT','UPDATE') then to_jsonb(new) end
  );
  return coalesce(new, old);
end $$;

drop trigger if exists auditoria_actas on public.actas;
create trigger auditoria_actas after insert or update or delete on public.actas
  for each row execute function public.registrar_auditoria();

drop trigger if exists auditoria_acta_votos on public.acta_votos;
create trigger auditoria_acta_votos after insert or update or delete on public.acta_votos
  for each row execute function public.registrar_auditoria();

-- Solo administradores pueden leer el historial; nadie puede escribirlo ni borrarlo desde la app
grant select on public.auditoria to authenticated;
do $$ begin
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='auditoria' and policyname='auditoria_leer_admin') then
    create policy auditoria_leer_admin on public.auditoria for select to authenticated using (public.es_administrador());
  end if;
end $$;

-- ───────────────────────────────────────────────────────────────
-- CONSULTAS ÚTILES (ejecutar aparte cuando se necesiten)
-- Últimos 50 cambios:
--   select a.fecha, p.nombre as usuario, a.tabla, a.accion, a.antes->>'estado' as antes, a.despues->>'estado' as despues
--   from auditoria a left join perfiles p on p.id = a.usuario order by a.fecha desc limit 50;
-- Revisar permisos (RLS) de las tablas principales:
--   select tablename, policyname, cmd, roles, qual, with_check from pg_policies
--   where schemaname='public' and tablename in ('actas','acta_votos','mesas','locales','datos_compartidos','auditoria')
--   order by tablename, cmd;
