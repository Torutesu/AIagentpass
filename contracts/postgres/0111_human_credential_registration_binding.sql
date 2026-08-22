BEGIN;

-- The 0092 registration function returns a composite row whose `id` field
-- shares a name with the RETURNS TABLE output column. Pin PL/pgSQL's conflict
-- policy for this reviewed authority function so PostgreSQL 16/17 resolve the
-- composite-field reference deterministically instead of rejecting it as
-- ambiguous at runtime.
ALTER FUNCTION public.agentpass_human_register_credential(
  uuid, uuid, uuid, bytea, bytea, bigint, text[], text, boolean, boolean
) SET plpgsql.variable_conflict = 'use_column';

COMMIT;
