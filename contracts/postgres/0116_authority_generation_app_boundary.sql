BEGIN;

-- Authority reductions advance the organization generation from the online
-- application role. Keep the mutation function-only: the application role
-- may not lock or update the generation/catalog tables directly, while the
-- migrator-owned SECURITY DEFINER function performs the exact tenant-scoped
-- transition and refreshes the row-level lock boundary.
CREATE OR REPLACE FUNCTION public.agentpass_advance_authority_generation(
  request_organization_id uuid,
  request_issued_at timestamptz DEFAULT clock_timestamp()
)
RETURNS TABLE (organization_id uuid, generation bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  current_generation bigint;
  next_generation bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:authority-generation:' || request_organization_id::text, 0));

  PERFORM 1 FROM public.organizations WHERE id = request_organization_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'organization was not found';
  END IF;

  SELECT authority.generation INTO current_generation
  FROM public.control_plane_authority_generations AS authority
  WHERE authority.organization_id = request_organization_id
  ORDER BY authority.generation DESC
  LIMIT 1
  FOR UPDATE;

  next_generation := COALESCE(current_generation, 0) + 1;
  UPDATE public.control_plane_authority_generations AS authority
  SET superseded_at = COALESCE(authority.superseded_at, request_issued_at)
  WHERE authority.organization_id = request_organization_id
    AND authority.superseded_at IS NULL;

  INSERT INTO public.control_plane_authority_generations (organization_id, generation, issued_at)
  VALUES (request_organization_id, next_generation, request_issued_at);

  RETURN QUERY SELECT request_organization_id, next_generation;
END;
$$;

ALTER FUNCTION public.agentpass_advance_authority_generation(uuid,timestamptz)
  OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_advance_authority_generation(uuid,timestamptz)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_advance_authority_generation(uuid,timestamptz)
  TO agentpass_app;

COMMIT;
