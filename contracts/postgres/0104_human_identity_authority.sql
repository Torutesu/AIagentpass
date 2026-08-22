BEGIN;

CREATE FUNCTION public.agentpass_human_identity_resolve(
  p_provider text,
  p_subject text,
  p_organization_id uuid
)
RETURNS TABLE (
  provider text,
  subject text,
  member_id uuid,
  membership_id uuid,
  organization_id uuid,
  role text
)
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_provider IS NULL OR p_provider !~ '^[a-z][a-z0-9._-]{0,63}$'
     OR p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 512
     OR p_subject ~ '[[:cntrl:]]' OR p_organization_id IS NULL THEN
    RAISE EXCEPTION 'invalid human identity resolution input' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT ui.provider, ui.subject, ui.member_id, m.id, m.organization_id, m.role
  FROM public.upstream_identities AS ui
  JOIN public.memberships AS m
    ON m.member_id = ui.member_id
   AND m.organization_id = p_organization_id
   AND m.status = 'active'
  JOIN public.organizations AS o ON o.id = m.organization_id
  WHERE ui.provider = p_provider
    AND ui.subject = p_subject
  LIMIT 2;
END;
$$;

CREATE FUNCTION public.agentpass_human_identity_bind(
  p_provider text,
  p_subject text,
  p_member_id uuid,
  p_organization_id uuid
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  existing_member_id uuid;
  inserted_member_id uuid;
BEGIN
  IF p_provider IS NULL OR p_provider !~ '^[a-z][a-z0-9._-]{0,63}$'
     OR p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 512
     OR p_subject ~ '[[:cntrl:]]' OR p_member_id IS NULL OR p_organization_id IS NULL THEN
    RAISE EXCEPTION 'invalid human identity binding input' USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_organization_id::text, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:human:identity:' || p_member_id::text, 0));

  PERFORM 1
  FROM public.memberships AS m
  JOIN public.organizations AS o ON o.id = m.organization_id
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_member_id
    AND m.status = 'active'
  FOR UPDATE OF m, o;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active membership is unavailable' USING ERRCODE = '23503';
  END IF;

  SELECT ui.member_id INTO existing_member_id
  FROM public.upstream_identities AS ui
  WHERE ui.provider = p_provider AND ui.subject = p_subject
  FOR UPDATE;
  IF FOUND THEN
    IF existing_member_id IS DISTINCT FROM p_member_id THEN
      RAISE EXCEPTION 'upstream identity is already bound' USING ERRCODE = '42501';
    END IF;
    RETURN 'already_exists';
  END IF;

  INSERT INTO public.upstream_identities (provider, subject, member_id)
  VALUES (p_provider, p_subject, p_member_id)
  ON CONFLICT (provider, subject) DO NOTHING
  RETURNING member_id INTO inserted_member_id;
  IF inserted_member_id IS NOT NULL THEN RETURN 'created'; END IF;

  SELECT ui.member_id INTO existing_member_id
  FROM public.upstream_identities AS ui
  WHERE ui.provider = p_provider AND ui.subject = p_subject;
  IF existing_member_id IS DISTINCT FROM p_member_id THEN
    RAISE EXCEPTION 'upstream identity is already bound' USING ERRCODE = '42501';
  END IF;
  RETURN 'already_exists';
END;
$$;

ALTER FUNCTION public.agentpass_human_identity_resolve(text,text,uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_identity_bind(text,text,uuid,uuid) OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_identity_resolve(text,text,uuid) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_identity_bind(text,text,uuid,uuid) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_identity_resolve(text,text,uuid) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_identity_bind(text,text,uuid,uuid) TO agentpass_app;

COMMIT;
