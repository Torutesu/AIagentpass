BEGIN;

-- 0104 introduced the identity bind entry point before the operator
-- connection was split from the online application connection.  Keep the
-- signature stable for already prepared clients, but make the original
-- authenticated session role part of the authority decision.  SECURITY
-- DEFINER changes current_user to the migrator owner; session_user is the
-- database-authenticated caller and cannot be supplied as an argument.
CREATE OR REPLACE FUNCTION public.agentpass_human_identity_resolve(
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
     OR octet_length(p_subject) > 512
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

CREATE OR REPLACE FUNCTION public.agentpass_human_identity_bind(
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
  IF session_user <> 'agentpass_maintenance' THEN
    RAISE EXCEPTION 'human identity binding requires the operator connection'
      USING ERRCODE = '42501';
  END IF;

  IF p_provider IS NULL OR p_provider !~ '^[a-z][a-z0-9._-]{0,63}$'
     OR p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 512
     OR octet_length(p_subject) > 512
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

-- Read projections keep the online role away from the identity, membership,
-- and organization base tables.  They return only the fields consumed by
-- the identity adapters and are intentionally SECURITY DEFINER.
CREATE FUNCTION public.agentpass_human_identity_find(
  p_provider text,
  p_subject text
)
RETURNS TABLE (
  provider text,
  subject text,
  member_id uuid,
  created_at timestamptz
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
     OR octet_length(p_subject) > 512
     OR p_subject ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid human identity lookup input' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT ui.provider, ui.subject, ui.member_id, ui.created_at
  FROM public.upstream_identities AS ui
  WHERE ui.provider = p_provider AND ui.subject = p_subject
  LIMIT 2;
END;
$$;

CREATE FUNCTION public.agentpass_human_identity_list_memberships(
  p_provider text,
  p_subject text,
  p_organization_id uuid
)
RETURNS TABLE (
  provider text,
  subject text,
  member_id uuid,
  identity_created_at timestamptz,
  organization_id uuid,
  membership_id uuid,
  role text,
  status text,
  version bigint,
  created_at timestamptz,
  updated_at timestamptz,
  organization_name text
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
     OR octet_length(p_subject) > 512
     OR p_subject ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid human identity membership lookup input' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT ui.provider, ui.subject, ui.member_id, ui.created_at,
         m.organization_id, m.id, m.role, m.status, m.version,
         m.created_at, m.updated_at, o.name
  FROM public.upstream_identities AS ui
  JOIN public.memberships AS m ON m.member_id = ui.member_id
  JOIN public.organizations AS o ON o.id = m.organization_id
  WHERE ui.provider = p_provider
    AND ui.subject = p_subject
    AND m.status = 'active'
    AND (p_organization_id IS NULL OR m.organization_id = p_organization_id)
  ORDER BY m.organization_id ASC, m.id ASC
  LIMIT 128;
END;
$$;

ALTER FUNCTION public.agentpass_human_identity_bind(text,text,uuid,uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_identity_resolve(text,text,uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_identity_find(text,text) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_identity_list_memberships(text,text,uuid) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_identity_bind(text,text,uuid,uuid)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_identity_find(text,text)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_identity_list_memberships(text,text,uuid)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_human_identity_bind(text,text,uuid,uuid) TO agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_identity_find(text,text) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_identity_list_memberships(text,text,uuid) TO agentpass_app;

-- The online application must not mutate immutable upstream mappings.  Keep a
-- read-only backup projection while denying every direct application table
-- privilege, including privileges left by an older role bootstrap.
REVOKE ALL PRIVILEGES ON TABLE public.upstream_identities FROM agentpass_app;
GRANT SELECT ON TABLE public.upstream_identities TO agentpass_backup;

-- These relations participate in the identity binding proof.  Keep online
-- reads for existing management projections, but remove every direct write
-- privilege so membership/organization changes cannot bypass invalidation.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.organizations, public.memberships FROM agentpass_app;
GRANT SELECT ON TABLE public.organizations, public.memberships TO agentpass_app;

COMMIT;
