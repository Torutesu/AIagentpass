BEGIN;

-- Invitation authority boundary.
--
-- organization_invitations is function-only for the application, including
-- listing. All invitation reads/writes are routed through these
-- SECURITY DEFINER entry points.  The repository continues to own the outer
-- transaction's idempotency, audit-chain, and outbox choreography.  The
-- accept entry point additionally owns membership creation and invitation
-- consumption together, so those two writes cannot be observed or committed
-- independently.

CREATE FUNCTION public.agentpass_organization_invitation_create(
  p_organization_id uuid,
  p_invitation_id uuid,
  p_token_hash bytea,
  p_role text,
  p_actor_member_id uuid,
  p_created_at timestamptz,
  p_expires_at timestamptz
)
RETURNS TABLE (
  organization_id uuid,
  invitation_id uuid,
  role text,
  created_at timestamptz,
  expires_at timestamptz,
  accepted_member_id uuid,
  consumed_at timestamptz,
  revoked_at timestamptz,
  version bigint,
  created_by uuid
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor_row public.memberships%ROWTYPE;
  invitation_row public.organization_invitations%ROWTYPE;
  created_timestamp timestamptz;
BEGIN
  IF p_organization_id IS NULL
     OR p_invitation_id IS NULL
     OR p_token_hash IS NULL
     OR octet_length(p_token_hash) <> 32
     OR p_role IS NULL
     OR p_role NOT IN ('admin', 'auditor', 'viewer')
     OR p_actor_member_id IS NULL
     OR p_created_at IS NOT NULL AND NOT pg_catalog.isfinite(p_created_at)
     OR p_expires_at IS NULL
     OR NOT pg_catalog.isfinite(p_expires_at) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'invitation creation authority input is invalid';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  created_timestamp := COALESCE(p_created_at, pg_catalog.clock_timestamp());
  IF p_expires_at <= created_timestamp THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'invitation expiration must be after creation';
  END IF;

  SELECT m.*
    INTO actor_row
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_actor_member_id
    AND m.status = 'active'
  FOR UPDATE;

  IF NOT FOUND OR actor_row.role NOT IN ('owner', 'admin') THEN
    RETURN;
  END IF;

  INSERT INTO public.organization_invitations (
    organization_id, id, token_hash, role, created_by, created_at, expires_at
  ) VALUES (
    p_organization_id, p_invitation_id, p_token_hash, p_role,
    p_actor_member_id, created_timestamp, p_expires_at
  )
  RETURNING * INTO invitation_row;

  RETURN QUERY SELECT
    invitation_row.organization_id,
    invitation_row.id,
    invitation_row.role,
    invitation_row.created_at,
    invitation_row.expires_at,
    invitation_row.consumed_by,
    invitation_row.consumed_at,
    invitation_row.revoked_at,
    invitation_row.version,
    invitation_row.created_by;
END;
$$;

CREATE FUNCTION public.agentpass_organization_invitation_revoke(
  p_organization_id uuid,
  p_invitation_id uuid,
  p_expected_version bigint,
  p_revoked_at timestamptz,
  p_actor_member_id uuid,
  p_revoke_reason text
)
RETURNS TABLE (
  organization_id uuid,
  invitation_id uuid,
  role text,
  created_at timestamptz,
  expires_at timestamptz,
  accepted_member_id uuid,
  consumed_at timestamptz,
  revoked_at timestamptz,
  version bigint,
  created_by uuid
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor_row public.memberships%ROWTYPE;
  invitation_row public.organization_invitations%ROWTYPE;
BEGIN
  IF p_organization_id IS NULL
     OR p_invitation_id IS NULL
     OR p_expected_version IS NULL
     OR p_expected_version < 1
     OR p_revoked_at IS NULL
     OR NOT pg_catalog.isfinite(p_revoked_at)
     OR p_actor_member_id IS NULL
     OR p_revoke_reason IS NULL
     OR char_length(p_revoke_reason) NOT BETWEEN 1 AND 256
     OR p_revoke_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'invitation revoke authority input is invalid';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );

  SELECT m.*
    INTO actor_row
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_actor_member_id
    AND m.status = 'active'
  FOR UPDATE;
  IF NOT FOUND OR actor_row.role NOT IN ('owner', 'admin') THEN
    RETURN;
  END IF;

  UPDATE public.organization_invitations AS i
     SET revoked_by = p_actor_member_id,
         revoked_at = p_revoked_at,
         revoke_reason = p_revoke_reason,
         version = i.version + 1,
         updated_at = pg_catalog.clock_timestamp()
   WHERE i.organization_id = p_organization_id
     AND i.id = p_invitation_id
     AND i.version = p_expected_version
     AND i.revoked_at IS NULL
     AND i.consumed_at IS NULL
  RETURNING i.* INTO invitation_row;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  RETURN QUERY SELECT
    invitation_row.organization_id,
    invitation_row.id,
    invitation_row.role,
    invitation_row.created_at,
    invitation_row.expires_at,
    invitation_row.consumed_by,
    invitation_row.consumed_at,
    invitation_row.revoked_at,
    invitation_row.version,
    invitation_row.created_by;
END;
$$;

CREATE FUNCTION public.agentpass_organization_invitation_reissue(
  p_organization_id uuid,
  p_invitation_id uuid,
  p_token_hash bytea,
  p_expires_at timestamptz,
  p_reissued_at timestamptz,
  p_expected_version bigint,
  p_actor_member_id uuid
)
RETURNS TABLE (
  organization_id uuid,
  invitation_id uuid,
  role text,
  created_at timestamptz,
  expires_at timestamptz,
  accepted_member_id uuid,
  consumed_at timestamptz,
  revoked_at timestamptz,
  version bigint,
  created_by uuid
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor_row public.memberships%ROWTYPE;
  current_row public.organization_invitations%ROWTYPE;
  invitation_row public.organization_invitations%ROWTYPE;
BEGIN
  IF p_organization_id IS NULL
     OR p_invitation_id IS NULL
     OR p_token_hash IS NULL
     OR octet_length(p_token_hash) <> 32
     OR p_expires_at IS NULL
     OR NOT pg_catalog.isfinite(p_expires_at)
     OR p_reissued_at IS NULL
     OR NOT pg_catalog.isfinite(p_reissued_at)
     OR p_expires_at <= p_reissued_at
     OR p_expected_version IS NULL
     OR p_expected_version < 1
     OR p_actor_member_id IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'invitation reissue authority input is invalid';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );

  SELECT m.*
    INTO actor_row
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_actor_member_id
    AND m.status = 'active'
  FOR UPDATE;
  IF NOT FOUND OR actor_row.role NOT IN ('owner', 'admin') THEN
    RETURN;
  END IF;

  SELECT i.*
    INTO current_row
  FROM public.organization_invitations AS i
  WHERE i.organization_id = p_organization_id
    AND i.id = p_invitation_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF current_row.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'organization_invitations_version',
      MESSAGE = 'invitation version is stale';
  END IF;
  IF current_row.consumed_at IS NOT NULL OR current_row.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'integrity_constraint_violation',
      CONSTRAINT = 'organization_invitations_terminal',
      MESSAGE = 'accepted or revoked invitation cannot be reissued';
  END IF;

  UPDATE public.organization_invitations AS i
     SET token_hash = p_token_hash,
         expires_at = p_expires_at,
         version = i.version + 1,
         updated_at = pg_catalog.clock_timestamp()
   WHERE i.organization_id = p_organization_id
     AND i.id = p_invitation_id
     AND i.version = p_expected_version
     AND i.revoked_at IS NULL
     AND i.consumed_at IS NULL
  RETURNING i.* INTO invitation_row;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'organization_invitations_mutation_cas',
      MESSAGE = 'invitation reissue lost its authority binding';
  END IF;

  RETURN QUERY SELECT
    invitation_row.organization_id,
    invitation_row.id,
    invitation_row.role,
    invitation_row.created_at,
    invitation_row.expires_at,
    invitation_row.consumed_by,
    invitation_row.consumed_at,
    invitation_row.revoked_at,
    invitation_row.version,
    invitation_row.created_by;
END;
$$;

CREATE FUNCTION public.agentpass_organization_invitation_accept(
  p_organization_id uuid,
  p_actor_member_id uuid,
  p_token_hash bytea,
  p_membership_id uuid,
  p_accepted_at timestamptz
)
RETURNS TABLE (
  organization_id uuid,
  invitation_id uuid,
  invitation_role text,
  invitation_created_by uuid,
  invitation_created_at timestamptz,
  invitation_expires_at timestamptz,
  invitation_consumed_by uuid,
  invitation_consumed_at timestamptz,
  invitation_revoked_at timestamptz,
  invitation_version bigint,
  membership_id uuid,
  member_id uuid,
  membership_role text,
  membership_status text,
  membership_version bigint,
  membership_created_at timestamptz,
  membership_updated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  invitation_row public.organization_invitations%ROWTYPE;
  consumed_row public.organization_invitations%ROWTYPE;
  membership_row public.memberships%ROWTYPE;
BEGIN
  IF p_organization_id IS NULL
     OR p_actor_member_id IS NULL
     OR p_token_hash IS NULL
     OR octet_length(p_token_hash) <> 32
     OR p_membership_id IS NULL
     OR p_accepted_at IS NULL
     OR NOT pg_catalog.isfinite(p_accepted_at) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'invitation acceptance authority input is invalid';
  END IF;

  -- Match the human mutation order used by membership/session authority:
  -- human authority -> organization -> session set -> invitation/membership.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_actor_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_actor_member_id::text, 0)
  );

  SELECT i.*
    INTO invitation_row
  FROM public.organization_invitations AS i
  WHERE i.organization_id = p_organization_id
    AND i.token_hash = p_token_hash
  FOR UPDATE;
  IF NOT FOUND
     OR invitation_row.revoked_at IS NOT NULL
     OR invitation_row.consumed_at IS NOT NULL
     OR invitation_row.expires_at <= p_accepted_at THEN
    RETURN;
  END IF;

  INSERT INTO public.memberships (
    organization_id, id, member_id, role, status
  ) VALUES (
    p_organization_id, p_membership_id, p_actor_member_id,
    invitation_row.role, 'active'
  )
  ON CONFLICT (organization_id, member_id) DO UPDATE
    SET role = EXCLUDED.role,
        status = 'active',
        version = memberships.version + 1,
        updated_at = pg_catalog.clock_timestamp()
  RETURNING * INTO membership_row;

  UPDATE public.organization_invitations AS i
     SET consumed_by = p_actor_member_id,
         consumed_at = p_accepted_at,
         version = i.version + 1,
         updated_at = pg_catalog.clock_timestamp()
   WHERE i.organization_id = p_organization_id
     AND i.id = invitation_row.id
     AND i.token_hash = p_token_hash
     AND i.revoked_at IS NULL
     AND i.consumed_at IS NULL
  RETURNING i.* INTO consumed_row;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'organization_invitations_accept_cas',
      MESSAGE = 'invitation acceptance lost its authority binding';
  END IF;

  RETURN QUERY SELECT
    consumed_row.organization_id,
    consumed_row.id,
    consumed_row.role,
    consumed_row.created_by,
    consumed_row.created_at,
    consumed_row.expires_at,
    consumed_row.consumed_by,
    consumed_row.consumed_at,
    consumed_row.revoked_at,
    consumed_row.version,
    membership_row.id,
    membership_row.member_id,
    membership_row.role,
    membership_row.status,
    membership_row.version,
    membership_row.created_at,
    membership_row.updated_at;
END;
$$;

CREATE FUNCTION public.agentpass_organization_invitation_list(
  p_organization_id uuid,
  p_actor_member_id uuid,
  p_after_created_at timestamptz,
  p_after_id uuid,
  p_limit integer
)
RETURNS TABLE (
  organization_id uuid,
  invitation_id uuid,
  role text,
  created_by uuid,
  created_at timestamptz,
  expires_at timestamptz,
  consumed_by uuid,
  consumed_at timestamptz,
  revoked_at timestamptz,
  version bigint
)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor_role text;
BEGIN
  IF p_organization_id IS NULL
     OR p_actor_member_id IS NULL
     OR p_limit IS NULL OR p_limit < 1 OR p_limit > 101
     OR (p_after_created_at IS NULL) <> (p_after_id IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'invitation listing authority input is invalid';
  END IF;

  SELECT m.role INTO actor_role
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_actor_member_id
    AND m.status = 'active'
  FOR SHARE;
  IF actor_role IS NULL OR actor_role NOT IN ('owner', 'admin', 'auditor') THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT i.organization_id, i.id, i.role, i.created_by, i.created_at,
         i.expires_at, i.consumed_by, i.consumed_at, i.revoked_at, i.version
  FROM public.organization_invitations AS i
  WHERE i.organization_id = p_organization_id
    AND (p_after_created_at IS NULL
      OR (date_trunc('milliseconds', i.created_at), i.id) > (p_after_created_at, p_after_id))
  ORDER BY date_trunc('milliseconds', i.created_at) ASC, i.id ASC
  LIMIT p_limit;
END;
$$;

ALTER FUNCTION public.agentpass_organization_invitation_create(
  uuid,uuid,bytea,text,uuid,timestamptz,timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_organization_invitation_revoke(
  uuid,uuid,bigint,timestamptz,uuid,text
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_organization_invitation_reissue(
  uuid,uuid,bytea,timestamptz,timestamptz,bigint,uuid
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_organization_invitation_accept(
  uuid,uuid,bytea,uuid,timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_organization_invitation_list(
  uuid,uuid,timestamptz,uuid,integer
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_organization_invitation_create(
  uuid,uuid,bytea,text,uuid,timestamptz,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_organization_invitation_revoke(
  uuid,uuid,bigint,timestamptz,uuid,text
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_organization_invitation_reissue(
  uuid,uuid,bytea,timestamptz,timestamptz,bigint,uuid
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_organization_invitation_accept(
  uuid,uuid,bytea,uuid,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_organization_invitation_list(
  uuid,uuid,timestamptz,uuid,integer
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_organization_invitation_create(
  uuid,uuid,bytea,text,uuid,timestamptz,timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_organization_invitation_revoke(
  uuid,uuid,bigint,timestamptz,uuid,text
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_organization_invitation_reissue(
  uuid,uuid,bytea,timestamptz,timestamptz,bigint,uuid
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_organization_invitation_accept(
  uuid,uuid,bytea,uuid,timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_organization_invitation_list(
  uuid,uuid,timestamptz,uuid,integer
) TO agentpass_app;

COMMENT ON FUNCTION public.agentpass_organization_invitation_accept(
  uuid,uuid,bytea,uuid,timestamptz
) IS 'SECURITY DEFINER atomic invitation consumption and membership activation; token never appears in the return shape.';

COMMIT;
