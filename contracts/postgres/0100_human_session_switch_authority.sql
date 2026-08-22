BEGIN;

-- Organization switching is one atomic session-set operation.  The old
-- bearer is checked against its complete authority snapshot, the target
-- membership/organization epoch is read under lock, and the successor plus
-- old-session revocation are committed together.
CREATE FUNCTION public.agentpass_human_session_switch(
  p_old_session_id uuid,
  p_old_token_hash bytea,
  p_session_id uuid,
  p_member_id uuid,
  p_old_organization_id uuid,
  p_target_organization_id uuid,
  p_token_hash bytea,
  p_csrf_token_hash bytea,
  p_created_at timestamptz,
  p_expires_at timestamptz,
  p_last_seen_at timestamptz,
  p_idle_expires_at timestamptz,
  p_switched_at timestamptz,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  old_session public.human_sessions%ROWTYPE;
  successor public.human_sessions%ROWTYPE;
  target_membership public.memberships%ROWTYPE;
  target_authority_epoch bigint;
  revoked_id uuid;
  switch_reason text;
BEGIN
  IF p_old_session_id IS NULL OR p_old_token_hash IS NULL OR octet_length(p_old_token_hash) <> 32
     OR p_session_id IS NULL OR p_member_id IS NULL
     OR p_old_organization_id IS NULL OR p_target_organization_id IS NULL
     OR p_token_hash IS NULL OR octet_length(p_token_hash) <> 32
     OR p_csrf_token_hash IS NULL OR octet_length(p_csrf_token_hash) <> 32
     OR p_created_at IS NULL OR p_expires_at IS NULL OR p_expires_at <= p_created_at
     OR p_last_seen_at IS NULL OR p_last_seen_at < p_created_at OR p_last_seen_at > p_expires_at
     OR (p_idle_expires_at IS NOT NULL AND (p_idle_expires_at <= p_created_at OR p_idle_expires_at > p_expires_at))
     OR p_switched_at IS NULL OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 128
     OR p_reason ~ '[[:cntrl:]]' OR p_old_session_id = p_session_id
     OR p_old_organization_id = p_target_organization_id THEN
    RAISE EXCEPTION 'invalid human session switch input' USING ERRCODE = '22023';
  END IF;

  -- Organization advisory locks are the outer lock in every membership
  -- invalidation path. Acquire both tenants in UUID order before the member
  -- lock so a cross-organization switch cannot deadlock a membership change.
  IF p_old_organization_id < p_target_organization_id THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_old_organization_id::text, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_target_organization_id::text, 0));
  ELSE
    PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_target_organization_id::text, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_old_organization_id::text, 0));
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0));

  -- Acquire both organization rows in one deterministic order before either
  -- membership/session row.  This prevents cross-organization switch races
  -- from taking the two organization locks in opposite order.
  PERFORM 1
  FROM public.organizations AS o
  WHERE o.id IN (p_old_organization_id, p_target_organization_id)
  ORDER BY o.id
  FOR UPDATE;

  SELECT s.*
    INTO old_session
  FROM public.human_sessions AS s
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id AND m.member_id = s.member_id AND m.id = s.membership_id
  JOIN public.organizations AS o ON o.id = s.organization_id
  WHERE s.id = p_old_session_id AND s.token_hash = p_old_token_hash
    AND s.member_id = p_member_id AND s.organization_id = p_old_organization_id
    AND s.revoked_at IS NULL AND s.expires_at > pg_catalog.clock_timestamp()
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > pg_catalog.clock_timestamp())
    AND m.status = 'active' AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF p_switched_at < old_session.created_at
     OR p_switched_at > pg_catalog.clock_timestamp()
     OR p_expires_at > old_session.expires_at THEN
    RAISE EXCEPTION 'human session switch lifetime is outside the old session authority window'
      USING ERRCODE = '22023';
  END IF;

  SELECT m, o.authority_epoch
    INTO target_membership, target_authority_epoch
  FROM public.memberships AS m
  JOIN public.organizations AS o ON o.id = m.organization_id
  WHERE m.organization_id = p_target_organization_id
    AND m.member_id = p_member_id AND m.status = 'active'
  FOR UPDATE OF m, o;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'target organization membership is unavailable' USING ERRCODE = '23503';
  END IF;

  switch_reason := CASE WHEN p_reason = 'organization_switch'
    THEN p_reason || ':' || p_session_id::text ELSE p_reason END;
  IF char_length(switch_reason) > 128 THEN
    RAISE EXCEPTION 'human session switch reason is too long' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.human_sessions (
    id, member_id, organization_id, membership_id, role,
    organization_authority_epoch, membership_session_epoch,
    token_hash, csrf_token_hash, created_at, expires_at, last_seen_at,
    idle_expires_at, recent_auth_at, revoked_at, revoke_reason
  ) VALUES (
    p_session_id, p_member_id, p_target_organization_id, target_membership.id, target_membership.role,
    target_authority_epoch, target_membership.session_epoch,
    p_token_hash, p_csrf_token_hash, p_created_at, p_expires_at, p_last_seen_at,
    p_idle_expires_at, NULL, NULL, NULL
  ) RETURNING * INTO successor;

  IF successor.id IS DISTINCT FROM p_session_id
     OR successor.member_id IS DISTINCT FROM p_member_id
     OR successor.organization_id IS DISTINCT FROM p_target_organization_id
     OR successor.membership_id IS DISTINCT FROM target_membership.id
     OR successor.role IS DISTINCT FROM target_membership.role
     OR successor.organization_authority_epoch IS DISTINCT FROM target_authority_epoch
     OR successor.membership_session_epoch IS DISTINCT FROM target_membership.session_epoch
     OR successor.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'human session switch successor is invalid' USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  UPDATE public.human_sessions AS s
  SET revoked_at = COALESCE(s.revoked_at, p_switched_at),
      revoke_reason = COALESCE(s.revoke_reason, switch_reason),
      version = s.version + 1,
      recent_auth_at = NULL,
      recent_auth_challenge_id = NULL,
      recent_auth_organization_id = NULL,
      recent_auth_operation = NULL,
      recent_auth_consumed_at = NULL
  WHERE s.id = p_old_session_id AND s.token_hash = p_old_token_hash
    AND s.member_id = p_member_id AND s.organization_id = p_old_organization_id
    AND s.revoked_at IS NULL
  RETURNING s.id INTO revoked_id;
  IF revoked_id IS DISTINCT FROM p_old_session_id THEN
    RAISE EXCEPTION 'human session switch lost its old session binding' USING ERRCODE = '40001';
  END IF;

  RETURN to_jsonb(successor) || jsonb_build_object(
    'token_hash_hex', encode(successor.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(successor.csrf_token_hash, 'hex')
  );
END;
$$;

ALTER FUNCTION public.agentpass_human_session_switch(
  uuid,bytea,uuid,uuid,uuid,uuid,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_switch(
  uuid,bytea,uuid,uuid,uuid,uuid,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_switch(
  uuid,bytea,uuid,uuid,uuid,uuid,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) TO agentpass_app;

COMMIT;
