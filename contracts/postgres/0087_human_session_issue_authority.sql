BEGIN;

-- Human-session issuance is authority state.  The application must not
-- perform the INSERT or the concurrent-session reduction itself: the member
-- lock and the epoch observations have to cover both operations.
--
-- The returned jsonb has the same shape as the repository's sessionRow input,
-- including hex encodings for the two bearer-related hashes.  A NULL result
-- means that the requested tenant-qualified membership was not active.
CREATE FUNCTION public.agentpass_human_session_create(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_membership_id uuid,
  p_role text,
  p_token_hash bytea,
  p_csrf_token_hash bytea,
  p_created_at timestamptz,
  p_expires_at timestamptz,
  p_last_seen_at timestamptz,
  p_idle_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  created public.human_sessions%ROWTYPE;
  organization_epoch bigint;
  membership_epoch bigint;
  membership_role text;
BEGIN
  IF p_session_id IS NULL OR p_member_id IS NULL OR p_organization_id IS NULL
     OR p_membership_id IS NULL OR p_role IS NULL
     OR p_role NOT IN ('owner', 'admin', 'auditor', 'viewer')
     OR p_token_hash IS NULL OR octet_length(p_token_hash) <> 32
     OR p_csrf_token_hash IS NULL OR octet_length(p_csrf_token_hash) <> 32
     OR p_created_at IS NULL OR p_expires_at IS NULL
     OR p_expires_at <= p_created_at
     OR p_last_seen_at IS NULL
     OR p_last_seen_at < p_created_at OR p_last_seen_at > p_expires_at
     OR (p_idle_expires_at IS NOT NULL
         AND (p_idle_expires_at <= p_created_at OR p_idle_expires_at > p_expires_at)) THEN
    RAISE EXCEPTION 'invalid human session issue input'
      USING ERRCODE = '22023';
  END IF;

  -- This lock is global to the member, not process-local.  It serializes
  -- issuance with ceiling reduction, rotation, logout lineage handling, and
  -- organization changes that use the same session-set lock.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );

  -- Lock both authority rows before observing their epochs.  The trigger from
  -- 0024 also rechecks this binding at INSERT time; keeping the explicit
  -- observation here makes the returned contract self-contained.
  SELECT o.authority_epoch, m.session_epoch, m.role
    INTO organization_epoch, membership_epoch, membership_role
  FROM public.organizations AS o
  JOIN public.memberships AS m
    ON m.organization_id = o.id
   AND m.id = p_membership_id
   AND m.member_id = p_member_id
  WHERE o.id = p_organization_id
    AND m.status = 'active'
  FOR UPDATE OF o, m;

  IF NOT FOUND OR membership_role IS DISTINCT FROM p_role THEN
    RETURN NULL;
  END IF;

  INSERT INTO public.human_sessions (
    id, member_id, organization_id, membership_id, role,
    organization_authority_epoch, membership_session_epoch,
    token_hash, csrf_token_hash, created_at, expires_at, last_seen_at,
    idle_expires_at, recent_auth_at, revoked_at, revoke_reason
  ) VALUES (
    p_session_id, p_member_id, p_organization_id, p_membership_id, p_role,
    organization_epoch, membership_epoch, p_token_hash, p_csrf_token_hash,
    p_created_at, p_expires_at, p_last_seen_at, p_idle_expires_at,
    NULL, NULL, NULL
  )
  RETURNING * INTO created;

  RETURN to_jsonb(created) || jsonb_build_object(
    'token_hash_hex', encode(created.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(created.csrf_token_hash, 'hex')
  );
END;
$$;

-- Revoke exactly the excess current sessions, retaining the newest
-- p_max_concurrent_sessions - 1 rows for the session that will be issued by
-- agentpass_human_session_create_with_ceiling.  Thus the subsequent INSERT
-- makes the committed ceiling exactly p_max_concurrent_sessions.  Expired,
-- idle-expired, revoked, inactive-membership, role-mismatched, and stale-epoch
-- rows are not counted as active sessions.
CREATE FUNCTION public.agentpass_human_session_reduce_to_ceiling(
  p_member_id uuid,
  p_issued_at timestamptz,
  p_max_concurrent_sessions integer,
  p_revoke_reason text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  reduced_count integer;
BEGIN
  IF p_member_id IS NULL OR p_issued_at IS NULL
     OR p_max_concurrent_sessions IS NULL
     OR p_max_concurrent_sessions NOT BETWEEN 1 AND 10000
     OR p_revoke_reason IS NULL
     OR char_length(p_revoke_reason) NOT BETWEEN 1 AND 128
     OR p_revoke_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid human session ceiling input'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );

  WITH ranked AS (
    SELECT s.id,
           row_number() OVER (ORDER BY s.created_at DESC, s.id DESC) AS position
    FROM public.human_sessions AS s
    JOIN public.memberships AS m
      ON m.organization_id = s.organization_id
     AND m.member_id = s.member_id
     AND m.id = s.membership_id
    JOIN public.organizations AS o ON o.id = s.organization_id
    WHERE s.member_id = p_member_id
      AND s.revoked_at IS NULL
      AND s.expires_at > p_issued_at
      AND (s.idle_expires_at IS NULL OR s.idle_expires_at > p_issued_at)
      AND m.status = 'active'
      AND m.role = s.role
      AND o.authority_epoch = s.organization_authority_epoch
      AND m.session_epoch = s.membership_session_epoch
  ), excess AS (
    SELECT id FROM ranked WHERE position >= p_max_concurrent_sessions
  )
  UPDATE public.human_sessions AS target
     SET revoked_at = p_issued_at,
         revoke_reason = COALESCE(target.revoke_reason, p_revoke_reason),
         version = target.version + 1
    FROM excess
   WHERE target.id = excess.id
     AND target.revoked_at IS NULL;

  GET DIAGNOSTICS reduced_count = ROW_COUNT;
  RETURN reduced_count;
END;
$$;

-- Atomic ceiling path used by createSessionWithLimit.  The reduction and the
-- issuance share one transaction and one member lock; any constraint or
-- authority failure rolls back both, so a failed issue never consumes the
-- ceiling by revoking existing sessions.
CREATE FUNCTION public.agentpass_human_session_create_with_ceiling(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_membership_id uuid,
  p_role text,
  p_token_hash bytea,
  p_csrf_token_hash bytea,
  p_created_at timestamptz,
  p_expires_at timestamptz,
  p_last_seen_at timestamptz,
  p_idle_expires_at timestamptz,
  p_max_concurrent_sessions integer,
  p_revoke_reason text,
  p_issued_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  created jsonb;
  target_role text;
BEGIN
  IF p_issued_at IS NULL THEN
    RAISE EXCEPTION 'invalid human session issue timestamp'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );

  -- Preflight the target before reducing anything.  This is deliberately
  -- repeated by agentpass_human_session_create after the reduction: the row
  -- lock remains held in this transaction, while the second check keeps the
  -- primitive safe when called independently in a future revision.
  SELECT m.role
    INTO target_role
  FROM public.organizations AS o
  JOIN public.memberships AS m
    ON m.organization_id = o.id
   AND m.id = p_membership_id
   AND m.member_id = p_member_id
  WHERE o.id = p_organization_id
    AND m.status = 'active'
  FOR UPDATE OF o, m;
  IF NOT FOUND OR target_role IS DISTINCT FROM p_role THEN
    RETURN NULL;
  END IF;

  PERFORM public.agentpass_human_session_reduce_to_ceiling(
    p_member_id, p_issued_at, p_max_concurrent_sessions, p_revoke_reason
  );

  created := public.agentpass_human_session_create(
    p_session_id, p_member_id, p_organization_id, p_membership_id, p_role,
    p_token_hash, p_csrf_token_hash, p_created_at, p_expires_at,
    p_last_seen_at, p_idle_expires_at
  );
  RETURN created;
END;
$$;

ALTER FUNCTION public.agentpass_human_session_create(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_reduce_to_ceiling(
  uuid,timestamptz,integer,text
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_create_with_ceiling(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_create(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_reduce_to_ceiling(
  uuid,timestamptz,integer,text
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_create_with_ceiling(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_create(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_reduce_to_ceiling(
  uuid,timestamptz,integer,text
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_create_with_ceiling(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) TO agentpass_app;

COMMIT;
