BEGIN;

-- Session rotation is a single authority operation.  The application supplies
-- the old bearer binding and the proposed successor, but this function owns
-- the membership/epoch checks, successor INSERT, and old-row revocation.
--
-- The member advisory lock is intentionally the only advisory lock here.  It
-- is the same lock used by issue and logout, and serializes every session set
-- operation for the member.  Organization authority is protected below by
-- row locks.  Taking an organization advisory lock as well would introduce
-- an order inversion with organization switching (member -> organization)
-- and identity invalidation (organization -> member).
CREATE FUNCTION public.agentpass_human_session_rotate(
  p_old_session_id uuid,
  p_old_token_hash bytea,
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
  p_rotated_at timestamptz,
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
  revoked_id uuid;
  revoked_reason text;
  organization_epoch bigint;
  membership_epoch bigint;
  membership_role text;
  successor_revoke_reason text;
  max_lineage_depth constant integer := 32;
BEGIN
  IF p_old_session_id IS NULL
     OR p_old_token_hash IS NULL
     OR octet_length(p_old_token_hash) <> 32
     OR p_session_id IS NULL
     OR p_member_id IS NULL
     OR p_organization_id IS NULL
     OR p_membership_id IS NULL
     OR p_role IS NULL
     OR p_role NOT IN ('owner', 'admin', 'auditor', 'viewer')
     OR p_token_hash IS NULL
     OR octet_length(p_token_hash) <> 32
     OR p_csrf_token_hash IS NULL
     OR octet_length(p_csrf_token_hash) <> 32
     OR p_created_at IS NULL
     OR p_expires_at IS NULL
     OR p_expires_at <= p_created_at
     OR p_last_seen_at IS NULL
     OR p_last_seen_at < p_created_at
     OR p_last_seen_at > p_expires_at
     OR (p_idle_expires_at IS NOT NULL
         AND (p_idle_expires_at <= p_created_at OR p_idle_expires_at > p_expires_at))
     OR p_rotated_at IS NULL
     OR p_reason IS NULL
     OR char_length(p_reason) NOT BETWEEN 1 AND 128
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid human session rotation input'
      USING ERRCODE = '22023';
  END IF;

  IF p_old_session_id = p_session_id THEN
    RAISE EXCEPTION 'a human session cannot rotate to itself'
      USING ERRCODE = '22023';
  END IF;

  -- This lock is the cross-instance/member serialization boundary shared with
  -- logout, issue, and concurrent rotations.  It is acquired before any row
  -- lock so all session-set operations have the same first lock.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );

  -- Bind the old bearer to every identity and authority dimension.  In
  -- particular, a valid token hash from another session, member, tenant,
  -- membership, role, epoch, or lifetime cannot authorize this rotation.
  SELECT s.*
    INTO old_session
  FROM public.human_sessions AS s
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_old_session_id
    AND s.token_hash = p_old_token_hash
    AND s.member_id = p_member_id
    AND s.organization_id = p_organization_id
    AND s.membership_id = p_membership_id
    AND s.role = p_role
    AND s.revoked_at IS NULL
    AND s.expires_at > p_rotated_at
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > p_rotated_at)
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  FOR UPDATE OF s;

  -- A retry, logout winner, expired session, or stale authority binding is a
  -- no-op.  Crucially, no successor is issued in this case.
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  -- Lock the current authority rows before taking their epoch snapshot.  The
  -- member lock above serializes this with session-set mutations; these row
  -- locks serialize the snapshot with authority changes without acquiring a
  -- second advisory lock in the opposite order.
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
    RAISE EXCEPTION 'active session membership is unavailable'
      USING ERRCODE = 'foreign_key_violation';
  END IF;

  -- A rotation edge is one bounded, exact successor reference.  Do not copy
  -- any prior reason into the new row; logout follows at most 32 such edges.
  successor_revoke_reason := CASE
    WHEN p_reason = 'session_rotation'
      THEN p_reason || ':' || p_session_id::text
    ELSE p_reason
  END;
  IF char_length(successor_revoke_reason) > 128
     OR (max_lineage_depth < 1) THEN
    RAISE EXCEPTION 'human session rotation lineage is invalid'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.human_sessions (
    id, member_id, organization_id, membership_id, role,
    organization_authority_epoch, membership_session_epoch,
    token_hash, csrf_token_hash, created_at, expires_at, last_seen_at,
    idle_expires_at, recent_auth_at, revoked_at, revoke_reason
  ) VALUES (
    p_session_id, p_member_id, p_organization_id, p_membership_id, p_role,
    organization_epoch, membership_epoch,
    p_token_hash, p_csrf_token_hash, p_created_at, p_expires_at,
    p_last_seen_at, p_idle_expires_at, NULL, NULL, NULL
  )
  RETURNING * INTO successor;

  -- INSERT ... RETURNING must produce exactly the successor that will be
  -- returned.  This explicit check makes a missing or trigger-altered
  -- successor fail closed before the old bearer is revoked; the transaction
  -- then rolls the successor back as well.
  IF NOT FOUND
     OR successor.id IS NULL
     OR successor.id IS DISTINCT FROM p_session_id
     OR successor.member_id IS DISTINCT FROM p_member_id
     OR successor.organization_id IS DISTINCT FROM p_organization_id
     OR successor.membership_id IS DISTINCT FROM p_membership_id
     OR successor.role IS DISTINCT FROM p_role
     OR successor.token_hash IS DISTINCT FROM p_token_hash
     OR successor.csrf_token_hash IS DISTINCT FROM p_csrf_token_hash
     OR successor.revoked_at IS NOT NULL
     OR successor.revoke_reason IS NOT NULL
     OR successor.organization_authority_epoch IS DISTINCT FROM organization_epoch
     OR successor.membership_session_epoch IS DISTINCT FROM membership_epoch THEN
    RAISE EXCEPTION 'human session rotation successor is missing or invalid'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  -- Recheck the exact old binding in the mutation itself.  The old row was
  -- already locked above, but repeating the predicates makes the revocation
  -- boundary independently safe if this function is revised or a trigger
  -- changes the row between the two statements.
  UPDATE public.human_sessions AS s
     SET revoked_at = COALESCE(s.revoked_at, p_rotated_at),
         revoke_reason = COALESCE(s.revoke_reason, successor_revoke_reason)
    FROM public.memberships AS m
    JOIN public.organizations AS o
      ON o.id = m.organization_id
   WHERE s.id = p_old_session_id
     AND s.token_hash = p_old_token_hash
     AND s.member_id = p_member_id
     AND s.organization_id = p_organization_id
     AND s.membership_id = p_membership_id
     AND s.role = p_role
     AND s.revoked_at IS NULL
     AND s.expires_at > p_rotated_at
     AND (s.idle_expires_at IS NULL OR s.idle_expires_at > p_rotated_at)
     AND m.organization_id = s.organization_id
     AND m.member_id = s.member_id
     AND m.id = s.membership_id
     AND m.status = 'active'
     AND m.role = s.role
     AND o.authority_epoch = s.organization_authority_epoch
     AND m.session_epoch = s.membership_session_epoch
  RETURNING s.id, s.revoke_reason INTO revoked_id, revoked_reason;

  IF NOT FOUND OR revoked_id IS DISTINCT FROM p_old_session_id THEN
    RAISE EXCEPTION 'human session rotation lost its old session binding'
      USING ERRCODE = 'serialization_failure';
  END IF;

  -- A normal active row has no prior revoke reason.  If a direct writer has
  -- populated one, retaining it must not silently discard the rotation edge.
  IF p_reason = 'session_rotation'
     AND revoked_reason IS DISTINCT FROM successor_revoke_reason THEN
    RAISE EXCEPTION 'human session rotation successor binding was not stored'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  RETURN to_jsonb(successor) || jsonb_build_object(
    'token_hash_hex', encode(successor.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(successor.csrf_token_hash, 'hex')
  );
END;
$$;

ALTER FUNCTION public.agentpass_human_session_rotate(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_rotate(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_rotate(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) TO agentpass_app;

COMMIT;
