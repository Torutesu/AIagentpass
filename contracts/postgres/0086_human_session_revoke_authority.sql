BEGIN;

-- Human-session revocation is authority state.  Keep the application role
-- away from human_sessions and expose only these reviewed primitives.
--
-- logout contract:
--   input  (session_id, member_id, organization_id, token_hash,
--           revoked_at, revoke_reason)
--   return the originally bound session as jsonb, or NULL when the binding
--   does not exist.  The token, tenant, member, and session id are all
--   required to identify the initial row.  A successor is followed only
--   through an exact session_rotation:<uuid> or organization_switch:<uuid>
--   link, for at most 32 rows.
CREATE FUNCTION public.agentpass_human_session_logout(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_token_hash bytea,
  p_revoked_at timestamptz,
  p_revoke_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  original public.human_sessions%ROWTYPE;
  successor public.human_sessions%ROWTYPE;
  successor_id uuid;
  visited integer := 1;
  result jsonb;
BEGIN
  IF p_session_id IS NULL OR p_member_id IS NULL OR p_organization_id IS NULL
     OR p_token_hash IS NULL OR octet_length(p_token_hash) <> 32
     OR p_revoked_at IS NULL OR p_revoke_reason IS NULL
     OR char_length(p_revoke_reason) NOT BETWEEN 1 AND 128
     OR p_revoke_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid human session logout input'
      USING ERRCODE = '22023';
  END IF;

  -- This is the same cross-instance/member lock used by rotateSession and
  -- logoutSession.  It closes the lookup/revoke race before row locking.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );

  SELECT s.*
    INTO original
  FROM public.human_sessions AS s
  WHERE s.id = p_session_id
    AND s.member_id = p_member_id
    AND s.organization_id = p_organization_id
    AND s.token_hash = p_token_hash
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  IF original.revoked_at IS NULL THEN
    UPDATE public.human_sessions AS s
       SET revoked_at = COALESCE(s.revoked_at, p_revoked_at),
           revoke_reason = COALESCE(s.revoke_reason, p_revoke_reason)
     WHERE s.id = p_session_id
       AND s.member_id = p_member_id
       AND s.organization_id = p_organization_id
       AND s.token_hash = p_token_hash
       AND s.revoked_at IS NULL
    RETURNING s.* INTO original;
  ELSE
    successor_id := CASE
      WHEN original.revoke_reason ~ '^(session_rotation|organization_switch):[0-9a-fA-F-]{36}$'
        THEN substring(original.revoke_reason FROM '^[^:]+:([0-9a-fA-F-]{36})$')::uuid
      ELSE NULL
    END;

    WHILE successor_id IS NOT NULL AND visited <= 32 LOOP
      SELECT s.*
        INTO successor
      FROM public.human_sessions AS s
      WHERE s.id = successor_id
        AND s.member_id = p_member_id
      FOR UPDATE;

      EXIT WHEN NOT FOUND;
      IF successor.revoked_at IS NULL THEN
        UPDATE public.human_sessions AS s
           SET revoked_at = COALESCE(s.revoked_at, p_revoked_at),
               revoke_reason = COALESCE(s.revoke_reason, p_revoke_reason)
         WHERE s.id = successor.id
           AND s.member_id = p_member_id
           AND s.revoked_at IS NULL;
      END IF;

      visited := visited + 1;
      successor_id := CASE
        WHEN successor.revoke_reason ~ '^(session_rotation|organization_switch):[0-9a-fA-F-]{36}$'
          THEN substring(successor.revoke_reason FROM '^[^:]+:([0-9a-fA-F-]{36})$')::uuid
        ELSE NULL
      END;
    END LOOP;

    IF successor_id IS NOT NULL AND visited > 32 THEN
      RAISE EXCEPTION 'session rotation lineage is too deep'
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;

  result := to_jsonb(original) || jsonb_build_object(
    'token_hash_hex', encode(original.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(original.csrf_token_hash, 'hex')
  );
  RETURN result;
END;
$$;

-- revoke contract:
--   input  (session_id, revoked_at, revoke_reason)
--   return the revoked session as jsonb, or NULL when the session is absent
--   or its tenant/member epoch binding is no longer current.  This mirrors
--   revokeSession; it intentionally has no bearer-token authority because it
--   is the management-path operation keyed by its session id.
CREATE FUNCTION public.agentpass_human_session_revoke(
  p_session_id uuid,
  p_revoked_at timestamptz,
  p_revoke_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  revoked public.human_sessions%ROWTYPE;
BEGIN
  IF p_session_id IS NULL OR p_revoked_at IS NULL
     OR p_revoke_reason IS NULL
     OR char_length(p_revoke_reason) NOT BETWEEN 1 AND 128
     OR p_revoke_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid human session revoke input'
      USING ERRCODE = '22023';
  END IF;

  UPDATE public.human_sessions AS s
     SET revoked_at = COALESCE(s.revoked_at, p_revoked_at),
         revoke_reason = COALESCE(s.revoke_reason, p_revoke_reason)
    FROM public.memberships AS m
    JOIN public.organizations AS o
      ON o.id = m.organization_id
   WHERE s.id = p_session_id
     AND s.organization_id = m.organization_id
     AND s.member_id = m.member_id
     AND s.membership_id = m.id
     AND o.authority_epoch = s.organization_authority_epoch
     AND m.session_epoch = s.membership_session_epoch
  RETURNING s.* INTO revoked;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  RETURN to_jsonb(revoked) || jsonb_build_object(
    'token_hash_hex', encode(revoked.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(revoked.csrf_token_hash, 'hex')
  );
END;
$$;

ALTER FUNCTION public.agentpass_human_session_logout(uuid,uuid,uuid,bytea,timestamptz,text)
  OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_revoke(uuid,timestamptz,text)
  OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_logout(uuid,uuid,uuid,bytea,timestamptz,text)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_revoke(uuid,timestamptz,text)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_logout(uuid,uuid,uuid,bytea,timestamptz,text)
  TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_revoke(uuid,timestamptz,text)
  TO agentpass_app;

COMMIT;
