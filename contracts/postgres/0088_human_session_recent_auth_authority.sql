BEGIN;

-- Recent WebAuthn authorization is session authority state.  Keep both the
-- challenge proof and its one-time session binding behind reviewed
-- SECURITY DEFINER entry points; the application must not UPDATE either
-- human_sessions or inspect the challenge with a direct EXISTS query.
CREATE FUNCTION public.agentpass_human_session_bind_recent_auth(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_operation text,
  p_challenge_id uuid,
  p_context_hash bytea,
  p_authenticated_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  affected integer;
BEGIN
  IF p_session_id IS NULL OR p_member_id IS NULL
     OR p_organization_id IS NULL OR p_operation IS NULL
     OR char_length(p_operation) NOT BETWEEN 1 AND 128
     OR p_challenge_id IS NULL
     OR (p_context_hash IS NOT NULL AND octet_length(p_context_hash) <> 32)
     OR p_authenticated_at IS NULL THEN
    RAISE EXCEPTION 'invalid recent authentication binding input'
      USING ERRCODE = '22023';
  END IF;

  -- Serialize all recent-auth transitions for one member across Cloud
  -- instances.  The UPDATE itself remains the atomic success predicate.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );

  UPDATE public.human_sessions AS s
     SET recent_auth_at = p_authenticated_at,
         recent_auth_challenge_id = p_challenge_id,
         recent_auth_organization_id = p_organization_id,
         recent_auth_operation = p_operation,
         recent_auth_context_hash = p_context_hash,
         recent_auth_consumed_at = NULL
    FROM public.memberships AS m
    JOIN public.organizations AS o
      ON o.id = m.organization_id
   WHERE s.id = p_session_id
     AND s.member_id = p_member_id
     AND s.organization_id = p_organization_id
     AND s.membership_id = m.id
     AND m.member_id = s.member_id
     AND m.organization_id = s.organization_id
     AND s.revoked_at IS NULL
     AND s.expires_at > p_authenticated_at
     AND (s.idle_expires_at IS NULL OR s.idle_expires_at > p_authenticated_at)
     AND m.status = 'active'
     AND m.role = s.role
     AND o.authority_epoch = s.organization_authority_epoch
     AND m.session_epoch = s.membership_session_epoch
     AND EXISTS (
       SELECT 1
       FROM public.webauthn_challenges AS c
       WHERE c.id = p_challenge_id
         AND c.session_id = s.id
         AND c.member_id = s.member_id
         AND c.organization_id = s.organization_id
         AND c.operation = p_operation
         AND c.context_hash IS NOT DISTINCT FROM p_context_hash
         AND c.ceremony = 'authentication'
         AND c.status = 'consumed'
         AND c.consumed_at = p_authenticated_at
     );

  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected = 1;
END;
$$;

CREATE FUNCTION public.agentpass_human_session_consume_recent_auth(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_operation text,
  p_challenge_id uuid,
  p_context_hash bytea,
  p_consumed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  consumed jsonb;
BEGIN
  IF p_session_id IS NULL OR p_member_id IS NULL
     OR p_organization_id IS NULL OR p_operation IS NULL
     OR char_length(p_operation) NOT BETWEEN 1 AND 128
     OR p_challenge_id IS NULL
     OR (p_context_hash IS NOT NULL AND octet_length(p_context_hash) <> 32)
     OR p_consumed_at IS NULL THEN
    RAISE EXCEPTION 'invalid recent authentication consume input'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );

  UPDATE public.human_sessions AS s
     SET recent_auth_consumed_at = p_consumed_at
    FROM public.memberships AS m
    JOIN public.organizations AS o
      ON o.id = m.organization_id
   WHERE s.id = p_session_id
     AND s.member_id = p_member_id
     AND s.recent_auth_organization_id = p_organization_id
     AND s.organization_id = p_organization_id
     AND s.recent_auth_operation = p_operation
     AND s.recent_auth_challenge_id = p_challenge_id
     AND s.recent_auth_context_hash IS NOT DISTINCT FROM p_context_hash
     AND s.recent_auth_consumed_at IS NULL
     AND s.revoked_at IS NULL
     AND s.expires_at > p_consumed_at
     AND (s.idle_expires_at IS NULL OR s.idle_expires_at > p_consumed_at)
     AND s.recent_auth_at > p_consumed_at - INTERVAL '5 minutes'
     AND s.recent_auth_at <= p_consumed_at
     AND s.membership_id = m.id
     AND m.member_id = s.member_id
     AND m.organization_id = s.organization_id
     AND m.status = 'active'
     AND m.role = s.role
     AND o.authority_epoch = s.organization_authority_epoch
     AND m.session_epoch = s.membership_session_epoch
  RETURNING jsonb_build_object(
    'authenticated_at', s.recent_auth_at,
    'context_hash', encode(s.recent_auth_context_hash, 'hex')
  ) INTO consumed;

  RETURN consumed;
END;
$$;

ALTER FUNCTION public.agentpass_human_session_bind_recent_auth(
  uuid,uuid,uuid,text,uuid,bytea,timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_consume_recent_auth(
  uuid,uuid,uuid,text,uuid,bytea,timestamptz
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_bind_recent_auth(
  uuid,uuid,uuid,text,uuid,bytea,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_consume_recent_auth(
  uuid,uuid,uuid,text,uuid,bytea,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_bind_recent_auth(
  uuid,uuid,uuid,text,uuid,bytea,timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_consume_recent_auth(
  uuid,uuid,uuid,text,uuid,bytea,timestamptz
) TO agentpass_app;

COMMIT;
