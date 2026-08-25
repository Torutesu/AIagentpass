BEGIN;

-- Membership removal/revocation must invalidate every human session and
-- pending WebAuthn challenge for the member without granting the application
-- role direct DML on either authority relation.
CREATE FUNCTION public.agentpass_human_member_session_revoke(
  p_member_id uuid,
  p_organization_id uuid,
  p_revoked_at timestamptz,
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
  result jsonb;
BEGIN
  IF p_member_id IS NULL OR p_organization_id IS NULL
     OR p_revoked_at IS NULL OR p_reason IS NULL
     OR char_length(p_reason) NOT BETWEEN 1 AND 128
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid member session revoke input' USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_organization_id::text, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0));

  WITH revoked_sessions AS (
    UPDATE public.human_sessions AS s
    SET revoked_at = COALESCE(s.revoked_at, p_revoked_at),
        revoke_reason = COALESCE(s.revoke_reason, p_reason),
        version = CASE WHEN s.revoked_at IS NULL THEN s.version + 1 ELSE s.version END,
        recent_auth_at = NULL,
        recent_auth_challenge_id = NULL,
        recent_auth_organization_id = NULL,
        recent_auth_operation = NULL,
        recent_auth_context_hash = NULL,
        recent_auth_consumed_at = NULL
    WHERE s.member_id = p_member_id
      AND s.organization_id = p_organization_id
      AND s.revoked_at IS NULL
    RETURNING s.id, s.member_id, s.organization_id, s.role, s.version,
      s.created_at, s.expires_at, s.last_seen_at, s.idle_expires_at,
      s.recent_auth_at, s.revoked_at, s.revoke_reason
  ), consumed_challenges AS (
    UPDATE public.webauthn_challenges AS c
    SET consumed_at = p_revoked_at,
        status = 'consumed'
    WHERE c.organization_id = p_organization_id
      AND c.member_id = p_member_id
      AND c.status IN ('pending', 'consuming')
      AND c.consumed_at IS NULL
    RETURNING c.id
  )
  SELECT jsonb_build_object(
    'sessions', COALESCE((SELECT jsonb_agg(to_jsonb(revoked_sessions) ORDER BY revoked_sessions.id) FROM revoked_sessions), '[]'::jsonb),
    'session_count', (SELECT count(*) FROM revoked_sessions),
    'challenge_count', (SELECT count(*) FROM consumed_challenges)
  ) INTO result;

  RETURN result;
END;
$$;

ALTER FUNCTION public.agentpass_human_member_session_revoke(uuid,uuid,timestamptz,text)
  OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_member_session_revoke(uuid,uuid,timestamptz,text)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_member_session_revoke(uuid,uuid,timestamptz,text)
  TO agentpass_app;

COMMIT;
