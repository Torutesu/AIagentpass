BEGIN;

CREATE FUNCTION public.agentpass_human_session_revoke_others(
  p_actor_session_id uuid,
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
  IF p_actor_session_id IS NULL OR p_member_id IS NULL OR p_organization_id IS NULL
     OR p_revoked_at IS NULL OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 128
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid other-session revoke input' USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_organization_id::text, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0));

  WITH actor AS (
    SELECT s.id
    FROM public.human_sessions AS s
    JOIN public.memberships AS m ON m.organization_id = s.organization_id AND m.member_id = s.member_id AND m.id = s.membership_id
    JOIN public.organizations AS o ON o.id = s.organization_id
    WHERE s.id = p_actor_session_id AND s.member_id = p_member_id AND s.organization_id = p_organization_id
      AND s.revoked_at IS NULL AND s.expires_at > pg_catalog.clock_timestamp()
      AND (s.idle_expires_at IS NULL OR s.idle_expires_at > pg_catalog.clock_timestamp())
      AND m.status = 'active' AND m.role = s.role
      AND o.authority_epoch = s.organization_authority_epoch AND m.session_epoch = s.membership_session_epoch
  ), changed AS (
    UPDATE public.human_sessions AS target
    SET revoked_at = p_revoked_at,
        revoke_reason = p_reason,
        version = target.version + 1,
        recent_auth_at = NULL,
        recent_auth_challenge_id = NULL,
        recent_auth_organization_id = NULL,
        recent_auth_operation = NULL,
        recent_auth_consumed_at = NULL
    FROM actor, public.memberships AS m, public.organizations AS o
    WHERE target.member_id = p_member_id AND target.organization_id = p_organization_id
      AND target.id <> p_actor_session_id AND target.revoked_at IS NULL
      AND target.expires_at > pg_catalog.clock_timestamp()
      AND (target.idle_expires_at IS NULL OR target.idle_expires_at > pg_catalog.clock_timestamp())
      AND m.organization_id = target.organization_id
      AND m.member_id = target.member_id
      AND m.id = target.membership_id
      AND o.id = target.organization_id
      AND m.status = 'active' AND m.role = target.role
      AND o.authority_epoch = target.organization_authority_epoch
      AND m.session_epoch = target.membership_session_epoch
    RETURNING target.id, target.member_id, target.organization_id, target.role, target.version,
      target.created_at, target.expires_at, target.last_seen_at, target.idle_expires_at,
      target.recent_auth_at, target.revoked_at, target.revoke_reason
  )
  SELECT COALESCE(jsonb_agg(to_jsonb(changed) ORDER BY changed.id), '[]'::jsonb)
    INTO result
  FROM changed;

  RETURN result;
END;
$$;

ALTER FUNCTION public.agentpass_human_session_revoke_others(uuid,uuid,uuid,timestamptz,text)
  OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_revoke_others(uuid,uuid,uuid,timestamptz,text)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_revoke_others(uuid,uuid,uuid,timestamptz,text)
  TO agentpass_app;

COMMIT;
