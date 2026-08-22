BEGIN;

-- Human session authentication and activity updates are authority operations.
-- The online application reaches them through these fixed SECURITY DEFINER
-- entry points instead of reading or mutating human_sessions directly.
CREATE FUNCTION public.agentpass_human_session_find_by_token(
  p_token_hash bytea
)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT to_jsonb(s) || jsonb_build_object(
    'token_hash_hex', encode(s.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(s.csrf_token_hash, 'hex')
  )
  FROM public.human_sessions AS s
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.token_hash = p_token_hash
    AND s.revoked_at IS NULL
    AND s.expires_at > clock_timestamp()
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > clock_timestamp())
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  LIMIT 1;
$$;

CREATE FUNCTION public.agentpass_human_session_touch(
  p_session_id uuid,
  p_last_seen_at timestamptz,
  p_idle_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  UPDATE public.human_sessions AS s
  SET last_seen_at = p_last_seen_at,
      idle_expires_at = p_idle_expires_at
  FROM public.memberships AS m
  JOIN public.organizations AS o
    ON o.id = m.organization_id
  WHERE s.id = p_session_id
    AND s.organization_id = m.organization_id
    AND s.member_id = m.member_id
    AND s.membership_id = m.id
    AND s.revoked_at IS NULL
    AND s.expires_at > clock_timestamp()
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > clock_timestamp())
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  RETURNING to_jsonb(s) || jsonb_build_object(
    'token_hash_hex', encode(s.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(s.csrf_token_hash, 'hex')
  );
$$;

ALTER FUNCTION public.agentpass_human_session_find_by_token(bytea) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_touch(uuid,timestamptz,timestamptz) OWNER TO agentpass_migrator;

-- Direct table privileges remain in place until every human-session and
-- credential repository path has moved to reviewed functions. A later
-- authority-cutover migration must revoke them atomically; revoking them here
-- would break create/list/WebAuthn/recent-auth paths that are still direct.
REVOKE EXECUTE ON FUNCTION public.agentpass_human_session_find_by_token(bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.agentpass_human_session_touch(uuid,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_find_by_token(bytea)
  FROM agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_touch(uuid,timestamptz,timestamptz)
  FROM agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_find_by_token(bytea) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_touch(uuid,timestamptz,timestamptz) TO agentpass_app;

COMMIT;
