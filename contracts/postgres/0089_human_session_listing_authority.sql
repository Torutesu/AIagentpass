BEGIN;

-- Human-session listings are management reads, not a bearer-token lookup.
-- Keep both paths behind purpose-specific functions so the application role
-- cannot select token or CSRF hashes from human_sessions.
CREATE FUNCTION public.agentpass_human_session_list(
  p_member_id uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    'session_id', s.id,
    'member_id', s.member_id,
    'organization_id', s.organization_id,
    'role', s.role,
    'version', s.version,
    'created_at', s.created_at,
    'expires_at', s.expires_at,
    'last_seen_at', s.last_seen_at,
    'idle_expires_at', s.idle_expires_at,
    'recent_auth_at', s.recent_auth_at,
    'revoked_at', s.revoked_at,
    'revoke_reason', s.revoke_reason
  )
  FROM public.human_sessions AS s
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.member_id = p_member_id
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  ORDER BY s.created_at ASC, s.id ASC
  LIMIT 100;
$$;

-- The safe management listing preserves the existing tenant/member/epoch and
-- active-membership predicates.  The cursor is the truncated millisecond
-- created_at plus id tuple, and the function deliberately returns one extra
-- row so the caller can derive its next page without a count query.
CREATE FUNCTION public.agentpass_human_session_list_safe(
  p_member_id uuid,
  p_organization_id uuid,
  p_after_created_at timestamptz DEFAULT NULL,
  p_after_id uuid DEFAULT NULL,
  p_limit integer DEFAULT 25
)
RETURNS SETOF jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_member_id IS NULL
     OR p_limit IS NULL
     OR p_limit NOT BETWEEN 1 AND 100
     OR ((p_after_created_at IS NULL) <> (p_after_id IS NULL)) THEN
    RAISE EXCEPTION 'invalid human session listing input'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT jsonb_build_object(
    'session_id', s.id,
    'member_id', s.member_id,
    'organization_id', s.organization_id,
    'role', s.role,
    'version', s.version,
    'created_at', s.created_at,
    'expires_at', s.expires_at,
    'last_seen_at', s.last_seen_at,
    'idle_expires_at', s.idle_expires_at,
    'recent_auth_at', s.recent_auth_at,
    'revoked_at', s.revoked_at,
    'revoke_reason', s.revoke_reason
  )
  FROM public.human_sessions AS s
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
   AND m.status = 'active'
   AND m.role = s.role
  JOIN public.organizations AS o
    ON o.id = s.organization_id
   AND o.authority_epoch = s.organization_authority_epoch
  WHERE s.member_id = p_member_id
    AND (p_organization_id IS NULL OR s.organization_id = p_organization_id)
    AND m.session_epoch = s.membership_session_epoch
    AND (
      p_after_created_at IS NULL
      OR (date_trunc('milliseconds', s.created_at), s.id)
         > (date_trunc('milliseconds', p_after_created_at), p_after_id)
    )
  ORDER BY date_trunc('milliseconds', s.created_at) ASC, s.id ASC
  LIMIT (p_limit + 1);
END;
$$;

ALTER FUNCTION public.agentpass_human_session_list(uuid)
  OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_list_safe(uuid,uuid,timestamptz,uuid,integer)
  OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_list(uuid)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_list_safe(uuid,uuid,timestamptz,uuid,integer)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_list(uuid)
  TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_list_safe(uuid,uuid,timestamptz,uuid,integer)
  TO agentpass_app;

COMMIT;
