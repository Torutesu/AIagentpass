BEGIN;

CREATE FUNCTION public.agentpass_human_session_revoke_managed(
  p_actor_session_id uuid,
  p_target_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_expected_version bigint,
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
  revoked public.human_sessions%ROWTYPE;
BEGIN
  IF p_actor_session_id IS NULL OR p_target_session_id IS NULL OR p_actor_session_id = p_target_session_id
     OR p_member_id IS NULL OR p_organization_id IS NULL OR p_expected_version < 1
     OR p_revoked_at IS NULL OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 128
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid managed human session revoke input' USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:organization:' || p_organization_id::text, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0));

  UPDATE public.human_sessions AS target
  SET revoked_at = p_revoked_at,
      revoke_reason = p_reason,
      version = target.version + 1,
      recent_auth_at = NULL,
      recent_auth_challenge_id = NULL,
      recent_auth_organization_id = NULL,
      recent_auth_operation = NULL,
      recent_auth_consumed_at = NULL
  FROM public.human_sessions AS actor,
       public.memberships AS actor_membership,
       public.organizations AS actor_organization,
       public.memberships AS target_membership,
       public.organizations AS target_organization
  WHERE target.id = p_target_session_id
    AND target.member_id = p_member_id
    AND target.organization_id = p_organization_id
    AND target.version = p_expected_version
    AND target.revoked_at IS NULL
    AND actor.id = p_actor_session_id
    AND actor_membership.organization_id = actor.organization_id
    AND actor_membership.member_id = actor.member_id
    AND actor_membership.id = actor.membership_id
    AND actor_organization.id = actor.organization_id
    AND target_membership.organization_id = target.organization_id
    AND target_membership.member_id = target.member_id
    AND target_membership.id = target.membership_id
    AND target_organization.id = target.organization_id
    AND actor.member_id = p_member_id
    AND actor.organization_id = p_organization_id
    AND actor.revoked_at IS NULL
    AND actor.expires_at > pg_catalog.clock_timestamp()
    AND (actor.idle_expires_at IS NULL OR actor.idle_expires_at > pg_catalog.clock_timestamp())
    AND actor_membership.status = 'active'
    AND actor_membership.role = actor.role
    AND actor_organization.authority_epoch = actor.organization_authority_epoch
    AND actor_membership.session_epoch = actor.membership_session_epoch
    AND target_membership.status = 'active'
    AND target_membership.role = target.role
    AND target_organization.authority_epoch = target.organization_authority_epoch
    AND target_membership.session_epoch = target.membership_session_epoch
  RETURNING target.* INTO revoked;

  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN to_jsonb(revoked) || jsonb_build_object(
    'token_hash_hex', encode(revoked.token_hash, 'hex'),
    'csrf_token_hash_hex', encode(revoked.csrf_token_hash, 'hex')
  );
END;
$$;

ALTER FUNCTION public.agentpass_human_session_revoke_managed(uuid,uuid,uuid,uuid,bigint,timestamptz,text)
  OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_revoke_managed(uuid,uuid,uuid,uuid,bigint,timestamptz,text)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_revoke_managed(uuid,uuid,uuid,uuid,bigint,timestamptz,text)
  TO agentpass_app;

COMMIT;
