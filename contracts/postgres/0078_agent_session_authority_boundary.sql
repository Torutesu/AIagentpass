BEGIN;

-- Agent Session Grants and Sessions are authority state, not ordinary
-- application data. The online application reaches them through reviewed
-- SECURITY DEFINER entry points.
--
-- Remove the legacy tenant DML policies as well as the ACLs.  Keeping those
-- policies would leave a misleading direct-DML contract in the catalog even
-- though the roles below no longer have table privileges.
DROP POLICY IF EXISTS agent_session_grants_tenant_select ON public.agent_session_grants;
DROP POLICY IF EXISTS agent_session_grants_tenant_insert ON public.agent_session_grants;
DROP POLICY IF EXISTS agent_session_grants_tenant_update ON public.agent_session_grants;
DROP POLICY IF EXISTS agent_session_grants_tenant_delete ON public.agent_session_grants;
DROP POLICY IF EXISTS agent_sessions_tenant_select ON public.agent_sessions;
DROP POLICY IF EXISTS agent_sessions_tenant_insert ON public.agent_sessions;
DROP POLICY IF EXISTS agent_sessions_tenant_update ON public.agent_sessions;
DROP POLICY IF EXISTS agent_sessions_tenant_delete ON public.agent_sessions;
DROP POLICY IF EXISTS agent_sessions_signing_capability_migrator_authority ON public.agent_sessions;

ALTER TABLE public.agent_session_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_session_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE public.agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_sessions FORCE ROW LEVEL SECURITY;

-- SECURITY DEFINER authority functions run as the migration owner and need a
-- deployment-wide policy to lock/recheck rows across the tenant boundary.
CREATE POLICY agent_session_grants_migrator_authority
  ON public.agent_session_grants FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY agent_session_grants_backup_select
  ON public.agent_session_grants FOR SELECT TO agentpass_backup
  USING (true);
CREATE POLICY agent_sessions_migrator_authority
  ON public.agent_sessions FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY agent_sessions_backup_select
  ON public.agent_sessions FOR SELECT TO agentpass_backup
  USING (true);

-- Typed issue boundary. The boolean is returned with the committed row so an
-- idempotent retry does not require a direct SELECT by the application.
CREATE FUNCTION public.agentpass_agent_session_grant_issue(
  p_organization_id uuid,
  p_grant_id uuid,
  p_device_id uuid,
  p_agent_id uuid,
  p_agent_kind text,
  p_adapter_id uuid,
  p_adapter_version text,
  p_worktree_binding_sha256 text,
  p_process_binding_policy_id text,
  p_scope_json jsonb,
  p_max_signatures integer,
  p_not_before timestamptz,
  p_expires_at timestamptz,
  p_control_sequence bigint,
  p_authority_generation bigint,
  p_issuer text,
  p_signer_key_id text,
  p_statement_hash text,
  p_grant_hash text,
  p_signature_base64url text,
  p_issued_at timestamptz,
  p_created_by uuid
)
RETURNS TABLE (
  inserted boolean,
  organization_id uuid, grant_id uuid, device_id uuid, agent_id uuid,
  agent_kind text, adapter_id uuid, adapter_version text,
  worktree_binding_sha256 text, process_binding_policy_id text, scope_json jsonb,
  max_signatures integer, not_before timestamptz, expires_at timestamptz,
  control_sequence bigint, authority_generation bigint, issuer text, signer_key_id text,
  statement_hash text, grant_hash text, signature_base64url text, status text,
  issued_at timestamptz, consumed_at timestamptz, consumed_session_id uuid,
  consumed_process_binding_sha256 text, expired_at timestamptz, revoked_at timestamptz,
  created_by uuid
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
#variable_conflict use_column
DECLARE
  changed integer;
  did_insert boolean;
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', CONSTRAINT = 'agent_session_authority_tenant';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:agent-session-grant:' || p_organization_id::text || ':' || p_grant_id::text, 0
  ));
  INSERT INTO public.agent_session_grants (
    organization_id, grant_id, device_id, agent_id, agent_kind, adapter_id,
    adapter_version, worktree_binding_sha256, process_binding_policy_id, scope_json,
    max_signatures, not_before, expires_at, control_sequence, authority_generation,
    issuer, signer_key_id, statement_hash, grant_hash, signature_base64url, status,
    issued_at, created_by
  ) VALUES (
    p_organization_id, p_grant_id, p_device_id, p_agent_id, p_agent_kind, p_adapter_id,
    p_adapter_version, p_worktree_binding_sha256, p_process_binding_policy_id, p_scope_json,
    p_max_signatures, p_not_before, p_expires_at, p_control_sequence, p_authority_generation,
    p_issuer, p_signer_key_id, p_statement_hash, p_grant_hash, p_signature_base64url,
    'issued', p_issued_at, p_created_by
  ) ON CONFLICT (organization_id, grant_id) DO NOTHING;
  GET DIAGNOSTICS changed = ROW_COUNT;
  did_insert := changed = 1;
  RETURN QUERY SELECT did_insert,
    g.organization_id, g.grant_id, g.device_id, g.agent_id, g.agent_kind,
    g.adapter_id, g.adapter_version, g.worktree_binding_sha256,
    g.process_binding_policy_id, g.scope_json, g.max_signatures,
    g.not_before, g.expires_at, g.control_sequence, g.authority_generation,
    g.issuer, g.signer_key_id, g.statement_hash, g.grant_hash,
    g.signature_base64url, g.status, g.issued_at, g.consumed_at,
    g.consumed_session_id, g.consumed_process_binding_sha256, g.expired_at,
    g.revoked_at, g.created_by
    FROM public.agent_session_grants AS g
    WHERE g.organization_id = p_organization_id AND g.grant_id = p_grant_id
    FOR UPDATE;
END;
$$;

CREATE FUNCTION public.agentpass_agent_session_lifecycle_expire_due(
  p_organization_id uuid,
  p_limit integer,
  p_expired_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  grant_count integer;
  session_count integer;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', CONSTRAINT = 'agent_session_authority_tenant';
  END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 500 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', CONSTRAINT = 'agent_session_authority_lifecycle_limit';
  END IF;
  WITH candidates AS (
    SELECT g.organization_id, g.grant_id
    FROM public.agent_session_grants AS g
    WHERE g.organization_id = p_organization_id AND g.status = 'issued' AND g.expires_at <= now_value
    ORDER BY g.expires_at ASC, g.grant_id ASC
    LIMIT p_limit
    FOR UPDATE OF g SKIP LOCKED
  )
  UPDATE public.agent_session_grants AS g
  SET status = 'expired',
      expired_at = GREATEST(now_value, COALESCE(p_expired_at, now_value), g.expires_at)
  FROM candidates
  WHERE g.organization_id = candidates.organization_id
    AND g.grant_id = candidates.grant_id
    AND g.status = 'issued'
  ;
  GET DIAGNOSTICS grant_count = ROW_COUNT;

  WITH candidates AS (
    SELECT s.organization_id, s.session_id
    FROM public.agent_sessions AS s
    WHERE s.organization_id = p_organization_id
      AND s.status IN ('challenge_pending','active','request_reserved','signing_intent','signed')
      AND s.expires_at <= now_value
    ORDER BY s.expires_at ASC, s.session_id ASC
    LIMIT p_limit
    FOR UPDATE OF s SKIP LOCKED
  )
  UPDATE public.agent_sessions AS s
  SET status = 'expired',
      last_request_id = COALESCE(s.last_request_id, s.active_request_id),
      active_request_id = NULL,
      expired_at = GREATEST(now_value, COALESCE(p_expired_at, now_value), s.expires_at)
  FROM candidates
  WHERE s.organization_id = candidates.organization_id
    AND s.session_id = candidates.session_id
    AND s.status IN ('challenge_pending','active','request_reserved','signing_intent','signed');
  GET DIAGNOSTICS session_count = ROW_COUNT;
  RETURN jsonb_build_object(
    'counts', jsonb_build_array(grant_count, session_count),
    'expired', grant_count + session_count,
    'revoked', 0
  );
END;
$$;

CREATE FUNCTION public.agentpass_agent_session_lifecycle_revoke(
  p_organization_id uuid,
  p_device_id uuid,
  p_agent_id uuid,
  p_grant_id uuid,
  p_session_id uuid,
  p_organization_wide boolean,
  p_revoked_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  grant_count integer;
  session_count integer;
  grant_expired_count integer;
  grant_revoked_count integer;
  session_expired_count integer;
  session_revoked_count integer;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', CONSTRAINT = 'agent_session_authority_tenant';
  END IF;
  IF NOT p_organization_wide AND p_device_id IS NULL AND p_agent_id IS NULL
     AND p_grant_id IS NULL AND p_session_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', CONSTRAINT = 'agent_session_authority_lifecycle_selector';
  END IF;

  WITH candidates AS (
    SELECT g.organization_id, g.grant_id
    FROM public.agent_session_grants AS g
    WHERE g.organization_id = p_organization_id AND g.status = 'issued'
      AND (p_organization_wide OR p_device_id IS NULL OR g.device_id = p_device_id)
      AND (p_organization_wide OR p_agent_id IS NULL OR g.agent_id = p_agent_id)
      AND (p_organization_wide OR p_grant_id IS NULL OR g.grant_id = p_grant_id)
      AND (p_organization_wide OR p_session_id IS NULL OR g.consumed_session_id = p_session_id)
    ORDER BY g.expires_at ASC, g.grant_id ASC
    LIMIT 500
    FOR UPDATE OF g
  ), updated AS (
    UPDATE public.agent_session_grants AS g
    SET status = CASE WHEN g.expires_at <= now_value THEN 'expired' ELSE 'revoked' END,
        expired_at = CASE WHEN g.expires_at <= now_value
          THEN GREATEST(now_value, COALESCE(p_revoked_at, now_value), g.expires_at) ELSE NULL END,
        revoked_at = CASE WHEN g.expires_at <= now_value THEN NULL
          ELSE GREATEST(now_value, COALESCE(p_revoked_at, now_value), g.issued_at) END
    FROM candidates
    WHERE g.organization_id = candidates.organization_id
      AND g.grant_id = candidates.grant_id
      AND g.status = 'issued'
    RETURNING g.status
  )
  SELECT COUNT(*) FILTER (WHERE status = 'expired'), COUNT(*) FILTER (WHERE status = 'revoked')
    INTO grant_expired_count, grant_revoked_count FROM updated;
  grant_count := grant_expired_count + grant_revoked_count;

  WITH candidates AS (
    SELECT s.organization_id, s.session_id
    FROM public.agent_sessions AS s
    WHERE s.organization_id = p_organization_id
      AND s.status IN ('challenge_pending','active','request_reserved','signing_intent','signed')
      AND (p_organization_wide OR p_device_id IS NULL OR s.device_id = p_device_id)
      AND (p_organization_wide OR p_agent_id IS NULL OR s.agent_id = p_agent_id)
      AND (p_organization_wide OR p_grant_id IS NULL OR s.grant_id = p_grant_id)
      AND (p_organization_wide OR p_session_id IS NULL OR s.session_id = p_session_id)
    ORDER BY s.expires_at ASC, s.session_id ASC
    LIMIT 500
    FOR UPDATE OF s
  ), updated AS (
    UPDATE public.agent_sessions AS s
    SET status = CASE WHEN s.expires_at <= now_value THEN 'expired' ELSE 'revoked' END,
        last_request_id = COALESCE(s.last_request_id, s.active_request_id),
        active_request_id = NULL,
        expired_at = CASE WHEN s.expires_at <= now_value
          THEN GREATEST(now_value, COALESCE(p_revoked_at, now_value), s.expires_at) ELSE NULL END,
        revoked_at = CASE WHEN s.expires_at <= now_value THEN NULL
          ELSE GREATEST(now_value, COALESCE(p_revoked_at, now_value), s.created_at) END
    FROM candidates
    WHERE s.organization_id = candidates.organization_id
      AND s.session_id = candidates.session_id
      AND s.status IN ('challenge_pending','active','request_reserved','signing_intent','signed')
    RETURNING s.status
  )
  SELECT COUNT(*) FILTER (WHERE status = 'expired'), COUNT(*) FILTER (WHERE status = 'revoked')
    INTO session_expired_count, session_revoked_count FROM updated;
  session_count := session_expired_count + session_revoked_count;
  RETURN jsonb_build_object(
    'counts', jsonb_build_array(grant_count, session_count),
    'expired', grant_expired_count + session_expired_count,
    'revoked', grant_revoked_count + session_revoked_count
  );
END;
$$;

CREATE FUNCTION public.agentpass_agent_session_grant_get(
  p_organization_id uuid,
  p_grant_id uuid
)
RETURNS SETOF public.agent_session_grants
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', CONSTRAINT = 'agent_session_authority_tenant';
  END IF;
  RETURN QUERY SELECT g.*
    FROM public.agent_session_grants AS g
    WHERE g.organization_id = p_organization_id AND g.grant_id = p_grant_id
    FOR SHARE;
END;
$$;

-- The grant row is locked before the current device/agent/control authority
-- is checked. Session INSERT remains the one-time grant-consumption trigger
-- boundary defined by migration 0019.
CREATE FUNCTION public.agentpass_agent_session_consume(
  p_organization_id uuid,
  p_grant_id uuid,
  p_device_id uuid,
  p_agent_id uuid,
  p_agent_kind text,
  p_adapter_id uuid,
  p_adapter_version text,
  p_worktree_binding_sha256 text,
  p_process_binding_policy_id text,
  p_scope_json jsonb,
  p_max_signatures integer,
  p_not_before timestamptz,
  p_expires_at timestamptz,
  p_control_sequence bigint,
  p_authority_generation bigint,
  p_issuer text,
  p_signer_key_id text,
  p_statement_hash text,
  p_grant_hash text,
  p_signature_base64url text,
  p_process_binding_sha256 text,
  p_ancestry_binding_sha256 text,
  p_session_id uuid,
  p_session_id_explicit boolean
)
RETURNS TABLE (
  replayed boolean,
  organization_id uuid, session_id uuid, grant_id uuid, device_id uuid, agent_id uuid,
  agent_kind text, adapter_id uuid, adapter_version text, process_binding_policy_id text,
  grant_hash text, process_binding_sha256 text, ancestry_binding_sha256 text,
  worktree_binding_sha256 text, control_sequence bigint, authority_generation bigint,
  max_signatures integer, used_signatures integer, reserved_signatures integer,
  status text, created_at timestamptz, not_before timestamptz, expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  grant_row public.agent_session_grants%ROWTYPE;
  session_row public.agent_sessions%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', CONSTRAINT = 'agent_session_authority_tenant';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:agent-session-grant:' || p_organization_id::text || ':' || p_grant_id::text, 0
  ));
  SELECT g.* INTO grant_row
    FROM public.agent_session_grants AS g
    WHERE g.organization_id = p_organization_id AND g.grant_id = p_grant_id AND g.device_id = p_device_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'agent_session_authority_grant_not_found';
  END IF;
  IF grant_row.device_id IS DISTINCT FROM p_device_id
     OR grant_row.agent_id IS DISTINCT FROM p_agent_id
     OR grant_row.agent_kind IS DISTINCT FROM p_agent_kind
     OR grant_row.adapter_id IS DISTINCT FROM p_adapter_id
     OR grant_row.adapter_version IS DISTINCT FROM p_adapter_version
     OR grant_row.worktree_binding_sha256 IS DISTINCT FROM p_worktree_binding_sha256
     OR grant_row.process_binding_policy_id IS DISTINCT FROM p_process_binding_policy_id
     OR grant_row.scope_json IS DISTINCT FROM p_scope_json
     OR grant_row.max_signatures IS DISTINCT FROM p_max_signatures
     OR grant_row.not_before IS DISTINCT FROM p_not_before
     OR grant_row.expires_at IS DISTINCT FROM p_expires_at
     OR grant_row.control_sequence IS DISTINCT FROM p_control_sequence
     OR grant_row.authority_generation IS DISTINCT FROM p_authority_generation
     OR grant_row.issuer IS DISTINCT FROM p_issuer
     OR grant_row.signer_key_id IS DISTINCT FROM p_signer_key_id
     OR grant_row.statement_hash IS DISTINCT FROM p_statement_hash
     OR grant_row.grant_hash IS DISTINCT FROM p_grant_hash
     OR grant_row.signature_base64url IS DISTINCT FROM p_signature_base64url THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'agent_session_authority_grant_conflict';
  END IF;

  IF grant_row.status = 'consumed' THEN
    SELECT s.* INTO session_row
      FROM public.agent_sessions AS s
      WHERE s.organization_id = p_organization_id
        AND s.session_id = grant_row.consumed_session_id
        AND s.grant_id = p_grant_id
      FOR SHARE;
    IF NOT FOUND OR session_row.status NOT IN ('challenge_pending','active','request_reserved','signing_intent','signed') THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_session_unavailable';
    END IF;
    IF now_value >= session_row.expires_at THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_session_expired';
    END IF;
    IF session_row.process_binding_sha256 IS DISTINCT FROM p_process_binding_sha256
       OR session_row.ancestry_binding_sha256 IS DISTINCT FROM p_ancestry_binding_sha256
       OR (p_session_id_explicit AND p_session_id IS DISTINCT FROM session_row.session_id) THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_binding_conflict';
    END IF;
    RETURN QUERY SELECT true,
      session_row.organization_id, session_row.session_id, session_row.grant_id,
      session_row.device_id, session_row.agent_id, session_row.agent_kind,
      session_row.adapter_id, session_row.adapter_version,
      session_row.process_binding_policy_id, session_row.grant_hash,
      session_row.process_binding_sha256, session_row.ancestry_binding_sha256,
      session_row.worktree_binding_sha256, session_row.control_sequence,
      session_row.authority_generation, session_row.max_signatures,
      session_row.used_signatures, session_row.reserved_signatures,
      session_row.status, session_row.created_at, session_row.not_before,
      session_row.expires_at;
    RETURN;
  END IF;
  IF grant_row.status <> 'issued' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_unavailable';
  END IF;
  IF now_value < grant_row.not_before THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_not_yet_valid';
  END IF;
  IF now_value >= grant_row.expires_at THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_expired';
  END IF;
  IF p_session_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', CONSTRAINT = 'agent_session_authority_session_id_required';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.agents AS a
    JOIN public.devices AS d ON d.organization_id = a.organization_id AND d.id = a.device_id
    JOIN public.control_plane_authority_generations AS generation
      ON generation.organization_id = a.organization_id
     AND generation.generation = grant_row.authority_generation
     AND generation.superseded_at IS NULL
    JOIN public.device_control_plane_state AS state
      ON state.organization_id = d.organization_id AND state.device_id = d.id
     AND state.desired_generation = generation.generation
     AND state.observed_generation = generation.generation
     AND state.refresh_state = 'applied'
    JOIN public.bundle_heads AS head
      ON head.organization_id = d.organization_id AND head.device_id = d.id
     AND head.format_epoch = 2 AND head.sequence = grant_row.control_sequence
     AND head.expires_at > now_value
    JOIN public.control_bundle_statements AS statement
      ON statement.organization_id = head.organization_id AND statement.device_id = head.device_id
     AND statement.format_epoch = head.format_epoch AND statement.sequence = head.sequence
     AND statement.statement_hash = head.statement_hash
     AND statement.authority_generation = generation.generation
    JOIN public.bundle_acknowledgements AS ack
      ON ack.organization_id = head.organization_id AND ack.device_id = head.device_id
     AND ack.format_epoch = head.format_epoch AND ack.sequence = head.sequence
     AND ack.statement_hash = head.statement_hash AND ack.status = 'applied'
    WHERE a.organization_id = p_organization_id AND a.id = p_agent_id AND a.device_id = p_device_id
      AND a.kind = p_agent_kind AND a.status = 'active' AND d.status = 'active'
      AND NOT EXISTS (
        SELECT 1 FROM public.revocations AS revocation
        WHERE revocation.organization_id = a.organization_id AND revocation.status = 'active'
          AND (revocation.target_type = 'organization'
            OR (revocation.target_type = 'device' AND revocation.target_id = d.id)
            OR (revocation.target_type = 'agent' AND revocation.target_id = a.id))
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_unavailable';
  END IF;

  INSERT INTO public.agent_sessions (
    organization_id, session_id, grant_id, device_id, agent_id, agent_kind, adapter_id,
    adapter_version, process_binding_policy_id, grant_hash, process_binding_sha256,
    ancestry_binding_sha256, worktree_binding_sha256, control_sequence, authority_generation,
    max_signatures, used_signatures, reserved_signatures, status, created_at, not_before, expires_at
  ) VALUES (
    p_organization_id, p_session_id, grant_row.grant_id, grant_row.device_id, grant_row.agent_id,
    grant_row.agent_kind, grant_row.adapter_id, grant_row.adapter_version,
    grant_row.process_binding_policy_id, grant_row.grant_hash, p_process_binding_sha256,
    p_ancestry_binding_sha256, grant_row.worktree_binding_sha256, grant_row.control_sequence,
    grant_row.authority_generation, grant_row.max_signatures, 0, 0, 'challenge_pending',
    now_value, grant_row.not_before, grant_row.expires_at
  );
  SELECT s.* INTO session_row
    FROM public.agent_sessions AS s
    WHERE s.organization_id = p_organization_id AND s.session_id = p_session_id
    FOR SHARE;
  RETURN QUERY SELECT false,
    session_row.organization_id, session_row.session_id, session_row.grant_id,
    session_row.device_id, session_row.agent_id, session_row.agent_kind,
    session_row.adapter_id, session_row.adapter_version,
    session_row.process_binding_policy_id, session_row.grant_hash,
    session_row.process_binding_sha256, session_row.ancestry_binding_sha256,
    session_row.worktree_binding_sha256, session_row.control_sequence,
    session_row.authority_generation, session_row.max_signatures,
    session_row.used_signatures, session_row.reserved_signatures,
    session_row.status, session_row.created_at, session_row.not_before,
    session_row.expires_at;
END;
$$;

-- No online service identity receives direct table visibility or mutation.
REVOKE ALL ON TABLE public.agent_session_grants, public.agent_sessions
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT ON TABLE public.agent_session_grants, public.agent_sessions TO agentpass_backup;

DO $$
DECLARE
  routine_signature text;
BEGIN
  FOREACH routine_signature IN ARRAY ARRAY[
    'agentpass_agent_session_grant_issue(uuid,uuid,uuid,uuid,text,uuid,text,text,text,jsonb,integer,timestamptz,timestamptz,bigint,bigint,text,text,text,text,text,timestamptz,uuid)',
    'agentpass_agent_session_grant_get(uuid,uuid)',
    'agentpass_agent_session_consume(uuid,uuid,uuid,uuid,text,uuid,text,text,text,jsonb,integer,timestamptz,timestamptz,bigint,bigint,text,text,text,text,text,text,text,uuid,boolean)',
    'agentpass_agent_session_lifecycle_expire_due(uuid,integer,timestamptz)',
    'agentpass_agent_session_lifecycle_revoke(uuid,uuid,uuid,uuid,uuid,boolean,timestamptz)'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance', routine_signature);
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO agentpass_app', routine_signature);
  END LOOP;
END
$$;

COMMENT ON TABLE public.agent_session_grants IS
  'Function-owned Agent Session Grant authority; online roles have no direct table privileges.';
COMMENT ON TABLE public.agent_sessions IS
  'Function-owned Agent Session Lease authority; online roles have no direct table privileges.';

COMMIT;
