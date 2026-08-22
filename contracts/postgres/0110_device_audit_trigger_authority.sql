BEGIN;

-- Device audit head advancement is trigger-owned state.  The online
-- application may insert an event, but must not inherit direct privileges on
-- the head/gap projections.  Run the trigger under the migration owner so
-- FORCE RLS and projection ACLs remain a real authority boundary.
ALTER FUNCTION public.agentpass_record_device_audit_head()
  OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_record_device_audit_head()
  SECURITY DEFINER;
ALTER FUNCTION public.agentpass_record_device_audit_head()
  SET search_path = pg_catalog, public;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_record_device_audit_head()
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;

ALTER FUNCTION public.agentpass_record_device_audit_export_entry()
  OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_record_device_audit_export_entry()
  SECURITY DEFINER;
ALTER FUNCTION public.agentpass_record_device_audit_export_entry()
  SET search_path = pg_catalog, public;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_record_device_audit_export_entry()
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;

-- Export projections share the device-audit transaction context. Replace the
-- legacy session-setting policies so the trigger remains tenant-bound after
-- the device authorization boundary is established.
DROP POLICY IF EXISTS device_audit_export_entries_tenant_select ON public.device_audit_export_entries;
DROP POLICY IF EXISTS device_audit_export_entries_tenant_insert ON public.device_audit_export_entries;
CREATE POLICY device_audit_export_entries_tenant_select
  ON public.device_audit_export_entries FOR SELECT
  USING (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_export_entries_tenant_insert
  ON public.device_audit_export_entries FOR INSERT
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());

DROP POLICY IF EXISTS device_audit_export_heads_tenant_select ON public.device_audit_export_heads;
DROP POLICY IF EXISTS device_audit_export_heads_tenant_insert ON public.device_audit_export_heads;
DROP POLICY IF EXISTS device_audit_export_heads_tenant_update ON public.device_audit_export_heads;
CREATE POLICY device_audit_export_heads_tenant_select
  ON public.device_audit_export_heads FOR SELECT
  USING (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_export_heads_tenant_insert
  ON public.device_audit_export_heads FOR INSERT
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_export_heads_tenant_update
  ON public.device_audit_export_heads FOR UPDATE
  USING (organization_id = public.agentpass_device_audit_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());

DROP POLICY IF EXISTS device_audit_export_entries_migrator_authority ON public.device_audit_export_entries;
CREATE POLICY device_audit_export_entries_migrator_authority
  ON public.device_audit_export_entries FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS device_audit_export_heads_migrator_authority ON public.device_audit_export_heads;
CREATE POLICY device_audit_export_heads_migrator_authority
  ON public.device_audit_export_heads FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);

ALTER FUNCTION public.agentpass_agent_session_grant_get(uuid, uuid) VOLATILE;

-- The authority-generation column was added after the original session row
-- layout. Re-declare the consume boundary with an explicit projection so
-- composite expansion cannot silently shift bigint/integer fields.
CREATE OR REPLACE FUNCTION public.agentpass_agent_session_consume(
  p_organization_id uuid, p_grant_id uuid, p_device_id uuid, p_agent_id uuid,
  p_agent_kind text, p_adapter_id uuid, p_adapter_version text,
  p_worktree_binding_sha256 text, p_process_binding_policy_id text,
  p_scope_json jsonb, p_max_signatures integer, p_not_before timestamptz,
  p_expires_at timestamptz, p_control_sequence bigint,
  p_authority_generation bigint, p_issuer text, p_signer_key_id text,
  p_statement_hash text, p_grant_hash text, p_signature_base64url text,
  p_process_binding_sha256 text, p_ancestry_binding_sha256 text,
  p_session_id uuid, p_session_id_explicit boolean
)
RETURNS TABLE (
  replayed boolean, organization_id uuid, session_id uuid, grant_id uuid,
  device_id uuid, agent_id uuid, agent_kind text, adapter_id uuid,
  adapter_version text, process_binding_policy_id text, grant_hash text,
  process_binding_sha256 text, ancestry_binding_sha256 text,
  worktree_binding_sha256 text, control_sequence bigint,
  authority_generation bigint, max_signatures integer, used_signatures integer,
  reserved_signatures integer, status text, created_at timestamptz,
  not_before timestamptz, expires_at timestamptz
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
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
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:agent-session-grant:' || p_organization_id::text || ':' || p_grant_id::text, 0));
  SELECT g.* INTO grant_row FROM public.agent_session_grants AS g
   WHERE g.organization_id = p_organization_id AND g.grant_id = p_grant_id AND g.device_id = p_device_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'agent_session_authority_grant_not_found'; END IF;
  IF grant_row.device_id IS DISTINCT FROM p_device_id OR grant_row.agent_id IS DISTINCT FROM p_agent_id
     OR grant_row.agent_kind IS DISTINCT FROM p_agent_kind OR grant_row.adapter_id IS DISTINCT FROM p_adapter_id
     OR grant_row.adapter_version IS DISTINCT FROM p_adapter_version
     OR grant_row.worktree_binding_sha256 IS DISTINCT FROM p_worktree_binding_sha256
     OR grant_row.process_binding_policy_id IS DISTINCT FROM p_process_binding_policy_id
     OR grant_row.scope_json IS DISTINCT FROM p_scope_json OR grant_row.max_signatures IS DISTINCT FROM p_max_signatures
     OR grant_row.not_before IS DISTINCT FROM p_not_before OR grant_row.expires_at IS DISTINCT FROM p_expires_at
     OR grant_row.control_sequence IS DISTINCT FROM p_control_sequence
     OR grant_row.authority_generation IS DISTINCT FROM p_authority_generation OR grant_row.issuer IS DISTINCT FROM p_issuer
     OR grant_row.signer_key_id IS DISTINCT FROM p_signer_key_id OR grant_row.statement_hash IS DISTINCT FROM p_statement_hash
     OR grant_row.grant_hash IS DISTINCT FROM p_grant_hash OR grant_row.signature_base64url IS DISTINCT FROM p_signature_base64url
  THEN RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'agent_session_authority_grant_conflict'; END IF;
  IF grant_row.status = 'consumed' THEN
    SELECT s.* INTO session_row FROM public.agent_sessions AS s
     WHERE s.organization_id = p_organization_id AND s.session_id = grant_row.consumed_session_id AND s.grant_id = p_grant_id FOR SHARE;
    IF NOT FOUND OR session_row.status NOT IN ('challenge_pending','active','request_reserved','signing_intent','signed') THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_session_unavailable';
    END IF;
    IF now_value >= session_row.expires_at THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_session_expired'; END IF;
    IF session_row.process_binding_sha256 IS DISTINCT FROM p_process_binding_sha256
       OR session_row.ancestry_binding_sha256 IS DISTINCT FROM p_ancestry_binding_sha256
       OR (p_session_id_explicit AND p_session_id IS DISTINCT FROM session_row.session_id)
    THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_binding_conflict'; END IF;
    RETURN QUERY SELECT true, session_row.organization_id, session_row.session_id, session_row.grant_id,
      session_row.device_id, session_row.agent_id, session_row.agent_kind, session_row.adapter_id,
      session_row.adapter_version, session_row.process_binding_policy_id, session_row.grant_hash,
      session_row.process_binding_sha256, session_row.ancestry_binding_sha256, session_row.worktree_binding_sha256,
      session_row.control_sequence, session_row.authority_generation, session_row.max_signatures,
      session_row.used_signatures, session_row.reserved_signatures, session_row.status, session_row.created_at,
      session_row.not_before, session_row.expires_at;
    RETURN;
  END IF;
  IF grant_row.status <> 'issued' THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_unavailable'; END IF;
  IF now_value < grant_row.not_before THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_not_yet_valid'; END IF;
  IF now_value >= grant_row.expires_at THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_expired'; END IF;
  IF p_session_id IS NULL THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', CONSTRAINT = 'agent_session_authority_session_id_required'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.agents AS a
    JOIN public.devices AS d ON d.organization_id = a.organization_id AND d.id = a.device_id
    JOIN public.control_plane_authority_generations AS generation ON generation.organization_id = a.organization_id
      AND generation.generation = grant_row.authority_generation AND generation.superseded_at IS NULL
    JOIN public.device_control_plane_state AS state ON state.organization_id = d.organization_id AND state.device_id = d.id
      AND state.desired_generation = generation.generation AND state.observed_generation = generation.generation AND state.refresh_state = 'applied'
    JOIN public.bundle_heads AS head ON head.organization_id = d.organization_id AND head.device_id = d.id
      AND head.format_epoch = 2 AND head.sequence = grant_row.control_sequence AND head.expires_at > now_value
    JOIN public.control_bundle_statements AS statement ON statement.organization_id = head.organization_id AND statement.device_id = head.device_id
      AND statement.format_epoch = head.format_epoch AND statement.sequence = head.sequence AND statement.statement_hash = head.statement_hash
      AND statement.authority_generation = generation.generation
    JOIN public.bundle_acknowledgements AS ack ON ack.organization_id = head.organization_id AND ack.device_id = head.device_id
      AND ack.format_epoch = head.format_epoch AND ack.sequence = head.sequence AND ack.statement_hash = head.statement_hash AND ack.status = 'applied'
    WHERE a.organization_id = p_organization_id AND a.id = p_agent_id AND a.device_id = p_device_id
      AND a.kind = p_agent_kind AND a.status = 'active' AND d.status = 'active'
      AND NOT EXISTS (SELECT 1 FROM public.revocations AS revocation WHERE revocation.organization_id = a.organization_id
        AND revocation.status = 'active' AND (revocation.target_type = 'organization'
          OR (revocation.target_type = 'device' AND revocation.target_id = d.id) OR (revocation.target_type = 'agent' AND revocation.target_id = a.id)))
  ) THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'agent_session_authority_grant_unavailable'; END IF;
  INSERT INTO public.agent_sessions (organization_id, session_id, grant_id, device_id, agent_id, agent_kind, adapter_id,
    adapter_version, process_binding_policy_id, grant_hash, process_binding_sha256, ancestry_binding_sha256,
    worktree_binding_sha256, control_sequence, authority_generation, max_signatures, used_signatures, reserved_signatures,
    status, created_at, not_before, expires_at)
  VALUES (p_organization_id, p_session_id, grant_row.grant_id, grant_row.device_id, grant_row.agent_id, grant_row.agent_kind,
    grant_row.adapter_id, grant_row.adapter_version, grant_row.process_binding_policy_id, grant_row.grant_hash,
    p_process_binding_sha256, p_ancestry_binding_sha256, grant_row.worktree_binding_sha256, grant_row.control_sequence,
    grant_row.authority_generation, grant_row.max_signatures, 0, 0, 'challenge_pending', now_value, grant_row.not_before, grant_row.expires_at);
  SELECT s.* INTO session_row FROM public.agent_sessions AS s WHERE s.organization_id = p_organization_id AND s.session_id = p_session_id FOR SHARE;
  RETURN QUERY SELECT false, session_row.organization_id, session_row.session_id, session_row.grant_id,
    session_row.device_id, session_row.agent_id, session_row.agent_kind, session_row.adapter_id, session_row.adapter_version,
    session_row.process_binding_policy_id, session_row.grant_hash, session_row.process_binding_sha256,
    session_row.ancestry_binding_sha256, session_row.worktree_binding_sha256, session_row.control_sequence,
    session_row.authority_generation, session_row.max_signatures, session_row.used_signatures, session_row.reserved_signatures,
    session_row.status, session_row.created_at, session_row.not_before, session_row.expires_at;
END;
$$;

COMMIT;
