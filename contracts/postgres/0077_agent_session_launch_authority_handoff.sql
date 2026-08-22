BEGIN;

-- The signed launch authority remains transient. This relation records only
-- the public binding and its one-use return marker; it never stores the Grant,
-- raw nonce, process binding, or any other authority-bearing secret.
CREATE TABLE public.agent_session_launch_authority_handoffs (
  organization_id uuid NOT NULL,
  session_id uuid NOT NULL,
  request_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  device_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  agent_kind text NOT NULL
    CHECK (agent_kind IN ('claude-code', 'cursor')),
  adapter_id uuid NOT NULL,
  adapter_version text NOT NULL
    CHECK (adapter_version ~ '^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$'),
  worktree_binding_sha256 bytea NOT NULL
    CHECK (octet_length(worktree_binding_sha256) = 32),
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  control_sequence bigint NOT NULL CHECK (control_sequence > 0),
  authority_generation bigint NOT NULL CHECK (authority_generation > 0),
  nonce_sha256 bytea NOT NULL
    CHECK (octet_length(nonce_sha256) = 32),
  lease_sha256 bytea NOT NULL
    CHECK (octet_length(lease_sha256) = 32),
  grant_hash text NOT NULL
    CHECK (grant_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, session_id),
  UNIQUE (organization_id, request_id),
  UNIQUE (organization_id, grant_id),
  FOREIGN KEY (organization_id, session_id, grant_id, device_id)
    REFERENCES public.agent_sessions(organization_id, session_id, grant_id, device_id),
  FOREIGN KEY (organization_id, grant_id, device_id, agent_id, grant_hash)
    REFERENCES public.agent_session_grants(organization_id, grant_id, device_id, agent_id, grant_hash),
  FOREIGN KEY (organization_id, agent_id, device_id)
    REFERENCES public.agents(organization_id, id, device_id),
  FOREIGN KEY (organization_id, authority_generation)
    REFERENCES public.control_plane_authority_generations(organization_id, generation),
  CHECK (expires_at > not_before)
);

-- A handoff marker is historical evidence. It is insert-only even for the
-- migration owner, so replay cannot rewrite the binding that was returned.
CREATE FUNCTION public.agentpass_guard_agent_session_launch_authority_handoff_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session launch authority handoffs are append-only',
      CONSTRAINT = 'agent_session_launch_authority_handoffs_append_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER agent_session_launch_authority_handoffs_append_only
  BEFORE UPDATE OR DELETE ON public.agent_session_launch_authority_handoffs
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_guard_agent_session_launch_authority_handoff_append_only();

-- This is the only online mutation boundary for launch authority handoffs.
-- The caller supplies only typed public bindings and SHA-256 digests. The
-- function does not trust those fields: it locks and rechecks the exact
-- Session/Grant/Device/Agent/current-generation authority before inserting.
CREATE FUNCTION public.agentpass_agent_launch_authority_handoff(
  p_request_id uuid,
  p_grant_id uuid,
  p_organization_id uuid,
  p_device_id uuid,
  p_agent_id uuid,
  p_agent_kind text,
  p_adapter_id uuid,
  p_adapter_version text,
  p_session_id uuid,
  p_worktree_binding_sha256 bytea,
  p_not_before timestamptz,
  p_expires_at timestamptz,
  p_control_sequence bigint,
  p_authority_generation bigint,
  p_nonce_sha256 bytea,
  p_lease_sha256 bytea,
  p_grant_hash bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  session_row public.agent_sessions%ROWTYPE;
  grant_row public.agent_session_grants%ROWTYPE;
  now_value timestamptz := clock_timestamp();
  inserted integer;
BEGIN
  -- The transaction-bound GUC is the only tenant context accepted by this
  -- function. It is set by the repository immediately before this call and
  -- is never derived from a row selected by the function.
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION USING
      ERRCODE = 'insufficient_privilege',
      MESSAGE = 'agent session launch authority tenant context is invalid';
  END IF;

  IF p_request_id IS NULL OR p_grant_id IS NULL OR p_device_id IS NULL
     OR p_agent_id IS NULL OR p_adapter_id IS NULL OR p_session_id IS NULL
     OR p_agent_kind IS NULL
     OR p_agent_kind NOT IN ('claude-code', 'cursor')
     OR p_adapter_version IS NULL
     OR p_adapter_version !~ '^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$'
     OR p_worktree_binding_sha256 IS NULL
     OR octet_length(p_worktree_binding_sha256) <> 32
     OR p_not_before IS NULL OR p_expires_at IS NULL
     OR p_control_sequence IS NULL OR p_control_sequence <= 0
     OR p_authority_generation IS NULL OR p_authority_generation <= 0
     OR p_nonce_sha256 IS NULL OR octet_length(p_nonce_sha256) <> 32
     OR p_lease_sha256 IS NULL OR octet_length(p_lease_sha256) <> 32
     OR p_grant_hash IS NULL OR octet_length(p_grant_hash) <> 32
     OR p_expires_at <= p_not_before THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session launch authority handoff binding is invalid';
  END IF;

  -- Serialize this authority read with control-plane revocations. Keep the
  -- key derivation byte-for-byte compatible with the control-plane SQL and
  -- JavaScript repository so a revocation cannot commit between the active
  -- revocation check and the handoff marker insert.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:organization:' || p_organization_id::text, 0
  ));

  -- This is intentionally the same authority projection used by the Session
  -- binder. FOR SHARE locks every mutable authority row participating in the
  -- decision before the one-use marker is attempted.
  SELECT s.*
    INTO session_row
  FROM public.agent_sessions AS s
  JOIN public.devices AS d
    ON d.organization_id = s.organization_id AND d.id = s.device_id
  JOIN public.agents AS a
    ON a.organization_id = s.organization_id AND a.id = s.agent_id
  JOIN public.agent_session_grants AS gr
    ON gr.organization_id = s.organization_id
   AND gr.grant_id = s.grant_id
   AND gr.device_id = s.device_id
   AND gr.agent_id = s.agent_id
   AND gr.grant_hash = s.grant_hash
   AND gr.status = 'consumed'
   AND gr.consumed_session_id = s.session_id
  JOIN public.control_plane_authority_generations AS authority
    ON authority.organization_id = s.organization_id
   AND authority.generation = s.authority_generation
   AND authority.superseded_at IS NULL
  WHERE s.organization_id = p_organization_id
    AND s.session_id = p_session_id
    AND s.grant_id = p_grant_id
    AND s.device_id = p_device_id
    AND s.agent_id = p_agent_id
    AND s.status IN ('active', 'signed', 'request_reserved', 'signing_intent')
    AND s.max_signatures = 2
    AND s.max_signatures > s.used_signatures + s.reserved_signatures
    AND s.not_before <= now_value
    AND s.expires_at > now_value
    AND s.authority_generation = p_authority_generation
    AND d.status = 'active'
    AND a.status = 'active'
    AND NOT EXISTS (
      SELECT 1
      FROM public.revocations AS r
      WHERE r.organization_id = s.organization_id
        AND r.status = 'active'
        AND (
          r.target_type = 'organization'
          OR (r.target_type = 'device' AND r.target_id = s.device_id)
          OR (r.target_type = 'agent' AND r.target_id = s.agent_id)
        )
    )
  FOR SHARE OF s, d, a, gr, authority;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session launch authority is unavailable';
  END IF;

  -- PostgreSQL does not allow an anonymous RECORD target as one item in a
  -- multi-target INTO list. Fetch the already-locked grant separately so the
  -- typed row variables remain compatible with every supported PostgreSQL
  -- version while preserving the same transaction-bound authority snapshot.
  SELECT gr.*
    INTO grant_row
  FROM public.agent_session_grants AS gr
  WHERE gr.organization_id = p_organization_id
    AND gr.grant_id = p_grant_id
    AND gr.device_id = p_device_id
    AND gr.agent_id = p_agent_id
    AND gr.status = 'consumed'
    AND gr.consumed_session_id = p_session_id
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session launch authority grant is unavailable';
  END IF;

  IF session_row.agent_kind IS DISTINCT FROM p_agent_kind
     OR grant_row.agent_kind IS DISTINCT FROM p_agent_kind
     OR session_row.adapter_id IS DISTINCT FROM p_adapter_id
     OR grant_row.adapter_id IS DISTINCT FROM p_adapter_id
     OR session_row.adapter_version IS DISTINCT FROM p_adapter_version
     OR grant_row.adapter_version IS DISTINCT FROM p_adapter_version
     OR decode(session_row.worktree_binding_sha256, 'hex') IS DISTINCT FROM p_worktree_binding_sha256
     OR decode(grant_row.worktree_binding_sha256, 'hex') IS DISTINCT FROM p_worktree_binding_sha256
     OR session_row.not_before IS DISTINCT FROM p_not_before
     OR grant_row.not_before IS DISTINCT FROM p_not_before
     OR session_row.expires_at IS DISTINCT FROM p_expires_at
     OR grant_row.expires_at IS DISTINCT FROM p_expires_at
     OR session_row.control_sequence IS DISTINCT FROM p_control_sequence
     OR grant_row.control_sequence IS DISTINCT FROM p_control_sequence
     OR session_row.authority_generation IS DISTINCT FROM p_authority_generation
     OR grant_row.authority_generation IS DISTINCT FROM p_authority_generation
     OR decode(grant_row.grant_hash, 'hex') IS DISTINCT FROM p_grant_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session launch authority binding conflicts with committed state';
  END IF;

  INSERT INTO public.agent_session_launch_authority_handoffs (
    organization_id, session_id, request_id, grant_id, device_id, agent_id,
    agent_kind, adapter_id, adapter_version, worktree_binding_sha256,
    not_before, expires_at, control_sequence, authority_generation,
    nonce_sha256, lease_sha256, grant_hash, created_at
  ) VALUES (
    p_organization_id, p_session_id, p_request_id, p_grant_id, p_device_id, p_agent_id,
    p_agent_kind, p_adapter_id, p_adapter_version, p_worktree_binding_sha256,
    p_not_before, p_expires_at, p_control_sequence, p_authority_generation,
    p_nonce_sha256, p_lease_sha256, encode(p_grant_hash, 'hex'), now_value
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;

  IF inserted = 1 THEN
    RETURN jsonb_build_object('state', 'issued');
  END IF;
  RETURN jsonb_build_object('state', 'already_returned');
END;
$$;

ALTER TABLE public.agent_session_launch_authority_handoffs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_session_launch_authority_handoffs FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_session_launch_authority_handoffs_tenant_select
  ON public.agent_session_launch_authority_handoffs FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY agent_session_launch_authority_handoffs_migrator_authority
  ON public.agent_session_launch_authority_handoffs FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY agent_session_launch_authority_handoffs_backup_select
  ON public.agent_session_launch_authority_handoffs FOR SELECT TO agentpass_backup
  USING (true);

-- The application can call only the atomic boundary. The marker and all
-- helper/trigger functions remain unavailable as direct online DML paths.
REVOKE ALL ON TABLE public.agent_session_launch_authority_handoffs
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT ON TABLE public.agent_session_launch_authority_handoffs TO agentpass_backup;

REVOKE ALL ON FUNCTION public.agentpass_agent_launch_authority_handoff(
  uuid, uuid, uuid, uuid, uuid, text, uuid, text, uuid, bytea,
  timestamptz, timestamptz, bigint, bigint, bytea, bytea, bytea
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_agent_launch_authority_handoff(
  uuid, uuid, uuid, uuid, uuid, text, uuid, text, uuid, bytea,
  timestamptz, timestamptz, bigint, bigint, bytea, bytea, bytea
) TO agentpass_app;

REVOKE ALL ON FUNCTION public.agentpass_guard_agent_session_launch_authority_handoff_append_only()
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;

COMMENT ON TABLE public.agent_session_launch_authority_handoffs IS
  'Append-only, tenant-qualified, secret-free one-use markers for Agent launch authority handoffs.';

COMMIT;
