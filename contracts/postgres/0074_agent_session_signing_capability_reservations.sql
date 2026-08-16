BEGIN;

-- F2b function-owned issuance ledger. agent_sessions remains the sole
-- signature-budget/request-lifecycle authority. This table retains the live
-- signed public response only so a lost response can be replayed without a
-- second key operation.
ALTER TABLE public.capabilities
  ADD COLUMN issued_by_session_id uuid,
  DROP CONSTRAINT capabilities_active_membership_authority_complete,
  ADD CONSTRAINT capabilities_issued_by_session_fk
    FOREIGN KEY (organization_id, issued_by_session_id)
    REFERENCES public.agent_sessions(organization_id, session_id),
  ADD CONSTRAINT capabilities_active_issuer_authority_complete
    CHECK (
      revoked_at IS NOT NULL
      OR (issued_by_member_id IS NOT NULL AND issued_membership_version IS NOT NULL
        AND issued_by_session_id IS NULL)
      OR (issued_by_member_id IS NULL AND issued_membership_version IS NULL
        AND issued_by_session_id IS NOT NULL)
    );

CREATE INDEX capabilities_issued_by_session_active_lookup
  ON public.capabilities (organization_id, issued_by_session_id, id)
  WHERE issued_by_session_id IS NOT NULL AND revoked_at IS NULL;

-- Every capability producer shares this allocator. The trigger below advances
-- it for legacy/human issuance; the reservation function advances it before a
-- Session Capability statement is constructed.
CREATE TABLE public.agent_capability_sequence_heads (
  organization_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, agent_id),
  FOREIGN KEY (organization_id, agent_id)
    REFERENCES public.agents(organization_id, id)
);

INSERT INTO public.agent_capability_sequence_heads (organization_id, agent_id, sequence)
SELECT organization_id, agent_id, max(sequence)
FROM public.capabilities
GROUP BY organization_id, agent_id;

CREATE TABLE public.agent_session_signing_capability_reservations (
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  reservation_id uuid NOT NULL,
  request_id uuid NOT NULL,
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  capability_id uuid NOT NULL,
  session_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  device_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  grant_hash text NOT NULL CHECK (grant_hash ~ '^[0-9a-f]{64}$'),
  sequence bigint NOT NULL CHECK (sequence > 0),
  operation text NOT NULL CHECK (operation = 'git.commit.sign'),
  key_purpose text NOT NULL CHECK (key_purpose = 'git.commit.sign'),
  key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  key_version bigint NOT NULL CHECK (key_version > 0),
  algorithm text NOT NULL CHECK (algorithm = 'ed25519'),
  scope_json jsonb NOT NULL CHECK (public.agentpass_public_scope_json_valid(scope_json)),
  control_sequence bigint NOT NULL CHECK (control_sequence > 0),
  authority_generation bigint NOT NULL CHECK (authority_generation > 0),
  claim_token_hash bytea NOT NULL CHECK (octet_length(claim_token_hash) = 32),
  claim_expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('reserved', 'completed', 'outcome_unknown', 'revoked', 'expired')),
  capability_statement_hash bytea CHECK (capability_statement_hash IS NULL OR octet_length(capability_statement_hash) = 32),
  capability_signature_hash bytea CHECK (capability_signature_hash IS NULL OR octet_length(capability_signature_hash) = 32),
  planned_provider_operation_id text NOT NULL CHECK (
    planned_provider_operation_id ~ '^managed-signer-v1-[0-9a-f]{64}$'
  ),
  provider_request_digest bytea NOT NULL CHECK (octet_length(provider_request_digest) = 32),
  provider_bytes_length integer NOT NULL CHECK (provider_bytes_length > 0 AND provider_bytes_length <= 1048576),
  provider_operation_id text CHECK (
    provider_operation_id IS NULL OR provider_operation_id ~ '^managed-signer-v1-[0-9a-f]{64}$'
  ),
  signing_bytes_digest bytea CHECK (signing_bytes_digest IS NULL OR octet_length(signing_bytes_digest) = 32),
  response_json jsonb,
  uncertain_reason text CHECK (uncertain_reason IS NULL OR uncertain_reason IN (
    'signer_failure', 'signer_output_invalid', 'commit_response_lost', 'commit_failure', 'claim_expired'
  )),
  issued_at timestamptz NOT NULL,
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  completed_at timestamptz,
  outcome_unknown_at timestamptz,
  revoked_at timestamptz,
  expired_at timestamptz,
  PRIMARY KEY (organization_id, reservation_id),
  UNIQUE (organization_id, request_id),
  UNIQUE (organization_id, capability_id),
  UNIQUE (organization_id, agent_id, sequence),
  UNIQUE (organization_id, session_id, sequence),
  FOREIGN KEY (organization_id, session_id, grant_id, device_id)
    REFERENCES public.agent_sessions(organization_id, session_id, grant_id, device_id),
  FOREIGN KEY (organization_id, grant_id, device_id, agent_id, grant_hash)
    REFERENCES public.agent_session_grants(organization_id, grant_id, device_id, agent_id, grant_hash),
  FOREIGN KEY (organization_id, agent_id, device_id)
    REFERENCES public.agents(organization_id, id, device_id),
  FOREIGN KEY (organization_id, authority_generation)
    REFERENCES public.control_plane_authority_generations(organization_id, generation),
  FOREIGN KEY (key_purpose, key_id, key_version)
    REFERENCES public.managed_signer_keys(purpose, key_id, key_version),
  FOREIGN KEY (key_purpose, provider_operation_id)
    REFERENCES public.managed_signer_provider_operations(purpose, operation_id),
  CHECK (issued_at = not_before),
  CHECK (expires_at > not_before AND expires_at - issued_at <= interval '15 minutes'),
  CHECK (claim_expires_at > created_at AND claim_expires_at <= expires_at),
  CHECK (updated_at >= created_at),
  CHECK (
    (state = 'reserved' AND capability_statement_hash IS NOT NULL
      AND capability_signature_hash IS NULL AND provider_operation_id IS NULL
      AND signing_bytes_digest IS NOT NULL AND response_json IS NULL
      AND uncertain_reason IS NULL AND completed_at IS NULL
      AND outcome_unknown_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL)
    OR (state = 'completed' AND capability_statement_hash IS NOT NULL
      AND capability_signature_hash IS NOT NULL AND provider_operation_id IS NOT NULL
      AND signing_bytes_digest IS NOT NULL AND jsonb_typeof(response_json) = 'object'
      AND uncertain_reason IS NULL AND completed_at IS NOT NULL
      AND outcome_unknown_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL)
    OR (state = 'outcome_unknown' AND capability_statement_hash IS NOT NULL
      AND capability_signature_hash IS NULL AND provider_operation_id IS NULL
      AND signing_bytes_digest IS NOT NULL AND response_json IS NULL
      AND uncertain_reason IS NOT NULL AND completed_at IS NULL
      AND outcome_unknown_at IS NOT NULL AND revoked_at IS NULL AND expired_at IS NULL)
    OR (state = 'revoked' AND response_json IS NULL AND revoked_at IS NOT NULL AND expired_at IS NULL)
    OR (state = 'expired' AND response_json IS NULL AND expired_at IS NOT NULL)
  )
);

CREATE FUNCTION public.agentpass_allocate_capability_sequence_on_insert()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  current_sequence bigint;
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.agent_session_signing_capability_reservations AS r
    WHERE r.organization_id = NEW.organization_id AND r.capability_id = NEW.id
      AND r.agent_id = NEW.agent_id AND r.sequence = NEW.sequence
  ) THEN
    SELECT sequence INTO current_sequence
    FROM public.agent_capability_sequence_heads
    WHERE organization_id = NEW.organization_id AND agent_id = NEW.agent_id
    FOR UPDATE;
    IF NOT FOUND OR current_sequence < NEW.sequence THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        MESSAGE = 'reserved capability sequence is not allocated',
        CONSTRAINT = 'capabilities_sequence_allocator';
    END IF;
    RETURN NEW;
  END IF;

  INSERT INTO public.agent_capability_sequence_heads (organization_id, agent_id, sequence)
  VALUES (NEW.organization_id, NEW.agent_id, 0)
  ON CONFLICT (organization_id, agent_id) DO NOTHING;
  SELECT sequence INTO current_sequence
  FROM public.agent_capability_sequence_heads
  WHERE organization_id = NEW.organization_id AND agent_id = NEW.agent_id
  FOR UPDATE;
  IF NEW.sequence IS DISTINCT FROM current_sequence + 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'capability sequence must be the next allocated value',
      CONSTRAINT = 'capabilities_sequence_allocator';
  END IF;
  UPDATE public.agent_capability_sequence_heads
  SET sequence = NEW.sequence, updated_at = clock_timestamp()
  WHERE organization_id = NEW.organization_id AND agent_id = NEW.agent_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER capabilities_sequence_allocator
  BEFORE INSERT ON public.capabilities
  FOR EACH ROW EXECUTE FUNCTION public.agentpass_allocate_capability_sequence_on_insert();

CREATE INDEX agent_session_signing_capability_reservations_session_state
  ON public.agent_session_signing_capability_reservations
  (organization_id, session_id, state, sequence);
CREATE INDEX agent_session_signing_capability_reservations_expiry
  ON public.agent_session_signing_capability_reservations
  (expires_at, organization_id, reservation_id) WHERE state IN ('reserved', 'completed');
CREATE INDEX agent_session_signing_capability_reservations_claim_expiry
  ON public.agent_session_signing_capability_reservations
  (claim_expires_at, organization_id, reservation_id) WHERE state = 'reserved';
CREATE INDEX agent_session_signing_capability_reservations_uncertain
  ON public.agent_session_signing_capability_reservations
  (organization_id, updated_at, reservation_id) WHERE state = 'outcome_unknown';

CREATE FUNCTION public.agentpass_agent_signing_capability_record(
  p_row public.agent_session_signing_capability_reservations,
  p_remaining integer,
  p_replayed boolean
) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS $$
  SELECT CASE
    WHEN p_row.state = 'completed' THEN jsonb_build_object(
      'state', 'committed', 'capability', p_row.response_json,
      'remaining_session_signatures', p_remaining)
    WHEN p_row.state = 'outcome_unknown' THEN jsonb_build_object('state', 'uncertain')
    WHEN p_row.state = 'reserved' THEN jsonb_build_object('state', 'in_progress')
    ELSE jsonb_build_object('state', 'absent')
  END
$$;

-- Canonical JSON helpers intentionally avoid jsonb::text for arrays because
-- its display whitespace is not packages/protocol canonicalJson(). These
-- functions reproduce the closed Agent signing scope and statement byte for
-- byte so PostgreSQL can bind the durable provider operation to the exact
-- Ed25519 preimage without implementing Ed25519 itself.
CREATE FUNCTION public.agentpass_agent_signing_capability_text_array_json(p_value jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
DECLARE
  result text;
BEGIN
  IF p_value IS NULL OR jsonb_typeof(p_value) <> 'array'
     OR jsonb_array_length(p_value) > 64
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(p_value) AS item(value)
       WHERE jsonb_typeof(item.value) <> 'string')
  THEN RETURN NULL; END IF;
  SELECT '[' || coalesce(string_agg(to_json(item.value)::text, ',' ORDER BY item.ordinal), '') || ']'
    INTO result
  FROM jsonb_array_elements_text(p_value) WITH ORDINALITY AS item(value, ordinal);
  RETURN result;
END;
$$;

CREATE FUNCTION public.agentpass_agent_signing_capability_scope_canonical_json(p_scope jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
DECLARE
  operations_json text;
  repositories_json text;
  branch_allow_json text;
  branch_deny_json text;
  remote_allow_json text;
  remote_deny_json text;
BEGIN
  IF NOT public.agentpass_public_scope_json_valid(p_scope)
     OR (SELECT count(*) FROM jsonb_object_keys(p_scope)) <> 4
     OR NOT (p_scope ?& ARRAY['branches','operations','remotes','repositories'])
     OR jsonb_typeof(p_scope->'branches') <> 'object'
     OR jsonb_typeof(p_scope->'remotes') <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(p_scope->'branches')) <> 2
     OR (SELECT count(*) FROM jsonb_object_keys(p_scope->'remotes')) <> 2
     OR NOT ((p_scope->'branches') ?& ARRAY['allow','deny'])
     OR NOT ((p_scope->'remotes') ?& ARRAY['allow','deny'])
  THEN RETURN NULL; END IF;
  operations_json := public.agentpass_agent_signing_capability_text_array_json(p_scope->'operations');
  repositories_json := public.agentpass_agent_signing_capability_text_array_json(p_scope->'repositories');
  branch_allow_json := public.agentpass_agent_signing_capability_text_array_json(p_scope->'branches'->'allow');
  branch_deny_json := public.agentpass_agent_signing_capability_text_array_json(p_scope->'branches'->'deny');
  remote_allow_json := public.agentpass_agent_signing_capability_text_array_json(p_scope->'remotes'->'allow');
  remote_deny_json := public.agentpass_agent_signing_capability_text_array_json(p_scope->'remotes'->'deny');
  IF operations_json IS NULL OR repositories_json IS NULL OR branch_allow_json IS NULL
     OR branch_deny_json IS NULL OR remote_allow_json IS NULL OR remote_deny_json IS NULL
  THEN RETURN NULL; END IF;
  RETURN '{"branches":{"allow":' || branch_allow_json || ',"deny":' || branch_deny_json || '}' ||
    ',"operations":' || operations_json ||
    ',"remotes":{"allow":' || remote_allow_json || ',"deny":' || remote_deny_json || '}' ||
    ',"repositories":' || repositories_json || '}';
END;
$$;

CREATE FUNCTION public.agentpass_agent_signing_capability_statement_canonical_json(
  p_row public.agent_session_signing_capability_reservations
) RETURNS text LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
DECLARE
  scope_text text := public.agentpass_agent_signing_capability_scope_canonical_json(p_row.scope_json);
BEGIN
  IF scope_text IS NULL THEN RETURN NULL; END IF;
  RETURN '{"agent_id":' || to_json(p_row.agent_id::text)::text ||
    ',"algorithm":"ed25519"' ||
    ',"authority_generation":' || p_row.authority_generation::text ||
    ',"capability_id":' || to_json(p_row.capability_id::text)::text ||
    ',"control_sequence":' || p_row.control_sequence::text ||
    ',"device_id":' || to_json(p_row.device_id::text)::text ||
    ',"expires_at":' || to_json(to_char(p_row.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
    ',"issued_at":' || to_json(to_char(p_row.issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
    ',"issuer":"agentpass-cloud"' ||
    ',"key_id":' || to_json(p_row.key_id)::text ||
    ',"key_purpose":"git.commit.sign"' ||
    ',"max_signatures":1' ||
    ',"not_before":' || to_json(to_char(p_row.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
    ',"one_use":true' ||
    ',"operation":"git.commit.sign"' ||
    ',"organization_id":' || to_json(p_row.organization_id::text)::text ||
    ',"scope":' || scope_text ||
    ',"sequence":' || p_row.sequence::text ||
    ',"session_id":' || to_json(p_row.session_id::text)::text ||
    ',"type":"agentpass.agent-signing-capability"' ||
    ',"version":1}';
END;
$$;

CREATE FUNCTION public.agentpass_capability_authority_public_json(p_row public.capabilities)
RETURNS jsonb LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
  SELECT jsonb_build_object(
    'organization_id', p_row.organization_id,
    'capability_id', p_row.id,
    'agent_id', p_row.agent_id,
    'device_id', p_row.device_id,
    'sequence', p_row.sequence,
    'statement_hash', p_row.statement_hash,
    'expires_at', p_row.expires_at,
    'revoked_at', p_row.revoked_at,
    'issued_by_member_id', p_row.issued_by_member_id,
    'issued_membership_version', p_row.issued_membership_version)
$$;

-- Human-issued Capability metadata uses the same function-only table boundary
-- as agent-issued capabilities. Membership version is always read under lock;
-- a caller-provided expected version is only a stale-write fence.
CREATE FUNCTION public.agentpass_capability_authority_issue(
  p_organization_id uuid, p_capability_id uuid, p_agent_id uuid,
  p_device_id uuid, p_sequence bigint, p_statement_hash text,
  p_expires_at timestamptz, p_issued_by_member_id uuid,
  p_expected_membership_version bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  membership_row public.memberships%ROWTYPE;
  capability_row public.capabilities%ROWTYPE;
  inserted boolean := false;
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF p_capability_id IS NULL OR p_agent_id IS NULL OR p_device_id IS NULL
     OR p_issued_by_member_id IS NULL OR p_sequence IS NULL OR p_sequence < 1
     OR p_statement_hash IS NULL OR p_statement_hash !~ '^[0-9a-f]{64}$'
     OR p_expires_at IS NULL OR p_expires_at <= clock_timestamp()
     OR (p_expected_membership_version IS NOT NULL AND p_expected_membership_version < 1)
  THEN RETURN jsonb_build_object('state', 'invalid'); END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:organization:' || p_organization_id::text, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:capability-authority:' || p_organization_id::text || ':' ||
      p_issued_by_member_id::text, 0));
  SELECT * INTO membership_row FROM public.memberships AS membership
  WHERE membership.organization_id = p_organization_id
    AND membership.member_id = p_issued_by_member_id
    AND membership.status = 'active' FOR SHARE;
  IF NOT FOUND OR membership_row.role NOT IN ('owner', 'admin')
  THEN RETURN jsonb_build_object('state', 'member_not_active'); END IF;
  IF p_expected_membership_version IS NOT NULL
     AND p_expected_membership_version IS DISTINCT FROM membership_row.version
  THEN RETURN jsonb_build_object('state', 'membership_version_conflict'); END IF;

  INSERT INTO public.capabilities (
    organization_id, id, agent_id, device_id, sequence, statement_hash,
    expires_at, issued_by_member_id, issued_membership_version)
  VALUES (p_organization_id, p_capability_id, p_agent_id, p_device_id,
    p_sequence, p_statement_hash, p_expires_at, p_issued_by_member_id,
    membership_row.version)
  ON CONFLICT (organization_id, id) DO NOTHING
  RETURNING * INTO capability_row;
  inserted := FOUND;
  IF NOT inserted THEN
    SELECT * INTO capability_row FROM public.capabilities AS capability
    WHERE capability.organization_id = p_organization_id
      AND capability.id = p_capability_id FOR UPDATE;
    IF NOT FOUND
       OR capability_row.agent_id IS DISTINCT FROM p_agent_id
       OR capability_row.device_id IS DISTINCT FROM p_device_id
       OR capability_row.sequence IS DISTINCT FROM p_sequence
       OR capability_row.statement_hash IS DISTINCT FROM p_statement_hash
       OR capability_row.expires_at IS DISTINCT FROM p_expires_at
       OR capability_row.issued_by_member_id IS DISTINCT FROM p_issued_by_member_id
       OR capability_row.issued_membership_version IS DISTINCT FROM membership_row.version
    THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  END IF;
  RETURN jsonb_build_object(
    'state', CASE WHEN inserted THEN 'issued' ELSE 'replayed' END,
    'capability', public.agentpass_capability_authority_public_json(capability_row));
END;
$$;

CREATE FUNCTION public.agentpass_capability_authority_revoke_member(
  p_organization_id uuid, p_member_id uuid, p_revoked_at timestamptz
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  capability_row public.capabilities%ROWTYPE;
  capabilities_value jsonb := '[]'::jsonb;
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
     OR p_member_id IS NULL OR p_revoked_at IS NULL
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:organization:' || p_organization_id::text, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:capability-authority:' || p_organization_id::text || ':' ||
      p_member_id::text, 0));
  FOR capability_row IN
    WITH updated AS (
      UPDATE public.capabilities SET revoked_at = p_revoked_at
      WHERE organization_id = p_organization_id
        AND issued_by_member_id = p_member_id AND revoked_at IS NULL
      RETURNING *
    ) SELECT * FROM updated ORDER BY id
  LOOP
    capabilities_value := capabilities_value ||
      jsonb_build_array(public.agentpass_capability_authority_public_json(capability_row));
  END LOOP;
  RETURN jsonb_build_object('state', 'revoked', 'capabilities', capabilities_value);
END;
$$;

CREATE FUNCTION public.agentpass_capability_authority_list_revoked(
  p_organization_id uuid, p_evaluated_at timestamptz, p_limit integer
) RETURNS jsonb LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  ids_value jsonb;
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
     OR p_evaluated_at IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 257
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  SELECT coalesce(jsonb_agg(candidate.id ORDER BY candidate.id), '[]'::jsonb)
    INTO ids_value
  FROM (
    SELECT capability.id FROM public.capabilities AS capability
    WHERE capability.organization_id = p_organization_id
      AND capability.revoked_at IS NOT NULL
      AND capability.expires_at > p_evaluated_at
    ORDER BY capability.id LIMIT p_limit
  ) AS candidate;
  RETURN jsonb_build_object('state', 'listed', 'capability_ids', ids_value);
END;
$$;

CREATE FUNCTION public.agentpass_capability_reservation_public_json(p_row public.capabilities)
RETURNS jsonb LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
  SELECT jsonb_build_object(
    'organization_id', p_row.organization_id, 'capability_id', p_row.id,
    'agent_id', p_row.agent_id, 'device_id', p_row.device_id,
    'sequence', p_row.sequence, 'statement_hash', p_row.statement_hash,
    'expires_at', p_row.expires_at, 'issued_by_member_id', p_row.issued_by_member_id,
    'issued_membership_version', p_row.issued_membership_version,
    'issuer', p_row.issuer, 'key_id', p_row.key_id, 'scope_json', p_row.scope_json,
    'not_before', p_row.not_before, 'revoked_at', p_row.revoked_at,
    'version', p_row.version)
$$;

CREATE FUNCTION public.agentpass_capability_reservation_issue(
  p_organization_id uuid, p_capability_id uuid, p_agent_id uuid, p_device_id uuid,
  p_sequence bigint, p_statement_hash text, p_expires_at timestamptz,
  p_issued_by_member_id uuid, p_issuer text, p_key_id text, p_scope_json jsonb,
  p_not_before timestamptz, p_nonce_digest bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  membership_row public.memberships%ROWTYPE;
  capability_row public.capabilities%ROWTYPE;
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF p_capability_id IS NULL OR p_agent_id IS NULL OR p_device_id IS NULL
     OR p_issued_by_member_id IS NULL OR p_sequence IS NULL OR p_sequence < 1
     OR p_statement_hash IS NULL OR p_statement_hash !~ '^[0-9a-f]{64}$'
     OR p_expires_at IS NULL OR p_not_before IS NULL OR p_expires_at <= p_not_before
     OR p_issuer IS NULL OR p_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
     OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
     OR p_scope_json IS NULL
     OR NOT coalesce(public.agentpass_public_scope_json_valid(p_scope_json), false)
     OR p_nonce_digest IS NULL OR octet_length(p_nonce_digest) IS DISTINCT FROM 32
  THEN RETURN jsonb_build_object('state', 'invalid'); END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:organization:' || p_organization_id::text, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:capability-reservation:' || p_organization_id::text || ':' ||
      p_issued_by_member_id::text, 0));
  SELECT * INTO membership_row FROM public.memberships AS membership
  WHERE membership.organization_id = p_organization_id
    AND membership.member_id = p_issued_by_member_id
    AND membership.status = 'active' FOR SHARE;
  IF NOT FOUND OR membership_row.role NOT IN ('owner', 'admin')
  THEN RETURN jsonb_build_object('state', 'member_not_active'); END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.agents AS agent
    JOIN public.devices AS device
      ON device.organization_id = agent.organization_id AND device.id = agent.device_id
    WHERE agent.organization_id = p_organization_id AND agent.id = p_agent_id
      AND agent.device_id = p_device_id AND agent.status = 'active'
      AND device.status = 'active'
  ) THEN RETURN jsonb_build_object('state', 'audience_absent'); END IF;
  INSERT INTO public.capabilities (
    organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at,
    issued_by_member_id,issued_membership_version,issuer,key_id,scope_json,
    not_before,nonce_digest)
  VALUES (p_organization_id,p_capability_id,p_agent_id,p_device_id,p_sequence,
    p_statement_hash,p_expires_at,p_issued_by_member_id,membership_row.version,
    p_issuer,p_key_id,p_scope_json,p_not_before,p_nonce_digest)
  ON CONFLICT (organization_id,id) DO NOTHING RETURNING * INTO capability_row;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  RETURN jsonb_build_object('state', 'issued', 'capability',
    public.agentpass_capability_reservation_public_json(capability_row));
END;
$$;

CREATE FUNCTION public.agentpass_capability_reservation_list(
  p_organization_id uuid, p_limit integer
) RETURNS jsonb LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  capabilities_value jsonb;
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1001
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  SELECT coalesce(jsonb_agg(candidate.value ORDER BY candidate.not_before, candidate.id), '[]'::jsonb)
    INTO capabilities_value
  FROM (
    SELECT public.agentpass_capability_reservation_public_json(capability) AS value,
      capability.not_before, capability.id
    FROM public.capabilities AS capability
    WHERE capability.organization_id = p_organization_id
      AND capability.issuer IS NOT NULL AND capability.key_id IS NOT NULL
      AND capability.scope_json IS NOT NULL AND capability.not_before IS NOT NULL
    ORDER BY capability.not_before, capability.id LIMIT p_limit
  ) AS candidate;
  RETURN jsonb_build_object('state', 'listed', 'capabilities', capabilities_value);
END;
$$;

CREATE FUNCTION public.agentpass_agent_signing_capability_reserve(
  p_organization_id uuid, p_device_id uuid, p_session_id uuid, p_request_id uuid,
  p_request_digest bytea, p_reservation_id uuid, p_capability_id uuid,
  p_claim_token_hash bytea, p_operation text, p_key_purpose text,
  p_one_use boolean, p_max_signatures integer, p_ttl_ms bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  session_row public.agent_sessions%ROWTYPE;
  grant_row public.agent_session_grants%ROWTYPE;
  existing_row public.agent_session_signing_capability_reservations%ROWTYPE;
  signer_row public.managed_signer_keys%ROWTYPE;
  next_sequence bigint;
  now_value timestamptz := date_trunc('milliseconds', clock_timestamp());
  expiry_value timestamptz;
  claim_expiry_value timestamptz;
  remaining_value integer;
  binding_row public.agent_session_signing_capability_reservations%ROWTYPE;
  statement_text text;
  signing_bytes bytea;
  provider_request_json text;
  statement_digest bytea;
  signing_digest bytea;
  provider_request_digest_value bytea;
  provider_operation_id_value text;
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF p_device_id IS NULL OR p_session_id IS NULL
     OR p_request_id IS NULL OR p_reservation_id IS NULL OR p_capability_id IS NULL
     OR octet_length(p_request_digest) IS DISTINCT FROM 32
     OR octet_length(p_claim_token_hash) IS DISTINCT FROM 32
     OR p_operation IS DISTINCT FROM 'git.commit.sign'
     OR p_key_purpose IS DISTINCT FROM 'git.commit.sign'
     OR p_one_use IS DISTINCT FROM true OR p_max_signatures IS DISTINCT FROM 1
     OR p_ttl_ms IS NULL OR p_ttl_ms NOT BETWEEN 1000 AND 900000
     OR p_request_id = p_reservation_id OR p_request_id = p_capability_id
     OR p_reservation_id = p_capability_id
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:organization:' || p_organization_id::text, 0));

  SELECT * INTO existing_row FROM public.agent_session_signing_capability_reservations AS r
  WHERE r.organization_id = p_organization_id AND r.request_id = p_request_id FOR UPDATE;
  IF FOUND THEN
    IF existing_row.device_id IS DISTINCT FROM p_device_id
       OR existing_row.session_id IS DISTINCT FROM p_session_id
       OR existing_row.request_digest IS DISTINCT FROM p_request_digest
       OR existing_row.operation IS DISTINCT FROM p_operation
       OR existing_row.key_purpose IS DISTINCT FROM p_key_purpose
    THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
    SELECT greatest(s.max_signatures - s.used_signatures - s.reserved_signatures, 0)
      INTO remaining_value FROM public.agent_sessions AS s
      WHERE s.organization_id = existing_row.organization_id AND s.session_id = existing_row.session_id;
    IF existing_row.state = 'reserved' AND existing_row.claim_expires_at <= now_value THEN
      SELECT * INTO session_row FROM public.agent_sessions AS s
      WHERE s.organization_id = existing_row.organization_id
        AND s.session_id = existing_row.session_id FOR UPDATE;
      IF session_row.status = 'signing_intent' AND session_row.active_request_id = existing_row.request_id THEN
        UPDATE public.agent_sessions SET status = 'outcome_unknown', active_request_id = NULL,
          last_request_id = existing_row.request_id, used_signatures = used_signatures + 1,
          reserved_signatures = reserved_signatures - 1, outcome_unknown_at = now_value
        WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
      END IF;
      UPDATE public.agent_session_signing_capability_reservations SET
        state = 'outcome_unknown', uncertain_reason = 'claim_expired',
        outcome_unknown_at = now_value, updated_at = now_value
      WHERE organization_id = existing_row.organization_id AND reservation_id = existing_row.reservation_id;
      RETURN jsonb_build_object('state', 'uncertain');
    END IF;
    RETURN public.agentpass_agent_signing_capability_record(existing_row, coalesce(remaining_value, 0), true);
  END IF;

  SELECT * INTO session_row FROM public.agent_sessions AS s
  WHERE s.organization_id = p_organization_id AND s.session_id = p_session_id
    AND s.device_id = p_device_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'absent'); END IF;

  -- A same-request transaction may have committed while this call waited on
  -- the Session lock. Re-read under the current READ COMMITTED snapshot before
  -- interpreting the now-advanced Session lifecycle.
  SELECT * INTO existing_row FROM public.agent_session_signing_capability_reservations AS r
  WHERE r.organization_id = p_organization_id AND r.request_id = p_request_id FOR UPDATE;
  IF FOUND THEN
    IF existing_row.device_id IS DISTINCT FROM p_device_id
       OR existing_row.session_id IS DISTINCT FROM p_session_id
       OR existing_row.request_digest IS DISTINCT FROM p_request_digest
    THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
    remaining_value := greatest(session_row.max_signatures - session_row.used_signatures
      - session_row.reserved_signatures, 0);
    RETURN public.agentpass_agent_signing_capability_record(existing_row, remaining_value, true);
  END IF;
  IF session_row.status = 'signed'
     AND session_row.used_signatures + session_row.reserved_signatures < session_row.max_signatures
  THEN
    UPDATE public.agent_sessions SET status = 'active'
      WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
    session_row.status := 'active';
  END IF;
  IF session_row.status <> 'active' OR session_row.max_signatures <> 2
     OR session_row.used_signatures + session_row.reserved_signatures >= session_row.max_signatures
     OR now_value < session_row.not_before OR now_value >= session_row.expires_at
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;

  SELECT * INTO grant_row FROM public.agent_session_grants AS g
  WHERE g.organization_id = session_row.organization_id AND g.grant_id = session_row.grant_id
    AND g.device_id = session_row.device_id AND g.agent_id = session_row.agent_id
    AND g.grant_hash = session_row.grant_hash FOR SHARE;
  IF NOT FOUND OR grant_row.status <> 'consumed' OR grant_row.scope_json IS NULL
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.devices AS d
    JOIN public.agents AS a ON a.organization_id = d.organization_id AND a.device_id = d.id
    JOIN public.control_plane_authority_generations AS g
      ON g.organization_id = d.organization_id AND g.generation = session_row.authority_generation
      AND g.superseded_at IS NULL
    WHERE d.organization_id = session_row.organization_id AND d.id = session_row.device_id
      AND d.status = 'active' AND a.id = session_row.agent_id AND a.status = 'active'
      AND NOT EXISTS (SELECT 1 FROM public.revocations AS r
        WHERE r.organization_id = session_row.organization_id AND r.status = 'active'
          AND (r.target_type = 'organization'
            OR (r.target_type = 'device' AND r.target_id = session_row.device_id)
            OR (r.target_type = 'agent' AND r.target_id = session_row.agent_id)))
  ) THEN RETURN jsonb_build_object('state', 'absent'); END IF;

  SELECT * INTO signer_row FROM public.managed_signer_keys AS k
    WHERE k.purpose = p_key_purpose AND k.state = 'active' FOR SHARE;
  IF NOT FOUND OR signer_row.algorithm <> 'ed25519'
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;

  INSERT INTO public.agent_capability_sequence_heads (organization_id, agent_id, sequence)
  VALUES (session_row.organization_id, session_row.agent_id, 0)
  ON CONFLICT (organization_id, agent_id) DO NOTHING;
  SELECT sequence INTO next_sequence
  FROM public.agent_capability_sequence_heads
  WHERE organization_id = session_row.organization_id AND agent_id = session_row.agent_id
  FOR UPDATE;
  next_sequence := next_sequence + 1;
  UPDATE public.agent_capability_sequence_heads
  SET sequence = next_sequence, updated_at = now_value
  WHERE organization_id = session_row.organization_id AND agent_id = session_row.agent_id;

  expiry_value := least(now_value + (p_ttl_ms * interval '1 millisecond'), session_row.expires_at);
  IF expiry_value <= now_value THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  claim_expiry_value := least(now_value + interval '60 seconds', expiry_value);

  binding_row.organization_id := session_row.organization_id;
  binding_row.capability_id := p_capability_id;
  binding_row.session_id := session_row.session_id;
  binding_row.device_id := session_row.device_id;
  binding_row.agent_id := session_row.agent_id;
  binding_row.sequence := next_sequence;
  binding_row.key_id := signer_row.key_id;
  binding_row.scope_json := grant_row.scope_json;
  binding_row.control_sequence := session_row.control_sequence;
  binding_row.authority_generation := session_row.authority_generation;
  binding_row.issued_at := now_value;
  binding_row.not_before := now_value;
  binding_row.expires_at := expiry_value;
  statement_text := public.agentpass_agent_signing_capability_statement_canonical_json(binding_row);
  IF statement_text IS NULL THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  signing_bytes := convert_to('AgentPass-Agent-Signing-Capability-v1', 'UTF8')
    || decode('00', 'hex') || convert_to(statement_text, 'UTF8');
  statement_digest := sha256(convert_to(statement_text, 'UTF8'));
  signing_digest := sha256(signing_bytes);
  provider_request_json := '{"algorithm":"ed25519","bytes":' ||
    to_json(replace(encode(signing_bytes, 'base64'), chr(10), ''))::text ||
    ',"key_id":' || to_json(signer_row.key_id)::text ||
    ',"key_version":' || signer_row.key_version::text ||
    ',"purpose":"git.commit.sign","version":1}';
  provider_request_digest_value := sha256(convert_to(provider_request_json, 'UTF8'));
  provider_operation_id_value := 'managed-signer-v1-' ||
    encode(provider_request_digest_value, 'hex');

  UPDATE public.agent_sessions SET status = 'request_reserved',
    reserved_signatures = reserved_signatures + 1, active_request_id = p_request_id
  WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
  UPDATE public.agent_sessions SET status = 'signing_intent'
  WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;

  INSERT INTO public.agent_session_signing_capability_reservations (
    organization_id, reservation_id, request_id, request_digest, capability_id,
    session_id, grant_id, device_id, agent_id, grant_hash, sequence, operation,
    key_purpose, key_id, key_version, algorithm, scope_json, control_sequence, authority_generation,
    claim_token_hash, claim_expires_at, state, capability_statement_hash,
    planned_provider_operation_id, provider_request_digest, provider_bytes_length,
    signing_bytes_digest, issued_at, not_before, expires_at,
    created_at, updated_at
  ) VALUES (
    session_row.organization_id, p_reservation_id, p_request_id, p_request_digest,
    p_capability_id, session_row.session_id, session_row.grant_id, session_row.device_id,
    session_row.agent_id, session_row.grant_hash, next_sequence, p_operation,
    p_key_purpose, signer_row.key_id, signer_row.key_version, signer_row.algorithm, grant_row.scope_json,
    session_row.control_sequence, session_row.authority_generation, p_claim_token_hash,
    claim_expiry_value, 'reserved', statement_digest, provider_operation_id_value,
    provider_request_digest_value, octet_length(signing_bytes), signing_digest,
    now_value, now_value, expiry_value, now_value, now_value
  ) RETURNING * INTO existing_row;

  remaining_value := session_row.max_signatures - session_row.used_signatures
    - session_row.reserved_signatures - 1;
  RETURN jsonb_build_object(
    'state', 'reserved', 'claim_issued', true,
    'capability_id', existing_row.capability_id,
    'organization_id', existing_row.organization_id, 'session_id', existing_row.session_id,
    'device_id', existing_row.device_id, 'agent_id', existing_row.agent_id,
    'scope', existing_row.scope_json, 'sequence', existing_row.sequence,
    'control_sequence', existing_row.control_sequence,
    'authority_generation', existing_row.authority_generation,
    'issued_at', to_char(existing_row.issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'not_before', to_char(existing_row.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'expires_at', to_char(existing_row.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'remaining_session_signatures', remaining_value
  );
END;
$$;

CREATE FUNCTION public.agentpass_agent_signing_capability_commit(
  p_organization_id uuid, p_device_id uuid, p_session_id uuid, p_request_id uuid,
  p_request_digest bytea, p_claim_token_hash bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  reservation_row public.agent_session_signing_capability_reservations%ROWTYPE;
  session_row public.agent_sessions%ROWTYPE;
  grant_row public.agent_session_grants%ROWTYPE;
  signer_row public.managed_signer_keys%ROWTYPE;
  provider_row public.managed_signer_provider_operations%ROWTYPE;
  now_value timestamptz := date_trunc('milliseconds', clock_timestamp());
  remaining_value integer;
  statement_text text;
  expected_statement_hash bytea;
  expected_signing_digest bytea;
  expected_provider_request_digest bytea;
  signing_bytes bytea;
  provider_request_json text;
  expected_signature text;
  expected_capability jsonb;
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF octet_length(p_request_digest) IS DISTINCT FROM 32
     OR octet_length(p_claim_token_hash) IS DISTINCT FROM 32
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:organization:' || p_organization_id::text, 0));
  SELECT * INTO reservation_row FROM public.agent_session_signing_capability_reservations AS r
    WHERE r.organization_id = p_organization_id AND r.request_id = p_request_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF reservation_row.device_id IS DISTINCT FROM p_device_id
     OR reservation_row.session_id IS DISTINCT FROM p_session_id
     OR reservation_row.request_digest IS DISTINCT FROM p_request_digest
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  SELECT * INTO session_row FROM public.agent_sessions AS s
    WHERE s.organization_id = reservation_row.organization_id
      AND s.session_id = reservation_row.session_id FOR UPDATE;
  remaining_value := greatest(session_row.max_signatures - session_row.used_signatures
    - session_row.reserved_signatures, 0);
  IF reservation_row.state = 'completed' THEN
    RETURN public.agentpass_agent_signing_capability_record(reservation_row, remaining_value, true);
  END IF;
  IF reservation_row.state = 'outcome_unknown' THEN RETURN jsonb_build_object('state', 'uncertain'); END IF;
  IF reservation_row.state <> 'reserved'
     OR reservation_row.claim_token_hash IS DISTINCT FROM p_claim_token_hash
     OR reservation_row.claim_expires_at <= now_value OR reservation_row.expires_at <= now_value
     OR session_row.status <> 'signing_intent'
     OR session_row.active_request_id IS DISTINCT FROM reservation_row.request_id
     OR session_row.device_id IS DISTINCT FROM reservation_row.device_id
     OR session_row.agent_id IS DISTINCT FROM reservation_row.agent_id
     OR session_row.grant_id IS DISTINCT FROM reservation_row.grant_id
     OR session_row.grant_hash IS DISTINCT FROM reservation_row.grant_hash
     OR session_row.control_sequence IS DISTINCT FROM reservation_row.control_sequence
     OR session_row.authority_generation IS DISTINCT FROM reservation_row.authority_generation
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;

  -- Repeat every mutable authority check after the external signing boundary.
  -- A reservation never authorizes commit after Device/Agent/Grant/generation,
  -- revocation, or signer lifecycle state changes.
  SELECT * INTO grant_row FROM public.agent_session_grants AS g
  WHERE g.organization_id = reservation_row.organization_id
    AND g.grant_id = reservation_row.grant_id
    AND g.device_id = reservation_row.device_id
    AND g.agent_id = reservation_row.agent_id
    AND g.grant_hash = reservation_row.grant_hash FOR SHARE;
  IF NOT FOUND OR grant_row.status <> 'consumed'
     OR grant_row.scope_json IS DISTINCT FROM reservation_row.scope_json
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.devices AS d
    WHERE d.organization_id = reservation_row.organization_id
      AND d.id = reservation_row.device_id AND d.status = 'active'
  ) OR NOT EXISTS (
    SELECT 1 FROM public.agents AS a
    WHERE a.organization_id = reservation_row.organization_id
      AND a.device_id = reservation_row.device_id
      AND a.id = reservation_row.agent_id AND a.status = 'active'
  ) OR NOT EXISTS (
    SELECT 1 FROM public.control_plane_authority_generations AS g
    WHERE g.organization_id = reservation_row.organization_id
      AND g.generation = reservation_row.authority_generation
      AND g.superseded_at IS NULL
  ) OR EXISTS (
    SELECT 1 FROM public.revocations AS r
    WHERE r.organization_id = reservation_row.organization_id
      AND r.status = 'active'
      AND (r.target_type = 'organization'
        OR (r.target_type = 'device' AND r.target_id = reservation_row.device_id)
        OR (r.target_type = 'agent' AND r.target_id = reservation_row.agent_id))
  ) THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  SELECT * INTO signer_row FROM public.managed_signer_keys AS k
  WHERE k.purpose = reservation_row.key_purpose
    AND k.key_id = reservation_row.key_id
    AND k.key_version = reservation_row.key_version
    AND k.algorithm = reservation_row.algorithm
    AND k.state = 'active' FOR SHARE;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'conflict'); END IF;

  statement_text := public.agentpass_agent_signing_capability_statement_canonical_json(reservation_row);
  IF statement_text IS NULL THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  expected_statement_hash := sha256(convert_to(statement_text, 'UTF8'));
  signing_bytes := convert_to('AgentPass-Agent-Signing-Capability-v1', 'UTF8')
    || decode('00', 'hex') || convert_to(statement_text, 'UTF8');
  expected_signing_digest := sha256(signing_bytes);
  provider_request_json := '{"algorithm":"ed25519","bytes":' ||
    to_json(replace(encode(signing_bytes, 'base64'), chr(10), ''))::text ||
    ',"key_id":' || to_json(reservation_row.key_id)::text ||
    ',"key_version":' || reservation_row.key_version::text ||
    ',"purpose":"git.commit.sign","version":1}';
  expected_provider_request_digest := sha256(convert_to(provider_request_json, 'UTF8'));
  IF reservation_row.planned_provider_operation_id IS DISTINCT FROM
       'managed-signer-v1-' || encode(expected_provider_request_digest, 'hex')
     OR reservation_row.capability_statement_hash IS DISTINCT FROM expected_statement_hash
     OR reservation_row.signing_bytes_digest IS DISTINCT FROM expected_signing_digest
     OR reservation_row.provider_request_digest IS DISTINCT FROM expected_provider_request_digest
     OR reservation_row.provider_bytes_length IS DISTINCT FROM octet_length(signing_bytes)
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;

  SELECT * INTO provider_row FROM public.managed_signer_provider_operations AS provider
  WHERE provider.purpose = reservation_row.key_purpose
    AND provider.operation_id = reservation_row.planned_provider_operation_id FOR SHARE;
  IF NOT FOUND OR provider_row.state <> 'committed'
     OR provider_row.algorithm IS DISTINCT FROM reservation_row.algorithm
     OR provider_row.request_digest IS DISTINCT FROM expected_provider_request_digest
     OR provider_row.bytes_length IS DISTINCT FROM octet_length(signing_bytes)
     OR provider_row.key_id IS DISTINCT FROM reservation_row.key_id
     OR provider_row.key_version IS DISTINCT FROM reservation_row.key_version
     OR provider_row.expires_at <= now_value
     OR provider_row.signature IS NULL OR octet_length(provider_row.signature) <> 64
     OR provider_row.public_key_der IS NULL
     OR sha256(provider_row.public_key_der) IS DISTINCT FROM signer_row.public_key_fingerprint
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;

  expected_signature := rtrim(translate(
    replace(encode(provider_row.signature, 'base64'), chr(10), ''), '+/', '-_'), '=');
  expected_capability := jsonb_build_object(
    'version', 1,
    'type', 'agentpass.agent-signing-capability',
    'statement', statement_text::jsonb,
    'statement_hash', encode(expected_statement_hash, 'hex'),
    'signature', expected_signature
  );
  IF (SELECT count(*) FROM jsonb_object_keys(expected_capability)) <> 5
     OR jsonb_typeof(expected_capability->'statement') <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(expected_capability->'statement')) <> 21
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;

  INSERT INTO public.capabilities (
    organization_id, id, agent_id, device_id, sequence, statement_hash, expires_at,
    issued_by_session_id, issuer, key_id, scope_json, not_before
  )
  VALUES (reservation_row.organization_id, reservation_row.capability_id,
    reservation_row.agent_id, reservation_row.device_id, reservation_row.sequence,
    encode(expected_statement_hash, 'hex'), reservation_row.expires_at,
    reservation_row.session_id, 'agentpass-cloud', reservation_row.key_id,
    reservation_row.scope_json, reservation_row.not_before);
  UPDATE public.agent_sessions SET status = 'signed', active_request_id = NULL,
    last_request_id = reservation_row.request_id, used_signatures = used_signatures + 1,
    reserved_signatures = reserved_signatures - 1
  WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
  UPDATE public.agent_session_signing_capability_reservations SET state = 'completed',
    capability_statement_hash = expected_statement_hash,
    capability_signature_hash = sha256(provider_row.signature),
    provider_operation_id = provider_row.operation_id,
    signing_bytes_digest = expected_signing_digest,
    response_json = expected_capability, completed_at = now_value, updated_at = now_value
  WHERE organization_id = reservation_row.organization_id
    AND reservation_id = reservation_row.reservation_id RETURNING * INTO reservation_row;
  remaining_value := session_row.max_signatures - session_row.used_signatures - 1;
  RETURN public.agentpass_agent_signing_capability_record(reservation_row, remaining_value, false);
END;
$$;

CREATE FUNCTION public.agentpass_agent_signing_capability_replay(
  p_organization_id uuid, p_device_id uuid, p_session_id uuid,
  p_request_id uuid, p_request_digest bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  reservation_row public.agent_session_signing_capability_reservations%ROWTYPE;
  session_row public.agent_sessions%ROWTYPE;
  remaining_value integer;
  now_value timestamptz := date_trunc('milliseconds', clock_timestamp());
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  SELECT * INTO reservation_row FROM public.agent_session_signing_capability_reservations AS r
    WHERE r.organization_id = p_organization_id AND r.request_id = p_request_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF reservation_row.device_id IS DISTINCT FROM p_device_id
     OR reservation_row.session_id IS DISTINCT FROM p_session_id
     OR reservation_row.request_digest IS DISTINCT FROM p_request_digest
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  SELECT * INTO session_row FROM public.agent_sessions AS s
    WHERE s.organization_id = reservation_row.organization_id
      AND s.session_id = reservation_row.session_id FOR UPDATE;
  remaining_value := greatest(session_row.max_signatures - session_row.used_signatures
    - session_row.reserved_signatures, 0);
  IF reservation_row.state = 'completed' AND reservation_row.expires_at <= now_value THEN
    UPDATE public.agent_session_signing_capability_reservations SET state = 'expired',
      response_json = NULL, expired_at = now_value, updated_at = now_value
    WHERE organization_id = reservation_row.organization_id
      AND reservation_id = reservation_row.reservation_id RETURNING * INTO reservation_row;
  END IF;
  RETURN public.agentpass_agent_signing_capability_record(reservation_row, remaining_value, true);
END;
$$;

CREATE FUNCTION public.agentpass_agent_signing_capability_uncertain(
  p_organization_id uuid, p_device_id uuid, p_session_id uuid, p_request_id uuid,
  p_request_digest bytea, p_claim_token_hash bytea, p_reason text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  reservation_row public.agent_session_signing_capability_reservations%ROWTYPE;
  session_row public.agent_sessions%ROWTYPE;
  now_value timestamptz := date_trunc('milliseconds', clock_timestamp());
BEGIN
  IF p_organization_id IS NULL
     OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF p_reason IS NULL OR p_reason NOT IN
    ('signer_failure', 'signer_output_invalid', 'commit_response_lost', 'commit_failure')
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  SELECT * INTO reservation_row FROM public.agent_session_signing_capability_reservations AS r
    WHERE r.organization_id = p_organization_id AND r.request_id = p_request_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF reservation_row.device_id IS DISTINCT FROM p_device_id
     OR reservation_row.session_id IS DISTINCT FROM p_session_id
     OR reservation_row.request_digest IS DISTINCT FROM p_request_digest
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  IF reservation_row.state = 'outcome_unknown' THEN RETURN jsonb_build_object('state', 'uncertain'); END IF;
  SELECT * INTO session_row FROM public.agent_sessions AS s
    WHERE s.organization_id = reservation_row.organization_id
      AND s.session_id = reservation_row.session_id FOR UPDATE;
  IF reservation_row.state = 'completed' THEN
    RETURN public.agentpass_agent_signing_capability_record(reservation_row,
      greatest(session_row.max_signatures - session_row.used_signatures
        - session_row.reserved_signatures, 0), true);
  END IF;
  IF reservation_row.state <> 'reserved'
     OR reservation_row.claim_token_hash IS DISTINCT FROM p_claim_token_hash
     OR session_row.status <> 'signing_intent'
     OR session_row.active_request_id IS DISTINCT FROM reservation_row.request_id
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  UPDATE public.agent_sessions SET status = 'outcome_unknown', active_request_id = NULL,
    last_request_id = reservation_row.request_id, used_signatures = used_signatures + 1,
    reserved_signatures = reserved_signatures - 1, outcome_unknown_at = now_value
  WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
  UPDATE public.agent_session_signing_capability_reservations SET state = 'outcome_unknown',
    uncertain_reason = p_reason, outcome_unknown_at = now_value, updated_at = now_value
  WHERE organization_id = reservation_row.organization_id
    AND reservation_id = reservation_row.reservation_id;
  RETURN jsonb_build_object('state', 'uncertain');
END;
$$;

CREATE FUNCTION public.agentpass_agent_signing_capability_recover_expired(
  p_batch_size integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  reservation_row public.agent_session_signing_capability_reservations%ROWTYPE;
  session_row public.agent_sessions%ROWTYPE;
  now_value timestamptz := date_trunc('milliseconds', clock_timestamp());
  uncertain_count integer := 0;
  expired_count integer := 0;
BEGIN
  IF p_batch_size IS NULL OR p_batch_size NOT BETWEEN 1 AND 256
  THEN RETURN jsonb_build_object('status', 'invalid'); END IF;
  FOR reservation_row IN
    SELECT * FROM public.agent_session_signing_capability_reservations AS reservation
    WHERE (
      (reservation.state = 'reserved' AND reservation.claim_expires_at <= now_value)
       OR (reservation.state = 'completed' AND reservation.expires_at <= now_value))
    ORDER BY least(reservation.claim_expires_at, reservation.expires_at),
      reservation.organization_id, reservation.reservation_id
    FOR UPDATE SKIP LOCKED LIMIT p_batch_size
  LOOP
    IF reservation_row.state = 'completed' THEN
      UPDATE public.agent_session_signing_capability_reservations
      SET state = 'expired', response_json = NULL, expired_at = now_value, updated_at = now_value
      WHERE organization_id = reservation_row.organization_id
        AND reservation_id = reservation_row.reservation_id;
      expired_count := expired_count + 1;
      CONTINUE;
    END IF;
    SELECT * INTO session_row FROM public.agent_sessions AS session
    WHERE session.organization_id = reservation_row.organization_id
      AND session.session_id = reservation_row.session_id FOR UPDATE;
    IF FOUND AND session_row.status = 'signing_intent'
       AND session_row.active_request_id = reservation_row.request_id
       AND session_row.reserved_signatures > 0
    THEN
      UPDATE public.agent_sessions SET status = 'outcome_unknown', active_request_id = NULL,
        last_request_id = reservation_row.request_id, used_signatures = used_signatures + 1,
        reserved_signatures = reserved_signatures - 1, outcome_unknown_at = now_value
      WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
    END IF;
    UPDATE public.agent_session_signing_capability_reservations
    SET state = 'outcome_unknown', uncertain_reason = 'claim_expired',
      response_json = NULL, outcome_unknown_at = now_value, updated_at = now_value
    WHERE organization_id = reservation_row.organization_id
      AND reservation_id = reservation_row.reservation_id;
    uncertain_count := uncertain_count + 1;
  END LOOP;
  RETURN jsonb_build_object('status', 'ok', 'expired', expired_count, 'uncertain', uncertain_count);
END;
$$;

ALTER TABLE public.agent_session_signing_capability_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_session_signing_capability_reservations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.agent_capability_sequence_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_capability_sequence_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE public.capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.capabilities FORCE ROW LEVEL SECURITY;
-- Expiry recovery is deployment-wide maintenance, not a tenant-scoped API.
-- The migration-owned SECURITY DEFINER function needs an explicit policy to
-- traverse all sessions while the online roles remain unable to read or write
-- these tables directly.
CREATE POLICY agent_sessions_signing_capability_migrator_authority
  ON public.agent_sessions FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY agent_session_signing_capability_reservations_tenant_select
  ON public.agent_session_signing_capability_reservations FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY agent_session_signing_capability_reservations_tenant_insert
  ON public.agent_session_signing_capability_reservations FOR INSERT
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY agent_session_signing_capability_reservations_tenant_update
  ON public.agent_session_signing_capability_reservations FOR UPDATE
  USING (organization_id = public.agentpass_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY agent_session_signing_capability_reservations_backup_select
  ON public.agent_session_signing_capability_reservations FOR SELECT TO agentpass_backup
  USING (true);
CREATE POLICY agent_session_signing_reservations_migrator_authority
  ON public.agent_session_signing_capability_reservations FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY agent_capability_sequence_heads_tenant_select
  ON public.agent_capability_sequence_heads FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY agent_capability_sequence_heads_tenant_insert
  ON public.agent_capability_sequence_heads FOR INSERT
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY agent_capability_sequence_heads_tenant_update
  ON public.agent_capability_sequence_heads FOR UPDATE
  USING (organization_id = public.agentpass_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY agent_capability_sequence_heads_migrator_authority
  ON public.agent_capability_sequence_heads TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY agent_capability_sequence_heads_backup_select
  ON public.agent_capability_sequence_heads FOR SELECT TO agentpass_backup
  USING (true);
CREATE POLICY capabilities_tenant_select
  ON public.capabilities FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY capabilities_tenant_insert
  ON public.capabilities FOR INSERT
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY capabilities_tenant_update
  ON public.capabilities FOR UPDATE
  USING (organization_id = public.agentpass_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
-- Existing database-owned invalidation triggers predate tenant GUCs. They run
-- only as the migration owner and remain reachable solely through reviewed
-- trigger/SECURITY DEFINER paths; online roles have no table privilege.
CREATE POLICY capabilities_migrator_authority
  ON public.capabilities FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY capabilities_backup_select
  ON public.capabilities FOR SELECT TO agentpass_backup
  USING (true);

REVOKE ALL ON TABLE public.agent_session_signing_capability_reservations
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT SELECT ON TABLE public.agent_session_signing_capability_reservations TO agentpass_backup;
REVOKE ALL ON TABLE public.agent_capability_sequence_heads
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT SELECT ON TABLE public.agent_capability_sequence_heads TO agentpass_backup;
REVOKE ALL ON TABLE public.capabilities
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT SELECT ON TABLE public.capabilities TO agentpass_backup;

REVOKE ALL ON FUNCTION public.agentpass_allocate_capability_sequence_on_insert()
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_record(
  public.agent_session_signing_capability_reservations, integer, boolean
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_text_array_json(jsonb)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_scope_canonical_json(jsonb)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_statement_canonical_json(
  public.agent_session_signing_capability_reservations
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_capability_authority_public_json(public.capabilities)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_capability_authority_issue(
  uuid, uuid, uuid, uuid, bigint, text, timestamptz, uuid, bigint
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_capability_authority_revoke_member(uuid, uuid, timestamptz)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_capability_authority_list_revoked(uuid, timestamptz, integer)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_capability_reservation_public_json(public.capabilities)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_capability_reservation_issue(
  uuid, uuid, uuid, uuid, bigint, text, timestamptz, uuid, text, text, jsonb, timestamptz, bytea
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_capability_reservation_list(uuid, integer)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_reserve(
  uuid, uuid, uuid, uuid, bytea, uuid, uuid, bytea, text, text, boolean, integer, bigint
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_commit(
  uuid, uuid, uuid, uuid, bytea, bytea
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_replay(
  uuid, uuid, uuid, uuid, bytea
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_uncertain(
  uuid, uuid, uuid, uuid, bytea, bytea, text
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL ON FUNCTION public.agentpass_agent_signing_capability_recover_expired(integer)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_agent_signing_capability_reserve(
  uuid, uuid, uuid, uuid, bytea, uuid, uuid, bytea, text, text, boolean, integer, bigint
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_agent_signing_capability_commit(
  uuid, uuid, uuid, uuid, bytea, bytea
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_agent_signing_capability_replay(
  uuid, uuid, uuid, uuid, bytea
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_agent_signing_capability_uncertain(
  uuid, uuid, uuid, uuid, bytea, bytea, text
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_agent_signing_capability_recover_expired(integer)
  TO agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_capability_authority_issue(
  uuid, uuid, uuid, uuid, bigint, text, timestamptz, uuid, bigint
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_capability_authority_revoke_member(uuid, uuid, timestamptz)
  TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_capability_authority_list_revoked(uuid, timestamptz, integer)
  TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_capability_reservation_issue(
  uuid, uuid, uuid, uuid, bigint, text, timestamptz, uuid, text, text, jsonb, timestamptz, bytea
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_capability_reservation_list(uuid, integer)
  TO agentpass_app;

COMMENT ON TABLE public.agent_session_signing_capability_reservations IS
  'Function-owned tenant-bound Capability issuance/replay ledger; agent_sessions owns the signature budget.';
COMMENT ON COLUMN public.agent_session_signing_capability_reservations.claim_token_hash IS
  'SHA-256 digest of an application-generated opaque fencing token; clear token is never persisted.';
COMMENT ON COLUMN public.agent_session_signing_capability_reservations.response_json IS
  'Short-lived signed public Capability retained for exact retry and scrubbed after expiry or revocation.';

COMMIT;
