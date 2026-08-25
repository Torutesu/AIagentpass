BEGIN;

-- Expiry evidence is separate from the public Capability response.  It is
-- deliberately secret-free and does not require a Human member actor: the
-- durable Agent Session/Capability identifiers are the subject, while the
-- database transition path supplies the cause.
CREATE TABLE public.agent_session_signing_capability_expiry_audit_events (
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  event_sequence bigint NOT NULL CHECK (event_sequence > 0),
  event_id uuid NOT NULL,
  reservation_id uuid NOT NULL,
  request_id uuid NOT NULL,
  capability_id uuid NOT NULL,
  session_id uuid NOT NULL,
  from_state text NOT NULL CHECK (from_state IN ('reserved', 'completed')),
  to_state text NOT NULL CHECK (to_state IN ('outcome_unknown', 'expired')),
  cause text NOT NULL CHECK (cause IN ('maintenance', 'reserve', 'replay')),
  capability_expires_at timestamptz NOT NULL,
  transition_expires_at timestamptz NOT NULL,
  observed_at timestamptz NOT NULL,
  previous_event_hash bytea NOT NULL CHECK (octet_length(previous_event_hash) = 32),
  event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
  PRIMARY KEY (organization_id, event_id),
  UNIQUE (organization_id, event_sequence),
  UNIQUE (organization_id, reservation_id),
  UNIQUE (organization_id, event_hash),
  FOREIGN KEY (organization_id, reservation_id)
    REFERENCES public.agent_session_signing_capability_reservations(organization_id, reservation_id),
  CHECK ((from_state = 'reserved' AND to_state = 'outcome_unknown')
      OR (from_state = 'completed' AND to_state = 'expired')),
  CHECK (transition_expires_at <= capability_expires_at),
  CHECK (observed_at >= transition_expires_at),
  CHECK (date_trunc('milliseconds', observed_at) = observed_at)
);

CREATE TABLE public.agent_session_signing_capability_expiry_audit_heads (
  organization_id uuid PRIMARY KEY REFERENCES public.organizations(id),
  event_sequence bigint NOT NULL DEFAULT 0 CHECK (event_sequence >= 0),
  last_event_id uuid,
  last_event_hash bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
    CHECK (octet_length(last_event_hash) = 32),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((event_sequence = 0 AND last_event_id IS NULL
      AND last_event_hash = decode(repeat('00', 32), 'hex'))
      OR (event_sequence > 0 AND last_event_id IS NOT NULL
      AND last_event_hash <> decode(repeat('00', 32), 'hex'))),
  FOREIGN KEY (organization_id, last_event_id)
    REFERENCES public.agent_session_signing_capability_expiry_audit_events(organization_id, event_id)
);

CREATE FUNCTION public.agentpass_agent_session_signing_capability_expiry_audit_hash(
  p_organization_id uuid, p_event_sequence bigint, p_event_id uuid,
  p_reservation_id uuid, p_request_id uuid, p_capability_id uuid,
  p_session_id uuid, p_from_state text, p_to_state text, p_cause text,
  p_capability_expires_at timestamptz, p_transition_expires_at timestamptz,
  p_observed_at timestamptz,
  p_previous_event_hash bytea
) RETURNS bytea LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT sha256(convert_to(concat_ws('|',
    'AgentPass-Agent-Session-Signing-Capability-Expiry-Audit-v1',
    '1', p_organization_id::text, p_event_sequence::text, p_event_id::text,
    p_reservation_id::text, p_request_id::text, p_capability_id::text,
    p_session_id::text, p_from_state, p_to_state, p_cause,
    to_char(p_capability_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    to_char(p_transition_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    to_char(p_observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    encode(p_previous_event_hash, 'hex')), 'UTF8'))
$$;

CREATE FUNCTION public.agentpass_validate_agent_session_signing_capability_expiry_audit_chain()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
DECLARE
  head public.agent_session_signing_capability_expiry_audit_heads%ROWTYPE;
BEGIN
  INSERT INTO public.agent_session_signing_capability_expiry_audit_heads (organization_id)
  VALUES (NEW.organization_id)
  ON CONFLICT (organization_id) DO NOTHING;

  SELECT * INTO head
  FROM public.agent_session_signing_capability_expiry_audit_heads
  WHERE organization_id = NEW.organization_id
  FOR UPDATE;

  IF NEW.event_sequence <> head.event_sequence + 1
     OR NEW.previous_event_hash IS DISTINCT FROM head.last_event_hash
     OR NEW.event_hash IS DISTINCT FROM public.agentpass_agent_session_signing_capability_expiry_audit_hash(
       NEW.organization_id, NEW.event_sequence, NEW.event_id,
           NEW.reservation_id, NEW.request_id, NEW.capability_id, NEW.session_id,
           NEW.from_state, NEW.to_state, NEW.cause, NEW.capability_expires_at,
           NEW.transition_expires_at, NEW.observed_at, NEW.previous_event_hash)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'agent_session_signing_capability_expiry_audit_chain',
      MESSAGE = 'Agent Session signing-capability expiry audit chain is invalid';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_record_agent_session_signing_capability_expiry_audit_head()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE public.agent_session_signing_capability_expiry_audit_heads
  SET event_sequence = NEW.event_sequence,
      last_event_id = NEW.event_id,
      last_event_hash = NEW.event_hash,
      updated_at = clock_timestamp()
  WHERE organization_id = NEW.organization_id;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_guard_agent_session_signing_capability_expiry_audit_append_only()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'check_violation',
    CONSTRAINT = 'agent_session_signing_capability_expiry_audit_append_only',
    MESSAGE = 'Agent Session signing-capability expiry audit events are append-only';
END;
$$;

CREATE FUNCTION public.agentpass_guard_agent_session_signing_capability_expiry_audit_head()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'agent_session_signing_capability_expiry_audit_head_forward_only',
      MESSAGE = 'Agent Session signing-capability expiry audit heads cannot be deleted';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.event_sequence <> OLD.event_sequence + 1
     OR NOT EXISTS (
       SELECT 1
       FROM public.agent_session_signing_capability_expiry_audit_events AS event
       WHERE event.organization_id = NEW.organization_id
         AND event.event_sequence = NEW.event_sequence
         AND event.event_id = NEW.last_event_id
         AND event.event_hash = NEW.last_event_hash
         AND event.previous_event_hash = OLD.last_event_hash)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'agent_session_signing_capability_expiry_audit_head_forward_only',
      MESSAGE = 'Agent Session signing-capability expiry audit head is not forward-only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER agent_session_signing_capability_expiry_audit_events_validate_chain
  BEFORE INSERT ON public.agent_session_signing_capability_expiry_audit_events
  FOR EACH ROW EXECUTE FUNCTION public.agentpass_validate_agent_session_signing_capability_expiry_audit_chain();
CREATE TRIGGER agent_session_signing_capability_expiry_audit_events_record_head
  AFTER INSERT ON public.agent_session_signing_capability_expiry_audit_events
  FOR EACH ROW EXECUTE FUNCTION public.agentpass_record_agent_session_signing_capability_expiry_audit_head();
CREATE TRIGGER agent_session_signing_capability_expiry_audit_events_append_only
  BEFORE UPDATE OR DELETE ON public.agent_session_signing_capability_expiry_audit_events
  FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_agent_session_signing_capability_expiry_audit_append_only();
CREATE TRIGGER agent_session_signing_capability_expiry_audit_heads_forward_only
  BEFORE UPDATE OR DELETE ON public.agent_session_signing_capability_expiry_audit_heads
  FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_agent_session_signing_capability_expiry_audit_head();

CREATE FUNCTION public.agentpass_append_agent_session_signing_capability_expiry_audit(
  p_organization_id uuid, p_reservation_id uuid, p_from_state text,
  p_to_state text, p_cause text, p_observed_at timestamptz
) RETURNS uuid LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  reservation_row public.agent_session_signing_capability_reservations%ROWTYPE;
  head_row public.agent_session_signing_capability_expiry_audit_heads%ROWTYPE;
  event_id_value uuid := gen_random_uuid();
  event_hash_value bytea;
  transition_expires_at_value timestamptz;
BEGIN
  IF p_organization_id IS NULL OR p_reservation_id IS NULL
     OR p_from_state IS NULL OR p_to_state IS NULL OR p_cause IS NULL
     OR p_observed_at IS NULL
     OR p_cause NOT IN ('maintenance', 'reserve', 'replay')
     OR NOT ((p_from_state = 'reserved' AND p_to_state = 'outcome_unknown')
          OR (p_from_state = 'completed' AND p_to_state = 'expired'))
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'agent_session_signing_capability_expiry_audit_input',
      MESSAGE = 'Agent Session signing-capability expiry audit input is invalid';
  END IF;

  SELECT * INTO reservation_row
  FROM public.agent_session_signing_capability_reservations AS reservation
  WHERE reservation.organization_id = p_organization_id
    AND reservation.reservation_id = p_reservation_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'agent_session_signing_capability_expiry_audit_reservation',
      MESSAGE = 'Agent Session signing-capability expiry audit reservation is missing';
  END IF;

  INSERT INTO public.agent_session_signing_capability_expiry_audit_heads (organization_id)
  VALUES (p_organization_id)
  ON CONFLICT (organization_id) DO NOTHING;
  SELECT * INTO head_row
  FROM public.agent_session_signing_capability_expiry_audit_heads
  WHERE organization_id = p_organization_id
  FOR UPDATE;

  event_hash_value := public.agentpass_agent_session_signing_capability_expiry_audit_hash(
    p_organization_id, head_row.event_sequence + 1, event_id_value,
    reservation_row.reservation_id, reservation_row.request_id,
    reservation_row.capability_id, reservation_row.session_id, p_from_state,
    p_to_state, p_cause, reservation_row.expires_at,
    CASE WHEN p_from_state = 'reserved' THEN reservation_row.claim_expires_at
      ELSE reservation_row.expires_at END,
    p_observed_at,
    head_row.last_event_hash);
  transition_expires_at_value := CASE WHEN p_from_state = 'reserved'
    THEN reservation_row.claim_expires_at ELSE reservation_row.expires_at END;

  INSERT INTO public.agent_session_signing_capability_expiry_audit_events (
    organization_id, event_sequence, event_id, reservation_id, request_id,
    capability_id, session_id, from_state, to_state, cause,
    capability_expires_at, transition_expires_at, observed_at,
    previous_event_hash, event_hash
  ) VALUES (
    p_organization_id, head_row.event_sequence + 1, event_id_value,
    reservation_row.reservation_id, reservation_row.request_id,
    reservation_row.capability_id, reservation_row.session_id, p_from_state,
    p_to_state, p_cause, reservation_row.expires_at,
    transition_expires_at_value, p_observed_at,
    head_row.last_event_hash, event_hash_value
  );
  RETURN event_id_value;
END;
$$;

CREATE OR REPLACE FUNCTION public.agentpass_agent_signing_capability_reserve(
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
      PERFORM public.agentpass_append_agent_session_signing_capability_expiry_audit(
        existing_row.organization_id, existing_row.reservation_id,
        'reserved', 'outcome_unknown', 'reserve', now_value);
      RETURN jsonb_build_object('state', 'uncertain');
    END IF;
    RETURN public.agentpass_agent_signing_capability_record(existing_row, coalesce(remaining_value, 0), true);
  END IF;

  SELECT * INTO session_row FROM public.agent_sessions AS s
  WHERE s.organization_id = p_organization_id AND s.session_id = p_session_id
    AND s.device_id = p_device_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'absent'); END IF;
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
  SELECT sequence INTO next_sequence FROM public.agent_capability_sequence_heads
  WHERE organization_id = session_row.organization_id AND agent_id = session_row.agent_id FOR UPDATE;
  next_sequence := next_sequence + 1;
  UPDATE public.agent_capability_sequence_heads SET sequence = next_sequence, updated_at = now_value
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
  signing_bytes := convert_to('AgentPass-Agent-Signing-Capability-v1', 'UTF8') || decode('00', 'hex') || convert_to(statement_text, 'UTF8');
  statement_digest := sha256(convert_to(statement_text, 'UTF8'));
  signing_digest := sha256(signing_bytes);
  provider_request_json := '{"algorithm":"ed25519","bytes":' || to_json(replace(encode(signing_bytes, 'base64'), chr(10), ''))::text ||
    ',"key_id":' || to_json(signer_row.key_id)::text || ',"key_version":' || signer_row.key_version::text ||
    ',"purpose":"git.commit.sign","version":1}';
  provider_request_digest_value := sha256(convert_to(provider_request_json, 'UTF8'));
  provider_operation_id_value := 'managed-signer-v1-' || encode(provider_request_digest_value, 'hex');
  UPDATE public.agent_sessions SET status = 'request_reserved', reserved_signatures = reserved_signatures + 1, active_request_id = p_request_id
  WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
  UPDATE public.agent_sessions SET status = 'signing_intent'
  WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
  INSERT INTO public.agent_session_signing_capability_reservations (
    organization_id, reservation_id, request_id, request_digest, capability_id, session_id, grant_id, device_id, agent_id, grant_hash, sequence, operation,
    key_purpose, key_id, key_version, algorithm, scope_json, control_sequence, authority_generation, claim_token_hash, claim_expires_at, state, capability_statement_hash,
    planned_provider_operation_id, provider_request_digest, provider_bytes_length, signing_bytes_digest, issued_at, not_before, expires_at, created_at, updated_at
  ) VALUES (
    session_row.organization_id, p_reservation_id, p_request_id, p_request_digest, p_capability_id, session_row.session_id, session_row.grant_id, session_row.device_id,
    session_row.agent_id, session_row.grant_hash, next_sequence, p_operation, p_key_purpose, signer_row.key_id, signer_row.key_version, signer_row.algorithm, grant_row.scope_json,
    session_row.control_sequence, session_row.authority_generation, p_claim_token_hash, claim_expiry_value, 'reserved', statement_digest, provider_operation_id_value,
    provider_request_digest_value, octet_length(signing_bytes), signing_digest, now_value, now_value, expiry_value, now_value, now_value
  ) RETURNING * INTO existing_row;
  remaining_value := session_row.max_signatures - session_row.used_signatures - session_row.reserved_signatures - 1;
  RETURN jsonb_build_object('state', 'reserved', 'claim_issued', true, 'capability_id', existing_row.capability_id,
    'organization_id', existing_row.organization_id, 'session_id', existing_row.session_id, 'device_id', existing_row.device_id, 'agent_id', existing_row.agent_id,
    'scope', existing_row.scope_json, 'sequence', existing_row.sequence, 'control_sequence', existing_row.control_sequence,
    'authority_generation', existing_row.authority_generation,
    'issued_at', to_char(existing_row.issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'not_before', to_char(existing_row.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'expires_at', to_char(existing_row.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'remaining_session_signatures', remaining_value);
END;
$$;

CREATE OR REPLACE FUNCTION public.agentpass_agent_signing_capability_replay(
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
  IF p_organization_id IS NULL OR public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id
  THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  SELECT * INTO reservation_row FROM public.agent_session_signing_capability_reservations AS r
    WHERE r.organization_id = p_organization_id AND r.request_id = p_request_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('state', 'absent'); END IF;
  IF reservation_row.device_id IS DISTINCT FROM p_device_id OR reservation_row.session_id IS DISTINCT FROM p_session_id
     OR reservation_row.request_digest IS DISTINCT FROM p_request_digest
  THEN RETURN jsonb_build_object('state', 'conflict'); END IF;
  SELECT * INTO session_row FROM public.agent_sessions AS s
    WHERE s.organization_id = reservation_row.organization_id AND s.session_id = reservation_row.session_id FOR UPDATE;
  remaining_value := greatest(session_row.max_signatures - session_row.used_signatures - session_row.reserved_signatures, 0);
  IF reservation_row.state = 'completed' AND reservation_row.expires_at <= now_value THEN
    UPDATE public.agent_session_signing_capability_reservations SET state = 'expired', response_json = NULL, expired_at = now_value, updated_at = now_value
    WHERE organization_id = reservation_row.organization_id AND reservation_id = reservation_row.reservation_id RETURNING * INTO reservation_row;
    PERFORM public.agentpass_append_agent_session_signing_capability_expiry_audit(
      reservation_row.organization_id, reservation_row.reservation_id, 'completed', 'expired', 'replay', now_value);
  END IF;
  RETURN public.agentpass_agent_signing_capability_record(reservation_row, remaining_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION public.agentpass_agent_signing_capability_recover_expired(
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
    WHERE ((reservation.state = 'reserved' AND reservation.claim_expires_at <= now_value)
       OR (reservation.state = 'completed' AND reservation.expires_at <= now_value))
    ORDER BY least(reservation.claim_expires_at, reservation.expires_at), reservation.organization_id, reservation.reservation_id
    FOR UPDATE SKIP LOCKED LIMIT p_batch_size
  LOOP
    IF reservation_row.state = 'completed' THEN
      UPDATE public.agent_session_signing_capability_reservations
      SET state = 'expired', response_json = NULL, expired_at = now_value, updated_at = now_value
      WHERE organization_id = reservation_row.organization_id AND reservation_id = reservation_row.reservation_id;
      PERFORM public.agentpass_append_agent_session_signing_capability_expiry_audit(
        reservation_row.organization_id, reservation_row.reservation_id,
        'completed', 'expired', 'maintenance', now_value);
      expired_count := expired_count + 1;
      CONTINUE;
    END IF;
    SELECT * INTO session_row FROM public.agent_sessions AS session
    WHERE session.organization_id = reservation_row.organization_id AND session.session_id = reservation_row.session_id FOR UPDATE;
    IF FOUND AND session_row.status = 'signing_intent' AND session_row.active_request_id = reservation_row.request_id
       AND session_row.reserved_signatures > 0
    THEN
      UPDATE public.agent_sessions SET status = 'outcome_unknown', active_request_id = NULL,
        last_request_id = reservation_row.request_id, used_signatures = used_signatures + 1,
        reserved_signatures = reserved_signatures - 1, outcome_unknown_at = now_value
      WHERE organization_id = session_row.organization_id AND session_id = session_row.session_id;
    END IF;
    UPDATE public.agent_session_signing_capability_reservations
    SET state = 'outcome_unknown', uncertain_reason = 'claim_expired', response_json = NULL,
      outcome_unknown_at = now_value, updated_at = now_value
    WHERE organization_id = reservation_row.organization_id AND reservation_id = reservation_row.reservation_id;
    PERFORM public.agentpass_append_agent_session_signing_capability_expiry_audit(
      reservation_row.organization_id, reservation_row.reservation_id,
      'reserved', 'outcome_unknown', 'maintenance', now_value);
    uncertain_count := uncertain_count + 1;
  END LOOP;
  RETURN jsonb_build_object('status', 'ok', 'expired', expired_count, 'uncertain', uncertain_count);
END;
$$;

ALTER TABLE public.agent_session_signing_capability_expiry_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_session_signing_capability_expiry_audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.agent_session_signing_capability_expiry_audit_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_session_signing_capability_expiry_audit_heads FORCE ROW LEVEL SECURITY;

CREATE POLICY cap_expiry_events_tenant_select
  ON public.agent_session_signing_capability_expiry_audit_events FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY cap_expiry_events_migrator_authority
  ON public.agent_session_signing_capability_expiry_audit_events FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY cap_expiry_events_backup_select
  ON public.agent_session_signing_capability_expiry_audit_events FOR SELECT TO agentpass_backup
  USING (true);
CREATE POLICY cap_expiry_heads_tenant_select
  ON public.agent_session_signing_capability_expiry_audit_heads FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY cap_expiry_heads_migrator_authority
  ON public.agent_session_signing_capability_expiry_audit_heads FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY cap_expiry_heads_backup_select
  ON public.agent_session_signing_capability_expiry_audit_heads FOR SELECT TO agentpass_backup
  USING (true);

REVOKE ALL ON TABLE public.agent_session_signing_capability_expiry_audit_events,
  public.agent_session_signing_capability_expiry_audit_heads
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_maintenance;
REVOKE ALL ON FUNCTION public.agentpass_agent_session_signing_capability_expiry_audit_hash(
  uuid,bigint,uuid,uuid,uuid,uuid,uuid,text,text,text,timestamptz,timestamptz,timestamptz,bytea
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL ON FUNCTION public.agentpass_append_agent_session_signing_capability_expiry_audit(
  uuid,uuid,text,text,text,timestamptz
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;

COMMENT ON TABLE public.agent_session_signing_capability_expiry_audit_events IS
  'Append-only, tenant-qualified, hash-chained, secret-free evidence for Agent Session signing-capability expiry transitions.';
COMMENT ON TABLE public.agent_session_signing_capability_expiry_audit_heads IS
  'Per-tenant predecessor hash head for Agent Session signing-capability expiry evidence.';

COMMIT;
