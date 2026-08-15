BEGIN;

-- First-organization creation is a function-only authority boundary. The
-- browser cannot select durable identifiers, membership role, audit content,
-- timestamps, or the replay response.
CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_organization_commit_v2(
  p_bootstrap_cookie_hash bytea,
  p_idempotency_key text,
  p_request_hash bytea,
  p_organization_name text,
  p_organization_id uuid,
  p_membership_id uuid,
  p_audit_event_id uuid
)
RETURNS TABLE (response_status integer, response_json jsonb, replayed boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE;
  prior_row public.hosted_identity_bootstrap_idempotency%ROWTYPE;
  organization_row public.organizations%ROWTYPE;
  membership_count bigint;
  now_value timestamptz := date_trunc('milliseconds', clock_timestamp());
  zero_hash constant text := repeat('0', 64);
  audit_json jsonb;
  audit_hash text;
  public_result jsonb;
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32
     OR octet_length(p_request_hash) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'bootstrap selector and request hash must be SHA-256 digests';
  END IF;
  IF p_idempotency_key IS NULL OR p_idempotency_key !~ '^[A-Za-z0-9._~-]{8,255}$' THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'idempotency key is invalid';
  END IF;
  IF p_organization_name IS NULL
     OR char_length(p_organization_name) NOT BETWEEN 1 AND 128
     OR octet_length(convert_to(p_organization_name, 'UTF8')) > 512
     OR p_organization_name <> btrim(p_organization_name)
     OR p_organization_name ~ '[[:cntrl:]]'
     OR p_organization_name ~ '[[:space:]][[:space:]]' THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'organization name is not normalized';
  END IF;
  IF p_organization_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_membership_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_audit_event_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_organization_id = p_membership_id
     OR p_organization_id = p_audit_event_id
     OR p_membership_id = p_audit_event_id THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'server identifiers are invalid';
  END IF;

  SELECT * INTO attempt_row
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
  FOR UPDATE;
  IF NOT FOUND OR attempt_row.expires_at <= now_value OR attempt_row.state = 'expired' THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap attempt is absent or expired';
  END IF;

  SELECT * INTO prior_row
  FROM public.hosted_identity_bootstrap_idempotency AS i
  WHERE i.member_id = attempt_row.member_id
    AND i.operation = 'first_organization_create'
    AND i.idempotency_key = p_idempotency_key
  FOR UPDATE;
  IF FOUND THEN
    IF prior_row.request_hash IS DISTINCT FROM p_request_hash THEN
      RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'idempotency key was reused with a different request';
    END IF;
    RETURN QUERY SELECT 200, prior_row.response_json, true;
    RETURN;
  END IF;

  IF p_request_hash IS DISTINCT FROM sha256(convert_to(p_organization_name, 'UTF8')) THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'organization request hash is invalid';
  END IF;

  IF attempt_row.state <> 'organization_required' OR attempt_row.organization_id IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'first organization bootstrap is already completed';
  END IF;

  -- This conflicts with membership FK key-share locks. Consequently a
  -- concurrent membership insertion either becomes visible before this full
  -- history check or waits until this transaction has committed.
  PERFORM 1 FROM public.members AS m WHERE m.id = attempt_row.member_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'bootstrap member is absent';
  END IF;
  SELECT count(*) INTO membership_count
  FROM public.memberships AS m
  WHERE m.member_id = attempt_row.member_id;
  IF membership_count <> 0 THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'member has organization membership history';
  END IF;

  INSERT INTO public.organizations (id, name, version, created_at, updated_at)
  VALUES (p_organization_id, p_organization_name, 1, now_value, now_value)
  RETURNING * INTO organization_row;
  INSERT INTO public.memberships
    (organization_id, id, member_id, role, status, version, created_at, updated_at)
  VALUES
    (organization_row.id, p_membership_id, attempt_row.member_id, 'owner', 'active', 1, now_value, now_value);

  public_result := jsonb_build_object(
    'version', 1,
    'organization', jsonb_build_object(
      'organization_id', organization_row.id,
      'name', organization_row.name,
      'version', organization_row.version,
      'created_at', organization_row.created_at,
      'updated_at', organization_row.updated_at
    ),
    'onboarding', jsonb_build_object('state', 'webauthn_required')
  );

  INSERT INTO public.hosted_identity_bootstrap_idempotency
    (attempt_id, member_id, organization_id, membership_id, operation,
     idempotency_key, request_hash, response_status, response_json, committed_at)
  VALUES
    (attempt_row.id, attempt_row.member_id, organization_row.id, p_membership_id,
     'first_organization_create', p_idempotency_key, p_request_hash, 201,
     public_result, now_value);

  -- organizations_create_admin_audit_head created sequence zero in this same
  -- transaction. Build the exact stored preimage in PostgreSQL so neither the
  -- caller nor JSON serialization differences can select audit evidence.
  PERFORM 1 FROM public.admin_audit_heads AS h
  WHERE h.organization_id = organization_row.id AND h.sequence = 0 AND h.event_hash = zero_hash
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'initial audit head is unavailable';
  END IF;
  audit_json := jsonb_build_object(
    'version', 1,
    'audit_event_id', p_audit_event_id,
    'organization_id', organization_row.id,
    'actor_id', attempt_row.member_id,
    'action', 'organization.created',
    'target_type', 'organization',
    'target_id', organization_row.id,
    'details', jsonb_build_object('role', 'owner', 'source', 'hosted_bootstrap'),
    'previous_hash', zero_hash,
    'sequence', 1
  );
  audit_hash := encode(sha256(convert_to(audit_json::text, 'UTF8')), 'hex');
  INSERT INTO public.admin_audit_events
    (organization_id, id, actor_id, action, target_type, target_id,
     previous_hash, event_hash, sequence, event_json, created_at)
  VALUES
    (organization_row.id, p_audit_event_id, attempt_row.member_id,
     'organization.created', 'organization', organization_row.id,
     zero_hash, audit_hash, 1, audit_json, now_value);
  UPDATE public.admin_audit_heads
  SET sequence = 1, event_hash = audit_hash, updated_at = now_value
  WHERE organization_id = organization_row.id AND sequence = 0 AND event_hash = zero_hash;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'initial audit head changed during bootstrap';
  END IF;

  UPDATE public.hosted_identity_bootstrap_attempts
  SET state = 'webauthn_required', organization_id = organization_row.id,
      membership_id = p_membership_id, version = version + 1
  WHERE id = attempt_row.id AND state = 'organization_required'
    AND organization_id IS NULL AND membership_id IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'bootstrap attempt changed during organization creation';
  END IF;

  RETURN QUERY SELECT 201, public_result, false;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_organization_commit_v2(bytea, text, bytea, text, uuid, uuid, uuid) FROM PUBLIC;

COMMIT;
