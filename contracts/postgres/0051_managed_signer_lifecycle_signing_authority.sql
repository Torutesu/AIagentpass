BEGIN;

-- 0051 is the database authority for the four managed-signer tables created by
-- 0037-0039.  Application code supplies only opaque operation identifiers,
-- request digests, public key metadata, and the SHA-256 digest of a claim
-- token.  The clear claim token never crosses this boundary.

CREATE FUNCTION public.agentpass_managed_signer_envelope(
  p_outcome text,
  p_payload jsonb
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object('outcome', p_outcome)
         || CASE WHEN jsonb_typeof(coalesce(p_payload, '{}'::jsonb)) = 'object'
                 THEN coalesce(p_payload, '{}'::jsonb)
                 ELSE '{}'::jsonb END
  WHERE p_outcome IN (
    'ok', 'absent', 'conflict', 'pending', 'uncertain', 'claim_lost',
    'configuration_conflict', 'not_initialized', 'not_active'
  );
$$;

CREATE FUNCTION public.agentpass_managed_signer_snapshot_is_valid(
  p_snapshot jsonb,
  p_purpose text,
  p_algorithm text,
  p_max_keys integer,
  p_max_verification_overlap_ms bigint,
  p_allow_expired_retiring boolean
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  key_value jsonb;
  key_version bigint;
  state_version bigint;
  snapshot_version bigint;
  key_count integer;
  active_count integer;
  now_at timestamptz := pg_catalog.clock_timestamp();
  verification_until timestamptz;
  verification_text text;
  key_id text;
  fingerprint text;
  state text;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_algorithm IS DISTINCT FROM 'ed25519'
     OR p_max_keys IS NULL OR p_max_keys < 1 OR p_max_keys > 32
     OR p_max_verification_overlap_ms IS NULL
     OR p_max_verification_overlap_ms < 1
     OR p_max_verification_overlap_ms > 31536000000
     OR p_snapshot IS NULL OR jsonb_typeof(p_snapshot) IS DISTINCT FROM 'object'
  THEN
    RETURN false;
  END IF;

  IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_snapshot)) <> 4
     OR NOT (p_snapshot ? 'version')
     OR NOT (p_snapshot ? 'purpose')
     OR NOT (p_snapshot ? 'algorithm')
     OR NOT (p_snapshot ? 'keys')
     OR jsonb_typeof(p_snapshot->'version') IS DISTINCT FROM 'number'
     OR jsonb_typeof(p_snapshot->'purpose') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_snapshot->'algorithm') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_snapshot->'keys') IS DISTINCT FROM 'array'
     OR p_snapshot->>'purpose' IS DISTINCT FROM p_purpose
     OR p_snapshot->>'algorithm' IS DISTINCT FROM p_algorithm
     OR p_snapshot->>'version' !~ '^[1-9][0-9]{0,18}$'
  THEN
    RETURN false;
  END IF;

  snapshot_version := (p_snapshot->>'version')::bigint;
  key_count := pg_catalog.jsonb_array_length(p_snapshot->'keys');
  IF snapshot_version < 1 OR key_count < 1 OR key_count > p_max_keys THEN
    RETURN false;
  END IF;

  active_count := 0;
  FOR key_value IN SELECT value FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') LOOP
    IF jsonb_typeof(key_value) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(key_value)) NOT BETWEEN 7 AND 9
       OR NOT (key_value ? 'key_id')
       OR NOT (key_value ? 'key_version')
       OR NOT (key_value ? 'purpose')
       OR NOT (key_value ? 'algorithm')
       OR NOT (key_value ? 'public_key_fingerprint')
       OR NOT (key_value ? 'state')
       OR NOT (key_value ? 'state_version')
       OR EXISTS (
         SELECT 1
         FROM pg_catalog.jsonb_object_keys(key_value) AS field(name)
         WHERE field.name NOT IN (
           'key_id', 'key_version', 'purpose', 'algorithm',
           'public_key_fingerprint', 'state', 'state_version',
           'public_key', 'verification_until'
         )
       )
    THEN
      RETURN false;
    END IF;

    key_id := key_value->>'key_id';
    fingerprint := key_value->>'public_key_fingerprint';
    state := key_value->>'state';
    IF jsonb_typeof(key_value->'key_id') IS DISTINCT FROM 'string'
       OR key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
       OR jsonb_typeof(key_value->'key_version') IS DISTINCT FROM 'number'
       OR key_value->>'key_version' !~ '^[1-9][0-9]{0,18}$'
       OR jsonb_typeof(key_value->'purpose') IS DISTINCT FROM 'string'
       OR key_value->>'purpose' IS DISTINCT FROM p_purpose
       OR jsonb_typeof(key_value->'algorithm') IS DISTINCT FROM 'string'
       OR key_value->>'algorithm' IS DISTINCT FROM p_algorithm
       OR jsonb_typeof(key_value->'public_key_fingerprint') IS DISTINCT FROM 'string'
       OR fingerprint !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(key_value->'state') IS DISTINCT FROM 'string'
       OR state NOT IN ('active', 'retiring', 'revoked', 'emergency-disabled')
       OR jsonb_typeof(key_value->'state_version') IS DISTINCT FROM 'number'
       OR key_value->>'state_version' !~ '^[1-9][0-9]{0,18}$'
    THEN
      RETURN false;
    END IF;

    key_version := (key_value->>'key_version')::bigint;
    state_version := (key_value->>'state_version')::bigint;
    IF state_version > snapshot_version THEN
      RETURN false;
    END IF;

    IF key_value ? 'public_key' THEN
      IF jsonb_typeof(key_value->'public_key') IS DISTINCT FROM 'string'
         OR octet_length(key_value->>'public_key') NOT BETWEEN 1 AND 8192
         OR key_value->>'public_key' ~* 'PRIVATE[[:space:]_-]*KEY'
      THEN
        RETURN false;
      END IF;
    END IF;

    IF state = 'active' THEN
      active_count := active_count + 1;
    END IF;

    IF state = 'retiring' THEN
      IF NOT (key_value ? 'verification_until')
         OR jsonb_typeof(key_value->'verification_until') IS DISTINCT FROM 'string'
      THEN
        RETURN false;
      END IF;
      verification_text := key_value->>'verification_until';
      IF verification_text !~ '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'
         OR pg_catalog.to_char(
              verification_text::timestamptz AT TIME ZONE 'UTC',
              'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ) IS DISTINCT FROM verification_text
      THEN
        RETURN false;
      END IF;
      verification_until := verification_text::timestamptz;
      IF (NOT p_allow_expired_retiring AND verification_until <= now_at)
         OR verification_until > now_at
             + (p_max_verification_overlap_ms::double precision * interval '1 millisecond')
      THEN
        RETURN false;
      END IF;
    ELSIF key_value ? 'verification_until' THEN
      RETURN false;
    END IF;
  END LOOP;

  IF active_count > 1 THEN
    RETURN false;
  END IF;

  IF (SELECT count(DISTINCT value->>'key_id')
      FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') AS item(value)) <> key_count
     OR (SELECT count(DISTINCT value->>'key_version')
         FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') AS item(value)) <> key_count
     OR (SELECT count(DISTINCT value->>'public_key_fingerprint')
         FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') AS item(value)) <> key_count
  THEN
    RETURN false;
  END IF;

  RETURN true;
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_key_identity(p_key jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT coalesce(p_key, '{}'::jsonb)
         - ARRAY['state', 'state_version', 'verification_until']::text[];
$$;

CREATE FUNCTION public.agentpass_managed_signer_transition_kind(
  p_current jsonb,
  p_target jsonb
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  current_keys jsonb := p_current->'keys';
  target_keys jsonb := p_target->'keys';
  current_length integer;
  target_length integer;
  target_version bigint;
  index_value integer;
  changed_count integer := 0;
  non_emergency_count integer := 0;
  current_key jsonb;
  target_key jsonb;
  current_active jsonb;
  target_new_key jsonb;
  current_active_index integer := -1;
  current_max_version bigint := 0;
  current_state text;
  target_state text;
BEGIN
  IF p_current IS NULL OR p_target IS NULL
     OR jsonb_typeof(p_current) IS DISTINCT FROM 'object'
     OR jsonb_typeof(p_target) IS DISTINCT FROM 'object'
     OR jsonb_typeof(current_keys) IS DISTINCT FROM 'array'
     OR jsonb_typeof(target_keys) IS DISTINCT FROM 'array'
     OR (p_target->>'version') !~ '^[1-9][0-9]{0,18}$'
  THEN
    RETURN NULL;
  END IF;

  target_version := (p_target->>'version')::bigint;
  IF target_version <> (p_current->>'version')::bigint + 1 THEN
    RETURN NULL;
  END IF;

  current_length := pg_catalog.jsonb_array_length(current_keys);
  target_length := pg_catalog.jsonb_array_length(target_keys);

  FOR index_value IN 0..current_length - 1 LOOP
    current_key := current_keys->index_value;
    current_state := current_key->>'state';
    IF current_state = 'active' THEN
      current_active_index := index_value;
      current_active := current_key;
    END IF;
    current_max_version := greatest(current_max_version, (current_key->>'key_version')::bigint);
  END LOOP;

  IF current_length = target_length THEN
    -- Emergency disable refreshes the state epoch of every key, including
    -- keys already in the terminal state.  Recognize this atomic shape before
    -- the single-key graph so a terminal epoch refresh is not mistaken for an
    -- illegal same-state transition.
    FOR index_value IN 0..current_length - 1 LOOP
      current_key := current_keys->index_value;
      target_key := target_keys->index_value;
      IF public.agentpass_managed_signer_key_identity(current_key)
           IS DISTINCT FROM public.agentpass_managed_signer_key_identity(target_key)
         OR target_key->>'state' <> 'emergency-disabled'
         OR target_key->>'state_version' <> target_version::text
         OR target_key ? 'verification_until'
      THEN
        non_emergency_count := -1;
        EXIT;
      END IF;
      IF current_key->>'state' <> 'emergency-disabled' THEN
        non_emergency_count := non_emergency_count + 1;
      END IF;
    END LOOP;
    IF non_emergency_count > 0 THEN
      RETURN 'emergency-disable-all';
    END IF;

    -- A single-key transition preserves the ordered key set and all immutable
    -- key metadata.  Exactly one state may change, and only along the legal
    -- lifecycle graph.
    FOR index_value IN 0..current_length - 1 LOOP
      current_key := current_keys->index_value;
      target_key := target_keys->index_value;
      IF current_key->>'key_id' IS DISTINCT FROM target_key->>'key_id'
         OR public.agentpass_managed_signer_key_identity(current_key)
            IS DISTINCT FROM public.agentpass_managed_signer_key_identity(target_key)
      THEN
        RETURN NULL;
      END IF;
      IF current_key IS DISTINCT FROM target_key THEN
        changed_count := changed_count + 1;
        current_state := current_key->>'state';
        target_state := target_key->>'state';
        IF target_key->>'state_version' <> target_version::text
           OR (current_state = 'active' AND target_state NOT IN ('retiring', 'revoked', 'emergency-disabled'))
           OR (current_state = 'retiring' AND target_state NOT IN ('revoked', 'emergency-disabled'))
           OR (current_state = 'revoked' AND target_state <> 'emergency-disabled')
           OR current_state = 'emergency-disabled'
           OR current_state = target_state
        THEN
          RETURN NULL;
        END IF;
      END IF;
    END LOOP;
    IF changed_count = 1 THEN
      RETURN 'single-key';
    END IF;
    RETURN NULL;
  END IF;

  IF target_length <> current_length + 1 THEN
    RETURN NULL;
  END IF;

  -- Both rotate and restore append exactly one immutable key.  Existing keys
  -- must stay in their original positions; the appended key must be newer
  -- than every historical key and be the sole active key.
  FOR index_value IN 0..current_length - 1 LOOP
    current_key := current_keys->index_value;
    target_key := target_keys->index_value;
    IF current_key IS DISTINCT FROM target_key THEN
      IF current_key->>'state' <> 'active'
         OR target_key->>'state' <> 'retiring'
         OR target_key->>'state_version' <> target_version::text
         OR NOT (target_key ? 'verification_until')
         OR public.agentpass_managed_signer_key_identity(current_key)
              IS DISTINCT FROM public.agentpass_managed_signer_key_identity(target_key)
      THEN
        RETURN NULL;
      END IF;
      changed_count := changed_count + 1;
    END IF;
  END LOOP;

  target_new_key := target_keys->current_length;
  IF target_new_key IS NULL
     OR target_new_key->>'state' <> 'active'
     OR target_new_key->>'state_version' <> target_version::text
     OR (target_new_key ? 'verification_until')
     OR (target_new_key->>'key_version')::bigint <= current_max_version
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.jsonb_array_elements(current_keys) AS item(value)
       WHERE value->>'key_id' = target_new_key->>'key_id'
          OR value->>'public_key_fingerprint' = target_new_key->>'public_key_fingerprint'
     )
  THEN
    RETURN NULL;
  END IF;

  IF current_active_index >= 0 AND changed_count = 1 THEN
    RETURN 'rotate';
  END IF;
  IF current_active_index < 0 AND changed_count = 0 THEN
    RETURN 'restore-new-key';
  END IF;
  RETURN NULL;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_snapshot_json(p_purpose text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_row record;
  snapshot_value jsonb;
BEGIN
  SELECT purpose, algorithm, version, max_keys, max_verification_overlap_ms
    INTO lifecycle_row
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT jsonb_build_object(
           'version', lifecycle_row.version,
           'purpose', lifecycle_row.purpose,
           'algorithm', lifecycle_row.algorithm,
           'keys', coalesce(
             jsonb_agg(
               jsonb_strip_nulls(jsonb_build_object(
                 'key_id', key_row.key_id,
                 'key_version', key_row.key_version,
                 'purpose', key_row.purpose,
                 'algorithm', key_row.algorithm,
                 'public_key_fingerprint', encode(key_row.public_key_fingerprint, 'hex'),
                 'public_key', key_row.public_key_pem,
                 'state', key_row.state,
                 'state_version', key_row.state_version,
                 'verification_until', CASE
                   WHEN key_row.verification_until IS NULL THEN NULL
                   ELSE pg_catalog.to_char(
                     key_row.verification_until AT TIME ZONE 'UTC',
                     'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                   )
                 END
               )) ORDER BY key_row.key_position
             ) FILTER (WHERE key_row.key_id IS NOT NULL),
             '[]'::jsonb
           )
         )
    INTO snapshot_value
  FROM public.managed_signer_keys AS key_row
  WHERE key_row.purpose = lifecycle_row.purpose;
  RETURN snapshot_value;
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_record_json(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_status text,
  p_reserved_lifecycle_version bigint,
  p_created_at timestamptz,
  p_updated_at timestamptz,
  p_expires_at timestamptz,
  p_claim_expires_at timestamptz,
  p_provider_started_at timestamptz,
  p_signature bytea,
  p_provider_receipt_provider text,
  p_provider_receipt_id text
)
RETURNS jsonb
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'purpose', p_purpose,
    'operation_id', p_operation_id,
    'request_digest', encode(p_request_digest, 'hex'),
    'key_id', p_key_id,
    'key_version', p_key_version,
    'state', p_status,
    'reserved_lifecycle_version', p_reserved_lifecycle_version,
    'created_at', p_created_at,
    'updated_at', p_updated_at,
    'expires_at', p_expires_at,
    'claim_expires_at', p_claim_expires_at,
    'provider_started_at', p_provider_started_at,
    'signature', CASE WHEN p_signature IS NULL THEN NULL ELSE encode(p_signature, 'base64') END,
    'provider_receipt', CASE
      WHEN p_provider_receipt_provider IS NULL THEN NULL
      ELSE jsonb_build_object('provider', p_provider_receipt_provider, 'receipt_id', p_provider_receipt_id)
    END
  ));
$$;

CREATE FUNCTION public.agentpass_managed_signer_receipt_is_valid(
  p_operation_id text,
  p_key_id text,
  p_key_version bigint,
  p_provider text,
  p_receipt_id text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT CASE
    WHEN p_provider IS NULL AND p_receipt_id IS NULL THEN true
    WHEN p_provider IS NULL OR p_receipt_id IS NULL THEN false
    ELSE (
        p_provider ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
        AND p_receipt_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND p_provider !~* '(private|secret|credential|diagnostic|debug|trace|token|pem)'
        AND p_receipt_id !~* '(private|secret|credential|diagnostic|debug|trace|token|pem)'
        AND p_operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
        AND p_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
        AND p_key_version BETWEEN 1 AND 9223372036854775807
      )
  END;
$$;

-- Emergency disable advances the lifecycle epoch for every key, including a
-- key that was already disabled by an earlier single-key transition.  Keep
-- terminal state immutable while allowing only that narrowly-scoped epoch
-- refresh.  This closes the gap between the 0037 trigger and the lifecycle
-- state-machine contract used by the authority below.
CREATE OR REPLACE FUNCTION public.agentpass_guard_managed_signer_key()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_version bigint;
  overlap_ms bigint;
  changed_state boolean := false;
  terminal_epoch_refresh boolean := false;
BEGIN
  SELECT version, max_verification_overlap_ms
    INTO lifecycle_version, overlap_ms
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = NEW.purpose
  FOR SHARE;

  IF NOT FOUND OR NEW.algorithm <> 'ed25519' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_keys_lifecycle_binding',
      MESSAGE = 'managed signer key lifecycle binding is invalid';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.key_id IS DISTINCT FROM OLD.key_id
       OR NEW.key_version IS DISTINCT FROM OLD.key_version
       OR NEW.algorithm IS DISTINCT FROM OLD.algorithm
       OR NEW.public_key_fingerprint IS DISTINCT FROM OLD.public_key_fingerprint
       OR NEW.public_key_pem IS DISTINCT FROM OLD.public_key_pem
       OR NEW.key_position IS DISTINCT FROM OLD.key_position
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'managed_signer_keys_metadata_immutable',
        MESSAGE = 'managed signer key metadata is immutable';
    END IF;
    changed_state := NEW.state IS DISTINCT FROM OLD.state;
    terminal_epoch_refresh := NOT changed_state
      AND OLD.state = 'emergency-disabled'
      AND NEW.state = 'emergency-disabled'
      AND NEW.state_version = lifecycle_version
      AND NEW.state_version > OLD.state_version
      AND NEW.verification_until IS NOT DISTINCT FROM OLD.verification_until;
    IF NOT changed_state
       AND NOT terminal_epoch_refresh
       AND (NEW.state_version IS DISTINCT FROM OLD.state_version
         OR NEW.verification_until IS DISTINCT FROM OLD.verification_until)
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'managed_signer_keys_state_immutable',
        MESSAGE = 'managed signer key state metadata cannot change without a transition';
    END IF;
    IF changed_state THEN
      IF NOT (
        (OLD.state = 'active' AND NEW.state IN ('retiring', 'revoked', 'emergency-disabled'))
        OR (OLD.state = 'retiring' AND NEW.state IN ('revoked', 'emergency-disabled'))
        OR (OLD.state = 'revoked' AND NEW.state = 'emergency-disabled')
      ) THEN
        RAISE EXCEPTION USING
          ERRCODE = 'check_violation',
          CONSTRAINT = 'managed_signer_keys_state_transition',
          MESSAGE = 'managed signer key state transition is not permitted';
      END IF;
      IF NEW.state_version <> lifecycle_version THEN
        RAISE EXCEPTION USING
          ERRCODE = 'check_violation',
          CONSTRAINT = 'managed_signer_keys_state_version',
          MESSAGE = 'managed signer key state version must equal the lifecycle version';
      END IF;
    END IF;
  ELSIF NEW.state_version <> lifecycle_version THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_keys_state_version',
      MESSAGE = 'managed signer key state version must equal the lifecycle version';
  END IF;

  IF NEW.state_version > lifecycle_version THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_keys_state_version',
      MESSAGE = 'managed signer key state version cannot exceed the lifecycle version';
  END IF;

  IF NEW.state = 'retiring' THEN
    IF NEW.verification_until IS NULL
       OR NEW.verification_until > pg_catalog.clock_timestamp() + (overlap_ms * interval '1 millisecond')
       OR (TG_OP = 'UPDATE' AND changed_state AND NEW.verification_until <= pg_catalog.clock_timestamp())
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'managed_signer_keys_verification_overlap',
        MESSAGE = 'managed signer key verification overlap is outside the permitted window';
    END IF;
  ELSIF NEW.verification_until IS NOT NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_keys_verification_overlap',
      MESSAGE = 'only retiring managed signer keys may have verification overlap';
  END IF;

  NEW.updated_at := pg_catalog.clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_lifecycle_snapshot(
  p_purpose text
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  snapshot_value jsonb;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  snapshot_value := public.agentpass_managed_signer_snapshot_json(p_purpose);
  IF snapshot_value IS NULL THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('snapshot', snapshot_value));
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_lifecycle_initialize(
  p_purpose text,
  p_algorithm text,
  p_snapshot jsonb,
  p_max_keys integer,
  p_max_verification_overlap_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  inserted boolean := false;
  lifecycle_row record;
  snapshot_value jsonb;
  key_value jsonb;
  key_position integer := 0;
BEGIN
  IF NOT public.agentpass_managed_signer_snapshot_is_valid(
       p_snapshot, p_purpose, p_algorithm, p_max_keys,
       p_max_verification_overlap_ms, false
     )
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;

  INSERT INTO public.managed_signer_key_lifecycles
    (purpose, algorithm, version, max_keys, max_verification_overlap_ms)
  VALUES
    (p_purpose, p_algorithm, (p_snapshot->>'version')::bigint,
     p_max_keys, p_max_verification_overlap_ms)
  ON CONFLICT (purpose) DO NOTHING
  RETURNING true INTO inserted;

  SELECT purpose, algorithm, version, max_keys, max_verification_overlap_ms
    INTO lifecycle_row
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;

  IF lifecycle_row.algorithm IS DISTINCT FROM p_algorithm
     OR lifecycle_row.max_keys IS DISTINCT FROM p_max_keys
     OR lifecycle_row.max_verification_overlap_ms IS DISTINCT FROM p_max_verification_overlap_ms
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;

  IF inserted THEN
    FOR key_value IN SELECT value FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') LOOP
      INSERT INTO public.managed_signer_keys
        (purpose, key_id, key_version, algorithm, public_key_fingerprint,
         public_key_pem, state, state_version, verification_until, key_position)
      VALUES
        (p_purpose, key_value->>'key_id', (key_value->>'key_version')::bigint,
         p_algorithm, pg_catalog.decode(key_value->>'public_key_fingerprint', 'hex'),
         key_value->>'public_key', key_value->>'state',
         (key_value->>'state_version')::bigint,
         (key_value->>'verification_until')::timestamptz, key_position);
      key_position := key_position + 1;
    END LOOP;
  END IF;

  snapshot_value := public.agentpass_managed_signer_snapshot_json(p_purpose);
  IF snapshot_value IS NULL OR snapshot_value IS DISTINCT FROM p_snapshot THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('snapshot', snapshot_value));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_lifecycle_apply(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_expected_version bigint,
  p_target_snapshot jsonb,
  p_operation_retention_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_row record;
  operation_row record;
  current_snapshot jsonb;
  transition_kind text;
  target_version bigint;
  key_value jsonb;
  key_position integer := 0;
  updated_version bigint;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_operation_id IS NULL OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_expected_version IS NULL OR p_expected_version < 1
     OR p_operation_retention_ms IS NULL OR p_operation_retention_ms < 1
     OR p_operation_retention_ms > 31536000000
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;

  SELECT purpose, algorithm, version, max_keys, max_verification_overlap_ms
    INTO lifecycle_row
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;

  SELECT request_digest, response_snapshot
    INTO operation_row
  FROM public.managed_signer_key_lifecycle_operations
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  IF FOUND THEN
    IF operation_row.request_digest IS DISTINCT FROM p_request_digest THEN
      RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
    END IF;
    RETURN public.agentpass_managed_signer_envelope(
      'ok', jsonb_build_object('snapshot', operation_row.response_snapshot)
    );
  END IF;

  current_snapshot := public.agentpass_managed_signer_snapshot_json(p_purpose);
  IF current_snapshot IS NULL THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  IF lifecycle_row.version IS DISTINCT FROM p_expected_version THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', jsonb_build_object('snapshot', current_snapshot));
  END IF;
  IF NOT public.agentpass_managed_signer_snapshot_is_valid(
       p_target_snapshot, p_purpose, lifecycle_row.algorithm,
       lifecycle_row.max_keys, lifecycle_row.max_verification_overlap_ms, false
     )
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  target_version := (p_target_snapshot->>'version')::bigint;
  IF target_version <> lifecycle_row.version + 1 THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
  END IF;

  transition_kind := public.agentpass_managed_signer_transition_kind(current_snapshot, p_target_snapshot);
  IF transition_kind IS NULL THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
  END IF;

  UPDATE public.managed_signer_key_lifecycles
  SET version = target_version,
      updated_at = pg_catalog.clock_timestamp()
  WHERE purpose = p_purpose AND version = p_expected_version
  RETURNING version INTO updated_version;
  IF updated_version IS NULL THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
  END IF;

  FOR key_value IN SELECT value FROM pg_catalog.jsonb_array_elements(p_target_snapshot->'keys') LOOP
    UPDATE public.managed_signer_keys
    SET state = key_value->>'state',
        state_version = (key_value->>'state_version')::bigint,
        verification_until = (key_value->>'verification_until')::timestamptz,
        updated_at = pg_catalog.clock_timestamp()
    WHERE purpose = p_purpose AND key_id = key_value->>'key_id';
    IF NOT FOUND THEN
      INSERT INTO public.managed_signer_keys
        (purpose, key_id, key_version, algorithm, public_key_fingerprint,
         public_key_pem, state, state_version, verification_until, key_position)
      VALUES
        (p_purpose, key_value->>'key_id', (key_value->>'key_version')::bigint,
         key_value->>'algorithm', pg_catalog.decode(key_value->>'public_key_fingerprint', 'hex'),
         key_value->>'public_key', key_value->>'state',
         (key_value->>'state_version')::bigint,
         (key_value->>'verification_until')::timestamptz, key_position);
    END IF;
    key_position := key_position + 1;
  END LOOP;

  INSERT INTO public.managed_signer_key_lifecycle_operations
    (purpose, operation_id, request_digest, response_snapshot, created_at, expires_at)
  VALUES
    (p_purpose, p_operation_id, p_request_digest, p_target_snapshot,
     pg_catalog.clock_timestamp(),
     pg_catalog.clock_timestamp() + (p_operation_retention_ms::double precision * interval '1 millisecond'));

  RETURN public.agentpass_managed_signer_envelope(
    'ok', jsonb_build_object('snapshot', p_target_snapshot, 'transition', transition_kind)
  );
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_reserve(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_claim_token_digest bytea,
  p_claim_lease_ms bigint,
  p_retention_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_row record;
  signing_row record;
  key_row record;
  had_signing boolean := false;
  now_at timestamptz := pg_catalog.clock_timestamp();
  output_record jsonb;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_operation_id IS NULL OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_key_version IS NULL OR p_key_version < 1
     OR p_claim_token_digest IS NULL OR octet_length(p_claim_token_digest) <> 32
     OR p_claim_lease_ms IS NULL OR p_claim_lease_ms < 1000 OR p_claim_lease_ms > 300000
     OR p_retention_ms IS NULL OR p_retention_ms < 1 OR p_retention_ms > 31536000000
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;

  SELECT purpose, version
    INTO lifecycle_row
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;

  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  IF FOUND THEN
    had_signing := true;
    IF signing_row.request_digest IS DISTINCT FROM p_request_digest
       OR signing_row.key_id IS DISTINCT FROM p_key_id
       OR signing_row.key_version IS DISTINCT FROM p_key_version
    THEN
      RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
    END IF;
    IF signing_row.status = 'committed' THEN
      output_record := public.agentpass_managed_signer_signing_record_json(
        signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
        signing_row.key_id, signing_row.key_version, signing_row.status,
        signing_row.reserved_lifecycle_version, signing_row.created_at,
        signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
        signing_row.provider_started_at, signing_row.signature,
        signing_row.provider_receipt_provider, signing_row.provider_receipt_id
      );
      RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
    END IF;
    IF signing_row.status = 'pending' AND signing_row.claim_expires_at <= now_at THEN
      IF signing_row.provider_started_at IS NULL THEN
        UPDATE public.managed_signer_signing_idempotency
        SET status = 'aborted', claim_token_digest = NULL,
            claim_expires_at = NULL, updated_at = now_at
        WHERE purpose = p_purpose AND operation_id = p_operation_id
          AND status = 'pending' AND claim_expires_at <= now_at;
      ELSE
        UPDATE public.managed_signer_signing_idempotency
        SET status = 'uncertain', claim_token_digest = NULL,
            claim_expires_at = NULL, updated_at = now_at
        WHERE purpose = p_purpose AND operation_id = p_operation_id
          AND status = 'pending' AND claim_expires_at <= now_at;
      END IF;
      SELECT * INTO signing_row
      FROM public.managed_signer_signing_idempotency
      WHERE purpose = p_purpose AND operation_id = p_operation_id
      FOR UPDATE;
    END IF;
    IF signing_row.status = 'pending' THEN
      output_record := public.agentpass_managed_signer_signing_record_json(
        signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
        signing_row.key_id, signing_row.key_version, signing_row.status,
        signing_row.reserved_lifecycle_version, signing_row.created_at,
        signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
        signing_row.provider_started_at, signing_row.signature,
        signing_row.provider_receipt_provider, signing_row.provider_receipt_id
      );
      RETURN public.agentpass_managed_signer_envelope('pending', jsonb_build_object('record', output_record));
    END IF;
    IF signing_row.status = 'uncertain' THEN
      output_record := public.agentpass_managed_signer_signing_record_json(
        signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
        signing_row.key_id, signing_row.key_version, signing_row.status,
        signing_row.reserved_lifecycle_version, signing_row.created_at,
        signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
        signing_row.provider_started_at, signing_row.signature,
        signing_row.provider_receipt_provider, signing_row.provider_receipt_id
      );
      RETURN public.agentpass_managed_signer_envelope('uncertain', jsonb_build_object('record', output_record));
    END IF;
    -- An aborted row is reclaimable only after the previous claim never
    -- crossed the provider boundary.
  END IF;

  SELECT key_id, key_version, state, state_version
    INTO key_row
  FROM public.managed_signer_keys
  WHERE purpose = p_purpose AND key_id = p_key_id
  FOR SHARE;
  IF NOT FOUND OR key_row.key_version IS DISTINCT FROM p_key_version THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  IF key_row.state IS DISTINCT FROM 'active' OR key_row.state_version IS DISTINCT FROM lifecycle_row.version THEN
    RETURN public.agentpass_managed_signer_envelope('not_active', '{}'::jsonb);
  END IF;

  IF had_signing AND signing_row.status = 'aborted' THEN
    UPDATE public.managed_signer_signing_idempotency
    SET status = 'pending', claim_token_digest = p_claim_token_digest,
        claim_expires_at = now_at + (p_claim_lease_ms::double precision * interval '1 millisecond'),
        provider_started_at = NULL,
        expires_at = now_at + (p_retention_ms::double precision * interval '1 millisecond'),
        updated_at = now_at
    WHERE purpose = p_purpose AND operation_id = p_operation_id
      AND status = 'aborted' AND provider_started_at IS NULL
      AND reserved_lifecycle_version = lifecycle_row.version;
    IF NOT FOUND THEN
      RETURN public.agentpass_managed_signer_envelope('not_active', '{}'::jsonb);
    END IF;
  ELSE
    INSERT INTO public.managed_signer_signing_idempotency
      (purpose, operation_id, request_digest, key_id, key_version, status,
       signature, created_at, updated_at, expires_at, claim_token_digest,
       claim_expires_at, provider_started_at, reserved_lifecycle_version,
       provider_receipt_provider, provider_receipt_id)
    VALUES
      (p_purpose, p_operation_id, p_request_digest, p_key_id, p_key_version,
       'pending', NULL, now_at, now_at,
       now_at + (p_retention_ms::double precision * interval '1 millisecond'),
       p_claim_token_digest,
       now_at + (p_claim_lease_ms::double precision * interval '1 millisecond'),
       NULL, lifecycle_row.version, NULL, NULL);
  END IF;

  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  output_record := public.agentpass_managed_signer_signing_record_json(
    signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
    signing_row.key_id, signing_row.key_version, signing_row.status,
    signing_row.reserved_lifecycle_version, signing_row.created_at,
    signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
    signing_row.provider_started_at, signing_row.signature,
    signing_row.provider_receipt_provider, signing_row.provider_receipt_id
  );
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_start(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_claim_token_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_row record;
  signing_row record;
  signing_found boolean := false;
  output_record jsonb;
  now_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_operation_id IS NULL OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_key_version IS NULL OR p_key_version < 1
     OR p_claim_token_digest IS NULL OR octet_length(p_claim_token_digest) <> 32
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  SELECT version INTO lifecycle_row
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  signing_found := FOUND;
  IF NOT signing_found THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  IF signing_row.request_digest IS DISTINCT FROM p_request_digest
     OR signing_row.key_id IS DISTINCT FROM p_key_id
     OR signing_row.key_version IS DISTINCT FROM p_key_version
  THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
  END IF;
  IF signing_row.status = 'committed' THEN
    output_record := public.agentpass_managed_signer_signing_record_json(
      signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
      signing_row.key_id, signing_row.key_version, signing_row.status,
      signing_row.reserved_lifecycle_version, signing_row.created_at,
      signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
      signing_row.provider_started_at, signing_row.signature,
      signing_row.provider_receipt_provider, signing_row.provider_receipt_id
    );
    RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
  END IF;
  IF signing_row.status IS DISTINCT FROM 'pending' THEN
    RETURN public.agentpass_managed_signer_envelope(
      CASE WHEN signing_row.status = 'uncertain' THEN 'uncertain' ELSE 'claim_lost' END,
      '{}'::jsonb
    );
  END IF;
  UPDATE public.managed_signer_signing_idempotency AS signing
  SET provider_started_at = coalesce(signing.provider_started_at, now_at),
      updated_at = now_at
  FROM public.managed_signer_keys AS key_row
  WHERE signing.purpose = p_purpose AND signing.operation_id = p_operation_id
    AND signing.status = 'pending'
    AND signing.claim_token_digest = p_claim_token_digest
    AND signing.claim_expires_at > now_at
    AND signing.reserved_lifecycle_version = lifecycle_row.version
    AND key_row.purpose = signing.purpose AND key_row.key_id = signing.key_id
    AND key_row.key_version = signing.key_version
    AND key_row.state = 'active' AND key_row.state_version = lifecycle_row.version;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id;
  output_record := public.agentpass_managed_signer_signing_record_json(
    signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
    signing_row.key_id, signing_row.key_version, signing_row.status,
    signing_row.reserved_lifecycle_version, signing_row.created_at,
    signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
    signing_row.provider_started_at, signing_row.signature,
    signing_row.provider_receipt_provider, signing_row.provider_receipt_id
  );
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_commit(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_claim_token_digest bytea,
  p_signature bytea,
  p_provider_receipt_provider text,
  p_provider_receipt_id text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_row record;
  signing_row record;
  output_record jsonb;
  now_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_operation_id IS NULL OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_key_version IS NULL OR p_key_version < 1
     OR (p_claim_token_digest IS NOT NULL AND octet_length(p_claim_token_digest) <> 32)
     OR p_signature IS NULL OR octet_length(p_signature) <> 64
     OR NOT public.agentpass_managed_signer_receipt_is_valid(
       p_operation_id, p_key_id, p_key_version,
       p_provider_receipt_provider, p_provider_receipt_id
     )
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  SELECT version INTO lifecycle_row
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  IF signing_row.request_digest IS DISTINCT FROM p_request_digest
     OR signing_row.key_id IS DISTINCT FROM p_key_id
     OR signing_row.key_version IS DISTINCT FROM p_key_version
  THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
  END IF;
  IF signing_row.status = 'committed' THEN
    IF signing_row.signature IS DISTINCT FROM p_signature
       OR signing_row.provider_receipt_provider IS DISTINCT FROM p_provider_receipt_provider
       OR signing_row.provider_receipt_id IS DISTINCT FROM p_provider_receipt_id
    THEN
      RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
    END IF;
    output_record := public.agentpass_managed_signer_signing_record_json(
      signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
      signing_row.key_id, signing_row.key_version, signing_row.status,
      signing_row.reserved_lifecycle_version, signing_row.created_at,
      signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
      signing_row.provider_started_at, signing_row.signature,
      signing_row.provider_receipt_provider, signing_row.provider_receipt_id
    );
    RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
  END IF;
  IF signing_row.status = 'uncertain' THEN
    RETURN public.agentpass_managed_signer_envelope('uncertain', '{}'::jsonb);
  END IF;
  IF signing_row.status IS DISTINCT FROM 'pending' THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  UPDATE public.managed_signer_signing_idempotency AS signing
  SET status = 'committed', signature = p_signature,
      claim_token_digest = NULL, claim_expires_at = NULL,
      provider_started_at = coalesce(signing.provider_started_at, now_at),
      provider_receipt_provider = p_provider_receipt_provider,
      provider_receipt_id = p_provider_receipt_id,
      updated_at = now_at
  FROM public.managed_signer_keys AS key_row
  WHERE signing.purpose = p_purpose AND signing.operation_id = p_operation_id
    AND signing.status = 'pending'
    AND signing.claim_token_digest = p_claim_token_digest
    AND signing.claim_expires_at > now_at
    AND signing.reserved_lifecycle_version = lifecycle_row.version
    AND key_row.purpose = signing.purpose AND key_row.key_id = signing.key_id
    AND key_row.key_version = signing.key_version
    AND key_row.state = 'active' AND key_row.state_version = lifecycle_row.version;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id;
  output_record := public.agentpass_managed_signer_signing_record_json(
    signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
    signing_row.key_id, signing_row.key_version, signing_row.status,
    signing_row.reserved_lifecycle_version, signing_row.created_at,
    signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
    signing_row.provider_started_at, signing_row.signature,
    signing_row.provider_receipt_provider, signing_row.provider_receipt_id
  );
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_uncertain(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_claim_token_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  signing_row record;
  output_record jsonb;
  now_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_operation_id IS NULL OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_key_version IS NULL OR p_key_version < 1
     OR p_claim_token_digest IS NULL OR octet_length(p_claim_token_digest) <> 32
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  PERFORM 1 FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  IF signing_row.request_digest IS DISTINCT FROM p_request_digest
     OR signing_row.key_id IS DISTINCT FROM p_key_id
     OR signing_row.key_version IS DISTINCT FROM p_key_version
  THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
  END IF;
  IF signing_row.status = 'committed' THEN
    output_record := public.agentpass_managed_signer_signing_record_json(
      signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
      signing_row.key_id, signing_row.key_version, signing_row.status,
      signing_row.reserved_lifecycle_version, signing_row.created_at,
      signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
      signing_row.provider_started_at, signing_row.signature,
      signing_row.provider_receipt_provider, signing_row.provider_receipt_id
    );
    RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
  END IF;
  IF signing_row.status = 'uncertain' THEN
    output_record := public.agentpass_managed_signer_signing_record_json(
      signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
      signing_row.key_id, signing_row.key_version, signing_row.status,
      signing_row.reserved_lifecycle_version, signing_row.created_at,
      signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
      signing_row.provider_started_at, signing_row.signature,
      signing_row.provider_receipt_provider, signing_row.provider_receipt_id
    );
    RETURN public.agentpass_managed_signer_envelope('uncertain', jsonb_build_object('record', output_record));
  END IF;
  IF signing_row.status IS DISTINCT FROM 'pending' THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  IF signing_row.claim_token_digest IS DISTINCT FROM p_claim_token_digest
     OR (signing_row.provider_started_at IS NULL AND signing_row.claim_expires_at <= now_at)
  THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  UPDATE public.managed_signer_signing_idempotency
  SET status = 'uncertain',
      claim_token_digest = NULL,
      claim_expires_at = NULL,
      provider_started_at = coalesce(provider_started_at, now_at),
      updated_at = now_at
  WHERE purpose = p_purpose AND operation_id = p_operation_id
    AND status = 'pending' AND claim_token_digest = p_claim_token_digest;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id;
  output_record := public.agentpass_managed_signer_signing_record_json(
    signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
    signing_row.key_id, signing_row.key_version, signing_row.status,
    signing_row.reserved_lifecycle_version, signing_row.created_at,
    signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
    signing_row.provider_started_at, signing_row.signature,
    signing_row.provider_receipt_provider, signing_row.provider_receipt_id
  );
  RETURN public.agentpass_managed_signer_envelope('uncertain', jsonb_build_object('record', output_record));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_reconcile(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_signature bytea,
  p_provider_receipt_provider text,
  p_provider_receipt_id text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_version bigint;
  signing_row record;
  output_record jsonb;
  now_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
  -- Reconciliation deliberately has no claim input: the original lease has
  -- already been cleared when a row becomes uncertain. Provider receipt and
  -- immutable request/key bindings are the recovery authority.
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_operation_id IS NULL OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
     OR p_key_version IS NULL OR p_key_version < 1
     OR p_signature IS NULL OR octet_length(p_signature) <> 64
     OR NOT public.agentpass_managed_signer_receipt_is_valid(
       p_operation_id, p_key_id, p_key_version,
       p_provider_receipt_provider, p_provider_receipt_id
     )
     OR p_provider_receipt_provider IS NULL
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  SELECT version INTO lifecycle_version
  FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  IF signing_row.request_digest IS DISTINCT FROM p_request_digest
     OR signing_row.key_id IS DISTINCT FROM p_key_id
     OR signing_row.key_version IS DISTINCT FROM p_key_version
  THEN
    RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
  END IF;
  IF signing_row.status = 'committed' THEN
    IF signing_row.signature IS DISTINCT FROM p_signature
       OR signing_row.provider_receipt_provider IS DISTINCT FROM p_provider_receipt_provider
       OR signing_row.provider_receipt_id IS DISTINCT FROM p_provider_receipt_id
    THEN
      RETURN public.agentpass_managed_signer_envelope('conflict', '{}'::jsonb);
    END IF;
    output_record := public.agentpass_managed_signer_signing_record_json(
      signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
      signing_row.key_id, signing_row.key_version, signing_row.status,
      signing_row.reserved_lifecycle_version, signing_row.created_at,
      signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
      signing_row.provider_started_at, signing_row.signature,
      signing_row.provider_receipt_provider, signing_row.provider_receipt_id
    );
    RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
  END IF;
  IF signing_row.status = 'pending' THEN
    RETURN public.agentpass_managed_signer_envelope('pending', '{}'::jsonb);
  END IF;
  IF signing_row.status IS DISTINCT FROM 'uncertain' THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  IF signing_row.provider_started_at IS NULL THEN
    RETURN public.agentpass_managed_signer_envelope('uncertain', '{}'::jsonb);
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.managed_signer_keys AS key_row
    WHERE key_row.purpose = p_purpose
      AND key_row.key_id = p_key_id
      AND key_row.key_version = p_key_version
      AND key_row.state = 'active'
      AND key_row.state_version = lifecycle_version
  ) OR signing_row.reserved_lifecycle_version IS DISTINCT FROM lifecycle_version
  THEN
    RETURN public.agentpass_managed_signer_envelope('not_active', '{}'::jsonb);
  END IF;
  UPDATE public.managed_signer_signing_idempotency
  SET status = 'committed', signature = p_signature,
      provider_receipt_provider = p_provider_receipt_provider,
      provider_receipt_id = p_provider_receipt_id,
      updated_at = now_at
  WHERE purpose = p_purpose AND operation_id = p_operation_id
    AND status = 'uncertain' AND provider_started_at IS NOT NULL;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('claim_lost', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id;
  output_record := public.agentpass_managed_signer_signing_record_json(
    signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
    signing_row.key_id, signing_row.key_version, signing_row.status,
    signing_row.reserved_lifecycle_version, signing_row.created_at,
    signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
    signing_row.provider_started_at, signing_row.signature,
    signing_row.provider_receipt_provider, signing_row.provider_receipt_id
  );
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_lookup(
  p_purpose text,
  p_operation_id text
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  signing_row record;
  output_record jsonb;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_operation_id IS NULL OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  PERFORM 1 FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  SELECT * INTO signing_row
  FROM public.managed_signer_signing_idempotency
  WHERE purpose = p_purpose AND operation_id = p_operation_id;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('absent', '{}'::jsonb);
  END IF;
  output_record := public.agentpass_managed_signer_signing_record_json(
    signing_row.purpose, signing_row.operation_id, signing_row.request_digest,
    signing_row.key_id, signing_row.key_version, signing_row.status,
    signing_row.reserved_lifecycle_version, signing_row.created_at,
    signing_row.updated_at, signing_row.expires_at, signing_row.claim_expires_at,
    signing_row.provider_started_at, signing_row.signature,
    signing_row.provider_receipt_provider, signing_row.provider_receipt_id
  );
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('record', output_record));
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_signing_prune(
  p_purpose text,
  p_before timestamptz,
  p_limit integer
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  deleted_count integer;
  now_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_before IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  PERFORM 1 FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  WITH doomed AS MATERIALIZED (
    SELECT purpose, operation_id
    FROM public.managed_signer_signing_idempotency
    WHERE purpose = p_purpose
      AND status = 'committed'
      AND expires_at <= p_before
      AND expires_at <= now_at
    ORDER BY expires_at, operation_id
    FOR UPDATE SKIP LOCKED
    LIMIT p_limit
  )
  DELETE FROM public.managed_signer_signing_idempotency AS signing
  USING doomed
  WHERE signing.purpose = doomed.purpose
    AND signing.operation_id = doomed.operation_id;
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('pruned', deleted_count));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_lifecycle_operation_prune(
  p_purpose text,
  p_before timestamptz,
  p_limit integer
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  deleted_count integer;
  now_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_before IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000
  THEN
    RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
  END IF;
  PERFORM 1 FROM public.managed_signer_key_lifecycles
  WHERE purpose = p_purpose FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_envelope('not_initialized', '{}'::jsonb);
  END IF;
  WITH doomed AS MATERIALIZED (
    SELECT purpose, operation_id
    FROM public.managed_signer_key_lifecycle_operations
    WHERE purpose = p_purpose
      AND expires_at <= p_before
      AND expires_at <= now_at
    ORDER BY expires_at, operation_id
    FOR UPDATE SKIP LOCKED
    LIMIT p_limit
  )
  DELETE FROM public.managed_signer_key_lifecycle_operations AS operation
  USING doomed
  WHERE operation.purpose = doomed.purpose
    AND operation.operation_id = doomed.operation_id;
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN public.agentpass_managed_signer_envelope('ok', jsonb_build_object('pruned', deleted_count));
EXCEPTION WHEN OTHERS THEN
  RETURN public.agentpass_managed_signer_envelope('configuration_conflict', '{}'::jsonb);
END;
$$;

-- Function EXECUTE defaults to PUBLIC in PostgreSQL.  No helper or entry
-- function is callable by PUBLIC; roles.sql grants only the reviewed entry
-- allow-list to the signer role after this migration is applied.
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_envelope(text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_snapshot_is_valid(jsonb, text, text, integer, bigint, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_key_identity(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_transition_kind(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_snapshot_json(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_record_json(text, text, bytea, text, bigint, text, bigint, timestamptz, timestamptz, timestamptz, timestamptz, timestamptz, bytea, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_receipt_is_valid(text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_guard_managed_signer_key() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_lifecycle_snapshot(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_lifecycle_initialize(text, text, jsonb, integer, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_lifecycle_apply(text, text, bytea, bigint, jsonb, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_reserve(text, text, bytea, text, bigint, bytea, bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_start(text, text, bytea, text, bigint, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_commit(text, text, bytea, text, bigint, bytea, bytea, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_uncertain(text, text, bytea, text, bigint, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_reconcile(text, text, bytea, text, bigint, bytea, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_lookup(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_prune(text, timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_lifecycle_operation_prune(text, timestamptz, integer) FROM PUBLIC;

COMMIT;
