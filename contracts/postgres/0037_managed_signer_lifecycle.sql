BEGIN;

-- Hosted KMS signers are deployment-global and purpose-scoped; purpose is the
-- isolation boundary for the configured deployment signer.
CREATE TABLE managed_signer_key_lifecycles (
  purpose text PRIMARY KEY
    CHECK (purpose ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
  algorithm text NOT NULL
    CHECK (algorithm = 'ed25519'),
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9223372036854775807),
  max_keys integer NOT NULL DEFAULT 4
    CHECK (max_keys BETWEEN 1 AND 32),
  max_verification_overlap_ms bigint NOT NULL DEFAULT 7776000000
    CHECK (max_verification_overlap_ms BETWEEN 1 AND 31536000000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE managed_signer_keys (
  purpose text NOT NULL
    REFERENCES managed_signer_key_lifecycles (purpose),
  key_id text NOT NULL
    CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  key_version bigint NOT NULL
    CHECK (key_version BETWEEN 1 AND 9223372036854775807),
  algorithm text NOT NULL
    CHECK (algorithm = 'ed25519'),
  public_key_fingerprint bytea NOT NULL
    CHECK (octet_length(public_key_fingerprint) = 32),
  -- Public key metadata is optional because a hosted KMS may expose it only
  -- through the provider.  Private material and provider credentials never
  -- have a column in this schema.
  public_key_pem text
    CHECK (public_key_pem IS NULL OR (
      octet_length(public_key_pem) BETWEEN 1 AND 8192
      AND public_key_pem !~* 'PRIVATE[[:space:]_-]*KEY'
    )),
  state text NOT NULL
    CHECK (state IN ('active', 'retiring', 'revoked', 'emergency-disabled')),
  state_version bigint NOT NULL
    CHECK (state_version BETWEEN 1 AND 9223372036854775807),
  verification_until timestamptz,
  key_position integer NOT NULL
    CHECK (key_position BETWEEN 0 AND 31),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (purpose, key_id),
  UNIQUE (purpose, key_version),
  UNIQUE (purpose, public_key_fingerprint),
  UNIQUE (purpose, key_id, key_version),
  UNIQUE (purpose, key_position),
  CHECK ((state = 'retiring' AND verification_until IS NOT NULL)
    OR (state <> 'retiring' AND verification_until IS NULL))
);

CREATE UNIQUE INDEX managed_signer_keys_one_active
  ON managed_signer_keys (purpose)
  WHERE state = 'active';

CREATE INDEX managed_signer_keys_verification_expiry
  ON managed_signer_keys (purpose, verification_until, key_position)
  WHERE state = 'retiring';

-- A lifecycle operation stores the exact public snapshot returned to the
-- caller.  The row is immutable; pruning is explicit and never implicit.
CREATE TABLE managed_signer_key_lifecycle_operations (
  purpose text NOT NULL
    REFERENCES managed_signer_key_lifecycles (purpose),
  operation_id text NOT NULL
    CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  request_digest bytea NOT NULL
    CHECK (octet_length(request_digest) = 32),
  response_snapshot jsonb NOT NULL
    CHECK (jsonb_typeof(response_snapshot) = 'object'
      AND response_snapshot ? 'version'
      AND response_snapshot ? 'purpose'
      AND response_snapshot ? 'algorithm'
      AND response_snapshot ? 'keys'
      AND response_snapshot::text !~* 'PRIVATE[[:space:]_-]*KEY|PASSWORD|SECRET'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (purpose, operation_id),
  CHECK (expires_at > created_at)
);

CREATE INDEX managed_signer_key_lifecycle_operations_retention
  ON managed_signer_key_lifecycle_operations (purpose, expires_at, operation_id);

-- A signing request is claimed before the external KMS call.  pending and
-- uncertain rows are intentionally durable and terminal for blind retry:
-- process loss after a provider call must not cause a second signature.
CREATE TABLE managed_signer_signing_idempotency (
  purpose text NOT NULL
    REFERENCES managed_signer_key_lifecycles (purpose),
  operation_id text NOT NULL
    CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  request_digest bytea NOT NULL
    CHECK (octet_length(request_digest) = 32),
  key_id text NOT NULL,
  key_version bigint NOT NULL
    CHECK (key_version BETWEEN 1 AND 9223372036854775807),
  status text NOT NULL
    CHECK (status IN ('pending', 'uncertain', 'committed')),
  signature bytea,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (purpose, operation_id),
  FOREIGN KEY (purpose, key_id, key_version)
    REFERENCES managed_signer_keys (purpose, key_id, key_version),
  CHECK (
    (status = 'committed' AND signature IS NOT NULL AND octet_length(signature) = 64)
    OR
    (status IN ('pending', 'uncertain') AND signature IS NULL)
  ),
  CHECK (expires_at > created_at)
);

CREATE INDEX managed_signer_signing_idempotency_retention
  ON managed_signer_signing_idempotency (purpose, expires_at, operation_id)
  WHERE status = 'committed';

CREATE FUNCTION agentpass_guard_managed_signer_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.purpose IS DISTINCT FROM OLD.purpose
     OR NEW.algorithm IS DISTINCT FROM OLD.algorithm
     OR NEW.max_keys IS DISTINCT FROM OLD.max_keys
     OR NEW.max_verification_overlap_ms IS DISTINCT FROM OLD.max_verification_overlap_ms
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_key_lifecycles_identity_immutable',
      MESSAGE = 'managed signer lifecycle identity and bounds are immutable';
  END IF;
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_key_lifecycles_version_monotonic',
      MESSAGE = 'managed signer lifecycle version must advance by one';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER managed_signer_key_lifecycles_guard
  BEFORE UPDATE ON managed_signer_key_lifecycles
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_managed_signer_lifecycle();

CREATE FUNCTION agentpass_guard_managed_signer_key()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  lifecycle_version bigint;
  overlap_ms bigint;
  changed_state boolean := false;
BEGIN
  SELECT version, max_verification_overlap_ms
    INTO lifecycle_version, overlap_ms
  FROM managed_signer_key_lifecycles
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
    IF NOT changed_state
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
       OR NEW.verification_until > clock_timestamp() + (overlap_ms * interval '1 millisecond')
       OR (TG_OP = 'UPDATE' AND changed_state AND NEW.verification_until <= clock_timestamp())
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

  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER managed_signer_keys_guard
  BEFORE INSERT OR UPDATE ON managed_signer_keys
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_managed_signer_key();

CREATE FUNCTION agentpass_guard_managed_signer_key_count()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  scoped_purpose text;
  maximum integer;
  actual integer;
BEGIN
  scoped_purpose := CASE WHEN TG_OP = 'DELETE' THEN OLD.purpose ELSE NEW.purpose END;
  SELECT max_keys INTO maximum
  FROM managed_signer_key_lifecycles
  WHERE purpose = scoped_purpose
  FOR UPDATE;
  SELECT count(*)::integer INTO actual
  FROM managed_signer_keys
  WHERE purpose = scoped_purpose;
  IF actual > maximum THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_keys_maximum',
      MESSAGE = 'managed signer historical key bound exceeded';
  END IF;
  RETURN NULL;
END;
$$;

CREATE TRIGGER managed_signer_keys_count_guard
  AFTER INSERT OR UPDATE OR DELETE ON managed_signer_keys
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_managed_signer_key_count();

CREATE FUNCTION agentpass_guard_managed_signer_key_lifecycle_operation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_key_lifecycle_operations_immutable',
      MESSAGE = 'managed signer lifecycle operation records are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER managed_signer_key_lifecycle_operations_guard
  BEFORE UPDATE ON managed_signer_key_lifecycle_operations
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_managed_signer_key_lifecycle_operation();

CREATE FUNCTION agentpass_guard_managed_signer_signing_idempotency()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.purpose IS DISTINCT FROM OLD.purpose
     OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_identity_immutable',
      MESSAGE = 'managed signer signing identity is immutable';
  END IF;
  IF OLD.status = 'committed' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_committed_immutable',
      MESSAGE = 'committed managed signer response is immutable';
  END IF;
  IF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'uncertain', 'committed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_transition',
      MESSAGE = 'managed signer signing transition is not permitted';
  END IF;
  IF OLD.status = 'uncertain' AND NEW.status NOT IN ('uncertain', 'committed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_transition',
      MESSAGE = 'managed signer uncertain response cannot be reopened';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER managed_signer_signing_idempotency_guard
  BEFORE UPDATE ON managed_signer_signing_idempotency
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_managed_signer_signing_idempotency();

COMMENT ON TABLE managed_signer_key_lifecycles IS
  'Deployment-global managed signer lifecycle, isolated by immutable signer purpose.';
COMMENT ON TABLE managed_signer_keys IS
  'Public managed signer key metadata and bounded historical state; private material is never persisted.';
COMMENT ON TABLE managed_signer_key_lifecycle_operations IS
  'Durable purpose-scoped lifecycle operation digests and exact public snapshot replays.';
COMMENT ON TABLE managed_signer_signing_idempotency IS
  'Durable purpose-scoped signing claims and exact public signature replays; pending or uncertain rows fail closed.';

COMMIT;
