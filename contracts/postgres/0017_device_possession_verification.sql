BEGIN;

-- A candidate is a trusted release identity, not caller-supplied enrollment
-- metadata.  Its release bindings are immutable; retirement is the only
-- permitted state transition so an old receipt remains attributable to the
-- exact artifact that was qualified.
CREATE TABLE release_candidates (
  candidate_id text PRIMARY KEY
    CHECK (candidate_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  source_commit text NOT NULL
    CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  artifact_sha256 text NOT NULL
    CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  manifest_sha256 text NOT NULL
    CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  team_id text NOT NULL
    CHECK (team_id ~ '^[A-Z0-9]{10}$'),
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  CHECK ((status = 'active' AND retired_at IS NULL)
      OR (status = 'retired' AND retired_at IS NOT NULL)),
  CHECK (retired_at IS NULL OR retired_at >= created_at),
  UNIQUE (candidate_id, source_commit, artifact_sha256, team_id)
);

CREATE INDEX release_candidates_active_lookup
  ON release_candidates (status, created_at DESC, candidate_id)
  WHERE status = 'active';

CREATE OR REPLACE FUNCTION agentpass_guard_release_candidate_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'release candidates cannot be deleted',
      CONSTRAINT = 'release_candidates_forward_only';
  END IF;

  IF NEW.candidate_id <> OLD.candidate_id
     OR NEW.source_commit <> OLD.source_commit
     OR NEW.artifact_sha256 <> OLD.artifact_sha256
     OR NEW.manifest_sha256 <> OLD.manifest_sha256
     OR NEW.team_id <> OLD.team_id
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'release candidate identity is immutable',
      CONSTRAINT = 'release_candidates_forward_only';
  END IF;

  IF OLD.status = 'retired' THEN
    IF NEW.status <> OLD.status OR NEW.retired_at <> OLD.retired_at THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'retired release candidates cannot be reopened or rewritten',
        CONSTRAINT = 'release_candidates_forward_only';
    END IF;
  ELSIF OLD.status = 'active' AND NEW.status = 'retired' THEN
    IF NEW.retired_at IS NULL THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'retiring a release candidate requires retired_at',
        CONSTRAINT = 'release_candidates_forward_only';
    END IF;
  ELSIF NEW.status <> OLD.status THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'release candidate status only moves from active to retired',
      CONSTRAINT = 'release_candidates_forward_only';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER release_candidates_forward_only
  BEFORE UPDATE OR DELETE ON release_candidates
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_release_candidate_identity();

-- Version 1 reservations retain their existing semantics. Version 2 binds
-- the reservation to a trusted candidate, a native public-key fingerprint,
-- and a challenge digest. The challenge value itself is deliberately absent
-- from this schema.
ALTER TABLE device_enrollments
  ADD COLUMN proof_version integer NOT NULL DEFAULT 1,
  ADD COLUMN candidate_id text,
  ADD COLUMN device_key_fingerprint text,
  ADD COLUMN challenge_nonce_digest bytea,
  ADD CONSTRAINT device_enrollments_proof_version_valid
    CHECK (proof_version IN (1, 2)),
  ADD CONSTRAINT device_enrollments_candidate_id_valid
    CHECK (candidate_id IS NULL OR candidate_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  ADD CONSTRAINT device_enrollments_key_fingerprint_valid
    CHECK (device_key_fingerprint IS NULL OR device_key_fingerprint ~ '^SHA256:[A-Za-z0-9_-]{43}$'),
  ADD CONSTRAINT device_enrollments_challenge_digest_valid
    CHECK (challenge_nonce_digest IS NULL OR octet_length(challenge_nonce_digest) = 32),
  ADD CONSTRAINT device_enrollments_v2_binding_complete
    CHECK (
      (proof_version = 1
       AND candidate_id IS NULL
       AND device_key_fingerprint IS NULL
       AND challenge_nonce_digest IS NULL)
      OR
      (proof_version = 2
       AND candidate_id IS NOT NULL
       AND device_key_fingerprint IS NOT NULL
       AND challenge_nonce_digest IS NOT NULL)
    ),
  ADD CONSTRAINT device_enrollments_candidate_fk
    FOREIGN KEY (candidate_id) REFERENCES release_candidates(candidate_id),
  ADD CONSTRAINT device_enrollments_tenant_identity
    UNIQUE (organization_id, id),
  ADD CONSTRAINT device_enrollments_possession_identity
    UNIQUE (organization_id, id, device_id, candidate_id,
      device_key_fingerprint, challenge_nonce_digest);

CREATE INDEX device_enrollments_candidate_lookup
  ON device_enrollments (organization_id, candidate_id, device_id, created_at, id)
  WHERE proof_version = 2;

CREATE OR REPLACE FUNCTION agentpass_guard_device_enrollment_possession_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.proof_version = 2 AND (
    NEW.proof_version <> OLD.proof_version
    OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id
    OR NEW.device_key_fingerprint IS DISTINCT FROM OLD.device_key_fingerprint
    OR NEW.challenge_nonce_digest IS DISTINCT FROM OLD.challenge_nonce_digest
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'v2 device enrollment binding is immutable',
      CONSTRAINT = 'device_enrollments_v2_binding_forward_only';
  END IF;

  IF NEW.proof_version = 2 THEN
    PERFORM 1
    FROM release_candidates AS candidate
    WHERE candidate.candidate_id = NEW.candidate_id
      AND candidate.status = 'active'
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING
        ERRCODE = 'foreign_key_violation',
        MESSAGE = 'v2 device enrollment requires an active release candidate',
        CONSTRAINT = 'device_enrollments_candidate_fk';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER device_enrollments_v2_binding_forward_only
  BEFORE INSERT OR UPDATE OF proof_version, candidate_id,
    device_key_fingerprint, challenge_nonce_digest ON device_enrollments
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_device_enrollment_possession_binding();

-- Receipt JSON is a public, canonical statement body. It contains the digest
-- of the challenge, never the challenge value or a credential/private key.
-- Restricting values to scalars and the exact allow-list also prevents a
-- forbidden value from being hidden in a nested JSON object or array.
CREATE OR REPLACE FUNCTION agentpass_possession_statement_json_valid(statement_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  item record;
  key_count integer;
BEGIN
  IF jsonb_typeof(statement_value) <> 'object' THEN
    RETURN false;
  END IF;

  SELECT count(*) INTO key_count FROM jsonb_object_keys(statement_value);
  IF jsonb_typeof(statement_value) <> 'object'
     OR key_count <> 12
     OR NOT (statement_value ?& ARRAY[
       'version', 'enrollment_id', 'organization_id', 'device_id',
       'candidate_id', 'artifact_sha256', 'source_commit', 'team_id',
       'device_key_fingerprint', 'device_key_epoch',
       'challenge_nonce_digest', 'issued_at'
     ]) THEN
    RETURN false;
  END IF;

  FOR item IN SELECT object_entry.key, object_entry.value
    FROM jsonb_each(statement_value) AS object_entry(key, value) LOOP
    IF item.key NOT IN (
      'version', 'enrollment_id', 'organization_id', 'device_id',
      'candidate_id', 'artifact_sha256', 'source_commit', 'team_id',
      'device_key_fingerprint', 'device_key_epoch',
      'challenge_nonce_digest', 'issued_at'
    ) OR jsonb_typeof(item.value) NOT IN ('string', 'number') THEN
      RETURN false;
    END IF;
  END LOOP;

  RETURN statement_value->>'version' = '1'
    AND statement_value->>'challenge_nonce_digest' ~ '^[0-9a-f]{64}$'
    AND statement_value->>'artifact_sha256' ~ '^[0-9a-f]{64}$'
    AND statement_value->>'source_commit' ~ '^[0-9a-f]{40}$'
    AND statement_value->>'team_id' ~ '^[A-Z0-9]{10}$'
    AND statement_value->>'device_key_fingerprint' ~ '^SHA256:[A-Za-z0-9_-]{43}$';
END;
$$;

-- This table is deliberately keyed and constrained by organization. Every
-- identity-bearing foreign key includes organization_id, so a receipt for a
-- device/enrollment/key epoch from another tenant cannot be inserted.
CREATE TABLE device_enrollment_possession_receipts (
  organization_id uuid NOT NULL,
  enrollment_id uuid NOT NULL,
  device_id uuid NOT NULL,
  candidate_id text NOT NULL,
  artifact_sha256 text NOT NULL
    CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  source_commit text NOT NULL
    CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  team_id text NOT NULL
    CHECK (team_id ~ '^[A-Z0-9]{10}$'),
  device_key_fingerprint text NOT NULL
    CHECK (device_key_fingerprint ~ '^SHA256:[A-Za-z0-9_-]{43}$'),
  device_key_epoch bigint NOT NULL CHECK (device_key_epoch > 0),
  challenge_nonce_digest bytea NOT NULL
    CHECK (octet_length(challenge_nonce_digest) = 32),
  purpose text NOT NULL
    CHECK (purpose = 'device-enrollment-possession-receipt'),
  signer_key_id text NOT NULL
    CHECK (signer_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'),
  signature_algorithm text NOT NULL
    CHECK (signature_algorithm IN ('ed25519', 'p256-sha256')),
  statement_json jsonb NOT NULL
    CHECK (agentpass_possession_statement_json_valid(statement_json)),
  statement_hash text NOT NULL
    CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  signature_base64url text NOT NULL
    CHECK (signature_base64url ~ '^[A-Za-z0-9_-]{86}$'),
  issued_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, enrollment_id),
  UNIQUE (organization_id, device_id, device_key_epoch),
  FOREIGN KEY (organization_id, enrollment_id)
    REFERENCES device_enrollments(organization_id, id),
  FOREIGN KEY (organization_id, enrollment_id, device_id, candidate_id,
      device_key_fingerprint, challenge_nonce_digest)
    REFERENCES device_enrollments(organization_id, id, device_id, candidate_id,
      device_key_fingerprint, challenge_nonce_digest),
  FOREIGN KEY (organization_id, device_id)
    REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, device_id, device_key_epoch)
    REFERENCES device_key_epochs(organization_id, device_id, key_epoch),
  FOREIGN KEY (candidate_id, source_commit, artifact_sha256, team_id)
    REFERENCES release_candidates(candidate_id, source_commit, artifact_sha256, team_id),
  CHECK (statement_json->>'version' = '1'),
  CHECK (statement_json->>'enrollment_id' = enrollment_id::text),
  CHECK (statement_json->>'organization_id' = organization_id::text),
  CHECK (statement_json->>'device_id' = device_id::text),
  CHECK (statement_json->>'candidate_id' = candidate_id),
  CHECK (statement_json->>'artifact_sha256' = artifact_sha256),
  CHECK (statement_json->>'source_commit' = source_commit),
  CHECK (statement_json->>'team_id' = team_id),
  CHECK (statement_json->>'device_key_fingerprint' = device_key_fingerprint),
  CHECK (statement_json->>'device_key_epoch' = device_key_epoch::text),
  CHECK (statement_json->>'challenge_nonce_digest' = encode(challenge_nonce_digest, 'hex'))
);

CREATE INDEX device_enrollment_possession_receipts_device_lookup
  ON device_enrollment_possession_receipts
    (organization_id, device_id, issued_at DESC, enrollment_id);

CREATE INDEX device_enrollment_possession_receipts_candidate_lookup
  ON device_enrollment_possession_receipts
    (organization_id, candidate_id, issued_at DESC, enrollment_id);

-- Possession evidence is append-only. A retry must read the existing exact
-- receipt rather than rewrite its statement or signature.
CREATE OR REPLACE FUNCTION agentpass_guard_device_possession_receipt_forward_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = 'check_violation',
    MESSAGE = 'device possession receipts are append-only',
    CONSTRAINT = 'device_enrollment_possession_receipts_forward_only';
END;
$$;

CREATE TRIGGER device_enrollment_possession_receipts_forward_only
  BEFORE UPDATE OR DELETE ON device_enrollment_possession_receipts
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_device_possession_receipt_forward_only();

COMMIT;
