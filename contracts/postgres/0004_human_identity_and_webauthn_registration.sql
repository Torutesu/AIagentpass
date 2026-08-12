BEGIN;

-- `github_subject` is retained as a legacy compatibility column. New
-- identities are represented by the provider-neutral mapping below.
ALTER TABLE members
  ALTER COLUMN github_subject DROP NOT NULL;

CREATE TABLE upstream_identities (
  provider text NOT NULL CHECK (
    char_length(provider) BETWEEN 1 AND 64
    AND provider ~ '^[a-z][a-z0-9._-]*$'
  ),
  subject text NOT NULL CHECK (
    char_length(subject) BETWEEN 1 AND 512
    AND octet_length(subject) <= 512
    AND subject !~ '[[:cntrl:]]'
  ),
  member_id uuid NOT NULL REFERENCES members(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (provider, subject)
);

CREATE INDEX upstream_identities_member_id
  ON upstream_identities (member_id, provider, subject);

-- An upstream identity may be created idempotently, but it must never be
-- reassigned to another member or have its provider/subject altered.
CREATE FUNCTION agentpass_reject_upstream_identity_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = 'restrict_violation',
    MESSAGE = 'upstream identity mappings are immutable';
  RETURN NEW;
END;
$$;

CREATE TRIGGER upstream_identities_immutable
  BEFORE UPDATE ON upstream_identities
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_reject_upstream_identity_update();

-- Preserve existing GitHub-backed members while moving all future identity
-- resolution to the provider-neutral table.
INSERT INTO upstream_identities (provider, subject, member_id)
SELECT 'github', github_subject, id
FROM members
WHERE github_subject IS NOT NULL
ON CONFLICT (provider, subject) DO NOTHING;

CREATE FUNCTION agentpass_valid_webauthn_transports(value text[])
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
  item text;
  seen text[] := ARRAY[]::text[];
BEGIN
  IF cardinality(value) > 7 THEN
    RETURN false;
  END IF;
  FOREACH item IN ARRAY value LOOP
    IF item IS NULL OR item NOT IN ('ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb') OR item = ANY(seen) THEN
      RETURN false;
    END IF;
    seen := array_append(seen, item);
  END LOOP;
  RETURN true;
END;
$$;

ALTER TABLE webauthn_credentials
  ADD COLUMN label text NOT NULL DEFAULT 'Unnamed credential',
  ADD COLUMN backup_eligible boolean NOT NULL DEFAULT false,
  ADD COLUMN backup_state boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT webauthn_credentials_label_valid CHECK (
    char_length(label) BETWEEN 1 AND 128
    AND label !~ '[[:cntrl:]]'
  ),
  ADD CONSTRAINT webauthn_credentials_transports_valid CHECK (
    agentpass_valid_webauthn_transports(transports)
  ),
  ADD CONSTRAINT webauthn_credentials_backup_state_valid CHECK (
    backup_state = false OR backup_eligible = true
  );

-- Existing rows receive an explicit compatibility value; new registration
-- writes must provide all registration metadata themselves.
ALTER TABLE webauthn_credentials
  ALTER COLUMN label DROP DEFAULT,
  ALTER COLUMN backup_eligible DROP DEFAULT,
  ALTER COLUMN backup_state DROP DEFAULT;

CREATE INDEX webauthn_credentials_member_created
  ON webauthn_credentials (member_id, created_at, id);

COMMIT;
