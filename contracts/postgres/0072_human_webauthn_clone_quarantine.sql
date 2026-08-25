BEGIN;

-- A verified assertion whose non-zero signature counter does not advance is
-- evidence that the credential may have been cloned or replayed.  Keep this
-- state distinct from a user-requested revocation so the final-credential
-- guard cannot prevent an emergency authentication shutdown.
ALTER TABLE webauthn_credentials
  ADD COLUMN sign_count_state text NOT NULL DEFAULT 'zero-counter'
    CHECK (sign_count_state IN ('zero-counter', 'monotonic', 'clone-detected')),
  ADD COLUMN clone_detected_at timestamptz,
  ADD CONSTRAINT webauthn_credentials_clone_state_valid CHECK (
    (sign_count_state = 'clone-detected') = (clone_detected_at IS NOT NULL)
  );

UPDATE webauthn_credentials
SET sign_count_state = CASE WHEN sign_count = 0 THEN 'zero-counter' ELSE 'monotonic' END;

CREATE INDEX webauthn_credentials_member_usable
  ON webauthn_credentials (member_id, created_at, id)
  WHERE revoked_at IS NULL AND clone_detected_at IS NULL;

CREATE FUNCTION agentpass_protect_webauthn_clone_quarantine()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.sign_count_state = 'clone-detected' THEN
    IF NEW.sign_count_state IS DISTINCT FROM OLD.sign_count_state
       OR NEW.clone_detected_at IS DISTINCT FROM OLD.clone_detected_at
       OR NEW.sign_count IS DISTINCT FROM OLD.sign_count
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'webauthn_credentials_clone_quarantine_monotonic',
        MESSAGE = 'WebAuthn clone quarantine is irreversible';
    END IF;
  ELSIF NEW.sign_count_state = 'clone-detected' THEN
    IF NEW.clone_detected_at IS NULL OR NEW.sign_count IS DISTINCT FROM OLD.sign_count THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'webauthn_credentials_clone_quarantine_transition',
        MESSAGE = 'WebAuthn clone quarantine transition is invalid';
    END IF;
  ELSIF NEW.clone_detected_at IS NOT NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_clone_quarantine_transition',
      MESSAGE = 'WebAuthn clone quarantine transition is invalid';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER webauthn_credentials_clone_quarantine_monotonic
  BEFORE UPDATE OF sign_count_state, clone_detected_at, sign_count
  ON webauthn_credentials
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_protect_webauthn_clone_quarantine();

-- A clone-quarantined credential is not a usable fallback when a human
-- explicitly revokes another credential.
CREATE OR REPLACE FUNCTION agentpass_prevent_last_webauthn_credential_revoke()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
    PERFORM pg_advisory_xact_lock(
      hashtextextended('agentpass:webauthn:credentials:' || NEW.member_id::text, 0)
    );

    IF OLD.clone_detected_at IS NULL AND NOT EXISTS (
      SELECT 1
      FROM webauthn_credentials
      WHERE member_id = NEW.member_id
        AND revoked_at IS NULL
        AND clone_detected_at IS NULL
        AND id <> NEW.id
    ) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'webauthn_credentials_last_active',
        MESSAGE = 'cannot revoke the last usable WebAuthn credential';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

COMMIT;
