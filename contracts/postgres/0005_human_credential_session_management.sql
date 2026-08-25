BEGIN;

-- Credential metadata is edited optimistically.  The version is deliberately
-- separate from the WebAuthn signature counter: the former protects human
-- management mutations, while the latter protects assertion replay.
ALTER TABLE webauthn_credentials
  ADD COLUMN version bigint NOT NULL DEFAULT 1,
  ADD COLUMN revoke_reason text,
  ADD CONSTRAINT webauthn_credentials_version_valid CHECK (version > 0);

ALTER TABLE human_sessions
  ADD COLUMN version bigint NOT NULL DEFAULT 1,
  ADD CONSTRAINT human_sessions_version_valid CHECK (version > 0);

ALTER TABLE webauthn_credentials
  ADD CONSTRAINT webauthn_credentials_revoke_reason_valid CHECK (
    revoke_reason IS NULL
    OR (char_length(revoke_reason) BETWEEN 1 AND 128 AND revoke_reason !~ '[[:cntrl:]]')
  );

CREATE INDEX webauthn_credentials_member_active
  ON webauthn_credentials (member_id, created_at, id)
  WHERE revoked_at IS NULL;

-- Every supported credential revocation takes this transaction-scoped lock.
-- The trigger also protects callers that bypass the JavaScript repository, and
-- serializes concurrent revocations for the same member before counting the
-- remaining active credentials.
CREATE FUNCTION agentpass_prevent_last_webauthn_credential_revoke()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
    PERFORM pg_advisory_xact_lock(
      hashtextextended('agentpass:webauthn:credentials:' || NEW.member_id::text, 0)
    );

    IF NOT EXISTS (
      SELECT 1
      FROM webauthn_credentials
      WHERE member_id = NEW.member_id
        AND revoked_at IS NULL
        AND id <> NEW.id
    ) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'webauthn_credentials_last_active',
        MESSAGE = 'cannot revoke the last active WebAuthn credential';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER webauthn_credentials_protect_last_active
  BEFORE UPDATE OF revoked_at ON webauthn_credentials
  FOR EACH ROW
  WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION agentpass_prevent_last_webauthn_credential_revoke();

COMMIT;
