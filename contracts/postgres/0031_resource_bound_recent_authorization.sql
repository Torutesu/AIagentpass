BEGIN;

-- Recent authorization context is intentionally nullable.  NULL is the
-- legacy, operation-only authorization form; a non-NULL value is the
-- SHA-256 digest of the exact resource/action/version being authorized.
-- Keeping the column nullable makes this migration safe for rows created by
-- the pre-context application while the completeness checks prevent a
-- partially-bound record from being stored.
ALTER TABLE webauthn_challenges
  ADD COLUMN context_hash bytea,
  ADD CONSTRAINT webauthn_challenges_context_hash_valid CHECK (
    context_hash IS NULL OR octet_length(context_hash) = 32
  );

ALTER TABLE human_sessions
  ADD COLUMN recent_auth_context_hash bytea,
  ADD CONSTRAINT human_sessions_context_hash_valid CHECK (
    recent_auth_context_hash IS NULL OR octet_length(recent_auth_context_hash) = 32
  );

-- Replace the original completeness check so clearing recent authorization
-- also clears its resource binding.  Both forms remain valid:
--   * legacy: recent authorization exists and context_hash IS NULL
--   * bound:  recent authorization exists and context_hash is a 32-byte hash
-- The consumed timestamp remains nullable while the authorization is being
-- consumed, as in the original contract.
ALTER TABLE human_sessions
  DROP CONSTRAINT human_sessions_recent_auth_complete,
  ADD CONSTRAINT human_sessions_recent_auth_complete CHECK (
    (
      recent_auth_at IS NULL
      AND recent_auth_challenge_id IS NULL
      AND recent_auth_organization_id IS NULL
      AND recent_auth_operation IS NULL
      AND recent_auth_context_hash IS NULL
      AND recent_auth_consumed_at IS NULL
    )
    OR
    (
      recent_auth_at IS NOT NULL
      AND recent_auth_challenge_id IS NOT NULL
      AND recent_auth_organization_id IS NOT NULL
      AND recent_auth_operation IS NOT NULL
      AND (recent_auth_context_hash IS NULL OR octet_length(recent_auth_context_hash) = 32)
    )
  );

-- The old index coalesced every live challenge for an operation, even when
-- callers had asked for different resources.  Preserve one live legacy
-- challenge per operation and independently allow one live challenge per
-- resource-bound context.  Two partial indexes are used because PostgreSQL
-- treats NULL values as distinct in a normal unique index.
DROP INDEX webauthn_challenges_one_live_operation;

CREATE UNIQUE INDEX webauthn_challenges_one_live_operation
  ON webauthn_challenges (session_id, organization_id, operation)
  WHERE status IN ('pending', 'consuming')
    AND consumed_at IS NULL
    AND context_hash IS NULL;

CREATE UNIQUE INDEX webauthn_challenges_one_live_operation_bound
  ON webauthn_challenges (session_id, organization_id, operation, context_hash)
  WHERE status IN ('pending', 'consuming')
    AND consumed_at IS NULL
    AND context_hash IS NOT NULL;

-- A session's recent authorization must refer to the exact same context as
-- its challenge.  The trigger permits both legacy NULL/NULL and bound
-- hash/hash pairs, but rejects a mixed pair or a cross-organization link.
CREATE FUNCTION agentpass_validate_recent_auth_context()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  challenge_organization_id uuid;
  challenge_context_hash bytea;
BEGIN
  IF NEW.recent_auth_challenge_id IS NULL THEN
    IF NEW.recent_auth_context_hash IS NOT NULL THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'human_sessions_recent_auth_complete',
        MESSAGE = 'recent authorization context requires a challenge';
    END IF;
    RETURN NEW;
  END IF;

  SELECT organization_id, context_hash
    INTO challenge_organization_id, challenge_context_hash
  FROM webauthn_challenges
  WHERE id = NEW.recent_auth_challenge_id;

  IF NOT FOUND
     OR challenge_organization_id IS DISTINCT FROM NEW.recent_auth_organization_id
     OR challenge_context_hash IS DISTINCT FROM NEW.recent_auth_context_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'human_sessions_recent_auth_context_binding',
      MESSAGE = 'recent authorization context does not match its challenge';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER human_sessions_recent_auth_context_binding
  BEFORE INSERT OR UPDATE OF organization_id, recent_auth_at,
    recent_auth_challenge_id, recent_auth_organization_id,
    recent_auth_operation, recent_auth_consumed_at, recent_auth_context_hash
  ON human_sessions
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_validate_recent_auth_context();

-- Once a challenge is referenced by a recent authorization, changing its
-- context would invalidate that authorization.  Allow NULL -> hash
-- backfills for unreferenced legacy challenges, but make an established
-- session/challenge binding immutable until the session is cleared.
CREATE FUNCTION agentpass_guard_recent_auth_context_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.context_hash IS DISTINCT FROM OLD.context_hash
     AND EXISTS (
       SELECT 1
       FROM human_sessions
       WHERE recent_auth_challenge_id = OLD.id
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'human_sessions_recent_auth_context_binding',
      MESSAGE = 'cannot change a challenge context referenced by recent authorization';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER webauthn_challenges_recent_auth_context_guard
  BEFORE UPDATE OF context_hash ON webauthn_challenges
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_recent_auth_context_update();

COMMIT;
