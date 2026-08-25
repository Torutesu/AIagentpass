BEGIN;

ALTER TABLE webauthn_challenges
  ADD COLUMN rp_id text,
  ADD COLUMN origin text,
  ADD COLUMN user_verification text,
  ADD COLUMN status text NOT NULL DEFAULT 'expired',
  ADD COLUMN consume_started_at timestamptz,
  ADD COLUMN failed_at timestamptz;

-- No pre-migration recent authorization is allowed to survive a change in
-- its challenge binding model.
UPDATE human_sessions
SET recent_auth_at = NULL,
    recent_auth_challenge_id = NULL,
    recent_auth_organization_id = NULL,
    recent_auth_operation = NULL,
    recent_auth_consumed_at = NULL
WHERE recent_auth_challenge_id IS NOT NULL;

-- Challenges created before this migration do not contain enough context to
-- verify an assertion. Preserve them only as inert audit history.
UPDATE webauthn_challenges
SET rp_id = 'invalid.agentpass.local',
    origin = 'https://invalid.agentpass.local',
    user_verification = 'required',
    status = CASE WHEN consumed_at IS NULL THEN 'expired' ELSE 'consumed' END;

ALTER TABLE webauthn_challenges
  ALTER COLUMN rp_id SET NOT NULL,
  ALTER COLUMN origin SET NOT NULL,
  ALTER COLUMN user_verification SET NOT NULL,
  ALTER COLUMN status DROP DEFAULT,
  ADD CONSTRAINT webauthn_challenges_rp_id_valid CHECK (
    char_length(rp_id) BETWEEN 1 AND 253
    AND rp_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$'
  ),
  ADD CONSTRAINT webauthn_challenges_origin_valid CHECK (
    char_length(origin) BETWEEN 9 AND 512
    AND origin ~ '^https://[^/?#@]+(?::[0-9]{1,5})?$'
  ),
  ADD CONSTRAINT webauthn_challenges_user_verification_valid CHECK (
    user_verification = 'required'
  ),
  ADD CONSTRAINT webauthn_challenges_status_valid CHECK (
    status IN ('pending', 'consuming', 'consumed', 'failed', 'expired')
  ),
  ADD CONSTRAINT webauthn_challenges_state_valid CHECK (
    (status = 'pending' AND consume_started_at IS NULL AND consumed_at IS NULL AND failed_at IS NULL)
    OR (status = 'consuming' AND consume_started_at IS NOT NULL AND consumed_at IS NULL AND failed_at IS NULL)
    OR (status = 'consumed' AND consumed_at IS NOT NULL AND failed_at IS NULL)
    OR (status = 'failed' AND consume_started_at IS NOT NULL AND consumed_at IS NOT NULL AND failed_at IS NOT NULL)
    OR (status = 'expired' AND consumed_at IS NULL AND failed_at IS NULL)
  );

DROP INDEX webauthn_challenges_one_live_operation;

CREATE UNIQUE INDEX webauthn_challenges_one_live_operation
  ON webauthn_challenges (session_id, organization_id, operation)
  WHERE status IN ('pending', 'consuming') AND consumed_at IS NULL;

DROP INDEX webauthn_challenges_expiry;

CREATE INDEX webauthn_challenges_expiry
  ON webauthn_challenges (expires_at)
  WHERE status IN ('pending', 'consuming') AND consumed_at IS NULL;

COMMIT;
