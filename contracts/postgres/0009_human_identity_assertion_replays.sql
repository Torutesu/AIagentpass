BEGIN;

-- The hosted Console BFF presents a short-lived, Ed25519-signed SIWC
-- assertion to the Cloud Human API.  Keep replay state separate from
-- idempotency records: this is an authentication-consumption ledger, not a
-- retry response cache, and it must not retain upstream identity attributes
-- or assertion material.
CREATE TABLE public.human_identity_assertion_replays (
  jti_digest bytea PRIMARY KEY CHECK (octet_length(jti_digest) = 32),
  expires_at timestamptz NOT NULL
);

-- Expired rows may be pruned by a bounded maintenance job.  The lookup is
-- intentionally ordered by expiry so pruning never needs to inspect claims.
CREATE INDEX human_identity_assertion_replays_expiry
  ON public.human_identity_assertion_replays (expires_at, jti_digest);

-- INSERT ... ON CONFLICT is the one-time consume primitive.  Concurrent
-- requests for the same digest can produce at most one true result; expired
-- assertions are refused before a row is written.  The digest is already
-- namespaced by the canonical issuer and audience at the protocol layer.
CREATE FUNCTION public.agentpass_consume_human_identity_assertion(
  assertion_jti_digest bytea,
  assertion_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF assertion_jti_digest IS NULL
     OR octet_length(assertion_jti_digest) <> 32
     OR assertion_expires_at <= clock_timestamp() THEN
    RETURN false;
  END IF;

  INSERT INTO public.human_identity_assertion_replays (jti_digest, expires_at)
  VALUES (assertion_jti_digest, assertion_expires_at)
  ON CONFLICT (jti_digest) DO NOTHING;
  RETURN FOUND;
END;
$$;

COMMIT;
