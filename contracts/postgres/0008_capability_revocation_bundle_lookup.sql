BEGIN;

-- ControlBundle generation reads only revoked capabilities that have not yet
-- expired. Keep the tenant predicate first and make expiry filtering bounded;
-- the repository still caps the signed result at the protocol maximum.
CREATE INDEX capabilities_revoked_bundle_lookup
  ON capabilities (organization_id, expires_at, id)
  WHERE revoked_at IS NOT NULL;

COMMIT;
