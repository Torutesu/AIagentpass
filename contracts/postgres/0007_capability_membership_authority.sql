BEGIN;

-- Capability rows created before membership authority was persisted do not
-- contain enough evidence to reconstruct their human issuer. Keep that fact
-- explicit instead of inventing attribution during migration.
ALTER TABLE capabilities
  ADD COLUMN issued_by_member_id uuid,
  ADD COLUMN issued_membership_version bigint;

ALTER TABLE capabilities
  ADD CONSTRAINT capabilities_issued_membership_version_valid
  CHECK (issued_membership_version > 0)
  NOT VALID;

-- Legacy bearer authority cannot safely remain active when its issuer is
-- unknown. Revocation is the only non-fictional migration. Historical rows
-- retain NULL attribution so audits do not claim evidence that never existed.
UPDATE capabilities
SET revoked_at = clock_timestamp()
WHERE revoked_at IS NULL;

ALTER TABLE capabilities
  VALIDATE CONSTRAINT capabilities_issued_membership_version_valid;

ALTER TABLE capabilities
  ADD CONSTRAINT capabilities_issued_by_member_fk
  FOREIGN KEY (issued_by_member_id)
  REFERENCES members (id),
  ADD CONSTRAINT capabilities_issued_by_member_tenant_fk
  FOREIGN KEY (organization_id, issued_by_member_id)
  REFERENCES memberships (organization_id, member_id),
  ADD CONSTRAINT capabilities_active_membership_authority_complete
  CHECK (
    revoked_at IS NOT NULL
    OR (issued_by_member_id IS NOT NULL AND issued_membership_version IS NOT NULL)
  );

-- The single-column FK protects member existence; the composite FK protects
-- tenant attribution and uses memberships' existing unique organization/member
-- key.  Keep a tenant-leading partial index for the revoke hot path.
CREATE INDEX capabilities_issued_by_member_active_lookup
  ON capabilities (organization_id, issued_by_member_id, id)
  WHERE revoked_at IS NULL;

COMMIT;
