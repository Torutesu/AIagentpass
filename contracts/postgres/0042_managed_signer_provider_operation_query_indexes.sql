BEGIN;

-- 0041 bounded the maintenance operations but the deployment-wide health and
-- maintenance queries still had to discover their oldest or next candidate
-- by sorting the whole provider-operation ledger.  These partial indexes keep
-- those ordered LIMIT paths selective without indexing terminal or unrelated
-- rows.  The existing 0041 claim-expiry index already covers quarantine and
-- stale-started health, so it is intentionally not duplicated here.
CREATE INDEX managed_signer_provider_operations_nonterminal_created_at
  ON managed_signer_provider_operations (created_at)
  WHERE state IN ('pending', 'started', 'accepted', 'uncertain');

CREATE INDEX managed_signer_provider_operations_reconciliation
  ON managed_signer_provider_operations (updated_at, purpose, operation_id)
  WHERE state IN ('accepted', 'uncertain');

CREATE INDEX managed_signer_provider_operations_committed_expiry
  ON managed_signer_provider_operations (expires_at, purpose, operation_id)
  WHERE state = 'committed';

COMMENT ON INDEX managed_signer_provider_operations_nonterminal_created_at IS
  'Supports deployment-wide oldest nonterminal health selection with a bounded ordered scan.';

COMMENT ON INDEX managed_signer_provider_operations_reconciliation IS
  'Supports bounded SQL-only reconciliation of accepted or uncertain provider operations.';

COMMENT ON INDEX managed_signer_provider_operations_committed_expiry IS
  'Supports bounded deployment-wide pruning of expired committed provider operations.';

COMMIT;
