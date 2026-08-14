import { withTransaction } from "./repository.mjs";

const MAX_LIMIT = 1_000;
const HEALTH_COUNT_CAP = 10_000;
const HEALTH_STATE_FIELDS = Object.freeze([
  "pending", "started", "accepted", "uncertain", "committed", "rejected", "failed"
]);
const NON_NEGATIVE_INTEGER = /^(?:0|[1-9][0-9]*)$/u;

export const PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_CONFIG",
  INPUT: "ERR_PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_INPUT",
  DATABASE: "ERR_PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_DATABASE"
});

const MESSAGES = Object.freeze({
  [PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.CONFIG]: "provider operation maintenance repository configuration is invalid",
  [PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.INPUT]: "provider operation maintenance request is invalid",
  [PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.DATABASE]: "provider operation maintenance storage is unavailable"
});

export class ProviderOperationMaintenanceRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "ProviderOperationMaintenanceRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code)
      ? code
      : PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.DATABASE;
  }
}

/**
 * Deployment-wide maintenance authority for the provider-operation ledgers.
 * There is deliberately no purpose, tenant, key, or operation selector here.
 * The database owns the candidate set and all selection is bounded.
 */
export function createPostgresProviderOperationMaintenanceRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") throw maintenanceError(PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.CONFIG);

  async function maintainProviderOperations(input) {
    const limit = normalizeLimit(input);
    return runDatabase(() => withTransaction(client, async (tx) => {
      const quarantined = await quarantineExpiredStarted(tx, limit);
      let remaining = limit - quarantined;

      // There is no provider lookup API, request bytes, or signing bytes in
      // this worker.  The only safe automatic reconciliation is the existing
      // SQL-only correlation below: the high-level terminal row must contain
      // the exact binding, request digest, signature, and provider receipt
      // already verified and committed by the application path.
      let reconciled = 0;
      if (remaining > 0) {
        reconciled = await reconcileCorrelatedOperations(tx, remaining);
        remaining -= reconciled;
      }

      let pruned = 0;
      if (remaining > 0) pruned = await pruneCorrelatedOperations(tx, remaining);

      return maintenanceResult({ quarantined, reconciled, pruned, limit });
    }));
  }

  async function health(...args) {
    if (args.length !== 0) throw maintenanceError(PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.INPUT);
    return runDatabase(async () => {
      const result = await client.query(`SELECT
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations WHERE state='pending' LIMIT $1
        ) bounded) AS pending,
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations WHERE state='started' LIMIT $1
        ) bounded) AS started,
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations WHERE state='accepted' LIMIT $1
        ) bounded) AS accepted,
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations WHERE state='uncertain' LIMIT $1
        ) bounded) AS uncertain,
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations WHERE state='committed' LIMIT $1
        ) bounded) AS committed,
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations WHERE state='rejected' LIMIT $1
        ) bounded) AS rejected,
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations WHERE state='failed' LIMIT $1
        ) bounded) AS failed,
        (SELECT count(*) FROM (
          SELECT 1 FROM managed_signer_provider_operations
          WHERE state='started' AND claim_expires_at IS NOT NULL
            AND claim_expires_at<=clock_timestamp()
          LIMIT $1
        ) bounded) AS stale_started,
        (SELECT created_at FROM managed_signer_provider_operations
          WHERE state IN ('pending','started','accepted','uncertain')
          ORDER BY created_at ASC
          LIMIT 1) AS oldest_nonterminal_at`, [HEALTH_COUNT_CAP]);
      if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) throw databaseError();
      const row = result.rows[0];
      const expected = [...HEALTH_STATE_FIELDS, "stale_started", "oldest_nonterminal_at"];
      if (!plainObject(row) || !exactKeys(row, expected)) throw databaseError();
      const states = Object.freeze(Object.fromEntries(HEALTH_STATE_FIELDS.map((state) => [state, boundedCount(row[state], HEALTH_COUNT_CAP)])));
      return Object.freeze({
        version: 1,
        states,
        stale_started: boundedCount(row.stale_started, HEALTH_COUNT_CAP),
        oldest_nonterminal_at: timestampOrNull(row.oldest_nonterminal_at)
      });
    });
  }

  return Object.freeze({ maintainProviderOperations, health });
}

async function quarantineExpiredStarted(client, limit) {
  const result = await client.query(
    "SELECT agentpass_quarantine_expired_managed_signer_provider_operations($1::integer) AS quarantined",
    [limit]
  );
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1
    || !plainObject(result.rows[0]) || !exactKeys(result.rows[0], ["quarantined"])) throw databaseError();
  return boundedCount(result.rows[0].quarantined, limit);
}

async function reconcileCorrelatedOperations(client, limit) {
  const result = await client.query(`WITH candidates AS MATERIALIZED (
      SELECT provider.purpose,provider.operation_id
      FROM managed_signer_provider_operations provider
      JOIN managed_signer_signing_idempotency signing
        ON signing.purpose=provider.purpose AND signing.operation_id=provider.operation_id
      WHERE provider.state IN ('accepted','uncertain')
        AND signing.status='committed'
        AND provider.request_digest=signing.request_digest
        AND provider.key_id=signing.key_id
        AND provider.key_version=signing.key_version
        AND provider.signature=signing.signature
        AND provider.provider_receipt_provider=signing.provider_receipt_provider
        AND provider.provider_receipt_id=signing.provider_receipt_id
      ORDER BY provider.updated_at ASC,provider.purpose ASC,provider.operation_id ASC
      LIMIT $1
      FOR UPDATE OF provider,signing SKIP LOCKED
    ), reconciled AS (
      UPDATE managed_signer_provider_operations provider
      SET state='committed',uncertain_reason=NULL,claim_token_digest=NULL,claim_expires_at=NULL
      FROM candidates
      WHERE provider.purpose=candidates.purpose AND provider.operation_id=candidates.operation_id
      RETURNING provider.purpose,provider.operation_id
    )
    SELECT count(*)::integer AS reconciled FROM reconciled`, [limit]);
  return readBoundedAggregate(result, "reconciled", limit);
}

async function pruneCorrelatedOperations(client, limit) {
  const result = await client.query(`WITH candidates AS MATERIALIZED (
      SELECT provider.purpose,provider.operation_id
      FROM managed_signer_provider_operations provider
      JOIN managed_signer_signing_idempotency signing
        ON signing.purpose=provider.purpose AND signing.operation_id=provider.operation_id
      CROSS JOIN (SELECT clock_timestamp() AS now) database_clock
      WHERE provider.state='committed'
        AND signing.status='committed'
        AND provider.expires_at<=database_clock.now
        AND signing.expires_at<=database_clock.now
      ORDER BY provider.expires_at ASC,signing.expires_at ASC,provider.purpose ASC,provider.operation_id ASC
      LIMIT $1
      FOR UPDATE OF provider,signing SKIP LOCKED
    ), deleted_signing AS (
      DELETE FROM managed_signer_signing_idempotency signing
      USING candidates
      WHERE signing.purpose=candidates.purpose AND signing.operation_id=candidates.operation_id
      RETURNING signing.purpose,signing.operation_id
    ), deleted_provider AS (
      DELETE FROM managed_signer_provider_operations provider
      USING deleted_signing
      WHERE provider.purpose=deleted_signing.purpose AND provider.operation_id=deleted_signing.operation_id
      RETURNING provider.purpose,provider.operation_id
    )
    SELECT count(*)::integer AS pruned FROM deleted_provider`, [limit]);
  return readBoundedAggregate(result, "pruned", limit);
}

function normalizeLimit(input) {
  if (!plainObject(input) || !exactKeys(input, ["limit"])
    || !Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > MAX_LIMIT) {
    throw maintenanceError(PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.INPUT);
  }
  return input.limit;
}

function maintenanceResult({ quarantined, reconciled, pruned, limit }) {
  const total = quarantined + reconciled + pruned;
  if (![quarantined, reconciled, pruned, total].every((value) => Number.isSafeInteger(value) && value >= 0)
    || total > limit) throw databaseError();
  return Object.freeze({ quarantined, reconciled, pruned, total });
}

function readBoundedAggregate(result, field, limit) {
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1
    || !plainObject(result.rows[0]) || !exactKeys(result.rows[0], [field])) throw databaseError();
  return boundedCount(result.rows[0][field], limit);
}

function boundedCount(value, limit) {
  let normalized;
  if (typeof value === "number") normalized = value;
  else if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) normalized = Number(value);
  else if (typeof value === "string" && NON_NEGATIVE_INTEGER.test(value)) normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0 || normalized > limit || Object.is(normalized, -0)) throw databaseError();
  return normalized;
}

function timestampOrNull(value) {
  if (value === null) return null;
  const parsed = value instanceof Date ? value.getTime() : Date.parse(String(value));
  if (!Number.isFinite(parsed)) throw databaseError();
  return new Date(parsed).toISOString();
}

async function runDatabase(operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ProviderOperationMaintenanceRepositoryError) throw error;
    throw databaseError();
  }
}

function maintenanceError(code) {
  return new ProviderOperationMaintenanceRepositoryError(code);
}

function databaseError() {
  return maintenanceError(PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.DATABASE);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function exactKeys(value, expected) {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && keys.every((key) => typeof key === "string"
    && expected.includes(key) && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true);
}

export default createPostgresProviderOperationMaintenanceRepository;
