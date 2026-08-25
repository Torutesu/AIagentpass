const MAX_LIMIT = 1_000;
const HEALTH_COUNT_CAP = 10_000;
const HEALTH_STATE_FIELDS = Object.freeze([
  "pending", "started", "accepted", "uncertain", "committed", "rejected", "failed"
]);
const MAINTENANCE_RESULT_FIELDS = Object.freeze([
  "quarantined", "reconciled", "pruned", "total"
]);
const HEALTH_RESULT_FIELDS = Object.freeze([
  "version", "states", "stale_started", "oldest_nonterminal_at"
]);
const NON_NEGATIVE_INTEGER = /^(?:0|[1-9][0-9]*)$/u;

const MAINTENANCE_FUNCTION_QUERY =
  "SELECT public.agentpass_maintain_managed_signer_provider_operations($1::integer) AS result";
const HEALTH_FUNCTION_QUERY =
  "SELECT public.agentpass_health_managed_signer_provider_operations() AS result";

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
 * Deployment-wide maintenance authority for provider-operation ledgers.
 *
 * The repository deliberately has no table access. The database owns the
 * candidate set, locking, correlation, clock, and mutation inside two
 * SECURITY DEFINER entry points. Only their bounded JSON result is exposed
 * to the application layer.
 */
export function createPostgresProviderOperationMaintenanceRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") {
    throw maintenanceError(PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.CONFIG);
  }

  async function maintainProviderOperations(input) {
    const limit = normalizeLimit(input);
    return runDatabase(async () => {
      const row = await queryFunction(client, MAINTENANCE_FUNCTION_QUERY, [limit]);
      return normalizeMaintenanceResult(row.result, limit);
    });
  }

  async function health(...args) {
    if (args.length !== 0) throw maintenanceError(PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.INPUT);
    return runDatabase(async () => {
      const row = await queryFunction(client, HEALTH_FUNCTION_QUERY, []);
      return normalizeHealthResult(row.result);
    });
  }

  return Object.freeze({ maintainProviderOperations, health });
}

async function queryFunction(client, text, params) {
  const result = await client.query(text, params);
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1
    || !plainObject(result.rows[0]) || !exactKeys(result.rows[0], ["result"])) throw databaseError();
  return result.rows[0];
}

function normalizeLimit(input) {
  if (!plainObject(input) || !exactKeys(input, ["limit"])
    || !Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > MAX_LIMIT) {
    throw maintenanceError(PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES.INPUT);
  }
  return input.limit;
}

function normalizeMaintenanceResult(value, limit) {
  if (!plainObject(value) || !exactKeys(value, MAINTENANCE_RESULT_FIELDS)) throw databaseError();
  const quarantined = boundedCount(value.quarantined, limit);
  const reconciled = boundedCount(value.reconciled, limit);
  const pruned = boundedCount(value.pruned, limit);
  const total = boundedCount(value.total, limit);
  if (total !== quarantined + reconciled + pruned || total > limit) throw databaseError();
  return Object.freeze({ quarantined, reconciled, pruned, total });
}

function normalizeHealthResult(value) {
  if (!plainObject(value) || !exactKeys(value, HEALTH_RESULT_FIELDS) || value.version !== 1
    || !plainObject(value.states) || !exactKeys(value.states, HEALTH_STATE_FIELDS)) throw databaseError();
  const states = Object.freeze(Object.fromEntries(
    HEALTH_STATE_FIELDS.map((state) => [state, boundedCount(value.states[state], HEALTH_COUNT_CAP)])
  ));
  return Object.freeze({
    version: 1,
    states,
    stale_started: boundedCount(value.stale_started, HEALTH_COUNT_CAP),
    oldest_nonterminal_at: timestampOrNull(value.oldest_nonterminal_at)
  });
}

function boundedCount(value, limit) {
  let normalized;
  if (typeof value === "number") normalized = value;
  else if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) normalized = Number(value);
  else if (typeof value === "string" && NON_NEGATIVE_INTEGER.test(value)) normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0 || normalized > limit || Object.is(normalized, -0)) {
    throw databaseError();
  }
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
