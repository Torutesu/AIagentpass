const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1_000;
const RESULT_KEYS = Object.freeze(["published", "dead_letter", "suppressed", "total"]);
const RESULT_KEY_SET = new Set(RESULT_KEYS);
const NON_NEGATIVE_INTEGER = /^(?:0|[1-9][0-9]*)$/u;

export const OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "owner_recovery_outbox_retention_invalid_request",
  UNAVAILABLE: "owner_recovery_outbox_retention_unavailable"
});

const MESSAGES = Object.freeze({
  [OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES.INVALID_REQUEST]: "Owner recovery outbox retention request is invalid",
  [OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES.UNAVAILABLE]: "Owner recovery outbox retention storage is unavailable"
});

export class OwnerRecoveryOutboxRetentionRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES.UNAVAILABLE]);
    this.name = "OwnerRecoveryOutboxRetentionRepositoryError";
    this.code = MESSAGES[code] === undefined
      ? OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES.UNAVAILABLE
      : code;
  }
}

/**
 * PostgreSQL authority for bounded deletion of terminal owner-recovery
 * outbox rows. The database function owns retention eligibility; this
 * boundary only supplies a bounded batch size and validates its aggregate.
 */
export function createPostgresOwnerRecoveryOutboxRetentionRepository({ client, metrics } = {}) {
  assertClient(client);

  async function prune(input = {}) {
    let limit;
    try {
      limit = normalizeInput(input);
    } catch (error) {
      if (error instanceof OwnerRecoveryOutboxRetentionRepositoryError) throw error;
      throw invalidRequest();
    }
    try {
      const result = await client.query(
        "SELECT published,dead_letter,suppressed,total FROM agentpass_prune_owner_recovery_outbox_terminal($1::integer)",
        [limit]
      );
      const pruned = validateResult(result, limit);
      if (pruned.total > 0) recordPruneMetric(metrics, pruned.total);
      return pruned;
    } catch {
      // Do not expose driver diagnostics, SQL text, or a rejected cause.
      throw unavailable();
    }
  }

  return Object.freeze({ prune });
}

function normalizeInput(input) {
  if (!isPlainObject(input)) throw invalidRequest();
  if (Reflect.ownKeys(input).some((key) => key !== "limit")) throw invalidRequest();
  if (input.limit === undefined) return DEFAULT_LIMIT;
  if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > MAX_LIMIT) throw invalidRequest();
  return input.limit;
}

function validateResult(result, limit) {
  // node-postgres returns a Result class instance, not a plain object. Treat
  // only its rows/rowCount envelope as transport metadata; the authoritative
  // database row below remains an exact plain four-field DTO.
  if (!result || typeof result !== "object" || Array.isArray(result) || !Array.isArray(result.rows) || result.rows.length !== 1) throw unavailable();
  if (result.rowCount !== undefined && result.rowCount !== 1) throw unavailable();
  const row = result.rows[0];
  if (!isPlainObject(row)) throw unavailable();
  const keys = Reflect.ownKeys(row);
  if (keys.length !== RESULT_KEYS.length || keys.some((key) => typeof key !== "string" || !RESULT_KEY_SET.has(key))) throw unavailable();

  const values = {};
  for (const key of RESULT_KEYS) values[key] = safeNonNegativeInteger(row[key]);
  const sum = BigInt(values.published) + BigInt(values.dead_letter) + BigInt(values.suppressed);
  if (sum !== BigInt(values.total) || values.total > limit) throw unavailable();
  return Object.freeze(values);
}

function safeNonNegativeInteger(value) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) throw unavailable();
    return value;
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw unavailable();
    return Number(value);
  }
  if (typeof value === "string" && NON_NEGATIVE_INTEGER.test(value)) {
    const number = Number(value);
    if (Number.isSafeInteger(number)) return number;
  }
  throw unavailable();
}

function recordPruneMetric(metrics, total) {
  try {
    if (!metrics || typeof metrics.recordOwnerRecoveryOutboxPrune !== "function") return;
    const outcome = metrics.recordOwnerRecoveryOutboxPrune(total);
    if (outcome && typeof outcome.then === "function") outcome.catch(() => {});
  } catch {
    // Observability must not turn a committed prune into an operational error.
  }
}

function invalidRequest() {
  return new OwnerRecoveryOutboxRetentionRepositoryError(
    OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES.INVALID_REQUEST
  );
}

function unavailable() {
  return new OwnerRecoveryOutboxRetentionRepositoryError(
    OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES.UNAVAILABLE
  );
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)");
}

export default createPostgresOwnerRecoveryOutboxRetentionRepository;
