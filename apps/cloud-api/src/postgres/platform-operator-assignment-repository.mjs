const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const OPERATION = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const MAX_OPERATION_LENGTH = 128;
const PLATFORM_OPERATOR_ROLE = "platform_operator";

const INPUT_KEYS = Object.freeze([
  "capability", "member_id", "now", "operation", "organization_id", "session_id"
]);
const ASSIGNMENT_KEYS = Object.freeze([
  "assignment_id", "capability", "expires_at", "issued_at", "member_id",
  "operation", "organization_id", "role", "session_id", "status"
]);

// This is intentionally the only SQL issued by this repository. The function
// owns active-assignment selection, expiry checks, revocation checks, and all
// authority joins. In particular, organization membership roles are not an
// input to this boundary and cannot grant platform authority.
export const PLATFORM_OPERATOR_ASSIGNMENT_FIND_ACTIVE_SQL =
  "SELECT agentpass_platform_operator_assignment_find_active($1::uuid,$2::uuid,$3::uuid,$4::text,$5::text,$6::timestamptz) AS assignment";

export const PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_CONFIG",
  INPUT: "ERR_PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_INPUT",
  RESULT: "ERR_PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_RESULT",
  DATABASE: "ERR_PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_DATABASE"
});

const MESSAGES = Object.freeze({
  [PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.CONFIG]: "platform operator assignment repository configuration is invalid",
  [PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.INPUT]: "platform operator assignment request is invalid",
  [PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT]: "platform operator assignment returned an invalid database result",
  [PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.DATABASE]: "platform operator assignment storage is unavailable"
});

export class PlatformOperatorAssignmentRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "PlatformOperatorAssignmentRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code)
      ? code
      : PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.DATABASE;
  }
}

/**
 * Read-only PostgreSQL seam for the platform-operator assignment authority.
 *
 * The database function is the authority boundary. This adapter does not
 * inspect memberships, organization roles, or any other tenant repository and
 * does not perform a second query that could weaken the function's decision.
 */
export function createPostgresPlatformOperatorAssignmentRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") {
    throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.CONFIG);
  }

  async function findActivePlatformOperatorAssignment(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.INPUT);
    let values;
    try {
      values = normalizeInput(args[0]);
    } catch (error) {
      if (error instanceof PlatformOperatorAssignmentRepositoryError) throw error;
      throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.INPUT);
    }
    try {
      const result = await client.query(PLATFORM_OPERATOR_ASSIGNMENT_FIND_ACTIVE_SQL, [
        values.organization_id,
        values.member_id,
        values.session_id,
        values.operation,
        values.capability,
        values.now
      ]);
      try {
        return normalizeQueryResult(result, values);
      } catch (error) {
        if (error instanceof PlatformOperatorAssignmentRepositoryError) throw error;
        throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
      }
    } catch (error) {
      if (error instanceof PlatformOperatorAssignmentRepositoryError) throw error;
      throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.DATABASE);
    }
  }

  return Object.freeze({ findActivePlatformOperatorAssignment });
}

function normalizeInput(value) {
  if (!isPlainObject(value) || !exactKeys(value, INPUT_KEYS)) throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    capability: operationValue(value.capability),
    member_id: uuidValue(value.member_id),
    now: timestampValue(value.now),
    operation: operationValue(value.operation),
    organization_id: uuidValue(value.organization_id),
    session_id: uuidValue(value.session_id)
  });
}

function normalizeQueryResult(result, input) {
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1
    || !isPlainObject(result.rows[0]) || !exactKeys(result.rows[0], ["assignment"])) {
    throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  }
  const value = result.rows[0].assignment;
  if (value === null) return null;
  if (!isPlainObject(value) || !exactKeys(value, ASSIGNMENT_KEYS)) {
    throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  }

  const issuedAt = timestampValue(value.issued_at, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  const expiresAt = timestampValue(value.expires_at, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  if (Date.parse(issuedAt) >= Date.parse(expiresAt)) {
    throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  }

  const normalized = Object.freeze({
    assignment_id: uuidValue(value.assignment_id, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT),
    capability: operationValue(value.capability, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT),
    expires_at: expiresAt,
    issued_at: issuedAt,
    member_id: uuidValue(value.member_id, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT),
    operation: operationValue(value.operation, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT),
    organization_id: uuidValue(value.organization_id, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT),
    role: exactRole(value.role),
    session_id: uuidValue(value.session_id, PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT),
    status: exactStatus(value.status)
  });
  const nowMs = Date.parse(input.now);
  if (normalized.organization_id !== input.organization_id
    || normalized.member_id !== input.member_id
    || normalized.session_id !== input.session_id
    || normalized.operation !== input.operation
    || normalized.capability !== input.capability
    || Date.parse(normalized.issued_at) > nowMs
    || Date.parse(normalized.expires_at) <= nowMs) {
    throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  }
  return normalized;
}

function uuidValue(value, code = PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.INPUT) {
  if (typeof value !== "string" || !UUID.test(value)) throw repositoryError(code);
  return value.toLowerCase();
}

function operationValue(value, code = PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.INPUT) {
  if (typeof value !== "string" || value.length > MAX_OPERATION_LENGTH || !OPERATION.test(value)) {
    throw repositoryError(code);
  }
  return value;
}

function timestampValue(value, code = PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.INPUT) {
  if (typeof value !== "string" || !RFC3339.test(value)) throw repositoryError(code);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw repositoryError(code);
  return new Date(parsed).toISOString();
}

function exactRole(value) {
  if (value !== PLATFORM_OPERATOR_ROLE) throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function exactStatus(value) {
  if (value !== "active") throw repositoryError(PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function exactKeys(value, expected) {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && keys.every((key) => typeof key === "string"
    && expected.includes(key) && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function repositoryError(code) {
  return new PlatformOperatorAssignmentRepositoryError(code);
}

export default createPostgresPlatformOperatorAssignmentRepository;
