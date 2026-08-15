const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const OPERATION = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const PLATFORM_OPERATOR_ROLE = "platform_operator";
const MAX_OPERATION_LENGTH = 128;

export { PLATFORM_OPERATOR_ROLE };

const REPOSITORY_METHODS = Object.freeze(["findActivePlatformOperatorAssignment"]);
const PRINCIPAL_KEYS = new Set([
  "created_at",
  "expires_at",
  "member_id",
  "organization_id",
  "recent_auth_at",
  "role",
  "session_id",
  "version"
]);
const INPUT_KEYS = new Set(["capability", "input", "operation", "principal", "request"]);
const ASSIGNMENT_KEYS = Object.freeze([
  "assignment_id",
  "capability",
  "expires_at",
  "issued_at",
  "member_id",
  "operation",
  "organization_id",
  "role",
  "session_id",
  "status"
]);

export const PLATFORM_OPERATOR_AUTHORIZER_REPOSITORY_METHODS = REPOSITORY_METHODS;
export const PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES = Object.freeze({
  DENIED: "platform_operator_authorizer_denied",
  INVALID_CONFIGURATION: "platform_operator_authorizer_invalid_configuration",
  REPOSITORY_UNAVAILABLE: "platform_operator_authorizer_repository_unavailable",
  REPOSITORY_INVALID: "platform_operator_authorizer_repository_invalid"
});

const ERROR_MESSAGES = Object.freeze({
  [PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.DENIED]: "Platform operator authorization denied",
  [PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.INVALID_CONFIGURATION]: "Platform operator authorization is unavailable",
  [PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_UNAVAILABLE]: "Platform operator authorization is unavailable",
  [PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_INVALID]: "Platform operator authorization is unavailable"
});

const DENIED = Object.freeze({ allowed: false });

/**
 * Public, non-sensitive failures for the platform authorization seam.
 *
 * Repository and row-shape failures intentionally collapse to one generic
 * message. The original database/provider error is never attached to this
 * error because callers must not be able to recover implementation details
 * from the authorization boundary.
 */
export class PlatformOperatorAuthorizationError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_UNAVAILABLE]);
    this.name = "PlatformOperatorAuthorizationError";
    this.code = Object.hasOwn(ERROR_MESSAGES, code)
      ? code
      : PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_UNAVAILABLE;
    this.status = this.code === PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.DENIED
      ? 403
      : this.code === PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.INVALID_CONFIGURATION ? 500 : 503;
  }
}

/**
 * Build the platform-operator authorization capability.
 *
 * The injected repository is deliberately narrower than the organization
 * repository. It must return either null (a policy denial) or one exact,
 * active assignment row. The row is revalidated here so a repository bug or
 * an over-broad SQL projection cannot turn an organization role into global
 * platform authority.
 *
 * The returned value is callable for the existing HTTP seam and also exposes
 * `.authorize` and `.assertAuthorized` for service-oriented callers.
 */
export function createPlatformOperatorAuthorizer({ repository, now = () => Date.now() } = {}) {
  if (!repository || typeof repository !== "object" || Array.isArray(repository)) {
    throw new TypeError("platform operator repository is required");
  }
  for (const method of REPOSITORY_METHODS) {
    if (typeof repository[method] !== "function") {
      throw new TypeError(`platform operator repository must expose ${method}()`);
    }
  }
  if (typeof now !== "function") throw new TypeError("now must be a function");

  async function authorize(input = {}) {
    const parsed = parseAuthorizationInput(input);
    if (parsed === null) return DENIED;

    const nowMs = readClock(now);
    if (parsed.principal.created_at_ms > nowMs || parsed.principal.expires_at_ms <= nowMs) return DENIED;
    let assignment;
    try {
      assignment = await repository.findActivePlatformOperatorAssignment(Object.freeze({
        capability: parsed.capability,
        member_id: parsed.principal.member_id,
        operation: parsed.operation,
        organization_id: parsed.principal.organization_id,
        session_id: parsed.principal.session_id,
        now: new Date(nowMs).toISOString()
      }));
    } catch {
      throw new PlatformOperatorAuthorizationError(PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_UNAVAILABLE);
    }

    if (assignment === null || assignment === undefined) return DENIED;
    if (!isValidAssignment(assignment)) {
      throw new PlatformOperatorAuthorizationError(PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_INVALID);
    }

    const issuedAt = Date.parse(assignment.issued_at);
    const expiresAt = Date.parse(assignment.expires_at);
    if (assignment.status !== "active"
      || assignment.role !== PLATFORM_OPERATOR_ROLE
      || assignment.session_id.toLowerCase() !== parsed.principal.session_id
      || assignment.member_id.toLowerCase() !== parsed.principal.member_id
      || assignment.organization_id.toLowerCase() !== parsed.principal.organization_id
      || assignment.operation !== parsed.operation
      || assignment.capability !== parsed.capability
      || !Number.isFinite(issuedAt)
      || !Number.isFinite(expiresAt)
      || issuedAt > nowMs
      || expiresAt <= nowMs) {
      return DENIED;
    }

    return Object.freeze({
      allowed: true,
      role: PLATFORM_OPERATOR_ROLE,
      capability: parsed.capability
    });
  }

  async function assertAuthorized(input = {}) {
    const decision = await authorize(input);
    if (decision.allowed !== true) {
      throw new PlatformOperatorAuthorizationError(PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.DENIED);
    }
    return decision;
  }

  Object.defineProperties(authorize, {
    assertAuthorized: { value: assertAuthorized, enumerable: true },
    authorize: { value: authorize, enumerable: true },
    repositoryMethods: { value: REPOSITORY_METHODS, enumerable: true }
  });
  return Object.freeze(authorize);
}

function parseAuthorizationInput(input) {
  if (!isPlainObject(input) || [...Object.keys(input)].some((key) => !INPUT_KEYS.has(key))) return null;
  const principal = parsePrincipal(input.principal);
  const operation = parseOperation(input.operation);
  const capability = parseOperation(input.capability);
  if (principal === null || operation === null || capability === null) return null;
  if (input.request !== undefined && !isPlainObject(input.request)) return null;
  if (input.input !== undefined && !isPlainObject(input.input)) return null;
  return Object.freeze({ principal, operation, capability });
}

function parsePrincipal(value) {
  if (!isPlainObject(value) || [...Object.keys(value)].some((key) => !PRINCIPAL_KEYS.has(key))) return null;
  const sessionId = canonicalUuid(value.session_id);
  const memberId = canonicalUuid(value.member_id);
  const organizationId = canonicalUuid(value.organization_id);
  const createdAt = parseTimestamp(value.created_at);
  const expiresAt = parseTimestamp(value.expires_at);
  if (sessionId === null || memberId === null || organizationId === null) return null;
  if (value.version !== 1 || createdAt === null || expiresAt === null || createdAt > expiresAt) return null;
  if (value.role !== undefined && typeof value.role !== "string") return null;
  return Object.freeze({
    created_at_ms: createdAt,
    expires_at_ms: expiresAt,
    member_id: memberId,
    organization_id: organizationId,
    session_id: sessionId
  });
}

function isValidAssignment(value) {
  if (!isPlainObject(value) || !sameKeys(value, ASSIGNMENT_KEYS)) return false;
  return canonicalUuid(value.assignment_id) !== null
    && canonicalUuid(value.session_id) !== null
    && canonicalUuid(value.member_id) !== null
    && canonicalUuid(value.organization_id) !== null
    && value.role === PLATFORM_OPERATOR_ROLE
    && value.status === "active"
    && parseOperation(value.operation) !== null
    && parseOperation(value.capability) !== null
    && parseTimestamp(value.issued_at) !== null
    && parseTimestamp(value.expires_at) !== null;
}

function parseOperation(value) {
  return typeof value === "string"
    && value.length <= MAX_OPERATION_LENGTH
    && OPERATION.test(value)
    ? value
    : null;
}

function canonicalUuid(value) {
  return typeof value === "string" && UUID.test(value) ? value.toLowerCase() : null;
}

function parseTimestamp(value) {
  if (typeof value !== "string" || !RFC3339.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function readClock(clock) {
  let value;
  try { value = clock(); } catch { throw new PlatformOperatorAuthorizationError(PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.INVALID_CONFIGURATION); }
  if (value instanceof Date) value = value.getTime();
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PlatformOperatorAuthorizationError(PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.INVALID_CONFIGURATION);
  }
  return value;
}

function sameKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
