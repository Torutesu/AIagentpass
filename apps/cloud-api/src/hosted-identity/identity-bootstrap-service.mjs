import crypto from "node:crypto";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const GITHUB_SUBJECT = /^[1-9][0-9]{0,19}$/u;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const STATES = new Set(["identity_verified", "organization_required", "no_membership"]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;

export const HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_HOSTED_IDENTITY_BOOTSTRAP_SERVICE_CONFIG",
  INPUT: "ERR_HOSTED_IDENTITY_BOOTSTRAP_SERVICE_INPUT",
  UNAVAILABLE: "ERR_HOSTED_IDENTITY_BOOTSTRAP_SERVICE_UNAVAILABLE"
});

const ERROR_MESSAGES = Object.freeze({
  [HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG]: "Hosted identity bootstrap service configuration is invalid",
  [HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT]: "Hosted identity bootstrap request is invalid",
  [HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE]: "Hosted identity bootstrap service is unavailable"
});

export class HostedIdentityBootstrapServiceError extends Error {
  constructor(code) {
    const safeCode = Object.hasOwn(ERROR_MESSAGES, code)
      ? code
      : HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE;
    super(ERROR_MESSAGES[safeCode]);
    this.name = "HostedIdentityBootstrapServiceError";
    this.code = safeCode;
  }
}

/**
 * Completes the verified OAuth boundary and turns the database-owned attempt
 * expiry into the small cookie DTO consumed by the HTTP boundary.
 *
 * The service deliberately generates both the candidate member ID and the
 * bootstrap selector. The repository is the transaction authority: this
 * layer never chooses a member, organization, role, or membership.
 */
export function createHostedIdentityBootstrapService(options = {}) {
  if (!isPlainObject(options)) throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG);
  const {
    repository,
    randomUUID = crypto.randomUUID,
    randomBytes = crypto.randomBytes,
    now = Date.now
  } = options;

  if (!repository || typeof repository.completeOAuthStateV2 !== "function"
    || typeof randomUUID !== "function" || typeof randomBytes !== "function" || typeof now !== "function") {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG);
  }

  async function createBootstrapSession(input = {}) {
    let request;
    try {
      request = normalizeInput(input);
    } catch (error) {
      if (error instanceof HostedIdentityBootstrapServiceError) throw error;
      throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT);
    }
    const candidateMemberId = generateCandidateMemberId(randomUUID);
    const bootstrapToken = generateBootstrapToken(randomBytes);

    let result;
    try {
      result = await repository.completeOAuthStateV2(Object.freeze({
        oauth_state_id: request.context.oauth_state_id,
        attempt_id: request.context.attempt_id,
        bootstrap_cookie: bootstrapToken,
        candidate_member_id: candidateMemberId,
        provider: request.identity.provider,
        subject: request.identity.subject
      }));
    } catch {
      throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    }

    let currentNow;
    try {
      currentNow = now();
    } catch {
      throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
    if (!Number.isSafeInteger(currentNow) || currentNow < 0) {
      throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    }

    let expiresAt;
    try {
      expiresAt = normalizeCompletionResult(result, request.context.attempt_id, currentNow);
    } catch (error) {
      if (error instanceof HostedIdentityBootstrapServiceError) throw error;
      throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
    return Object.freeze({ bootstrapToken, expiresAt });
  }

  return Object.freeze({ createBootstrapSession });
}

function normalizeInput(value) {
  if (!isPlainObject(value) || !exactKeys(value, ["identity", "context"])
    || !isPlainObject(value.identity) || !exactKeys(value.identity, ["provider", "subject"])
    || value.identity.provider !== "github"
    || typeof value.identity.subject !== "string"
    || !GITHUB_SUBJECT.test(value.identity.subject)
    || value.identity.subject.length > 20
    || CONTROL_CHARACTERS.test(value.identity.subject)
    || !isPlainObject(value.context) || !exactKeys(value.context, ["attempt_id", "oauth_state_id"])
    || !UUID_V4.test(value.context.attempt_id)
    || !UUID_V4.test(value.context.oauth_state_id)) {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT);
  }
  return Object.freeze({
    identity: Object.freeze({ provider: "github", subject: value.identity.subject }),
    context: Object.freeze({
      attempt_id: value.context.attempt_id.toLowerCase(),
      oauth_state_id: value.context.oauth_state_id.toLowerCase()
    })
  });
}

function generateCandidateMemberId(randomUUID) {
  let value;
  try {
    value = randomUUID();
  } catch {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  if (typeof value !== "string" || !UUID_V4.test(value)) {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  return value.toLowerCase();
}

function generateBootstrapToken(randomBytes) {
  let bytes;
  try {
    bytes = randomBytes(32);
    if (!(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new Error("invalid random bytes");
    }
    bytes = Buffer.from(bytes);
  } catch {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  const token = bytes.toString("base64url");
  if (!BASE64URL_32.test(token) || Buffer.from(token, "base64url").length !== 32
    || Buffer.from(token, "base64url").toString("base64url") !== token) {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  return token;
}

function normalizeCompletionResult(value, expectedAttemptId, currentNow) {
  if (!isPlainObject(value) || !exactKeys(value, ["attempt_id", "state", "organization_count", "expires_at"]) || value === null) {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  if (typeof value.attempt_id !== "string" || !UUID_V4.test(value.attempt_id)
    || value.attempt_id.toLowerCase() !== expectedAttemptId
    || typeof value.state !== "string" || !STATES.has(value.state)
    || !Number.isSafeInteger(value.organization_count) || value.organization_count < 0
    || (value.state === "identity_verified" ? value.organization_count < 1 : value.organization_count !== 0)
    || typeof value.expires_at !== "string" || !RFC3339.test(value.expires_at)) {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }

  const expiresAt = Date.parse(value.expires_at);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= currentNow) {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  const maxAge = Math.ceil((expiresAt - currentNow) / 1_000);
  if (!Number.isSafeInteger(maxAge) || maxAge < 1 || maxAge > 900) {
    throw serviceError(HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  return expiresAt;
}

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function serviceError(code) {
  return new HostedIdentityBootstrapServiceError(code);
}

export default createHostedIdentityBootstrapService;
