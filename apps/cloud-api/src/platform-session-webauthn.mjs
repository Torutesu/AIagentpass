import crypto from "node:crypto";

import { createSimpleWebAuthnAssertionVerifier } from "./human-auth/webauthn/simplewebauthn-adapter.mjs";

const DEFAULT_CHALLENGE_TTL_MS = 120_000;
const MAX_CHALLENGE_TTL_MS = 300_000;
const DEFAULT_SESSION_TTL_SECONDS = 900;
const DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS = 300;
const MAX_RESPONSE_CACHE_MS = 300_000;
const MAX_RESPONSE_CACHE_ENTRIES = 1_000;
const CHALLENGE_BYTES = 32;
const SESSION_BEARER_BYTES = 32;
const SESSION_CSRF_BYTES = 32;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 4 * 1024;
const MAX_SIGNATURE_BYTES = 1_024;
const MAX_CREDENTIAL_ID_BYTES = 1_024;
const MAX_USER_HANDLE_BYTES = 64;
const MAX_CLOCK_SKEW_MS = 30_000;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const OPERATION = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u;
const ORIGIN_SCHEMES = new Set(["https:", "http:"]);
const CLIENT_DATA_KEYS = new Set(["type", "challenge", "origin", "crossOrigin", "tokenBinding"]);
const VERIFIER_RESULT_KEYS = new Set(["verified", "credential_id", "sign_count", "authenticated_at"]);
const TERMINAL_CHALLENGE_STATUSES = new Set(["consumed", "failed", "expired"]);
const PLATFORM_CAPABILITIES = new Set([
  "platform.assignment.manage",
  "platform.promotion.issue",
  "platform.promotion.replay",
  "platform.promotion.verify",
  "platform.promotion.reconcile"
]);

export const PLATFORM_SESSION_WEBAUTHN_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "platform_session_webauthn_invalid_request",
  INVALID_CONTEXT: "platform_session_webauthn_invalid_context",
  CHALLENGE_NOT_FOUND: "platform_session_webauthn_challenge_not_found",
  CHALLENGE_EXPIRED: "platform_session_webauthn_challenge_expired",
  CHALLENGE_REPLAYED: "platform_session_webauthn_challenge_replayed",
  CHALLENGE_BUSY: "platform_session_webauthn_challenge_busy",
  CHALLENGE_MISMATCH: "platform_session_webauthn_challenge_mismatch",
  JTI_MISMATCH: "platform_session_webauthn_jti_mismatch",
  BINDING_MISMATCH: "platform_session_webauthn_binding_mismatch",
  INVALID_RESPONSE: "platform_session_webauthn_invalid_response",
  VERIFICATION_FAILED: "platform_session_webauthn_verification_failed",
  CREDENTIAL_UNAVAILABLE: "platform_session_webauthn_credential_unavailable",
  CREDENTIAL_CLONE_DETECTED: "platform_session_webauthn_credential_clone_detected",
  SESSION_ISSUANCE_FAILED: "platform_session_webauthn_session_issuance_failed",
  RESPONSE_LOST: "platform_session_webauthn_response_lost",
  REPOSITORY_UNAVAILABLE: "platform_session_webauthn_repository_unavailable",
  INVALID_REPOSITORY_RESULT: "platform_session_webauthn_invalid_repository_result"
});

const ERROR_MESSAGES = Object.freeze({
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REQUEST]: "Platform session WebAuthn request is invalid",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT]: "Platform session WebAuthn context is invalid",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_NOT_FOUND]: "Platform session WebAuthn challenge was not found",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED]: "Platform session WebAuthn challenge has expired",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED]: "Platform session WebAuthn challenge has already been consumed",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY]: "Platform session WebAuthn challenge is already being verified",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH]: "Platform session WebAuthn challenge does not match",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.JTI_MISMATCH]: "Platform session WebAuthn JTI does not match",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.BINDING_MISMATCH]: "Platform session WebAuthn binding does not match",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE]: "Platform session WebAuthn assertion is invalid",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED]: "Platform session WebAuthn assertion verification failed",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CREDENTIAL_UNAVAILABLE]: "Platform WebAuthn credential is unavailable",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CREDENTIAL_CLONE_DETECTED]: "Platform WebAuthn credential clone was detected",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.SESSION_ISSUANCE_FAILED]: "Platform session issuance failed",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.RESPONSE_LOST]: "Platform session response was already issued but is no longer recoverable",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.REPOSITORY_UNAVAILABLE]: "Platform session WebAuthn repository is unavailable",
  [PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT]: "Platform session WebAuthn repository returned an invalid result"
});

export class PlatformSessionWebAuthnError extends Error {
  constructor(code, details = undefined, cause = undefined) {
    super(ERROR_MESSAGES[code] ?? "Platform session WebAuthn ceremony failed");
    this.name = "PlatformSessionWebAuthnError";
    this.code = code;
    if (details !== undefined) this.details = details;
    void cause;
  }
}

/**
 * The repository is the persistence and concurrency boundary for this service.
 * It must store only the hash fields in `create...`/`claim...`/`complete...`
 * calls. None of these methods may accept clientDataJSON, authenticatorData,
 * signature, a raw challenge, a raw JTI, or a raw session bearer.
 * Session issuance receives only SHA-256 digests for the bearer and dedicated
 * CSRF token, plus the already-bound canonical request digest.
 *
 * Required methods:
 * - createPlatformSessionChallenge(record)
 * - findPlatformSessionChallenge({ challenge_id })
 * - claimPlatformSessionChallenge(record)
 * - failPlatformSessionChallenge(record)
 * - completePlatformSessionChallenge(record)
 * - findPlatformCredentialForSession(record)
 * - advancePlatformCredentialCounter(record)
 * - issuePlatformSession(record)
 *
 * `claimPlatformSessionChallenge` must be an atomic one-use transition. It
 * returns `{ claimed: true, record }` on success and an outcome such as
 * `busy`, `replayed`, `expired`, or `mismatch` otherwise.
 */
export const PLATFORM_SESSION_WEBAUTHN_REPOSITORY_METHODS = Object.freeze([
  "createPlatformSessionChallenge",
  "findPlatformSessionChallenge",
  "claimPlatformSessionChallenge",
  "failPlatformSessionChallenge",
  "completePlatformSessionChallenge",
  "findPlatformCredentialForSession",
  "advancePlatformCredentialCounter",
  "issuePlatformSession"
]);

/**
 * Creates the platform-only WebAuthn ceremony.
 *
 * A platform session is not a human session. The binding includes the
 * principal, member, organization, assignment, operation, capability, and
 * authority generation, and every one of those values is checked again at
 * verification time before a session is issued.
 */
export function createPlatformSessionWebAuthnService({
  repository,
  verifyAssertion,
  webauthnVerify,
  now = () => Date.now(),
  ttlMs = DEFAULT_CHALLENGE_TTL_MS,
  sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS,
  sessionIdleTimeoutSeconds = DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
  responseCacheMs = MAX_RESPONSE_CACHE_MS,
  randomUUID = crypto.randomUUID,
  randomBytes = crypto.randomBytes
} = {}) {
  assertRepository(repository);
  if (typeof now !== "function" || typeof randomUUID !== "function" || typeof randomBytes !== "function") throw new TypeError("clock and random sources are invalid");
  assertDuration(ttlMs, "ttlMs", 1_000, MAX_CHALLENGE_TTL_MS);
  assertDuration(responseCacheMs, "responseCacheMs", 1_000, MAX_RESPONSE_CACHE_MS);
  assertIntegerRange(sessionTtlSeconds, "sessionTtlSeconds", 1, 86_400);
  assertIntegerRange(sessionIdleTimeoutSeconds, "sessionIdleTimeoutSeconds", 1, sessionTtlSeconds);
  assertClock(now());

  const responseCache = new Map();
  const verifierContexts = new Map();
  const pendingCounters = new Map();
  const verifier = verifyAssertion ?? createPlatformSimpleWebAuthnAssertionVerifier({
    repository,
    verify: webauthnVerify,
    verifierContexts,
    pendingCounters
  });
  if (typeof verifier !== "function") throw new TypeError("verifyAssertion must be a function");

  async function begin(input = {}) {
    const context = normalizeBeginContext(input);
    const issuedAt = assertClock(now());
    const requestedTtl = input.ttl_ms ?? input.ttlMs ?? ttlMs;
    assertDuration(requestedTtl, "ttl_ms", 1_000, ttlMs);
    const challengeId = requiredUuidV4(randomUUID(), "challenge_id");
    const platformSessionId = requiredUuidV4(randomUUID(), "platform_session_id");
    const jti = requiredUuidV4(randomUUID(), "jti");
    const challengeBytes = randomBytes(CHALLENGE_BYTES);
    if (!(challengeBytes instanceof Uint8Array) || challengeBytes.byteLength !== CHALLENGE_BYTES) throw new TypeError("random challenge bytes are invalid");
    const challenge = Buffer.from(challengeBytes).toString("base64url");
    const expiresAt = issuedAt + requestedTtl;
    const binding = Object.freeze({ ...context, platform_session_id: platformSessionId });
    const record = Object.freeze({
      challenge_id: challengeId,
      jti_hash: sha256Bytes(jti),
      challenge_hash: sha256Bytes(challenge),
      binding_hash: bindingHash(binding),
      platform_session_id: platformSessionId,
      ...binding,
      issued_at: issuedAt,
      expires_at: expiresAt,
      status: "pending"
    });

    let stored;
    try {
      stored = await repository.createPlatformSessionChallenge(record);
    } catch (error) {
      throw repositoryError(error);
    }
    assertStoredChallenge(stored, record);
    return Object.freeze({
      version: 1,
      type: "agentpass.platform-session-challenge",
      challenge_id: challengeId,
      challenge,
      jti,
      platform_session_id: platformSessionId,
      principal_id: context.principal_id,
      member_id: context.member_id,
      organization_id: context.organization_id,
      assignment_id: context.assignment_id,
      authority_generation: context.authority_generation,
      operation: context.operation,
      capability: context.capability,
      request_digest_sha256: context.request_digest_sha256,
      allowed_credential_ids: context.allowed_credential_ids,
      challenge_expires_at: new Date(expiresAt).toISOString(),
      issued_at: new Date(issuedAt).toISOString(),
      expires_at: new Date(expiresAt).toISOString(),
      one_use: true,
      rp_id: context.rp_id,
      origin: context.origin,
      user_verification: context.user_verification
    });
  }

  async function verify(input = {}) {
    let request = normalizeVerifyInput(input);
    const requestFingerprint = assertionFingerprint(request);
    const cached = getCachedResponse(request.challenge_id);
    if (cached) {
      if (cached.authority_fingerprint !== authorityFingerprint(request)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
      if (cached.assertion_fingerprint !== requestFingerprint) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
      // Never replay bearer material from process memory. The durable session
      // is idempotent, but a lost transport response requires a new ceremony.
      throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.RESPONSE_LOST);
    }

    const currentTime = assertClock(now());
    let stored;
    try {
      stored = await repository.findPlatformSessionChallenge({ challenge_id: request.challenge_id });
    } catch (error) {
      throw repositoryError(error);
    }
    const record = normalizeStoredChallenge(stored);
    checkChallengeState(record, currentTime);
    const clientChallenge = extractClientChallenge(request.client_data_json, record.origin);
    request = Object.freeze({ ...request, challenge: clientChallenge, platform_session_id: record.platform_session_id });
    if (!constantTimeBufferEqual(record.challenge_hash, sha256Bytes(request.challenge))) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH);
    if (!constantTimeBufferEqual(record.jti_hash, sha256Bytes(request.jti))) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.JTI_MISMATCH);
    const requestBinding = normalizeVerifyBinding(request);
    if (!sameBinding(record, requestBinding) || !constantTimeBufferEqual(record.binding_hash, bindingHash(requestBinding))) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
    validateAssertionEnvelope(request, record);
    if (!record.allowed_credential_ids.includes(request.credential_id)) {
      throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CREDENTIAL_UNAVAILABLE);
    }

    let claim;
    try {
      claim = await repository.claimPlatformSessionChallenge({
        challenge_id: record.challenge_id,
        challenge_hash: record.challenge_hash,
        jti_hash: record.jti_hash,
        binding_hash: record.binding_hash,
        claimed_at: currentTime
      });
    } catch (error) {
      throw repositoryError(error);
    }
    const claimedRecord = assertClaimResult(claim, record);
    let issued;
    let response;
    verifierContexts.set(record.platform_session_id, Object.freeze({ ...record }));
    try {
      const credential = await findPlatformCredential(repository, record, request.credential_id);
      const platformCredentialId = requiredUuidStorage(credential.platform_credential_id, "platform_credential_id");
      const verification = await verifier(buildVerifierInput(record, request, credential));
      validateVerifierResult(verification, request.credential_id, currentTime);

      let counterResult;
      try {
        counterResult = await repository.advancePlatformCredentialCounter({
          credential_id: platformCredentialId,
          webauthn_credential_id: request.credential_id,
          principal_id: record.principal_id,
          member_id: record.member_id,
          organization_id: record.organization_id,
          assignment_id: record.assignment_id,
          authority_generation: record.authority_generation,
          request_digest_sha256: record.request_digest_sha256,
          sign_count: verification.sign_count
        });
      } catch (error) {
        throw repositoryError(error);
      }
      assertCounterResult(counterResult);

      const bearerBytes = randomBytes(SESSION_BEARER_BYTES);
      if (!(bearerBytes instanceof Uint8Array) || bearerBytes.byteLength !== SESSION_BEARER_BYTES) throw new TypeError("random session bearer bytes are invalid");
      const sessionBearer = Buffer.from(bearerBytes).toString("base64url");
      const csrfBytes = randomBytes(SESSION_CSRF_BYTES);
      if (!(csrfBytes instanceof Uint8Array) || csrfBytes.byteLength !== SESSION_CSRF_BYTES) throw new TypeError("random session CSRF bytes are invalid");
      const csrfToken = Buffer.from(csrfBytes).toString("base64url");
      // Lookup repositories hash the exact base64url cookie value, so issue
      // must persist the digest of that same transport representation.
      const sessionMaterialHash = sha256Bytes(sessionBearer);
      const csrfTokenHash = sha256Bytes(csrfToken);
      try {
        issued = await repository.issuePlatformSession({
          session_id: record.platform_session_id,
          session_material_hash: sessionMaterialHash,
          csrf_token_hash: csrfTokenHash,
          principal_id: record.principal_id,
          member_id: record.member_id,
          organization_id: record.organization_id,
          assignment_id: record.assignment_id,
          credential_id: platformCredentialId,
          operation: record.operation,
          capability: record.capability,
          authority_generation: record.authority_generation,
          request_digest_sha256: record.request_digest_sha256,
          challenge_id: record.challenge_id,
          jti_hash: record.jti_hash,
          ttl_seconds: sessionTtlSeconds,
          idle_timeout_seconds: sessionIdleTimeoutSeconds,
          authenticated_at: assertClock(now())
        });
      } catch (error) {
        throw issuanceError(error);
      }
      const safeSession = normalizeIssuedSession(issued, record);
      response = Object.freeze({
        session: safeSession,
        session_bearer: sessionBearer,
        csrf_token: csrfToken,
        challenge_id: record.challenge_id,
        authenticated_at: assertClock(now())
      });

      try {
        const completed = await repository.completePlatformSessionChallenge({
          challenge_id: record.challenge_id,
          challenge_hash: record.challenge_hash,
          jti_hash: record.jti_hash,
          binding_hash: record.binding_hash,
          credential_id: request.credential_id,
          completed_at: assertClock(now())
        });
        assertCompletionResult(completed, record);
      } catch (error) {
        // The session is already idempotently issued. Keep the bearer in the
        // bounded process-local cache so a lost response can be retried, but
        // do not pretend that the challenge completion write succeeded.
        cacheResponse(record, request, requestFingerprint);
        throw repositoryError(error);
      }
      cacheResponse(record, request, requestFingerprint);
      return response;
    } catch (error) {
      if (!issued) await failClaim(repository, claimedRecord, record, error, now);
      throw error instanceof PlatformSessionWebAuthnError ? error : failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
    } finally {
      verifierContexts.delete(record.platform_session_id);
      pendingCounters.delete(record.platform_session_id);
    }
  }

  return Object.freeze({ begin, verify });

  function cacheResponse(record, request, assertionFingerprintValue) {
    responseCache.set(record.challenge_id, {
      authority_fingerprint: authorityFingerprint(request),
      assertion_fingerprint: assertionFingerprintValue,
      expires_at: Math.min(record.expires_at + MAX_RESPONSE_CACHE_MS, assertClock(now()) + responseCacheMs)
    });
    trimResponseCache();
  }

  function getCachedResponse(challengeId) {
    const entry = responseCache.get(challengeId);
    if (!entry) return undefined;
    if (assertClock(now()) >= entry.expires_at) {
      responseCache.delete(challengeId);
      return undefined;
    }
    return entry;
  }

  function trimResponseCache() {
    while (responseCache.size > MAX_RESPONSE_CACHE_ENTRIES) responseCache.delete(responseCache.keys().next().value);
  }
}

/**
 * Composes the existing SimpleWebAuthn verifier with the platform repository.
 * The adapter sees only platform-scoped credential lookups; it never receives
 * a human session or organization membership authorization decision.
 */
export function createPlatformSimpleWebAuthnAssertionVerifier({
  repository,
  verify,
  verifierContexts = new Map(),
  pendingCounters = new Map()
} = {}) {
  if (!repository || typeof repository.findPlatformCredentialForSession !== "function") throw new TypeError("platform credential repository is invalid");
  const credentialRepository = {
    async findCredentialForSession({ session_id, organization_id, credential_id }) {
      const context = verifierContexts.get(session_id);
      if (!context) throw new Error("platform WebAuthn session context is unavailable");
      const credential = await repository.findPlatformCredentialForSession({
        platform_session_id: session_id,
        session_id,
        organization_id,
        principal_id: context.principal_id,
        member_id: context.member_id,
        assignment_id: context.assignment_id,
        authority_generation: context.authority_generation,
        credential_id
      });
      validatePlatformCredential(credential, context, credential_id);
      return credential;
    },
    async updateCredentialCounter(input) {
      const context = verifierContexts.get(input.session_id);
      if (!context) return false;
      pendingCounters.set(input.session_id, input.sign_count);
      return true;
    }
  };
  const adapter = createSimpleWebAuthnAssertionVerifier({ credentialRepository, verify });
  return async (input) => {
    const result = await adapter(input);
    const signCount = pendingCounters.get(input.ceremony.session_id);
    return Object.freeze({ ...result, ...(signCount === undefined ? {} : { sign_count: signCount }) });
  };
}

function assertRepository(repository) {
  if (!repository || typeof repository !== "object") throw new TypeError("platform session WebAuthn repository is required");
  for (const method of PLATFORM_SESSION_WEBAUTHN_REPOSITORY_METHODS) if (typeof repository[method] !== "function") throw new TypeError(`repository.${method} is required`);
}

function normalizeBeginContext(input) {
  if (!isObject(input)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT);
  const operation = requiredOperation(input.operation);
  const capability = requiredOperation(input.capability);
  if (!PLATFORM_CAPABILITIES.has(capability) || operation !== capability) {
    throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "operation_or_capability");
  }
  const rp_id = requiredRpId(input.rp_id ?? input.rpId);
  const origin = requiredOrigin(input.origin);
  if (!rpIdMatchesOrigin(rp_id, origin)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "rp_id_origin");
  return Object.freeze({
    principal_id: requiredUuid(input.principal_id ?? input.principalId, "principal_id"),
    member_id: requiredUuid(input.member_id ?? input.memberId, "member_id"),
    organization_id: requiredUuid(input.organization_id ?? input.organizationId, "organization_id"),
    assignment_id: requiredUuid(input.assignment_id ?? input.assignmentId, "assignment_id"),
    authority_generation: requiredPositiveInteger(input.authority_generation ?? input.authorityGeneration, "authority_generation"),
    operation,
    capability,
    request_digest_sha256: requiredDigestHex(input.request_digest_sha256 ?? input.requestDigestSha256, "request_digest_sha256"),
    allowed_credential_ids: requiredCredentialIds(input.allowed_credential_ids ?? input.allowedCredentialIds),
    rp_id,
    origin,
    user_verification: requiredUserVerification(input.user_verification ?? input.userVerification ?? "required")
  });
}

function normalizeVerifyInput(input) {
  if (!isObject(input)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REQUEST);
  const context = normalizeBeginContext(input);
  return Object.freeze({
    challenge_id: requiredUuidV4(input.challenge_id ?? input.challengeId, "challenge_id"),
    jti: requiredUuidV4(input.jti, "jti"),
    credential_id: requiredBase64Url(input.credential_id ?? input.credentialId, [16, MAX_CREDENTIAL_ID_BYTES], "credential_id"),
    client_data_json: requiredBase64Url(input.client_data_json ?? input.clientDataJSON, [1, MAX_CLIENT_DATA_BYTES], "client_data_json"),
    authenticator_data: requiredBase64Url(input.authenticator_data ?? input.authenticatorData, [37, MAX_AUTHENTICATOR_DATA_BYTES], "authenticator_data"),
    signature: requiredBase64Url(input.signature, [64, MAX_SIGNATURE_BYTES], "signature"),
    ...(input.user_handle === undefined && input.userHandle === undefined ? {} : { user_handle: requiredBase64Url(input.user_handle ?? input.userHandle, [1, MAX_USER_HANDLE_BYTES], "user_handle") }),
    ...context
  });
}

function normalizeVerifyBinding(input) {
  return Object.freeze({
    platform_session_id: input.platform_session_id,
    principal_id: input.principal_id,
    member_id: input.member_id,
    organization_id: input.organization_id,
    assignment_id: input.assignment_id,
    authority_generation: input.authority_generation,
    operation: input.operation,
    capability: input.capability,
    request_digest_sha256: input.request_digest_sha256,
    allowed_credential_ids: input.allowed_credential_ids,
    rp_id: input.rp_id,
    origin: input.origin,
    user_verification: input.user_verification
  });
}

function normalizeStoredChallenge(row) {
  if (!isObject(row)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_NOT_FOUND);
  const result = {
    challenge_id: requiredUuidV4Storage(row.challenge_id ?? row.id, "challenge_id"),
    jti_hash: storageDigest(row.jti_hash, "jti_hash"),
    challenge_hash: storageDigest(row.challenge_hash, "challenge_hash"),
    binding_hash: storageDigest(row.binding_hash, "binding_hash"),
    platform_session_id: requiredUuidStorage(row.platform_session_id ?? row.session_id, "platform_session_id"),
    principal_id: requiredUuidStorage(row.principal_id, "principal_id"),
    member_id: requiredUuidStorage(row.member_id, "member_id"),
    organization_id: requiredUuidStorage(row.organization_id, "organization_id"),
    assignment_id: requiredUuidStorage(row.assignment_id, "assignment_id"),
    authority_generation: requiredPositiveIntegerStorage(row.authority_generation, "authority_generation"),
    operation: storageOperation(row.operation),
    capability: storageOperation(row.capability),
    request_digest_sha256: storageDigest(row.request_digest_sha256 ?? row.request_digest, "request_digest").toString("hex"),
    allowed_credential_ids: requiredCredentialIdsStorage(row.allowed_credential_ids),
    rp_id: storageRpId(row.rp_id),
    origin: storageOrigin(row.origin),
    user_verification: row.user_verification,
    issued_at: storageTime(row.issued_at ?? row.created_at, "issued_at"),
    expires_at: storageTime(row.expires_at, "expires_at"),
    status: row.status
  };
  if (result.user_verification !== "required" || result.expires_at <= result.issued_at || !["pending", "consuming", "consumed", "failed", "expired"].includes(result.status)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT);
  return Object.freeze(result);
}

function assertStoredChallenge(row, expected) {
  const actual = normalizeStoredChallenge(row);
  if (!sameBinding(actual, expected) || actual.challenge_id !== expected.challenge_id || actual.issued_at !== expected.issued_at || actual.expires_at !== expected.expires_at || actual.status !== "pending" || !constantTimeBufferEqual(actual.jti_hash, expected.jti_hash) || !constantTimeBufferEqual(actual.challenge_hash, expected.challenge_hash) || !constantTimeBufferEqual(actual.binding_hash, expected.binding_hash)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT);
}

function assertClaimResult(value, expected) {
  if (value?.outcome === "busy") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
  if (value?.outcome === "replayed") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
  if (value?.outcome === "expired") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
  if (value?.outcome === "mismatch") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
  if (!value || value.claimed !== true) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
  const record = normalizeStoredChallenge(value.record ?? value);
  if (record.challenge_id !== expected.challenge_id || record.status !== "consuming" || !sameBinding(record, expected)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT);
  return record;
}

function assertCompletionResult(value, expected) {
  if (value?.outcome === "already-completed" || value?.outcome === "completed") return;
  if (value?.completed === true) return;
  if (isObject(value)) {
    const record = normalizeStoredChallenge(value.record ?? value);
    if (record.challenge_id === expected.challenge_id && record.status === "consumed") return;
  }
  throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT);
}

async function findPlatformCredential(repository, record, credentialId) {
  let credential;
  try {
    credential = await repository.findPlatformCredentialForSession({
      platform_session_id: record.platform_session_id,
      session_id: record.platform_session_id,
      principal_id: record.principal_id,
      member_id: record.member_id,
      organization_id: record.organization_id,
      assignment_id: record.assignment_id,
      authority_generation: record.authority_generation,
      credential_id: credentialId
    });
  } catch (error) {
    throw repositoryError(error);
  }
  validatePlatformCredential(credential, record, credentialId);
  return credential;
}

function validatePlatformCredential(value, context, credentialId) {
  const webauthnCredentialId = value?.webauthn_credential_id ?? value?.credential_id ?? value?.id;
  if (!isObject(value) || webauthnCredentialId !== credentialId || typeof value.platform_credential_id !== "string" || !UUID.test(value.platform_credential_id) || (value.principal_id ?? value.principalId) !== context.principal_id || (value.member_id ?? value.memberId) !== context.member_id || (value.status !== undefined && value.status !== "active") || value.revoked_at !== undefined && value.revoked_at !== null || value.clone_detected_at !== undefined && value.clone_detected_at !== null || value.sign_count_state === "clone-detected") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CREDENTIAL_UNAVAILABLE);
}

function validateAssertionEnvelope(request, record) {
  const clientDataBytes = decodeBase64Url(request.client_data_json, [1, MAX_CLIENT_DATA_BYTES], "client_data_json");
  const clientDataText = Buffer.from(clientDataBytes).toString("utf8");
  if (Buffer.from(clientDataText, "utf8").compare(Buffer.from(clientDataBytes)) !== 0) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  let clientData;
  try { clientData = JSON.parse(clientDataText); } catch { throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE); }
  if (!isObject(clientData) || Object.keys(clientData).some((key) => !CLIENT_DATA_KEYS.has(key)) || clientData.type !== "webauthn.get" || clientData.challenge !== request.challenge || clientData.origin !== record.origin || clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);

  const authenticatorData = decodeBase64Url(request.authenticator_data, [37, MAX_AUTHENTICATOR_DATA_BYTES], "authenticator_data");
  const expectedRpIdHash = crypto.createHash("sha256").update(record.rp_id).digest();
  if (!crypto.timingSafeEqual(Buffer.from(authenticatorData.subarray(0, 32)), expectedRpIdHash)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
}

function extractClientChallenge(clientDataJson, expectedOrigin) {
  const clientDataBytes = decodeBase64Url(clientDataJson, [1, MAX_CLIENT_DATA_BYTES], "client_data_json");
  const clientDataText = Buffer.from(clientDataBytes).toString("utf8");
  if (Buffer.from(clientDataText, "utf8").compare(Buffer.from(clientDataBytes)) !== 0) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  let clientData;
  try { clientData = JSON.parse(clientDataText); } catch { throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE); }
  if (!isObject(clientData) || Object.keys(clientData).some((key) => !CLIENT_DATA_KEYS.has(key)) || clientData.type !== "webauthn.get" || clientData.origin !== expectedOrigin || clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  return requiredBase64Url(clientData.challenge, CHALLENGE_BYTES, "challenge");
}

function buildVerifierInput(record, request, credential) {
  return Object.freeze({
    ceremony: Object.freeze({
      challenge_id: record.challenge_id,
      session_id: record.platform_session_id,
      platform_session_id: record.platform_session_id,
      principal_id: record.principal_id,
      member_id: record.member_id,
      organization_id: record.organization_id,
      assignment_id: record.assignment_id,
      authority_generation: record.authority_generation,
      operation: record.operation,
      capability: record.capability,
      request_digest_sha256: record.request_digest_sha256,
      jti: request.jti,
      context_hash: record.binding_hash.toString("hex"),
      rp_id: record.rp_id,
      origin: record.origin,
      user_verification: record.user_verification,
      expected_challenge: request.challenge
    }),
    assertion: Object.freeze({
      credential_id: request.credential_id,
      client_data_json: request.client_data_json,
      authenticator_data: request.authenticator_data,
      signature: request.signature,
      ...(request.user_handle === undefined ? {} : { user_handle: request.user_handle })
    }),
    credential
  });
}

function validateVerifierResult(value, credentialId, currentTime) {
  if (!isObject(value) || value.verified !== true || (value.credential_id ?? value.credentialId) !== credentialId || Object.keys(value).some((key) => !VERIFIER_RESULT_KEYS.has(key))) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
  if (!Number.isSafeInteger(value.sign_count) || value.sign_count < 0 || value.sign_count > 0xffff_ffff) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
  if (value.authenticated_at !== undefined && (!Number.isSafeInteger(value.authenticated_at) || value.authenticated_at < 0 || value.authenticated_at > currentTime + MAX_CLOCK_SKEW_MS)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
}

function assertCounterResult(value) {
  if (value === true) return;
  if (!isObject(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CREDENTIAL_UNAVAILABLE);
  if (value.outcome === "clone-detected" || value.outcome === "denied") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CREDENTIAL_CLONE_DETECTED);
  if (value.outcome !== "accepted" && value.outcome !== "already-accepted") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CREDENTIAL_UNAVAILABLE);
}

function normalizeIssuedSession(value, record) {
  if (!isObject(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.SESSION_ISSUANCE_FAILED);
  const session = value.session ?? value;
  if (!isObject(session)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.SESSION_ISSUANCE_FAILED);
  for (const key of Object.keys(session)) if (/(bearer|token|secret|assertion|signature|challenge|session_material_hash|jti)/iu.test(key)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT);
  if ((session.session_id ?? session.id) !== record.platform_session_id || session.principal_id !== record.principal_id || session.member_id !== record.member_id || session.organization_id !== record.organization_id || session.assignment_id !== record.assignment_id || session.operation !== record.operation || session.capability !== record.capability) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.SESSION_ISSUANCE_FAILED);
  return Object.freeze({ ...session });
}

function checkChallengeState(record, currentTime) {
  if (record.status === "consuming") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
  if (TERMINAL_CHALLENGE_STATUSES.has(record.status)) {
    if (record.status === "expired" || currentTime >= record.expires_at) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
    throw failure(record.status === "consumed" ? PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.RESPONSE_LOST : PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
  }
  if (record.status !== "pending") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT);
  if (currentTime < record.issued_at || currentTime >= record.expires_at) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
}

async function failClaim(repository, claimedRecord, expected, originalError, now = () => Date.now()) {
  try {
    await repository.failPlatformSessionChallenge({
      challenge_id: expected.challenge_id,
      challenge_hash: expected.challenge_hash,
      jti_hash: expected.jti_hash,
      binding_hash: expected.binding_hash,
      failed_at: assertClock(now())
    });
  } catch {
    throw repositoryError(originalError);
  }
  void claimedRecord;
}

function sameBinding(left, right) {
  return left.platform_session_id === right.platform_session_id && left.principal_id === right.principal_id && left.member_id === right.member_id && left.organization_id === right.organization_id && left.assignment_id === right.assignment_id && left.authority_generation === right.authority_generation && left.operation === right.operation && left.capability === right.capability && left.request_digest_sha256 === right.request_digest_sha256 && sameStringArray(left.allowed_credential_ids, right.allowed_credential_ids) && left.rp_id === right.rp_id && left.origin === right.origin && left.user_verification === right.user_verification;
}

function bindingHash(binding) {
  return sha256Bytes(JSON.stringify({
    version: 1,
    type: "agentpass.platform-session-webauthn",
    platform_session_id: binding.platform_session_id,
    principal_id: binding.principal_id,
    member_id: binding.member_id,
    organization_id: binding.organization_id,
    assignment_id: binding.assignment_id,
    authority_generation: binding.authority_generation,
    operation: binding.operation,
    capability: binding.capability,
    request_digest_sha256: binding.request_digest_sha256,
    allowed_credential_ids: binding.allowed_credential_ids,
    rp_id: binding.rp_id,
    origin: binding.origin,
    user_verification: binding.user_verification
  }));
}

function authorityFingerprint(request) {
  return sha256Hex(JSON.stringify({
    principal_id: request.principal_id,
    member_id: request.member_id,
    organization_id: request.organization_id,
    assignment_id: request.assignment_id,
    authority_generation: request.authority_generation,
    operation: request.operation,
    capability: request.capability,
    request_digest_sha256: request.request_digest_sha256,
    allowed_credential_ids: request.allowed_credential_ids,
    rp_id: request.rp_id,
    origin: request.origin,
    user_verification: request.user_verification
  }));
}

function assertionFingerprint(request) {
  return sha256Bytes(JSON.stringify({
    challenge_id: request.challenge_id,
    jti: request.jti,
    credential_id: request.credential_id,
    client_data_json: sha256Hex(request.client_data_json),
    authenticator_data: sha256Hex(request.authenticator_data),
    signature: sha256Hex(request.signature),
    user_handle: request.user_handle === undefined ? null : sha256Hex(request.user_handle)
  })).toString("hex");
}

function sha256Bytes(value) { return crypto.createHash("sha256").update(value).digest(); }
function sha256Hex(value) { return sha256Bytes(value).toString("hex"); }
function constantTimeBufferEqual(left, right) { return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length === right.length && crypto.timingSafeEqual(left, right); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function failure(code, details) { return new PlatformSessionWebAuthnError(code, details); }
function repositoryError(cause) { return failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.REPOSITORY_UNAVAILABLE, undefined, cause); }
function issuanceError(cause) { return failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.SESSION_ISSUANCE_FAILED, undefined, cause); }
function assertClock(value) { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock value is invalid"); return value; }
function assertDuration(value, field, minimum, maximum) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`${field} is invalid`); return value; }
function assertIntegerRange(value, field, minimum, maximum) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`${field} is invalid`); return value; }
function requiredUuid(value, field) { if (typeof value !== "string" || !UUID.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, field); return value.toLowerCase(); }
function requiredUuidV4(value, field) { if (typeof value !== "string" || !UUID_V4.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REQUEST, field); return value.toLowerCase(); }
function requiredUuidStorage(value, field) { if (typeof value !== "string" || !UUID.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT, field); return value.toLowerCase(); }
function requiredUuidV4Storage(value, field) { if (typeof value !== "string" || !UUID_V4.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT, field); return value.toLowerCase(); }
function requiredPositiveInteger(value, field) { if (!Number.isSafeInteger(value) || value < 1) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, field); return value; }
function requiredPositiveIntegerStorage(value, field) { if (!Number.isSafeInteger(value) || value < 1) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT, field); return value; }
function requiredDigestHex(value, field) { if (typeof value !== "string" || !SHA256_HEX.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, field); return value; }
function requiredCredentialIds(value) { if (!Array.isArray(value) || value.length < 1 || value.length > 16) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "allowed_credential_ids"); const ids = value.map((item) => requiredBase64Url(item, [16, MAX_CREDENTIAL_ID_BYTES], "allowed_credential_ids")); if (new Set(ids).size !== ids.length) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "allowed_credential_ids"); return Object.freeze([...ids].sort()); }
function requiredCredentialIdsStorage(value) { try { return requiredCredentialIds(value); } catch { throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT, "allowed_credential_ids"); } }
function sameStringArray(left, right) { return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((value, index) => value === right[index]); }
function requiredOperation(value) { if (typeof value !== "string" || !OPERATION.test(value) || /[\u0000-\u001f\u007f]/u.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "operation_or_capability"); return value; }
function storageOperation(value) { if (typeof value !== "string" || !OPERATION.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT); return value; }
function requiredUserVerification(value) { if (value !== "required") throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "user_verification"); return value; }
function requiredRpId(value) { if (typeof value !== "string" || value.length < 1 || value.length > 253 || !RP_ID.test(value) || value.includes("..")) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "rp_id"); return value.toLowerCase(); }
function storageRpId(value) { try { return requiredRpId(value); } catch { throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT); } }
function requiredOrigin(value) { if (typeof value !== "string" || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); let url; try { url = new URL(value); } catch { throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); } if (!ORIGIN_SCHEMES.has(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash || (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) || url.origin !== value) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); return url.origin; }
function storageOrigin(value) { try { return requiredOrigin(value); } catch { throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT); } }
function rpIdMatchesOrigin(rpId, origin) { const hostname = new URL(origin).hostname.toLowerCase(); const normalizedHost = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname; const normalizedRpId = rpId.toLowerCase(); if (netIsIp(normalizedHost) || netIsIp(normalizedRpId)) return normalizedHost === normalizedRpId; return normalizedHost === normalizedRpId || normalizedHost.endsWith(`.${normalizedRpId}`); }
function netIsIp(value) { return /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value) || value.includes(":"); }
function requiredBase64Url(value, length, field) { if (typeof value !== "string" || !BASE64URL.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REQUEST, field); decodeBase64Url(value, length, field); return value; }
function decodeBase64Url(value, length, field) { if (typeof value !== "string" || !BASE64URL.test(value)) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); let bytes; try { bytes = Buffer.from(value, "base64url"); } catch { throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); } const [minimum, maximum] = Array.isArray(length) ? length : [length, length]; if (bytes.length < minimum || bytes.length > maximum || bytes.toString("base64url") !== value) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); return bytes; }
function storageDigest(value, field) { const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array ? Buffer.from(value) : typeof value === "string" && /^[0-9a-f]{64}$/iu.test(value) ? Buffer.from(value, "hex") : null; if (!bytes || bytes.length !== 32) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT, field); return bytes; }
function storageTime(value, field) { const result = value instanceof Date ? value.getTime() : typeof value === "string" ? Date.parse(value) : Number.isSafeInteger(value) ? value : Number.NaN; if (!Number.isSafeInteger(result) || result < 0) throw failure(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT, field); return result; }
