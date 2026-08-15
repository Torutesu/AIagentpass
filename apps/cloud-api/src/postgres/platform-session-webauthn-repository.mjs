import {
  PLATFORM_SESSION_WEBAUTHN_REPOSITORY_METHODS
} from "../platform-session-webauthn.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const HEX_256 = /^[0-9a-f]{64}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const OPERATION = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$/u;
const CAPABILITIES = new Set([
  "platform.assignment.manage",
  "platform.promotion.issue",
  "platform.promotion.replay",
  "platform.promotion.verify",
  "platform.promotion.reconcile"
]);
const SESSION_STATUSES = new Set(["active", "expired", "revoked"]);
const CHALLENGE_STATUSES = new Set(["pending", "consuming", "consumed", "failed", "expired"]);
const CHALLENGE_RESULT_KEYS = Object.freeze([
  "challenge_id", "platform_session_id", "jti_hash", "challenge_hash", "binding_hash",
  "request_digest_sha256", "allowed_credential_ids", "principal_id", "member_id",
  "organization_id", "assignment_id", "authority_generation", "operation", "capability",
  "rp_id", "origin", "user_verification", "status", "version", "issued_at", "expires_at",
  "claimed_at", "completed_at", "failed_at", "failure_reason"
]);
const CREDENTIAL_RESULT_KEYS = Object.freeze([
  "platform_credential_id", "webauthn_credential_id", "principal_id", "member_id", "status",
  "sign_count", "sign_count_state", "backup_eligible", "backup_state", "version", "public_key",
  "transports", "revoked_at"
]);
const SESSION_RESULT_KEYS = Object.freeze([
  "session_id", "principal_id", "member_id", "organization_id", "assignment_id", "credential_id",
  "operation", "capability", "principal_authority_generation", "assignment_version",
  "credential_version", "status", "version", "created_at", "authenticated_at", "last_seen_at",
  "expires_at", "idle_expires_at", "expired_at", "revoked_at", "revoke_reason"
]);
const MAX_CACHE_ENTRIES = 4096;

/**
 * The SQL strings are deliberately kept beside the adapter so a query cannot
 * be changed by a caller.  The issue method points only at the 0054 atomic
 * wrapper; the ungranted issue and challenge-complete helpers are never used.
 */
export const PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL = Object.freeze({
  createChallenge: "SELECT public.agentpass_platform_session_challenge_create($1::uuid,$2::uuid,$3::bytea,$4::bytea,$5::bytea,$6::bytea,$7::bytea[],$8::uuid,$9::uuid,$10::uuid,$11::uuid,$12::bigint,$13::text,$14::text,$15::text,$16::text,$17::text,$18::integer) AS challenge",
  findChallenge: "SELECT public.agentpass_platform_session_challenge_find($1::uuid) AS challenge",
  claimChallenge: "SELECT public.agentpass_platform_session_challenge_claim($1::uuid,$2::bytea,$3::bytea,$4::bytea,$5::bytea) AS claim",
  failChallenge: "SELECT public.agentpass_platform_session_challenge_fail($1::uuid,$2::bytea,$3::bytea,$4::bytea,$5::bytea,$6::text) AS failure",
  findCredential: "SELECT public.agentpass_platform_session_credential_find($1::uuid,$2::bytea,$3::bytea) AS credential",
  advanceCredential: "SELECT public.agentpass_platform_credential_advance_verified($1::uuid,$2::bytea,$3::uuid,$4::bytea,$5::bigint,$6::bigint,$7::bigint,$8::boolean,$9::boolean) AS counter",
  completeAndIssue: "SELECT public.agentpass_platform_session_complete_and_issue($1::uuid,$2::bytea,$3::bytea,$4::uuid,$5::bytea,$6::bytea,$7::bytea,$8::bytea,$9::bytea,$10::integer,$11::integer) AS result"
});

export const PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_SESSION_WEBAUTHN_REPOSITORY_CONFIG",
  INPUT: "ERR_PLATFORM_SESSION_WEBAUTHN_REPOSITORY_INPUT",
  RESULT: "ERR_PLATFORM_SESSION_WEBAUTHN_REPOSITORY_RESULT",
  DATABASE: "ERR_PLATFORM_SESSION_WEBAUTHN_REPOSITORY_DATABASE"
});

const ERROR_MESSAGES = Object.freeze({
  [PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.CONFIG]: "platform WebAuthn repository configuration is invalid",
  [PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT]: "platform WebAuthn repository request is invalid",
  [PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT]: "platform WebAuthn repository returned an invalid result",
  [PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.DATABASE]: "platform WebAuthn storage is unavailable"
});

export class PlatformSessionWebAuthnRepositoryError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "PlatformSessionWebAuthnRepositoryError";
    this.code = Object.hasOwn(ERROR_MESSAGES, code)
      ? code
      : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.DATABASE;
  }
}

export function createPostgresPlatformSessionWebAuthnRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.CONFIG);

  // These maps contain only public identifiers and fixed-width digests.  They
  // bridge the current ceremony service's narrow callbacks to 0054's
  // request-bound signatures; no raw ceremony material is ever retained.
  const challenges = new Map();
  const credentials = new Map();

  async function createPlatformSessionChallenge(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeCreateInput(args[0]);
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.createChallenge,
      [
        input.challenge_id, input.platform_session_id, input.jti_hash, input.challenge_hash,
        input.binding_hash, input.request_digest_sha256, input.allowed_webauthn_credential_ids,
        input.principal_id, input.member_id, input.organization_id, input.assignment_id,
        input.authority_generation, input.operation, input.capability, input.rp_id, input.origin,
        input.user_verification, input.ttl_ms
      ],
      "challenge"
    );
    const challenge = normalizeChallengeResult(result);
    assertChallengeBinding(challenge, input);
    rememberChallenge(challenge);
    return challenge;
  }

  async function findPlatformSessionChallenge(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeFindChallengeInput(args[0]);
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.findChallenge,
      [input.challenge_id],
      "challenge"
    );
    if (result === null) {
      challenges.delete(input.challenge_id);
      return null;
    }
    const challenge = normalizeChallengeResult(result);
    rememberChallenge(challenge);
    return challenge;
  }

  async function claimPlatformSessionChallenge(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeClaimInput(args[0]);
    const state = challengeState(challenges, input.challenge_id);
    assertChallengeProof(state, input.jti_hash, input.challenge_hash, input.binding_hash);
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.claimChallenge,
      [input.challenge_id, input.jti_hash, input.challenge_hash, input.binding_hash, state.request_digest_sha256],
      "claim"
    );
    const claim = normalizeClaimResult(result, state);
    if (claim.record) rememberChallenge(claim.record);
    return claim;
  }

  async function failPlatformSessionChallenge(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeFailInput(args[0]);
    const state = challengeState(challenges, input.challenge_id);
    assertChallengeProof(state, input.jti_hash, input.challenge_hash, input.binding_hash);
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.failChallenge,
      [input.challenge_id, input.jti_hash, input.challenge_hash, input.binding_hash, state.request_digest_sha256, "verification_failed"],
      "failure"
    );
    const failure = normalizeChallengeTransitionResult(result, state, "failure");
    if (failure.record) rememberChallenge(failure.record);
    return failure;
  }

  async function completePlatformSessionChallenge(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeCompleteInput(args[0]);
    const state = challengeState(challenges, input.challenge_id);
    assertChallengeProof(state, input.jti_hash, input.challenge_hash, input.binding_hash);
    assertPublicCredentialMatches(state, input.credential_id);
    // 0054 does not grant challenge_complete to agentpass_app.  Session issue
    // is atomic and already completes the challenge; this method is therefore
    // a read-only confirmation for the legacy service callback.
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.findChallenge,
      [input.challenge_id],
      "challenge"
    );
    if (result === null) return Object.freeze({ outcome: "replayed" });
    const challenge = normalizeChallengeResult(result);
    assertChallengeBinding(challenge, state);
    rememberChallenge(challenge);
    if (challenge.status === "consumed") return Object.freeze({ outcome: "already-completed", record: challenge });
    if (challenge.status === "expired") return Object.freeze({ outcome: "expired", record: challenge });
    return Object.freeze({ outcome: "not-completed", record: challenge });
  }

  async function findPlatformCredentialForSession(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeFindCredentialInput(args[0]);
    const state = challengeStateBySession(challenges, input.platform_session_id);
    assertCredentialBinding(state, input);
    const publicCredentialId = publicCredentialBytes(input.credential_id);
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.findCredential,
      [state.challenge_id, state.request_digest_sha256, publicCredentialId],
      "credential"
    );
    if (result === null) return null;
    const credential = normalizeCredentialResult(result);
    if (credential.webauthn_credential_id !== input.credential_id
      || credential.principal_id !== state.principal_id
      || credential.member_id !== state.member_id) {
      throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
    }
    rememberCredential(state, credential);
    return credential;
  }

  async function advancePlatformCredentialCounter(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeAdvanceInput(args[0]);
    const credential = credentialState(credentials, input.credential_id);
    const state = challengeStateBySession(challenges, input.platform_session_id ?? credential.platform_session_id);
    if (credential.challenge_id !== state.challenge_id
      || credential.webauthn_credential_id !== input.webauthn_credential_id
      || credential.principal_id !== input.principal_id
      || credential.member_id !== input.member_id
      || input.request_digest_sha256.toString("hex") !== state.request_digest_sha256.toString("hex")) {
      throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    }
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.advanceCredential,
      [
        state.challenge_id, state.request_digest_sha256, credential.platform_credential_id,
        publicCredentialBytes(input.webauthn_credential_id), credential.version,
        credential.sign_count, input.sign_count, credential.backup_eligible, credential.backup_state
      ],
      "counter"
    );
    const counter = normalizeCounterResult(result, credential);
    if (counter.credential) rememberCredential(state, counter.credential);
    return counter;
  }

  async function issuePlatformSession(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
    const input = normalizeIssueInput(args[0]);
    const state = challengeState(challenges, input.challenge_id);
    const credential = credentialState(credentials, input.credential_id);
    assertIssueBinding(input, state, credential);
    const result = await call(client,
      PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.completeAndIssue,
      [
        input.session_id, input.session_material_hash, input.csrf_token_hash, input.challenge_id,
        input.jti_hash, input.challenge_hash, input.binding_hash, state.request_digest_sha256,
        publicCredentialBytes(credential.webauthn_credential_id), input.ttl_seconds, input.idle_timeout_seconds
      ],
      "result"
    );
    const atomic = normalizeAtomicIssueResult(result, state, credential);
    rememberChallenge(atomic.challenge);
    return atomic;
  }

  const repository = {};
  for (const method of PLATFORM_SESSION_WEBAUTHN_REPOSITORY_METHODS) {
    const implementation = {
      createPlatformSessionChallenge,
      findPlatformSessionChallenge,
      claimPlatformSessionChallenge,
      failPlatformSessionChallenge,
      completePlatformSessionChallenge,
      findPlatformCredentialForSession,
      advancePlatformCredentialCounter,
      issuePlatformSession
    }[method];
    if (typeof implementation !== "function") throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.CONFIG);
    repository[method] = implementation;
  }
  return Object.freeze(repository);

  function rememberChallenge(value) {
    const state = Object.freeze({
      challenge_id: value.challenge_id,
      platform_session_id: value.platform_session_id,
      jti_hash: Buffer.from(value.jti_hash),
      challenge_hash: Buffer.from(value.challenge_hash),
      binding_hash: Buffer.from(value.binding_hash),
      request_digest_sha256: Buffer.from(value.request_digest_sha256),
      allowed_credential_ids: Object.freeze([...value.allowed_credential_ids]),
      principal_id: value.principal_id,
      member_id: value.member_id,
      organization_id: value.organization_id,
      assignment_id: value.assignment_id,
      authority_generation: value.authority_generation,
      operation: value.operation,
      capability: value.capability,
      rp_id: value.rp_id,
      origin: value.origin,
      user_verification: value.user_verification,
      status: value.status,
      version: value.version
    });
    remember(challenges, value.challenge_id, state);
    remember(challenges, value.platform_session_id, state);
  }

  function rememberCredential(state, value) {
    const record = Object.freeze({
      challenge_id: state.challenge_id,
      platform_session_id: state.platform_session_id,
      platform_credential_id: value.platform_credential_id,
      webauthn_credential_id: value.webauthn_credential_id,
      principal_id: value.principal_id,
      member_id: value.member_id,
      version: value.version,
      sign_count: value.sign_count,
      backup_eligible: value.backup_eligible,
      backup_state: value.backup_state
    });
    remember(credentials, value.platform_credential_id, record);
    remember(credentials, value.webauthn_credential_id, record);
  }
}

async function call(client, sql, params, alias) {
  let result;
  try {
    result = await client.query(sql, params);
  } catch {
    throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.DATABASE);
  }
  try {
    const row = singleRow(result, alias);
    return parseJsonValue(row[alias]);
  } catch (error) {
    if (error instanceof PlatformSessionWebAuthnRepositoryError) throw error;
    throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  }
}

function normalizeCreateInput(value) {
  const keys = [
    "challenge_id", "jti_hash", "challenge_hash", "binding_hash", "platform_session_id",
    "principal_id", "member_id", "organization_id", "assignment_id", "authority_generation",
    "operation", "capability", "request_digest_sha256", "allowed_credential_ids", "rp_id",
    "origin", "user_verification", "issued_at", "expires_at", "status"
  ];
  if (!exactKeys(value, keys)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  const issuedAt = safeInteger(value.issued_at);
  const expiresAt = safeInteger(value.expires_at);
  const ttl = expiresAt - issuedAt;
  if (ttl < 1_000 || ttl > 300_000 || value.status !== "pending") throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    challenge_id: uuid(value.challenge_id),
    platform_session_id: uuid(value.platform_session_id),
    jti_hash: digestBytes(value.jti_hash),
    challenge_hash: digestBytes(value.challenge_hash),
    binding_hash: digestBytes(value.binding_hash),
    request_digest_sha256: digestInput(value.request_digest_sha256),
    allowed_credential_ids: credentialArray(value.allowed_credential_ids),
    allowed_webauthn_credential_ids: value.allowed_credential_ids.map(publicCredentialBytes),
    principal_id: uuid(value.principal_id),
    member_id: uuid(value.member_id),
    organization_id: uuid(value.organization_id),
    assignment_id: uuid(value.assignment_id),
    authority_generation: positiveInteger(value.authority_generation),
    operation: operation(value.operation),
    capability: capability(value.capability),
    rp_id: boundedText(value.rp_id, 253),
    origin: boundedText(value.origin, 512),
    user_verification: value.user_verification === "required" ? value.user_verification : invalidInput(),
    ttl_ms: ttl
  });
}

function normalizeFindChallengeInput(value) {
  if (!exactKeys(value, ["challenge_id"])) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({ challenge_id: uuid(value.challenge_id) });
}

function normalizeClaimInput(value) {
  if (!exactKeys(value, ["challenge_id", "challenge_hash", "jti_hash", "binding_hash", "claimed_at"])) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    challenge_id: uuid(value.challenge_id),
    challenge_hash: digestBytes(value.challenge_hash),
    jti_hash: digestBytes(value.jti_hash),
    binding_hash: digestBytes(value.binding_hash),
    claimed_at: safeInteger(value.claimed_at)
  });
}

function normalizeFailInput(value) {
  if (!exactKeys(value, ["challenge_id", "challenge_hash", "jti_hash", "binding_hash", "failed_at"])) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    challenge_id: uuid(value.challenge_id),
    challenge_hash: digestBytes(value.challenge_hash),
    jti_hash: digestBytes(value.jti_hash),
    binding_hash: digestBytes(value.binding_hash),
    failed_at: safeInteger(value.failed_at)
  });
}

function normalizeCompleteInput(value) {
  if (!exactKeys(value, ["challenge_id", "challenge_hash", "jti_hash", "binding_hash", "credential_id", "completed_at"])) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    challenge_id: uuid(value.challenge_id),
    challenge_hash: digestBytes(value.challenge_hash),
    jti_hash: digestBytes(value.jti_hash),
    binding_hash: digestBytes(value.binding_hash),
    credential_id: credentialId(value.credential_id),
    completed_at: safeInteger(value.completed_at)
  });
}

function normalizeFindCredentialInput(value) {
  const keys = ["platform_session_id", "session_id", "principal_id", "member_id", "organization_id", "assignment_id", "authority_generation", "credential_id"];
  if (!exactKeys(value, keys)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    platform_session_id: uuid(value.platform_session_id),
    session_id: uuid(value.session_id),
    principal_id: uuid(value.principal_id),
    member_id: uuid(value.member_id),
    organization_id: uuid(value.organization_id),
    assignment_id: uuid(value.assignment_id),
    authority_generation: positiveInteger(value.authority_generation),
    credential_id: credentialId(value.credential_id)
  });
}

function normalizeAdvanceInput(value) {
  const keys = ["credential_id", "webauthn_credential_id", "principal_id", "member_id", "organization_id", "assignment_id", "authority_generation", "request_digest_sha256", "sign_count"];
  if (!exactKeys(value, keys)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    credential_id: uuid(value.credential_id),
    webauthn_credential_id: credentialId(value.webauthn_credential_id),
    principal_id: uuid(value.principal_id),
    member_id: uuid(value.member_id),
    organization_id: uuid(value.organization_id),
    assignment_id: uuid(value.assignment_id),
    authority_generation: positiveInteger(value.authority_generation),
    request_digest_sha256: digestInput(value.request_digest_sha256),
    sign_count: signCount(value.sign_count)
  });
}

function normalizeIssueInput(value) {
  const keys = [
    "session_id", "session_material_hash", "csrf_token_hash", "principal_id", "member_id",
    "organization_id", "assignment_id", "credential_id", "operation", "capability",
    "authority_generation", "request_digest_sha256", "challenge_id", "jti_hash", "ttl_seconds",
    "idle_timeout_seconds", "authenticated_at"
  ];
  if (!exactKeys(value, keys)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  const ttl = positiveInteger(value.ttl_seconds);
  const idle = positiveInteger(value.idle_timeout_seconds);
  if (ttl > 86_400 || idle > ttl) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    session_id: uuid(value.session_id),
    session_material_hash: digestBytes(value.session_material_hash),
    csrf_token_hash: digestBytes(value.csrf_token_hash),
    principal_id: uuid(value.principal_id),
    member_id: uuid(value.member_id),
    organization_id: uuid(value.organization_id),
    assignment_id: uuid(value.assignment_id),
    credential_id: uuid(value.credential_id),
    operation: operation(value.operation),
    capability: capability(value.capability),
    authority_generation: positiveInteger(value.authority_generation),
    request_digest_sha256: digestInput(value.request_digest_sha256),
    challenge_id: uuid(value.challenge_id),
    jti_hash: digestBytes(value.jti_hash),
    ttl_seconds: ttl,
    idle_timeout_seconds: idle,
    authenticated_at: safeInteger(value.authenticated_at)
  });
}

function normalizeChallengeResult(value) {
  const row = objectValue(value);
  if (!exactKeys(row, CHALLENGE_RESULT_KEYS)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  const challenge = Object.freeze({
    challenge_id: uuid(row.challenge_id, true),
    platform_session_id: uuid(row.platform_session_id, true),
    jti_hash: digestResult(row.jti_hash),
    challenge_hash: digestResult(row.challenge_hash),
    binding_hash: digestResult(row.binding_hash),
    request_digest_sha256: digestResult(row.request_digest_sha256),
    allowed_credential_ids: credentialArrayResult(row.allowed_credential_ids),
    principal_id: uuid(row.principal_id, true),
    member_id: uuid(row.member_id, true),
    organization_id: uuid(row.organization_id, true),
    assignment_id: uuid(row.assignment_id, true),
    authority_generation: positiveInteger(row.authority_generation, true),
    operation: operation(row.operation, true),
    capability: capability(row.capability, true),
    rp_id: boundedText(row.rp_id, 253, true),
    origin: boundedText(row.origin, 512, true),
    user_verification: row.user_verification,
    status: challengeStatus(row.status),
    version: positiveInteger(row.version, true),
    issued_at: timestamp(row.issued_at),
    expires_at: timestamp(row.expires_at),
    claimed_at: nullableTimestamp(row.claimed_at),
    completed_at: nullableTimestamp(row.completed_at),
    failed_at: nullableTimestamp(row.failed_at),
    failure_reason: nullableReason(row.failure_reason)
  });
  if (challenge.user_verification !== "required" || Date.parse(challenge.expires_at) <= Date.parse(challenge.issued_at)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return challenge;
}

function normalizeClaimResult(value, state) {
  const row = objectValue(value);
  if (Object.hasOwn(row, "outcome")) {
    if (!exactKeys(row, ["outcome"]) || !new Set(["busy", "replayed", "expired", "mismatch"]).has(row.outcome)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
    return Object.freeze({ outcome: row.outcome });
  }
  if (!exactKeys(row, ["claimed", "record"]) || row.claimed !== true) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  const record = normalizeChallengeResult(row.record);
  assertChallengeBinding(record, state);
  if (record.status !== "consuming") throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return Object.freeze({ claimed: true, record });
}

function normalizeChallengeTransitionResult(value, state, alias) {
  const row = objectValue(value);
  const allowed = alias === "failure" ? new Set(["failed", "already-failed", "replayed", "mismatch"]) : new Set();
  if (!Object.hasOwn(row, "outcome") || (Object.keys(row).length !== 1 && Object.keys(row).length !== 2) || !allowed.has(row.outcome)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  if (Object.keys(row).length === 1) return Object.freeze({ outcome: row.outcome });
  const record = normalizeChallengeResult(row.record);
  assertChallengeBinding(record, state);
  return Object.freeze({ outcome: row.outcome, record });
}

function normalizeCredentialResult(value) {
  if (value === null) return null;
  const row = objectValue(value);
  if (!exactKeys(row, CREDENTIAL_RESULT_KEYS)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return Object.freeze({
    platform_credential_id: uuid(row.platform_credential_id, true),
    webauthn_credential_id: credentialId(row.webauthn_credential_id, true),
    principal_id: uuid(row.principal_id, true),
    member_id: uuid(row.member_id, true),
    status: row.status === "active" ? row.status : invalidResult(),
    sign_count: signCount(row.sign_count, true),
    sign_count_state: new Set(["zero-counter", "monotonic", "clone-detected"]).has(row.sign_count_state) ? row.sign_count_state : invalidResult(),
    backup_eligible: booleanValue(row.backup_eligible),
    backup_state: booleanValue(row.backup_state),
    version: positiveInteger(row.version, true),
    public_key: publicKey(row.public_key),
    transports: normalizeTransports(row.transports),
    revoked_at: nullableTimestamp(row.revoked_at)
  });
}

function normalizeCounterResult(value, previous) {
  const row = objectValue(value);
  if (!exactKeys(row, ["outcome"]) && !exactKeys(row, ["outcome", "credential"])) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  if (!new Set(["accepted", "clone-detected", "denied", "conflict"]).has(row.outcome)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  if (!Object.hasOwn(row, "credential")) return Object.freeze({ outcome: row.outcome });
  const credential = normalizeCounterCredential(row.credential);
  if (credential.platform_credential_id !== previous.platform_credential_id
    || credential.webauthn_credential_id !== previous.webauthn_credential_id) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return Object.freeze({ outcome: row.outcome, credential });
}

function normalizeCounterCredential(value) {
  const row = objectValue(value);
  const keys = ["platform_credential_id", "webauthn_credential_id", "status", "sign_count", "sign_count_state", "backup_eligible", "backup_state", "version", "clone_detected_at"];
  if (!exactKeys(row, keys)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return Object.freeze({
    platform_credential_id: uuid(row.platform_credential_id, true),
    webauthn_credential_id: credentialId(row.webauthn_credential_id, true),
    status: row.status === "active" ? row.status : invalidResult(),
    sign_count: signCount(row.sign_count, true),
    sign_count_state: new Set(["zero-counter", "monotonic", "clone-detected"]).has(row.sign_count_state) ? row.sign_count_state : invalidResult(),
    backup_eligible: booleanValue(row.backup_eligible),
    backup_state: booleanValue(row.backup_state),
    version: positiveInteger(row.version, true),
    clone_detected_at: nullableTimestamp(row.clone_detected_at)
  });
}

function normalizeAtomicIssueResult(value, state, credential) {
  const row = objectValue(value);
  if (!exactKeys(row, ["session", "challenge"])) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  const session = normalizeSessionResult(row.session);
  const challenge = normalizeChallengeResult(row.challenge);
  assertChallengeBinding(challenge, state);
  if (challenge.status !== "consumed"
    || session.session_id !== state.platform_session_id
    || session.principal_id !== state.principal_id
    || session.member_id !== state.member_id
    || session.organization_id !== state.organization_id
    || session.assignment_id !== state.assignment_id
    || session.credential_id !== credential.platform_credential_id
    || session.operation !== state.operation
    || session.capability !== state.capability) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return Object.freeze({ session, challenge });
}

function normalizeSessionResult(value) {
  const row = objectValue(value);
  if (!exactKeys(row, SESSION_RESULT_KEYS)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  const session = Object.freeze({
    session_id: uuid(row.session_id, true),
    principal_id: uuid(row.principal_id, true),
    member_id: uuid(row.member_id, true),
    organization_id: uuid(row.organization_id, true),
    assignment_id: uuid(row.assignment_id, true),
    credential_id: uuid(row.credential_id, true),
    operation: operation(row.operation, true),
    capability: capability(row.capability, true),
    principal_authority_generation: positiveInteger(row.principal_authority_generation, true),
    assignment_version: positiveInteger(row.assignment_version, true),
    credential_version: positiveInteger(row.credential_version, true),
    status: SESSION_STATUSES.has(row.status) ? row.status : invalidResult(),
    version: positiveInteger(row.version, true),
    created_at: timestamp(row.created_at),
    authenticated_at: timestamp(row.authenticated_at),
    last_seen_at: timestamp(row.last_seen_at),
    expires_at: timestamp(row.expires_at),
    idle_expires_at: timestamp(row.idle_expires_at),
    expired_at: nullableTimestamp(row.expired_at),
    revoked_at: nullableTimestamp(row.revoked_at),
    revoke_reason: nullableReason(row.revoke_reason)
  });
  if (session.operation !== session.capability || Date.parse(session.authenticated_at) >= Date.parse(session.expires_at) || Date.parse(session.idle_expires_at) > Date.parse(session.expires_at)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return session;
}

function assertChallengeBinding(actual, expected) {
  const state = expected;
  if (actual.challenge_id !== state.challenge_id
    || actual.platform_session_id !== state.platform_session_id
    || actual.principal_id !== state.principal_id
    || actual.member_id !== state.member_id
    || actual.organization_id !== state.organization_id
    || actual.assignment_id !== state.assignment_id
    || actual.authority_generation !== state.authority_generation
    || actual.operation !== state.operation
    || actual.capability !== state.capability
    || actual.rp_id !== state.rp_id
    || actual.origin !== state.origin
    || actual.user_verification !== state.user_verification
    || actual.request_digest_sha256.toString("hex") !== state.request_digest_sha256.toString("hex")
    || !sameArray(actual.allowed_credential_ids, state.allowed_credential_ids)
    || !sameBytes(actual.jti_hash, state.jti_hash)
    || !sameBytes(actual.challenge_hash, state.challenge_hash)
    || !sameBytes(actual.binding_hash, state.binding_hash)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
}

function assertChallengeProof(state, jtiHash, challengeHash, bindingHash) {
  if (!sameBytes(state.jti_hash, jtiHash) || !sameBytes(state.challenge_hash, challengeHash) || !sameBytes(state.binding_hash, bindingHash)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
}

function assertPublicCredentialMatches(state, value) {
  if (!state.allowed_credential_ids.includes(value)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
}

function assertCredentialBinding(state, input) {
  if (input.session_id !== input.platform_session_id
    || input.principal_id !== state.principal_id
    || input.member_id !== state.member_id
    || input.organization_id !== state.organization_id
    || input.assignment_id !== state.assignment_id
    || input.authority_generation !== state.authority_generation
    || !state.allowed_credential_ids.includes(input.credential_id)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
}

function assertIssueBinding(input, state, credential) {
  if (input.session_id !== state.platform_session_id
    || input.principal_id !== state.principal_id
    || input.member_id !== state.member_id
    || input.organization_id !== state.organization_id
    || input.assignment_id !== state.assignment_id
    || input.authority_generation !== state.authority_generation
    || input.operation !== state.operation
    || input.capability !== state.capability
    || input.request_digest_sha256.toString("hex") !== state.request_digest_sha256.toString("hex")
    || !sameBytes(input.jti_hash, state.jti_hash)
    || input.credential_id !== credential.platform_credential_id
    || !state.allowed_credential_ids.includes(credential.webauthn_credential_id)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
}

function challengeState(challenges, value) {
  const state = challenges.get(value);
  if (!state || state.challenge_id !== value) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return state;
}

function challengeStateBySession(challenges, value) {
  const state = challenges.get(value);
  if (!state || state.platform_session_id !== value) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return state;
}

function credentialState(credentials, value) {
  const state = credentials.get(value);
  if (!state || state.platform_credential_id !== value) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return state;
}

function remember(map, key, value) {
  map.delete(key);
  map.set(key, value);
  while (map.size > MAX_CACHE_ENTRIES) map.delete(map.keys().next().value);
}

function singleRow(result, alias) {
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1 || !exactKeys(result.rows[0], [alias])) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return result.rows[0];
}

function parseJsonValue(value) {
  if (value === null) return null;
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch { throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT); }
  }
  return value;
}

function objectValue(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function credentialArray(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  const result = value.map((item) => credentialId(item));
  if (new Set(result).size !== result.length) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  const bytes = result.map(publicCredentialBytes);
  for (let index = 1; index < bytes.length; index += 1) if (Buffer.compare(bytes[index - 1], bytes[index]) >= 0) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze(result);
}

function credentialArrayResult(value) {
  try { return credentialArray(value); } catch { throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT); }
}

function credentialId(value, result = false) {
  if (typeof value !== "string" || !BASE64URL.test(value)) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  let bytes;
  try { bytes = Buffer.from(value, "base64url"); } catch { throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT); }
  if (bytes.length < 16 || bytes.length > 1024 || bytes.toString("base64url") !== value) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function publicCredentialBytes(value) {
  credentialId(value);
  return Buffer.from(value, "base64url");
}

function digestInput(value) {
  if (typeof value === "string" && HEX_256.test(value)) return Buffer.from(value, "hex");
  if (Buffer.isBuffer(value) && value.length === 32) return Buffer.from(value);
  if (value instanceof Uint8Array && value.byteLength === 32) return Buffer.from(value);
  throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
}

function digestBytes(value) {
  if (Buffer.isBuffer(value) && value.length === 32) return Buffer.from(value);
  if (value instanceof Uint8Array && value.byteLength === 32) return Buffer.from(value);
  throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
}

function digestResult(value) {
  if (typeof value === "string" && HEX_256.test(value)) return Buffer.from(value, "hex");
  if (Buffer.isBuffer(value) && value.length === 32) return Buffer.from(value);
  throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
}

function publicKey(value) {
  if (Buffer.isBuffer(value) && value.length >= 32 && value.length <= 4096) return Buffer.from(value);
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  let bytes;
  try { bytes = Buffer.from(value, "base64"); } catch { throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT); }
  if (bytes.length < 32 || bytes.length > 4096) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return bytes;
}

function normalizeTransports(value) {
  if (value === null || value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 8 || value.some((item) => typeof item !== "string" || !["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"].includes(item))) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return Object.freeze([...new Set(value)]);
}

function timestamp(value) {
  if (typeof value !== "string" || !RFC3339.test(value) || !Number.isFinite(Date.parse(value))) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return new Date(Date.parse(value)).toISOString();
}

function nullableTimestamp(value) { return value === null ? null : timestamp(value); }

function nullableReason(value) {
  if (value === null) return null;
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || /[\u0000-\u001f\u007f]/u.test(value)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function boundedText(value, maximum, result = false) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function uuid(value, result = false) {
  if (typeof value !== "string" || !UUID.test(value)) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value.toLowerCase();
}

function operation(value, result = false) {
  if (typeof value !== "string" || !OPERATION.test(value)) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function capability(value, result = false) {
  if (typeof value !== "string" || !CAPABILITIES.has(value)) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function challengeStatus(value) {
  if (!CHALLENGE_STATUSES.has(value)) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function positiveInteger(value, result = false) {
  if (!Number.isSafeInteger(value) || value < 1) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function safeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function signCount(value, result = false) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) throw repositoryError(result ? PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT : PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function booleanValue(value) {
  if (typeof value !== "boolean") throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function sameBytes(left, right) { return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length === right.length && left.equals(right); }
function sameArray(left, right) { return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((value, index) => value === right[index]); }

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && keys.every((key) => typeof key === "string" && expected.includes(key) && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true);
}

function invalidInput() { throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.INPUT); }
function invalidResult() { throw repositoryError(PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES.RESULT); }
function repositoryError(code) { return new PlatformSessionWebAuthnRepositoryError(code); }

export default createPostgresPlatformSessionWebAuthnRepository;
