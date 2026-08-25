import crypto from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const OPAQUE = /^[A-Za-z0-9_-]{43}$/u;
const OPERATION_APPROVE = "human.recovery.approve";
const OPERATION_ACTIVATE = "human.recovery.activate";
const OPERATION_REGISTER = "human.recovery.credential.register";
const DEFAULT_THRESHOLD = 2;
const DEFAULT_REQUEST_TTL_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_DELAY_MS = 24 * 60 * 60 * 1_000;
const MAX_DURATION_MS = 30 * 24 * 60 * 60 * 1_000;
const TERMINAL_STATES = new Set(["cancelled", "expired", "failed", "activated"]);
const LIVE_STATES = new Set(["pending", "approved", "delayed", "session_issued", "credential_enrolled"]);
const OWNER_ROLES = new Set(["owner"]);

export const OWNER_RECOVERY_OPERATIONS = Object.freeze({
  approve: OPERATION_APPROVE,
  register: OPERATION_REGISTER,
  activate: OPERATION_ACTIVATE
});

export const OWNER_RECOVERY_REPOSITORY_METHODS = Object.freeze([
  "createRecoveryRequest",
  "getRecoveryRequest",
  "approveRecoveryRequest",
  "cancelRecoveryRequest",
  "consumeRecoveryExchange",
  "authenticateRecoverySession",
  "enrollRecoveryCredentialInTransaction",
  "activateRecoveryInTransaction"
]);

export const OWNER_RECOVERY_CEREMONY_METHODS = Object.freeze([
  "beginRegistration",
  "verifyRegistration",
  "beginActivation",
  "authorizeActivation"
]);

export const OWNER_RECOVERY_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "owner_recovery_invalid_request",
  FORBIDDEN: "owner_recovery_forbidden",
  NOT_FOUND: "owner_recovery_not_found",
  VERSION_CONFLICT: "owner_recovery_stale_version",
  IDEMPOTENCY_CONFLICT: "owner_recovery_idempotency_conflict",
  APPROVAL_REPLAYED: "owner_recovery_approval_replayed",
  APPROVAL_INVALID: "owner_recovery_approval_invalid",
  THRESHOLD_UNAVAILABLE: "owner_recovery_threshold_unavailable",
  DELAY_NOT_ELAPSED: "owner_recovery_delay_not_elapsed",
  EXCHANGE_INVALID: "owner_recovery_exchange_invalid",
  EXCHANGE_REPLAYED: "owner_recovery_exchange_replayed",
  SESSION_REQUIRED: "owner_recovery_session_required",
  SESSION_REPLAYED: "owner_recovery_session_replayed",
  REGISTRATION_INVALID: "owner_recovery_registration_invalid",
  CREDENTIAL_EXISTS: "owner_recovery_credential_exists",
  ACTIVATION_INVALID: "owner_recovery_activation_invalid",
  ACTIVATION_REPLAYED: "owner_recovery_activation_replayed",
  UNAVAILABLE: "owner_recovery_unavailable"
});

const CODE = OWNER_RECOVERY_ERROR_CODES;

const ERROR_MESSAGES = Object.freeze({
  [CODE.INVALID_REQUEST]: "The recovery request is invalid",
  [CODE.FORBIDDEN]: "The recovery operation is not allowed",
  [CODE.NOT_FOUND]: "The recovery request was not found",
  [CODE.VERSION_CONFLICT]: "The recovery request was changed by another request",
  [CODE.IDEMPOTENCY_CONFLICT]: "The idempotency key was already used for another recovery request",
  [CODE.APPROVAL_REPLAYED]: "The recovery approval is no longer valid",
  [CODE.APPROVAL_INVALID]: "The recovery approval is invalid",
  [CODE.THRESHOLD_UNAVAILABLE]: "The organization cannot satisfy the recovery threshold",
  [CODE.DELAY_NOT_ELAPSED]: "The recovery delay has not elapsed",
  [CODE.EXCHANGE_INVALID]: "The recovery exchange is invalid",
  [CODE.EXCHANGE_REPLAYED]: "The recovery exchange is no longer valid",
  [CODE.SESSION_REQUIRED]: "A valid recovery session is required",
  [CODE.SESSION_REPLAYED]: "The recovery session is no longer valid",
  [CODE.REGISTRATION_INVALID]: "The recovery registration is invalid",
  [CODE.CREDENTIAL_EXISTS]: "The recovery credential already exists",
  [CODE.ACTIVATION_INVALID]: "The recovery activation is invalid",
  [CODE.ACTIVATION_REPLAYED]: "The recovery activation is no longer valid",
  [CODE.UNAVAILABLE]: "The recovery service is unavailable"
});

export class OwnerRecoveryError extends Error {
  constructor(code, { cause = undefined } = {}) {
    // Causes can contain assertions, credentials, challenge material, or
    // database details. Stable public errors deliberately retain none of it.
    void cause;
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[CODE.UNAVAILABLE]);
    this.name = "OwnerRecoveryError";
    this.code = code;
  }
}

/**
 * Service boundary for threshold owner recovery.
 *
 * Repository methods are transaction boundaries. They must re-check tenant,
 * role, membership epoch, request/session state, and the expected version
 * under the lock order in THRESHOLD_OWNER_RECOVERY_DESIGN.md. They receive
 * `exchange_digest` and `session_digest`, never their raw values. They also
 * receive no assertion, challenge, attestation object, or notification data.
 *
 * - createRecoveryRequest(input) -> { request, eligibility?, exchange_value? }
 * - getRecoveryRequest(input) -> { request, eligibility?, exchange_value? }
 * - approveRecoveryRequest(input) -> { request, eligibility?, exchange_value? }
 * - cancelRecoveryRequest(input) -> { request, eligibility?, exchange_value? }
 * - consumeRecoveryExchange(input) -> { recovery_session } or session
 * - authenticateRecoverySession(input) -> internal session or null
 * - enrollRecoveryCredentialInTransaction({ tx, binding, verified_credential, recovery_session, ... }) -> { committed, mutation }
 * - activateRecoveryInTransaction({ tx, binding, authorization, recovery_session, ... }) -> { committed, mutation }
 *
 * The ceremony methods are:
 * - beginRegistration({ recovery_session, organization_id, member_id, operation, rp_id, origin }) -> public options
 * - verifyRegistration({ recovery_session, organization_id, member_id, operation, challenge_id, credential, complete(tx, binding, verified_credential) }) -> { committed, mutation }
 * - beginActivation({ recovery_session, organization_id, member_id, operation, rp_id, origin }) -> { challenge_id, options }
 * - verifyActivation({ recovery_session, organization_id, member_id, operation, challenge_id, assertion, complete(tx, binding, authorization) }) -> { verified, consumed, authorization, committed, mutation }
 *
 * `complete` is mandatory for both mutating ceremonies. The recovery ceremony
 * must call it from the transaction that consumes the durable challenge or
 * authorization. This is the composition point for the 0026 low-level
 * `complete({ mutate(tx, binding) })` coordinator; no credential/state
 * mutation is performed in a second service transaction.
 */
export function createOwnerRecoveryService({
  repository,
  ceremony,
  now = () => Date.now(),
  uuid = crypto.randomUUID,
  randomBytes = crypto.randomBytes,
  threshold = DEFAULT_THRESHOLD,
  requestTtlMs = DEFAULT_REQUEST_TTL_MS,
  delayMs = DEFAULT_DELAY_MS,
  rpId = undefined,
  origin = undefined
} = {}) {
  assertRepository(repository);
  assertCeremony(ceremony);
  if (typeof now !== "function" || typeof uuid !== "function" || typeof randomBytes !== "function") throw new TypeError("recovery clock and randomness sources are invalid");
  requiredThreshold(threshold);
  boundedDuration(requestTtlMs, "requestTtlMs");
  boundedDuration(delayMs, "delayMs");
  if (rpId !== undefined && !isRpId(rpId)) throw new TypeError("rpId is invalid");
  if (origin !== undefined && !isOrigin(origin)) throw new TypeError("origin is invalid");

  async function create(input = {}) {
    const actor = normalizeOwner(normalizeActor(input.actor));
    const organizationId = requiredUuid(input.organization_id);
    const subjectMemberId = requiredUuid(input.subject_member_id);
    if (actor.organization_id !== organizationId || subjectMemberId !== actor.member_id) fail(CODE.FORBIDDEN);
    const requestedThreshold = input.threshold ?? threshold;
    requiredThreshold(requestedThreshold);
    const issuedAt = clockNow(now);
    const requestId = createUuid(uuid);
    const expiresAt = isoAt(issuedAt, requestTtlMs);
    let result;
    try {
      result = await repositoryMethod(repository, "createRecoveryRequest", "createRequest")(Object.freeze({
        actor,
        organization_id: organizationId,
        subject_member_id: subjectMemberId,
        creator_member_id: actor.member_id,
        creator_session_id: actor.session_id,
        request_id: requestId,
        threshold: requestedThreshold,
        created_at: new Date(issuedAt).toISOString(),
        expires_at: expiresAt,
        delay_ms: delayMs,
        idempotency_key: requiredIdempotencyKey(input.idempotency_key)
      }));
    } catch (error) { throw mapRepositoryError(error); }
    return normalizeEnvelope(result, { organizationId, requestId });
  }

  async function get(input = {}) {
    const actor = normalizeOwner(normalizeActor(input.actor));
    const organizationId = requiredUuid(input.organization_id);
    const requestId = requiredUuid(input.request_id);
    if (actor.organization_id !== organizationId) fail(CODE.NOT_FOUND);
    try {
      let result = await repositoryMethod(repository, "getRecoveryRequest", "getRequest")({ actor, organization_id: organizationId, request_id: requestId });
      if (!result) fail(CODE.NOT_FOUND);
      const request = result.request ?? result.recovery ?? result;
      if (request?.state === "delayed" && typeof repository.issueExchange === "function" && Number.isFinite(Date.parse(request.delay_until)) && Date.parse(request.delay_until) <= clockNow(now)) {
        const issued = await repository.issueExchange({ organization_id: organizationId, request_id: requestId, expected_version: requiredVersion(request.version) });
        result = { ...issued, ...(issued?.exchange_token === undefined || issued.exchange_token === null ? {} : { exchange_value: issued.exchange_token }) };
      }
      return normalizeEnvelope(result, { organizationId, requestId });
    } catch (error) { throw mapRepositoryError(error, CODE.NOT_FOUND); }
  }

  async function approve(input = {}) {
    const actor = normalizeOwner(normalizeActor(input.actor));
    const organizationId = requiredUuid(input.organization_id);
    const requestId = requiredUuid(input.request_id);
    if (actor.organization_id !== organizationId) fail(CODE.NOT_FOUND);
    const authorization = normalizeAuthorization(input.recent_authorization ?? input.recent_auth, actor, organizationId, OPERATION_APPROVE, clockNow(now));
    const expectedVersion = requiredVersion(input.expected_version);
    let result;
    try {
      result = await repositoryMethod(repository, "approveRecoveryRequest", "approve")(Object.freeze({
        actor,
        organization_id: organizationId,
        request_id: requestId,
        expected_version: expectedVersion,
        recent_authorization: authorization,
        owner_member_id: actor.member_id,
        owner_session_id: actor.session_id,
        idempotency_key: requiredIdempotencyKey(input.idempotency_key),
        now: new Date(clockNow(now)).toISOString()
      }));
    } catch (error) { throw mapRepositoryError(error); }
    return normalizeEnvelope(result, { organizationId, requestId });
  }

  async function cancel(input = {}) {
    const actor = normalizeOwner(normalizeActor(input.actor));
    const organizationId = requiredUuid(input.organization_id);
    const requestId = requiredUuid(input.request_id);
    if (actor.organization_id !== organizationId) fail(CODE.NOT_FOUND);
    const expectedVersion = requiredVersion(input.expected_version);
    let result;
    try {
      result = await repositoryMethod(repository, "cancelRecoveryRequest", "cancel")(Object.freeze({
        actor,
        organization_id: organizationId,
        request_id: requestId,
        expected_version: expectedVersion,
        owner_member_id: actor.member_id,
        owner_session_id: actor.session_id,
        idempotency_key: requiredIdempotencyKey(input.idempotency_key),
        now: new Date(clockNow(now)).toISOString()
      }));
    } catch (error) { throw mapRepositoryError(error); }
    return normalizeEnvelope(result, { organizationId, requestId });
  }

  async function exchange(input = {}) {
    const exchangeValue = requiredOpaque(input.exchange_value ?? input.exchange ?? input.exchange_token);
    const issuedAt = clockNow(now);
    const recoverySessionId = createUuid(uuid);
    const sessionToken = generateOpaque(randomBytes);
    let result;
    try {
      result = await repositoryMethod(repository, "consumeRecoveryExchange", "exchange")(Object.freeze({
        exchange_digest: digest(exchangeValue),
        recovery_session_id: recoverySessionId,
        session_digest: digest(sessionToken),
        issued_at: new Date(issuedAt).toISOString(),
        now: new Date(issuedAt).toISOString()
      }));
    } catch (error) { throw mapRepositoryError(error, CODE.EXCHANGE_INVALID); }
    const session = normalizeRecoverySession(result?.recovery_session ?? result);
    if (!result?.request_id && !session.request_id) fail(CODE.EXCHANGE_INVALID);
    return Object.freeze({ request_id: requiredUuid(result?.request_id ?? session.request_id), recovery_session: session, recovery_session_token: sessionToken });
  }

  async function registrationOptions(input = {}) {
    const session = await authenticate(input.session_token ?? input.recovery_session_token, input.organization_id, "session_issued", input.request_id);
    let result;
    try {
      result = await ceremonyMethod(ceremony, "beginRegistration", "registrationOptions")(Object.freeze({
        recovery_session: session,
        organization_id: session.organization_id,
        member_id: session.member_id,
        operation: OPERATION_REGISTER,
        ...(rpId === undefined ? {} : { rp_id: rpId }),
        ...(origin === undefined ? {} : { origin })
      }));
    } catch (error) { throw mapCeremonyError(error, CODE.REGISTRATION_INVALID); }
    if (!plainObject(result) || !isUuid(result.challenge_id)) fail(CODE.REGISTRATION_INVALID);
    return Object.freeze({ request_id: session.request_id, challenge_id: result.challenge_id.toLowerCase(), options: result.options ?? result });
  }

  async function registrationVerify(input = {}) {
    const session = await authenticate(input.session_token ?? input.recovery_session_token, input.organization_id, "session_issued", input.request_id);
    const challengeId = requiredUuid(input.challenge_id);
    if (!plainObject(input.credential)) fail(CODE.REGISTRATION_INVALID);
    const verified = input.verified_credential ?? {};
    let completed = false;
    let enrolledCredentialId;
    const complete = async (txOrInput, binding, verifiedCredential = verified) => {
      const completion = normalizeCompletionArguments(txOrInput, binding, verifiedCredential);
      completed = true;
      enrolledCredentialId = completion.verified_credential?.credential_id;
      try {
        return await repositoryMethod(repository, "enrollRecoveryCredentialInTransaction", "enrollCredentialInTransaction")(Object.freeze({
          ...completion,
          recovery_session: session,
          organization_id: session.organization_id,
          member_id: session.member_id,
          request_id: session.request_id,
          challenge_id: challengeId,
          verified_credential: stripSecretFields(completion.verified_credential),
          now: new Date(clockNow(now)).toISOString()
        }));
      } catch (error) { throw mapRepositoryError(error, CODE.REGISTRATION_INVALID); }
    };
    let result;
    try {
      result = await ceremonyMethod(ceremony, "verifyRegistration", "registrationVerify")(Object.freeze({
        recovery_session: session,
        organization_id: session.organization_id,
        member_id: session.member_id,
        request_id: session.request_id,
        operation: OPERATION_REGISTER,
        challenge_id: challengeId,
        credential: input.credential,
        complete
      }));
    } catch (error) { throw mapCeremonyError(error, CODE.REGISTRATION_INVALID); }
    if (!completed || !plainObject(result)) fail(CODE.REGISTRATION_INVALID);
    const progress = normalizeProgress(result.mutation ?? result, session, CODE.REGISTRATION_INVALID);
    let activation;
    try {
      activation = await ceremonyMethod(ceremony, "beginActivation", "activationOptions")(Object.freeze({
        recovery_session: progress.recovery_session ?? session,
        organization_id: session.organization_id,
        member_id: session.member_id,
        request_id: session.request_id,
        operation: OPERATION_ACTIVATE,
        credential_id: enrolledCredentialId,
        ...(rpId === undefined ? {} : { rp_id: rpId }),
        ...(origin === undefined ? {} : { origin })
      }));
    } catch (error) { throw mapCeremonyError(error, CODE.ACTIVATION_INVALID); }
    if (!plainObject(activation) || !isUuid(activation.challenge_id) || !plainObject(activation.options ?? activation)) fail(CODE.ACTIVATION_INVALID);
    return Object.freeze({ request_id: progress.request.request_id, recovery: progress.request, registered: true, activation: Object.freeze({ challenge_id: activation.challenge_id.toLowerCase(), options: activation.options ?? activation }) });
  }

  async function activate(input = {}) {
    const session = await authenticate(input.session_token ?? input.recovery_session_token, input.organization_id, "credential_enrolled", input.request_id);
    const challengeId = requiredUuid(input.challenge_id);
    if (!plainObject(input.assertion)) fail(CODE.ACTIVATION_INVALID);
    let authorization;
    let completed = false;
    const complete = async (txOrInput, binding, proof = undefined) => {
      const completion = normalizeCompletionArguments(txOrInput, binding, proof ?? {});
      completed = true;
      try {
        return await repositoryMethod(repository, "activateRecoveryInTransaction", "activateInTransaction")(Object.freeze({
          ...completion,
          recovery_session: session,
          organization_id: session.organization_id,
          member_id: session.member_id,
          request_id: session.request_id,
          challenge_id: challengeId,
          authorization: stripSecretFields(completion.verified_credential),
          now: new Date(clockNow(now)).toISOString()
        }));
      } catch (error) { throw mapRepositoryError(error, CODE.ACTIVATION_INVALID); }
    };
    try {
      authorization = await activationCeremonyMethod(ceremony)(Object.freeze({
        recovery_session: session,
        organization_id: session.organization_id,
        member_id: session.member_id,
        request_id: session.request_id,
        operation: OPERATION_ACTIVATE,
        challenge_id: challengeId,
        assertion: input.assertion,
        complete
      }));
    } catch (error) { throw mapCeremonyError(error, CODE.ACTIVATION_INVALID); }
    if (!plainObject(authorization) || !completed) fail(CODE.ACTIVATION_INVALID);
    normalizeActivationAuthorization(authorization.authorization ?? authorization, session, clockNow(now));
    const mutation = authorization.mutation ?? authorization.result;
    const progress = normalizeProgress(mutation ?? authorization, session, CODE.ACTIVATION_INVALID);
    return Object.freeze({ request_id: progress.request.request_id, recovery: progress.request, activated: true });
  }

  async function authenticate(token, organizationId, stage, requestId = undefined) {
    const sessionToken = requiredOpaque(token);
    const expectedOrganizationId = organizationId === undefined ? undefined : requiredUuid(organizationId);
    let result;
    try {
      result = await repositoryMethod(repository, "authenticateRecoverySession", "getRecoverySession")({
        session_digest: digest(sessionToken),
        organization_id: expectedOrganizationId,
        required_stage: stage,
        ...(requestId === undefined ? {} : { request_id: requiredUuid(requestId) }),
        now: new Date(clockNow(now)).toISOString()
      });
    } catch (error) { throw mapRepositoryError(error, CODE.SESSION_REQUIRED); }
    if (!result) fail(CODE.SESSION_REQUIRED);
    const session = normalizeRecoverySession(result);
    if (expectedOrganizationId !== undefined && session.organization_id !== expectedOrganizationId) fail(CODE.SESSION_REQUIRED);
    if (requestId !== undefined && session.request_id !== requiredUuid(requestId)) fail(CODE.SESSION_REQUIRED);
    if (session.stage !== stage) fail(CODE.SESSION_REQUIRED);
    return session;
  }

  return Object.freeze({
    create,
    createRequest: create,
    get,
    getRequest: get,
    approve,
    approveRequest: approve,
    cancel,
    cancelRequest: cancel,
    exchange,
    exchangeRecovery: exchange,
    registrationOptions,
    beginRegistration: registrationOptions,
    registrationVerify,
    verifyRegistration: registrationVerify,
    authenticateRecoverySession: async (input = {}) => authenticate(input.session_token ?? input.recovery_session_token, input.organization_id, input.required_stage ?? "session_issued", input.request_id),
    activate,
    activateRecovery: activate,
    operations: OWNER_RECOVERY_OPERATIONS
  });
}

function assertRepository(repository) {
  if (!repository || typeof repository !== "object") throw new TypeError("recovery repository is invalid");
  const aliases = [
    ["createRecoveryRequest", "createRequest"], ["getRecoveryRequest", "getRequest"],
    ["approveRecoveryRequest", "approve"], ["cancelRecoveryRequest", "cancel"],
    ["consumeRecoveryExchange", "exchange"], ["authenticateRecoverySession", "getRecoverySession"],
    ["enrollRecoveryCredentialInTransaction", "enrollCredentialInTransaction"], ["activateRecoveryInTransaction", "activateInTransaction"]
  ];
  for (const [primary, alias] of aliases) if (typeof repository[primary] !== "function" && typeof repository[alias] !== "function") throw new TypeError(`recovery repository must expose ${primary}()`);
}

function assertCeremony(ceremony) {
  if (!ceremony || typeof ceremony !== "object") throw new TypeError("recovery ceremony is invalid");
  const aliases = [["beginRegistration", "registrationOptions"], ["verifyRegistration", "registrationVerify"], ["beginActivation", "activationOptions"], ["verifyActivation", "activationVerify", "authorizeActivation"]];
  for (const [primary, alias, alternate] of aliases) if (typeof ceremony[primary] !== "function" && typeof ceremony[alias] !== "function" && typeof ceremony[alternate] !== "function") throw new TypeError(`recovery ceremony must expose ${primary}()`);
}

function repositoryMethod(repository, primary, alias) { return repository[primary] ?? repository[alias]; }
function ceremonyMethod(ceremony, primary, alias) { return ceremony[primary] ?? ceremony[alias]; }
function activationCeremonyMethod(ceremony) { return ceremony.verifyActivation ?? ceremony.activationVerify ?? ceremony.authorizeActivation; }
function requiredIdempotencyKey(value) { if (typeof value !== "string" || !/^[A-Za-z0-9._~-]{8,255}$/u.test(value)) fail(CODE.INVALID_REQUEST); return value; }

function normalizeActor(value) {
  if (!plainObject(value) || !isUuid(value.session_id) || !isUuid(value.member_id) || !isUuid(value.organization_id) || typeof value.role !== "string") fail(CODE.FORBIDDEN);
  return Object.freeze({ session_id: value.session_id.toLowerCase(), member_id: value.member_id.toLowerCase(), organization_id: value.organization_id.toLowerCase(), role: value.role });
}

function normalizeOwner(actor) { if (!OWNER_ROLES.has(actor.role)) fail(CODE.FORBIDDEN); return actor; }

function normalizeAuthorization(value, actor, organizationId, operation, now) {
  if (!plainObject(value) || value.verified !== true || value.consumed !== true || !isUuid(value.authorization_id ?? value.challenge_id) || (value.member_id && value.member_id !== actor.member_id) || (value.organization_id && value.organization_id !== organizationId) || value.operation !== operation || !Number.isSafeInteger(value.authenticated_at) || value.authenticated_at < 0 || value.authenticated_at > now + 30_000 || now - value.authenticated_at > 5 * 60_000) fail(CODE.APPROVAL_INVALID);
  return Object.freeze({ authorization_id: (value.authorization_id ?? value.challenge_id).toLowerCase(), authenticated_at: value.authenticated_at, member_id: actor.member_id, organization_id: organizationId, operation });
}

function normalizeActivationAuthorization(value, session, now) {
  if (!plainObject(value) || value.verified !== true || value.consumed !== true || !isUuid(value.authorization_id ?? value.challenge_id) || value.operation !== OPERATION_ACTIVATE || (value.member_id && value.member_id !== session.member_id) || (value.organization_id && value.organization_id !== session.organization_id) || !Number.isSafeInteger(value.authenticated_at) || value.authenticated_at < 0 || value.authenticated_at > now + 30_000 || now - value.authenticated_at > 5 * 60_000) fail(CODE.ACTIVATION_INVALID);
  return Object.freeze({ authorization_id: (value.authorization_id ?? value.challenge_id).toLowerCase(), authenticated_at: value.authenticated_at, member_id: session.member_id, organization_id: session.organization_id, operation: OPERATION_ACTIVATE });
}

function normalizeCompletionArguments(txOrInput, binding, verifiedCredential) {
  if (plainObject(txOrInput) && Object.hasOwn(txOrInput, "tx") && Object.hasOwn(txOrInput, "binding")) {
    return Object.freeze({ tx: txOrInput.tx, binding: txOrInput.binding, verified_credential: txOrInput.verified_credential ?? verifiedCredential });
  }
  if (txOrInput === undefined || binding === undefined) fail(CODE.UNAVAILABLE);
  return Object.freeze({ tx: txOrInput, binding, verified_credential: verifiedCredential });
}

function normalizeRequest(value, binding) {
  if (!plainObject(value)) fail(CODE.UNAVAILABLE);
  const request = {
    schema_version: value.schema_version ?? 1,
    kind: value.kind ?? "threshold-owner-recovery",
    request_id: requiredUuid(value.request_id ?? value.id),
    organization_id: requiredUuid(value.organization_id),
    subject_member_id: requiredUuid(value.subject_member_id),
    state: value.state,
    threshold: value.threshold,
    approved_owner_count: value.approved_owner_count,
    approved_at: nullableDate(value.approved_at),
    delay_until: nullableDate(value.delay_until),
    session_issued_at: nullableDate(value.session_issued_at),
    credential_enrolled_at: nullableDate(value.credential_enrolled_at),
    activated_at: nullableDate(value.activated_at),
    expires_at: requiredDate(value.expires_at),
    terminal_reason: value.terminal_reason ?? null,
    version: requiredVersion(value.version),
    created_at: requiredDate(value.created_at),
    ...(value.updated_at === undefined ? {} : { updated_at: requiredDate(value.updated_at) })
  };
  if (request.schema_version !== 1 || request.kind !== "threshold-owner-recovery" || !new Set(["pending", "approved", "delayed", "session_issued", "credential_enrolled", "activated", "cancelled", "expired", "failed"]).has(request.state) || !Number.isSafeInteger(request.threshold) || request.threshold < 2 || request.threshold > 32 || !Number.isSafeInteger(request.approved_owner_count) || request.approved_owner_count < 0 || request.approved_owner_count > 32 || (request.terminal_reason !== null && (typeof request.terminal_reason !== "string" || request.terminal_reason.length < 1 || request.terminal_reason.length > 128 || /[\u0000-\u001f\u007f]/u.test(request.terminal_reason)))) fail(CODE.UNAVAILABLE);
  if (request.organization_id !== binding.organizationId || request.request_id !== binding.requestId) fail(CODE.UNAVAILABLE);
  return Object.freeze(request);
}

function normalizeEnvelope(result, binding) {
  const request = normalizeRequest(result?.request ?? result?.recovery ?? result, binding);
  const output = { request_id: request.request_id, recovery: request };
  if (plainObject(result?.eligibility)) output.eligibility = normalizeEligibility(result.eligibility, request.threshold);
  const exchangeValue = result?.exchange_value;
  if (exchangeValue !== undefined) output.exchange_value = requiredOpaque(exchangeValue);
  if (result?.replayed !== undefined) { if (result.replayed !== true) fail(CODE.UNAVAILABLE); output.replayed = true; }
  return Object.freeze(output);
}

function normalizeEligibility(value, requestThreshold) {
  if (!Number.isSafeInteger(value.eligible_owner_count) || value.eligible_owner_count < 0 || !Number.isSafeInteger(value.threshold) || value.threshold < 2 || value.threshold !== requestThreshold || typeof value.recoverable !== "boolean") fail(CODE.UNAVAILABLE);
  return Object.freeze({ eligible_owner_count: value.eligible_owner_count, threshold: value.threshold, recoverable: value.recoverable });
}

function normalizeRecoverySession(value) {
  if (!plainObject(value)) fail(CODE.SESSION_REQUIRED);
  const session = {
    recovery_session_id: requiredUuid(value.recovery_session_id ?? value.session_id),
    request_id: requiredUuid(value.request_id),
    member_id: requiredUuid(value.member_id),
    organization_id: requiredUuid(value.organization_id),
    stage: value.stage,
    issued_at: requiredDate(value.issued_at),
    expires_at: requiredDate(value.expires_at),
    idle_expires_at: requiredDate(value.idle_expires_at),
    ...(value.credential_enrolled_at === undefined ? {} : { credential_enrolled_at: nullableDate(value.credential_enrolled_at) })
  };
  if (!new Set(["session_issued", "credential_enrolled", "activated"]).has(session.stage)) fail(CODE.SESSION_REQUIRED);
  return Object.freeze(session);
}

function normalizeProgress(result, session, failureCode) {
  if (!plainObject(result)) fail(failureCode === CODE.REGISTRATION_INVALID ? CODE.REGISTRATION_INVALID : CODE.ACTIVATION_INVALID);
  const requestValue = result.request ?? result.recovery_request ?? (result.request_id === undefined ? undefined : result);
  if (!requestValue) fail(failureCode);
  const request = normalizeRequest(requestValue, { organizationId: session.organization_id, requestId: session.request_id });
  const sessionValue = result.recovery_session ?? result.session ?? session;
  const recoverySession = normalizeRecoverySession(sessionValue);
  return Object.freeze({ request, recovery_session: recoverySession });
}

function stripSecretFields(value) {
  const forbidden = new Set(["assertion", "client_data_json", "authenticator_data", "signature", "attestation_object", "raw_id", "challenge", "token", "secret"]);
  return Object.freeze(Object.fromEntries(Object.entries(value).filter(([key]) => !forbidden.has(key))));
}

function mapRepositoryError(error, fallback = CODE.UNAVAILABLE) {
  if (error instanceof OwnerRecoveryError) return error;
  const code = String(error?.code ?? error?.reason ?? error?.name ?? "").toLowerCase();
  if (["not_found", "request_not_found", "recovery_not_found", "tenant_not_found"].includes(code)) return new OwnerRecoveryError(CODE.NOT_FOUND, { cause: error });
  if (["forbidden", "owner_required", "subject_self_approval", "non_owner", "wrong_member", "wrong_organization", "tenant_scope_error"].includes(code)) return new OwnerRecoveryError(CODE.FORBIDDEN, { cause: error });
  if (["stale_version", "version_conflict", "expected_version_mismatch"].includes(code)) return new OwnerRecoveryError(CODE.VERSION_CONFLICT, { cause: error });
  if (["idempotency_conflict", "idempotency_key_reused", "err_idempotency_conflict"].includes(code)) return new OwnerRecoveryError(CODE.IDEMPOTENCY_CONFLICT, { cause: error });
  if (["approval_replayed", "duplicate_approval", "approval_exists"].includes(code)) return new OwnerRecoveryError(CODE.APPROVAL_REPLAYED, { cause: error });
  if (["insufficient_owners", "threshold_unavailable", "owner_threshold_unavailable"].includes(code)) return new OwnerRecoveryError(CODE.THRESHOLD_UNAVAILABLE, { cause: error });
  if (["delay_not_elapsed", "recovery_delay_not_elapsed"].includes(code)) return new OwnerRecoveryError(CODE.DELAY_NOT_ELAPSED, { cause: error });
  if (["exchange_replayed", "exchange_consumed", "already_used"].includes(code)) return new OwnerRecoveryError(CODE.EXCHANGE_REPLAYED, { cause: error });
  if (["exchange_invalid", "exchange_not_found", "exchange_expired"].includes(code)) return new OwnerRecoveryError(CODE.EXCHANGE_INVALID, { cause: error });
  if (["session_not_found", "session_expired", "session_revoked", "wrong_stage"].includes(code)) return new OwnerRecoveryError(CODE.SESSION_REQUIRED, { cause: error });
  if (["session_replayed", "activation_replayed"].includes(code)) return new OwnerRecoveryError(CODE.SESSION_REPLAYED, { cause: error });
  if (["credential_exists", "credential_replayed"].includes(code)) return new OwnerRecoveryError(CODE.CREDENTIAL_EXISTS, { cause: error });
  return new OwnerRecoveryError(fallback, { cause: error });
}

function mapCeremonyError(error, fallback) {
  if (error instanceof OwnerRecoveryError) return error;
  const code = String(error?.code ?? error?.reason ?? error?.name ?? "").toLowerCase();
  if (["challenge_replayed", "challenge_expired", "challenge_not_found", "binding_mismatch", "verification_failed", "invalid_response"].some((item) => code.includes(item))) return new OwnerRecoveryError(fallback, { cause: error });
  return new OwnerRecoveryError(CODE.UNAVAILABLE, { cause: error });
}

function requiredOpaque(value) { if (typeof value !== "string" || !OPAQUE.test(value)) fail(CODE.INVALID_REQUEST); return value; }
function generateOpaque(randomBytes) { const value = randomBytes(32); if (!Buffer.isBuffer(value) || value.length !== 32) throw new OwnerRecoveryError(CODE.UNAVAILABLE); return value.toString("base64url"); }
function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function requiredUuid(value) { if (!isUuid(value)) fail(CODE.INVALID_REQUEST); return value.toLowerCase(); }
function isUuid(value) { return typeof value === "string" && UUID.test(value); }
function createUuid(uuid) { const value = uuid(); if (!isUuid(value)) throw new OwnerRecoveryError(CODE.UNAVAILABLE); return value.toLowerCase(); }
function requiredVersion(value) { if (!Number.isSafeInteger(value) || value < 1) fail(CODE.INVALID_REQUEST); return value; }
function requiredThreshold(value) { if (!Number.isSafeInteger(value) || value < 2 || value > 32) fail(CODE.INVALID_REQUEST); return value; }
function boundedDuration(value, field) { if (!Number.isSafeInteger(value) || value < 1_000 || value > MAX_DURATION_MS) throw new TypeError(`${field} is invalid`); return value; }
function clockNow(now) { const value = now(); if (!Number.isSafeInteger(value) || value < 0) throw new OwnerRecoveryError(CODE.UNAVAILABLE); return value; }
function isoAt(now, duration) { const value = now + duration; if (!Number.isSafeInteger(value)) throw new OwnerRecoveryError(CODE.UNAVAILABLE); return new Date(value).toISOString(); }
function requiredDate(value) { if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) fail(CODE.UNAVAILABLE); return value; }
function nullableDate(value) { if (value === null || value === undefined) return null; return requiredDate(value); }
function isRpId(value) { return typeof value === "string" && value.length > 0 && value.length <= 253 && /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(value) && !value.includes(".."); }
function isOrigin(value) { try { const parsed = new URL(value); return typeof value === "string" && parsed.origin === value && parsed.protocol === "https:" && parsed.pathname === "/" && !parsed.username && !parsed.password && !parsed.search && !parsed.hash; } catch { return false; } }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function fail(code) { throw new OwnerRecoveryError(code); }

// Keep alias resolution local so the published interface remains easy to audit.
void repositoryMethod;
void ceremonyMethod;
