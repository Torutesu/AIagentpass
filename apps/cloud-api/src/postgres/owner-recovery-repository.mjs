import crypto from "node:crypto";

import { createPostgresAdminAuditRepository } from "./admin-audit-repository.mjs";
import { createPostgresOwnerRecoveryIdempotencyRepository, sha256Digest } from "./owner-recovery-idempotency-repository.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/iu;
const HEX = /^[0-9a-f]+$/iu;
const TOKEN_BYTES = 32;
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const LIVE_REQUEST_STATES = new Set(["pending", "approved", "delayed", "session_issued", "credential_enrolled"]);
const TERMINAL_REQUEST_STATES = new Set(["cancelled", "expired", "failed", "activated"]);
const RECOVERY_SESSION_STAGES = new Set(["session_issued", "credential_enrolled", "activated", "revoked", "expired"]);
const OUTBOX_EVENTS = new Set([
  "recovery.request.created",
  "recovery.approval.recorded",
  "recovery.delay.started",
  "recovery.session.issued",
  "recovery.credential.enrolled",
  "recovery.activated",
  "recovery.cancelled",
  "recovery.expired",
  "recovery.failed"
]);
const CONTROL = /[\u0000-\u001f\u007f]/u;
const DEFAULTS = Object.freeze({
  requestTtlMs: 24 * 60 * 60 * 1000,
  delayMs: 24 * 60 * 60 * 1000,
  exchangeTtlMs: 15 * 60 * 1000,
  sessionTtlMs: 60 * 60 * 1000,
  idleTtlMs: 15 * 60 * 1000,
  authorizationWindowMs: 5 * 60 * 1000
});

export const OWNER_RECOVERY_REPOSITORY_METHODS = Object.freeze([
  "createRecoveryRequest",
  "getRecoveryRequest",
  "approveRecoveryRequest",
  "cancelRecoveryRequest",
  "consumeRecoveryExchange",
  "authenticateRecoverySession",
  "enrollRecoveryCredentialInTransaction",
  "activateRecoveryInTransaction",
  "getRecoveryRegistrationContext",
  "findRecoveryCredential",
  "updateRecoveryCredentialCounterInTransaction",
  "createRequest",
  "getRequest",
  "approveOwner",
  "cancelRequest",
  "issueExchange",
  "consumeExchange",
  "recordEnrollment",
  "activate",
  "expireRequest",
  "expireDue"
]);

export const OWNER_RECOVERY_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "invalid_input",
  TENANT_SCOPE: "tenant_scope",
  NOT_FOUND: "not_found",
  FORBIDDEN: "forbidden",
  CONFLICT: "conflict",
  STALE_VERSION: "stale_version",
  EXPIRED: "expired",
  NOT_READY: "not_ready",
  INELIGIBLE: "ineligible",
  AUTHORIZATION_REQUIRED: "authorization_required",
  IDEMPOTENCY_CONFLICT: "idempotency_conflict",
  EXCHANGE_REPLAYED: "exchange_replayed",
  AUDIT_UNAVAILABLE: "audit_unavailable",
  UNAVAILABLE: "unavailable"
});

const PUBLIC_MESSAGES = Object.freeze({
  invalid_input: "Owner recovery request is invalid",
  tenant_scope: "Owner recovery tenant scope is invalid",
  not_found: "Owner recovery request was not found",
  forbidden: "Owner recovery operation is forbidden",
  conflict: "Owner recovery operation conflicts with current state",
  stale_version: "Owner recovery request version is stale",
  expired: "Owner recovery request is expired",
  not_ready: "Owner recovery request is not ready",
  ineligible: "Owner recovery owner threshold is not satisfied",
  authorization_required: "Owner recovery authorization is unavailable",
  idempotency_conflict: "Owner recovery idempotency key conflicts with another request",
  exchange_replayed: "Owner recovery exchange is no longer valid",
  audit_unavailable: "Owner recovery audit durability is unavailable",
  unavailable: "Owner recovery storage is unavailable"
});

const REQUEST_COLUMNS = `organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,
  creator_session_id,state,threshold,approved_owner_count,approved_at,delay_until,session_issued_at,
  credential_enrolled_at,activated_at,expires_at,terminal_reason,version,created_at,updated_at`;

export class OwnerRecoveryRepositoryError extends Error {
  constructor(code, cause = undefined) {
    const publicCode = PUBLIC_MESSAGES[code] === undefined ? OWNER_RECOVERY_ERROR_CODES.UNAVAILABLE : code;
    super(PUBLIC_MESSAGES[publicCode]);
    // Provider diagnostics may contain SQL, connection strings, or caller
    // material. The public repository boundary intentionally discards them.
    void cause;
    this.name = "OwnerRecoveryRepositoryError";
    this.code = publicCode;
  }
}

/**
 * PostgreSQL authority for threshold owner recovery.  The returned object is
 * deliberately closed: all state-changing methods own their tenant checks,
 * lock order, CAS predicates, digest handling, and secret-free errors.
 *
 * The activation audit callback receives the already-checked transaction
 * client.  It must append a durable audit event and return its UUID.  The
 * default is the repository's existing append-only admin audit interface;
 * callers may inject a different implementation when the surrounding
 * transaction is owned by another repository.
 */
export function createPostgresOwnerRecoveryRepository({
  client,
  clock = () => new Date(),
  randomBytes = crypto.randomBytes,
  randomUUID = crypto.randomUUID,
  requestTtlMs = DEFAULTS.requestTtlMs,
  delayMs = DEFAULTS.delayMs,
  exchangeTtlMs = DEFAULTS.exchangeTtlMs,
  sessionTtlMs = DEFAULTS.sessionTtlMs,
  idleTtlMs = DEFAULTS.idleTtlMs,
  authorizationWindowMs = DEFAULTS.authorizationWindowMs,
  auditRepository = undefined,
  idempotencyRepository = undefined,
  appendActivationAudit = undefined,
  verifyActivationAuthorization = undefined
} = {}) {
  assertClient(client);
  if (typeof clock !== "function" || typeof randomBytes !== "function" || typeof randomUUID !== "function") throw new TypeError("owner recovery crypto and clock dependencies are invalid");
  if (verifyActivationAuthorization !== undefined && typeof verifyActivationAuthorization !== "function") throw new TypeError("verifyActivationAuthorization must be a function");
  const limits = Object.freeze({
    requestTtlMs: duration(requestTtlMs, "requestTtlMs"),
    delayMs: duration(delayMs, "delayMs"),
    exchangeTtlMs: duration(exchangeTtlMs, "exchangeTtlMs"),
    sessionTtlMs: duration(sessionTtlMs, "sessionTtlMs"),
    idleTtlMs: duration(idleTtlMs, "idleTtlMs"),
    authorizationWindowMs: duration(authorizationWindowMs, "authorizationWindowMs")
  });
  function nowDate() { return date(clock(), "clock"); }
  function nowIso() { return nowDate().toISOString(); }

  const audit = auditRepository ?? createPostgresAdminAuditRepository({ client, now: () => nowIso() });
  const idempotency = idempotencyRepository ?? createPostgresOwnerRecoveryIdempotencyRepository({ client, now: () => nowDate(), randomBytes });
  if (!idempotency || typeof idempotency.claimInTransaction !== "function" || typeof idempotency.completeInTransaction !== "function") throw new TypeError("owner recovery idempotency repository is invalid");
  const auditAppender = appendActivationAudit ?? (typeof audit?.appendAdminAuditEventInTransaction === "function"
    ? (input) => audit.appendAdminAuditEventInTransaction(input)
    : undefined);

  const repository = {
    createRequest,
    getRequest,
    approveOwner,
    cancelRequest,
    issueExchange,
    consumeExchange,
    recordEnrollment,
    activate,
    expireRequest,
    expireDue,
    createRecoveryRequest,
    getRecoveryRequest,
    approveRecoveryRequest,
    cancelRecoveryRequest,
    consumeRecoveryExchange,
    authenticateRecoverySession,
    getRecoverySession: authenticateRecoverySession,
    enrollRecoveryCredentialInTransaction,
    enrollCredentialInTransaction: enrollRecoveryCredentialInTransaction,
    activateRecoveryInTransaction,
    activateInTransaction: activateRecoveryInTransaction,
    getRecoveryRegistrationContext,
    findRecoveryCredential,
    updateRecoveryCredentialCounterInTransaction
  };
  return Object.freeze(repository);

  async function createRecoveryRequest(input = {}) {
    return createRequest({
      organization_id: input.organization_id,
      request_id: input.request_id,
      subject_member_id: input.subject_member_id,
      creator_member_id: input.creator_member_id ?? input.actor?.member_id,
      creator_session_id: input.creator_session_id ?? input.actor?.session_id,
      threshold: input.threshold,
      created_at: input.created_at,
      expires_at: input.expires_at,
      idempotency_key: input.idempotency_key
    });
  }

  async function getRecoveryRequest(input = {}) {
    return getRequest({ organization_id: input.organization_id, request_id: input.request_id });
  }

  async function approveRecoveryRequest(input = {}) {
    const authorization = input.recent_authorization ?? input.recent_auth;
    return approveOwner({
      organization_id: input.organization_id,
      request_id: input.request_id,
      owner_member_id: input.owner_member_id ?? input.actor?.member_id,
      owner_session_id: input.owner_session_id ?? input.actor?.session_id,
      authorization_id: authorization?.authorization_id,
      authorized_at: authorization?.authenticated_at,
      expected_version: input.expected_version,
      idempotency_key: input.idempotency_key
    });
  }

  async function cancelRecoveryRequest(input = {}) {
    return cancelRequest({
      organization_id: input.organization_id,
      request_id: input.request_id,
      actor_member_id: input.owner_member_id ?? input.actor?.member_id,
      actor_session_id: input.owner_session_id ?? input.actor?.session_id,
      expected_version: input.expected_version,
      reason: "cancelled_by_owner",
      idempotency_key: input.idempotency_key
    });
  }

  async function createRequest(input = {}) {
    const values = normalizeCreateInput(input);
    return mutate("create_request", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const replay = await claimIdempotency(tx, {
        organizationId: values.organizationId,
        operation: "human.recovery.create",
        principalId: values.creatorMemberId,
        idempotencyKey: values.idempotencyKey,
        identity: {
          organization_id: values.organizationId,
          subject_member_id: values.subjectMemberId,
          creator_member_id: values.creatorMemberId,
          creator_session_id: values.creatorSessionId,
          threshold: values.threshold
        }
      });
      if (replay.replayed) return replay.response;
      const membershipIds = uniqueSorted([values.subjectMemberId, values.creatorMemberId]);
      const memberships = await lockMemberships(tx, values.organizationId, membershipIds);
      const subject = membershipFor(memberships, values.subjectMemberId);
      const creator = membershipFor(memberships, values.creatorMemberId);
      if (!subject || !creator || subject.status !== "active" || creator.status !== "active" || values.subjectMemberId !== values.creatorMemberId) throw failure("forbidden");
      const eligibleOwners = await countEligibleOwners(tx, values.organizationId, values.subjectMemberId);
      if (eligibleOwners < values.threshold) throw failure("ineligible");
      const creatorSession = await lockHumanSession(tx, {
        organizationId: values.organizationId,
        sessionId: values.creatorSessionId,
        memberId: values.creatorMemberId,
        membershipId: creator.id,
        now: values.createdAt
      });
      if (!creatorSession || creatorSession.role !== creator.role) throw failure("forbidden");

      const inserted = await tx.query(`INSERT INTO owner_recovery_requests
        (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,
         state,threshold,approved_owner_count,expires_at,version,created_at,updated_at)
        VALUES ($1,$2,1,'threshold-owner-recovery',$3,$4,$5,'pending',$6,0,$7,1,$8,$8)
        RETURNING ${REQUEST_COLUMNS}`, [
        values.organizationId, values.requestId, values.subjectMemberId, values.creatorMemberId,
        values.creatorSessionId, values.threshold, values.expiresAt, values.createdAt
      ]);
      const request = oneRow(inserted, "request");
      await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: values.subjectMemberId,
        eventType: "recovery.request.created"
      });
      const response = Object.freeze({ request: publicRequest(request), replayed: false });
      await completeIdempotency(tx, replay, 201, response);
      return response;
    });
  }

  async function getRequest(input = {}) {
    const values = normalizeRequestLookup(input);
    try {
      const result = await client.query(`SELECT ${REQUEST_COLUMNS}
        FROM owner_recovery_requests WHERE organization_id=$1 AND request_id=$2`, [values.organizationId, values.requestId]);
      if (rowCount(result) !== 1) return null;
      const request = publicRequest(result.rows[0]);
      const approvals = await client.query(`SELECT owner_member_id,owner_membership_session_epoch,approved_at,invalidated_at,invalidation_reason
        FROM owner_recovery_approvals WHERE organization_id=$1 AND request_id=$2
        ORDER BY owner_member_id ASC,approval_id ASC`, [values.organizationId, values.requestId]);
      return Object.freeze({ request, approvals: Object.freeze((approvals.rows ?? []).map(publicApproval)) });
    } catch (error) {
      if (error instanceof OwnerRecoveryRepositoryError) throw error;
      throw failure("unavailable", error);
    }
  }

  async function approveOwner(input = {}) {
    const values = normalizeApproveInput(input);
    return mutate("approve_owner", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const replay = await claimIdempotency(tx, {
        organizationId: values.organizationId,
        operation: "human.recovery.approve",
        principalId: values.ownerMemberId,
        idempotencyKey: values.idempotencyKey,
        identity: {
          organization_id: values.organizationId,
          request_id: values.requestId,
          owner_member_id: values.ownerMemberId,
          owner_session_id: values.ownerSessionId,
          authorization_id: values.authorizationId,
          expected_version: values.expectedVersion
        }
      });
      if (replay.replayed) return replay.response;
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const membershipIds = uniqueSorted([request.subject_member_id, values.ownerMemberId, ...approvalIds]);
      const memberships = await lockMemberships(tx, values.organizationId, membershipIds);
      const session = await lockHumanSession(tx, {
        organizationId: values.organizationId,
        sessionId: values.ownerSessionId,
        memberId: values.ownerMemberId,
        membershipId: membershipFor(memberships, values.ownerMemberId)?.id,
        now: values.now
      });
      const approvals = await lockApprovals(tx, values.organizationId, values.requestId);
      const prior = approvals.find((approval) => approval.owner_member_id === values.ownerMemberId);
      if (prior && prior.invalidated_at === null && prior.authorization_id === values.authorizationId) {
        const response = Object.freeze({ request: publicRequest(request), approval: publicApproval(prior), replayed: true });
        await completeIdempotency(tx, replay, 200, response);
        return response;
      }
      if (prior) throw failure("conflict");
      if (!LIVE_REQUEST_STATES.has(request.state) || request.state !== "pending") throw failure(request.state === "expired" ? "expired" : "conflict");
      requireExpectedVersion(request, values.expectedVersion);
      if (request.expires_at <= values.now) throw failure("expired");

      const owner = membershipFor(memberships, values.ownerMemberId);
      if (!owner || owner.status !== "active" || owner.role !== "owner" || values.ownerMemberId === request.subject_member_id) throw failure("forbidden");
      if (!session || session.role !== "owner") throw failure("forbidden");
      const authorization = await lockApprovalAuthorization(tx, {
        organizationId: values.organizationId,
        authorizationId: values.authorizationId,
        memberId: values.ownerMemberId,
        sessionId: values.ownerSessionId,
        now: values.now
      });
      if (!authorization) throw failure("authorization_required");
      if (values.authorizedAt !== undefined && values.authorizedAt.getTime() !== authorization.consumed_at.getTime()) throw failure("authorization_required");
      if (authorization.consumed_at < new Date(values.now.getTime() - limits.authorizationWindowMs) || authorization.consumed_at > values.now) throw failure("authorization_required");
      if (approvals.some((approval) => approval.authorization_id === values.authorizationId)) throw failure("conflict");

      const approvalId = newUuid(randomUUID);
      const inserted = await tx.query(`INSERT INTO owner_recovery_approvals
        (organization_id,request_id,approval_id,owner_member_id,owner_session_id,authorization_id,
         authorization_operation,authorized_at,owner_membership_session_epoch,approved_at)
        VALUES ($1,$2,$3,$4,$5,$6,'human.recovery.approve',$7,$8,$7)
        RETURNING owner_member_id,owner_membership_session_epoch,approved_at,invalidated_at,invalidation_reason,approval_id,authorization_id`, [
        values.organizationId, values.requestId, approvalId, values.ownerMemberId, values.ownerSessionId,
        values.authorizationId, authorization.consumed_at, positiveInteger(owner.session_epoch)
      ]);
      const approval = oneRow(inserted, "approval");
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.now);
      const eligibleOwners = await countEligibleOwners(tx, values.organizationId, request.subject_member_id);
      if (eligibleOwners < request.threshold || validApprovals.length < request.threshold) throw failure("ineligible");

      let next = await updateRequestVersion(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        expectedVersion: request.version,
        state: "pending",
        approvedOwnerCount: validApprovals.length
      });
      let delayed = false;
      if (validApprovals.length >= request.threshold) {
        next = await transitionRequest(tx, {
          organizationId: values.organizationId,
          requestId: values.requestId,
          expectedVersion: next.version,
          fromState: "pending",
          toState: "approved",
          approvedAt: values.now,
          approvedOwnerCount: validApprovals.length
        });
        next = await transitionRequest(tx, {
          organizationId: values.organizationId,
          requestId: values.requestId,
          expectedVersion: next.version,
          fromState: "approved",
          toState: "delayed",
          delayUntil: new Date(values.now.getTime() + limits.delayMs),
          approvedAt: values.now,
          approvedOwnerCount: validApprovals.length
        });
        delayed = true;
      }
      await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: request.subject_member_id,
        eventType: "recovery.approval.recorded",
        eventKey: approvalId
      });
      if (delayed) await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: request.subject_member_id,
        eventType: "recovery.delay.started",
        eventKey: String(next.version)
      });
      const response = Object.freeze({ request: publicRequest(next), approval: publicApproval(approval), replayed: false });
      await completeIdempotency(tx, replay, 200, response);
      return response;
    });
  }

  async function cancelRequest(input = {}) {
    const values = normalizeCancelInput(input);
    return mutate("cancel_request", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const replay = await claimIdempotency(tx, {
        organizationId: values.organizationId,
        operation: "human.recovery.cancel",
        principalId: values.actorMemberId,
        idempotencyKey: values.idempotencyKey,
        identity: {
          organization_id: values.organizationId,
          request_id: values.requestId,
          actor_member_id: values.actorMemberId,
          actor_session_id: values.actorSessionId,
          expected_version: values.expectedVersion,
          reason: values.reason
        }
      });
      if (replay.replayed) return replay.response;
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      if (request.state === "cancelled") {
        const response = Object.freeze({ request: publicRequest(request), replayed: true });
        await completeIdempotency(tx, replay, 200, response);
        return response;
      }
      if (!LIVE_REQUEST_STATES.has(request.state)) throw failure(request.state === "expired" ? "expired" : "conflict");
      requireExpectedVersion(request, values.expectedVersion);
      if (request.expires_at <= values.now) throw failure("expired");
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([request.subject_member_id, values.actorMemberId, ...approvalIds]));
      const actor = membershipFor(memberships, values.actorMemberId);
      if (!actor || actor.status !== "active" || actor.role !== "owner") throw failure("forbidden");
      const actorSession = await lockHumanSession(tx, {
        organizationId: values.organizationId,
        sessionId: values.actorSessionId,
        memberId: values.actorMemberId,
        membershipId: actor.id,
        now: values.now
      });
      if (!actorSession || actorSession.role !== "owner") throw failure("forbidden");
      const next = await transitionRequest(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        expectedVersion: request.version,
        fromState: request.state,
        toState: "cancelled",
        terminalReason: values.reason
      });
      await revokeRecoverySessions(tx, values.organizationId, request.subject_member_id, values.now, "recovery_cancelled");
      await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: request.subject_member_id,
        eventType: "recovery.cancelled"
      });
      const response = Object.freeze({ request: publicRequest(next), replayed: false });
      await completeIdempotency(tx, replay, 200, response);
      return response;
    });
  }

  async function issueExchange(input = {}) {
    const values = normalizeVersionedRequestInput(input);
    return mutate("issue_exchange", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const existing = await findExchange(tx, values.organizationId, values.requestId);
      if (existing) {
        if (!existing.consumed_at) return Object.freeze({ request: publicRequest(request), exchange_id: existing.exchange_id, expires_at: timestamp(existing.expires_at), exchange_token: null, replayed: true });
        return Object.freeze({ request: publicRequest(request), exchange_id: existing.exchange_id, expires_at: timestamp(existing.expires_at), exchange_token: null, replayed: true });
      }
      requireExpectedVersion(request, values.expectedVersion);
      if (request.state !== "delayed") throw failure(request.state === "expired" ? "expired" : "not_ready");
      if (request.expires_at <= values.now) throw failure("expired");
      if (!request.delay_until || request.delay_until > values.now) throw failure("not_ready");
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([request.subject_member_id, ...approvalIds]));
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.now);
      if (validApprovals.length < request.threshold || await countEligibleOwners(tx, values.organizationId, request.subject_member_id) < request.threshold) throw failure("ineligible");

      const raw = randomToken(randomBytes);
      const exchangeId = newUuid(randomUUID);
      const expiresAt = new Date(Math.min(request.expires_at.getTime(), values.now.getTime() + limits.exchangeTtlMs));
      const inserted = await tx.query(`INSERT INTO owner_recovery_exchanges
        (organization_id,request_id,exchange_id,exchange_digest,issued_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6) RETURNING exchange_id,expires_at,consumed_at`, [
        values.organizationId, values.requestId, exchangeId, sha256(raw), values.now, expiresAt
      ]);
      if (rowCount(inserted) !== 1) throw failure("unavailable");
      return Object.freeze({ request: publicRequest(request), exchange_id: exchangeId, expires_at: timestamp(inserted.rows[0].expires_at), exchange_token: raw.toString("base64url"), replayed: false });
    });
  }

  async function consumeExchange(input = {}) {
    const values = normalizeConsumeExchangeInput(input);
    return mutate("consume_exchange", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const exchange = await findExchangeByDigest(tx, values.organizationId, values.requestId, sha256(values.exchangeToken));
      if (!exchange) throw failure("forbidden");
      const consumedSession = exchange.consumed_recovery_session_id
        ? await recoverySessionById(tx, values.organizationId, exchange.consumed_recovery_session_id)
        : null;
      if (exchange.consumed_at && consumedSession) return Object.freeze({ request: publicRequest(request), recovery_session_id: consumedSession.recovery_session_id, recovery_session_token: null, expires_at: timestamp(consumedSession.expires_at), idle_expires_at: timestamp(consumedSession.idle_expires_at), replayed: true });
      requireExpectedVersion(request, values.expectedVersion);
      if (request.state !== "delayed") throw failure(request.state === "expired" ? "expired" : "conflict");
      if (request.expires_at <= values.now || !request.delay_until || request.delay_until > values.now) throw failure(request.expires_at <= values.now ? "expired" : "not_ready");
      if (exchange.expires_at <= values.now) throw failure("expired");
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([request.subject_member_id, ...approvalIds]));
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.now);
      if (validApprovals.length < request.threshold || await countEligibleOwners(tx, values.organizationId, request.subject_member_id) < request.threshold) throw failure("ineligible");
      const activeSessions = await lockRecoverySessions(tx, values.organizationId, request.subject_member_id, values.requestId);
      if (activeSessions.some((session) => ["session_issued", "credential_enrolled"].includes(session.stage))) throw failure("conflict");

      const raw = randomToken(randomBytes);
      const sessionId = newUuid(randomUUID);
      const issuedAt = values.now;
      const expiresAt = new Date(Math.min(request.expires_at.getTime(), issuedAt.getTime() + limits.sessionTtlMs));
      const idleExpiresAt = new Date(Math.min(expiresAt.getTime(), issuedAt.getTime() + limits.idleTtlMs));
      if (idleExpiresAt <= issuedAt) throw failure("not_ready");
      const consumed = await tx.query(`UPDATE owner_recovery_exchanges
        SET consumed_at=$5,consumed_recovery_session_id=$4
        WHERE organization_id=$1 AND request_id=$2 AND exchange_id=$3 AND exchange_digest=$6
          AND consumed_at IS NULL AND expires_at>$5
        RETURNING exchange_id,consumed_at`, [values.organizationId, values.requestId, exchange.exchange_id, sessionId, issuedAt, sha256(values.exchangeToken)]);
      if (rowCount(consumed) !== 1) throw failure("conflict");
      const inserted = await tx.query(`INSERT INTO owner_recovery_sessions
        (organization_id,recovery_session_id,request_id,member_id,session_digest,stage,issued_at,expires_at,idle_expires_at,last_seen_at)
        VALUES ($1,$2,$3,$4,$5,'session_issued',$6,$7,$8,$6)
        RETURNING recovery_session_id,expires_at,idle_expires_at`, [
        values.organizationId, sessionId, values.requestId, request.subject_member_id, sha256(raw), issuedAt, expiresAt, idleExpiresAt
      ]);
      const next = await transitionRequest(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        expectedVersion: request.version,
        fromState: "delayed",
        toState: "session_issued",
        sessionIssuedAt: issuedAt,
        approvedOwnerCount: validApprovals.length
      });
      await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: request.subject_member_id,
        eventType: "recovery.session.issued"
      });
      return Object.freeze({ request: publicRequest(next), recovery_session_id: sessionId, recovery_session_token: raw.toString("base64url"), expires_at: timestamp(inserted.rows[0].expires_at), idle_expires_at: timestamp(inserted.rows[0].idle_expires_at), replayed: false });
    });
  }

  async function recordEnrollment(input = {}) {
    const values = normalizeEnrollmentInput(input);
    return mutate("record_enrollment", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([request.subject_member_id, ...approvalIds]));
      const session = await lockRecoverySessionByDigest(tx, values.organizationId, values.requestId, sha256(values.recoverySessionToken));
      if (!session) throw failure("forbidden");
      if (session.stage === "credential_enrolled" && Buffer.compare(session.credential_id, values.credentialId) === 0) return Object.freeze({ request: publicRequest(request), recovery_session_id: session.recovery_session_id, credential_id: session.credential_id.toString("base64url"), replayed: true });
      requireExpectedVersion(request, values.expectedVersion);
      if (request.state !== "session_issued" || session.stage !== "session_issued") throw failure(request.state === "expired" ? "expired" : "conflict");
      if (session.expires_at <= values.now || session.idle_expires_at <= values.now) throw failure("expired");
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.now);
      if (validApprovals.length < request.threshold) throw failure("ineligible");
      await lockCredentialSet(tx, request.subject_member_id);
      const credential = await tx.query(`SELECT id FROM webauthn_credentials
        WHERE id=$1 AND member_id=$2 AND revoked_at IS NULL FOR SHARE`, [values.credentialId, request.subject_member_id]);
      if (rowCount(credential) !== 1) throw failure("forbidden");
      const enrolled = await tx.query(`UPDATE owner_recovery_sessions
        SET stage='credential_enrolled',credential_id=$5,credential_enrolled_at=$6,last_seen_at=$6
        WHERE organization_id=$1 AND recovery_session_id=$2 AND request_id=$3 AND member_id=$4
          AND session_digest=$7 AND stage='session_issued' AND expires_at>$6 AND idle_expires_at>$6
        RETURNING recovery_session_id,credential_id,credential_enrolled_at`, [values.organizationId, session.recovery_session_id, values.requestId, request.subject_member_id, values.credentialId, values.enrolledAt, sha256(values.recoverySessionToken)]);
      if (rowCount(enrolled) !== 1) throw failure("conflict");
      const next = await transitionRequest(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        expectedVersion: request.version,
        fromState: "session_issued",
        toState: "credential_enrolled",
        credentialEnrolledAt: values.enrolledAt,
        approvedOwnerCount: validApprovals.length
      });
      await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: request.subject_member_id,
        eventType: "recovery.credential.enrolled"
      });
      return Object.freeze({ request: publicRequest(next), recovery_session_id: session.recovery_session_id, credential_id: values.credentialId.toString("base64url"), replayed: false });
    });
  }

  async function activate(input = {}) {
    const values = normalizeActivationInput(input);
    return mutate("activate", async (tx) => {
      if (typeof auditAppender !== "function") throw failure("audit_unavailable");
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([request.subject_member_id, ...approvalIds]));
      const currentSession = await lockRecoverySessionByDigest(tx, values.organizationId, values.requestId, sha256(values.recoverySessionToken));
      const humanSessions = await lockHumanSessionsForMember(tx, values.organizationId, request.subject_member_id);
      const recoverySessions = await lockRecoverySessions(tx, values.organizationId, request.subject_member_id, values.requestId);
      if (request.state === "activated" && currentSession?.stage === "activated" && currentSession.activation_authorization_id === values.authorizationId) return Object.freeze({ request: publicRequest(request), recovery_session_id: currentSession.recovery_session_id, replayed: true });
      requireExpectedVersion(request, values.expectedVersion);
      if (request.state !== "credential_enrolled" || !currentSession || currentSession.stage !== "credential_enrolled") throw failure(request.state === "expired" ? "expired" : "conflict");
      if (currentSession.expires_at <= values.now || currentSession.idle_expires_at <= values.now) throw failure("expired");
      const subject = membershipFor(memberships, request.subject_member_id);
      if (!subject || subject.status !== "active") throw failure("forbidden");
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.now);
      if (validApprovals.length < request.threshold) throw failure("ineligible");
      await lockCredentialSet(tx, request.subject_member_id);
      const credential = await tx.query(`SELECT id FROM webauthn_credentials
        WHERE id=$1 AND member_id=$2 AND revoked_at IS NULL FOR SHARE`, [currentSession.credential_id, request.subject_member_id]);
      if (rowCount(credential) !== 1) throw failure("forbidden");
      const authorization = await lockActivationAuthorization(tx, {
        organizationId: values.organizationId,
        memberId: request.subject_member_id,
        authorizationId: values.authorizationId,
        now: values.now,
        currentSessionId: request.creator_session_id
      });
      if (!authorization) throw failure("authorization_required");
      if (values.authorizedAt !== undefined && values.authorizedAt.getTime() !== authorization.consumed_at.getTime()) throw failure("authorization_required");
      if (verifyActivationAuthorization) {
        const verified = await verifyActivationAuthorization(Object.freeze({
          tx,
          organization_id: values.organizationId,
          request_id: values.requestId,
          member_id: request.subject_member_id,
          credential_id: currentSession.credential_id,
          authorization_id: values.authorizationId,
          authorized_at: authorization.consumed_at
        }));
        if (verified !== true && verified?.allowed !== true) throw failure("authorization_required");
      }

      await tx.query("SET LOCAL agentpass.recovery_epoch_bump = 'on'", []);
      const bumped = await tx.query(`UPDATE memberships
        SET session_epoch=session_epoch+1,updated_at=clock_timestamp()
        WHERE organization_id=$1 AND id=$2 AND member_id=$3 AND status='active'
        RETURNING session_epoch`, [values.organizationId, subject.id, request.subject_member_id]);
      if (rowCount(bumped) !== 1) throw failure("forbidden");
      await tx.query(`UPDATE human_sessions
        SET revoked_at=COALESCE(revoked_at,$3),revoke_reason=COALESCE(revoke_reason,'recovery_activated')
        WHERE organization_id=$1 AND member_id=$2 AND revoked_at IS NULL`, [values.organizationId, request.subject_member_id, values.now]);
      await tx.query(`UPDATE owner_recovery_sessions
        SET stage='revoked',revoked_at=$3,revoke_reason='recovery_activated'
        WHERE organization_id=$1 AND member_id=$2 AND recovery_session_id<>$4
          AND stage IN ('session_issued','credential_enrolled') AND revoked_at IS NULL`, [values.organizationId, request.subject_member_id, values.now, currentSession.recovery_session_id]);
      const activatedSession = await tx.query(`UPDATE owner_recovery_sessions
        SET stage='activated',activation_authorization_id=$5,activation_authorized_at=$6,activated_at=$6,last_seen_at=$6
        WHERE organization_id=$1 AND recovery_session_id=$2 AND request_id=$3 AND member_id=$4
          AND session_digest=$7 AND stage='credential_enrolled' AND activation_authorization_id IS NULL
        RETURNING recovery_session_id`, [values.organizationId, currentSession.recovery_session_id, values.requestId, request.subject_member_id, values.authorizationId, authorization.consumed_at, sha256(values.recoverySessionToken)]);
      if (rowCount(activatedSession) !== 1) throw failure("conflict");
      const next = await transitionRequest(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        expectedVersion: request.version,
        fromState: "credential_enrolled",
        toState: "activated",
        activatedAt: values.activatedAt,
        approvedOwnerCount: validApprovals.length
      });
      const auditEvent = await auditAppender({
        tx,
        organization_id: values.organizationId,
        actor_id: request.subject_member_id,
        audit_event_id: deterministicUuid(values.organizationId, values.requestId, "audit:activated"),
        idempotency_key: `owner-recovery-${values.requestId}-activated`,
        event_type: "human.recovery.activated",
        target_type: "owner_recovery_request",
        target_id: values.requestId,
        details: {
          request_id: values.requestId,
          subject_member_id: request.subject_member_id,
          membership_epoch: positiveInteger(bumped.rows[0].session_epoch),
          state: "activated"
        }
      });
      const auditEventId = newUuid(auditEvent?.audit_event_id);
      await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: request.subject_member_id,
        eventType: "recovery.activated",
        eventKey: auditEventId
      });
      return Object.freeze({ request: publicRequest(next), recovery_session_id: currentSession.recovery_session_id, replayed: false });
    });
  }

  async function expireRequest(input = {}) {
    const values = normalizeRequestLookup({ ...input, expected_version: input.expected_version ?? input.expectedVersion });
    return mutate("expire_request", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      if (!LIVE_REQUEST_STATES.has(request.state)) return Object.freeze({ request: publicRequest(request), expired: false, replayed: true });
      if (request.expires_at > values.now) return Object.freeze({ request: publicRequest(request), expired: false, replayed: false });
      if (values.expectedVersion !== undefined) requireExpectedVersion(request, values.expectedVersion);
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      await lockMemberships(tx, values.organizationId, uniqueSorted([request.subject_member_id, ...approvalIds]));
      await lockRecoverySessions(tx, values.organizationId, request.subject_member_id, values.requestId);
      const next = await transitionRequest(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        expectedVersion: request.version,
        fromState: request.state,
        toState: "expired",
        terminalReason: "recovery_request_expired"
      });
      await tx.query(`UPDATE owner_recovery_sessions
        SET stage='expired',revoked_at=$3,revoke_reason='recovery_request_expired'
        WHERE organization_id=$1 AND request_id=$2 AND stage IN ('session_issued','credential_enrolled')`, [values.organizationId, values.requestId, values.now]);
      await insertOutbox(tx, { organizationId: values.organizationId, requestId: values.requestId, subjectMemberId: request.subject_member_id, eventType: "recovery.expired" });
      return Object.freeze({ request: publicRequest(next), expired: true, replayed: false });
    });
  }

  async function expireDue(input = {}) {
    const values = normalizeExpireDueInput(input);
    return mutate("expire_due", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const due = await tx.query(`SELECT ${REQUEST_COLUMNS}
        FROM owner_recovery_requests
        WHERE organization_id=$1 AND state IN ('pending','approved','delayed','session_issued','credential_enrolled')
          AND expires_at<=$2
        ORDER BY expires_at ASC,request_id ASC LIMIT $3 FOR UPDATE`, [values.organizationId, values.now, values.limit]);
      const expired = [];
      for (const row of due.rows ?? []) {
        const approvalIds = await approvalOwnerIds(tx, values.organizationId, row.request_id);
        await lockMemberships(tx, values.organizationId, uniqueSorted([row.subject_member_id, ...approvalIds]));
        await lockRecoverySessions(tx, values.organizationId, row.subject_member_id, row.request_id);
        const next = await transitionRequest(tx, { organizationId: values.organizationId, requestId: row.request_id, expectedVersion: positiveInteger(row.version), fromState: row.state, toState: "expired", terminalReason: "recovery_request_expired" });
        await tx.query(`UPDATE owner_recovery_sessions SET stage='expired',revoked_at=$3,revoke_reason='recovery_request_expired'
          WHERE organization_id=$1 AND request_id=$2 AND stage IN ('session_issued','credential_enrolled')`, [values.organizationId, row.request_id, values.now]);
        await insertOutbox(tx, { organizationId: values.organizationId, requestId: row.request_id, subjectMemberId: row.subject_member_id, eventType: "recovery.expired" });
        expired.push(publicRequest(next));
      }
      return Object.freeze({ expired: Object.freeze(expired) });
    });
  }

  /**
   * Transaction composition point used by the 0026 WebAuthn coordinator.
   * The coordinator owns BEGIN/COMMIT and calls this before it marks its
   * registration challenge consumed.  This method therefore never starts a
   * transaction and never accepts assertion/attestation material; it accepts
   * only the verifier's public credential metadata.
   */
  async function enrollRecoveryCredentialInTransaction(input = {}) {
    const values = normalizeTransactionalEnrollmentInput(input);
    const tx = values.tx;
    try {
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([values.memberId, ...approvalIds]));
      await lockHumanSessionsForMember(tx, values.organizationId, values.memberId);
      const recoverySessions = await lockRecoverySessions(tx, values.organizationId, values.memberId, values.requestId);
      const session = recoverySessions.find((row) => row.recovery_session_id === values.recoverySessionId) ?? null;
      const challenge = await lockRecoveryWebAuthnChallenge(tx, {
        organizationId: values.organizationId,
        challengeId: values.challengeId,
        recoverySessionId: values.recoverySessionId,
        requestId: values.requestId,
        memberId: values.memberId,
        ceremony: "registration",
        operation: "human.recovery.credential.register"
      });
      if (!session || session.request_id !== values.requestId || session.member_id !== values.memberId || session.stage !== "session_issued" || !challenge || challenge.status !== "consuming") throw failure("authorization_required");
      if (session.expires_at <= values.completedAt || session.idle_expires_at <= values.completedAt) throw failure("expired");
      if (request.state !== "session_issued" || request.subject_member_id !== values.memberId) throw failure("conflict");
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.completedAt);
      if (validApprovals.length < request.threshold) throw failure("ineligible");
      await lockCredentialSet(tx, values.memberId);
      const inserted = await tx.query(`INSERT INTO webauthn_credentials
        (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (id) DO NOTHING
        RETURNING id`, [
        values.credentialId, values.memberId, values.publicKey, values.signCount, values.transports,
        values.label, values.backupEligible, values.backupState
      ]);
      if (rowCount(inserted) !== 1) throw failure("conflict");
      const enrolled = await tx.query(`UPDATE owner_recovery_sessions
        SET stage='credential_enrolled',credential_id=$5,credential_enrolled_at=$6,last_seen_at=$6
        WHERE organization_id=$1 AND recovery_session_id=$2 AND request_id=$3 AND member_id=$4
          AND stage='session_issued' AND expires_at>$6 AND idle_expires_at>$6
        RETURNING recovery_session_id,credential_id,credential_enrolled_at,issued_at,expires_at,idle_expires_at`, [
        values.organizationId, values.recoverySessionId, values.requestId, values.memberId, values.credentialId, values.completedAt
      ]);
      if (rowCount(enrolled) !== 1) throw failure("conflict");
      const next = await transitionRequest(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        expectedVersion: request.version,
        fromState: "session_issued",
        toState: "credential_enrolled",
        credentialEnrolledAt: values.completedAt,
        approvedOwnerCount: validApprovals.length
      });
      await insertOutbox(tx, {
        organizationId: values.organizationId,
        requestId: values.requestId,
        subjectMemberId: values.memberId,
        eventType: "recovery.credential.enrolled"
      });
      return Object.freeze({ committed: true, mutation: Object.freeze({ request: publicRequest(next), recovery_session: publicRecoverySession(enrolled.rows[0]) }) });
    } catch (error) {
      if (error instanceof OwnerRecoveryRepositoryError) throw error;
      throw failure("unavailable", error);
    }
  }

  /**
   * Transaction composition point used by the 0026 authentication
   * coordinator. The coordinator's callback is invoked while its challenge
   * row is `consuming`; the coordinator then atomically marks it consumed,
   * stores the verified credential id, and records authorization_consumed_at.
   * This method binds the mutation to that exact credential and never updates
   * the ceremony row itself. The coordinator performs that final challenge
   * transition after this mutation returns.
   */
  async function activateRecoveryInTransaction(input = {}) {
    const values = normalizeTransactionalActivationInput(input);
    const tx = values.tx;
    try {
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([values.memberId, ...approvalIds]));
      const session = await lockRecoverySessionById(tx, values.organizationId, values.recoverySessionId);
      const challenge = await lockRecoveryWebAuthnChallenge(tx, {
        organizationId: values.organizationId,
        challengeId: values.authorizationId,
        recoverySessionId: values.recoverySessionId,
        requestId: values.requestId,
        memberId: values.memberId,
        ceremony: "authentication",
        operation: "human.recovery.activate"
      });
      if (!session || session.request_id !== values.requestId || session.member_id !== values.memberId || session.stage !== "credential_enrolled" || !session.credential_id) throw failure("forbidden");
      if (!challenge || challenge.status !== "consuming" || !challenge.consume_started_at || challenge.consumed_at !== null) throw failure("authorization_required");
      if (challenge.verified_credential_id && !constantBufferEqual(challenge.verified_credential_id, values.credentialId)) throw failure("authorization_required");
      if (!constantBufferEqual(session.credential_id, values.credentialId)) throw failure("authorization_required");
      if (request.state !== "credential_enrolled" || request.subject_member_id !== values.memberId) throw failure("conflict");
      if (session.expires_at <= values.completedAt || session.idle_expires_at <= values.completedAt) throw failure("expired");
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.completedAt);
      if (validApprovals.length < request.threshold) throw failure("ineligible");
      await lockCredentialSet(tx, values.memberId);
      const credential = await tx.query(`SELECT id FROM webauthn_credentials
        WHERE id=$1 AND member_id=$2 AND revoked_at IS NULL FOR SHARE`, [values.credentialId, values.memberId]);
      if (rowCount(credential) !== 1) throw failure("forbidden");
      const counter = await updateRecoveryCredentialCounterInTransaction({
        tx,
        member_id: values.memberId,
        credential_id: values.credentialId,
        expected_sign_count: values.expectedSignCount,
        sign_count: values.signCount,
        backup_eligible: values.backupEligible,
        backup_state: values.backupState,
        expected_backup_eligible: values.expectedBackupEligible,
        expected_backup_state: values.expectedBackupState,
        updated_at: values.completedAt
      });
      return await activateRecoveryStateInTransaction(tx, {
        request,
        session,
        organizationId: values.organizationId,
        memberId: values.memberId,
        recoverySessionId: values.recoverySessionId,
        authorizationId: values.authorizationId,
        completedAt: values.completedAt,
        validApprovals,
        counter
      });
    } catch (error) {
      if (error instanceof OwnerRecoveryRepositoryError) throw error;
      throw failure("unavailable", error);
    }
  }

  async function getRecoveryRegistrationContext(input = {}) {
    const values = normalizeRecoveryContextInput(input);
    try {
      const result = await client.query(`SELECT s.organization_id,s.recovery_session_id,s.request_id,s.member_id,s.stage,s.issued_at,
          s.expires_at,s.idle_expires_at,s.last_seen_at,s.credential_id,r.state,r.version,r.expires_at AS request_expires_at
        FROM owner_recovery_sessions s JOIN owner_recovery_requests r
          ON r.organization_id=s.organization_id AND r.request_id=s.request_id
        WHERE s.organization_id=$1 AND s.recovery_session_id=$2 AND s.request_id=$3 AND s.member_id=$4
          AND s.session_digest=$5 AND s.stage IN ('session_issued','credential_enrolled')
          AND r.state IN ('session_issued','credential_enrolled') AND s.expires_at>$6 AND s.idle_expires_at>$6`, [
        values.organizationId, values.recoverySessionId, values.requestId, values.memberId, values.sessionDigest, values.now
      ]);
      if (rowCount(result) !== 1) return null;
      const row = result.rows[0];
      return Object.freeze({ organization_id: row.organization_id, recovery_session_id: row.recovery_session_id, request_id: row.request_id, member_id: row.member_id, stage: row.stage, issued_at: timestamp(row.issued_at), expires_at: timestamp(row.expires_at), idle_expires_at: timestamp(row.idle_expires_at), credential_id: row.credential_id ? credentialBytes(row.credential_id).toString("base64url") : null, request_state: row.state, request_version: positiveInteger(row.version), request_expires_at: timestamp(row.request_expires_at) });
    } catch (error) {
      if (error instanceof OwnerRecoveryRepositoryError) throw error;
      throw failure("unavailable", error);
    }
  }

  async function authenticateRecoverySession(input = {}) {
    const values = normalizeAuthenticatedSessionInput(input);
    const requestClause = values.requestId === undefined ? "" : " AND s.request_id=$3";
    const params = values.requestId === undefined
      ? [values.organizationId, values.sessionDigest, values.now]
      : [values.organizationId, values.sessionDigest, values.requestId, values.now];
    const nowParameter = values.requestId === undefined ? "$3" : "$4";
    const result = await client.query(`SELECT s.organization_id,s.recovery_session_id,s.request_id,s.member_id,s.stage,s.issued_at,s.expires_at,s.idle_expires_at,s.credential_enrolled_at
      FROM owner_recovery_sessions s JOIN owner_recovery_requests r ON r.organization_id=s.organization_id AND r.request_id=s.request_id
      WHERE s.organization_id=$1 AND s.session_digest=$2${requestClause}
        AND s.stage IN ('session_issued','credential_enrolled') AND r.state IN ('session_issued','credential_enrolled')
        AND s.expires_at>${nowParameter} AND s.idle_expires_at>${nowParameter}`, params);
    if (rowCount(result) !== 1) return null;
    const row = result.rows[0];
    if (values.requiredStage !== undefined && row.stage !== values.requiredStage) return null;
    return Object.freeze({ recovery_session_id: row.recovery_session_id, session_id: row.recovery_session_id, request_id: row.request_id, member_id: row.member_id, organization_id: row.organization_id, stage: row.stage, issued_at: timestamp(row.issued_at), expires_at: timestamp(row.expires_at), idle_expires_at: timestamp(row.idle_expires_at), credential_enrolled_at: row.credential_enrolled_at === null || row.credential_enrolled_at === undefined ? null : timestamp(row.credential_enrolled_at) });
  }

  async function findRecoveryCredential(input = {}) {
    const values = normalizeCredentialLookupInput(input);
    const queryClient = values.tx ?? client;
    let credentialId = values.credentialId;
    if (!credentialId) {
      if (!values.sessionDigest) throw failure("invalid_input");
      const session = await queryClient.query(`SELECT credential_id FROM owner_recovery_sessions
        WHERE organization_id=$1 AND recovery_session_id=$2 AND request_id=$3 AND member_id=$4
          AND session_digest=$5 AND stage='credential_enrolled' AND credential_id IS NOT NULL
          AND expires_at>$6 AND idle_expires_at>$6`, [values.organizationId, values.recoverySessionId, values.requestId, values.memberId, values.sessionDigest, values.now]);
      if (rowCount(session) !== 1) return null;
      credentialId = credentialBytes(session.rows[0].credential_id);
    } else if (values.recoverySessionId) {
      const binding = await queryClient.query(`SELECT 1 FROM owner_recovery_sessions
        WHERE organization_id=$1 AND recovery_session_id=$2 AND request_id=$3 AND member_id=$4
          AND credential_id=$5 AND stage IN ('credential_enrolled','activated')`, [values.organizationId, values.recoverySessionId, values.requestId, values.memberId, credentialId]);
      if (rowCount(binding) !== 1) return null;
    }
    const result = await queryClient.query(`SELECT c.id,c.member_id,c.public_key,c.sign_count,c.transports,c.label,c.backup_eligible,c.backup_state,c.created_at,c.last_used_at,c.revoked_at
      FROM webauthn_credentials c WHERE c.id=$1 AND c.member_id=$2 AND c.revoked_at IS NULL`, [credentialId, values.memberId]);
    return result.rows?.[0] ? publicCredential(result.rows[0]) : null;
  }

  async function updateRecoveryCredentialCounterInTransaction(input = {}) {
    const values = normalizeCredentialCounterInput(input);
    const assignments = values.hasBackupMetadata
      ? "sign_count=$4,backup_eligible=$6,backup_state=$7,last_used_at=$5"
      : "sign_count=$4,last_used_at=$5";
    const predicates = values.hasBackupMetadata
      ? " AND backup_eligible=$8 AND backup_state=$9"
      : "";
    const params = [values.credentialId, values.memberId, values.expectedSignCount, values.signCount, values.updatedAt];
    if (values.hasBackupMetadata) params.push(values.backupEligible, values.backupState, values.expectedBackupEligible, values.expectedBackupState);
    const result = await values.tx.query(`UPDATE webauthn_credentials
      SET ${assignments}
      WHERE id=$1 AND member_id=$2 AND sign_count=$3${predicates} AND revoked_at IS NULL
      RETURNING id,sign_count,last_used_at`, params);
    if (rowCount(result) !== 1) throw failure("conflict");
    return Object.freeze({ committed: true, updated: true, credential_id: values.credentialId.toString("base64url"), sign_count: counterValue(result.rows[0].sign_count), last_used_at: timestamp(result.rows[0].last_used_at) });
  }

  async function consumeRecoveryExchange(input = {}) {
    const supplied = normalizeDigestExchangeInput(input);
    let scope;
    try {
      const found = await client.query(`SELECT organization_id,request_id FROM owner_recovery_exchanges
        WHERE exchange_digest=$1`, [supplied.exchangeDigest]);
      if (rowCount(found) !== 1) throw failure("forbidden");
      scope = { organizationId: uuid(found.rows[0].organization_id, "organization_id"), requestId: uuid(found.rows[0].request_id, "request_id") };
    } catch (error) {
      if (error instanceof OwnerRecoveryRepositoryError) throw error;
      throw failure("unavailable", error);
    }
    const values = Object.freeze({ ...supplied, ...scope });
    return mutate("consume_recovery_exchange", async (tx) => {
      await lockOrganization(tx, values.organizationId);
      const request = await lockRequest(tx, values.organizationId, values.requestId);
      const exchange = await findExchangeByDigest(tx, values.organizationId, values.requestId, values.exchangeDigest);
      if (!exchange) throw failure("forbidden");
      if (exchange.consumed_recovery_session_id) throw failure("exchange_replayed");
      if (request.state !== "delayed" || request.expires_at <= values.now || !request.delay_until || request.delay_until > values.now || exchange.expires_at <= values.now) throw failure("conflict");
      const approvalIds = await approvalOwnerIds(tx, values.organizationId, values.requestId);
      const memberships = await lockMemberships(tx, values.organizationId, uniqueSorted([request.subject_member_id, ...approvalIds]));
      const validApprovals = await revalidateApprovals(tx, request, memberships, values.now);
      if (validApprovals.length < request.threshold) throw failure("ineligible");
      const sessionId = values.sessionId;
      const expiresAt = new Date(Math.min(request.expires_at.getTime(), values.now.getTime() + limits.sessionTtlMs));
      const idleExpiresAt = new Date(Math.min(expiresAt.getTime(), values.now.getTime() + limits.idleTtlMs));
      const consumed = await tx.query(`UPDATE owner_recovery_exchanges
        SET consumed_at=$5,consumed_recovery_session_id=$4
        WHERE organization_id=$1 AND request_id=$2 AND exchange_id=$3 AND exchange_digest=$6
          AND consumed_at IS NULL AND expires_at>$5 RETURNING exchange_id`, [values.organizationId, values.requestId, exchange.exchange_id, sessionId, values.now, values.exchangeDigest]);
      if (rowCount(consumed) !== 1) throw failure("conflict");
      const inserted = await tx.query(`INSERT INTO owner_recovery_sessions
        (organization_id,recovery_session_id,request_id,member_id,session_digest,stage,issued_at,expires_at,idle_expires_at,last_seen_at)
        VALUES ($1,$2,$3,$4,$5,'session_issued',$6,$7,$8,$6)
        RETURNING recovery_session_id,request_id,member_id,stage,issued_at,expires_at,idle_expires_at,last_seen_at,credential_id,credential_enrolled_at,activation_authorization_id,activation_authorized_at,activated_at,revoked_at,revoke_reason`, [values.organizationId, sessionId, values.requestId, request.subject_member_id, values.sessionDigest, values.now, expiresAt, idleExpiresAt]);
      const next = await transitionRequest(tx, { organizationId: values.organizationId, requestId: values.requestId, expectedVersion: request.version, fromState: "delayed", toState: "session_issued", sessionIssuedAt: values.now, approvedOwnerCount: validApprovals.length });
      await insertOutbox(tx, { organizationId: values.organizationId, requestId: values.requestId, subjectMemberId: request.subject_member_id, eventType: "recovery.session.issued" });
      return Object.freeze({ request_id: request.request_id, replayed: false, recovery_session: publicRecoverySession({ ...inserted.rows[0], organization_id: values.organizationId, session_digest: Buffer.alloc(32) }), mutation: Object.freeze({ request: publicRequest(next) }) });
    });
  }

  async function activateRecoveryStateInTransaction(tx, { request, session, organizationId, memberId, recoverySessionId, authorizationId, completedAt, validApprovals, counter }) {
    if (typeof auditAppender !== "function") throw failure("audit_unavailable");
    await tx.query("SET LOCAL agentpass.recovery_epoch_bump = 'on'", []);
    const bumped = await tx.query(`UPDATE memberships SET session_epoch=session_epoch+1,updated_at=clock_timestamp()
      WHERE organization_id=$1 AND id=(SELECT id FROM memberships WHERE organization_id=$1 AND member_id=$2) AND member_id=$2 AND status='active'
      RETURNING session_epoch`, [organizationId, memberId]);
    if (rowCount(bumped) !== 1) throw failure("forbidden");
    await tx.query(`UPDATE human_sessions SET revoked_at=COALESCE(revoked_at,$3),revoke_reason=COALESCE(revoke_reason,'recovery_activated')
      WHERE organization_id=$1 AND member_id=$2 AND revoked_at IS NULL`, [organizationId, memberId, completedAt]);
    await tx.query(`UPDATE owner_recovery_sessions SET stage='revoked',revoked_at=$3,revoke_reason='recovery_activated'
      WHERE organization_id=$1 AND member_id=$2 AND recovery_session_id<>$4 AND stage IN ('session_issued','credential_enrolled') AND revoked_at IS NULL`, [organizationId, memberId, completedAt, recoverySessionId]);
    const activated = await tx.query(`UPDATE owner_recovery_sessions
      SET stage='activated',activation_authorization_id=$5,activation_authorized_at=$6,activated_at=$6,last_seen_at=$6
      WHERE organization_id=$1 AND recovery_session_id=$2 AND request_id=$3 AND member_id=$4
        AND stage='credential_enrolled' AND activation_authorization_id IS NULL RETURNING recovery_session_id`, [organizationId, recoverySessionId, request.request_id, memberId, authorizationId, completedAt]);
    if (rowCount(activated) !== 1) throw failure("conflict");
    const next = await transitionRequest(tx, { organizationId, requestId: request.request_id, expectedVersion: request.version, fromState: "credential_enrolled", toState: "activated", activatedAt: completedAt, approvedOwnerCount: validApprovals.length });
    const auditEvent = await auditAppender({
      tx,
      organization_id: organizationId,
      actor_id: memberId,
      audit_event_id: deterministicUuid(organizationId, request.request_id, "audit:activated"),
      idempotency_key: `owner-recovery-${request.request_id}-activated`,
      event_type: "human.recovery.activated",
      target_type: "owner_recovery_request",
      target_id: request.request_id,
      details: { request_id: request.request_id, subject_member_id: memberId, membership_epoch: positiveInteger(bumped.rows[0].session_epoch), state: "activated" }
    });
    const auditEventId = uuid(auditEvent?.audit_event_id, "audit_event_id");
    await insertOutbox(tx, { organizationId, requestId: request.request_id, subjectMemberId: memberId, eventType: "recovery.activated", eventKey: auditEventId });
    return Object.freeze({ committed: true, mutation: Object.freeze({ request: publicRequest(next), recovery_session: publicRecoverySession({ ...session, stage: "activated", activated_at: completedAt, activation_authorization_id: authorizationId }), credential: Object.freeze({ sign_count: counter.sign_count }) }) });
  }

  function normalizeCreateInput(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "request_id", "requestId", "subject_member_id", "subjectMemberId", "creator_member_id", "creatorMemberId", "creator_session_id", "creatorSessionId", "threshold", "expires_at", "expiresAt", "created_at", "createdAt", "idempotency_key", "idempotencyKey"]);
    const organizationId = uuid(input.organization_id ?? input.organizationId, "organization_id");
    const requestId = optionalUuid(input.request_id ?? input.requestId, "request_id") ?? newUuid(randomUUID);
    const subjectMemberId = uuid(input.subject_member_id ?? input.subjectMemberId, "subject_member_id");
    const creatorMemberId = uuid(input.creator_member_id ?? input.creatorMemberId ?? subjectMemberId, "creator_member_id");
    const creatorSessionId = uuid(input.creator_session_id ?? input.creatorSessionId, "creator_session_id");
    const threshold = boundedInteger(input.threshold ?? 2, 2, 32);
    const createdAt = input.created_at === undefined && input.createdAt === undefined ? nowDate() : date(input.created_at ?? input.createdAt, "created_at");
    const expiresAt = input.expires_at === undefined && input.expiresAt === undefined ? new Date(createdAt.getTime() + limits.requestTtlMs) : date(input.expires_at ?? input.expiresAt, "expires_at");
    if (expiresAt <= createdAt) throw failure("invalid_input");
    return Object.freeze({ organizationId, requestId, subjectMemberId, creatorMemberId, creatorSessionId, threshold, createdAt, expiresAt, idempotencyKey: requiredIdempotencyKey(input.idempotency_key ?? input.idempotencyKey) });
  }

  function normalizeRequestLookup(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "request_id", "requestId", "expected_version", "expectedVersion"]);
    return Object.freeze({
      organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
      requestId: uuid(input.request_id ?? input.requestId, "request_id"),
      expectedVersion: input.expected_version === undefined && input.expectedVersion === undefined ? undefined : positiveInteger(input.expected_version ?? input.expectedVersion)
    });
  }

  function normalizeVersionedRequestInput(input) {
    const values = normalizeRequestLookup(input);
    return Object.freeze({ ...values, now: nowDate() });
  }

  function normalizeApproveInput(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "request_id", "requestId", "owner_member_id", "ownerMemberId", "owner_session_id", "ownerSessionId", "authorization_id", "authorizationId", "authorized_at", "authorizedAt", "expected_version", "expectedVersion", "idempotency_key", "idempotencyKey"]);
    return Object.freeze({
      organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
      requestId: uuid(input.request_id ?? input.requestId, "request_id"),
      ownerMemberId: uuid(input.owner_member_id ?? input.ownerMemberId, "owner_member_id"),
      ownerSessionId: uuid(input.owner_session_id ?? input.ownerSessionId, "owner_session_id"),
      authorizationId: uuid(input.authorization_id ?? input.authorizationId, "authorization_id"),
      authorizedAt: input.authorized_at === undefined && input.authorizedAt === undefined ? undefined : date(input.authorized_at ?? input.authorizedAt, "authorized_at"),
      expectedVersion: positiveInteger(input.expected_version ?? input.expectedVersion),
      now: nowDate(),
      idempotencyKey: requiredIdempotencyKey(input.idempotency_key ?? input.idempotencyKey)
    });
  }

  function normalizeCancelInput(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "request_id", "requestId", "actor_member_id", "actorMemberId", "actor_session_id", "actorSessionId", "reason", "expected_version", "expectedVersion", "idempotency_key", "idempotencyKey"]);
    return Object.freeze({
      organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
      requestId: uuid(input.request_id ?? input.requestId, "request_id"),
      actorMemberId: uuid(input.actor_member_id ?? input.actorMemberId, "actor_member_id"),
      actorSessionId: uuid(input.actor_session_id ?? input.actorSessionId, "actor_session_id"),
      reason: safeText(input.reason ?? "cancelled_by_owner", "reason", 128),
      expectedVersion: positiveInteger(input.expected_version ?? input.expectedVersion),
      now: nowDate(),
      idempotencyKey: requiredIdempotencyKey(input.idempotency_key ?? input.idempotencyKey)
    });
  }

  function normalizeConsumeExchangeInput(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "request_id", "requestId", "exchange_token", "exchangeToken", "expected_version", "expectedVersion"]);
    return Object.freeze({
      organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
      requestId: uuid(input.request_id ?? input.requestId, "request_id"),
      exchangeToken: rawToken(input.exchange_token ?? input.exchangeToken, "exchange_token"),
      expectedVersion: positiveInteger(input.expected_version ?? input.expectedVersion),
      now: nowDate()
    });
  }

  function normalizeEnrollmentInput(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "request_id", "requestId", "recovery_session_token", "recoverySessionToken", "credential_id", "credentialId", "enrolled_at", "enrolledAt", "expected_version", "expectedVersion"]);
    return Object.freeze({
      organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
      requestId: uuid(input.request_id ?? input.requestId, "request_id"),
      recoverySessionToken: rawToken(input.recovery_session_token ?? input.recoverySessionToken, "recovery_session_token"),
      credentialId: credentialBytes(input.credential_id ?? input.credentialId),
      enrolledAt: input.enrolled_at === undefined && input.enrolledAt === undefined ? nowDate() : date(input.enrolled_at ?? input.enrolledAt, "enrolled_at"),
      expectedVersion: positiveInteger(input.expected_version ?? input.expectedVersion),
      now: nowDate()
    });
  }

  function normalizeActivationInput(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "request_id", "requestId", "recovery_session_token", "recoverySessionToken", "authorization_id", "authorizationId", "authorized_at", "authorizedAt", "activated_at", "activatedAt", "expected_version", "expectedVersion"]);
    return Object.freeze({
      organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
      requestId: uuid(input.request_id ?? input.requestId, "request_id"),
      recoverySessionToken: rawToken(input.recovery_session_token ?? input.recoverySessionToken, "recovery_session_token"),
      authorizationId: uuid(input.authorization_id ?? input.authorizationId, "authorization_id"),
      authorizedAt: input.authorized_at === undefined && input.authorizedAt === undefined ? undefined : date(input.authorized_at ?? input.authorizedAt, "authorized_at"),
      activatedAt: input.activated_at === undefined && input.activatedAt === undefined ? nowDate() : date(input.activated_at ?? input.activatedAt, "activated_at"),
      expectedVersion: positiveInteger(input.expected_version ?? input.expectedVersion),
      now: nowDate()
    });
  }

  function normalizeExpireDueInput(input) {
    assertObject(input);
    assertKeys(input, ["organization_id", "organizationId", "limit"]);
    return Object.freeze({ organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"), limit: boundedInteger(input.limit ?? 100, 1, 1000), now: nowDate() });
  }

  async function claimIdempotency(tx, { organizationId, operation, principalId, idempotencyKey, identity }) {
    const requestDigest = sha256Digest(stableCanonicalize({ version: 1, operation, identity }));
    const result = await idempotency.claimInTransaction({
      tx,
      organization_id: organizationId,
      operation,
      principal_id: principalId,
      idempotency_key: idempotencyKey,
      request_digest: requestDigest
    });
    if (result?.state === "conflict") throw failure("idempotency_conflict");
    if (result?.state === "in_progress") throw failure("unavailable");
    if (result?.state === "replay") {
      if (!result.response_body || typeof result.response_body !== "object" || Array.isArray(result.response_body)) throw failure("unavailable");
      return Object.freeze({ replayed: true, response: Object.freeze({ ...result.response_body, replayed: true }) });
    }
    if (result?.state !== "claimed" || typeof result.owner_token !== "string") throw failure("unavailable");
    return Object.freeze({ replayed: false, organizationId, operation, principalId, idempotencyKey, requestDigest, ownerToken: result.owner_token });
  }

  async function completeIdempotency(tx, claim, responseStatus, response) {
    if (claim.replayed) throw failure("unavailable");
    const completed = await idempotency.completeInTransaction({
      tx,
      organization_id: claim.organizationId,
      operation: claim.operation,
      principal_id: claim.principalId,
      idempotency_key: claim.idempotencyKey,
      request_digest: claim.requestDigest,
      owner_token: claim.ownerToken,
      response_status: responseStatus,
      response_body: response
    });
    if (completed?.state !== "completed") throw failure("unavailable");
  }

  async function mutate(operation, callback) {
    try {
      return await withTransaction(client, callback);
    } catch (error) {
      if (error instanceof OwnerRecoveryRepositoryError) throw error;
      throw failure("unavailable", error);
    }
  }

  async function lockRequest(tx, organizationId, requestId) {
    const result = await tx.query(`SELECT ${REQUEST_COLUMNS} FROM owner_recovery_requests
      WHERE organization_id=$1 AND request_id=$2 FOR UPDATE`, [organizationId, requestId]);
    if (rowCount(result) !== 1) throw failure("not_found");
    return storedRequest(result.rows[0]);
  }

  async function lockOrganization(tx, organizationId) {
    await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`agentpass:organization:${organizationId}`]);
  }

  async function lockCredentialSet(tx, memberId) {
    await tx.query("SELECT pg_advisory_xact_lock(hashtextextended('agentpass:webauthn:credentials:' || $1::text, 0)) AS locked", [memberId]);
  }

  async function approvalOwnerIds(tx, organizationId, requestId) {
    const result = await tx.query(`SELECT owner_member_id FROM owner_recovery_approvals
      WHERE organization_id=$1 AND request_id=$2 ORDER BY owner_member_id ASC,approval_id ASC`, [organizationId, requestId]);
    return (result.rows ?? []).map((row) => uuid(row.owner_member_id, "owner_member_id"));
  }

  async function lockApprovals(tx, organizationId, requestId) {
    const result = await tx.query(`SELECT owner_member_id,owner_membership_session_epoch,approved_at,invalidated_at,invalidation_reason,approval_id,authorization_id
      FROM owner_recovery_approvals WHERE organization_id=$1 AND request_id=$2
      ORDER BY owner_member_id ASC,approval_id ASC FOR UPDATE`, [organizationId, requestId]);
    return (result.rows ?? []).map(storedApproval);
  }

  async function lockMemberships(tx, organizationId, memberIds) {
    const ids = uniqueSorted(memberIds);
    const result = await tx.query(`SELECT id,organization_id,member_id,role,status,session_epoch
      FROM memberships WHERE organization_id=$1 AND member_id=ANY($2::uuid[])
      ORDER BY member_id ASC,id ASC FOR UPDATE`, [organizationId, ids]);
    return (result.rows ?? []).map(storedMembership);
  }

  async function lockHumanSession(tx, { organizationId, sessionId, memberId, membershipId, now }) {
    if (!membershipId) return null;
    const result = await tx.query(`SELECT s.id,s.member_id,s.organization_id,s.membership_id,s.role,s.expires_at,s.idle_expires_at,
        s.revoked_at,m.status AS membership_status,m.session_epoch,s.membership_session_epoch,o.authority_epoch,s.organization_authority_epoch
      FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.id=s.membership_id AND m.member_id=s.member_id
      JOIN organizations o ON o.id=s.organization_id
      WHERE s.id=$1 AND s.organization_id=$2 AND s.member_id=$3 AND s.membership_id=$4
        AND s.revoked_at IS NULL AND s.expires_at>$5 AND (s.idle_expires_at IS NULL OR s.idle_expires_at>$5)
        AND m.status='active' AND m.role=s.role AND m.session_epoch=s.membership_session_epoch
        AND o.authority_epoch=s.organization_authority_epoch FOR UPDATE`, [sessionId, organizationId, memberId, membershipId, now]);
    return result.rows?.[0] ? storedSession(result.rows[0]) : null;
  }

  async function lockHumanSessionsForMember(tx, organizationId, memberId) {
    const result = await tx.query(`SELECT id FROM human_sessions
      WHERE organization_id=$1 AND member_id=$2 ORDER BY id ASC FOR UPDATE`, [organizationId, memberId]);
    return result.rows ?? [];
  }

  async function lockRecoverySessionByDigest(tx, organizationId, requestId, digest) {
    const result = await tx.query(`SELECT organization_id,recovery_session_id,request_id,member_id,session_digest,stage,issued_at,expires_at,
        idle_expires_at,last_seen_at,credential_id,credential_enrolled_at,activation_authorization_id,activation_authorized_at,activated_at,revoked_at,revoke_reason
      FROM owner_recovery_sessions WHERE organization_id=$1 AND request_id=$2 AND session_digest=$3 FOR UPDATE`, [organizationId, requestId, digest]);
    return result.rows?.[0] ? storedRecoverySession(result.rows[0]) : null;
  }

  async function lockRecoverySessionById(tx, organizationId, recoverySessionId) {
    const result = await tx.query(`SELECT organization_id,recovery_session_id,request_id,member_id,session_digest,stage,issued_at,expires_at,
        idle_expires_at,last_seen_at,credential_id,credential_enrolled_at,activation_authorization_id,activation_authorized_at,activated_at,revoked_at,revoke_reason
      FROM owner_recovery_sessions WHERE organization_id=$1 AND recovery_session_id=$2 FOR UPDATE`, [organizationId, recoverySessionId]);
    return result.rows?.[0] ? storedRecoverySession(result.rows[0]) : null;
  }

  async function lockRecoveryWebAuthnChallenge(tx, { organizationId, challengeId, recoverySessionId, requestId, memberId, ceremony, operation }) {
    const result = await tx.query(`SELECT organization_id,challenge_id,recovery_session_id,request_id,member_id,ceremony,operation,status,
        created_at,expires_at,consume_started_at,consumed_at,failed_at,verified_credential_id,authorization_consumed_at
      FROM owner_recovery_webauthn_challenges
      WHERE organization_id=$1 AND challenge_id=$2 AND recovery_session_id=$3 AND request_id=$4 AND member_id=$5
        AND ceremony=$6 AND operation=$7 FOR UPDATE`, [organizationId, challengeId, recoverySessionId, requestId, memberId, ceremony, operation]);
    return result.rows?.[0] ? storedRecoveryWebAuthnChallenge(result.rows[0]) : null;
  }

  async function recoverySessionById(tx, organizationId, sessionId) {
    const result = await tx.query(`SELECT organization_id,recovery_session_id,request_id,member_id,session_digest,stage,issued_at,expires_at,
        idle_expires_at,last_seen_at,credential_id,credential_enrolled_at,activation_authorization_id,activation_authorized_at,activated_at,revoked_at,revoke_reason
      FROM owner_recovery_sessions WHERE organization_id=$1 AND recovery_session_id=$2 FOR SHARE`, [organizationId, sessionId]);
    return result.rows?.[0] ? storedRecoverySession(result.rows[0]) : null;
  }

  async function lockRecoverySessions(tx, organizationId, memberId, requestId = undefined) {
    const params = [organizationId, memberId];
    const requestClause = requestId === undefined ? "" : " AND request_id=$3";
    if (requestId !== undefined) params.push(requestId);
    const result = await tx.query(`SELECT organization_id,recovery_session_id,request_id,member_id,session_digest,stage,issued_at,expires_at,
        idle_expires_at,last_seen_at,credential_id,credential_enrolled_at,activation_authorization_id,activation_authorized_at,activated_at,revoked_at,revoke_reason
      FROM owner_recovery_sessions WHERE organization_id=$1 AND member_id=$2${requestClause}
      ORDER BY recovery_session_id ASC FOR UPDATE`, params);
    return (result.rows ?? []).map(storedRecoverySession);
  }

  async function findExchange(tx, organizationId, requestId) {
    const result = await tx.query(`SELECT organization_id,request_id,exchange_id,exchange_digest,issued_at,expires_at,consumed_at,consumed_recovery_session_id
      FROM owner_recovery_exchanges WHERE organization_id=$1 AND request_id=$2 FOR UPDATE`, [organizationId, requestId]);
    return result.rows?.[0] ? storedExchange(result.rows[0]) : null;
  }

  async function findExchangeByDigest(tx, organizationId, requestId, digest) {
    const result = await tx.query(`SELECT organization_id,request_id,exchange_id,exchange_digest,issued_at,expires_at,consumed_at,consumed_recovery_session_id
      FROM owner_recovery_exchanges WHERE organization_id=$1 AND request_id=$2 AND exchange_digest=$3 FOR UPDATE`, [organizationId, requestId, digest]);
    return result.rows?.[0] ? storedExchange(result.rows[0]) : null;
  }

  async function lockApprovalAuthorization(tx, { organizationId, authorizationId, memberId, sessionId, now }) {
    const result = await tx.query(`SELECT id,session_id,member_id,organization_id,operation,ceremony,status,consumed_at,expires_at
      FROM webauthn_challenges
      WHERE id=$1 AND organization_id=$2 AND member_id=$3 AND session_id=$4
        AND operation='human.recovery.approve' AND ceremony='authentication' AND status='consumed'
        AND consumed_at IS NOT NULL AND consumed_at<=$5 AND expires_at>=consumed_at FOR SHARE`, [authorizationId, organizationId, memberId, sessionId, now]);
    return result.rows?.[0] ? storedAuthorization(result.rows[0]) : null;
  }

  async function lockActivationAuthorization(tx, { organizationId, memberId, authorizationId, now }) {
    const result = await tx.query(`SELECT id,session_id,member_id,organization_id,operation,ceremony,status,consumed_at,expires_at
      FROM webauthn_challenges
      WHERE id=$1 AND organization_id=$2 AND member_id=$3
        AND operation='human.recovery.activate' AND ceremony='authentication' AND status='consumed'
        AND consumed_at IS NOT NULL AND consumed_at<=$4 AND consumed_at>=$5 AND expires_at>=consumed_at
        AND NOT EXISTS (SELECT 1 FROM owner_recovery_sessions used
          WHERE used.organization_id=$2 AND used.activation_authorization_id=$1) FOR SHARE`, [authorizationId, organizationId, memberId, now, new Date(now.getTime() - limits.authorizationWindowMs)]);
    return result.rows?.[0] ? storedAuthorization(result.rows[0]) : null;
  }

  async function revalidateApprovals(tx, request, memberships, now) {
    const approvals = await lockApprovals(tx, request.organization_id, request.request_id);
    const valid = [];
    for (const approval of approvals) {
      const membership = membershipFor(memberships, approval.owner_member_id);
      const isValid = approval.invalidated_at === null && membership?.status === "active" && membership.role === "owner"
        && positiveInteger(membership.session_epoch) === positiveInteger(approval.owner_membership_session_epoch)
        && approval.approved_at <= now;
      if (isValid) valid.push(approval);
      else if (approval.invalidated_at === null) {
        await tx.query(`UPDATE owner_recovery_approvals
          SET invalidated_at=$3,invalidation_reason='owner_membership_changed'
          WHERE organization_id=$1 AND request_id=$2 AND approval_id=$4 AND invalidated_at IS NULL`, [request.organization_id, request.request_id, now, approval.approval_id]);
      }
    }
    return valid;
  }

  async function countEligibleOwners(tx, organizationId, subjectMemberId) {
    const result = await tx.query(`SELECT count(*)::text AS count FROM memberships
      WHERE organization_id=$1 AND member_id<>$2 AND role='owner' AND status='active'`, [organizationId, subjectMemberId]);
    return boundedCount(result.rows?.[0]?.count);
  }

  async function updateRequestVersion(tx, { organizationId, requestId, expectedVersion, state, approvedOwnerCount }) {
    const result = await tx.query(`UPDATE owner_recovery_requests SET state=$4,approved_owner_count=$5,version=version+1,updated_at=clock_timestamp()
      WHERE organization_id=$1 AND request_id=$2 AND version=$3 RETURNING ${REQUEST_COLUMNS}`, [organizationId, requestId, expectedVersion, state, approvedOwnerCount]);
    if (rowCount(result) !== 1) throw failure("stale_version");
    return storedRequest(result.rows[0]);
  }

  async function transitionRequest(tx, { organizationId, requestId, expectedVersion, fromState, toState, approvedAt = undefined, delayUntil = undefined, sessionIssuedAt = undefined, credentialEnrolledAt = undefined, activatedAt = undefined, terminalReason = undefined, approvedOwnerCount = undefined }) {
    const assignments = ["state=$4", "version=version+1", "updated_at=clock_timestamp()"];
    const params = [organizationId, requestId, expectedVersion, toState];
    if (approvedAt !== undefined) { params.push(approvedAt); assignments.push(`approved_at=$${params.length}`); }
    if (delayUntil !== undefined) { params.push(delayUntil); assignments.push(`delay_until=$${params.length}`); }
    if (sessionIssuedAt !== undefined) { params.push(sessionIssuedAt); assignments.push(`session_issued_at=$${params.length}`); }
    if (credentialEnrolledAt !== undefined) { params.push(credentialEnrolledAt); assignments.push(`credential_enrolled_at=$${params.length}`); }
    if (activatedAt !== undefined) { params.push(activatedAt); assignments.push(`activated_at=$${params.length}`); }
    if (terminalReason !== undefined) { params.push(terminalReason); assignments.push(`terminal_reason=$${params.length}`); }
    if (approvedOwnerCount !== undefined) { params.push(approvedOwnerCount); assignments.push(`approved_owner_count=$${params.length}`); }
    const result = await tx.query(`UPDATE owner_recovery_requests SET ${assignments.join(",")}
      WHERE organization_id=$1 AND request_id=$2 AND version=$3 AND state=$${4} RETURNING ${REQUEST_COLUMNS}`, params);
    if (rowCount(result) !== 1) throw failure("stale_version");
    return storedRequest(result.rows[0]);
  }

  async function revokeRecoverySessions(tx, organizationId, memberId, at, reason) {
    await tx.query(`UPDATE owner_recovery_sessions SET stage='revoked',revoked_at=$3,revoke_reason=$4
      WHERE organization_id=$1 AND member_id=$2 AND stage IN ('session_issued','credential_enrolled') AND revoked_at IS NULL`, [organizationId, memberId, at, reason]);
  }

  async function insertOutbox(tx, { organizationId, requestId, subjectMemberId, eventType, eventKey = "" }) {
    if (!OUTBOX_EVENTS.has(eventType)) throw failure("unavailable");
    const eventId = deterministicUuid(organizationId, requestId, `outbox:${eventType}:${eventKey}`);
    const inserted = await tx.query(`INSERT INTO owner_recovery_outbox
      (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at)
      VALUES ($1,$2,$3,$4,$5,'pending',0,clock_timestamp(),clock_timestamp(),clock_timestamp())
      ON CONFLICT (organization_id,event_id) DO NOTHING RETURNING event_id,event_type,request_id,subject_member_id`, [organizationId, eventId, requestId, subjectMemberId, eventType]);
    if (rowCount(inserted) === 1) return eventId;
    const existing = await tx.query(`SELECT event_id,event_type,request_id,subject_member_id FROM owner_recovery_outbox
      WHERE organization_id=$1 AND event_id=$2 FOR UPDATE`, [organizationId, eventId]);
    if (rowCount(existing) !== 1 || existing.rows[0].event_type !== eventType || existing.rows[0].request_id !== requestId || existing.rows[0].subject_member_id !== subjectMemberId) throw failure("unavailable");
    return eventId;
  }
}

function storedRequest(row) {
  if (!row || typeof row !== "object") throw failure("unavailable");
  return Object.freeze({
    organization_id: uuid(row.organization_id, "organization_id"), request_id: uuid(row.request_id, "request_id"),
    schema_version: positiveInteger(row.schema_version), kind: row.kind, subject_member_id: uuid(row.subject_member_id, "subject_member_id"),
    creator_member_id: uuid(row.creator_member_id, "creator_member_id"), creator_session_id: uuid(row.creator_session_id, "creator_session_id"),
    state: String(row.state), threshold: boundedInteger(Number(row.threshold), 2, 32), approved_owner_count: boundedInteger(Number(row.approved_owner_count), 0, 32),
    approved_at: optionalDate(row.approved_at), delay_until: optionalDate(row.delay_until), session_issued_at: optionalDate(row.session_issued_at),
    credential_enrolled_at: optionalDate(row.credential_enrolled_at), activated_at: optionalDate(row.activated_at), expires_at: date(row.expires_at, "expires_at"),
    terminal_reason: row.terminal_reason === null || row.terminal_reason === undefined ? null : safeText(row.terminal_reason, "terminal_reason", 128),
    version: positiveInteger(row.version), created_at: date(row.created_at, "created_at"), updated_at: date(row.updated_at, "updated_at")
  });
}

function publicRequest(row) {
  const stored = row.organization_id ? storedRequest(row) : row;
  return Object.freeze({
    organization_id: stored.organization_id, request_id: stored.request_id, schema_version: stored.schema_version, kind: stored.kind,
    subject_member_id: stored.subject_member_id, state: stored.state, threshold: stored.threshold, approved_owner_count: stored.approved_owner_count,
    approved_at: optionalTimestamp(stored.approved_at), delay_until: optionalTimestamp(stored.delay_until), session_issued_at: optionalTimestamp(stored.session_issued_at),
    credential_enrolled_at: optionalTimestamp(stored.credential_enrolled_at), activated_at: optionalTimestamp(stored.activated_at), expires_at: timestamp(stored.expires_at),
    terminal_reason: stored.terminal_reason, version: stored.version, created_at: timestamp(stored.created_at), updated_at: timestamp(stored.updated_at)
  });
}

function storedApproval(row) {
  return Object.freeze({
    owner_member_id: uuid(row.owner_member_id, "owner_member_id"), owner_membership_session_epoch: positiveInteger(row.owner_membership_session_epoch),
    approved_at: date(row.approved_at, "approved_at"), invalidated_at: optionalDate(row.invalidated_at),
    invalidation_reason: row.invalidation_reason === null || row.invalidation_reason === undefined ? null : safeText(row.invalidation_reason, "invalidation_reason", 128),
    approval_id: uuid(row.approval_id, "approval_id"), authorization_id: uuid(row.authorization_id, "authorization_id")
  });
}

function publicApproval(row) {
  const stored = row.approval_id ? storedApproval(row) : row;
  return Object.freeze({ owner_member_id: stored.owner_member_id, owner_membership_session_epoch: stored.owner_membership_session_epoch, approved_at: timestamp(stored.approved_at), invalidated_at: optionalTimestamp(stored.invalidated_at), invalidation_reason: stored.invalidation_reason });
}

function storedMembership(row) {
  return Object.freeze({ id: uuid(row.id, "membership_id"), organization_id: uuid(row.organization_id, "organization_id"), member_id: uuid(row.member_id, "member_id"), role: role(row.role), status: row.status, session_epoch: positiveInteger(row.session_epoch) });
}

function storedSession(row) { return Object.freeze({ id: uuid(row.id, "session_id"), role: role(row.role), expires_at: date(row.expires_at, "expires_at"), idle_expires_at: optionalDate(row.idle_expires_at) }); }
function storedRecoverySession(row) { return Object.freeze({ ...row, organization_id: uuid(row.organization_id, "organization_id"), recovery_session_id: uuid(row.recovery_session_id, "recovery_session_id"), request_id: uuid(row.request_id, "request_id"), member_id: uuid(row.member_id, "member_id"), session_digest: bytes(row.session_digest, 32), stage: recoveryStage(row.stage), issued_at: date(row.issued_at, "issued_at"), expires_at: date(row.expires_at, "expires_at"), idle_expires_at: date(row.idle_expires_at, "idle_expires_at"), last_seen_at: date(row.last_seen_at, "last_seen_at"), credential_id: row.credential_id === null || row.credential_id === undefined ? null : credentialBytes(row.credential_id), credential_enrolled_at: optionalDate(row.credential_enrolled_at), activation_authorization_id: row.activation_authorization_id ? uuid(row.activation_authorization_id, "authorization_id") : null, activation_authorized_at: optionalDate(row.activation_authorized_at), activated_at: optionalDate(row.activated_at), revoked_at: optionalDate(row.revoked_at), revoke_reason: row.revoke_reason ?? null }); }
function storedExchange(row) { return Object.freeze({ ...row, organization_id: uuid(row.organization_id, "organization_id"), request_id: uuid(row.request_id, "request_id"), exchange_id: uuid(row.exchange_id, "exchange_id"), exchange_digest: bytes(row.exchange_digest, 32), issued_at: date(row.issued_at, "issued_at"), expires_at: date(row.expires_at, "expires_at"), consumed_at: optionalDate(row.consumed_at), consumed_recovery_session_id: row.consumed_recovery_session_id ? uuid(row.consumed_recovery_session_id, "recovery_session_id") : null }); }
function storedAuthorization(row) { return Object.freeze({ id: uuid(row.id, "authorization_id"), session_id: uuid(row.session_id, "session_id"), member_id: uuid(row.member_id, "member_id"), organization_id: uuid(row.organization_id, "organization_id"), operation: row.operation, ceremony: row.ceremony, status: row.status, consumed_at: date(row.consumed_at, "authorized_at"), expires_at: date(row.expires_at, "expires_at") }); }
function storedRecoveryWebAuthnChallenge(row) { return Object.freeze({ organization_id: uuid(row.organization_id, "organization_id"), challenge_id: uuid(row.challenge_id, "challenge_id"), recovery_session_id: uuid(row.recovery_session_id, "recovery_session_id"), request_id: uuid(row.request_id, "request_id"), member_id: uuid(row.member_id, "member_id"), ceremony: row.ceremony, operation: row.operation, status: row.status, created_at: date(row.created_at, "created_at"), expires_at: date(row.expires_at, "expires_at"), consume_started_at: optionalDate(row.consume_started_at), consumed_at: optionalDate(row.consumed_at), failed_at: optionalDate(row.failed_at), verified_credential_id: row.verified_credential_id === null || row.verified_credential_id === undefined ? null : credentialBytes(row.verified_credential_id), authorization_consumed_at: optionalDate(row.authorization_consumed_at) }); }
function publicRecoverySession(row) { const stored = row.session_digest === undefined ? row : storedRecoverySession(row); return Object.freeze({ recovery_session_id: stored.recovery_session_id, request_id: stored.request_id, member_id: stored.member_id, organization_id: stored.organization_id, stage: stored.stage, issued_at: timestamp(stored.issued_at), expires_at: timestamp(stored.expires_at), idle_expires_at: timestamp(stored.idle_expires_at), ...(stored.credential_enrolled_at === null || stored.credential_enrolled_at === undefined ? {} : { credential_enrolled_at: timestamp(stored.credential_enrolled_at) }) }); }
function publicCredential(row) { return Object.freeze({ credential_id: credentialBytes(row.id).toString("base64url"), member_id: uuid(row.member_id, "member_id"), public_key: credentialBytes(row.public_key).toString("base64url"), sign_count: counterValue(row.sign_count), transports: Array.isArray(row.transports) ? Object.freeze([...row.transports]) : Object.freeze([]), label: safeText(row.label ?? "Unnamed credential", "label", 128), backup_eligible: row.backup_eligible === true, backup_state: row.backup_state === true, created_at: timestamp(row.created_at), last_used_at: optionalTimestamp(row.last_used_at) }); }

function membershipFor(rows, memberId) { return rows.find((row) => row.member_id === memberId); }
function uniqueSorted(values) { return [...new Set(values)].sort(); }
function approvalOwnerIdsFromRows(rows) { return rows.map((row) => row.owner_member_id); }
function requireExpectedVersion(request, expectedVersion) { if (request.version !== expectedVersion) throw failure("stale_version"); }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function oneRow(result, label) { if (rowCount(result) !== 1) throw failure("unavailable"); return result.rows[0]; }
function boundedCount(value) { const count = Number(value); if (!Number.isSafeInteger(count) || count < 0 || count > 32) throw failure("unavailable"); return count; }
function role(value) { if (!ROLES.has(value)) throw failure("unavailable"); return value; }
function recoveryStage(value) { if (!RECOVERY_SESSION_STAGES.has(value)) throw failure("unavailable"); return value; }
function positiveInteger(value) { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < 1) throw failure("unavailable"); return number; }
function boundedInteger(value, min, max) { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < min || number > max) throw failure("invalid_input"); return number; }
function duration(value, label) { if (!Number.isSafeInteger(value) || value < 1 || value > 365 * 24 * 60 * 60 * 1000) throw new TypeError(`${label} is invalid`); return value; }
function uuid(value, label) { if (typeof value !== "string" || !UUID.test(value)) throw failure(label === "organization_id" ? "tenant_scope" : "invalid_input"); return value.toLowerCase(); }
function optionalUuid(value, label) { if (value === undefined || value === null) return undefined; return uuid(value, label); }
function newUuid(generator) { const value = generator(); return uuid(value, "uuid"); }
function date(value, label) { const parsed = value instanceof Date ? new Date(value.getTime()) : new Date(value); if (!Number.isFinite(parsed.getTime())) throw failure("invalid_input"); return parsed; }
function optionalDate(value) { return value === undefined || value === null ? null : date(value, "timestamp"); }
function timestamp(value) { return date(value, "timestamp").toISOString(); }
function optionalTimestamp(value) { return value === null || value === undefined ? null : timestamp(value); }
function safeText(value, label, max) { if (typeof value !== "string" || value.length < 1 || value.length > max || CONTROL.test(value)) throw failure("invalid_input"); return value; }
function assertObject(value) { if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw failure("invalid_input"); }
function assertKeys(input, keys) { const allowed = new Set(keys); if (Object.keys(input).some((key) => !allowed.has(key))) throw failure("invalid_input"); }
function credentialBytes(value) { if (Buffer.isBuffer(value)) { if (value.length < 16 || value.length > 1024) throw failure("invalid_input"); return Buffer.from(value); } if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw failure("invalid_input"); let parsed; try { parsed = Buffer.from(value, "base64url"); } catch { throw failure("invalid_input"); } if (parsed.length < 16 || parsed.length > 1024) throw failure("invalid_input"); return parsed; }
function rawToken(value, label) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw failure("invalid_input"); let parsed; try { parsed = Buffer.from(value, "base64url"); } catch { throw failure("invalid_input"); } if (parsed.length !== TOKEN_BYTES) throw failure("invalid_input"); return parsed; }
function digestValue(value, label = "digest") { if (Buffer.isBuffer(value)) { if (value.length !== 32) throw failure("invalid_input"); return Buffer.from(value); } if (typeof value !== "string" || !DIGEST.test(value)) throw failure("invalid_input"); return Buffer.from(value, "hex"); }
function publicKeyBytes(value) { if (Buffer.isBuffer(value)) { if (value.length < 32 || value.length > 4096) throw failure("invalid_input"); return Buffer.from(value); } if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw failure("invalid_input"); let parsed; try { parsed = Buffer.from(value, "base64url"); } catch { throw failure("invalid_input"); } if (parsed.length < 32 || parsed.length > 4096) throw failure("invalid_input"); return parsed; }
function transportList(value) { if (value === undefined) return []; if (!Array.isArray(value) || value.length > 7) throw failure("invalid_input"); const allowed = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]); const seen = new Set(); for (const item of value) { if (typeof item !== "string" || !allowed.has(item) || seen.has(item)) throw failure("invalid_input"); seen.add(item); } return [...value]; }
function counterValue(value, label = "sign_count") { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < 0) throw failure("invalid_input"); return number; }
function optionalBoolean(value, label) { if (value === undefined) return undefined; if (typeof value !== "boolean") throw failure("invalid_input"); return value; }
function requiredBoolean(value, label) { if (typeof value !== "boolean") throw failure("authorization_required"); return value; }
function constantBufferEqual(left, right) { return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length === right.length && crypto.timingSafeEqual(left, right); }
function randomToken(generator) { const value = generator(TOKEN_BYTES); if (!Buffer.isBuffer(value) || value.length !== TOKEN_BYTES) throw failure("unavailable"); return value; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest(); }
function bytes(value, length) { const result = Buffer.isBuffer(value) ? Buffer.from(value) : typeof value === "string" && HEX.test(value) ? Buffer.from(value, "hex") : null; if (!result || result.length !== length) throw failure("unavailable"); return result; }
function deterministicUuid(...parts) { const value = crypto.createHash("sha256").update("AgentPass-Owner-Recovery-v1\0").update(parts.join("\0"), "utf8").digest().subarray(0, 16); value[6] = (value[6] & 0x0f) | 0x50; value[8] = (value[8] & 0x3f) | 0x80; const hex = value.toString("hex"); return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`; }
function stableCanonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableCanonicalize).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw failure("invalid_input");
  const keys = Object.keys(value).sort();
  if (keys.some((key) => value[key] === undefined)) throw failure("invalid_input");
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableCanonicalize(value[key])}`).join(",")}}`;
}
function requiredIdempotencyKey(value) { if (typeof value !== "string" || !/^[A-Za-z0-9._~-]{8,255}$/u.test(value)) throw failure("invalid_input"); return value; }
function failure(code, cause = undefined) { return new OwnerRecoveryRepositoryError(code, cause); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)"); }

function normalizeTransactionalEnrollmentInput(input) {
  assertObject(input);
  assertTransactionClient(input.tx);
  const binding = input.binding && typeof input.binding === "object" ? input.binding : input;
  const verified = input.verified_credential ?? input.verifiedCredential;
  assertObject(verified);
  const organizationId = uuid(input.organization_id ?? binding.organization_id, "organization_id");
  const requestId = uuid(input.request_id ?? binding.request_id, "request_id");
  const recoverySessionId = uuid(input.recovery_session_id ?? binding.recovery_session_id, "recovery_session_id");
  const memberId = uuid(input.member_id ?? binding.member_id, "member_id");
  const challengeId = uuid(input.challenge_id ?? binding.challenge_id, "challenge_id");
  const credentialId = credentialBytes(verified.credential_id ?? binding.credential_id);
  if (binding.credential_id && !constantBufferEqual(credentialId, credentialBytes(binding.credential_id))) throw failure("authorization_required");
  return Object.freeze({
    tx: input.tx, organizationId, requestId, recoverySessionId, memberId, challengeId, credentialId,
    publicKey: publicKeyBytes(verified.public_key), signCount: counterValue(verified.sign_count),
    transports: transportList(verified.transports), label: safeText(verified.label ?? "Unnamed credential", "label", 128),
    backupEligible: verified.backup_eligible ?? (verified.credential_device_type === "multiDevice" || verified.credential_backed_up === true),
    backupState: verified.backup_state ?? (verified.credential_backed_up === true),
    completedAt: date(input.now ?? binding.completed_at ?? new Date(), "completed_at")
  });
}

function normalizeTransactionalActivationInput(input) {
  assertObject(input);
  assertTransactionClient(input.tx);
  const binding = input.binding && typeof input.binding === "object" ? input.binding : input;
  const proof = input.authorization ?? input.verified_credential ?? input.verifiedCredential ?? input.proof;
  if (proof === undefined) throw failure("authorization_required");
  assertObject(proof);
  const organizationId = uuid(input.organization_id ?? binding.organization_id, "organization_id");
  const requestId = uuid(input.request_id ?? binding.request_id, "request_id");
  const recoverySessionId = uuid(input.recovery_session_id ?? binding.recovery_session_id, "recovery_session_id");
  const memberId = uuid(input.member_id ?? binding.member_id, "member_id");
  const authorizationId = uuid(input.authorization_id ?? input.authorizationId ?? proof.authorization_id ?? proof.authorizationId ?? binding.challenge_id ?? input.challenge_id, "authorization_id");
  const credentialId = credentialBytes(input.credential_id ?? input.credentialId ?? proof.credential_id ?? proof.credentialId ?? binding.credential_id);
  const expectedSignCount = counterValue(proof.expected_sign_count ?? proof.expectedSignCount ?? input.expected_sign_count ?? input.expectedSignCount);
  const signCount = counterValue(proof.sign_count ?? proof.signCount ?? input.sign_count ?? input.signCount);
  const expectedBackupEligible = requiredBoolean(proof.expected_backup_eligible ?? proof.expectedBackupEligible ?? input.expected_backup_eligible ?? input.expectedBackupEligible, "expected_backup_eligible");
  const expectedBackupState = requiredBoolean(proof.expected_backup_state ?? proof.expectedBackupState ?? input.expected_backup_state ?? input.expectedBackupState, "expected_backup_state");
  const backupEligible = requiredBoolean(proof.backup_eligible ?? proof.backupEligible ?? input.backup_eligible ?? input.backupEligible, "backup_eligible");
  const backupState = requiredBoolean(proof.backup_state ?? proof.backupState ?? input.backup_state ?? input.backupState, "backup_state");
  const deviceType = proof.credential_device_type ?? proof.credentialDeviceType;
  if (deviceType !== "singleDevice" && deviceType !== "multiDevice") throw failure("invalid_input");
  const credentialBackedUp = requiredBoolean(proof.credential_backed_up ?? proof.credentialBackedUp, "credential_backed_up");
  if (signCount < expectedSignCount || backupState && !backupEligible || expectedBackupState && !expectedBackupEligible || credentialBackedUp !== backupState) throw failure("authorization_required");
  if (deviceType === "singleDevice" && (backupEligible || backupState || credentialBackedUp)) throw failure("authorization_required");
  if (deviceType === "multiDevice" && !backupEligible) throw failure("authorization_required");
  return Object.freeze({ tx: input.tx, organizationId, requestId, recoverySessionId, memberId, authorizationId, credentialId, expectedSignCount, signCount, expectedBackupEligible, expectedBackupState, backupEligible, backupState, credentialDeviceType: deviceType, credentialBackedUp, completedAt: date(input.now ?? binding.completed_at ?? new Date(), "completed_at") });
}

function normalizeRecoveryContextInput(input) {
  assertObject(input);
  return Object.freeze({
    organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
    recoverySessionId: uuid(input.recovery_session_id ?? input.recoverySessionId, "recovery_session_id"),
    requestId: uuid(input.request_id ?? input.requestId, "request_id"),
    memberId: uuid(input.member_id ?? input.memberId, "member_id"),
    sessionDigest: digestValue(input.session_digest ?? input.sessionDigest),
    requiredStage: input.required_stage ?? input.requiredStage,
    now: date(input.now ?? new Date(), "now")
  });
}

function normalizeAuthenticatedSessionInput(input) {
  assertObject(input);
  return Object.freeze({
    organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
    requestId: input.request_id === undefined && input.requestId === undefined ? undefined : uuid(input.request_id ?? input.requestId, "request_id"),
    sessionDigest: digestValue(input.session_digest ?? input.sessionDigest),
    requiredStage: input.required_stage ?? input.requiredStage,
    now: date(input.now ?? new Date(), "now")
  });
}

function normalizeCredentialLookupInput(input) {
  assertObject(input);
  const hasCredential = input.credential_id !== undefined || input.credentialId !== undefined;
  const hasSession = input.recovery_session_id !== undefined || input.recoverySessionId !== undefined;
  if (!hasCredential && !hasSession) throw failure("invalid_input");
  return Object.freeze({
    tx: input.tx,
    organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
    requestId: uuid(input.request_id ?? input.requestId, "request_id"),
    recoverySessionId: hasSession ? uuid(input.recovery_session_id ?? input.recoverySessionId, "recovery_session_id") : undefined,
    sessionDigest: input.session_digest === undefined && input.sessionDigest === undefined ? undefined : digestValue(input.session_digest ?? input.sessionDigest),
    memberId: uuid(input.member_id ?? input.memberId, "member_id"),
    credentialId: hasCredential ? credentialBytes(input.credential_id ?? input.credentialId) : undefined,
    now: date(input.now ?? new Date(), "now")
  });
}

function normalizeCredentialCounterInput(input) {
  assertObject(input);
  assertTransactionClient(input.tx);
  const backupEligible = optionalBoolean(input.backup_eligible ?? input.backupEligible, "backup_eligible");
  const backupState = optionalBoolean(input.backup_state ?? input.backupState, "backup_state");
  const expectedBackupEligible = optionalBoolean(input.expected_backup_eligible ?? input.expectedBackupEligible, "expected_backup_eligible");
  const expectedBackupState = optionalBoolean(input.expected_backup_state ?? input.expectedBackupState, "expected_backup_state");
  const hasBackupMetadata = [backupEligible, backupState, expectedBackupEligible, expectedBackupState].some((value) => value !== undefined);
  if (hasBackupMetadata && [backupEligible, backupState, expectedBackupEligible, expectedBackupState].some((value) => value === undefined)) throw failure("invalid_input");
  return Object.freeze({ tx: input.tx, memberId: uuid(input.member_id ?? input.memberId, "member_id"), credentialId: credentialBytes(input.credential_id ?? input.credentialId), expectedSignCount: counterValue(input.expected_sign_count ?? input.expectedSignCount), signCount: counterValue(input.sign_count ?? input.signCount), backupEligible, backupState, expectedBackupEligible, expectedBackupState, hasBackupMetadata, updatedAt: date(input.updated_at ?? input.updatedAt ?? new Date(), "updated_at") });
}

function normalizeDigestExchangeInput(input) {
  assertObject(input);
  return Object.freeze({ exchangeDigest: digestValue(input.exchange_digest ?? input.exchangeDigest), sessionId: uuid(input.recovery_session_id ?? input.recoverySessionId, "recovery_session_id"), sessionDigest: digestValue(input.session_digest ?? input.sessionDigest), issuedAt: date(input.issued_at ?? input.issuedAt ?? new Date(), "issued_at"), now: date(input.now ?? new Date(), "now") });
}

function assertTransactionClient(client) { if (!client || typeof client.query !== "function") throw failure("invalid_input"); }

export default createPostgresOwnerRecoveryRepository;
