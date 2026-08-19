import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AGENT_SESSION_GRANT_TYPE,
  agentSessionGrantStatementHash,
  normalizeAgentSessionGrantStatement
} from "../agent-session-grant.mjs";
import {
  normalizeQualificationGrantBatchManifest,
  QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER,
  QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION
} from "../qualification-grant-batch-manifest.mjs";
import { createPostgresAdminAuditRepository } from "./admin-audit-repository.mjs";
import { assertTenantId, withTransaction } from "./repository.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const HASH = /^[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const AGENT_KINDS = new Set(["claude-code", "cursor"]);
const ADMIN_ROLES = new Set(["owner", "admin"]);
const BATCH_SCHEMA_VERSION = 1;
const BATCH_KIND = "agentpass-n3e-qualification-grant-batch";
const ISSUE_OPERATION = "qualification.grant_batch.issue";
const BATCH_STEPS = Object.freeze([
  Object.freeze({ index: 0, kind: "unarmed-control", scenario: null, phase: null }),
  Object.freeze({ index: 1, kind: "scenario", scenario: "pre-cloud-kill", phase: "pre-cloud" }),
  Object.freeze({ index: 2, kind: "scenario", scenario: "post-cloud-pre-local-kill", phase: "post-cloud-pre-local" }),
  Object.freeze({ index: 3, kind: "scenario", scenario: "post-activation-pre-audit-kill", phase: "post-activation-pre-audit" }),
  Object.freeze({ index: 4, kind: "scenario", scenario: "post-audit-pre-reply-loss", phase: "post-audit-pre-reply" }),
  Object.freeze({ index: 5, kind: "scenario", scenario: "audit-fsync-failure", phase: "audit-fsync" }),
  Object.freeze({ index: 6, kind: "scenario", scenario: "transport-reply-loss", phase: "transport-reply" })
]);

export const QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION = BATCH_SCHEMA_VERSION;
export const QUALIFICATION_GRANT_BATCH_KIND = BATCH_KIND;
export const QUALIFICATION_GRANT_BATCH_MANIFEST_KIND = QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE;
export const QUALIFICATION_GRANT_BATCH_STEPS = BATCH_STEPS;

export const QUALIFICATION_GRANT_BATCH_REPOSITORY_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "ERR_INPUT",
  TENANT_SCOPE: "ERR_TENANT_SCOPE",
  FORBIDDEN: "ERR_FORBIDDEN",
  NOT_FOUND: "ERR_NOT_FOUND",
  IDEMPOTENCY_CONFLICT: "ERR_IDEMPOTENCY_CONFLICT",
  IN_PROGRESS: "ERR_IDEMPOTENCY_IN_PROGRESS",
  CLAIM_CONFLICT: "ERR_CLAIM_CONFLICT",
  EXPIRED: "ERR_EXPIRED",
  REVOKED: "ERR_REVOKED",
  DATABASE: "ERR_DATABASE"
});

export class QualificationGrantBatchRepositoryError extends Error {
  constructor(code, cause = undefined) {
    super(publicMessage(code), cause === undefined ? undefined : { cause });
    this.name = "QualificationGrantBatchRepositoryError";
    this.code = QUALIFICATION_GRANT_BATCH_REPOSITORY_ERROR_CODES[code]
      ?? (Object.values(QUALIFICATION_GRANT_BATCH_REPOSITORY_ERROR_CODES).includes(code) ? code : QUALIFICATION_GRANT_BATCH_REPOSITORY_ERROR_CODES.DATABASE);
  }
}

/**
 * PostgreSQL authority for the seven normal Agent Session Grants used by a
 * physical qualification run.
 *
 * `buildGrants` is called exactly once for a new idempotency record.  It must
 * return seven existing agent-session-grant-v1 envelopes.  The repository
 * validates those envelopes and stores them in agent_session_grants without
 * translating them into a qualification-specific Grant type.  `buildManifest`
 * is then called once with the ordered, public inventory and must return a
 * signed qualification manifest envelope.  Both callbacks run inside the
 * transaction and no callback runs on an exact idempotent replay.
 */
export function createQualificationGrantBatchRepository({
  client,
  sharedControls = undefined,
  adminAuditRepository = undefined,
  now = () => new Date().toISOString()
} = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new QualificationGrantBatchRepositoryError("INVALID_INPUT");
  const controls = sharedControls ?? createSharedControlRepository({ client });
  const audit = adminAuditRepository ?? createPostgresAdminAuditRepository({ client, now });
  assertMethod(controls, "acquireIdempotency");
  assertMethod(controls, "completeIdempotency");
  assertMethod(audit, "appendAdminAuditEventInTransaction");

  async function issueQualificationGrantBatch(input = {}) {
    const values = normalizeIssueInput(input, now);
    try {
      return await withTransaction(client, async (tx) => {
        await setTenantContext(tx, values.organizationId);
        await lockAuthority(tx, values.organizationId, values.deviceId, values.agentId, values.agentKind);

        const acquired = await controls.acquireIdempotency({
          tx,
          organizationId: values.organizationId,
          principalId: values.actor.memberId,
          idempotencyKey: values.idempotencyKey,
          requestHash: values.requestFingerprint
        });
        if (acquired.state === "conflict") throw failure("IDEMPOTENCY_CONFLICT");
        if (acquired.state === "in_progress") throw failure("IN_PROGRESS");
        if (acquired.state === "replay") {
          const pointer = normalizeIdempotencyPointer(acquired.response);
          const replay = await loadBatch(tx, values.organizationId, pointer.batch_id, true);
          if (replay.request_id !== pointer.request_id) throw failure("DATABASE");
          return Object.freeze({ ...replay, replayed: true });
        }

        await authorizeHumanWebAuthn(tx, values);
        await assertAudienceAndCandidate(tx, values);
        const authorityGeneration = await currentAuthorityGeneration(tx, values.organizationId);
        const allocations = await allocateControlSequences(tx, values, authorityGeneration);

        let builtGrants;
        try {
          builtGrants = await values.buildGrants(Object.freeze({ allocations: Object.freeze(allocations) }));
        } catch (error) {
          throw failure("DATABASE", error);
        }
        const grants = normalizeBuiltGrants(builtGrants, values, allocations);
        const manifestInput = createManifestInput(values, grants);
        let builtManifest;
        try {
          builtManifest = await values.buildManifest(Object.freeze({
            manifest: manifestInput,
            grants: Object.freeze(grants.map((entry) => entry.grant)),
            steps: Object.freeze(grants.map((entry) => entry.step))
          }));
        } catch (error) {
          throw failure("DATABASE", error);
        }
        const manifest = normalizeManifest(builtManifest, manifestInput);

        await insertBatch(tx, values, manifest);
        for (const entry of grants) await insertGrant(tx, values, entry);
        for (const entry of grants) await insertStep(tx, values, entry);

        const auditEvent = await appendAudit(tx, values, manifest, grants.length, audit);
        await insertOutbox(tx, values, manifest, auditEvent.audit_event_id);

        const batch = publicIssueBatch({
          ...values,
          status: "issued",
          manifest_hash: manifest.statement_hash,
          issued_at: values.issuedAt,
          expires_at: values.expiresAt
        });
        await controls.completeIdempotency({
          tx,
          organizationId: values.organizationId,
          principalId: values.actor.memberId,
          idempotencyKey: values.idempotencyKey,
          requestHash: values.requestFingerprint,
          responseStatus: 201,
          response: { batch_id: values.batchId, request_id: values.requestId }
        });
        return Object.freeze({ batch, request_id: values.requestId, replayed: false });
      });
    } catch (error) {
      throw mapError(error);
    }
  }

  async function claimQualificationGrantBatch(input = {}) {
    const values = normalizeClaimInput(input, now);
    try {
      return await withTransaction(client, async (tx) => {
        await setTenantContext(tx, values.organizationId);
        await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) AS locked", [
          `agentpass:qualification-grant-batch-claim:${values.organizationId}:${values.batchId}`
        ]);
        const selected = await tx.query(`SELECT organization_id,batch_id,request_id,schema_version,kind,
            device_id,agent_id,agent_kind,requested_ttl_seconds,candidate_sha256,artifact_sha256,
            release_trust_sha256,candidate_checkpoint_sha256,source_commit,team_id,manifest_json,
            manifest_hash,manifest_signature_base64url,manifest_signer_key_id,status,issued_at,expires_at,
            claimed_at,expired_at,revoked_at,claimed_device_id,claim_identity_sha256,claim_request_sha256
          FROM qualification_grant_batches
          WHERE organization_id=$1 AND batch_id=$2
          FOR UPDATE`, [values.organizationId, values.batchId]);
        if (rowCount(selected) !== 1) throw failure("NOT_FOUND");
        const batchRow = selected.rows[0];
        assertClaimBinding(batchRow, values);

        if (batchRow.status === "expired") throw failure("EXPIRED");
        if (batchRow.status === "revoked") throw failure("REVOKED");
        if (batchRow.status === "claimed") {
          if (batchRow.claimed_device_id !== values.deviceId
            || batchRow.claim_identity_sha256 !== values.claimIdentitySha256
            || batchRow.claim_request_sha256 !== values.requestSha256) throw failure("CLAIM_CONFLICT");
          return loadClaimResult(tx, batchRow, true);
        }
        if (values.nowMs >= Date.parse(batchRow.expires_at)) {
          const expired = await tx.query(`UPDATE qualification_grant_batches
            SET status='expired',expired_at=clock_timestamp()
            WHERE organization_id=$1 AND batch_id=$2 AND status='issued'
            RETURNING batch_id`, [values.organizationId, values.batchId]);
          if (rowCount(expired) !== 1) throw failure("DATABASE");
          throw failure("EXPIRED");
        }

        const claimed = await tx.query(`UPDATE qualification_grant_batches
          SET status='claimed',claimed_at=clock_timestamp(),claimed_device_id=$3,
              claim_identity_sha256=$4,claim_request_sha256=$5
          WHERE organization_id=$1 AND batch_id=$2 AND status='issued'
          RETURNING organization_id,batch_id,request_id,schema_version,kind,device_id,agent_id,agent_kind,
            requested_ttl_seconds,candidate_sha256,artifact_sha256,release_trust_sha256,
            candidate_checkpoint_sha256,source_commit,team_id,manifest_json,manifest_hash,
            manifest_signature_base64url,manifest_signer_key_id,status,issued_at,expires_at,claimed_at,
            expired_at,revoked_at,claimed_device_id,claim_identity_sha256,claim_request_sha256`, [
          values.organizationId, values.batchId, values.deviceId, values.claimIdentitySha256, values.requestSha256
        ]);
        if (rowCount(claimed) !== 1) throw failure("CLAIM_CONFLICT");
        return loadClaimResult(tx, claimed.rows[0], false);
      });
    } catch (error) {
      throw mapError(error);
    }
  }

  return Object.freeze({ issueQualificationGrantBatch, claimQualificationGrantBatch });
}

async function insertBatch(tx, values, manifest) {
  const result = await tx.query(`INSERT INTO qualification_grant_batches
    (organization_id,batch_id,request_id,schema_version,kind,device_id,agent_id,agent_kind,
     requested_ttl_seconds,candidate_sha256,artifact_sha256,release_trust_sha256,
     candidate_checkpoint_sha256,source_commit,team_id,manifest_json,manifest_hash,
     manifest_signature_base64url,manifest_signer_key_id,authorized_session_id,authorized_member_id,
     authorization_id,authorized_at,status,issued_at,expires_at,created_by)
    VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18,$19,$20,$21,$22::timestamptz,'issued',$23::timestamptz,$24::timestamptz,$25)`, [
    values.organizationId, values.batchId, values.requestId, BATCH_KIND, values.deviceId, values.agentId,
    values.agentKind, values.requestedTtlSeconds, values.request.candidate_sha256, values.request.artifact_sha256,
    values.request.release_trust_sha256, values.request.candidate_checkpoint_sha256, values.request.source_commit,
    values.request.team_id, JSON.stringify(manifest.envelope), manifest.statement_hash,
    manifest.signature, manifest.key_id, values.actor.sessionId, values.actor.memberId,
    values.recentAuth.authorizationId, values.recentAuth.authenticatedAt, values.issuedAt, values.expiresAt,
    values.actor.memberId
  ]);
  if (rowCount(result) !== 0 && rowCount(result) !== 1) throw failure("DATABASE");
}

async function insertGrant(tx, values, entry) {
  const statement = entry.grant.statement;
  const result = await tx.query(`SELECT * FROM public.agentpass_agent_session_grant_issue(
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::text,$6::uuid,$7::text,$8::text,$9::text,
    $10::jsonb,$11::integer,$12::timestamptz,$13::timestamptz,$14::bigint,$15::bigint,
    $16::text,$17::text,$18::text,$19::text,$20::text,$21::timestamptz,$22::uuid)`, [
    values.organizationId, statement.grant_id, statement.device_id, statement.agent_id, statement.agent_kind,
    statement.adapter_id, statement.adapter_version, statement.worktree_binding_sha256,
    statement.process_binding_policy_id, JSON.stringify(statement.scope), statement.max_signatures,
    statement.not_before, statement.expires_at, statement.control_sequence, statement.authority_generation,
    statement.issuer, statement.key_id, entry.statement_hash, entry.grant_hash, entry.grant.signature,
    statement.not_before, values.actor.memberId
  ]);
  if (rowCount(result) !== 1 || !sameStoredGrant(result.rows[0], entry, values)) throw failure("DATABASE");
}

async function insertStep(tx, values, entry) {
  const result = await tx.query(`INSERT INTO qualification_grant_batch_steps
    (organization_id,batch_id,step_index,kind,scenario,phase,run_binding,grant_id,device_id,agent_id,grant_hash,statement_hash)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, [
    values.organizationId, values.batchId, entry.step.index, entry.step.kind, entry.step.scenario,
    entry.step.phase, entry.step.run_binding, entry.grant.statement.grant_id, values.deviceId,
    values.agentId, entry.grant_hash, entry.statement_hash
  ]);
  if (rowCount(result) !== 1 && rowCount(result) !== 0) throw failure("DATABASE");
}

async function appendAudit(tx, values, manifest, stepCount, audit) {
  try {
    const event = await audit.appendAdminAuditEventInTransaction({
      tx,
      organization_id: values.organizationId,
      actor_id: values.actor.memberId,
      idempotency_key: `${values.idempotencyKey}:qualification-batch-audit`,
      event_type: "qualification_grant_batch.issued",
      target_type: "qualification_grant_batch",
      target_id: values.batchId,
      details: {
        request_id: values.requestId,
        device_id: values.deviceId,
        agent_id: values.agentId,
        candidate_sha256: values.request.candidate_sha256,
        artifact_sha256: values.request.artifact_sha256,
        release_trust_sha256: values.request.release_trust_sha256,
        candidate_checkpoint_sha256: values.request.candidate_checkpoint_sha256,
        source_commit: values.request.source_commit,
        team_id: values.request.team_id,
        manifest_hash: manifest.statement_hash,
        step_count: stepCount
      }
    });
    if (!isUuid(event?.audit_event_id)) throw failure("DATABASE");
    return event;
  } catch (error) {
    if (error instanceof QualificationGrantBatchRepositoryError) throw error;
    throw failure("DATABASE", error);
  }
}

async function insertOutbox(tx, values, manifest, auditEventId) {
  const outboxId = deterministicUuid(`outbox\0${values.organizationId}\0${values.batchId}`);
  const payload = {
    version: 1,
    batch_id: values.batchId,
    request_id: values.requestId,
    device_id: values.deviceId,
    agent_id: values.agentId,
    manifest_hash: manifest.statement_hash,
    audit_event_id: auditEventId,
    step_count: 7
  };
  const result = await tx.query(`INSERT INTO outbox_events
    (organization_id,id,aggregate,action,payload,status)
    VALUES ($1,$2,'qualification-grant-batch','qualification_grant_batch.issued',$3::jsonb,'pending')
    ON CONFLICT (organization_id,id) DO NOTHING
    RETURNING id`, [values.organizationId, outboxId, JSON.stringify(payload)]);
  if (rowCount(result) === 1 && result.rows[0]?.id !== outboxId) throw failure("DATABASE");
  if (rowCount(result) > 1) throw failure("DATABASE");
}

async function loadClaimResult(tx, row, replayed) {
  const stepsResult = await tx.query(`SELECT step.step_index,step.kind,step.scenario,step.phase,step.run_binding,
      step.grant_id,step.grant_hash,step.statement_hash,
      grant_record.organization_id,grant_record.device_id,grant_record.agent_id,grant_record.agent_kind,
      grant_record.adapter_id,grant_record.adapter_version,grant_record.worktree_binding_sha256,
      grant_record.process_binding_policy_id,grant_record.scope_json,grant_record.max_signatures,
      grant_record.not_before,grant_record.expires_at,grant_record.control_sequence,
      grant_record.authority_generation,grant_record.issuer,grant_record.signer_key_id,
      grant_record.signature_base64url,grant_record.status,grant_record.issued_at
    FROM qualification_grant_batch_steps step
    JOIN agent_session_grants grant_record
      ON grant_record.organization_id=step.organization_id AND grant_record.grant_id=step.grant_id
    WHERE step.organization_id=$1 AND step.batch_id=$2
    ORDER BY step.step_index ASC
    FOR SHARE OF step,grant_record`, [row.organization_id, row.batch_id]);
  if (rowCount(stepsResult) !== 7) throw failure("DATABASE");
  const steps = stepsResult.rows.map((step) => {
    const grant = publicGrant(step);
    if (step.status !== "issued" || grant.statement_hash !== step.statement_hash
      || sha256(canonicalJson(grant)) !== step.grant_hash) throw failure("DATABASE");
    return Object.freeze({
      index: Number(step.step_index),
      kind: step.kind,
      scenario: step.scenario,
      phase: step.phase,
      run_binding: step.run_binding,
      grant
    });
  });
  if (!steps.every((step, index) => step.index === index) || new Set(steps.map((step) => step.grant.statement.grant_id)).size !== 7) throw failure("DATABASE");
  return Object.freeze({
    batch: publicClaimBatch(row, normalizeStoredManifest(row), steps),
    replayed
  });
}

async function loadBatch(tx, organizationId, batchId, includeManifest) {
  const result = await tx.query(`SELECT organization_id,batch_id,request_id,schema_version,kind,device_id,agent_id,
      agent_kind,requested_ttl_seconds,candidate_sha256,artifact_sha256,release_trust_sha256,
      candidate_checkpoint_sha256,source_commit,team_id,manifest_json,manifest_hash,
      manifest_signature_base64url,manifest_signer_key_id,status,issued_at,expires_at,claimed_at,
      expired_at,revoked_at,claimed_device_id,claim_identity_sha256,claim_request_sha256
    FROM qualification_grant_batches WHERE organization_id=$1 AND batch_id=$2 FOR SHARE`, [organizationId, batchId]);
  if (rowCount(result) !== 1) throw failure("NOT_FOUND");
  const row = result.rows[0];
  return Object.freeze({
    batch: publicIssueBatch(row),
    request_id: row.request_id,
    ...(includeManifest ? { manifest: normalizeStoredManifest(row) } : {})
  });
}

function normalizeIssueInput(input, clock) {
  const actor = normalizeActor(input.actor);
  const organizationId = tenant(input.organization_id);
  if (organizationId !== actor.organizationId) throw failure("TENANT_SCOPE");
  const request = normalizeRequest(input.request);
  const batchId = uuid(input.batch_id, "batch_id");
  const requestId = uuid(input.request_id, "request_id");
  const idempotencyKey = idempotency(input.idempotency_key);
  const requestFingerprint = hash(input.request_fingerprint, "request_fingerprint");
  const issuedAt = timestamp(input.issued_at, "issued_at");
  const expiresAt = timestamp(input.expires_at, "expires_at");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)
    || Date.parse(expiresAt) > Date.parse(issuedAt) + request.grant_intent.ttl_seconds * 1000) throw failure("INVALID_INPUT");
  const recentAuth = normalizeRecentAuth(input.recent_auth);
  const steps = normalizeSteps(input.steps);
  if (typeof input.buildGrants !== "function" || typeof input.buildManifest !== "function") throw failure("INVALID_INPUT");
  // Reading the clock here makes malformed injected clocks fail closed while
  // the database remains the source of truth for expiry and authorization.
  return Object.freeze({
    actor, organizationId, batchId, requestId, idempotencyKey, requestFingerprint,
    request, deviceId: request.grant_intent.device_id, agentId: uuid(input.agent_id, "agent_id"),
    agentKind: request.grant_intent.agent_kind, requestedTtlSeconds: request.grant_intent.ttl_seconds,
    issuedAt, expiresAt, recentAuth, steps, buildGrants: input.buildGrants,
    buildManifest: input.buildManifest, audit: input.auditRepository
  });
}

function normalizeClaimInput(input, clock) {
  const organizationId = tenant(input.organization_id);
  const values = {
    organizationId,
    batchId: uuid(input.batch_id, "batch_id"),
    deviceId: uuid(input.device_id, "device_id"),
    candidateSha256: hash(input.candidate_sha256, "candidate_sha256"),
    artifactSha256: hash(input.artifact_sha256, "artifact_sha256"),
    releaseTrustSha256: hash(input.release_trust_sha256, "release_trust_sha256"),
    candidateCheckpointSha256: hash(input.candidate_checkpoint_sha256, "candidate_checkpoint_sha256"),
    sourceCommit: sourceCommit(input.source_commit),
    teamId: team(input.team_id),
    requestSha256: hash(input.request_sha256, "request_sha256"),
    claimIdentitySha256: hash(input.claim_identity_sha256, "claim_identity_sha256"),
    observedAt: timestamp(input.observed_at, "observed_at"),
    nowMs: readClockMilliseconds(clock)
  };
  return Object.freeze(values);
}

function normalizeRequest(value) {
  if (!plainObject(value)) throw failure("INVALID_INPUT");
  const intent = value.grant_intent;
  if (!plainObject(intent)) throw failure("INVALID_INPUT");
  const normalized = {
    candidate_sha256: hash(value.candidate_sha256, "candidate_sha256"),
    artifact_sha256: hash(value.artifact_sha256, "artifact_sha256"),
    release_trust_sha256: hash(value.release_trust_sha256, "release_trust_sha256"),
    candidate_checkpoint_sha256: hash(value.candidate_checkpoint_sha256, "candidate_checkpoint_sha256"),
    source_commit: sourceCommit(value.source_commit),
    team_id: team(value.team_id),
    grant_intent: Object.freeze({
      device_id: uuid(intent.device_id, "device_id"),
      agent_kind: enumValue(intent.agent_kind, AGENT_KINDS),
      adapter_id: uuid(intent.adapter_id, "adapter_id"),
      adapter_version: text(intent.adapter_version, 128),
      worktree_binding_sha256: hash(intent.worktree_binding_sha256, "worktree_binding_sha256"),
      process_binding_policy_id: safeIdentifier(intent.process_binding_policy_id, "process_binding_policy_id"),
      scope: intent.scope,
      max_signatures: positiveInteger(intent.max_signatures, 1, 64),
      ttl_seconds: positiveInteger(intent.ttl_seconds, 60, 3600)
    })
  };
  if (normalized.grant_intent.max_signatures !== 1) throw failure("INVALID_INPUT");
  return Object.freeze(normalized);
}

function normalizeActor(value) {
  if (!plainObject(value)) throw failure("FORBIDDEN");
  const actor = {
    sessionId: uuid(value.session_id, "session_id"),
    memberId: uuid(value.member_id, "member_id"),
    organizationId: tenant(value.organization_id),
    role: value.role
  };
  if (!ADMIN_ROLES.has(actor.role)) throw failure("FORBIDDEN");
  return Object.freeze(actor);
}

function normalizeRecentAuth(value) {
  if (!plainObject(value)) throw failure("FORBIDDEN");
  const authorizationId = uuid(value.authorization_id, "authorization_id");
  const milliseconds = Number.isSafeInteger(value.authenticated_at) ? value.authenticated_at : Date.parse(value.authenticated_at);
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw failure("FORBIDDEN");
  return Object.freeze({ authorizationId, authenticatedAt: new Date(milliseconds).toISOString() });
}

function normalizeSteps(value) {
  if (!Array.isArray(value) || value.length !== BATCH_STEPS.length) throw failure("INVALID_INPUT");
  const seen = new Set();
  return Object.freeze(value.map((step, index) => {
    if (!plainObject(step)) throw failure("INVALID_INPUT");
    const expected = BATCH_STEPS[index];
    if (step.index !== expected.index || step.kind !== expected.kind || step.scenario !== expected.scenario
      || step.phase !== expected.phase || !SAFE_IDENTIFIER.test(step.run_binding ?? "") || seen.has(step.run_binding)) throw failure("INVALID_INPUT");
    seen.add(step.run_binding);
    return Object.freeze({
      index: step.index, kind: step.kind, scenario: step.scenario, phase: step.phase,
      run_binding: step.run_binding, grant_id: uuid(step.grant_id, "grant_id")
    });
  }));
}

function normalizeBuiltGrants(value, values, allocations) {
  if (!Array.isArray(value) || value.length !== BATCH_STEPS.length) throw failure("DATABASE");
  const seenGrantIds = new Set();
  const seenSequences = new Set();
  return Object.freeze(value.map((item, index) => {
    const source = plainObject(item) && plainObject(item.grant) ? item : { grant: item };
    const grant = normalizeGrant(source.grant);
    const step = values.steps[index];
    const allocation = allocations[index];
    const statement = grant.statement;
    const statementHash = hash(source.statement_hash, "statement_hash");
    const grantHash = hash(source.grant_hash, "grant_hash");
    if (statement.grant_id !== step.grant_id || statement.organization_id !== values.organizationId
      || statement.device_id !== values.deviceId || statement.agent_id !== values.agentId
      || statement.agent_kind !== values.agentKind || statement.expires_at !== values.expiresAt
      || statement.max_signatures !== 1 || statement.control_sequence !== allocation.control_sequence
      || statement.authority_generation !== allocation.authority_generation
      || statementHash !== agentSessionGrantStatementHash(statement)
      || grantHash !== sha256(canonicalJson(grant)) || seenGrantIds.has(statement.grant_id)
      || seenSequences.has(statement.control_sequence)) throw failure("DATABASE");
    seenGrantIds.add(statement.grant_id);
    seenSequences.add(statement.control_sequence);
    return Object.freeze({
      step,
      grant,
      grant_hash: grantHash,
      statement_hash: statementHash
    });
  }));
}

function normalizeGrant(value) {
  if (!plainObject(value) || value.version !== 1 || value.type !== AGENT_SESSION_GRANT_TYPE
    || !plainObject(value.statement) || !SIGNATURE.test(value.signature ?? "")) throw failure("DATABASE");
  const statement = normalizeAgentSessionGrantStatement(value.statement, { allowExpired: true, allowFuture: true, maxTtlMs: 60 * 60 * 1000 });
  return Object.freeze({ version: 1, type: AGENT_SESSION_GRANT_TYPE, statement, statement_hash: value.statement_hash, signature: value.signature });
}

function createManifestInput(values, grants) {
  return Object.freeze({
    version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
    type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
    batch_id: values.batchId,
    organization_id: values.organizationId,
    device_id: values.deviceId,
    agent_id: values.agentId,
    agent_kind: values.agentKind,
    requested_ttl_seconds: values.requestedTtlSeconds,
    candidate_sha256: values.request.candidate_sha256,
    artifact_sha256: values.request.artifact_sha256,
    source_commit: values.request.source_commit,
    team_id: values.request.team_id,
    release_trust_sha256: values.request.release_trust_sha256,
    candidate_checkpoint_sha256: values.request.candidate_checkpoint_sha256,
    issued_at: values.issuedAt,
    expires_at: values.expiresAt,
    steps: Object.freeze(grants.map(({ step, grant_hash, statement_hash, grant }) => Object.freeze({
      index: step.index,
      kind: step.kind,
      scenario: step.scenario,
      phase: step.phase,
      run_binding: step.run_binding,
      grant_id: grant.statement.grant_id,
      grant_hash,
      statement_hash,
      grant
    }))),
    issuer: QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER
  });
}

function normalizeManifest(value, expectedStatement) {
  let manifest;
  try {
    manifest = normalizeQualificationGrantBatchManifest(value, { allowExpired: true, allowFuture: true });
  } catch (error) {
    throw failure("DATABASE", error);
  }
  const statement = manifest.statement;
  const expectedKeys = [
    "version", "type", "batch_id", "organization_id", "device_id", "agent_id", "agent_kind",
    "requested_ttl_seconds", "candidate_sha256", "artifact_sha256", "source_commit", "team_id",
    "release_trust_sha256", "candidate_checkpoint_sha256", "issued_at", "expires_at", "steps", "issuer"
  ];
  if (expectedKeys.some((key) => canonicalJson(statement[key]) !== canonicalJson(expectedStatement[key]))) throw failure("DATABASE");
  return Object.freeze({
    envelope: manifest,
    statement_hash: manifest.statement_hash,
    signature: manifest.signature,
    key_id: statement.key_id
  });
}

function normalizeStoredManifest(row) {
  try {
    const manifest = normalizeQualificationGrantBatchManifest(row.manifest_json, { allowExpired: true, allowFuture: true });
    if (manifest.statement_hash !== row.manifest_hash
      || manifest.signature !== row.manifest_signature_base64url
      || manifest.statement.key_id !== row.manifest_signer_key_id) throw new Error("stored manifest metadata mismatch");
    return manifest;
  } catch {
    throw failure("DATABASE");
  }
}

function publicIssueBatch(row) {
  const request = row.request ?? {};
  const intent = request.grant_intent ?? {};
  return Object.freeze({
    schema_version: 1,
    kind: BATCH_KIND,
    batch_id: row.batchId ?? row.batch_id,
    organization_id: row.organizationId ?? row.organization_id,
    device_id: row.deviceId ?? row.device_id ?? intent.device_id,
    agent_id: row.agentId ?? row.agent_id,
    candidate_sha256: row.candidateSha256 ?? row.candidate_sha256 ?? request.candidate_sha256,
    artifact_sha256: row.artifactSha256 ?? row.artifact_sha256 ?? request.artifact_sha256,
    release_trust_sha256: row.releaseTrustSha256 ?? row.release_trust_sha256 ?? request.release_trust_sha256,
    candidate_checkpoint_sha256: row.candidateCheckpointSha256 ?? row.candidate_checkpoint_sha256 ?? request.candidate_checkpoint_sha256,
    source_commit: row.sourceCommit ?? row.source_commit ?? request.source_commit,
    team_id: row.teamId ?? row.team_id ?? request.team_id,
    // Human issue responses are an issuance receipt, not a lifecycle view.
    // An idempotent replay after Device claim must remain byte-shape compatible
    // with qualification-batch-service.normalizeResult().
    status: "issued",
    issued_at: timestampValue(row.issuedAt ?? row.issued_at, "issued_at"),
    expires_at: timestampValue(row.expiresAt ?? row.expires_at, "expires_at")
  });
}

function publicClaimBatch(row, manifest, steps) {
  const batch = Object.freeze({
    schema_version: 1,
    kind: BATCH_KIND,
    batch_id: row.batch_id,
    organization_id: row.organization_id,
    device_id: row.device_id,
    agent_id: row.agent_id,
    agent_kind: row.agent_kind,
    requested_ttl_seconds: Number(row.requested_ttl_seconds),
    candidate_sha256: row.candidate_sha256,
    source_commit: row.source_commit,
    artifact_sha256: row.artifact_sha256,
    release_trust_sha256: row.release_trust_sha256,
    candidate_checkpoint_sha256: row.candidate_checkpoint_sha256,
    team_id: row.team_id,
    expires_at: timestampValue(row.expires_at, "expires_at"),
    steps: Object.freeze(steps),
    manifest
  });
  if (!Array.isArray(steps) || steps.length !== 7) throw failure("DATABASE");
  return batch;
}

function publicGrant(row) {
  const statement = normalizeAgentSessionGrantStatement({
    version: 1,
    grant_id: row.grant_id,
    organization_id: row.organization_id,
    device_id: row.device_id,
    agent_id: row.agent_id,
    agent_kind: row.agent_kind,
    adapter_id: row.adapter_id,
    adapter_version: row.adapter_version,
    worktree_binding_sha256: row.worktree_binding_sha256,
    process_binding_policy_id: row.process_binding_policy_id,
    scope: row.scope_json,
    max_signatures: Number(row.max_signatures),
    not_before: timestampValue(row.not_before, "not_before"),
    expires_at: timestampValue(row.expires_at, "expires_at"),
    control_sequence: Number(row.control_sequence),
    authority_generation: Number(row.authority_generation),
    issuer: row.issuer,
    key_id: row.signer_key_id
  }, { allowExpired: true, allowFuture: true, maxTtlMs: 60 * 60 * 1000 });
  const grant = Object.freeze({ version: 1, type: AGENT_SESSION_GRANT_TYPE, statement, statement_hash: row.statement_hash, signature: row.signature_base64url });
  if (sha256(canonicalJson(grant)) !== row.grant_hash || agentSessionGrantStatementHash(statement) !== row.statement_hash) throw failure("DATABASE");
  return grant;
}

function sameStoredGrant(row, entry, values) {
  return row.status === "issued"
    && row.device_id === values.deviceId
    && row.agent_id === values.agentId
    && row.agent_kind === values.agentKind
    && row.grant_hash === entry.grant_hash
    && row.statement_hash === entry.statement_hash
    && row.signature_base64url === entry.grant.signature
    && row.created_by === values.actor.memberId;
}

async function setTenantContext(tx, organizationId) {
  const configured = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
  if (rowCount(configured) !== 1 || configured.rows[0]?.organization_id !== organizationId) throw failure("TENANT_SCOPE");
  const verified = await tx.query("SELECT current_setting('agentpass.organization_id',true) AS organization_id", []);
  if (rowCount(verified) !== 1 || verified.rows[0]?.organization_id !== organizationId) throw failure("TENANT_SCOPE");
}

async function lockAuthority(tx, organizationId, deviceId, agentId, agentKind) {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) AS locked", [`agentpass:qualification-grant-batch:${organizationId}:${deviceId}`]);
  const organization = await tx.query("SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE", [organizationId]);
  if (rowCount(organization) !== 1) throw failure("NOT_FOUND");
  const audience = await tx.query(`SELECT d.status AS device_status,a.status AS agent_status
    FROM devices d JOIN agents a ON a.organization_id=d.organization_id AND a.device_id=d.id
    WHERE d.organization_id=$1 AND d.id=$2 AND a.id=$3 AND a.kind=$4 FOR SHARE OF d,a`, [organizationId, deviceId, agentId, agentKind]);
  if (rowCount(audience) !== 1 || audience.rows[0].device_status !== "active" || audience.rows[0].agent_status !== "active") throw failure("NOT_FOUND");
}

async function authorizeHumanWebAuthn(tx, values) {
  const result = await tx.query(`SELECT session.role,membership.role AS membership_role
    FROM human_sessions session
    JOIN memberships membership
      ON membership.organization_id=session.organization_id
     AND membership.id=session.membership_id
     AND membership.member_id=session.member_id
    WHERE session.id=$1 AND session.member_id=$2 AND session.organization_id=$3
      AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
      AND (session.idle_expires_at IS NULL OR session.idle_expires_at>clock_timestamp())
      AND membership.status='active' AND membership.role=session.role
      AND membership.role IN ('owner','admin')
      AND session.recent_auth_challenge_id=$4
      AND session.recent_auth_organization_id=$3
      AND session.recent_auth_operation=$5
      AND session.recent_auth_consumed_at IS NOT NULL
      AND session.recent_auth_at=$6::timestamptz
    FOR SHARE OF session,membership`, [
    values.actor.sessionId, values.actor.memberId, values.organizationId,
    values.recentAuth.authorizationId, ISSUE_OPERATION, values.recentAuth.authenticatedAt
  ]);
  if (rowCount(result) !== 1 || result.rows[0].role !== values.actor.role || !ADMIN_ROLES.has(result.rows[0].membership_role)) throw failure("FORBIDDEN");
}

async function assertAudienceAndCandidate(tx, values) {
  const audience = await tx.query(`SELECT a.id,a.kind,d.id AS device_id
    FROM agents a JOIN devices d ON d.organization_id=a.organization_id AND d.id=a.device_id
    WHERE a.organization_id=$1 AND a.id=$2 AND a.device_id=$3 AND a.status='active' AND d.status='active'
      AND a.kind=$4 FOR SHARE OF a,d`, [values.organizationId, values.agentId, values.deviceId, values.agentKind]);
  if (rowCount(audience) !== 1) throw failure("NOT_FOUND");
  const candidate = await tx.query(`SELECT candidate_id
    FROM release_candidates
    WHERE source_commit=$1 AND artifact_sha256=$2 AND manifest_sha256=$3 AND team_id=$4 AND status='active'
    FOR SHARE`, [values.request.source_commit, values.request.artifact_sha256, values.request.release_trust_sha256, values.request.team_id]);
  if (rowCount(candidate) !== 1) throw failure("NOT_FOUND");
}

async function currentAuthorityGeneration(tx, organizationId) {
  const result = await tx.query(`SELECT generation FROM control_plane_authority_generations
    WHERE organization_id=$1 AND superseded_at IS NULL ORDER BY generation DESC LIMIT 1 FOR SHARE`, [organizationId]);
  if (rowCount(result) !== 1) throw failure("DATABASE");
  return positiveInteger(result.rows[0].generation, 1, Number.MAX_SAFE_INTEGER);
}

async function allocateControlSequences(tx, values, authorityGeneration) {
  await tx.query(`INSERT INTO qualification_grant_control_heads (organization_id,device_id,last_control_sequence)
    VALUES ($1,$2,0) ON CONFLICT (organization_id,device_id) DO NOTHING`, [values.organizationId, values.deviceId]);
  const current = await tx.query(`SELECT head.last_control_sequence,
      GREATEST(head.last_control_sequence,
        COALESCE((SELECT MAX(grant_record.control_sequence) FROM agent_session_grants grant_record
          WHERE grant_record.organization_id=$1 AND grant_record.device_id=$2),0),
        COALESCE((SELECT MAX(statement.sequence) FROM control_bundle_statements statement
          WHERE statement.organization_id=$1 AND statement.device_id=$2),0)) AS baseline
    FROM qualification_grant_control_heads head
    WHERE head.organization_id=$1 AND head.device_id=$2 FOR UPDATE`, [values.organizationId, values.deviceId]);
  if (rowCount(current) !== 1) throw failure("DATABASE");
  const baseline = positiveInteger(current.rows[0].baseline, 0, Number.MAX_SAFE_INTEGER - 7);
  const updated = await tx.query(`UPDATE qualification_grant_control_heads
    SET last_control_sequence=$3,updated_at=clock_timestamp()
    WHERE organization_id=$1 AND device_id=$2 AND last_control_sequence <= $4
    RETURNING last_control_sequence`, [values.organizationId, values.deviceId, baseline + 7, baseline]);
  if (rowCount(updated) !== 1) throw failure("DATABASE");
  return Object.freeze(Array.from({ length: 7 }, (_, index) => Object.freeze({
    grant_id: values.steps[index].grant_id,
    control_sequence: baseline + index + 1,
    authority_generation
  })));
}

function assertClaimBinding(row, values) {
  if (row.device_id !== values.deviceId
    || row.candidate_sha256 !== values.candidateSha256
    || row.artifact_sha256 !== values.artifactSha256
    || row.release_trust_sha256 !== values.releaseTrustSha256
    || row.candidate_checkpoint_sha256 !== values.candidateCheckpointSha256
    || row.source_commit !== values.sourceCommit
    || row.team_id !== values.teamId) throw failure("CLAIM_CONFLICT");
}

function normalizeIdempotencyPointer(value) {
  if (!plainObject(value) || !isUuid(value.batch_id) || !isUuid(value.request_id)) throw failure("DATABASE");
  return value;
}

function mapError(error) {
  if (error instanceof QualificationGrantBatchRepositoryError) return error;
  if (error?.code === "23505" && /idempotency|request_id/u.test(String(error.constraint ?? ""))) return failure("IDEMPOTENCY_CONFLICT");
  return failure("DATABASE", error);
}

function failure(code, cause = undefined) { return new QualificationGrantBatchRepositoryError(code, cause); }
function publicMessage(code) { return `Qualification Grant batch ${String(code).toLowerCase()}`; }
function assertClient(client) { if (!client || typeof client.query !== "function") throw failure("DATABASE"); }
function assertMethod(value, method) { if (!value || typeof value[method] !== "function") throw failure("DATABASE"); }
function assertTransactionClient(client) { assertClient(client); }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function isUuid(value) { return typeof value === "string" && UUID.test(value); }
function uuid(value) { if (!isUuid(value)) throw failure("INVALID_INPUT"); return value.toLowerCase(); }
function tenant(value) { try { return assertTenantId(value).toLowerCase(); } catch { throw failure("TENANT_SCOPE"); } }
function hash(value) { if (typeof value !== "string" || !HASH.test(value)) throw failure("INVALID_INPUT"); return value.toLowerCase(); }
function sourceCommit(value) { if (typeof value !== "string" || !SOURCE_COMMIT.test(value)) throw failure("INVALID_INPUT"); return value.toLowerCase(); }
function team(value) { if (typeof value !== "string" || !TEAM_ID.test(value)) throw failure("INVALID_INPUT"); return value; }
function text(value, max) { if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) throw failure("INVALID_INPUT"); return value; }
function safeIdentifier(value) { if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value)) throw failure("INVALID_INPUT"); return value; }
function enumValue(value, set) { if (!set.has(value)) throw failure("INVALID_INPUT"); return value; }
function positiveInteger(value, min, max) { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < min || number > max) throw failure("INVALID_INPUT"); return number; }
function idempotency(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw failure("INVALID_INPUT"); return value; }
function timestamp(value) { if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) throw failure("INVALID_INPUT"); return value; }
function timestampValue(value, label) { try { return timestamp(value instanceof Date ? value.toISOString() : value); } catch { throw failure("DATABASE"); } }
function readClockMilliseconds(clock) { const value = clock(); const milliseconds = value instanceof Date ? value.getTime() : typeof value === "number" ? value : Date.parse(value); if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw failure("INVALID_INPUT"); return milliseconds; }
function sha256(value) { return crypto.createHash("sha256").update(String(value), "utf8").digest("hex"); }
function deterministicUuid(value) { const bytes = crypto.createHash("sha256").update("AgentPass-Qualification-Batch-v1\0").update(value).digest().subarray(0, 16); bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80; const hex = bytes.toString("hex"); return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`; }

export default createQualificationGrantBatchRepository;
