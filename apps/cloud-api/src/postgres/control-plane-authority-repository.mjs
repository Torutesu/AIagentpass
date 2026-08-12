import crypto from "node:crypto";

import { canonicalJson, normalizeAuditEvent, normalizeScope } from "../../../../packages/protocol/src/index.mjs";
import { auditCursorBinding, createAuditCursorCodec, normalizeAuditPageInput } from "../audit-pagination.mjs";
import { createCapabilityAuthorityRepository } from "./capability-authority-repository.mjs";
import { assertTenantId, PostgresRepositoryError, withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = "0".repeat(64);
const MAX_AUDIT_BATCH = 64;
const MAX_CONTROL_BUNDLE_REVOCATIONS = 256;
const LOCK_PREFIX = "agentpass:control-plane-authority:";
const TARGET_TABLES = Object.freeze({ device: "devices", agent: "agents", capability: "capabilities" });
const REVOCATION_TARGETS = new Set(["organization", "device", "agent", "capability"]);
const ACK_STATUSES = new Set(["applied", "blocked"]);
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;

/**
 * These are intentionally public metadata, not a migration shim.  They make
 * the deployment contract explicit when the repository is used with the
 * current contract migrations.
 */
export const CONTROL_PLANE_SCHEMA_GAPS = Object.freeze([]);

export class ControlPlaneAuthorityRepositoryError extends PostgresRepositoryError {
  constructor(code, message, details = undefined, cause = undefined) {
    super(code, message, details, cause);
    this.name = "ControlPlaneAuthorityRepositoryError";
  }
}

/**
 * Transactional PostgreSQL authority for the control-plane state consumed by
 * the Cloud API.  Every query is explicitly tenant-qualified, and all
 * cross-request sequence/head mutations use a transaction-scoped advisory
 * lock.  The method names intentionally mirror the file CloudStore and the
 * capability/audit interfaces consumed by server.mjs.
 */
export function createControlPlaneAuthorityRepository({ client, cursorCodec, cursorSecret, now = () => new Date().toISOString() } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new ControlPlaneAuthorityRepositoryError("ERR_CLOCK", "now must be a function");

  const capabilityAuthority = createCapabilityAuthorityRepository({ client, now });
  const auditCursor = cursorCodec ?? createAuditCursorCodec({ secret: cursorSecret, now });
  if (!auditCursor || typeof auditCursor.encode !== "function" || typeof auditCursor.decode !== "function") {
    throw new ControlPlaneAuthorityRepositoryError("ERR_CURSOR", "cursorCodec must expose encode() and decode()");
  }

  async function createRevocation(input = {}) {
    const values = normalizeRevocationInput(input, now);
    return databaseOperation(() => transaction(client, async (tx) => {
      await lockOrganization(tx, values.organizationId);
      await assertActiveMember(tx, values.organizationId, values.createdBy);
      await assertRevocationTarget(tx, values);

      const active = await tx.query(`SELECT organization_id,id AS revocation_id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at,version
        FROM revocations
        WHERE organization_id=$1 AND target_type=$2 AND target_id IS NOT DISTINCT FROM $3 AND status='active'
        FOR UPDATE`, [values.organizationId, values.targetType, values.databaseTargetId]);
      if (rowCount(active) > 0 && active.rows[0].revocation_id !== values.revocationId) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_ALREADY_REVOKED", "the target is already revoked");
      }

      const sequenceResult = await tx.query(`SELECT COALESCE(MAX(sequence),0)+1 AS sequence
        FROM revocations WHERE organization_id=$1`, [values.organizationId]);
      const sequence = positiveInteger(sequenceResult.rows?.[0]?.sequence, "sequence");
      let result = await tx.query(`INSERT INTO revocations
        (organization_id,id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at)
        VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$7,$8::timestamptz,$8::timestamptz)
        ON CONFLICT (organization_id,id) DO NOTHING
        RETURNING organization_id,id AS revocation_id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at,version`, [
        values.organizationId, values.revocationId, values.targetType, values.databaseTargetId,
        sequence, values.reason, values.createdBy, values.createdAt
      ]);

      let replayed = false;
      if (rowCount(result) !== 1) {
        result = await tx.query(`SELECT organization_id,id AS revocation_id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at,version
          FROM revocations WHERE organization_id=$1 AND id=$2 FOR UPDATE`, [values.organizationId, values.revocationId]);
        if (rowCount(result) !== 1 || !sameRevocation(result.rows[0], values)) {
          throw new ControlPlaneAuthorityRepositoryError("ERR_REVOCATION_CONFLICT", "revocation identity conflicts with another request");
        }
        replayed = true;
      }
      return publicRevocation(result.rows[0], replayed);
    }));
  }

  async function getRevocation(input = {}) {
    const organizationId = tenant(input.organization_id ?? input.organizationId);
    const revocationId = uuid(input.revocation_id ?? input.revocationId ?? input.id, "revocation_id");
    return databaseOperation(async () => {
      const result = await client.query(`SELECT organization_id,id AS revocation_id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at,version
        FROM revocations WHERE organization_id=$1 AND id=$2 LIMIT 1`, [organizationId, revocationId]);
      if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "revocation was not found");
      return publicRevocation(result.rows[0]);
    });
  }

  async function listRevocations(input = {}) {
    const organizationId = tenant(input.organization_id ?? input.organizationId);
    const limit = boundedLimit(input.limit);
    return databaseOperation(async () => {
      const result = await client.query(`SELECT organization_id,id AS revocation_id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at,version
        FROM revocations WHERE organization_id=$1 ORDER BY sequence ASC,id ASC LIMIT $2`, [organizationId, limit]);
      return Object.freeze((result.rows ?? []).map((row) => publicRevocation(row)));
    });
  }

  async function assignBundleHead(input = {}) {
    const values = normalizeBundleHeadInput(input);
    return databaseOperation(() => transaction(client, async (tx) => {
      await lockDevice(tx, values.organizationId, values.deviceId);
      await assertDevice(tx, values.organizationId, values.deviceId);
      return assignBundleHeadInTransaction(tx, values);
    }));
  }

  async function assignBundleHeadInTransaction(tx, values) {
    const currentResult = await tx.query(`SELECT organization_id,device_id,format_epoch,sequence,statement_hash,issued_at,expires_at
      FROM bundle_heads WHERE organization_id=$1 AND device_id=$2 FOR UPDATE`, [values.organizationId, values.deviceId]);
    const current = currentResult.rows?.[0];
    const sequence = Math.max(values.minimumSequence, current ? positiveInteger(current.sequence, "sequence") + 1 : 1);
    const result = await tx.query(`INSERT INTO bundle_heads
      (organization_id,device_id,format_epoch,sequence,statement_hash,issued_at,expires_at)
      VALUES ($1,$2,2,$3,$4,$5::timestamptz,$6::timestamptz)
      ON CONFLICT (organization_id,device_id) DO UPDATE SET
        format_epoch=EXCLUDED.format_epoch,
        sequence=EXCLUDED.sequence,
        statement_hash=EXCLUDED.statement_hash,
        issued_at=EXCLUDED.issued_at,
        expires_at=EXCLUDED.expires_at
      RETURNING organization_id,device_id,format_epoch,sequence,statement_hash,issued_at,expires_at`, [
      values.organizationId, values.deviceId, sequence, values.stateFingerprint, values.issuedAt, values.expiresAt
    ]);
    if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "bundle head was not created");
    return publicBundleHead(result.rows[0]);
  }

  /**
   * Atomically capture the authority state that a control bundle will sign and
   * assign its monotonic device head.  The organization lock is deliberately
   * the first authority operation, matching createRevocation(), so a bundle
   * can only be signed from a state that is ordered before or after a
   * concurrent revocation; it cannot straddle one.
   *
   * The returned snapshot contains the exact derived fields consumed by
   * ControlBundle signing.  Callers must sign using snapshot.state_fingerprint
   * and head.sequence/issued_at/expires_at from this same result.
   */
  async function snapshotAndAssignBundleHead(input = {}) {
    const values = normalizeBundleAuthoritySnapshotInput(input);
    return databaseOperation(() => transaction(client, async (tx) => {
      await lockOrganization(tx, values.organizationId);
      await lockOrganizationRow(tx, values.organizationId);
      await assertDevice(tx, values.organizationId, values.deviceId);

      const policyResult = await tx.query(`SELECT organization_id,id,sequence,name,scope_json,status,created_at,updated_at,version
        FROM policies
        WHERE organization_id=$1
        ORDER BY created_at ASC,id ASC`, [values.organizationId]);
      const policies = Object.freeze((policyResult.rows ?? []).map(publicPolicy));
      const activePolicy = policies
        .filter((policy) => policy.status === "active")
        .sort((left, right) => right.sequence - left.sequence || left.policy_id.localeCompare(right.policy_id))[0];
      if (!activePolicy) throw new ControlPlaneAuthorityRepositoryError("ERR_POLICY_MISSING", "no active policy exists for the organization");

      const revocationResult = await tx.query(`SELECT organization_id,id AS revocation_id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at,version
        FROM revocations
        WHERE organization_id=$1
        ORDER BY sequence ASC,id ASC`, [values.organizationId]);
      const revocations = Object.freeze((revocationResult.rows ?? []).map((row) => publicRevocation(row)));

      // Capability revocations are durable authority state too.  Read them
      // inside this transaction so the returned snapshot never omits a
      // capability that was already revoked at the snapshot boundary.
      const capabilityResult = await tx.query(`SELECT id AS capability_id
        FROM capabilities
        WHERE organization_id=$1 AND revoked_at IS NOT NULL AND expires_at>$2::timestamptz
        ORDER BY id ASC
        LIMIT $3`, [values.organizationId, values.issuedAt, MAX_CONTROL_BUNDLE_REVOCATIONS + 1]);
      const durableCapabilityRevocations = (capabilityResult.rows ?? []).map((row) => uuid(row.capability_id ?? row.id, "capability_id"));
      if (durableCapabilityRevocations.length > MAX_CONTROL_BUNDLE_REVOCATIONS) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_REVOCATION_CAPACITY", "active capability revocations exceed the ControlBundle limit");
      }

      const snapshot = createBundleAuthoritySnapshot({
        organizationId: values.organizationId,
        deviceId: values.deviceId,
        activePolicy,
        policies,
        revocations,
        durableCapabilityRevocations
      });
      if (values.expectedStateFingerprint !== undefined && values.expectedStateFingerprint !== snapshot.state_fingerprint) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_STATE_FINGERPRINT_MISMATCH", "bundle authority state changed or fingerprint is invalid");
      }

      const head = await assignBundleHeadInTransaction(tx, {
        ...values,
        stateFingerprint: snapshot.state_fingerprint
      });
      return Object.freeze({ snapshot, head });
    }));
  }

  async function acknowledgeBundle(input = {}) {
    const values = normalizeAcknowledgementInput(input, now);
    return databaseOperation(() => transaction(client, async (tx) => {
      await lockDevice(tx, values.organizationId, values.deviceId);
      await assertDevice(tx, values.organizationId, values.deviceId);
      const head = await tx.query(`SELECT format_epoch,sequence,statement_hash
        FROM bundle_heads WHERE organization_id=$1 AND device_id=$2 FOR SHARE`, [values.organizationId, values.deviceId]);
      if (rowCount(head) !== 1 || Number(head.rows[0].format_epoch) !== values.formatEpoch
        || Number(head.rows[0].sequence) !== values.sequence || head.rows[0].statement_hash !== values.statementHash) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_BUNDLE_HEAD_MISMATCH", "bundle acknowledgement does not match the current bundle head");
      }

      let result = await tx.query(`INSERT INTO bundle_acknowledgements
        (organization_id,device_id,format_epoch,sequence,statement_hash,status,reason,applied_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8::timestamptz)
        ON CONFLICT (organization_id,device_id,format_epoch,sequence) DO NOTHING
        RETURNING organization_id,device_id,format_epoch,sequence,statement_hash,status,reason,applied_at,received_at`, [
        values.organizationId, values.deviceId, values.formatEpoch, values.sequence, values.statementHash,
        values.status, values.reason, values.appliedAt
      ]);
      if (rowCount(result) !== 1) {
        result = await tx.query(`SELECT organization_id,device_id,format_epoch,sequence,statement_hash,status,reason,applied_at,received_at
          FROM bundle_acknowledgements
          WHERE organization_id=$1 AND device_id=$2 AND format_epoch=$3 AND sequence=$4 FOR UPDATE`, [
          values.organizationId, values.deviceId, values.formatEpoch, values.sequence
        ]);
        if (rowCount(result) !== 1 || !sameAcknowledgement(result.rows[0], values)) {
          throw new ControlPlaneAuthorityRepositoryError("ERR_ACK_CONFLICT", "bundle acknowledgement conflicts with a previous acknowledgement");
        }
      }
      return publicAcknowledgement(result.rows[0]);
    }));
  }

  async function getBundleAcknowledgement(input = {}) {
    const values = normalizeAcknowledgementKey(input);
    return databaseOperation(async () => {
      const result = await client.query(`SELECT organization_id,device_id,format_epoch,sequence,statement_hash,status,reason,applied_at,received_at
        FROM bundle_acknowledgements
        WHERE organization_id=$1 AND device_id=$2 AND format_epoch=$3 AND sequence=$4 LIMIT 1`, [
        values.organizationId, values.deviceId, values.formatEpoch, values.sequence
      ]);
      if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "bundle acknowledgement was not found");
      return publicAcknowledgement(result.rows[0]);
    });
  }

  async function ingestDeviceAuditEvents(input = {}) {
    const values = normalizeAuditInput(input);
    return databaseOperation(() => transaction(client, async (tx) => {
      await lockDevice(tx, values.organizationId, values.deviceId);
      await assertDevice(tx, values.organizationId, values.deviceId);
      await assertAuditAgents(tx, values.organizationId, values.deviceId, values.events);
      const headResult = await tx.query(`SELECT last_event_id,last_event_hash,chain_status,gap_count
        FROM device_audit_heads WHERE organization_id=$1 AND device_id=$2 FOR UPDATE`, [values.organizationId, values.deviceId]);
      let head = durableHead(headResult.rows?.[0]);
      const accepted = [];
      const duplicates = [];
      const gaps = [];

      for (const event of values.events) {
        const existing = await tx.query(`SELECT organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at
          FROM device_audit_events
          WHERE organization_id=$1 AND device_id=$2 AND event_id=$3 FOR UPDATE`, [values.organizationId, values.deviceId, event.event_id]);
        if (rowCount(existing) === 1) {
          if (canonicalJson(existing.rows[0].redacted_json) !== canonicalJson(event)) {
            throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_DEDUP_CONFLICT", "an event id was already ingested with different evidence");
          }
          duplicates.push(event.event_id);
          continue;
        }

        const gap = event.previous_hash !== head.last_hash;
        if (gap) {
          gaps.push(Object.freeze({
            gap_id: event.event_id,
            organization_id: values.organizationId,
            device_id: values.deviceId,
            event_id: event.event_id,
            expected_previous_hash: head.last_hash,
            received_previous_hash: event.previous_hash,
            recorded_at: values.receivedAt
          }));
        }
        const inserted = await tx.query(`INSERT INTO device_audit_events
          (organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at)
          VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::timestamptz)
          ON CONFLICT (organization_id,device_id,event_id) DO NOTHING
          RETURNING organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at`, [
          values.organizationId, values.deviceId, event.event_id, event.previous_hash, event.event_hash,
          event, values.receivedAt
        ]);
        if (rowCount(inserted) !== 1) {
          // A writer outside this repository may have raced us.  Re-read the
          // row and apply the same exact-evidence idempotency rule.
          const raced = await tx.query(`SELECT redacted_json FROM device_audit_events
            WHERE organization_id=$1 AND device_id=$2 AND event_id=$3 FOR SHARE`, [values.organizationId, values.deviceId, event.event_id]);
          if (rowCount(raced) !== 1 || canonicalJson(raced.rows[0].redacted_json) !== canonicalJson(event)) {
            throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_DEDUP_CONFLICT", "an event id was already ingested with different evidence");
          }
          duplicates.push(event.event_id);
          continue;
        }
        accepted.push(event.event_id);
        head = { last_hash: event.event_hash, last_event_id: event.event_id, chain_status: gap || head.chain_status === "gap" ? "gap" : "continuous", gap_count: head.gap_count + (gap ? 1 : 0) };
      }
      return Object.freeze({ device_id: values.deviceId, accepted: Object.freeze(accepted), duplicates: Object.freeze(duplicates), gaps: Object.freeze(gaps), head: Object.freeze(head) });
    }));
  }

  async function appendDeviceAuditEvent(input = {}) {
    return ingestDeviceAuditEvents({ ...input, events: [input.event ?? input.auditEvent ?? input.audit_event] });
  }

  async function listDeviceAuditEvents(input = {}) {
    const organizationId = tenant(input.organization_id ?? input.organizationId);
    const page = normalizeAuditPageInput(input);
    return databaseOperation(async () => {
      const position = page.cursor === undefined ? null : auditCursor.decode(page.cursor, auditCursorBinding(organizationId, page.device_id));
      const params = [organizationId, page.device_id];
      const clauses = ["organization_id=$1", "device_id=$2"];
      if (position !== null) {
        params.push(position.device_timestamp, position.device_id, position.event_id);
        const base = params.length - 2;
        clauses.push(`((redacted_json ->> 'device_timestamp'), device_id, event_id) < ($${base}::timestamptz,$${base + 1}::uuid,$${base + 2}::uuid)`);
      }
      params.push(page.limit + 1);
      const result = await client.query(`SELECT organization_id,device_id,event_id,redacted_json,received_at
        FROM device_audit_events WHERE ${clauses.join(" AND ")}
        ORDER BY (redacted_json ->> 'device_timestamp') DESC,device_id DESC,event_id DESC LIMIT $${params.length}`, params);
      const rows = (result.rows ?? []).map(publicAuditRow);
      const events = rows.slice(0, page.limit);
      const last = events.at(-1);
      const next_cursor = rows.length > page.limit
        ? auditCursor.encode({ organization_id: organizationId, device_id: page.device_id, device_timestamp: last.event.device_timestamp, event_id: last.event_id })
        : null;
      return Object.freeze({ events: Object.freeze(events), next_cursor });
    });
  }

  async function getAuditHealth(input = {}) {
    const organizationId = tenant(input.organization_id ?? input.organizationId);
    return databaseOperation(async () => {
      const result = await client.query(`SELECT d.id AS device_id,h.last_event_id,h.last_event_hash,h.chain_status,h.gap_count
        FROM devices d LEFT JOIN device_audit_heads h
          ON h.organization_id=d.organization_id AND h.device_id=d.id
        WHERE d.organization_id=$1 ORDER BY d.id ASC`, [organizationId]);
      return Object.freeze((result.rows ?? []).map((row) => Object.freeze({ device_id: uuid(row.device_id, "device_id"), ...durableHead(row) })));
    });
  }

  return Object.freeze({
    acknowledgeBundle,
    acknowledgeControlBundle: acknowledgeBundle,
    appendDeviceAuditEvent,
    assignBundleHead,
    createRevocation,
    getAuditHealth,
    getBundleAcknowledgement,
    getRevocation,
    ingestDeviceAuditEvents,
    snapshotAndAssignBundleHead,
    issueCapabilityMetadata: capabilityAuthority.issueCapabilityMetadata,
    listDeviceAuditEvents,
    listRevocations,
    listRevokedCapabilityIds: capabilityAuthority.listRevokedCapabilityIds,
    revoke: createRevocation,
    revokeActiveCapabilitiesForMember: capabilityAuthority.revokeActiveCapabilitiesForMember
  });
}

export const createPostgresControlPlaneAuthorityRepository = createControlPlaneAuthorityRepository;
export default createControlPlaneAuthorityRepository;

function normalizeRevocationInput(input, now) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "revocation input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const targetType = textEnum(input.target_type ?? input.targetType, REVOCATION_TARGETS, "target_type");
  const suppliedTarget = input.target_id ?? input.targetId;
  const targetId = uuid(suppliedTarget, "target_id");
  if (targetType === "organization" && targetId !== organizationId) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "revocation target was not found");
  const createdBy = uuid(input.created_by ?? input.createdBy ?? input.actor_id ?? input.actorId, "created_by");
  const suppliedRevocationId = input.revocation_id ?? input.revocationId ?? input.id;
  const idempotencyKey = input.idempotency_key ?? input.idempotencyKey;
  if (suppliedRevocationId === undefined && (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY.test(idempotencyKey))) throw new ControlPlaneAuthorityRepositoryError("ERR_IDEMPOTENCY", "revocation requires a valid idempotency key");
  const revocationId = uuid(suppliedRevocationId ?? deterministicUuid(canonicalJson({ version: 1, organization_id: organizationId, principal_id: input.principal_id ?? input.principalId ?? createdBy, idempotency_key: idempotencyKey })), "revocation_id");
  const reason = boundedText(input.reason, "reason", 256);
  const createdAt = timestamp(input.created_at ?? input.createdAt ?? input.revoked_at ?? input.revokedAt ?? now(), "created_at");
  return { organizationId, targetType, targetId, databaseTargetId: targetType === "organization" ? null : targetId, createdBy, revocationId, reason, createdAt };
}

function normalizeBundleHeadInput(input) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "bundle head input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  const stateFingerprint = hash(input.state_fingerprint ?? input.stateFingerprint, "state_fingerprint");
  const minimumSequence = positiveInteger(input.minimum_sequence ?? input.minimumSequence ?? 1, "minimum_sequence");
  const issuedAt = timestamp(input.issued_at ?? input.issuedAt, "issued_at");
  const expiresAt = timestamp(input.expires_at ?? input.expiresAt, "expires_at");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) throw new ControlPlaneAuthorityRepositoryError("ERR_TIMESTAMP", "bundle head expiry must be after issuance");
  return { organizationId, deviceId, stateFingerprint, minimumSequence, issuedAt, expiresAt };
}

function normalizeBundleAuthoritySnapshotInput(input) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "bundle authority snapshot input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  const minimumSequence = positiveInteger(input.minimum_sequence ?? input.minimumSequence ?? 1, "minimum_sequence");
  const issuedAt = timestamp(input.issued_at ?? input.issuedAt, "issued_at");
  const expiresAt = timestamp(input.expires_at ?? input.expiresAt, "expires_at");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) throw new ControlPlaneAuthorityRepositoryError("ERR_TIMESTAMP", "bundle head expiry must be after issuance");
  const expectedValue = input.state_fingerprint ?? input.stateFingerprint;
  const expectedStateFingerprint = expectedValue === undefined ? undefined : hash(expectedValue, "state_fingerprint");
  return { organizationId, deviceId, minimumSequence, issuedAt, expiresAt, expectedStateFingerprint };
}

function normalizeAcknowledgementInput(input, now) {
  const key = normalizeAcknowledgementKey(input);
  const status = textEnum(input.status, ACK_STATUSES, "status");
  const reason = input.reason === undefined ? null : boundedText(input.reason, "reason", 128);
  if (status === "blocked" && reason === null) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "blocked acknowledgement requires a reason");
  if (status === "applied" && reason !== null) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "applied acknowledgement cannot include a reason");
  const appliedAt = timestamp(input.applied_at ?? input.appliedAt ?? now(), "applied_at");
  return { ...key, status, reason, appliedAt };
}

function normalizeAcknowledgementKey(input) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "bundle acknowledgement input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  const formatEpoch = positiveInteger(input.format_epoch ?? input.formatEpoch, "format_epoch");
  if (formatEpoch !== 2) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "format_epoch must be 2");
  const sequence = positiveInteger(input.sequence, "sequence");
  const statementHash = hash(input.statement_hash ?? input.statementHash, "statement_hash");
  return { organizationId, deviceId, formatEpoch, sequence, statementHash };
}

function normalizeAuditInput(input) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "audit ingestion input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  if (!Array.isArray(input.events) || input.events.length < 1 || input.events.length > MAX_AUDIT_BATCH) throw new ControlPlaneAuthorityRepositoryError("ERR_LIMIT_EXCEEDED", `events must contain 1-${MAX_AUDIT_BATCH} items`);
  let events;
  try { events = input.events.map((event) => normalizeAndVerifyAuditEvent(event)); }
  catch (error) {
    if (error instanceof ControlPlaneAuthorityRepositoryError) throw error;
    throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_EVENT_INVALID", "audit event is invalid", undefined, error);
  }
  const receivedAt = timestamp(input.received_at ?? input.receivedAt ?? new Date().toISOString(), "received_at");
  return { organizationId, deviceId, events, receivedAt };
}

function normalizeAndVerifyAuditEvent(input) {
  let event;
  try { event = normalizeAuditEvent(input); } catch { throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_EVENT_INVALID", "audit event is invalid"); }
  const expected = crypto.createHash("sha256").update(canonicalJson(withoutEventHash(event)), "utf8").digest("hex");
  if (event.event_hash !== expected) throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_HASH_MISMATCH", "event_hash does not match the audit event", { event_id: event.event_id, expected_hash: expected, received_hash: event.event_hash });
  return Object.freeze(event);
}

function withoutEventHash(event) {
  const { event_hash: _eventHash, ...preimage } = event;
  return preimage;
}

async function assertRevocationTarget(tx, values) {
  if (values.targetType === "organization") return;
  const table = TARGET_TABLES[values.targetType];
  const result = await tx.query(`SELECT id FROM ${table} WHERE organization_id=$1 AND id=$2 FOR SHARE`, [values.organizationId, values.targetId]);
  if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "revocation target was not found");
}

async function assertActiveMember(tx, organizationId, memberId) {
  const result = await tx.query(`SELECT member_id FROM memberships WHERE organization_id=$1 AND member_id=$2 AND status='active' FOR SHARE`, [organizationId, memberId]);
  if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_MEMBER_NOT_ACTIVE", "revocation actor is not an active organization member");
}

async function assertDevice(tx, organizationId, deviceId) {
  const result = await tx.query(`SELECT id FROM devices WHERE organization_id=$1 AND id=$2 FOR SHARE`, [organizationId, deviceId]);
  if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "device was not found");
}

async function assertAuditAgents(tx, organizationId, deviceId, events) {
  const agentIds = [...new Set(events.map((event) => event.agent_id))];
  const result = await tx.query(`SELECT id FROM agents
    WHERE organization_id=$1 AND device_id=$2 AND id = ANY($3::uuid[])`, [organizationId, deviceId, agentIds]);
  const found = new Set((result.rows ?? []).map((row) => String(row.id).toLowerCase()));
  if (found.size !== agentIds.length || agentIds.some((id) => !found.has(id.toLowerCase()))) {
    throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_DEVICE_MISMATCH", "audit agent is not bound to the authenticated device");
  }
}

async function lockOrganization(tx, organizationId) {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:organization:${organizationId}`]);
}

async function lockOrganizationRow(tx, organizationId) {
  const result = await tx.query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE", [organizationId]);
  if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "organization was not found");
}

async function lockDevice(tx, organizationId, deviceId) {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`${LOCK_PREFIX}device:${organizationId}:${deviceId}`]);
}

async function transaction(client, operation) {
  const txClient = typeof client.connect === "function" ? await client.connect() : client;
  try { return await withTransaction(txClient, operation); }
  finally { if (txClient !== client) txClient.release?.(); }
}

async function databaseOperation(operation) {
  try { return await operation(); }
  catch (error) {
    if (error instanceof ControlPlaneAuthorityRepositoryError) throw error;
    if (error?.code === "ERR_AUDIT_CURSOR_INVALID") throw error;
    throw new ControlPlaneAuthorityRepositoryError("ERR_DATABASE", "control-plane authority storage is unavailable", undefined, error);
  }
}

function publicPolicy(row) {
  if (!row || typeof row !== "object") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "policy query returned an invalid row");
  let scope;
  try { scope = normalizeScope(row.scope_json ?? row.scope); }
  catch (error) { throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "stored policy scope is invalid", undefined, error); }
  return Object.freeze({
    policy_id: uuid(row.policy_id ?? row.id, "policy_id"),
    organization_id: uuid(row.organization_id, "organization_id"),
    name: boundedText(row.name, "name", 128),
    scope,
    sequence: positiveInteger(row.sequence, "sequence"),
    status: textEnum(row.status, new Set(["active", "disabled"]), "status"),
    created_at: timestamp(row.created_at, "created_at"),
    updated_at: timestamp(row.updated_at, "updated_at"),
    version: positiveInteger(row.version, "version")
  });
}

function createBundleAuthoritySnapshot({ organizationId, deviceId, activePolicy, policies, revocations, durableCapabilityRevocations }) {
  const activeRevocations = revocations.filter((item) => item.status === "active");
  const revokedDevices = activeRevocations.filter((item) => item.target_type === "device").map((item) => item.target_id).sort();
  const revokedAgents = activeRevocations.filter((item) => item.target_type === "agent").map((item) => item.target_id).sort();
  const revokedCapabilities = [...new Set([
    ...activeRevocations.filter((item) => item.target_type === "capability").map((item) => item.target_id),
    ...durableCapabilityRevocations
  ])].sort();
  for (const [label, values] of [["device", revokedDevices], ["agent", revokedAgents], ["capability", revokedCapabilities]]) {
    if (values.length > MAX_CONTROL_BUNDLE_REVOCATIONS) {
      throw new ControlPlaneAuthorityRepositoryError("ERR_REVOCATION_CAPACITY", `active ${label} revocations exceed the ControlBundle limit`);
    }
  }

  // Keep this preimage byte-for-byte compatible with the current HTTP bundle
  // signer. The new primitive owns the read boundary; the signer owns only
  // the private-key operation after this result is returned.
  const state = {
    device_id: deviceId,
    policy_id: activePolicy.policy_id,
    policy_sequence: activePolicy.sequence,
    policy_scope: activePolicy.scope,
    revocations: revocations
      .filter((item) => item.target_type !== "capability")
      .map((item) => [item.revocation_id, item.target_type, item.target_id, item.status])
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
    revoked_capabilities: revokedCapabilities
  };
  const stateFingerprint = crypto.createHash("sha256").update(JSON.stringify(state), "utf8").digest("hex");
  return Object.freeze({
    organization_id: organizationId,
    device_id: deviceId,
    active_policy: activePolicy,
    policies: Object.freeze([...policies]),
    revocations: Object.freeze([...revocations]),
    policy_scope: activePolicy.scope,
    global_revoked: activeRevocations.some((item) => item.target_type === "organization"),
    revoked_devices: Object.freeze(revokedDevices),
    revoked_agents: Object.freeze(revokedAgents),
    revoked_capabilities: Object.freeze(revokedCapabilities),
    state_fingerprint: stateFingerprint
  });
}

function publicRevocation(row, replayed = false) {
  if (!row || typeof row !== "object") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "revocation query returned an invalid row");
  const organizationId = uuid(row.organization_id, "organization_id");
  const targetType = textEnum(row.target_type, REVOCATION_TARGETS, "target_type");
  const targetId = targetType === "organization" ? organizationId : uuid(row.target_id, "target_id");
  const value = { revocation_id: uuid(row.revocation_id ?? row.id, "revocation_id"), organization_id: organizationId, target_type: targetType, target_id: targetId, reason: boundedText(row.reason, "reason", 256), status: textEnum(row.status, new Set(["active", "superseded"]), "status"), revoked_at: timestamp(row.revoked_at, "revoked_at"), version: positiveInteger(row.version, "version") };
  return Object.freeze(replayed ? { ...value, replayed: true } : value);
}

function publicBundleHead(row) {
  if (!row || typeof row !== "object") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "bundle head query returned an invalid row");
  return Object.freeze({ organization_id: uuid(row.organization_id, "organization_id"), device_id: uuid(row.device_id, "device_id"), sequence: positiveInteger(row.sequence, "sequence"), state_fingerprint: hash(row.statement_hash, "state_fingerprint"), issued_at: timestamp(row.issued_at, "issued_at"), expires_at: timestamp(row.expires_at, "expires_at") });
}

function publicAcknowledgement(row) {
  if (!row || typeof row !== "object") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "acknowledgement query returned an invalid row");
  const value = { version: 1, organization_id: uuid(row.organization_id, "organization_id"), device_id: uuid(row.device_id, "device_id"), format_epoch: positiveInteger(row.format_epoch, "format_epoch"), sequence: positiveInteger(row.sequence, "sequence"), statement_hash: hash(row.statement_hash, "statement_hash"), applied_at: timestamp(row.applied_at, "applied_at"), status: textEnum(row.status, ACK_STATUSES, "status") };
  if (value.status === "blocked") value.reason = boundedText(row.reason, "reason", 128);
  return Object.freeze(value);
}

function sameAcknowledgement(row, values) {
  return row.organization_id === values.organizationId && row.device_id === values.deviceId
    && Number(row.format_epoch) === values.formatEpoch && Number(row.sequence) === values.sequence
    && row.statement_hash === values.statementHash && row.status === values.status
    && (row.reason ?? null) === values.reason && timestamp(row.applied_at, "applied_at") === values.appliedAt;
}

function sameRevocation(row, values) {
  return row.organization_id === values.organizationId
    && row.target_type === values.targetType
    && (row.target_id ?? null) === (values.databaseTargetId ?? null)
    && row.reason === values.reason && row.created_by === values.createdBy;
}

function publicAuditRow(row) {
  const stored = publicStoredAuditRow(row);
  return Object.freeze({ organization_id: stored.organization_id, device_id: stored.device_id, event_id: stored.event_id, event: structuredClone(stored.event), received_at: timestamp(row.received_at, "received_at") });
}

function publicStoredAuditRow(row) {
  if (!row || typeof row !== "object") throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_ROW", "stored audit event is invalid");
  const organizationId = uuid(row.organization_id, "organization_id");
  const deviceId = uuid(row.device_id, "device_id");
  const eventId = uuid(row.event_id, "event_id");
  let event;
  try { event = normalizeAuditEvent(row.redacted_json); } catch { throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_ROW", "stored audit event is invalid"); }
  if (event.event_id !== eventId || row.event_hash !== event.event_hash || row.previous_hash !== event.previous_hash) throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_ROW", "stored audit event key or hash is inconsistent");
  return { organization_id: organizationId, device_id: deviceId, event_id: eventId, previous_hash: row.previous_hash, event_hash: row.event_hash, event, received_at: timestamp(row.received_at, "received_at") };
}

function durableHead(row) {
  if (!row || row.last_event_id === null || row.last_event_id === undefined) return { last_hash: ZERO_HASH, last_event_id: null, chain_status: "continuous", gap_count: 0 };
  const gapCount = typeof row.gap_count === "string" ? Number(row.gap_count) : row.gap_count;
  if (!Number.isSafeInteger(gapCount) || gapCount < 0) throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_ROW", "stored audit head is invalid");
  const chainStatus = textEnum(row.chain_status, new Set(["continuous", "gap"]), "chain_status");
  return { last_hash: hash(row.last_event_hash, "last_event_hash"), last_event_id: uuid(row.last_event_id, "last_event_id"), chain_status: chainStatus, gap_count: gapCount };
}

function tenant(value) {
  try { return assertTenantId(value); }
  catch (error) { throw new ControlPlaneAuthorityRepositoryError(error.code ?? "ERR_TENANT_SCOPE", error.message, error.details, error); }
}

function uuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw new ControlPlaneAuthorityRepositoryError("ERR_UUID", `${field} must be a UUID`);
  return value.toLowerCase();
}

function hash(value, field) {
  if (typeof value !== "string" || !SHA256.test(value)) throw new ControlPlaneAuthorityRepositoryError("ERR_HASH", `${field} must be a lowercase SHA-256 hex digest`);
  return value;
}

function positiveInteger(value, field) {
  const number = typeof value === "string" && /^[0-9]+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 1) throw new ControlPlaneAuthorityRepositoryError("ERR_INTEGER", `${field} must be a positive safe integer`);
  return number;
}

function boundedLimit(value) {
  if (value === undefined) return 1000;
  if (!Number.isSafeInteger(value) || value < 1 || value > 1000) throw new ControlPlaneAuthorityRepositoryError("ERR_LIMIT", "limit must be between 1 and 1000");
  return value;
}

function boundedText(value, field, max) {
  if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", `${field} is invalid`);
  return value;
}

function textEnum(value, allowed, field) {
  if (typeof value !== "string" || !allowed.has(value)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", `${field} is invalid`);
  return value;
}

function timestamp(value, field) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new ControlPlaneAuthorityRepositoryError("ERR_TIMESTAMP", `${field} must be a valid timestamp`);
  return date.toISOString();
}

function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function deterministicUuid(identity) { const bytes=crypto.createHash("sha256").update("AgentPass-Revocation-Id-v1\0").update(identity).digest().subarray(0,16); bytes[6]=(bytes[6]&0x0f)|0x50; bytes[8]=(bytes[8]&0x3f)|0x80; const hex=bytes.toString("hex"); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`; }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_CLIENT", "database client must provide query(text, params)"); }
