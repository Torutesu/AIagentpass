import crypto from "node:crypto";

import {
  BUNDLE_ACK_REASON_CODES,
  BUNDLE_ACK_RESULTS,
  BUNDLE_ACK_TYPE,
  DEVICE_REFRESH_STATES,
  canonicalJson,
  normalizeAuditEvent,
  normalizeBundleAcknowledgement,
  normalizeScope
} from "../../../../packages/protocol/src/index.mjs";
import { auditCursorBinding, createAuditCursorCodec, normalizeAuditPageInput } from "../audit-pagination.mjs";
import { createCapabilityAuthorityRepository } from "./capability-authority-repository.mjs";
import { REFRESH_NONCE_KEY_ID_PATTERN } from "./refresh-nonce-codec.mjs";
import { assertTenantId, PostgresRepositoryError, withTransaction } from "./repository.mjs";
import { assertDeviceAuditChainOrdered } from "../device-audit-ingestion.mjs";

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
const REFRESH_NONCE_BYTES = 16;
const MAX_REFRESH_WAIT_MS = 30_000;
const MAX_REFRESH_TTL_MS = 5 * 60 * 1000;
const REFRESH_STATE_SET = new Set(DEVICE_REFRESH_STATES);
const ACK_RESULT_SET = new Set(BUNDLE_ACK_RESULTS);
const ACK_REASON_SET = new Set(BUNDLE_ACK_REASON_CODES);

/**
 * Exact unsigned metadata returned by pollDeviceRefresh.  The values are
 * deliberately descriptive rather than a second runtime schema; the actual
 * row is normalized and frozen by publicRefreshPollMetadata().
 */
export const DEVICE_REFRESH_POLL_RETURN_SHAPE = Object.freeze({
  organization_id: "uuid",
  device_id: "uuid",
  desired_generation: "positive integer",
  refresh_state: "frozen device refresh state",
  outbox_id: "uuid",
  refresh_nonce_key_id: "refresh-nonce-v[1-9][0-9]{0,8}",
  refresh_nonce_digest: "lower-case SHA-256 hex",
  published_at: "immutable outbox created_at ISO timestamp",
  expires_at: "ISO timestamp after published_at"
});

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
export function createControlPlaneAuthorityRepository({ client, cursorCodec, cursorSecret, refreshNonceCodec, now = () => new Date().toISOString(), onRevocation } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new ControlPlaneAuthorityRepositoryError("ERR_CLOCK", "now must be a function");
  if (onRevocation !== undefined && typeof onRevocation !== "function") throw new TypeError("onRevocation must be a function");

  const capabilityAuthority = createCapabilityAuthorityRepository({ client, now });
  if (refreshNonceCodec !== undefined && (!refreshNonceCodec || typeof refreshNonceCodec.derive !== "function" || typeof refreshNonceCodec.activeKeyId !== "string")) {
    throw new ControlPlaneAuthorityRepositoryError("ERR_REFRESH_NONCE_CODEC", "refreshNonceCodec must expose derive() and activeKeyId");
  }
  const auditCursor = cursorCodec ?? createAuditCursorCodec({ secret: cursorSecret, now });
  if (!auditCursor || typeof auditCursor.encode !== "function" || typeof auditCursor.decode !== "function") {
    throw new ControlPlaneAuthorityRepositoryError("ERR_CURSOR", "cursorCodec must expose encode() and decode()");
  }

  async function createRevocation(input = {}) {
    const values = normalizeRevocationInput(input, now);
    return databaseOperation(() => transaction(client, async (tx) => {
      await establishTenantContext(tx, values.organizationId, values.createdBy, undefined);
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
      const revocation = publicRevocation(result.rows[0], replayed);
      await onRevocation?.({ tx, revocation });
      return revocation;
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

  async function assignBundleHeadInTransaction(tx, values, options = {}) {
    const currentResult = await tx.query(`SELECT organization_id,device_id,format_epoch,sequence,statement_hash,issued_at,expires_at
      FROM bundle_heads WHERE organization_id=$1 AND device_id=$2 FOR UPDATE`, [values.organizationId, values.deviceId]);
    const current = currentResult.rows?.[0];
    const sequence = Math.max(values.minimumSequence, current ? positiveInteger(current.sequence, "sequence") + 1 : 1);
    let statementHash = values.stateFingerprint;
    if (options.statementHashFactory !== undefined) {
      if (typeof options.statementHashFactory !== "function") throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "bundle statement hash factory must be a function");
      try {
        statementHash = hash(await options.statementHashFactory(Object.freeze({
          snapshot: options.snapshot,
          head: Object.freeze({ format_epoch: 2, sequence, issued_at: values.issuedAt, expires_at: values.expiresAt })
        })), "statement_hash");
      } catch (error) {
        if (error instanceof ControlPlaneAuthorityRepositoryError) throw error;
        throw new ControlPlaneAuthorityRepositoryError("ERR_BUNDLE_STATEMENT", "bundle statement hash could not be derived", undefined, error);
      }
    }
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
      values.organizationId, values.deviceId, sequence, statementHash, values.issuedAt, values.expiresAt
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
   * ControlBundle signing. Production callers supply statementHashFactory so
   * the transaction persists the hash of the exact wire-computable unsigned
   * ControlBundle using the assigned sequence/timestamps. The authority
   * fingerprint remains a concurrency check and is never substituted for the
   * device's canonical ControlBundle hash.
   */
  async function snapshotAndAssignBundleHead(input = {}) {
    const values = normalizeBundleAuthoritySnapshotInput(input);
    const statementHashFactory = input.statement_hash_factory ?? input.statementHashFactory;
    if (typeof statementHashFactory !== "function") throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "bundle statement hash factory is required");
    return databaseOperation(() => transaction(client, async (tx) => {
      await establishTenantContext(tx, values.organizationId, values.principalId ?? values.createdBy, values.deviceId);
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
      const capabilityResult = await tx.query(`SELECT public.agentpass_capability_authority_list_revoked(
        $1,$2::timestamptz,$3
      ) AS result`, [values.organizationId, values.issuedAt, MAX_CONTROL_BUNDLE_REVOCATIONS + 1]);
      const capabilityRecord = capabilityResult.rows?.[0]?.result;
      if (rowCount(capabilityResult) !== 1 || capabilityRecord?.state !== "listed" || !Array.isArray(capabilityRecord.capability_ids)) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "capability revocation snapshot is unavailable");
      }
      const durableCapabilityRevocations = capabilityRecord.capability_ids.map((id) => uuid(id, "capability_id"));
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
      }, { snapshot, statementHashFactory });
      const stateResult = await tx.query(`SELECT desired_generation,observed_generation,refresh_state
        FROM device_control_plane_state
        WHERE organization_id=$1 AND device_id=$2
        FOR UPDATE`, [values.organizationId, values.deviceId]);
      if (rowCount(stateResult) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_REFRESH_STATE_MISSING", "device refresh state was not found");
      const desiredGeneration = positiveInteger(stateResult.rows[0].desired_generation, "desired_generation");
      await bindOutboxToBundleStatement(tx, values.organizationId, values.deviceId, desiredGeneration, head);
      return Object.freeze({ snapshot, head, desired_generation: desiredGeneration });
    }));
  }

  async function acknowledgeBundle(input = {}) {
    if (isG4AcknowledgementInput(input)) return acknowledgeG4Bundle(input);
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

  async function acknowledgeG4Bundle(input) {
    const values = normalizeG4AcknowledgementInput(input);
    return databaseOperation(() => transaction(client, async (tx) => {
      await lockDevice(tx, values.organizationId, values.deviceId);
      await assertDevice(tx, values.organizationId, values.deviceId);
      await assertActiveDeviceKeyEpoch(tx, values);

      const existing = await tx.query(`SELECT organization_id,device_id,device_key_epoch,format_epoch,sequence,statement_hash,result,reason_code,observed_at,ack_nonce_digest
        FROM device_bundle_acknowledgements
        WHERE organization_id=$1 AND device_id=$2 AND device_key_epoch=$3 AND sequence=$4
        FOR SHARE`, [values.organizationId, values.deviceId, values.deviceKeyEpoch, values.sequence]);
      if (rowCount(existing) === 1) {
        if (!sameG4Acknowledgement(existing.rows[0], values)) {
          throw new ControlPlaneAuthorityRepositoryError("ERR_ACK_CONFLICT", "bundle acknowledgement conflicts with previous evidence");
        }
        return refreshAcknowledgementResponse(tx, values.organizationId, values.deviceId, true);
      }

      const currentHead = await tx.query(`SELECT format_epoch,sequence,statement_hash
        FROM bundle_heads
        WHERE organization_id=$1 AND device_id=$2
        FOR SHARE`, [values.organizationId, values.deviceId]);
      if (rowCount(currentHead) === 1 && Number(currentHead.rows[0].sequence) > values.sequence) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_ACK_SEQUENCE_ROLLBACK", "bundle acknowledgement sequence is older than the current bundle head");
      }
      if (rowCount(currentHead) !== 1 || Number(currentHead.rows[0].format_epoch) !== values.formatEpoch
        || Number(currentHead.rows[0].sequence) !== values.sequence || currentHead.rows[0].statement_hash !== values.statementHash) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_BUNDLE_HEAD_MISMATCH", "bundle acknowledgement does not match the current bundle head");
      }

      const history = await tx.query(`SELECT organization_id,device_id,format_epoch,sequence,statement_hash,authority_generation,issued_at,expires_at
        FROM control_bundle_statements
        WHERE organization_id=$1 AND device_id=$2 AND format_epoch=$3 AND sequence=$4 AND statement_hash=$5
        FOR SHARE`, [values.organizationId, values.deviceId, values.formatEpoch, values.sequence, values.statementHash]);
      if (rowCount(history) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_BUNDLE_STATEMENT_NOT_FOUND", "bundle statement history was not found");

      const outbox = await tx.query(`SELECT organization_id,device_id,desired_generation,format_epoch,sequence,statement_hash,status
        FROM device_refresh_outbox
        WHERE organization_id=$1 AND device_id=$2 AND format_epoch=$3 AND sequence=$4 AND statement_hash=$5
        LIMIT 1 FOR SHARE`, [values.organizationId, values.deviceId, values.formatEpoch, values.sequence, values.statementHash]);
      if (rowCount(outbox) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_BUNDLE_OUTBOX_NOT_FOUND", "bundle refresh outbox binding was not found");

      let persisted;
      try {
        persisted = await tx.query(`SELECT accepted,duplicate
          FROM agentpass_record_device_bundle_ack($1::uuid,$2::uuid,$3::bigint,$4::integer,$5::bigint,$6::text,$7::text,$8::text,$9::timestamptz,$10::bytea)`, [
          values.organizationId, values.deviceId, values.deviceKeyEpoch, values.formatEpoch, values.sequence,
          values.statementHash, values.result, values.reasonCode, values.observedAt, values.ackNonceDigest
        ]);
      } catch (error) {
        if (error?.code === "23505" || error?.code === "23514") {
          throw new ControlPlaneAuthorityRepositoryError("ERR_ACK_CONFLICT", "bundle acknowledgement conflicts with previous evidence", undefined, error);
        }
        throw error;
      }
      if (rowCount(persisted) !== 1 || persisted.rows[0].accepted !== true) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_ACK_NOT_ACCEPTED", "bundle acknowledgement was not accepted");
      }
      return refreshAcknowledgementResponse(tx, values.organizationId, values.deviceId, persisted.rows[0].duplicate === true);
    }));
  }

  async function advanceAuthorityGenerationAndEnqueueRefresh(input = {}) {
    const values = normalizeAuthorityAdvanceInput(input, now);
    const nonceCodec = requireRefreshNonceCodec(refreshNonceCodec);
    return databaseOperation(() => transaction(client, async (tx) => {
      // This is the repository-wide organization lock. The migration helper
      // takes its own compatible generation lock as well; keeping this lock
      // first makes reductions and bundle snapshots share one ordering point.
      await lockOrganization(tx, values.organizationId);
      await lockOrganizationRow(tx, values.organizationId);
      let revocation;
      if (values.reduction !== undefined) {
        await assertActiveMember(tx, values.organizationId, values.reduction.createdBy);
        await assertRevocationTarget(tx, values.reduction);
        revocation = await insertRevocationInTransaction(tx, values.reduction);
        await onRevocation?.({ tx, revocation });
        if (revocation.replayed === true) {
          const current = await tx.query(`SELECT generation
            FROM control_plane_authority_generations
            WHERE organization_id=$1
              AND superseded_at IS NULL
            FOR SHARE`, [values.organizationId]);
          if (rowCount(current) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "authority generation was not found");
          return Object.freeze({
            organization_id: values.organizationId,
            generation: positiveInteger(current.rows[0].generation, "generation"),
            devices: Object.freeze([]),
            revocation
          });
        }
      }
      const generationResult = await tx.query(`SELECT organization_id,generation
        FROM agentpass_advance_authority_generation($1::uuid,$2::timestamptz)`, [values.organizationId, values.issuedAt]);
      if (rowCount(generationResult) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "authority generation advance did not return a row");
      const generation = positiveInteger(generationResult.rows[0].generation, "generation");
      const devices = await tx.query(`SELECT id
        FROM devices
        WHERE organization_id=$1
        ORDER BY id ASC
        FOR UPDATE`, [values.organizationId]);
      const enqueued = [];
      for (const row of devices.rows ?? []) {
        const deviceId = uuid(row.id, "device_id");
        const outboxId = refreshOutboxIdForDevice(values, deviceId);
        const derived = nonceCodec.derive({
          organization_id: values.organizationId,
          device_id: deviceId,
          authority_generation: generation,
          outbox_id: outboxId,
          key_id: nonceCodec.activeKeyId
        });
        const result = await tx.query(`SELECT outbox_id,desired_generation,refresh_nonce_key_id,refresh_nonce_digest,replayed
          FROM agentpass_request_device_refresh($1::uuid,$2::uuid,$3::uuid,$4::bigint,$5::text,$6::bytea,$7::timestamptz)`, [
          outboxId, values.organizationId, deviceId, generation, derived.key_id, derived.nonce_digest_bytes, values.expiresAt
        ]);
        if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "device refresh enqueue did not return a row");
        const storedDigest = decodeDigest(result.rows[0].refresh_nonce_digest, "refresh_nonce_digest");
        enqueued.push(Object.freeze({
          device_id: deviceId,
          outbox_id: uuid(result.rows[0].outbox_id, "outbox_id"),
          desired_generation: positiveInteger(result.rows[0].desired_generation, "desired_generation"),
          replayed: result.rows[0].replayed === true,
          refresh_nonce_key_id: normalizeRefreshNonceKeyId(result.rows[0].refresh_nonce_key_id),
          refresh_nonce_digest: storedDigest.toString("hex")
        }));
      }
      return Object.freeze({ organization_id: values.organizationId, generation, devices: Object.freeze(enqueued), ...(revocation === undefined ? {} : { revocation }) });
    }));
  }

  async function ensureInitialDeviceRefresh(input = {}) {
    const values = normalizeInitialDeviceRefreshInput(input, now);
    const nonceCodec = requireRefreshNonceCodec(refreshNonceCodec);
    return databaseOperation(() => transaction(client, async (tx) => {
      await lockOrganization(tx, values.organizationId);
      await lockOrganizationRow(tx, values.organizationId);
      const enrollmentResult = await tx.query(`SELECT enrollment.device_id,enrollment.proof_version,
          EXISTS (SELECT 1 FROM device_enrollment_possession_receipts AS receipt
            WHERE receipt.organization_id=enrollment.organization_id
              AND receipt.enrollment_id=enrollment.id
              AND receipt.device_id=enrollment.device_id) AS possession_recorded
        FROM device_enrollments AS enrollment
        WHERE enrollment.organization_id=$1 AND enrollment.id=$2
        FOR SHARE`, [values.organizationId, values.enrollmentId]);
      if (rowCount(enrollmentResult) !== 1
        || uuid(enrollmentResult.rows[0].device_id, "device_id") !== values.deviceId
        || Number(enrollmentResult.rows[0].proof_version) !== 2
        || enrollmentResult.rows[0].possession_recorded !== true) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_ENROLLMENT_BINDING", "initial device refresh is not bound to a completed v2 enrollment");
      }
      const stateResult = await tx.query(`SELECT desired_generation,observed_generation,refresh_state
        FROM device_control_plane_state
        WHERE organization_id=$1 AND device_id=$2
        FOR UPDATE`, [values.organizationId, values.deviceId]);
      if (rowCount(stateResult) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "device refresh state was not found");
      const state = stateResult.rows[0];
      const desiredGeneration = positiveInteger(state.desired_generation, "desired_generation");
      const observedGeneration = state.observed_generation === null ? null : positiveInteger(state.observed_generation, "observed_generation");
      if (state.refresh_state === "applied" && observedGeneration === desiredGeneration) {
        return Object.freeze({
          organization_id: values.organizationId,
          device_id: values.deviceId,
          desired_generation: desiredGeneration,
          state: "already_applied",
          outbox: null
        });
      }

      // SQL serializes one active outbox per device/generation. A fresh UUID
      // avoids colliding with an expired/failed historical attempt; exact
      // response-loss replay returns the already-active row before insert.
      const outboxId = crypto.randomUUID();
      const derived = nonceCodec.derive({
        organization_id: values.organizationId,
        device_id: values.deviceId,
        authority_generation: desiredGeneration,
        outbox_id: outboxId,
        key_id: nonceCodec.activeKeyId
      });
      const result = await tx.query(`SELECT outbox_id,desired_generation,refresh_nonce_key_id,refresh_nonce_digest,replayed
        FROM agentpass_request_device_refresh($1::uuid,$2::uuid,$3::uuid,$4::bigint,$5::text,$6::bytea,$7::timestamptz)`, [
        outboxId, values.organizationId, values.deviceId, desiredGeneration,
        derived.key_id, derived.nonce_digest_bytes, values.expiresAt
      ]);
      if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "initial device refresh enqueue did not return a row");
      const row = result.rows[0];
      return Object.freeze({
        organization_id: values.organizationId,
        device_id: values.deviceId,
        desired_generation: positiveInteger(row.desired_generation, "desired_generation"),
        state: row.replayed === true ? "already_queued" : "queued",
        outbox: Object.freeze({
          outbox_id: uuid(row.outbox_id, "outbox_id"),
          refresh_nonce_key_id: normalizeRefreshNonceKeyId(row.refresh_nonce_key_id),
          refresh_nonce_digest: decodeDigest(row.refresh_nonce_digest, "refresh_nonce_digest").toString("hex")
        })
      });
    }));
  }

  async function getDeviceRefreshState(input = {}) {
    const values = normalizeRefreshStateKey(input);
    return databaseOperation(async () => {
      const result = await client.query(`SELECT organization_id,device_id,desired_generation,observed_generation,refresh_state,
          refresh_requested_at,last_delivered_at,last_observed_at,last_error_code,updated_at
        FROM device_control_plane_state
        WHERE organization_id=$1 AND device_id=$2
        LIMIT 1`, [values.organizationId, values.deviceId]);
      if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "device refresh state was not found");
      return publicRefreshState(result.rows[0]);
    });
  }

  async function pollDeviceRefresh(input = {}) {
    const values = normalizeRefreshPollInput(input);
    return databaseOperation(async () => {
      // Deliberately one bounded query. Long-poll orchestration belongs to the
      // Cloud layer and must not create a database busy-wait loop here.
      const result = await client.query(`SELECT state.organization_id,state.device_id,state.desired_generation,state.refresh_state,
          outbox.outbox_id,outbox.refresh_nonce_key_id,outbox.refresh_nonce_digest,
          outbox.created_at AS published_at,outbox.expires_at
        FROM device_control_plane_state state
        JOIN LATERAL (
          SELECT refresh_outbox.outbox_id,refresh_outbox.refresh_nonce_key_id,refresh_outbox.refresh_nonce_digest,
              refresh_outbox.created_at,refresh_outbox.expires_at
          FROM device_refresh_outbox refresh_outbox
          WHERE refresh_outbox.organization_id=$1
            AND refresh_outbox.device_id=$2
            AND refresh_outbox.desired_generation>$3
            AND refresh_outbox.status IN ('pending','delivered')
          ORDER BY refresh_outbox.desired_generation ASC,refresh_outbox.created_at ASC,refresh_outbox.outbox_id ASC
          LIMIT 1
        ) outbox ON true
        WHERE state.organization_id=$1 AND state.device_id=$2
        LIMIT 1`, [values.organizationId, values.deviceId, values.afterGeneration]);
      if (rowCount(result) !== 1) return null;
      return publicRefreshPollMetadata(result.rows[0]);
    });
  }

  async function markDeviceRefreshDelivered(input = {}) {
    const values = normalizeRefreshDeliveryInput(input, now);
    return databaseOperation(() => transaction(client, async (tx) => {
      const selected = await tx.query(`SELECT attempt_count,status,expires_at
        FROM device_refresh_outbox
        WHERE organization_id=$1 AND device_id=$2 AND outbox_id=$3 AND desired_generation=$4
        FOR UPDATE`, [values.organizationId, values.deviceId, values.outboxId, values.desiredGeneration]);
      if (rowCount(selected) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_NOT_FOUND", "device refresh delivery was not found");
      const row = selected.rows[0];
      const clockResult = await tx.query(`WITH database_clock AS MATERIALIZED (
          SELECT clock_timestamp() AS delivered_at
        )
        SELECT to_char(delivered_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS delivered_at,
            $1::timestamptz <= delivered_at AS expired
        FROM database_clock`, [row.expires_at]);
      if (rowCount(clockResult) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "database delivery clock did not return a row");
      const deliveredAt = databaseTimestamp(clockResult.rows[0].delivered_at, "delivered_at");
      if (!new Set(["pending", "delivered"]).has(row.status) || clockResult.rows[0].expired === true) {
        throw new ControlPlaneAuthorityRepositoryError("ERR_REFRESH_EXPIRED", "device refresh delivery is no longer deliverable");
      }
      const attemptNo = nonNegativeInteger(row.attempt_count, "attempt_count") + 1;
      if (attemptNo > 100) throw new ControlPlaneAuthorityRepositoryError("ERR_REFRESH_DELIVERY_LIMIT", "device refresh delivery attempt limit was reached");
      const updated = await tx.query(`UPDATE device_refresh_outbox
        SET status='delivered',attempt_count=$5,
            first_delivered_at=COALESCE(first_delivered_at,$6::timestamptz),
            last_delivered_at=$6::timestamptz
        WHERE organization_id=$1 AND device_id=$2 AND outbox_id=$3 AND desired_generation=$4
        RETURNING outbox_id,desired_generation,status,attempt_count`, [
        values.organizationId, values.deviceId, values.outboxId, values.desiredGeneration, attemptNo, deliveredAt
      ]);
      await tx.query(`INSERT INTO device_refresh_delivery_attempts
        (attempt_id,organization_id,outbox_id,attempt_no,status,started_at,completed_at,response_status)
        VALUES ($1,$2,$3,$4,'delivered',$5::timestamptz,$5::timestamptz,200)`, [
        crypto.randomUUID(), values.organizationId, values.outboxId, attemptNo, deliveredAt
      ]);
      await tx.query(`UPDATE device_control_plane_state
        SET refresh_state=CASE WHEN refresh_state='revoked' THEN 'revoked' ELSE 'fetching' END,
            last_delivered_at=$4::timestamptz,updated_at=$4::timestamptz
        WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$3`, [
        values.organizationId, values.deviceId, values.desiredGeneration, deliveredAt
      ]);
      return Object.freeze({ outbox_id: uuid(updated.rows[0].outbox_id, "outbox_id"), desired_generation: positiveInteger(updated.rows[0].desired_generation, "desired_generation"), status: "delivered", attempt_count: attemptNo });
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
      await establishTenantContext(tx, values.organizationId, values.memberId, values.deviceId);
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
    const memberId = uuid(input.principal_id ?? input.principalId ?? input.member_id ?? input.memberId, "member_id");
    const page = normalizeAuditPageInput(input);
    return databaseOperation(() => transaction(client, async (tx) => {
      await establishTenantContext(tx, organizationId, memberId, undefined);
      const position = page.cursor === undefined ? null : auditCursor.decode(page.cursor, auditCursorBinding(organizationId, page.device_id));
      const params = [organizationId, page.device_id];
      const clauses = ["organization_id=$1", "device_id=$2"];
      if (position !== null) {
        params.push(position.device_timestamp, position.device_id, position.event_id);
        const base = params.length - 2;
        clauses.push(`((redacted_json ->> 'device_timestamp'), device_id, event_id) < ($${base}::timestamptz,$${base + 1}::uuid,$${base + 2}::uuid)`);
      }
      params.push(page.limit + 1);
      const result = await tx.query(`SELECT organization_id,device_id,event_id,redacted_json,received_at
        FROM device_audit_events WHERE ${clauses.join(" AND ")}
        ORDER BY (redacted_json ->> 'device_timestamp') DESC,device_id DESC,event_id DESC LIMIT $${params.length}`, params);
      const rows = (result.rows ?? []).map(publicAuditRow);
      const events = rows.slice(0, page.limit);
      const last = events.at(-1);
      const next_cursor = rows.length > page.limit
        ? auditCursor.encode({ organization_id: organizationId, device_id: page.device_id, device_timestamp: last.event.device_timestamp, event_id: last.event_id })
        : null;
      return Object.freeze({ events: Object.freeze(events), next_cursor });
    }));
  }

  async function getAuditHealth(input = {}) {
    const organizationId = tenant(input.organization_id ?? input.organizationId);
    const memberId = uuid(input.principal_id ?? input.principalId ?? input.member_id ?? input.memberId, "member_id");
    return databaseOperation(() => transaction(client, async (tx) => {
      await establishTenantContext(tx, organizationId, memberId, undefined);
      const result = await tx.query(`SELECT d.id AS device_id,h.last_event_id,h.last_event_hash,h.chain_status,h.gap_count
        FROM devices d LEFT JOIN device_audit_heads h
          ON h.organization_id=d.organization_id AND h.device_id=d.id
        WHERE d.organization_id=$1 ORDER BY d.id ASC`, [organizationId]);
      return Object.freeze((result.rows ?? []).map((row) => Object.freeze({ device_id: uuid(row.device_id, "device_id"), ...durableHead(row) })));
    }));
  }

  return Object.freeze({
    acknowledgeBundle,
    acknowledgeControlBundle: acknowledgeBundle,
    advanceAuthorityGeneration: advanceAuthorityGenerationAndEnqueueRefresh,
    advanceAuthorityGenerationAndEnqueueRefresh,
    appendDeviceAuditEvent,
    assignBundleHead,
    createRevocation,
    ensureInitialDeviceRefresh,
    getAuditHealth,
    getBundleAcknowledgement,
    getDeviceRefreshState,
    getRevocation,
    ingestDeviceAuditEvents,
    snapshotAndAssignBundleHead,
    issueCapabilityMetadata: capabilityAuthority.issueCapabilityMetadata,
    listDeviceAuditEvents,
    listRevocations,
    listRevokedCapabilityIds: capabilityAuthority.listRevokedCapabilityIds,
    pollDeviceRefresh,
    markDeviceRefreshDelivered,
    reduceAuthority: advanceAuthorityGenerationAndEnqueueRefresh,
    reduceAuthorityAndEnqueueRefresh: advanceAuthorityGenerationAndEnqueueRefresh,
    revoke: createRevocation,
    revokeActiveCapabilitiesForMember: capabilityAuthority.revokeActiveCapabilitiesForMember
  });
}

async function establishTenantContext(tx, organizationId, memberId, deviceId) {
  const configured = memberId !== undefined
    ? await tx.query("SELECT public.agentpass_authorize_device_audit_tenant($1::uuid,$2::uuid) AS organization_id", [organizationId, memberId])
    : await tx.query("SELECT public.agentpass_authorize_device_audit_device($1::uuid,$2::uuid) AS organization_id", [organizationId, deviceId]);
  if (rowCount(configured) !== 1 || configured.rows[0]?.organization_id !== organizationId) {
    throw new ControlPlaneAuthorityRepositoryError("ERR_DATABASE", "tenant context is unavailable");
  }
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

function isG4AcknowledgementInput(input) {
  return isObject(input) && (input.type === BUNDLE_ACK_TYPE || input.result !== undefined || input.nonce !== undefined || input.signature !== undefined);
}

function normalizeG4AcknowledgementInput(input) {
  let normalized;
  try {
    normalized = normalizeBundleAcknowledgement(input);
  } catch (error) {
    throw new ControlPlaneAuthorityRepositoryError("ERR_ACK_INVALID", "bundle acknowledgement input is invalid", undefined, error);
  }
  const organizationId = tenant(normalized.organization_id);
  const deviceId = uuid(normalized.device_id, "device_id");
  const nonceBytes = decodeBase64Url(normalized.nonce, "nonce", REFRESH_NONCE_BYTES);
  return Object.freeze({
    ...normalized,
    organizationId,
    deviceId,
    deviceKeyEpoch: positiveInteger(normalized.device_key_epoch, "device_key_epoch"),
    formatEpoch: positiveInteger(normalized.format_epoch, "format_epoch"),
    sequence: positiveInteger(normalized.sequence, "sequence"),
    statementHash: hash(normalized.statement_hash, "statement_hash"),
    result: textEnum(normalized.result, ACK_RESULT_SET, "result"),
    reasonCode: normalized.reason_code === undefined ? null : textEnum(normalized.reason_code, ACK_REASON_SET, "reason_code"),
    observedAt: timestamp(normalized.observed_at, "observed_at"),
    ackNonceDigest: crypto.createHash("sha256").update(nonceBytes).digest()
  });
}

function sameG4Acknowledgement(row, values) {
  return row.organization_id === values.organizationId
    && row.device_id === values.deviceId
    && Number(row.device_key_epoch) === values.deviceKeyEpoch
    && Number(row.format_epoch) === values.formatEpoch
    && Number(row.sequence) === values.sequence
    && row.statement_hash === values.statementHash
    && row.result === values.result
    && (row.reason_code ?? null) === values.reasonCode
    && timestamp(row.observed_at, "observed_at") === values.observedAt
    && Buffer.isBuffer(row.ack_nonce_digest)
    && row.ack_nonce_digest.length === values.ackNonceDigest.length
    && crypto.timingSafeEqual(row.ack_nonce_digest, values.ackNonceDigest);
}

function normalizeAuthorityAdvanceInput(input, now) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "authority advance input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const issuedAt = timestamp(input.issued_at ?? input.issuedAt ?? now(), "issued_at");
  const expiresAt = timestamp(input.expires_at ?? input.expiresAt ?? new Date(Date.parse(issuedAt) + MAX_REFRESH_TTL_MS).toISOString(), "expires_at");
  const ttl = Date.parse(expiresAt) - Date.parse(issuedAt);
  if (ttl < 1 || ttl > MAX_REFRESH_TTL_MS) throw new ControlPlaneAuthorityRepositoryError("ERR_TIMESTAMP", "refresh expiry must be within five minutes after issuance");
  const outboxIds = input.outbox_ids ?? input.outboxIds;
  const reductionInput = input.reduction ?? input.revocation ?? (input.target_type !== undefined ? input : undefined);
  const reduction = reductionInput === undefined ? undefined : normalizeRevocationInput({ ...input, ...reductionInput, organization_id: organizationId }, now);
  if (input.refresh_nonces !== undefined || input.refreshNonces !== undefined || input.refresh_nonce_digests !== undefined || input.refreshNonceDigests !== undefined) {
    throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "raw or caller-supplied refresh nonce material is not accepted; the repository derives it from the immutable outbox identity");
  }
  if (outboxIds !== undefined && !isObject(outboxIds)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "outbox_ids must be an object");
  return Object.freeze({ organizationId, issuedAt, expiresAt, outboxIds, reduction });
}

function refreshOutboxIdForDevice(values, deviceId) {
  const supplied = values.outboxIds?.[deviceId];
  return supplied === undefined ? crypto.randomUUID() : uuid(supplied, "outbox_id");
}

function normalizeRefreshStateKey(input) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "refresh state input must be an object");
  return { organizationId: tenant(input.organization_id ?? input.organizationId), deviceId: uuid(input.device_id ?? input.deviceId, "device_id") };
}

function normalizeInitialDeviceRefreshInput(input, clock) {
  if (!isObject(input)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", "initial device refresh input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  const enrollmentId = uuid(input.enrollment_id ?? input.enrollmentId, "enrollment_id");
  const requestedAt = timestamp(input.requested_at ?? input.requestedAt ?? clock(), "requested_at");
  const defaultExpiry = new Date(Date.parse(requestedAt) + MAX_REFRESH_TTL_MS).toISOString();
  const expiresAt = timestamp(input.expires_at ?? input.expiresAt ?? defaultExpiry, "expires_at");
  const ttl = Date.parse(expiresAt) - Date.parse(requestedAt);
  if (ttl < 1 || ttl > MAX_REFRESH_TTL_MS) throw new ControlPlaneAuthorityRepositoryError("ERR_TIMESTAMP", "initial device refresh expiry must be within five minutes");
  return { organizationId, deviceId, enrollmentId, requestedAt, expiresAt };
}

function normalizeRefreshPollInput(input) {
  const key = normalizeRefreshStateKey(input);
  const afterGeneration = nonNegativeInteger(input.after_generation ?? input.afterGeneration ?? 0, "after_generation");
  const waitMs = input.wait_ms ?? input.waitMs ?? 0;
  if (!Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > MAX_REFRESH_WAIT_MS) throw new ControlPlaneAuthorityRepositoryError("ERR_LIMIT", "wait_ms must be between 0 and 30000");
  return { ...key, afterGeneration, waitMs };
}

function normalizeRefreshDeliveryInput(input, clock) {
  const key = normalizeRefreshStateKey(input);
  return {
    ...key,
    outboxId: uuid(input.outbox_id ?? input.outboxId, "outbox_id"),
    desiredGeneration: positiveInteger(input.desired_generation ?? input.desiredGeneration, "desired_generation"),
    deliveredAt: timestamp(input.delivered_at ?? input.deliveredAt ?? clock(), "delivered_at")
  };
}

function publicRefreshState(row) {
  if (!row || typeof row !== "object") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "device refresh state query returned an invalid row");
  return Object.freeze({
    organization_id: uuid(row.organization_id, "organization_id"),
    device_id: uuid(row.device_id, "device_id"),
    desired_generation: positiveInteger(row.desired_generation, "desired_generation"),
    observed_generation: nullablePositiveInteger(row.observed_generation, "observed_generation"),
    refresh_state: refreshState(row.refresh_state),
    refresh_requested_at: timestamp(row.refresh_requested_at, "refresh_requested_at"),
    last_delivered_at: nullableTimestamp(row.last_delivered_at, "last_delivered_at"),
    last_observed_at: nullableTimestamp(row.last_observed_at, "last_observed_at"),
    last_error_code: row.last_error_code === null || row.last_error_code === undefined ? null : boundedText(row.last_error_code, "last_error_code", 128),
    updated_at: timestamp(row.updated_at, "updated_at")
  });
}

function publicRefreshPollMetadata(row) {
  if (!row || typeof row !== "object") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "device refresh poll query returned an invalid row");
  const publishedAt = timestamp(row.published_at, "published_at");
  const expiresAt = timestamp(row.expires_at, "expires_at");
  if (Date.parse(expiresAt) <= Date.parse(publishedAt)) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "device refresh poll expiry is invalid");
  return Object.freeze({
    organization_id: uuid(row.organization_id, "organization_id"),
    device_id: uuid(row.device_id, "device_id"),
    desired_generation: positiveInteger(row.desired_generation, "desired_generation"),
    refresh_state: refreshState(row.refresh_state),
    outbox_id: uuid(row.outbox_id, "outbox_id"),
    refresh_nonce_key_id: normalizeRefreshNonceKeyId(row.refresh_nonce_key_id),
    refresh_nonce_digest: decodeDigest(row.refresh_nonce_digest, "refresh_nonce_digest").toString("hex"),
    published_at: publishedAt,
    expires_at: expiresAt
  });
}

function refreshState(value) { return textEnum(value, REFRESH_STATE_SET, "refresh_state"); }
function normalizeRefreshNonceKeyId(value) {
  if (typeof value !== "string" || !REFRESH_NONCE_KEY_ID_PATTERN.test(value)) throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", "refresh nonce key id is invalid");
  return value;
}
function nullableTimestamp(value, field) { return value === null || value === undefined ? null : timestamp(value, field); }
function nullablePositiveInteger(value, field) { return value === null || value === undefined ? null : positiveInteger(value, field); }
function nonNegativeInteger(value, field) {
  const number = typeof value === "string" && /^[0-9]+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) throw new ControlPlaneAuthorityRepositoryError("ERR_INTEGER", `${field} must be a non-negative safe integer`);
  return number;
}
function decodeBase64Url(value, field, expectedBytes) {
  const expectedLength = Math.ceil(expectedBytes * 8 / 6);
  if (typeof value !== "string" || !new RegExp(`^[A-Za-z0-9_-]{${expectedLength}}$`, "u").test(value)) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", `${field} must be canonical base64url`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== expectedBytes || bytes.toString("base64url") !== value) throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", `${field} must be canonical base64url`);
  return bytes;
}
function decodeDigest(value, field) {
  if (Buffer.isBuffer(value) && value.length === 32) return Buffer.from(value);
  if (value instanceof Uint8Array && value.length === 32) return Buffer.from(value);
  if (typeof value === "string" && SHA256.test(value)) return Buffer.from(value, "hex");
  throw new ControlPlaneAuthorityRepositoryError("ERR_INPUT", `${field} must be a 32-byte digest`);
}

function requireRefreshNonceCodec(codec) {
  if (!codec || typeof codec.derive !== "function" || typeof codec.activeKeyId !== "string") {
    throw new ControlPlaneAuthorityRepositoryError("ERR_REFRESH_NONCE_KEY_UNAVAILABLE", "restart-safe refresh nonce codec is unavailable");
  }
  return codec;
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
  try { assertDeviceAuditChainOrdered(events); }
  catch (error) { throw new ControlPlaneAuthorityRepositoryError("ERR_AUDIT_CHAIN_ORDER", error.message); }
  const receivedAt = timestamp(input.received_at ?? input.receivedAt ?? new Date().toISOString(), "received_at");
  const memberInput = input.principal_id ?? input.principalId ?? input.member_id ?? input.memberId;
  const memberId = memberInput === undefined ? undefined : uuid(memberInput, "member_id");
  return { organizationId, deviceId, events, receivedAt, memberId };
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

async function insertRevocationInTransaction(tx, values) {
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

async function bindOutboxToBundleStatement(tx, organizationId, deviceId, desiredGeneration, head) {
  const result = await tx.query(`UPDATE device_refresh_outbox
    SET format_epoch=$3,sequence=$4,statement_hash=$5
    WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$6
      AND status IN ('pending','delivered')
      AND format_epoch IS NULL AND sequence IS NULL AND statement_hash IS NULL
    RETURNING outbox_id,desired_generation,format_epoch,sequence,statement_hash`, [
    organizationId, deviceId, head.format_epoch ?? 2, head.sequence, head.state_fingerprint, desiredGeneration
  ]);
  for (const row of result.rows ?? []) uuid(row.outbox_id, "outbox_id");
}

async function assertActiveDeviceKeyEpoch(tx, values) {
  const result = await tx.query(`SELECT epochs.organization_id,epochs.device_id,epochs.key_epoch,epochs.status
    FROM device_key_epochs epochs
    JOIN devices devices
      ON devices.organization_id=epochs.organization_id AND devices.id=epochs.device_id
    WHERE epochs.organization_id=$1 AND epochs.device_id=$2 AND epochs.key_epoch=$3
      AND epochs.status='active' AND devices.status='active'
    FOR SHARE`, [values.organizationId, values.deviceId, values.deviceKeyEpoch]);
  if (rowCount(result) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_ACK_KEY_EPOCH_STALE", "device acknowledgement key epoch is not active");
}

async function refreshAcknowledgementResponse(tx, organizationId, deviceId, duplicate) {
  const state = await tx.query(`SELECT desired_generation,observed_generation,refresh_state
    FROM device_control_plane_state
    WHERE organization_id=$1 AND device_id=$2
    FOR SHARE`, [organizationId, deviceId]);
  if (rowCount(state) !== 1) throw new ControlPlaneAuthorityRepositoryError("ERR_REFRESH_STATE_MISSING", "device refresh state was not found");
  return Object.freeze({
    duplicate: duplicate === true,
    observed_generation: nullablePositiveInteger(state.rows[0].observed_generation, "observed_generation"),
    refresh_state: refreshState(state.rows[0].refresh_state)
  });
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

function databaseTimestamp(value, field) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new ControlPlaneAuthorityRepositoryError("ERR_DB_RESULT", `${field} database timestamp is invalid`);
  }
  return value;
}

function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function deterministicUuid(identity) { const bytes=crypto.createHash("sha256").update("AgentPass-Revocation-Id-v1\0").update(identity).digest().subarray(0,16); bytes[6]=(bytes[6]&0x0f)|0x50; bytes[8]=(bytes[8]&0x3f)|0x80; const hex=bytes.toString("hex"); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`; }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new ControlPlaneAuthorityRepositoryError("ERR_DB_CLIENT", "database client must provide query(text, params)"); }
