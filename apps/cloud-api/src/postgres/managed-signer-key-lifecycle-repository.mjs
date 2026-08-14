import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  createManagedSignerKeyLifecycle,
  MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS,
  MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES,
  ManagedSignerKeyLifecycleError,
  parseManagedSignerKeyLifecycleSnapshot
} from "../managed-signer-key-lifecycle.mjs";
import { withTransaction } from "./repository.mjs";

const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const DIGEST = /^[0-9a-f]{64}$/iu;
const ALGORITHM = "ed25519";
const SIGNATURE_BYTES = 64;
const DEFAULT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_RETENTION_MS = 365 * 24 * 60 * 60 * 1000;
const MAX_PRUNE = 1000;

export const MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES = Object.freeze({
  DATABASE: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_DATABASE",
  NOT_INITIALIZED: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_NOT_INITIALIZED",
  CONFIGURATION_CONFLICT: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_CONFIGURATION_CONFLICT",
  OPERATION_CONFLICT: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_OPERATION_CONFLICT",
  SIGNING_CONFLICT: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_SIGNING_CONFLICT",
  SIGNING_PENDING: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_SIGNING_PENDING",
  SIGNING_UNCERTAIN: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_SIGNING_UNCERTAIN",
  SIGNING_CLAIM_LOST: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_SIGNING_CLAIM_LOST",
  RETENTION: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_RETENTION"
});

const MESSAGES = Object.freeze({
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE]: "managed signer lifecycle storage is unavailable",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.NOT_INITIALIZED]: "managed signer lifecycle is not initialized",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.CONFIGURATION_CONFLICT]: "managed signer lifecycle configuration conflicts with the stored purpose",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.OPERATION_CONFLICT]: "managed signer lifecycle operation id was reused with a different request",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT]: "managed signer signing operation conflicts with its durable binding",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_PENDING]: "managed signer signing operation is already pending and cannot be retried blindly",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_UNCERTAIN]: "managed signer signing operation is uncertain and cannot be retried blindly",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST]: "managed signer signing claim is not available",
  [MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.RETENTION]: "managed signer retention request is invalid"
});

export class ManagedSignerKeyLifecycleRepositoryError extends Error {
  constructor(code, details = undefined) {
    super(MESSAGES[code] ?? MESSAGES[MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "ManagedSignerKeyLifecycleRepositoryError";
    this.code = MESSAGES[code] === undefined ? MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE : code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * Durable purpose-scoped storage for the public managed-signer lifecycle.
 * The returned snapshot deliberately has the same shape accepted by
 * createManagedSignerKeyLifecycle; no organization scope is invented here.
 */
export function createPostgresManagedSignerKeyLifecycleRepository({
  client,
  purpose,
  algorithm = ALGORITHM,
  maxKeys = MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxKeys,
  maxVerificationOverlapMs = MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxVerificationOverlapMs,
  lifecycleOperationRetentionMs = DEFAULT_RETENTION_MS,
  signingRetentionMs = DEFAULT_RETENTION_MS,
  now = () => Date.now()
} = {}) {
  assertClient(client);
  const config = normalizeConfig({ purpose, algorithm, maxKeys, maxVerificationOverlapMs, lifecycleOperationRetentionMs, signingRetentionMs, now });

  async function snapshot() {
    return runDatabase(() => readSnapshot(client, { lock: false }, config));
  }

  async function initialize(input = {}) {
    assertObject(input);
    assertAllowedKeys(input, ["snapshot"]);
    const target = normalizeSnapshot(input.snapshot, config);
    return runDatabase((tx) => initializeInTransaction(tx, target, config));
  }

  async function transitionKey(input = {}) {
    const values = normalizeTransitionInput(input, config);
    return runLifecycleMutation(values, (lifecycle) => lifecycle.transitionKey({
      expected_version: values.expectedVersion,
      operation_id: values.operationId,
      key_id: values.keyId,
      to: values.to,
      ...(values.verificationUntil === undefined ? {} : { verification_until: values.verificationUntil })
    }));
  }

  async function rotate(input = {}) {
    const values = normalizeRotateInput(input, config);
    return runLifecycleMutation(values, (lifecycle) => lifecycle.rotate({
      expected_version: values.expectedVersion,
      operation_id: values.operationId,
      new_key: values.newKey,
      ...(values.verificationUntil === undefined ? {} : { verification_until: values.verificationUntil })
    }));
  }

  async function emergencyDisable(input = {}) {
    const values = normalizeSimpleMutationInput(input, "emergency_disable", config);
    return runLifecycleMutation(values, (lifecycle) => lifecycle.emergencyDisable({
      expected_version: values.expectedVersion,
      operation_id: values.operationId
    }));
  }

  async function restore(input = {}) {
    const values = normalizeRestoreInput(input, config);
    return runLifecycleMutation(values, (lifecycle) => lifecycle.restore({
      expected_version: values.expectedVersion,
      operation_id: values.operationId,
      new_key: values.newKey
    }));
  }

  async function reserveSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true }, config);
    return runDatabase((tx) => reserveSignatureInTransaction(tx, values));
  }

  async function commitSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true, requireSignature: true }, config);
    return runDatabase((tx) => commitSignatureInTransaction(tx, values, false));
  }

  async function markSignatureUncertain(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true }, config);
    return runDatabase((tx) => markSignatureUncertainInTransaction(tx, values));
  }

  async function reconcileSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true, requireSignature: true }, config);
    return runDatabase((tx) => commitSignatureInTransaction(tx, values, true));
  }

  async function lookupSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: false }, config);
    return runDatabase(async (tx) => {
      await selectLifecycle(tx, { lock: true }, config);
      const row = await selectSigningRecord(tx, values.operationId, true, config);
      if (!row) return Object.freeze({ state: "absent", purpose: config.purpose, operation_id: values.operationId });
      assertSigningIdentity(row, values);
      return publicSigningRecord(row, config);
    });
  }

  async function pruneSigningRecords(input = {}) {
    const values = normalizePruneInput(input, config);
    return runDatabase(async (tx) => {
      await selectLifecycle(tx, { lock: true }, config);
      const result = await tx.query(`WITH doomed AS (
          SELECT purpose,operation_id
          FROM managed_signer_signing_idempotency
          WHERE purpose=$1 AND status='committed' AND expires_at<=$2::timestamptz
          ORDER BY expires_at ASC,operation_id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT $3
        )
        DELETE FROM managed_signer_signing_idempotency record
        USING doomed
        WHERE record.purpose=doomed.purpose AND record.operation_id=doomed.operation_id
        RETURNING record.operation_id`, [config.purpose, values.before.toISOString(), values.limit]);
      return Object.freeze({ pruned: rowCount(result) });
    });
  }

  async function pruneLifecycleOperations(input = {}) {
    const values = normalizePruneInput(input, config);
    return runDatabase(async (tx) => {
      await selectLifecycle(tx, { lock: true }, config);
      const result = await tx.query(`WITH doomed AS (
          SELECT purpose,operation_id
          FROM managed_signer_key_lifecycle_operations
          WHERE purpose=$1 AND expires_at<=$2::timestamptz
          ORDER BY expires_at ASC,operation_id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT $3
        )
        DELETE FROM managed_signer_key_lifecycle_operations record
        USING doomed
        WHERE record.purpose=doomed.purpose AND record.operation_id=doomed.operation_id
        RETURNING record.operation_id`, [config.purpose, values.before.toISOString(), values.limit]);
      return Object.freeze({ pruned: rowCount(result) });
    });
  }

  async function runLifecycleMutation(values, apply) {
    return runDatabase(async (tx) => {
      const parent = await selectLifecycle(tx, { lock: true }, config);
      const previous = await selectLifecycleOperation(tx, values.operationId, true, config);
      if (previous) return replayLifecycleOperation(previous, values.requestDigest, config);
      const current = await readSnapshotFromParent(tx, parent, { lock: true }, config);
      let next;
      try {
        const lifecycle = createManagedSignerKeyLifecycle({
          purpose: config.purpose,
          algorithm: config.algorithm,
          snapshot: current,
          now: () => values.nowMs,
          maxKeys: config.maxKeys,
          maxVerificationOverlapMs: config.maxVerificationOverlapMs
        });
        next = apply(lifecycle);
      } catch (error) {
        throw error;
      }
      await persistSnapshot(tx, current, next, parent);
      await insertLifecycleOperation(tx, values.operationId, values.requestDigest, next, values.nowMs, config);
      return next;
    });
  }

  async function initializeInTransaction(tx, target, repositoryConfig) {
    const inserted = await tx.query(`INSERT INTO managed_signer_key_lifecycles
        (purpose,algorithm,version,max_keys,max_verification_overlap_ms)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (purpose) DO NOTHING
        RETURNING purpose`, [config.purpose, config.algorithm, target.version, config.maxKeys, config.maxVerificationOverlapMs]);
    const parent = await selectLifecycle(tx, { lock: true }, repositoryConfig);
    if (rowCount(inserted) === 1) {
      await insertKeys(tx, target);
      return readSnapshotFromParent(tx, parent, { lock: true }, repositoryConfig);
    }
    const current = await readSnapshotFromParent(tx, parent, { lock: true }, repositoryConfig);
    if (canonicalJson(current) !== canonicalJson(target)) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.CONFIGURATION_CONFLICT);
    return current;
  }

  async function reserveSignatureInTransaction(tx, values) {
    await selectLifecycle(tx, { lock: true }, config);
    const existing = await selectSigningRecord(tx, values.operationId, true, config);
    if (existing) {
      assertSigningIdentity(existing, values);
      if (existing.status === "committed") return publicSigningRecord(existing, config);
      if (existing.status === "pending") throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_PENDING, safeSigningDetails(existing));
      throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_UNCERTAIN, safeSigningDetails(existing));
    }
    const key = await selectKeyForSigning(tx, values.keyId, true, config);
    if (!key || key.key_version !== values.keyVersion) throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
    if (key.state !== "active") throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.NOT_ACTIVE);
    const result = await tx.query(`INSERT INTO managed_signer_signing_idempotency
        (purpose,operation_id,request_digest,key_id,key_version,status,signature,created_at,updated_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,'pending',NULL,$6::timestamptz,$6::timestamptz,$7::timestamptz)
        RETURNING purpose,operation_id,encode(request_digest,'hex') AS request_digest,key_id,key_version::text AS key_version,status,signature,created_at,updated_at,expires_at`, [
      config.purpose, values.operationId, Buffer.from(values.requestDigest, "hex"), values.keyId, values.keyVersion,
      new Date(values.nowMs).toISOString(), new Date(values.nowMs + config.signingRetentionMs).toISOString()
    ]);
    if (rowCount(result) !== 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
    return publicSigningRecord(result.rows[0], config);
  }

  async function commitSignatureInTransaction(tx, values, reconcile) {
    await selectLifecycle(tx, { lock: true }, config);
    const existing = await selectSigningRecord(tx, values.operationId, true, config);
    if (!existing) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
    assertSigningIdentity(existing, values);
    if (existing.status === "committed") {
      if (!bytesEqual(existing.signature, values.signature)) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
      return publicSigningRecord(existing, config);
    }
    if (existing.status === "uncertain" && !reconcile) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_UNCERTAIN, safeSigningDetails(existing));
    if (existing.status === "pending" && reconcile) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_PENDING, safeSigningDetails(existing));
    const result = await tx.query(`UPDATE managed_signer_signing_idempotency
        SET status='committed',signature=$3,updated_at=clock_timestamp()
        WHERE purpose=$1 AND operation_id=$2 AND status=$4
        RETURNING purpose,operation_id,encode(request_digest,'hex') AS request_digest,key_id,key_version::text AS key_version,status,signature,created_at,updated_at,expires_at`, [
      config.purpose, values.operationId, values.signature, existing.status
    ]);
    if (rowCount(result) !== 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
    return publicSigningRecord(result.rows[0], config);
  }

  async function markSignatureUncertainInTransaction(tx, values) {
    await selectLifecycle(tx, { lock: true }, config);
    const existing = await selectSigningRecord(tx, values.operationId, true, config);
    if (!existing) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
    assertSigningIdentity(existing, values);
    if (existing.status === "committed") return publicSigningRecord(existing, config);
    if (existing.status === "uncertain") return publicSigningRecord(existing, config);
    const result = await tx.query(`UPDATE managed_signer_signing_idempotency
        SET status='uncertain',updated_at=clock_timestamp()
        WHERE purpose=$1 AND operation_id=$2 AND status='pending'
        RETURNING purpose,operation_id,encode(request_digest,'hex') AS request_digest,key_id,key_version::text AS key_version,status,signature,created_at,updated_at,expires_at`, [config.purpose, values.operationId]);
    if (rowCount(result) !== 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
    return publicSigningRecord(result.rows[0], config);
  }

  async function runDatabase(operation) {
    try {
      return await withTransaction(client, operation);
    } catch (error) {
      if (error instanceof ManagedSignerKeyLifecycleRepositoryError || error instanceof ManagedSignerKeyLifecycleError) throw error;
      throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
    }
  }

  return Object.freeze({
    purpose: config.purpose,
    algorithm: config.algorithm,
    snapshot,
    getSnapshot: snapshot,
    initialize,
    transitionKey,
    rotate,
    emergencyDisable,
    restore,
    reserveSignature,
    beginSigning: reserveSignature,
    commitSignature,
    commitSigning: commitSignature,
    markSignatureUncertain,
    markSigningUncertain: markSignatureUncertain,
    reconcileSignature,
    reconcileSigning: reconcileSignature,
    lookupSignature,
    lookupSigning: lookupSignature,
    pruneSigningRecords,
    pruneSigning: pruneSigningRecords,
    pruneLifecycleOperations
  });
}

export function canonicalManagedSignerRequestDigest(value) {
  try {
    return crypto.createHash("sha256").update(canonicalJson(canonicalBytes(value)), "utf8").digest("hex");
  } catch {
    throw new TypeError("managed signer request must be canonical JSON");
  }
}

async function persistSnapshot(tx, current, next, parent) {
  if (next.version !== current.version + 1 || next.purpose !== current.purpose || next.algorithm !== current.algorithm) throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION);
  const updatedParent = await tx.query(`UPDATE managed_signer_key_lifecycles
      SET version=$2,updated_at=clock_timestamp()
      WHERE purpose=$1 AND version=$3
      RETURNING version`, [parent.purpose, next.version, current.version]);
  if (rowCount(updatedParent) !== 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  const oldById = new Map(current.keys.map((key) => [key.key_id, key]));
  const nextById = new Map(next.keys.map((key) => [key.key_id, key]));
  for (const oldKey of current.keys) {
    const nextKey = nextById.get(oldKey.key_id);
    if (!nextKey) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
    if (oldKey.state === nextKey.state && oldKey.state_version === nextKey.state_version && oldKey.verification_until === nextKey.verification_until) continue;
    const result = await tx.query(`UPDATE managed_signer_keys
        SET state=$3,state_version=$4,verification_until=$5::timestamptz,updated_at=clock_timestamp()
        WHERE purpose=$1 AND key_id=$2`, [current.purpose, oldKey.key_id, nextKey.state, nextKey.state_version, nextKey.verification_until ?? null]);
    if (rowCount(result) !== 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  }
  for (const nextKey of next.keys) {
    if (oldById.has(nextKey.key_id)) continue;
    await insertKey(tx, nextKey, next.keys.findIndex((key) => key.key_id === nextKey.key_id));
  }
}

async function insertKeys(tx, snapshot) {
  for (const [position, key] of snapshot.keys.entries()) await insertKey(tx, key, position);
}

async function insertKey(tx, key, position) {
  await tx.query(`INSERT INTO managed_signer_keys
      (purpose,key_id,key_version,algorithm,public_key_fingerprint,public_key_pem,state,state_version,verification_until,key_position)
      VALUES ($1,$2,$3,$4,decode($5,'hex'),$6,$7,$8,$9::timestamptz,$10)`, [
    key.purpose, key.key_id, key.key_version, key.algorithm, key.public_key_fingerprint, key.public_key ?? null,
    key.state, key.state_version, key.verification_until ?? null, position
  ]);
}

async function readSnapshot(client, { lock }, config) {
  const parent = await selectLifecycle(client, { lock }, config);
  return readSnapshotFromParent(client, parent, { lock }, config);
}

async function readSnapshotFromParent(client, parent, { lock }, config) {
  const result = await client.query(`SELECT purpose,key_id,key_version::text AS key_version,algorithm,
      encode(public_key_fingerprint,'hex') AS public_key_fingerprint,public_key_pem,state,
      state_version::text AS state_version,verification_until
    FROM managed_signer_keys
    WHERE purpose=$1
    ORDER BY key_position ASC
    ${lock ? "FOR UPDATE" : "FOR SHARE"}`, [parent.purpose]);
  if (rowCount(result) < 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  const snapshot = {
    version: databaseInteger(parent.version, "version"),
    purpose: parent.purpose,
    algorithm: parent.algorithm,
    keys: result.rows.map(publicKeyRecord)
  };
  try {
    return parseManagedSignerKeyLifecycleSnapshot(snapshot, {
      purpose: parent.purpose,
      algorithm: parent.algorithm,
      now: config.now,
      maxKeys: parent.maxKeys,
      maxVerificationOverlapMs: parent.maxVerificationOverlapMs
    });
  } catch (error) {
    if (error instanceof ManagedSignerKeyLifecycleError) throw error;
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  }
}

async function selectLifecycle(client, { lock }, config) {
  const result = await client.query(`SELECT purpose,algorithm,version::text AS version,max_keys,
      max_verification_overlap_ms::text AS max_verification_overlap_ms
    FROM managed_signer_key_lifecycles
    WHERE purpose=$1
    ${lock ? "FOR UPDATE" : "FOR SHARE"}`, [config.purpose]);
  if (rowCount(result) !== 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.NOT_INITIALIZED);
  return configFor(result.rows[0], config);
}

async function selectLifecycleOperation(client, operationId, lock, config) {
  const result = await client.query(`SELECT purpose,operation_id,request_digest,response_snapshot,created_at,expires_at
    FROM managed_signer_key_lifecycle_operations
    WHERE purpose=$1 AND operation_id=$2
    ${lock ? "FOR UPDATE" : "FOR SHARE"}`, [config.purpose, operationId]);
  return rowCount(result) === 1 ? result.rows[0] : undefined;
}

async function selectSigningRecord(client, operationId, lock, config) {
  const result = await client.query(`SELECT purpose,operation_id,encode(request_digest,'hex') AS request_digest,
      key_id,key_version::text AS key_version,status,signature,created_at,updated_at,expires_at
    FROM managed_signer_signing_idempotency
    WHERE purpose=$1 AND operation_id=$2
    ${lock ? "FOR UPDATE" : "FOR SHARE"}`, [config.purpose, operationId]);
  return rowCount(result) === 1 ? result.rows[0] : undefined;
}

async function selectKeyForSigning(client, keyId, lock, config) {
  const result = await client.query(`SELECT key_id,key_version::text AS key_version,state
    FROM managed_signer_keys
    WHERE purpose=$1 AND key_id=$2
    ${lock ? "FOR SHARE" : ""}`, [config.purpose, keyId]);
  if (rowCount(result) !== 1) return undefined;
  return { key_id: result.rows[0].key_id, key_version: databaseInteger(result.rows[0].key_version, "key_version"), state: result.rows[0].state };
}

async function insertLifecycleOperation(client, operationId, requestDigest, response, nowMs, config) {
  await client.query(`INSERT INTO managed_signer_key_lifecycle_operations
      (purpose,operation_id,request_digest,response_snapshot,created_at,expires_at)
      VALUES ($1,$2,$3,$4::jsonb,$5::timestamptz,$6::timestamptz)`, [
    config.purpose, operationId, Buffer.from(requestDigest, "hex"), JSON.stringify(response),
    new Date(nowMs).toISOString(), new Date(nowMs + config.lifecycleOperationRetentionMs).toISOString()
  ]);
}

function replayLifecycleOperation(row, requestDigest, config) {
  if (!bytesEqual(row.request_digest, requestDigest)) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.OPERATION_CONFLICT);
  try {
    const value = typeof row.response_snapshot === "string" ? JSON.parse(row.response_snapshot) : row.response_snapshot;
    return parseManagedSignerKeyLifecycleSnapshot(value, {
      purpose: config.purpose,
      algorithm: config.algorithm,
      maxKeys: config.maxKeys,
      maxVerificationOverlapMs: config.maxVerificationOverlapMs,
      now: () => Date.now()
    });
  } catch (error) {
    if (error instanceof ManagedSignerKeyLifecycleError) throw error;
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  }
}

function publicKeyRecord(row) {
  const value = {
    key_id: text(row.key_id, KEY_ID, "key_id"),
    key_version: databaseInteger(row.key_version, "key_version"),
    purpose: text(row.purpose, PURPOSE, "purpose"),
    algorithm: text(row.algorithm, /^ed25519$/u, "algorithm"),
    public_key_fingerprint: hex(row.public_key_fingerprint, "public_key_fingerprint"),
    state: row.state,
    state_version: databaseInteger(row.state_version, "state_version"),
    ...(row.public_key_pem === null || row.public_key_pem === undefined ? {} : { public_key: row.public_key_pem }),
    ...(row.verification_until === null || row.verification_until === undefined ? {} : { verification_until: timestamp(row.verification_until) })
  };
  return value;
}

function publicSigningRecord(row, config) {
  const result = {
    state: row.status,
    purpose: config.purpose,
    operation_id: text(row.operation_id, OPERATION_ID, "operation_id"),
    request_digest: hex(row.request_digest, "request_digest"),
    key_id: text(row.key_id, KEY_ID, "key_id"),
    key_version: databaseInteger(row.key_version, "key_version"),
    ...(row.created_at === undefined ? {} : { created_at: timestamp(row.created_at) }),
    ...(row.updated_at === undefined ? {} : { updated_at: timestamp(row.updated_at) }),
    ...(row.expires_at === undefined ? {} : { expires_at: timestamp(row.expires_at) }),
    ...(row.signature === null || row.signature === undefined ? {} : { signature: cloneSignature(row.signature) })
  };
  return Object.freeze(result);
}

function assertSigningIdentity(row, values) {
  if (hex(row.request_digest, "request_digest") !== values.requestDigest
    || (values.keyId !== undefined && row.key_id !== values.keyId)
    || (values.keyVersion !== undefined && databaseInteger(row.key_version, "key_version") !== values.keyVersion)) {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
  }
}

function safeSigningDetails(row) {
  return { state: row.status, operation_id: row.operation_id, key_id: row.key_id, key_version: databaseInteger(row.key_version, "key_version") };
}

function normalizeConfig(value) {
  if (typeof value.purpose !== "string" || !PURPOSE.test(value.purpose) || value.algorithm !== ALGORITHM || typeof value.now !== "function") throw new TypeError("managed signer lifecycle configuration is invalid");
  positive(value.maxKeys, "maxKeys", 1, 32);
  positive(value.maxVerificationOverlapMs, "maxVerificationOverlapMs", 1, 365 * 24 * 60 * 60 * 1000);
  retention(value.lifecycleOperationRetentionMs, "lifecycleOperationRetentionMs");
  retention(value.signingRetentionMs, "signingRetentionMs");
  return Object.freeze({
    purpose: value.purpose,
    algorithm: value.algorithm,
    maxKeys: value.maxKeys,
    maxVerificationOverlapMs: value.maxVerificationOverlapMs,
    lifecycleOperationRetentionMs: value.lifecycleOperationRetentionMs,
    signingRetentionMs: value.signingRetentionMs,
    now: value.now
  });
}

function configFor(row, config) {
  const value = {
    purpose: text(row.purpose, PURPOSE, "purpose"),
    algorithm: text(row.algorithm, /^ed25519$/u, "algorithm"),
    version: databaseInteger(row.version, "version"),
    maxKeys: databaseInteger(row.max_keys, "max_keys"),
    maxVerificationOverlapMs: databaseInteger(row.max_verification_overlap_ms, "max_verification_overlap_ms")
  };
  if (value.purpose !== config.purpose || value.algorithm !== config.algorithm || value.maxKeys !== config.maxKeys || value.maxVerificationOverlapMs !== config.maxVerificationOverlapMs) {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.CONFIGURATION_CONFLICT);
  }
  return value;
}

function normalizeSnapshot(value, config) {
  try {
    return parseManagedSignerKeyLifecycleSnapshot(value, {
      purpose: config.purpose,
      algorithm: config.algorithm,
      maxKeys: config.maxKeys,
      maxVerificationOverlapMs: config.maxVerificationOverlapMs,
      now: () => nowMs(config.now)
    });
  } catch (error) {
    if (error instanceof ManagedSignerKeyLifecycleError) throw error;
    throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  }
}

function normalizeTransitionInput(input, config) {
  assertObject(input);
  assertAllowedKeys(input, ["expected_version", "operation_id", "operationId", "key_id", "keyId", "to", "verification_until", "verificationUntil"]);
  const values = mutationBase(input, "transition_key", config);
  const verificationUntil = alias(input, "verification_until", "verificationUntil");
  const request = { kind: "transition_key", expected_version: values.expectedVersion, key_id: values.keyId, to: input.to };
  if (verificationUntil !== undefined) request.verification_until = verificationUntil;
  return Object.freeze({ ...values, to: input.to, verificationUntil, requestDigest: digestHex(request) });
}

function normalizeRotateInput(input, config) {
  assertObject(input);
  assertAllowedKeys(input, ["expected_version", "operation_id", "operationId", "new_key", "newKey", "verification_until", "verificationUntil"]);
  const values = mutationBase(input, "rotate", config);
  const candidate = candidateKey(alias(input, "new_key", "newKey"), config);
  const verificationUntil = alias(input, "verification_until", "verificationUntil");
  const request = { kind: "rotate", expected_version: values.expectedVersion, new_key: candidate };
  if (verificationUntil !== undefined) request.verification_until = verificationUntil;
  return Object.freeze({ ...values, newKey: candidate, verificationUntil, requestDigest: digestHex(request) });
}

function normalizeRestoreInput(input, config) {
  assertObject(input);
  assertAllowedKeys(input, ["expected_version", "operation_id", "operationId", "new_key", "newKey"]);
  const values = mutationBase(input, "restore", config);
  const candidate = candidateKey(alias(input, "new_key", "newKey"), config);
  return Object.freeze({ ...values, newKey: candidate, requestDigest: digestHex({ kind: "restore", expected_version: values.expectedVersion, new_key: candidate }) });
}

function normalizeSimpleMutationInput(input, kind, config) {
  assertObject(input);
  assertAllowedKeys(input, ["expected_version", "operation_id", "operationId"]);
  const values = mutationBase(input, kind, config);
  return Object.freeze({ ...values, requestDigest: digestHex({ kind, expected_version: values.expectedVersion }) });
}

function mutationBase(input, kind, config) {
  const expectedVersion = positive(input.expected_version, "expected_version", 1, Number.MAX_SAFE_INTEGER);
  const operationId = operation(input);
  return { kind, expectedVersion, operationId, nowMs: nowMs(config.now) };
}

function normalizeSigningInput(input, { requireBinding, requireSignature = false } = {}, config) {
  assertObject(input);
  const allowed = ["purpose", "operation_id", "operationId", "request_id", "requestId", "request_digest", "requestDigest", "key_id", "keyId", "key_version", "keyVersion", "signature"];
  assertAllowedKeys(input, allowed);
  if (input.purpose !== undefined && input.purpose !== config.purpose) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
  const operationId = operation(input);
  const requestDigest = digest(input.request_digest ?? input.requestDigest);
  const keyId = input.key_id ?? input.keyId;
  const keyVersion = input.key_version ?? input.keyVersion;
  if (requireBinding && (keyId === undefined || keyVersion === undefined)) throw new TypeError("signing key binding is required");
  if (keyId !== undefined && (typeof keyId !== "string" || !KEY_ID.test(keyId))) throw new TypeError("key_id is invalid");
  if (keyVersion !== undefined) positive(keyVersion, "key_version", 1, Number.MAX_SAFE_INTEGER);
  const signature = input.signature === undefined ? undefined : normalizeSignature(input.signature);
  if (requireSignature && signature === undefined) throw new TypeError("signature is required");
  return Object.freeze({ purpose: config.purpose, operationId, requestDigest, keyId, keyVersion, signature, nowMs: nowMs(config.now) });
}

function normalizePruneInput(input, config) {
  assertObject(input);
  assertAllowedKeys(input, ["before", "limit"]);
  const before = input.before === undefined ? new Date(nowMs(config.now)) : new Date(input.before);
  if (Number.isNaN(before.getTime())) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.RETENTION);
  const limit = input.limit === undefined ? MAX_PRUNE : positive(input.limit, "limit", 1, MAX_PRUNE);
  return Object.freeze({ before, limit });
}

function candidateKey(value, config) {
  assertObject(value);
  const required = ["key_id", "key_version", "purpose", "algorithm", "public_key_fingerprint", "state", "state_version"];
  const optional = ["public_key", "verification_until"];
  assertAllowedKeys(value, [...required, ...optional]);
  for (const key of required) if (!Object.hasOwn(value, key) || value[key] === undefined) throw new TypeError("new_key metadata is incomplete");
  const result = {};
  for (const key of [...required, ...optional]) if (value[key] !== undefined) result[key] = value[key];
  if (result.purpose !== config.purpose || result.algorithm !== config.algorithm) throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.PURPOSE);
  return Object.freeze(result);
}

function operation(input) {
  const value = aliasMany(input, ["operation_id", "operationId", "request_id", "requestId"]);
  if (typeof value !== "string" || !OPERATION_ID.test(value)) throw new TypeError("operation_id is invalid");
  return value;
}

function digest(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    if (value.length !== 32) throw new TypeError("request_digest is invalid");
    return Buffer.from(value).toString("hex");
  }
  if (typeof value !== "string" || !DIGEST.test(value)) throw new TypeError("request_digest is invalid");
  return value.toLowerCase();
}

function normalizeSignature(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) throw new TypeError("signature must be bytes");
  if (value.length !== SIGNATURE_BYTES) throw new TypeError("signature must contain 64 bytes");
  return Buffer.from(value);
}

function canonicalBytes(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value).toString("base64");
  if (Array.isArray(value)) return value.map(canonicalBytes);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, canonicalBytes(nested)]));
  return value;
}

function digestHex(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function nowMs(clock) {
  const value = clock();
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) throw new TypeError("managed signer clock is invalid");
  return result;
}

function positive(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`${name} is invalid`);
  return value;
}

function retention(value, name) { return positive(value, name, 1, MAX_RETENTION_MS); }

function timestamp(value) {
  const date = value instanceof Date ? new Date(value) : new Date(value);
  if (Number.isNaN(date.getTime())) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  return date.toISOString();
}

function databaseInteger(value, field) {
  const result = typeof value === "string" ? Number(value) : value;
  if (!Number.isSafeInteger(result) || result < 1) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE, { field });
  return result;
}

function text(value, pattern, field) {
  if (typeof value !== "string" || !pattern.test(value)) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE, { field });
  return value;
}

function hex(value, field) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    if (value.length !== 32) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE, { field });
    return Buffer.from(value).toString("hex");
  }
  if (typeof value !== "string" || !DIGEST.test(value)) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE, { field });
  return value.toLowerCase();
}

function bytesEqual(left, right) {
  try {
    const a = Buffer.isBuffer(left) || left instanceof Uint8Array ? Buffer.from(left) : Buffer.from(hex(left, "digest"), "hex");
    const b = Buffer.isBuffer(right) || right instanceof Uint8Array ? Buffer.from(right) : Buffer.from(digest(right), "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function cloneSignature(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  if (value.length !== SIGNATURE_BYTES) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
  return Buffer.from(value);
}

function alias(input, first, second) {
  if (input[first] !== undefined && input[second] !== undefined && input[first] !== input[second]) throw new TypeError(`${first} aliases conflict`);
  return input[first] ?? input[second];
}

function aliasMany(input, names) {
  const values = names.filter((name) => input[name] !== undefined).map((name) => input[name]);
  if (new Set(values).size > 1) throw new TypeError("operation aliases conflict");
  return values[0];
}

function assertObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new TypeError("input must be a plain object");
}

function assertAllowedKeys(value, allowed) {
  const set = new Set(allowed);
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string" || !set.has(key))) throw new TypeError("input contains an unknown field");
}

function repositoryError(code, details = undefined) { return new ManagedSignerKeyLifecycleRepositoryError(code, details); }
function lifecycleError(code) { return new ManagedSignerKeyLifecycleError(code); }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function assertClient(value) { if (!value || (typeof value.query !== "function" && typeof value.connect !== "function")) throw new TypeError("database client must provide query or connect"); }

export default createPostgresManagedSignerKeyLifecycleRepository;
