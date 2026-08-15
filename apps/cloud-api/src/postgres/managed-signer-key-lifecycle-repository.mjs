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
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const ALGORITHM = "ed25519";
const SIGNATURE_BYTES = 64;
const RECEIPT_PROVIDER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const RECEIPT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DEFAULT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_RETENTION_MS = 365 * 24 * 60 * 60 * 1000;
const MAX_PRUNE = 1000;
const DEFAULT_CLAIM_LEASE_MS = 30_000;
const MAX_CLAIM_LEASE_MS = 5 * 60_000;

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
const AUTHORITY_SQL = Object.freeze({
  snapshot: "SELECT public.agentpass_managed_signer_lifecycle_snapshot($1) AS result",
  initialize: "SELECT public.agentpass_managed_signer_lifecycle_initialize($1,$2,$3::jsonb,$4,$5) AS result",
  apply: "SELECT public.agentpass_managed_signer_lifecycle_apply($1,$2,$3,$4,$5::jsonb,$6) AS result",
  reserve: "SELECT public.agentpass_managed_signer_signing_reserve($1,$2,$3,$4,$5,$6,$7,$8) AS result",
  start: "SELECT public.agentpass_managed_signer_signing_start($1,$2,$3,$4,$5,$6) AS result",
  commit: "SELECT public.agentpass_managed_signer_signing_commit($1,$2,$3,$4,$5,$6,$7,$8,$9) AS result",
  uncertain: "SELECT public.agentpass_managed_signer_signing_uncertain($1,$2,$3,$4,$5,$6) AS result",
  reconcile: "SELECT public.agentpass_managed_signer_signing_reconcile($1,$2,$3,$4,$5,$6,$7,$8) AS result",
  lookup: "SELECT public.agentpass_managed_signer_signing_lookup($1,$2) AS result",
  pruneSigning: "SELECT public.agentpass_managed_signer_signing_prune($1,$2::timestamptz,$3) AS result",
  pruneLifecycle: "SELECT public.agentpass_managed_signer_lifecycle_operation_prune($1,$2::timestamptz,$3) AS result"
});
const AUTHORITY_OUTCOMES = new Set(["ok", "absent", "conflict", "pending", "uncertain", "claim_lost", "configuration_conflict", "not_initialized", "not_active"]);
const AUTHORITY_FIELDS = new Set(["outcome", "snapshot", "record", "pruned", "transition"]);

export function createPostgresManagedSignerKeyLifecycleRepository({
  client,
  purpose,
  algorithm = ALGORITHM,
  maxKeys = MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxKeys,
  maxVerificationOverlapMs = MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxVerificationOverlapMs,
  lifecycleOperationRetentionMs = DEFAULT_RETENTION_MS,
  signingRetentionMs = DEFAULT_RETENTION_MS,
  signingClaimLeaseMs = DEFAULT_CLAIM_LEASE_MS,
  randomBytes = crypto.randomBytes,
  now = () => Date.now()
} = {}) {
  assertClient(client);
  const config = normalizeConfig({ purpose, algorithm, maxKeys, maxVerificationOverlapMs, lifecycleOperationRetentionMs, signingRetentionMs, signingClaimLeaseMs, randomBytes, now });
  const localClaimTokens = new Map();

  function rememberClaimToken(operationId, token) {
    localClaimTokens.set(operationId, token);
    while (localClaimTokens.size > MAX_PRUNE) localClaimTokens.delete(localClaimTokens.keys().next().value);
  }

  async function snapshot() {
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, AUTHORITY_SQL.snapshot, [config.purpose]);
      return snapshotFromEnvelope(envelope, config);
    });
  }

  async function initialize(input = {}) {
    assertObject(input);
    assertAllowedKeys(input, ["snapshot"]);
    const target = normalizeSnapshot(input.snapshot, config);
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, AUTHORITY_SQL.initialize, [
        config.purpose,
        config.algorithm,
        JSON.stringify(target),
        config.maxKeys,
        config.maxVerificationOverlapMs
      ]);
      if (envelope.outcome === "configuration_conflict") throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.CONFIGURATION_CONFLICT);
      return snapshotFromEnvelope(envelope, config);
    });
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
    const claimToken = makeToken(config.randomBytes);
    const claimDigest = Buffer.from(sha256(claimToken), "hex");
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, AUTHORITY_SQL.reserve, signingBinding(values, config, [
        claimDigest,
        config.signingClaimLeaseMs,
        config.signingRetentionMs
      ]));
      if (envelope.outcome === "ok") {
        const row = recordFromEnvelope(envelope);
        assertSigningIdentity(row, values);
        if (row.status === "pending") {
          rememberClaimToken(values.operationId, claimToken);
          return publicSigningRecord(row, config, claimToken);
        }
        if (row.status !== "committed") throw malformedAuthority();
        return publicSigningRecord(row, config);
      }
      if (envelope.outcome === "not_active") throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.NOT_ACTIVE);
      throwSigningOutcome(envelope, values, config);
    });
  }

  async function startSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true, requireClaimToken: true }, config);
    const claimDigest = Buffer.from(sha256(values.claimToken), "hex");
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, AUTHORITY_SQL.start, signingBinding(values, config, [claimDigest]));
      const row = signingSuccess(envelope, values, config);
      if (row.status === "pending") rememberClaimToken(values.operationId, values.claimToken);
      return publicSigningRecord(row, config, row.status === "pending" ? values.claimToken : undefined);
    });
  }

  async function commitSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true, requireSignature: true }, config);
    const claimToken = values.claimToken ?? localClaimTokens.get(values.operationId);
    const receipt = values.providerReceipt;
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, AUTHORITY_SQL.commit, signingBinding(values, config, [
        claimToken ? Buffer.from(sha256(claimToken), "hex") : null,
        values.signature,
        receipt?.provider ?? null,
        receipt?.receipt_id ?? null
      ]));
      const row = signingSuccess(envelope, values, config);
      if (row.status !== "committed") throw malformedAuthority();
      if (!bytesEqual(row.signature, values.signature)) throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
      if (receipt !== undefined) assertStoredReceipt(row, receipt);
      localClaimTokens.delete(values.operationId);
      return publicSigningRecord(row, config);
    });
  }

  async function markSignatureUncertain(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true }, config);
    const claimToken = values.claimToken ?? localClaimTokens.get(values.operationId);
    return runDatabase(async (tx) => {
      if (!claimToken) {
        const replayEnvelope = await callAuthority(tx, AUTHORITY_SQL.lookup, [config.purpose, values.operationId]);
        if (replayEnvelope.outcome === "absent") {
          assertExactAuthorityFields(replayEnvelope, ["outcome"]);
          throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
        }
        if (replayEnvelope.outcome !== "ok") throwSigningOutcome(replayEnvelope, values, config);
        const replay = recordFromEnvelope(replayEnvelope);
        assertSigningIdentity(replay, values);
        if (!["uncertain", "committed"].includes(replay.status)) {
          throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
        }
        return publicSigningRecord(replay, config);
      }
      const claimDigest = Buffer.from(sha256(claimToken), "hex");
      // The uncertainty authority itself records provider_started_at when a
      // live claim is quarantined. Do not re-run signing_start here: lifecycle
      // fencing may intentionally make start unavailable after provider
      // acceptance, while the pending row still has to become uncertain.
      const envelope = await callAuthority(tx, AUTHORITY_SQL.uncertain, signingBinding(values, config, [claimDigest]));
      if (!["ok", "uncertain"].includes(envelope.outcome)) throwSigningOutcome(envelope, values, config);
      const row = recordFromEnvelope(envelope);
      assertSigningIdentity(row, values);
      if (!["uncertain", "committed"].includes(row.status)) throw malformedAuthority();
      localClaimTokens.delete(values.operationId);
      return publicSigningRecord(row, config);
    });
  }

  async function reconcileSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: true, requireSignature: true, requireProviderReceipt: true }, config);
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, AUTHORITY_SQL.reconcile, signingBinding(values, config, [
        values.signature,
        values.providerReceipt.provider,
        values.providerReceipt.receipt_id
      ]));
      const row = signingSuccess(envelope, values, config);
      if (row.status !== "committed" || !bytesEqual(row.signature, values.signature)) {
        throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
      }
      assertStoredReceipt(row, values.providerReceipt);
      localClaimTokens.delete(values.operationId);
      return publicSigningRecord(row, config);
    });
  }

  async function lookupSignature(input = {}) {
    const values = normalizeSigningInput(input, { requireBinding: false }, config);
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, AUTHORITY_SQL.lookup, [config.purpose, values.operationId]);
      if (envelope.outcome === "absent") {
        assertExactAuthorityFields(envelope, ["outcome"]);
        return Object.freeze({ state: "absent", purpose: config.purpose, operation_id: values.operationId });
      }
      const row = signingSuccess(envelope, values, config);
      return publicSigningRecord(row, config);
    });
  }

  async function pruneSigningRecords(input = {}) {
    const values = normalizePruneInput(input, config);
    return prune(AUTHORITY_SQL.pruneSigning, values);
  }

  async function pruneLifecycleOperations(input = {}) {
    const values = normalizePruneInput(input, config);
    return prune(AUTHORITY_SQL.pruneLifecycle, values);
  }

  async function prune(sql, values) {
    return runDatabase(async (tx) => {
      const envelope = await callAuthority(tx, sql, [config.purpose, values.before.toISOString(), values.limit]);
      if (envelope.outcome !== "ok") throwAuthorityOutcome(envelope);
      assertExactAuthorityFields(envelope, ["outcome", "pruned"]);
      if (!Number.isSafeInteger(envelope.pruned) || envelope.pruned < 0 || envelope.pruned > values.limit) throw malformedAuthority();
      return Object.freeze({ pruned: envelope.pruned });
    });
  }

  async function runLifecycleMutation(values, apply) {
    return runDatabase(async (tx) => {
      const currentEnvelope = await callAuthority(tx, AUTHORITY_SQL.snapshot, [config.purpose]);
      const current = snapshotFromEnvelope(currentEnvelope, config);
      let target = current;
      if (current.version === values.expectedVersion) {
        const lifecycle = createManagedSignerKeyLifecycle({
          purpose: config.purpose,
          algorithm: config.algorithm,
          snapshot: current,
          now: () => values.nowMs,
          maxKeys: config.maxKeys,
          maxVerificationOverlapMs: config.maxVerificationOverlapMs
        });
        target = apply(lifecycle);
      }
      const envelope = await callAuthority(tx, AUTHORITY_SQL.apply, [
        config.purpose,
        values.operationId,
        Buffer.from(values.requestDigest, "hex"),
        values.expectedVersion,
        JSON.stringify(target),
        config.lifecycleOperationRetentionMs
      ]);
      if (envelope.outcome === "ok") return snapshotFromEnvelope(envelope, config, true);
      if (envelope.outcome === "conflict") {
        if (Object.hasOwn(envelope, "snapshot")) throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION);
        throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.OPERATION_CONFLICT);
      }
      throwAuthorityOutcome(envelope);
    });
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
    startSignature,
    markSignatureProviderStarted: startSignature,
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

function signingBinding(values, config, tail = []) {
  return [
    config.purpose,
    values.operationId,
    Buffer.from(values.requestDigest, "hex"),
    values.keyId,
    values.keyVersion,
    ...tail
  ];
}

async function callAuthority(client, sql, params) {
  if (!Object.values(AUTHORITY_SQL).includes(sql)) throw malformedAuthority();
  const result = await client.query(sql, params);
  if (rowCount(result) !== 1) throw malformedAuthority();
  const envelope = result.rows?.[0]?.result;
  if (!isPlainObject(envelope) || !AUTHORITY_OUTCOMES.has(envelope.outcome)
      || Reflect.ownKeys(envelope).some((key) => typeof key !== "string" || !AUTHORITY_FIELDS.has(key))) {
    throw malformedAuthority();
  }
  return envelope;
}

function snapshotFromEnvelope(envelope, config, allowTransition = false) {
  if (envelope.outcome !== "ok") throwAuthorityOutcome(envelope);
  const allowed = allowTransition && Object.hasOwn(envelope, "transition")
    ? ["outcome", "snapshot", "transition"]
    : ["outcome", "snapshot"];
  assertExactAuthorityFields(envelope, allowed);
  if (allowTransition && Object.hasOwn(envelope, "transition")
      && !["single-key", "rotate", "emergency-disable-all", "restore-new-key"].includes(envelope.transition)) {
    throw malformedAuthority();
  }
  try {
    return parseManagedSignerKeyLifecycleSnapshot(envelope.snapshot, {
      purpose: config.purpose,
      algorithm: config.algorithm,
      maxKeys: config.maxKeys,
      maxVerificationOverlapMs: config.maxVerificationOverlapMs,
      now: () => nowMs(config.now)
    });
  } catch {
    throw malformedAuthority();
  }
}

function signingSuccess(envelope, values, config) {
  if (envelope.outcome !== "ok") throwSigningOutcome(envelope, values, config);
  const row = recordFromEnvelope(envelope);
  assertSigningIdentity(row, values);
  return row;
}

function recordFromEnvelope(envelope) {
  assertExactAuthorityFields(envelope, ["outcome", "record"]);
  const value = envelope.record;
  if (!isPlainObject(value)) throw malformedAuthority();
  const allowed = new Set([
    "purpose", "operation_id", "request_digest", "key_id", "key_version", "state",
    "reserved_lifecycle_version", "created_at", "updated_at", "expires_at",
    "claim_expires_at", "provider_started_at", "signature", "provider_receipt"
  ]);
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string" || !allowed.has(key))) throw malformedAuthority();
  const required = ["purpose", "operation_id", "request_digest", "key_id", "key_version", "state", "reserved_lifecycle_version", "created_at", "updated_at", "expires_at"];
  if (required.some((key) => !Object.hasOwn(value, key))) throw malformedAuthority();
  const row = {
    purpose: value.purpose,
    operation_id: value.operation_id,
    request_digest: value.request_digest,
    key_id: value.key_id,
    key_version: value.key_version,
    status: value.state,
    reserved_lifecycle_version: value.reserved_lifecycle_version,
    created_at: value.created_at,
    updated_at: value.updated_at,
    expires_at: value.expires_at,
    claim_expires_at: value.claim_expires_at,
    provider_started_at: value.provider_started_at
  };
  if (!["pending", "uncertain", "committed", "aborted"].includes(row.status)) throw malformedAuthority();
  if (value.signature !== undefined) {
    if (typeof value.signature !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(value.signature)) throw malformedAuthority();
    const signature = Buffer.from(value.signature, "base64");
    if (signature.length !== SIGNATURE_BYTES || signature.toString("base64") !== value.signature) throw malformedAuthority();
    row.signature = signature;
  }
  if (value.provider_receipt !== undefined && value.provider_receipt !== null) {
    if (!isPlainObject(value.provider_receipt)
        || Reflect.ownKeys(value.provider_receipt).sort().join(",") !== "provider,receipt_id") throw malformedAuthority();
    row.provider_receipt_provider = value.provider_receipt.provider;
    row.provider_receipt_id = value.provider_receipt.receipt_id;
  }
  return row;
}

function throwSigningOutcome(envelope, values, config) {
  if (envelope.outcome === "pending" || envelope.outcome === "uncertain") {
    let details;
    if (Object.hasOwn(envelope, "record")) {
      const row = recordFromEnvelope(envelope);
      assertSigningIdentity(row, values);
      details = safeSigningDetails(row);
    } else {
      assertExactAuthorityFields(envelope, ["outcome"]);
    }
    const code = envelope.outcome === "pending"
      ? MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_PENDING
      : MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_UNCERTAIN;
    throw repositoryError(code, details);
  }
  if (envelope.outcome === "conflict" || envelope.outcome === "configuration_conflict") {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
  }
  if (envelope.outcome === "claim_lost") {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
  }
  if (envelope.outcome === "not_active") {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CLAIM_LOST);
  }
  if (envelope.outcome === "not_initialized") {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.NOT_INITIALIZED);
  }
  throw malformedAuthority();
}

function throwAuthorityOutcome(envelope) {
  if (envelope.outcome === "not_initialized") {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.NOT_INITIALIZED);
  }
  if (envelope.outcome === "configuration_conflict") {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.CONFIGURATION_CONFLICT);
  }
  if (envelope.outcome === "not_active") throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.NOT_ACTIVE);
  throw malformedAuthority();
}

function assertExactAuthorityFields(value, fields) {
  if (Reflect.ownKeys(value).sort().join(",") !== [...fields].sort().join(",")) throw malformedAuthority();
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function malformedAuthority() {
  return repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.DATABASE);
}

function publicSigningRecord(row, config, claimToken = undefined) {
  const result = {
    state: row.status,
    purpose: config.purpose,
    operation_id: text(row.operation_id, OPERATION_ID, "operation_id"),
    request_digest: hex(row.request_digest, "request_digest"),
    key_id: text(row.key_id, KEY_ID, "key_id"),
    key_version: databaseInteger(row.key_version, "key_version"),
    ...(row.reserved_lifecycle_version === undefined ? {} : { reserved_lifecycle_version: databaseInteger(row.reserved_lifecycle_version, "reserved_lifecycle_version") }),
    ...(row.created_at === undefined ? {} : { created_at: timestamp(row.created_at) }),
    ...(row.updated_at === undefined ? {} : { updated_at: timestamp(row.updated_at) }),
    ...(row.expires_at === undefined ? {} : { expires_at: timestamp(row.expires_at) }),
    ...(row.claim_expires_at === null || row.claim_expires_at === undefined ? {} : { claim_expires_at: timestamp(row.claim_expires_at) }),
    ...(row.provider_started_at === null || row.provider_started_at === undefined ? {} : { provider_started_at: timestamp(row.provider_started_at) }),
    ...(claimToken === undefined ? {} : { claim_token: claimToken }),
    ...(row.signature === null || row.signature === undefined ? {} : { signature: cloneSignature(row.signature) }),
    ...(row.provider_receipt_provider === null || row.provider_receipt_provider === undefined
      ? {}
      : { provider_receipt: normalizeProviderReceipt({
        provider: row.provider_receipt_provider,
        receipt_id: row.provider_receipt_id,
        operation_id: row.operation_id,
        key_id: row.key_id,
        key_version: databaseInteger(row.key_version, "key_version")
      }, {
        operationId: row.operation_id,
        keyId: row.key_id,
        keyVersion: databaseInteger(row.key_version, "key_version")
      }) })
  };
  return Object.freeze(result);
}

function normalizeProviderReceipt(value, expected) {
  assertObject(value);
  const expectedKeys = ["provider", "receipt_id", "operation_id", "key_id", "key_version"];
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expectedKeys.length || keys.some((key) => typeof key !== "string"
    || !expectedKeys.includes(key) || Object.getOwnPropertyDescriptor(value, key)?.enumerable !== true)) {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
  }
  if (typeof value.provider !== "string" || !RECEIPT_PROVIDER.test(value.provider)
    || typeof value.receipt_id !== "string" || !RECEIPT_ID.test(value.receipt_id)
    || /(private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(value.provider)
    || /(private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(value.receipt_id)
    || value.operation_id !== expected.operationId || value.key_id !== expected.keyId) {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
  }
  const keyVersion = typeof value.key_version === "string" ? Number(value.key_version) : value.key_version;
  if (!Number.isSafeInteger(keyVersion) || keyVersion < 1 || keyVersion !== expected.keyVersion) {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
  }
  return Object.freeze({
    provider: value.provider,
    receipt_id: value.receipt_id,
    operation_id: expected.operationId,
    key_id: expected.keyId,
    key_version: expected.keyVersion
  });
}

function assertStoredReceipt(row, receipt) {
  if (row.provider_receipt_provider !== receipt.provider || row.provider_receipt_id !== receipt.receipt_id) {
    throw repositoryError(MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT);
  }
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
  if (typeof value.purpose !== "string" || !PURPOSE.test(value.purpose) || value.algorithm !== ALGORITHM || typeof value.now !== "function" || typeof value.randomBytes !== "function") throw new TypeError("managed signer lifecycle configuration is invalid");
  positive(value.maxKeys, "maxKeys", 1, 32);
  positive(value.maxVerificationOverlapMs, "maxVerificationOverlapMs", 1, 365 * 24 * 60 * 60 * 1000);
  retention(value.lifecycleOperationRetentionMs, "lifecycleOperationRetentionMs");
  retention(value.signingRetentionMs, "signingRetentionMs");
  positive(value.signingClaimLeaseMs, "signingClaimLeaseMs", 1_000, MAX_CLAIM_LEASE_MS);
  return Object.freeze({
    purpose: value.purpose,
    algorithm: value.algorithm,
    maxKeys: value.maxKeys,
    maxVerificationOverlapMs: value.maxVerificationOverlapMs,
    lifecycleOperationRetentionMs: value.lifecycleOperationRetentionMs,
    signingRetentionMs: value.signingRetentionMs,
    signingClaimLeaseMs: value.signingClaimLeaseMs,
    randomBytes: value.randomBytes,
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
  const keyId = alias(input, "key_id", "keyId");
  if (typeof keyId !== "string" || !KEY_ID.test(keyId)) throw lifecycleError(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  const verificationUntil = alias(input, "verification_until", "verificationUntil");
  const request = { kind: "transition_key", expected_version: values.expectedVersion, key_id: keyId, to: input.to };
  if (verificationUntil !== undefined) request.verification_until = verificationUntil;
  return Object.freeze({ ...values, keyId, to: input.to, verificationUntil, requestDigest: digestHex(request) });
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

function normalizeSigningInput(input, { requireBinding, requireSignature = false, requireClaimToken = false, requireProviderReceipt = false } = {}, config) {
  assertObject(input);
  const allowed = ["purpose", "operation_id", "operationId", "request_id", "requestId", "request_digest", "requestDigest", "key_id", "keyId", "key_version", "keyVersion", "signature", "claim_token", "claimToken", "provider_receipt", "providerReceipt"];
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
  const providerReceiptInput = alias(input, "provider_receipt", "providerReceipt");
  const providerReceipt = providerReceiptInput === undefined
    ? undefined
    : normalizeProviderReceipt(providerReceiptInput, { operationId, keyId, keyVersion });
  if (requireProviderReceipt && providerReceipt === undefined) throw new TypeError("provider_receipt is required");
  const claimToken = alias(input, "claim_token", "claimToken");
  if (claimToken !== undefined && (typeof claimToken !== "string" || !TOKEN.test(claimToken))) throw new TypeError("claim_token is invalid");
  if (requireClaimToken && claimToken === undefined) throw new TypeError("claim_token is required");
  return Object.freeze({ purpose: config.purpose, operationId, requestDigest, keyId, keyVersion, signature, providerReceipt, claimToken, nowMs: nowMs(config.now) });
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

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function makeToken(randomBytes) {
  const value = randomBytes(32);
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array) || value.length !== 32) throw new TypeError("managed signer randomness is invalid");
  return Buffer.from(value).toString("base64url");
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
