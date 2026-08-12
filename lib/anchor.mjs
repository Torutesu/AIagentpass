import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { atomicWrite, secureMkdir } from "./config.mjs";
import { publicKeyFingerprint, verifyCheckpointRecord } from "./audit.mjs";
import { canonicalJson } from "./identity.mjs";
import { nativeAuditPublicKeyFingerprint, parseNativeAuditPublicKey, verifyNativeCheckpointRecord } from "./native-audit.mjs";

const ZERO_HASH = "0".repeat(64);
// NativeAuditRetentionVerifier accepts a 1 MiB canonical authorization. The
// HTTP envelope needs a small, bounded allowance for {"authorization":...}.
const MAX_DOCUMENT_BYTES = 1024 * 1024;
const MAX_BODY_BYTES = MAX_DOCUMENT_BYTES + 1024;
const MAX_RECOVERY_AUTHORIZATION_MS = 15 * 60_000;
const MAX_RECOVERY_CLOCK_SKEW_MS = 5_000;
// NativeAuditRetentionVerifier applies the deployment's configured minimum.
// The anchor validates the signed duration and its elapsed age without inventing
// a second policy value that could make a valid Swift authorization incompatible.
const MIN_AUDIT_RETENTION_SECONDS = 1;
const MAX_PRUNE_SEGMENTS = 4096;
const MAX_PRUNE_NONCE_LOG_BYTES = 64 * 1024 * 1024;
const PRUNE_HEAD_SNAPSHOT_NAME = ".audit-prune-head.snapshot.json";
const PRUNE_HEAD_SNAPSHOT_MAX_BYTES = 32 * 1024;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
// SEC 2 secp256r1 group order. P1363 encodes r and s as two fixed-width,
// unsigned, big-endian 32-byte integers. Requiring s <= floor(n / 2) gives
// every signed statement one canonical representation and prevents an
// observer from replacing (r, s) with the equally valid (r, n - s) after the
// signature bytes have been committed into a checkpoint/transition/prune hash.
const P256_ORDER = Buffer.from("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", "hex");
const P256_HALF_ORDER = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");
const P256_ZERO_SCALAR = Buffer.alloc(32);

export function initializeAnchor(directory) {
  secureMkdir(directory);
  const privateFile = path.join(directory, "anchor-private.pem");
  const publicFile = path.join(directory, "anchor-public.pem");
  if (fs.existsSync(privateFile) || fs.existsSync(publicFile)) throw new Error("Anchor key files already exist");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(privateFile, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
  fs.writeFileSync(publicFile, publicKey.export({ type: "spki", format: "pem" }), { flag: "wx", mode: 0o644 });
  secureMkdir(path.join(directory, "tenants"));
  return { private_file: privateFile, public_file: publicFile, fingerprint: publicKeyFingerprint(publicKey) };
}

export function enrollAnchorTenant(directory, tenant, auditPublicKey, { installationId, recoveryPolicy } = {}) {
  assertTenant(tenant);
  loadAnchorPrivateKey(directory);
  const identity = identifyAuditPublicKey(auditPublicKey);
  const tenantDir = path.join(directory, "tenants", tenant);
  secureMkdir(tenantDir);
  const configFile = path.join(tenantDir, "config.json");
  if (fs.existsSync(configFile)) throw new Error("Anchor tenant is already enrolled");
  if ((installationId === undefined) !== (recoveryPolicy === undefined)) throw new Error("Recovery-enabled enrollment requires both installation ID and recovery policy");
  const pinnedRecovery = recoveryPolicy === undefined ? undefined : normalizeRecoveryPolicy(recoveryPolicy);
  if (pinnedRecovery && !isInstallationId(installationId)) throw new Error("Anchor tenant installation ID is invalid");
  const config = {
    version: pinnedRecovery ? 3 : identity.algorithm === "ed25519" ? 1 : 2,
    tenant,
    checkpoint_algorithm: identity.algorithm,
    audit_public_key: identity.publicKey,
    audit_key_fingerprint: identity.fingerprint,
    ...(pinnedRecovery ? { installation_id: installationId, recovery_policy: pinnedRecovery } : {}),
    enrolled_at: new Date().toISOString()
  };
  atomicWrite(configFile, `${JSON.stringify(config, null, 2)}\n`, 0o600);
  rebuildPruneHeadSnapshot(directory, tenant);
  return config;
}

/*
Stable cross-language v3 contract (objects reject every unlisted field):
  policy = {version:1, policy_id, threshold,
    keys:[{id, public_key, fingerprint}], policy_hash}
  authorization = anchorRecoveryAuthorization(transition)
  recovery_evidence = {version:1, policy, authorization,
    approvals:[{key_id, signature}]}
  transition = {...authorization, recovery_evidence, new_signature,
    transition_hash}
IDs in policy.keys and approvals use ascending ASCII order. public_key is the
canonical Ed25519 SPKI PEM and fingerprint is SHA-256 over its SPKI DER.
policy_hash is SHA-256(canonicalJson(policy without policy_hash)). Every recovery
approval signature and new_signature signs UTF-8 canonicalJson(authorization);
new_signature uses the replacement audit-key algorithm. transition_hash is
SHA-256(canonicalJson(transition without transition_hash)). The anchor emits the
unchanged schema-v2 transition receipt/event record for v2 and v3 transitions.
*/
export function createAnchorRecoveryPolicy({ policy_id, threshold, keys }) {
  return normalizeRecoveryPolicy({ version: 1, policy_id, threshold, keys });
}

// Stable v3 signing schema. Recovery approvers and the replacement audit key
// sign canonicalJson(returnValue). The transition embeds this value byte-for-byte
// as recovery_evidence.authorization; no request-only fields are permitted.
export function anchorRecoveryAuthorization(value) {
  return {
    version: 3,
    tenant: value.tenant,
    installation_id: value.installation_id,
    role: value.role,
    operation_id: value.operation_id,
    recovery_request_id: value.recovery_request_id,
    recovery_policy_id: value.recovery_policy_id,
    recovery_policy_hash: value.recovery_policy_hash,
    from_generation: value.from_generation,
    to_generation: value.to_generation,
    old_key_fingerprint: value.old_key_fingerprint,
    new_key_fingerprint: value.new_key_fingerprint,
    new_public_key: value.new_public_key,
    lifecycle_head_hash: value.lifecycle_head_hash,
    created_at: value.created_at,
    expires_at: value.expires_at,
    previous_transition_hash: value.previous_transition_hash,
    previous_transition_receipt_hash: value.previous_transition_receipt_hash,
    last_checkpoint_index: value.last_checkpoint_index,
    last_checkpoint_hash: value.last_checkpoint_hash,
    last_checkpoint_receipt_hash: value.last_checkpoint_receipt_hash,
    previous_anchor_event_index: value.previous_anchor_event_index,
    previous_anchor_event_hash: value.previous_anchor_event_hash,
    retiring_generation_pending_checkpoint_count: value.retiring_generation_pending_checkpoint_count
  };
}

export function submitAnchorCheckpoint(directory, tenant, checkpoint, now = Date.now()) {
  const recordsFile = path.join(directory, "tenants", tenant, "records.jsonl");
  const lockFile = path.join(directory, "tenants", tenant, ".update.lock");
  const lock = acquireTenantLock(lockFile);
  let recordsLog;
  try {
    recordsLog = openRecordLog(recordsFile, { create: true });
    const config = loadTenant(directory, tenant);
    const transitionRecords = readRecords(path.join(directory, "tenants", tenant, "key-transitions.jsonl"));
    const records = recordsLog.records;
    const anchorVerificationKey = readAnchorPublicKey(directory);
    const tenantConfig = verifyTenantTransitions(transitionRecords, config, anchorVerificationKey, tenant);
    verifyTenantRecords(records, tenantConfig, anchorVerificationKey, tenant);
    const pruneRecords = readRecords(path.join(directory, "tenants", tenant, "audit-prunes.jsonl"));
    verifyTenantPrunes(pruneRecords, records, transitionRecords, tenantConfig, anchorVerificationKey, tenant, path.join(directory, "tenants", tenant, "audit-prunes.tip.json"));
    const eventState = verifyTenantEventState(records, transitionRecords, pruneRecords, tenant);
    verifyTransitionBoundaries(transitionRecords, records, tenantConfig, tenant);

    // A response may have been lost immediately before a key transition. Locate a
    // byte-identical already-anchored checkpoint before enforcing the current key.
    const existing = records.find((record) => record.checkpoint?.checkpoint_hash === checkpoint?.checkpoint_hash);
    if (existing) {
      if (canonicalJson(existing.checkpoint) !== canonicalJson(checkpoint)) throw new Error("Checkpoint hash equivocation detected");
      return existing.receipt;
    }
    const verifiedCheckpoint = verifyTenantCheckpoint(checkpoint, tenantConfig.active, { requireCanonicalP256: true });
    if (tenantConfig.active.generation > 1 && (verifiedCheckpoint.version !== 2 || verifiedCheckpoint.key_generation !== tenantConfig.active.generation || verifiedCheckpoint.lifecycle_head_hash !== tenantConfig.latestTransition.transition.lifecycle_head_hash)) {
      throw new Error("Checkpoint does not bind the active audit key generation and lifecycle head");
    }
    const previous = records.at(-1);
    if (!previous && verifiedCheckpoint.previous_checkpoint_hash !== ZERO_HASH) throw new Error("First anchored checkpoint must start at the checkpoint chain origin");
    if (previous && verifiedCheckpoint.previous_checkpoint_hash !== previous.checkpoint.checkpoint_hash) throw new Error("Checkpoint does not extend the anchored chain");
    if (previous && verifiedCheckpoint.entries < previous.checkpoint.entries) throw new Error("Checkpoint entry count rollback detected");
    const receiptStatement = {
      version: 2,
      tenant,
      index: records.length + 1,
      checkpoint_hash: verifiedCheckpoint.checkpoint_hash,
      received_at: new Date(Math.max(now, previous ? Date.parse(previous.receipt.received_at) : 0, eventState.receivedAt)).toISOString(),
      previous_receipt_hash: previous?.receipt.receipt_hash ?? ZERO_HASH,
      event_index: eventState.index + 1,
      previous_event_hash: eventState.hash
    };
    const privateKey = loadAnchorPrivateKey(directory);
    const anchorPublicKey = crypto.createPublicKey(privateKey);
    const signature = crypto.sign(null, receiptBytes(receiptStatement), privateKey).toString("base64");
    const receipt = { ...receiptStatement, anchor_key_fingerprint: publicKeyFingerprint(anchorPublicKey), signature };
    receipt.receipt_hash = hashCanonical(receipt);
    invalidatePruneHeadSnapshot(directory, tenant);
    recordsLog.append(`${JSON.stringify({ checkpoint: verifiedCheckpoint, receipt })}\n`);
    rebuildPruneHeadSnapshot(directory, tenant);
    return receipt;
  } finally {
    try { recordsLog?.close(); }
    finally { releaseTenantLock(lockFile, lock); }
  }
}

export function submitAnchorKeyTransition(directory, tenant, transition, now = Date.now()) {
  const file = path.join(directory, "tenants", tenant, "key-transitions.jsonl");
  const checkpointsFile = path.join(directory, "tenants", tenant, "records.jsonl");
  const lockFile = path.join(directory, "tenants", tenant, ".update.lock");
  const lock = acquireTenantLock(lockFile);
  let transitionLog;
  try {
    transitionLog = openRecordLog(file, { create: true });
    const config = loadTenant(directory, tenant);
    const records = transitionLog.records;
    const checkpoints = readRecords(checkpointsFile);
    const anchorPublicKey = readAnchorPublicKey(directory);
    const trust = verifyTenantTransitions(records, config, anchorPublicKey, tenant);
    verifyTenantRecords(checkpoints, trust, anchorPublicKey, tenant);
    const pruneRecords = readRecords(path.join(directory, "tenants", tenant, "audit-prunes.jsonl"));
    verifyTenantPrunes(pruneRecords, checkpoints, records, trust, anchorPublicKey, tenant, path.join(directory, "tenants", tenant, "audit-prunes.tip.json"));
    const eventState = verifyTenantEventState(checkpoints, records, pruneRecords, tenant);
    verifyTransitionBoundaries(records, checkpoints, trust, tenant);
    const decoded = decodeKeyTransition(transition);
    const existing = records.find((record) => record.transition.operation_id === decoded.operation_id);
    if (existing) {
      if (canonicalJson(existing.transition) !== canonicalJson(decoded)) throw new Error("Audit key transition operation equivocation detected");
      return existing.receipt;
    }
    if (![2, 3].includes(decoded.version)) throw new Error("New audit key transitions require schema version 2 or 3; version 1 records are verification-only migration history");
    const next = verifyKeyTransition(decoded, trust.active, {
      tenant,
      expectedGeneration: trust.active.generation + 1,
      previousTransitionHash: trust.latestTransition?.transition.transition_hash ?? ZERO_HASH,
      previousCreatedAt: trust.latestTransition?.transition.created_at,
      usedFingerprints: new Set(trust.keyHistory.map((item) => item.fingerprint)),
      usedRecoveryRequestIds: new Set(trust.transitions.filter((item) => item.transition.version === 3).map((item) => item.transition.recovery_request_id)),
      recoveryTrust: trust.recovery_policy ? { installationId: trust.installation_id, policy: trust.recovery_policy } : undefined,
      requireCanonicalP256: true,
      now
    });
    assertCurrentTransitionBoundary(next, checkpoints, records, trust, eventState);
    const previousReceipt = trust.latestTransition?.receipt;
    const receivedAt = Math.max(now, Date.parse(next.created_at), previousReceipt ? Date.parse(previousReceipt.received_at) : 0, eventState.receivedAt);
    if (next.version === 3 && receivedAt > Date.parse(next.expires_at)) throw new Error("Audit key recovery authorization expired before the anchor event boundary");
    const statement = {
      version: 2,
      tenant,
      index: records.length + 1,
      transition_hash: next.transition_hash,
      received_at: new Date(receivedAt).toISOString(),
      previous_receipt_hash: previousReceipt?.receipt_hash ?? ZERO_HASH,
      event_index: eventState.index + 1,
      previous_event_hash: eventState.hash,
      last_checkpoint_index: next.last_checkpoint_index,
      last_checkpoint_hash: next.last_checkpoint_hash,
      last_checkpoint_receipt_hash: next.last_checkpoint_receipt_hash
    };
    const privateKey = loadAnchorPrivateKey(directory);
    const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64");
    const receipt = { ...statement, anchor_key_fingerprint: publicKeyFingerprint(crypto.createPublicKey(privateKey)), signature };
    receipt.receipt_hash = hashCanonical(receipt);
    invalidatePruneHeadSnapshot(directory, tenant);
    transitionLog.append(`${JSON.stringify({ transition: next, receipt })}\n`);
    rebuildPruneHeadSnapshot(directory, tenant);
    return receipt;
  } finally {
    try { transitionLog?.close(); }
    finally { releaseTenantLock(lockFile, lock); }
  }
}

// The post-prune manifest is deliberately absent here. It is a local artifact
// produced only after deletion and is neither accepted nor trusted by the anchor.
export function submitAnchorPrune(directory, tenant, authorization, now = Date.now(), submittedLease = undefined, leaseRuntime = defaultPruneLeaseRuntime) {
  assertTenant(tenant);
  if (!isEpochMilliseconds(now)) throw new Error("Audit prune anchor time is invalid");
  const tenantDir = path.join(directory, "tenants", tenant);
  const file = path.join(tenantDir, "audit-prunes.jsonl");
  const tipFile = path.join(tenantDir, "audit-prunes.tip.json");
  const lockFile = path.join(tenantDir, ".update.lock");
  const leaseFile = path.join(tenantDir, ".audit-prune-lease.json");
  const lock = acquireTenantLock(lockFile);
  let pruneLog;
  try {
    pruneLog = openRecordLog(file, { create: true });
    const config = loadTenant(directory, tenant);
    const checkpoints = readRecords(path.join(tenantDir, "records.jsonl"));
    const transitions = readRecords(path.join(tenantDir, "key-transitions.jsonl"));
    const anchorPublicKey = readAnchorPublicKey(directory);
    const trust = verifyTenantTransitions(transitions, config, anchorPublicKey, tenant);
    verifyTenantRecords(checkpoints, trust, anchorPublicKey, tenant);
    const priorPrunes = verifyTenantPrunes(pruneLog.records, checkpoints, transitions, trust, anchorPublicKey, tenant, tipFile);
    const eventState = verifyTenantEventState(checkpoints, transitions, pruneLog.records, tenant);
    verifyTransitionBoundaries(transitions, checkpoints, trust, tenant);

    const decoded = decodePruneAuthorization(authorization);
    const activeLease = readActivePruneLease(leaseFile, tenant, anchorPublicKey, leaseRuntime);
    if (activeLease) {
      guardSubmittedPruneLease(activeLease, submittedLease, decoded, priorPrunes.at(-1)?.receipt ?? null, trust);
      removePruneLease(leaseFile, activeLease.lease_id);
      leaseRuntime.foreignLeaseFirstObserved.delete(activeLease.lease_id);
    } else throw new Error("Audit prune submit requires an exact active lease; direct submission is disabled");
    const sameOperation = pruneLog.records.find((record) => record.authorization.operation_id === decoded.operation_id);
    const sameSequence = pruneLog.records.find((record) => record.authorization.sequence === decoded.sequence);
    const sameHash = pruneLog.records.find((record) => record.authorization.authorization_hash === decoded.authorization_hash);
    const existing = sameOperation ?? sameSequence ?? sameHash;
    if (existing) {
      if (canonicalJson(existing.authorization) !== canonicalJson(decoded)) throw new Error("Audit prune operation, sequence, or hash equivocation detected");
      return existing.receipt;
    }

    const prior = priorPrunes.at(-1);
    const verified = verifyPruneAuthorization(decoded, {
      tenant,
      prior,
      checkpoints,
      transitions,
      trust,
      eventState,
      requireCanonicalP256: true,
      now
    });
    const receivedAt = Math.max(Number(now), Date.parse(verified.requested_at), eventState.receivedAt, prior ? Date.parse(prior.receipt.received_at) : 0);
    if (!Number.isFinite(receivedAt)) throw new Error("Audit prune receipt timestamp is invalid");
    const statement = {
      version: 1,
      tenant,
      sequence: verified.sequence,
      authorization_hash: verified.authorization_hash,
      previous_receipt_hash: prior?.receipt.receipt_hash ?? ZERO_HASH,
      anchor_event_index: eventState.index + 1,
      previous_anchor_event_hash: eventState.hash,
      received_at: new Date(receivedAt).toISOString()
    };
    const privateKey = loadAnchorPrivateKey(directory);
    const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64");
    const receipt = { ...statement, anchor_key_fingerprint: publicKeyFingerprint(crypto.createPublicKey(privateKey)), signature };
    receipt.receipt_hash = hashCanonical(receipt);
    invalidatePruneHeadSnapshot(directory, tenant);
    pruneLog.append(`${JSON.stringify({ authorization: verified, receipt })}\n`);
    writePruneTip(tipFile, pruneLog.records.length + 1, verified, receipt);
    rebuildPruneHeadSnapshot(directory, tenant);
    return receipt;
  } finally {
    try { pruneLog?.close(); }
    finally { releaseTenantLock(lockFile, lock); }
  }
}

// Read-only monotonic position used by native clients to pin completed prune
// evidence outside the host. Both empty and non-empty positions are wrapped in
// a fresh nonce-bound envelope signed by the anchor key. A caller verifies the
// envelope before separately verifying the exact embedded prune receipt.
export function readAnchorPruneHead(directory, tenant, requestNonce, now = Date.now()) {
  assertTenant(tenant);
  if (!isPruneHeadNonce(requestNonce) || !isEpochMilliseconds(now)) throw new Error("Audit prune head nonce or time is invalid");
  const privateKey = loadAnchorPrivateKey(directory);
  const tenantDir = path.join(directory, "tenants", tenant);
  const configFile = path.join(tenantDir, "config.json");
  if (!fs.existsSync(configFile)) {
    if (fs.existsSync(tenantDir)) assertPrivateDirectory(tenantDir, "Anchor tenant directory");
    return pruneHeadValue(tenant, null, false, requestNonce, now, privateKey);
  }
  assertPrivateDirectory(tenantDir, "Anchor tenant directory");

  // Deliberately do not acquire `.update.lock`: GET is a non-mutating observation and
  // must never fence a writer. A concurrent append can make this verification fail or
  // yield the preceding coherent head; the subsequent signed lease POST performs the
  // authoritative expected-position CAS under the tenant lock.
  const config = loadTenant(directory, tenant);
  const checkpoints = readRecords(path.join(tenantDir, "records.jsonl"));
  const transitions = readRecords(path.join(tenantDir, "key-transitions.jsonl"));
  const prunes = readRecords(path.join(tenantDir, "audit-prunes.jsonl"));
  const anchorPublicKey = readAnchorPublicKey(directory);
  const trust = verifyTenantTransitions(transitions, config, anchorPublicKey, tenant);
  verifyTenantRecords(checkpoints, trust, anchorPublicKey, tenant);
  const verifiedPrunes = verifyTenantPrunes(prunes, checkpoints, transitions, trust, anchorPublicKey, tenant, path.join(tenantDir, "audit-prunes.tip.json"), { repairTip: false });
  verifyTenantEventState(checkpoints, transitions, prunes, tenant);
  verifyTransitionBoundaries(transitions, checkpoints, trust, tenant);
  const receipt = verifiedPrunes.at(-1)?.receipt ?? null;
  return pruneHeadValue(tenant, receipt, true, requestNonce, now, privateKey);
}

/// HTTP-only O(1) path. Startup and every writer establish the signed snapshot;
/// this function never scans an append-only history and never takes the tenant lock.
export function readAnchorPruneHeadSnapshot(directory, tenant, requestNonce, now = Date.now(), verifiedSnapshot = undefined) {
  assertTenant(tenant);
  if (!isPruneHeadNonce(requestNonce) || !isEpochMilliseconds(now)) throw new Error("Audit prune head nonce or time is invalid");
  const privateKey = loadAnchorPrivateKey(directory);
  const tenantDir = path.join(directory, "tenants", tenant);
  const configFile = path.join(tenantDir, "config.json");
  if (!fs.existsSync(configFile)) {
    if (fs.existsSync(tenantDir)) assertPrivateDirectory(tenantDir, "Anchor tenant directory");
    return pruneHeadValue(tenant, null, false, requestNonce, now, privateKey);
  }
  const snapshot = verifiedSnapshot ?? readVerifiedPruneHeadSnapshot(directory, tenant);
  verifyPruneHeadSnapshot(snapshot, tenant, readAnchorPublicKey(directory));
  return pruneHeadValue(tenant, snapshot.prune_receipt, true, requestNonce, now, privateKey);
}

function computePruneHeadSnapshot(directory, tenant, { repairNonceTip = false } = {}) {
  const tenantDir = path.join(directory, "tenants", tenant);
  assertPrivateDirectory(tenantDir, "Anchor tenant directory");
  const config = loadTenant(directory, tenant);
  const checkpoints = readRecords(path.join(tenantDir, "records.jsonl"));
  const transitions = readRecords(path.join(tenantDir, "key-transitions.jsonl"));
  const prunes = readRecords(path.join(tenantDir, "audit-prunes.jsonl"));
  const anchorPublicKey = readAnchorPublicKey(directory);
  const trust = verifyTenantTransitions(transitions, config, anchorPublicKey, tenant);
  verifyTenantRecords(checkpoints, trust, anchorPublicKey, tenant);
  const verifiedPrunes = verifyTenantPrunes(prunes, checkpoints, transitions, trust, anchorPublicKey, tenant, path.join(tenantDir, "audit-prunes.tip.json"), { repairTip: repairNonceTip });
  const eventState = verifyTenantEventState(checkpoints, transitions, prunes, tenant);
  verifyTransitionBoundaries(transitions, checkpoints, trust, tenant);
  const checkpoint = checkpoints.at(-1) ?? null;
  const transition = transitions.at(-1) ?? null;
  const prune = verifiedPrunes.at(-1) ?? null;
  const nonceLedger = readPruneNonceLedgerPosition(tenantDir, tenant, anchorPublicKey, { repairTip: repairNonceTip });
  return {
    version: 1, tenant,
    checkpoint_count: checkpoints.length,
    checkpoint_hash: checkpoint?.checkpoint.checkpoint_hash ?? ZERO_HASH,
    checkpoint_receipt_hash: checkpoint?.receipt.receipt_hash ?? ZERO_HASH,
    transition_count: transitions.length,
    transition_hash: transition?.transition.transition_hash ?? ZERO_HASH,
    transition_receipt_hash: transition?.receipt.receipt_hash ?? ZERO_HASH,
    prune_count: verifiedPrunes.length,
    prune_authorization_hash: prune?.authorization.authorization_hash ?? ZERO_HASH,
    prune_receipt_hash: prune?.receipt.receipt_hash ?? ZERO_HASH,
    prune_receipt: prune?.receipt ?? null,
    event_index: eventState.index,
    event_hash: eventState.hash,
    active_audit_key_fingerprint: trust.active.fingerprint,
    nonce_ledger_count: nonceLedger.count,
    nonce_ledger_head_hash: nonceLedger.headHash
  };
}

function signedPruneHeadSnapshot(directory, tenant, options = {}) {
  const statement = computePruneHeadSnapshot(directory, tenant, options);
  const privateKey = loadAnchorPrivateKey(directory);
  const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64");
  const signed = { ...statement, anchor_key_fingerprint: publicKeyFingerprint(crypto.createPublicKey(privateKey)), signature };
  return { ...signed, snapshot_hash: hashCanonical(signed) };
}

function verifyPruneHeadSnapshot(value, tenant, anchorPublicKey) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Audit prune head snapshot is invalid");
  const statementKeys = ["active_audit_key_fingerprint", "checkpoint_count", "checkpoint_hash", "checkpoint_receipt_hash", "event_hash", "event_index", "nonce_ledger_count", "nonce_ledger_head_hash", "prune_authorization_hash", "prune_count", "prune_receipt", "prune_receipt_hash", "tenant", "transition_count", "transition_hash", "transition_receipt_hash", "version"];
  assertExactKeys(value, [...statementKeys, "anchor_key_fingerprint", "signature", "snapshot_hash"], "Audit prune head snapshot");
  const { anchor_key_fingerprint, signature, snapshot_hash, ...statement } = value;
  if (statement.version !== 1 || statement.tenant !== tenant || ![statement.checkpoint_count, statement.transition_count, statement.prune_count, statement.event_index, statement.nonce_ledger_count].every((item) => Number.isSafeInteger(item) && item >= 0) ||
      ![statement.checkpoint_hash, statement.checkpoint_receipt_hash, statement.transition_hash, statement.transition_receipt_hash, statement.prune_authorization_hash, statement.prune_receipt_hash, statement.event_hash, statement.nonce_ledger_head_hash].every(isHash) || !isFingerprint(statement.active_audit_key_fingerprint)) throw new Error("Audit prune head snapshot statement is invalid");
  if (statement.prune_count === 0) {
    if (statement.prune_receipt !== null || statement.prune_receipt_hash !== ZERO_HASH || statement.prune_authorization_hash !== ZERO_HASH) throw new Error("Audit prune head snapshot zero state is invalid");
  } else {
    const receipt = verifyAnchorPruneReceipt(statement.prune_receipt, anchorPublicKey, { tenant, sequence: statement.prune_count });
    if (receipt.receipt_hash !== statement.prune_receipt_hash) throw new Error("Audit prune head snapshot receipt is invalid");
  }
  const key = assertEd25519PublicKey(anchorPublicKey, "Audit prune head snapshot key");
  if (anchor_key_fingerprint !== publicKeyFingerprint(key) || !isCanonicalBase64(signature)) throw new Error("Audit prune head snapshot signature is invalid");
  const signatureBytes = Buffer.from(signature, "base64");
  if (signatureBytes.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(statement)), key, signatureBytes)) throw new Error("Audit prune head snapshot signature is invalid");
  const signed = { ...statement, anchor_key_fingerprint, signature };
  if (snapshot_hash !== hashCanonical(signed)) throw new Error("Audit prune head snapshot hash is invalid");
  return value;
}

function readVerifiedPruneHeadSnapshot(directory, tenant) {
  const file = path.join(directory, "tenants", tenant, PRUNE_HEAD_SNAPSHOT_NAME);
  const bytes = readPrivateFilePinned(file, "Audit prune head snapshot", PRUNE_HEAD_SNAPSHOT_MAX_BYTES);
  if (bytes.length === 0 || bytes.length > PRUNE_HEAD_SNAPSHOT_MAX_BYTES) throw new Error("Audit prune head snapshot size is invalid");
  const value = JSON.parse(bytes.toString("utf8"));
  if (!bytes.equals(Buffer.from(canonicalJson(value)))) throw new Error("Audit prune head snapshot is noncanonical");
  return verifyPruneHeadSnapshot(value, tenant, readAnchorPublicKey(directory));
}

function writePruneHeadSnapshot(directory, tenant, value) {
  const file = path.join(directory, "tenants", tenant, PRUNE_HEAD_SNAPSHOT_NAME);
  writePrivateCanonicalAtomic(file, value, "Audit prune head snapshot");
}

function invalidatePruneHeadSnapshot(directory, tenant) {
  const file = path.join(directory, "tenants", tenant, PRUNE_HEAD_SNAPSHOT_NAME);
  if (!fs.existsSync(file)) return;
  removePrivateFilePinned(file, "Audit prune head snapshot");
}

function rebuildPruneHeadSnapshot(directory, tenant) {
  const value = signedPruneHeadSnapshot(directory, tenant);
  writePruneHeadSnapshot(directory, tenant, value);
  return value;
}

function initializePruneHeadSnapshots(directory) {
  const floors = new Map();
  const tenantsDir = path.join(directory, "tenants");
  assertPrivateDirectory(tenantsDir, "Anchor tenants directory");
  for (const entry of fs.readdirSync(tenantsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(entry.name)) throw new Error("Anchor tenants directory contains an unsafe entry");
    const tenantDir = path.join(tenantsDir, entry.name);
    assertPrivateDirectory(tenantDir, "Anchor tenant directory");
    cleanPruneHeadSnapshotTemps(tenantDir);
    const lockFile = path.join(tenantDir, ".update.lock");
    const lock = acquireTenantLock(lockFile);
    try {
      const expected = signedPruneHeadSnapshot(directory, entry.name, { repairNonceTip: true });
      const snapshotFile = path.join(tenantDir, PRUNE_HEAD_SNAPSHOT_NAME);
      if (fs.existsSync(snapshotFile)) {
        assertPrivateRegularFile(snapshotFile, "Audit prune head snapshot");
        const current = readVerifiedPruneHeadSnapshot(directory, entry.name);
        if (canonicalJson(current) === canonicalJson(expected)) {
          floors.set(entry.name, createPruneHeadFloor(directory, entry.name, current));
          continue;
        }
        assertSnapshotCanAdvance(current, expected);
      }
      writePruneHeadSnapshot(directory, entry.name, expected);
      floors.set(entry.name, createPruneHeadFloor(directory, entry.name, expected));
    } finally { releaseTenantLock(lockFile, lock); }
  }
  return floors;
}

function cleanPruneHeadSnapshotTemps(tenantDir) {
  const prefixes = [`${PRUNE_HEAD_SNAPSHOT_NAME}.`, ".audit-prune-lease-nonces.tip.json."];
  const directoryFlags = fs.constants.O_RDONLY | noFollowFlag() | (fs.constants.O_DIRECTORY ?? 0);
  const directoryFd = fs.openSync(tenantDir, directoryFlags);
  try {
    assertPrivateDirectoryFd(directoryFd, "Audit prune temporary cleanup");
    for (const name of fs.readdirSync(tenantDir)) {
      assertDirectoryPathRefersToFd(tenantDir, directoryFd, "Audit prune temporary cleanup");
      if (!prefixes.some((prefix) => name.startsWith(prefix)) || !name.endsWith(".tmp")) continue;
      const file = path.join(tenantDir, name);
      assertPrivateRegularFile(file, "Audit prune head snapshot temporary file");
      fs.unlinkSync(file);
      assertDirectoryPathRefersToFd(tenantDir, directoryFd, "Audit prune temporary cleanup");
      fs.fsyncSync(directoryFd);
    }
    assertDirectoryPathRefersToFd(tenantDir, directoryFd, "Audit prune temporary cleanup");
  } finally { fs.closeSync(directoryFd); }
}

function assertSnapshotCanAdvance(current, expected) {
  const positions = [
    ["checkpoint_count", "checkpoint_hash", "checkpoint_receipt_hash"],
    ["transition_count", "transition_hash", "transition_receipt_hash"],
    ["prune_count", "prune_authorization_hash", "prune_receipt_hash"],
    ["nonce_ledger_count", "nonce_ledger_head_hash"]
  ];
  for (const [count, ...hashes] of positions) {
    if (current[count] > expected[count]) throw new Error("Audit prune head snapshot detects history rollback");
    if (current[count] === expected[count] && hashes.some((key) => current[key] !== expected[key])) throw new Error("Audit prune head snapshot detects history substitution");
  }
  if (current.event_index > expected.event_index || (current.event_index === expected.event_index && current.event_hash !== expected.event_hash)) throw new Error("Audit prune head snapshot detects event history rollback or substitution");
  // Writers remove the snapshot and fsync its parent before touching any bound
  // log. Therefore an existing, valid but different snapshot cannot be a normal
  // append-before-snapshot crash remnant; accepting it would enable coherent
  // rollback of the histories and snapshot together.
  throw new Error("Audit prune head snapshot does not match verified tenant history");
}

function createPruneHeadFloor(directory, tenant, snapshot) {
  return {
    snapshot,
    storage: [directory, path.join(directory, "tenants"), path.join(directory, "tenants", tenant)].map((item) => {
      assertPrivateDirectory(item, "Anchor monotonic floor directory");
      const stat = fs.lstatSync(item);
      return { path: item, dev: stat.dev, ino: stat.ino };
    })
  };
}

function observePruneHeadFloor(directory, tenant, floors) {
  const floor = floors.get(tenant);
  if (!floor) throw new Error("Anchor tenant is not enrolled");
  validatePruneHeadFloorStorage(floor);
  const current = readVerifiedPruneHeadSnapshot(directory, tenant);
  if (canonicalJson(current) === canonicalJson(floor.snapshot)) return current;
  assertStrictPruneHeadAdvance(floor.snapshot, current);
  const lockFile = path.join(directory, "tenants", tenant, ".update.lock");
  const lock = acquireTenantLock(lockFile);
  try {
    validatePruneHeadFloorStorage(floor);
    const lockedCurrent = readVerifiedPruneHeadSnapshot(directory, tenant);
    if (canonicalJson(lockedCurrent) === canonicalJson(floor.snapshot)) throw new Error("Anchor signed snapshot changed during strict-advance verification");
    assertStrictPruneHeadAdvance(floor.snapshot, lockedCurrent);
    const derived = signedPruneHeadSnapshot(directory, tenant, { repairNonceTip: false });
    if (canonicalJson(derived) !== canonicalJson(lockedCurrent)) throw new Error("Anchor signed snapshot advance does not match fully verified durable history and tips");
    validatePruneHeadFloorStorage(floor);
    const finalCurrent = readVerifiedPruneHeadSnapshot(directory, tenant);
    if (canonicalJson(finalCurrent) !== canonicalJson(lockedCurrent)) throw new Error("Anchor signed snapshot changed during durable-history verification");
    floor.snapshot = finalCurrent;
    return finalCurrent;
  } finally { releaseTenantLock(lockFile, lock); }
}

function validatePruneHeadFloorStorage(floor) {
  for (const identity of floor.storage) {
    assertPrivateDirectory(identity.path, "Anchor monotonic floor directory");
    const stat = fs.lstatSync(identity.path);
    if (stat.dev !== identity.dev || stat.ino !== identity.ino) throw new Error("Anchor storage volume or directory identity changed after startup");
  }
}

function assertStrictPruneHeadAdvance(previous, current) {
  const positions = [
    ["checkpoint_count", ["checkpoint_hash", "checkpoint_receipt_hash"]],
    ["transition_count", ["transition_hash", "transition_receipt_hash"]],
    ["prune_count", ["prune_authorization_hash", "prune_receipt_hash"]],
    ["nonce_ledger_count", ["nonce_ledger_head_hash"]]
  ];
  let advanced = false;
  for (const [count, hashes] of positions) {
    if (current[count] < previous[count]) throw new Error("Anchor signed snapshot regressed behind the in-memory monotonic floor");
    if (current[count] === previous[count]) {
      if (hashes.some((key) => current[key] !== previous[key])) throw new Error("Anchor signed snapshot equivocated at the in-memory monotonic floor");
    } else advanced = true;
  }
  if (current.event_index < previous.event_index) throw new Error("Anchor signed event snapshot regressed behind the in-memory monotonic floor");
  if (current.event_index === previous.event_index && current.event_hash !== previous.event_hash) throw new Error("Anchor signed event snapshot equivocated at the in-memory monotonic floor");
  const eventDelta = current.event_index - previous.event_index;
  const expectedEventDelta = (current.checkpoint_count - previous.checkpoint_count) + (current.transition_count - previous.transition_count) + (current.prune_count - previous.prune_count);
  if (eventDelta !== expectedEventDelta) throw new Error("Anchor signed snapshot component advance is inconsistent");
  if (current.transition_count === previous.transition_count && current.active_audit_key_fingerprint !== previous.active_audit_key_fingerprint) throw new Error("Anchor signed snapshot audit principal equivocated without a transition");
  if (!advanced && eventDelta === 0) throw new Error("Anchor signed snapshot changed without a monotonic component advance");
}

export function acquireAnchorPruneLease(directory, tenant, signedRequest, now = Date.now(), leaseRuntime = defaultPruneLeaseRuntime) {
  assertTenant(tenant);
  if (!isEpochMilliseconds(now)) throw new Error("Audit prune lease acquisition time is invalid");
  const tenantDir = path.join(directory, "tenants", tenant);
  assertPrivateDirectory(tenantDir, "Anchor tenant directory");
  const lockFile = path.join(tenantDir, ".update.lock");
  const leaseFile = path.join(tenantDir, ".audit-prune-lease.json");
  const nonceFile = path.join(tenantDir, ".audit-prune-lease-nonces.jsonl");
  const lock = acquireTenantLock(lockFile);
  try {
    if (readActivePruneLease(leaseFile, tenant, readAnchorPublicKey(directory), leaseRuntime)) throw new Error("Another audit prune lease is active for this tenant");
    const config = loadTenant(directory, tenant);
    const checkpoints = readRecords(path.join(tenantDir, "records.jsonl"));
    const transitions = readRecords(path.join(tenantDir, "key-transitions.jsonl"));
    const prunes = readRecords(path.join(tenantDir, "audit-prunes.jsonl"));
    const anchorPublicKey = readAnchorPublicKey(directory);
    const trust = verifyTenantTransitions(transitions, config, anchorPublicKey, tenant);
    verifyTenantRecords(checkpoints, trust, anchorPublicKey, tenant);
    const verifiedPrunes = verifyTenantPrunes(prunes, checkpoints, transitions, trust, anchorPublicKey, tenant, path.join(tenantDir, "audit-prunes.tip.json"), { repairTip: false });
    verifyTenantEventState(checkpoints, transitions, prunes, tenant);
    verifyTransitionBoundaries(transitions, checkpoints, trust, tenant);
    const receipt = verifiedPrunes.at(-1)?.receipt ?? null;
    const request = verifyPruneLeaseRequest(signedRequest, tenant, trust.active, receipt, now);
    rememberPruneLeaseNonce(directory, tenant, nonceFile, request.nonce, request.audit_key_fingerprint, now);
    const lease = pruneLeaseValue(tenant, receipt, request, now, loadAnchorPrivateKey(directory), leaseRuntime);
    writePruneLease(leaseFile, lease);
    return lease;
  } finally {
    releaseTenantLock(lockFile, lock);
  }
}

export function releaseAnchorPruneLease(directory, tenant, lease, signedRequest, now = Date.now(), leaseRuntime = defaultPruneLeaseRuntime) {
  assertTenant(tenant);
  if (!isEpochMilliseconds(now)) throw new Error("Audit prune lease release time is invalid");
  const tenantDir = path.join(directory, "tenants", tenant);
  assertPrivateDirectory(tenantDir, "Anchor tenant directory");
  const lockFile = path.join(tenantDir, ".update.lock");
  const leaseFile = path.join(tenantDir, ".audit-prune-lease.json");
  const lock = acquireTenantLock(lockFile);
  try {
    const active = readActivePruneLease(leaseFile, tenant, readAnchorPublicKey(directory), leaseRuntime);
    if (!active || canonicalJson(active) !== canonicalJson(lease)) throw new Error("Audit prune lease is expired, replayed, or substituted");
    const trust = loadTenantTrust(directory, tenant);
    verifyPruneLeaseReleaseRequest(signedRequest, tenant, trust.active, active, now);
    removePruneLease(leaseFile, active.lease_id);
    leaseRuntime.foreignLeaseFirstObserved.delete(active.lease_id);
    return { released: true, lease_id: active.lease_id };
  } finally {
    releaseTenantLock(lockFile, lock);
  }
}

export function verifyAnchorPruneReceipt(receipt, anchorPublicKey, { tenant, sequence, authorizationHash, previousReceiptHash, anchorEventIndex, previousAnchorEventHash } = {}) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("Audit prune receipt must be an object");
  const statement = {
    version: receipt.version,
    tenant: receipt.tenant,
    sequence: receipt.sequence,
    authorization_hash: receipt.authorization_hash,
    previous_receipt_hash: receipt.previous_receipt_hash,
    anchor_event_index: receipt.anchor_event_index,
    previous_anchor_event_hash: receipt.previous_anchor_event_hash,
    received_at: receipt.received_at
  };
  assertExactKeys(receipt, [...Object.keys(statement), "anchor_key_fingerprint", "signature", "receipt_hash"], "Audit prune receipt");
  if (statement.version !== 1 || !isSlug(statement.tenant) || !positiveSafeInteger(statement.sequence) || !isHash(statement.authorization_hash) || !isHash(statement.previous_receipt_hash) || !positiveSafeInteger(statement.anchor_event_index) || !isHash(statement.previous_anchor_event_hash) || !isCanonicalDate(statement.received_at)) throw new Error("Audit prune receipt statement is invalid");
  if (tenant !== undefined && statement.tenant !== tenant) throw new Error("Audit prune receipt tenant mismatch");
  if (sequence !== undefined && statement.sequence !== sequence) throw new Error("Audit prune receipt sequence mismatch");
  if (authorizationHash !== undefined && statement.authorization_hash !== authorizationHash) throw new Error("Audit prune receipt authorization mismatch");
  if (previousReceiptHash !== undefined && statement.previous_receipt_hash !== previousReceiptHash) throw new Error("Audit prune receipt chain mismatch");
  if (anchorEventIndex !== undefined && statement.anchor_event_index !== anchorEventIndex) throw new Error("Audit prune receipt event index mismatch");
  if (previousAnchorEventHash !== undefined && statement.previous_anchor_event_hash !== previousAnchorEventHash) throw new Error("Audit prune receipt event chain mismatch");
  const key = assertEd25519PublicKey(anchorPublicKey, "Anchor receipt public key");
  if (receipt.anchor_key_fingerprint !== publicKeyFingerprint(key) || !isCanonicalBase64(receipt.signature)) throw new Error("Audit prune receipt signature is invalid");
  const signature = Buffer.from(receipt.signature, "base64");
  if (signature.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(statement)), key, signature)) throw new Error("Audit prune receipt signature is invalid");
  const copy = { ...statement, anchor_key_fingerprint: receipt.anchor_key_fingerprint, signature: receipt.signature };
  if (hashCanonical(copy) !== receipt.receipt_hash) throw new Error("Audit prune receipt hash is invalid");
  return { ...copy, receipt_hash: receipt.receipt_hash };
}

export function verifyAnchorKeyTransitionReceipt(receipt, anchorPublicKey, { tenant, transitionHash, previousReceiptHash } = {}) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("Audit key transition receipt must be an object");
  const key = assertEd25519PublicKey(anchorPublicKey, "Anchor receipt public key");
  const statement = receipt.version === 2
    ? {
        version: receipt.version,
        tenant: receipt.tenant,
        index: receipt.index,
        transition_hash: receipt.transition_hash,
        received_at: receipt.received_at,
        previous_receipt_hash: receipt.previous_receipt_hash,
        event_index: receipt.event_index,
        previous_event_hash: receipt.previous_event_hash,
        last_checkpoint_index: receipt.last_checkpoint_index,
        last_checkpoint_hash: receipt.last_checkpoint_hash,
        last_checkpoint_receipt_hash: receipt.last_checkpoint_receipt_hash
      }
    : { version: receipt.version, tenant: receipt.tenant, index: receipt.index, transition_hash: receipt.transition_hash, received_at: receipt.received_at, previous_receipt_hash: receipt.previous_receipt_hash };
  const expectedKeys = receipt.version === 2
    ? [...Object.keys(statement), "anchor_key_fingerprint", "receipt_hash", "signature"].sort()
    : ["anchor_key_fingerprint", "index", "previous_receipt_hash", "receipt_hash", "received_at", "signature", "tenant", "transition_hash", "version"];
  if (canonicalJson(Object.keys(receipt).sort()) !== canonicalJson(expectedKeys)) throw new Error("Audit key transition receipt encoding is invalid");
  const commonInvalid = ![1, 2].includes(statement.version) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(statement.tenant ?? "") || !Number.isSafeInteger(statement.index) || statement.index < 1 || !isHash(statement.transition_hash) || !Number.isFinite(Date.parse(statement.received_at)) || !isHash(statement.previous_receipt_hash);
  const eventInvalid = statement.version === 2 && (!Number.isSafeInteger(statement.event_index) || statement.event_index < 1 || !isHash(statement.previous_event_hash) || !Number.isSafeInteger(statement.last_checkpoint_index) || statement.last_checkpoint_index < 1 || !isHash(statement.last_checkpoint_hash) || !isHash(statement.last_checkpoint_receipt_hash));
  if (commonInvalid || eventInvalid) throw new Error("Audit key transition receipt statement is invalid");
  if (tenant !== undefined && statement.tenant !== tenant) throw new Error("Audit key transition receipt tenant mismatch");
  if (transitionHash !== undefined && statement.transition_hash !== transitionHash) throw new Error("Audit key transition receipt hash mismatch");
  if (previousReceiptHash !== undefined && statement.previous_receipt_hash !== previousReceiptHash) throw new Error("Audit key transition receipt chain mismatch");
  if (receipt.anchor_key_fingerprint !== publicKeyFingerprint(key) || !isCanonicalBase64(receipt.signature)) throw new Error("Audit key transition receipt signature is invalid");
  const signature = Buffer.from(receipt.signature, "base64");
  if (signature.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(statement)), key, signature)) throw new Error("Audit key transition receipt signature is invalid");
  const copy = { ...statement, anchor_key_fingerprint: receipt.anchor_key_fingerprint, signature: receipt.signature };
  if ((statement.version === 2 ? hashCanonical(copy) : hash(copy)) !== receipt.receipt_hash) throw new Error("Audit key transition receipt hash is invalid");
  return { ...copy, receipt_hash: receipt.receipt_hash };
}

export function verifyAnchorReceipt(receipt, anchorPublicKey, { tenant, checkpointHash, previousReceiptHash } = {}) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("Anchor receipt must be an object");
  const verificationKey = assertEd25519PublicKey(anchorPublicKey, "Anchor receipt public key");
  const statement = receipt.version === 2
    ? { version: receipt.version, tenant: receipt.tenant, index: receipt.index, checkpoint_hash: receipt.checkpoint_hash, received_at: receipt.received_at, previous_receipt_hash: receipt.previous_receipt_hash, event_index: receipt.event_index, previous_event_hash: receipt.previous_event_hash }
    : { version: receipt.version, tenant: receipt.tenant, index: receipt.index, checkpoint_hash: receipt.checkpoint_hash, received_at: receipt.received_at, previous_receipt_hash: receipt.previous_receipt_hash };
  const expectedKeys = receipt.version === 2
    ? [...Object.keys(statement), "anchor_key_fingerprint", "receipt_hash", "signature"].sort()
    : ["anchor_key_fingerprint", "checkpoint_hash", "index", "previous_receipt_hash", "receipt_hash", "received_at", "signature", "tenant", "version"];
  if (canonicalJson(Object.keys(receipt).sort()) !== canonicalJson(expectedKeys)) throw new Error("Anchor receipt encoding is invalid");
  const commonInvalid = ![1, 2].includes(statement.version) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(statement.tenant ?? "") || !Number.isSafeInteger(statement.index) || statement.index < 1 || !isHash(statement.checkpoint_hash) || !Number.isFinite(Date.parse(statement.received_at)) || !isHash(statement.previous_receipt_hash);
  const eventInvalid = statement.version === 2 && (!Number.isSafeInteger(statement.event_index) || statement.event_index < 1 || !isHash(statement.previous_event_hash));
  if (commonInvalid || eventInvalid) throw new Error("Anchor receipt statement is invalid");
  if (tenant !== undefined && statement.tenant !== tenant) throw new Error("Anchor receipt tenant mismatch");
  if (checkpointHash !== undefined && statement.checkpoint_hash !== checkpointHash) throw new Error("Anchor receipt checkpoint mismatch");
  if (previousReceiptHash !== undefined && statement.previous_receipt_hash !== previousReceiptHash) throw new Error("Anchor receipt chain mismatch");
  if (receipt.anchor_key_fingerprint !== publicKeyFingerprint(verificationKey)) throw new Error("Anchor receipt key fingerprint mismatch");
  if (typeof receipt.signature !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(receipt.signature)) throw new Error("Anchor receipt signature is invalid");
  let signatureValid = false;
  try {
    const signature = Buffer.from(receipt.signature, "base64");
    signatureValid = signature.length === 64 && crypto.verify(null, receiptBytes(statement), verificationKey, signature);
  } catch {}
  if (!signatureValid) throw new Error("Anchor receipt signature is invalid");
  const copy = { ...statement, anchor_key_fingerprint: receipt.anchor_key_fingerprint, signature: receipt.signature };
  if ((statement.version === 2 ? hashCanonical(copy) : hash(copy)) !== receipt.receipt_hash) throw new Error("Anchor receipt hash is invalid");
  return { ...copy, receipt_hash: receipt.receipt_hash };
}

export function verifyAnchorRecords(records, auditPublicKey, anchorPublicKey, tenant) {
  const identity = identifyAuditPublicKey(auditPublicKey);
  return verifyTenantRecords(records, { checkpoint_algorithm: identity.algorithm, audit_public_key: identity.publicKey }, anchorPublicKey, tenant);
}

function verifyTenantRecords(records, tenantConfig, anchorPublicKey, tenant) {
  let previousCheckpoint = ZERO_HASH;
  let previousReceipt = ZERO_HASH;
  let previousEntries = 0;
  let previousReceivedAt = 0;
  let previousGeneration = 1;
  for (let index = 0; index < records.length; index += 1) {
    const identity = tenantConfig.keyHistory
      ? tenantConfig.keyHistory.find((item) => item.fingerprint === records[index].checkpoint?.public_key_fingerprint)
      : tenantConfig;
    if (!identity) throw new Error("Anchor checkpoint references an unknown audit key generation");
    if (identity.generation < previousGeneration) throw new Error("Anchor checkpoint audit key generation rollback detected");
    const checkpoint = verifyTenantCheckpoint(records[index].checkpoint, identity, { previousCheckpointHash: previousCheckpoint });
    if (identity.generation > 1 && (checkpoint.version !== 2 || checkpoint.key_generation !== identity.generation || checkpoint.lifecycle_head_hash !== identity.lifecycleHeadHash)) throw new Error("Anchor checkpoint lifecycle binding is invalid");
    const receipt = verifyAnchorReceipt(records[index].receipt, anchorPublicKey, { tenant, checkpointHash: checkpoint.checkpoint_hash, previousReceiptHash: previousReceipt });
    if (receipt.index !== index + 1) throw new Error("Anchor receipt index is invalid");
    if (checkpoint.entries < previousEntries) throw new Error("Anchor checkpoint entry count rollback detected");
    if (Date.parse(receipt.received_at) < previousReceivedAt) throw new Error("Anchor receipt timestamp rollback detected");
    previousCheckpoint = checkpoint.checkpoint_hash;
    previousReceipt = receipt.receipt_hash;
    previousEntries = checkpoint.entries;
    previousReceivedAt = Date.parse(receipt.received_at);
    previousGeneration = identity.generation ?? 1;
  }
  return { valid: true, records: records.length, latest_checkpoint: records.length ? previousCheckpoint : null, latest_receipt: records.length ? previousReceipt : null };
}

export function createAnchorServer(directory, { pruneLeaseRuntime = createAnchorPruneLeaseRuntime() } = {}) {
  loadAnchorPrivateKey(directory);
  const pruneHeadFloors = initializePruneHeadSnapshots(directory);
  const pruneHeadGlobalRate = new Map();
  const pruneHeadTenantRate = new Map();
  let activeRequests = 0;
  const server = http.createServer((request, response) => {
    if (activeRequests >= 128) return canonicalJsonResponse(response, 503, { error: "server_busy" });
    activeRequests += 1;
    Promise.resolve(handleRequest(directory, request, response, pruneLeaseRuntime, pruneHeadFloors, pruneHeadGlobalRate, pruneHeadTenantRate))
      .finally(() => { activeRequests -= 1; });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.maxConnections = 128;
  server.maxRequestsPerSocket = 100;
  return server;
}

export function verifyAnchorTenant(directory, tenant) {
  loadAnchorPrivateKey(directory);
  const tenantConfig = loadTenantTrust(directory, tenant);
  const records = readRecords(path.join(directory, "tenants", tenant, "records.jsonl"));
  return verifyTenantRecords(records, tenantConfig, readAnchorPublicKey(directory), tenant);
}

async function handleRequest(directory, request, response, pruneLeaseRuntime, pruneHeadFloors, pruneHeadGlobalRate, pruneHeadTenantRate) {
  try {
    if (request.method === "GET" && request.url === "/v1/public-key") {
      return json(response, 200, { public_key: readAnchorPublicKey(directory) });
    }
    const transitionMatch = /^\/v1\/key-transitions\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?:\/latest)?$/.exec(request.url ?? "");
    if (transitionMatch) {
      const tenant = transitionMatch[1];
      observePruneHeadFloor(directory, tenant, pruneHeadFloors);
      if (request.method === "GET" && request.url.endsWith("/latest")) {
        const trust = loadTenantTrust(directory, tenant);
        return trust.latestTransition ? json(response, 200, trust.latestTransition) : json(response, 404, { error: "no_transition" });
      }
      if (request.method !== "POST" || request.url.endsWith("/latest")) return json(response, 405, { error: "method_not_allowed" });
      const body = await readBody(request);
      const parsed = JSON.parse(body.toString("utf8"));
      observePruneHeadFloor(directory, tenant, pruneHeadFloors);
      const receipt = submitAnchorKeyTransition(directory, tenant, parsed.transition);
      observePruneHeadFloor(directory, tenant, pruneHeadFloors);
      return json(response, 200, { receipt });
    }
    const parsedURL = new URL(request.url ?? "", "http://anchor.invalid");
    const pruneHeadMatch = /^\/v1\/audit-prunes\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})\/head$/.exec(parsedURL.pathname);
    if (pruneHeadMatch) {
      if (request.method !== "GET") return json(response, 405, { error: "method_not_allowed" });
      const remote = request.socket.remoteAddress ?? "unknown";
      if (!consumeRate(pruneHeadGlobalRate, remote, 64, 32)) return canonicalJsonResponse(response, 429, { error: "rate_limited" });
      if (!pruneHeadFloors.has(pruneHeadMatch[1])) return canonicalJsonResponse(response, 404, { configured: false, error: "not_configured", version: 1 });
      if (!consumeRate(pruneHeadTenantRate, `${remote}:${pruneHeadMatch[1]}`, 32, 16)) return canonicalJsonResponse(response, 429, { error: "rate_limited" });
      const keys = [...parsedURL.searchParams.keys()].sort();
      if (canonicalJson(keys) !== canonicalJson(["nonce"]) || parsedURL.searchParams.getAll("nonce").length !== 1) throw new Error("Audit prune head requires one exact nonce");
      const snapshot = observePruneHeadFloor(directory, pruneHeadMatch[1], pruneHeadFloors);
      const head = readAnchorPruneHeadSnapshot(directory, pruneHeadMatch[1], parsedURL.searchParams.get("nonce"), Date.now(), snapshot);
      return canonicalJsonResponse(response, head.configured ? 200 : 404, head);
    }
    const pruneLeaseAcquireMatch = /^\/v1\/audit-prunes\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})\/leases$/.exec(parsedURL.pathname);
    if (pruneLeaseAcquireMatch) {
      if (request.method !== "POST" || parsedURL.search) return json(response, 405, { error: "method_not_allowed" });
      observePruneHeadFloor(directory, pruneLeaseAcquireMatch[1], pruneHeadFloors);
      const bytes = await readBody(request);
      const parsed = JSON.parse(bytes.toString("utf8"));
      if (!bytes.equals(Buffer.from(canonicalJson(parsed)))) throw new Error("Audit prune lease acquisition envelope must be exact canonical JSON");
      assertExactKeys(parsed, ["request"], "Audit prune lease acquisition envelope");
      observePruneHeadFloor(directory, pruneLeaseAcquireMatch[1], pruneHeadFloors);
      const lease = acquireAnchorPruneLease(directory, pruneLeaseAcquireMatch[1], parsed.request, Date.now(), pruneLeaseRuntime);
      observePruneHeadFloor(directory, pruneLeaseAcquireMatch[1], pruneHeadFloors);
      return canonicalJsonResponse(response, 200, lease);
    }
    const pruneLeaseReleaseMatch = /^\/v1\/audit-prunes\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})\/leases\/release$/.exec(parsedURL.pathname);
    if (pruneLeaseReleaseMatch) {
      if (request.method !== "POST" || parsedURL.search) return json(response, 405, { error: "method_not_allowed" });
      observePruneHeadFloor(directory, pruneLeaseReleaseMatch[1], pruneHeadFloors);
      const bytes = await readBody(request);
      const parsed = JSON.parse(bytes.toString("utf8"));
      if (!bytes.equals(Buffer.from(canonicalJson(parsed)))) throw new Error("Audit prune lease release envelope must be exact canonical JSON");
      assertExactKeys(parsed, ["lease", "request"], "Audit prune lease release request");
      observePruneHeadFloor(directory, pruneLeaseReleaseMatch[1], pruneHeadFloors);
      const released = releaseAnchorPruneLease(directory, pruneLeaseReleaseMatch[1], parsed.lease, parsed.request, Date.now(), pruneLeaseRuntime);
      observePruneHeadFloor(directory, pruneLeaseReleaseMatch[1], pruneHeadFloors);
      return json(response, 200, released);
    }
    const pruneMatch = /^\/v1\/audit-prunes\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})$/.exec(request.url ?? "");
    if (pruneMatch) {
      if (request.method !== "POST") return json(response, 405, { error: "method_not_allowed" });
      observePruneHeadFloor(directory, pruneMatch[1], pruneHeadFloors);
      const body = await readBody(request);
      const parsed = JSON.parse(body.toString("utf8"));
      assertExactKeys(parsed, ["authorization", "lease"], "Audit prune request");
      observePruneHeadFloor(directory, pruneMatch[1], pruneHeadFloors);
      const receipt = submitAnchorPrune(directory, pruneMatch[1], parsed.authorization, Date.now(), parsed.lease, pruneLeaseRuntime);
      observePruneHeadFloor(directory, pruneMatch[1], pruneHeadFloors);
      return json(response, 200, { receipt });
    }
    const match = /^\/v1\/checkpoints\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?:\/latest)?$/.exec(request.url ?? "");
    if (!match) return json(response, 404, { error: "not_found" });
    const tenant = match[1];
    observePruneHeadFloor(directory, tenant, pruneHeadFloors);
    if (request.method === "GET" && request.url.endsWith("/latest")) {
      const records = readRecords(path.join(directory, "tenants", tenant, "records.jsonl"));
      const tenantConfig = loadTenantTrust(directory, tenant);
      verifyTenantRecords(records, tenantConfig, readAnchorPublicKey(directory), tenant);
      return records.length ? json(response, 200, records.at(-1)) : json(response, 404, { error: "no_checkpoint" });
    }
    if (request.method !== "POST" || request.url.endsWith("/latest")) return json(response, 405, { error: "method_not_allowed" });
    const body = await readBody(request);
    const parsed = JSON.parse(body.toString("utf8"));
    observePruneHeadFloor(directory, tenant, pruneHeadFloors);
    const receipt = submitAnchorCheckpoint(directory, tenant, parsed.checkpoint);
    observePruneHeadFloor(directory, tenant, pruneHeadFloors);
    return json(response, 200, { receipt });
  } catch (error) {
    return json(response, 400, { error: error.message });
  }
}

function loadTenantTrust(directory, tenant) {
  const config = loadTenant(directory, tenant);
  const transitionRecords = readRecords(path.join(directory, "tenants", tenant, "key-transitions.jsonl"));
  const checkpointRecords = readRecords(path.join(directory, "tenants", tenant, "records.jsonl"));
  const pruneRecords = readRecords(path.join(directory, "tenants", tenant, "audit-prunes.jsonl"));
  const anchorPublicKey = readAnchorPublicKey(directory);
  const trust = verifyTenantTransitions(transitionRecords, config, anchorPublicKey, tenant);
  verifyTenantRecords(checkpointRecords, trust, anchorPublicKey, tenant);
  verifyTenantPrunes(pruneRecords, checkpointRecords, transitionRecords, trust, anchorPublicKey, tenant, path.join(directory, "tenants", tenant, "audit-prunes.tip.json"));
  verifyTenantEventState(checkpointRecords, transitionRecords, pruneRecords, tenant);
  verifyTransitionBoundaries(transitionRecords, checkpointRecords, trust, tenant);
  return trust;
}

function loadTenant(directory, tenant) {
  assertTenant(tenant);
  const file = path.join(directory, "tenants", tenant, "config.json");
  if (!fs.existsSync(file)) throw new Error("Anchor tenant is not enrolled");
  assertPrivateRegularFile(file, "Anchor tenant configuration");
  let config;
  try { config = JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error("Anchor tenant configuration is invalid"); }
  if (![1, 2, 3].includes(config?.version) || config.tenant !== tenant) throw new Error("Anchor tenant configuration is invalid");
  const identity = identifyAuditPublicKey(config.audit_public_key);
  const expectedAlgorithm = config.version === 1 ? "ed25519" : config.checkpoint_algorithm;
  if (config.version === 2 && expectedAlgorithm !== "p256-sha256") throw new Error("Anchor tenant checkpoint algorithm is unsupported");
  if (identity.algorithm !== expectedAlgorithm || config.audit_key_fingerprint !== identity.fingerprint) throw new Error("Anchor tenant audit key identity mismatch");
  if (config.version === 3) {
    const configKeys = ["audit_key_fingerprint", "audit_public_key", "checkpoint_algorithm", "enrolled_at", "installation_id", "recovery_policy", "tenant", "version"];
    if (canonicalJson(Object.keys(config).sort()) !== canonicalJson(configKeys)) throw new Error("Anchor tenant recovery configuration encoding is invalid");
    if (!isInstallationId(config.installation_id)) throw new Error("Anchor tenant installation ID is invalid");
    const policy = normalizeRecoveryPolicy(config.recovery_policy);
    if (canonicalJson(policy) !== canonicalJson(config.recovery_policy)) throw new Error("Anchor tenant recovery policy is not canonical");
  }
  return config;
}

function verifyTenantTransitions(records, config, anchorPublicKey, tenant) {
  const base = identifyAuditPublicKey(config.audit_public_key);
  let active = { checkpoint_algorithm: base.algorithm, audit_public_key: base.publicKey, fingerprint: base.fingerprint, generation: 1, lifecycleHeadHash: null };
  const keyHistory = [active];
  let previousTransition = ZERO_HASH;
  let previousReceipt = ZERO_HASH;
  let previousReceivedAt = 0;
  let previousCreatedAt = 0;
  let latestTransition = null;
  const transitions = [];
  const operationIds = new Set();
  const usedFingerprints = new Set([active.fingerprint]);
  const usedRecoveryRequestIds = new Set();
  for (let index = 0; index < records.length; index += 1) {
    const transition = verifyKeyTransition(decodeKeyTransition(records[index].transition), active, {
      tenant,
      expectedGeneration: active.generation + 1,
      previousTransitionHash: previousTransition,
      previousCreatedAt: index ? new Date(previousCreatedAt).toISOString() : undefined,
      usedFingerprints,
      usedRecoveryRequestIds,
      recoveryTrust: config.recovery_policy ? { installationId: config.installation_id, policy: config.recovery_policy } : undefined
    });
    if (operationIds.has(transition.operation_id)) throw new Error("Audit key transition operation ID is duplicated");
    operationIds.add(transition.operation_id);
    if (transition.version === 3) usedRecoveryRequestIds.add(transition.recovery_request_id);
    const receipt = verifyAnchorKeyTransitionReceipt(records[index].receipt, anchorPublicKey, { tenant, transitionHash: transition.transition_hash, previousReceiptHash: previousReceipt });
    const createdAt = Date.parse(transition.created_at);
    if (receipt.index !== index + 1 || Date.parse(receipt.received_at) < previousReceivedAt || ([2, 3].includes(transition.version) && Date.parse(receipt.received_at) < createdAt)) throw new Error("Audit key transition receipt order is invalid");
    const identity = identifyAuditPublicKey(transition.new_public_key);
    active = { checkpoint_algorithm: identity.algorithm, audit_public_key: identity.publicKey, fingerprint: identity.fingerprint, generation: transition.to_generation, lifecycleHeadHash: transition.lifecycle_head_hash };
    usedFingerprints.add(active.fingerprint);
    keyHistory.push(active);
    previousTransition = transition.transition_hash;
    previousReceipt = receipt.receipt_hash;
    previousReceivedAt = Date.parse(receipt.received_at);
    previousCreatedAt = createdAt;
    latestTransition = { transition, receipt };
    transitions.push(latestTransition);
  }
  return { ...config, active, keyHistory, latestTransition, transitions };
}

function decodeKeyTransition(value) {
  const version1Keys = ["created_at", "from_generation", "lifecycle_head_hash", "new_key_fingerprint", "new_public_key", "new_signature", "old_key_fingerprint", "old_signature", "operation_id", "previous_transition_hash", "tenant", "to_generation", "transition_hash", "version"];
  const version2Keys = [...version1Keys, "last_checkpoint_hash", "last_checkpoint_index", "last_checkpoint_receipt_hash", "previous_anchor_event_hash", "previous_anchor_event_index", "previous_transition_receipt_hash", "retiring_generation_pending_checkpoint_count"].sort();
  const version3Keys = version2Keys.filter((key) => key !== "old_signature").concat(["expires_at", "installation_id", "recovery_evidence", "recovery_policy_hash", "recovery_policy_id", "recovery_request_id", "role"]).sort();
  const expected = value?.version === 3 ? version3Keys : value?.version === 2 ? version2Keys : version1Keys;
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson(expected)) throw new Error("Audit key transition encoding is invalid");
  return value;
}

function verifyKeyTransition(transition, active, { tenant, expectedGeneration, previousTransitionHash, previousCreatedAt, usedFingerprints = new Set([active.fingerprint]), usedRecoveryRequestIds = new Set(), recoveryTrust, requireCanonicalP256 = false, now }) {
  const legacyStatement = {
    version: transition.version,
    tenant: transition.tenant,
    operation_id: transition.operation_id,
    from_generation: transition.from_generation,
    to_generation: transition.to_generation,
    old_key_fingerprint: transition.old_key_fingerprint,
    new_key_fingerprint: transition.new_key_fingerprint,
    new_public_key: transition.new_public_key,
    lifecycle_head_hash: transition.lifecycle_head_hash,
    created_at: transition.created_at,
    previous_transition_hash: transition.previous_transition_hash,
    ...([2, 3].includes(transition.version) ? {
      previous_transition_receipt_hash: transition.previous_transition_receipt_hash,
      last_checkpoint_index: transition.last_checkpoint_index,
      last_checkpoint_hash: transition.last_checkpoint_hash,
      last_checkpoint_receipt_hash: transition.last_checkpoint_receipt_hash,
      previous_anchor_event_index: transition.previous_anchor_event_index,
      previous_anchor_event_hash: transition.previous_anchor_event_hash,
      retiring_generation_pending_checkpoint_count: transition.retiring_generation_pending_checkpoint_count
    } : {})
  };
  const statement = transition.version === 3 ? anchorRecoveryAuthorization(transition) : legacyStatement;
  const createdAt = Date.parse(statement.created_at);
  const boundedInvalid = [2, 3].includes(statement.version) && (!isHash(statement.previous_transition_receipt_hash) || !Number.isSafeInteger(statement.last_checkpoint_index) || statement.last_checkpoint_index < 1 || !isHash(statement.last_checkpoint_hash) || !isHash(statement.last_checkpoint_receipt_hash) || !Number.isSafeInteger(statement.previous_anchor_event_index) || statement.previous_anchor_event_index < 1 || !isHash(statement.previous_anchor_event_hash) || statement.retiring_generation_pending_checkpoint_count !== 0);
  if (![1, 2, 3].includes(statement.version) || statement.tenant !== tenant || !isSlug(statement.operation_id) || !Number.isSafeInteger(statement.from_generation) || !Number.isSafeInteger(statement.to_generation) || statement.from_generation !== active.generation || statement.to_generation !== expectedGeneration || statement.to_generation !== statement.from_generation + 1 || statement.old_key_fingerprint !== active.fingerprint || !isHash(statement.lifecycle_head_hash) || !Number.isFinite(createdAt) || ([2, 3].includes(statement.version) && previousCreatedAt !== undefined && createdAt <= Date.parse(previousCreatedAt)) || statement.previous_transition_hash !== previousTransitionHash || boundedInvalid) throw new Error("Audit key transition statement is invalid");
  const replacement = identifyAuditPublicKey(statement.new_public_key);
  if (replacement.algorithm !== active.checkpoint_algorithm || replacement.fingerprint !== statement.new_key_fingerprint || usedFingerprints.has(replacement.fingerprint)) throw new Error("Audit key transition replacement identity is invalid or has been used by an earlier generation");
  if (transition.version === 3) return verifyRecoveryKeyTransition(transition, statement, replacement, { recoveryTrust, usedRecoveryRequestIds, requireCanonicalP256, now });
  if (!verifyAuditKeySignature(active, statement, transition.old_signature, { requireLowS: requireCanonicalP256 }) || !verifyAuditKeySignature({ checkpoint_algorithm: replacement.algorithm, audit_public_key: replacement.publicKey }, statement, transition.new_signature, { requireLowS: requireCanonicalP256 })) throw new Error("Audit key transition possession proof is invalid");
  const copy = { ...statement, old_signature: transition.old_signature, new_signature: transition.new_signature };
  if (hashCanonical(copy) !== transition.transition_hash) throw new Error("Audit key transition hash is invalid");
  return { ...copy, transition_hash: transition.transition_hash };
}

function verifyRecoveryKeyTransition(transition, statement, replacement, { recoveryTrust, usedRecoveryRequestIds, requireCanonicalP256 = false, now }) {
  if (!recoveryTrust) throw new Error("Audit key recovery is not enrolled for this tenant");
  const policy = normalizeRecoveryPolicy(recoveryTrust.policy);
  const expiresAt = Date.parse(statement.expires_at);
  const createdAt = Date.parse(statement.created_at);
  const submissionTime = now === undefined ? undefined : Number(now);
  if (!isInstallationId(statement.installation_id) || statement.installation_id !== recoveryTrust.installationId || statement.role !== "audit_checkpoint" || !isSlug(statement.recovery_request_id) || usedRecoveryRequestIds.has(statement.recovery_request_id) || statement.recovery_policy_id !== policy.policy_id || statement.recovery_policy_hash !== policy.policy_hash || new Date(createdAt).toISOString() !== statement.created_at || !Number.isFinite(expiresAt) || new Date(expiresAt).toISOString() !== statement.expires_at || expiresAt <= createdAt || expiresAt - createdAt > MAX_RECOVERY_AUTHORIZATION_MS || (submissionTime !== undefined && (!Number.isFinite(submissionTime) || createdAt > submissionTime + MAX_RECOVERY_CLOCK_SKEW_MS || submissionTime > expiresAt))) {
    throw new Error("Audit key recovery authorization statement is invalid, expired, or replayed");
  }
  const evidence = transition.recovery_evidence;
  const evidenceKeys = ["approvals", "authorization", "policy", "version"];
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) || canonicalJson(Object.keys(evidence).sort()) !== canonicalJson(evidenceKeys) || evidence.version !== 1 || canonicalJson(evidence.authorization) !== canonicalJson(statement) || canonicalJson(evidence.policy) !== canonicalJson(policy) || !Array.isArray(evidence.approvals) || evidence.approvals.length < policy.threshold || evidence.approvals.length > policy.keys.length) {
    throw new Error("Audit key recovery evidence bundle is invalid");
  }
  const keyById = new Map(policy.keys.map((item) => [item.id, item]));
  const signerIds = new Set();
  let previousId = "";
  for (const approval of evidence.approvals) {
    if (!approval || typeof approval !== "object" || Array.isArray(approval) || canonicalJson(Object.keys(approval).sort()) !== canonicalJson(["key_id", "signature"]) || !isSlug(approval.key_id) || approval.key_id <= previousId || signerIds.has(approval.key_id)) {
      throw new Error("Audit key recovery approvals must contain unique policy signers in canonical order");
    }
    const pinned = keyById.get(approval.key_id);
    if (!pinned || !verifyEd25519Signature(pinned.public_key, statement, approval.signature)) throw new Error("Audit key recovery approval signature or signer is invalid");
    signerIds.add(approval.key_id);
    previousId = approval.key_id;
  }
  if (!verifyAuditKeySignature({ checkpoint_algorithm: replacement.algorithm, audit_public_key: replacement.publicKey }, statement, transition.new_signature, { requireLowS: requireCanonicalP256 })) throw new Error("Audit key recovery replacement-key possession proof is invalid");
  const copy = { ...statement, recovery_evidence: evidence, new_signature: transition.new_signature };
  if (hashCanonical(copy) !== transition.transition_hash) throw new Error("Audit key transition hash is invalid");
  return { ...copy, transition_hash: transition.transition_hash };
}

function normalizeRecoveryPolicy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Anchor recovery policy is invalid");
  const suppliedKeys = Object.keys(value).sort();
  const allowedKeys = value.policy_hash === undefined ? ["keys", "policy_id", "threshold", "version"] : ["keys", "policy_hash", "policy_id", "threshold", "version"];
  if (canonicalJson(suppliedKeys) !== canonicalJson(allowedKeys) || value.version !== 1 || !isSlug(value.policy_id) || !Number.isSafeInteger(value.threshold) || !Array.isArray(value.keys) || value.keys.length < 1 || value.keys.length > 16 || value.threshold < 1 || value.threshold > value.keys.length) throw new Error("Anchor recovery policy is invalid");
  const normalizedKeys = value.keys.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Anchor recovery policy key is invalid");
    const inputKeys = Object.keys(item).sort();
    const expectedKeys = item.fingerprint === undefined ? ["id", "public_key"] : ["fingerprint", "id", "public_key"];
    if (canonicalJson(inputKeys) !== canonicalJson(expectedKeys) || !isSlug(item.id)) throw new Error("Anchor recovery policy key is invalid");
    const key = assertEd25519PublicKey(item.public_key, "Anchor recovery policy key");
    const publicKey = key.export({ type: "spki", format: "pem" }).toString();
    const fingerprint = publicKeyFingerprint(key);
    if (item.fingerprint !== undefined && item.fingerprint !== fingerprint) throw new Error("Anchor recovery policy key fingerprint mismatch");
    return { id: item.id, public_key: publicKey, fingerprint };
  }).sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
  if (new Set(normalizedKeys.map((item) => item.id)).size !== normalizedKeys.length || new Set(normalizedKeys.map((item) => item.fingerprint)).size !== normalizedKeys.length) throw new Error("Anchor recovery policy keys must be unique");
  const statement = { version: 1, policy_id: value.policy_id, threshold: value.threshold, keys: normalizedKeys };
  const policyHash = hashCanonical(statement);
  if (value.policy_hash !== undefined && value.policy_hash !== policyHash) throw new Error("Anchor recovery policy hash mismatch");
  return { ...statement, policy_hash: policyHash };
}

function verifyEd25519Signature(publicKey, statement, encoded) {
  if (!isCanonicalBase64(encoded)) return false;
  try {
    const signature = Buffer.from(encoded, "base64");
    return signature.length === 64 && crypto.verify(null, Buffer.from(canonicalJson(statement)), assertEd25519PublicKey(publicKey, "Recovery public key"), signature);
  } catch { return false; }
}

function decodePruneAuthorization(value) {
  const authorizationKeys = ["authorization_hash", "boundary", "operation_id", "previous_authorization_hash", "previous_manifest_hash", "previous_prune_receipt_hash", "requested_at", "retention_seconds", "segments", "sequence", "signature", "signer_fingerprint", "tenant", "version"];
  assertExactKeys(value, authorizationKeys, "Audit prune authorization");
  const boundaryKeys = ["anchor_event_hash", "anchor_event_index", "audit_key_transition_receipt_hash", "checkpoint_hash", "checkpoint_index", "checkpoint_receipt_hash", "lifecycle_head_hash"];
  assertExactKeys(value.boundary, boundaryKeys, "Audit prune boundary");
  if (!Array.isArray(value.segments) || value.segments.length < 1 || value.segments.length > MAX_PRUNE_SEGMENTS) throw new Error("Audit prune segment count is invalid");
  const segmentKeys = ["anchored_event_hash", "anchored_event_index", "audit_archive_file", "audit_archive_sha256", "checkpoint_archive_file", "checkpoint_archive_sha256", "first_checkpoint_index", "first_event_index", "first_receipt_index", "last_checkpoint_index", "last_event_index", "last_receipt_index", "latest_anchor_received_at", "previous_checkpoint_hash", "previous_event_hash", "previous_receipt_hash", "receipt_archive_file", "receipt_archive_sha256", "sealed_at", "segment_id", "terminal_checkpoint_hash", "terminal_event_hash", "terminal_receipt_hash"];
  for (const segment of value.segments) assertExactKeys(segment, segmentKeys, "Audit prune segment");
  if (Buffer.byteLength(canonicalJson(value)) > MAX_DOCUMENT_BYTES) throw new Error("Audit prune authorization exceeds the verification limit");
  return value;
}

function verifyPruneAuthorization(value, { tenant, prior, checkpoints, transitions, trust, eventState, requireCanonicalP256 = false, now }) {
  const requestedAt = Date.parse(value.requested_at);
  const priorAuthorization = prior?.authorization;
  const priorLast = priorAuthorization?.segments.at(-1);
  const expectedSequence = (priorAuthorization?.sequence ?? 0) + 1;
  const previousAuthorizationHash = priorAuthorization?.authorization_hash ?? ZERO_HASH;
  const previousPruneReceiptHash = prior?.receipt.receipt_hash ?? ZERO_HASH;
  if (value.version !== 1 || value.tenant !== tenant || !isRetentionSlug(value.operation_id) || !positiveSafeInteger(value.sequence) || value.sequence !== expectedSequence || value.previous_authorization_hash !== previousAuthorizationHash || value.previous_prune_receipt_hash !== previousPruneReceiptHash || !isHash(value.previous_manifest_hash) || !safeIntegerAtLeast(value.retention_seconds, MIN_AUDIT_RETENTION_SECONDS) || (priorAuthorization && value.retention_seconds < priorAuthorization.retention_seconds) || !isDate(value.requested_at) || requestedAt > Number(now) || !isFingerprint(value.signer_fingerprint) || !isHash(value.authorization_hash)) {
    throw new Error("Audit prune authorization chain, retention, or timestamp is invalid");
  }
  verifyPruneBoundary(value.boundary, { checkpoints, transitions, trust, eventState });

  let eventIndex = (priorLast?.last_event_index ?? 0) + 1;
  let checkpointIndex = (priorLast?.last_checkpoint_index ?? 0) + 1;
  let receiptIndex = (priorLast?.last_receipt_index ?? 0) + 1;
  let eventHash = priorLast?.terminal_event_hash ?? ZERO_HASH;
  let checkpointHash = priorLast?.terminal_checkpoint_hash ?? ZERO_HASH;
  let receiptHash = priorLast?.terminal_receipt_hash ?? ZERO_HASH;
  const ids = new Set();
  const files = new Set();
  for (const segment of value.segments) {
    validatePruneSegmentShape(segment);
    const archiveFiles = [segment.audit_archive_file, segment.checkpoint_archive_file, segment.receipt_archive_file];
    const terminalCheckpoint = checkpoints[segment.last_checkpoint_index - 1];
    const firstCheckpoint = checkpoints[segment.first_checkpoint_index - 1];
    const anchoredCheckpoint = checkpoints.find((record) => record.checkpoint.entries === segment.anchored_event_index && record.checkpoint.head_hash === segment.anchored_event_hash);
    const sealedAt = Date.parse(segment.sealed_at);
    const latestAnchorAt = Date.parse(segment.latest_anchor_received_at);
    const invalid = ids.has(segment.segment_id) || archiveFiles.some((name) => files.has(name)) ||
      segment.first_event_index !== eventIndex || segment.first_checkpoint_index !== checkpointIndex || segment.first_receipt_index !== receiptIndex ||
      segment.previous_event_hash !== eventHash || segment.previous_checkpoint_hash !== checkpointHash || segment.previous_receipt_hash !== receiptHash ||
      segment.first_checkpoint_index !== segment.first_receipt_index || segment.last_checkpoint_index !== segment.last_receipt_index ||
      segment.anchored_event_index !== segment.last_event_index || segment.anchored_event_hash !== segment.terminal_event_hash ||
      !firstCheckpoint || !terminalCheckpoint || !anchoredCheckpoint ||
      firstCheckpoint.checkpoint.previous_checkpoint_hash !== segment.previous_checkpoint_hash || firstCheckpoint.receipt.previous_receipt_hash !== segment.previous_receipt_hash ||
      terminalCheckpoint.checkpoint.checkpoint_hash !== segment.terminal_checkpoint_hash || terminalCheckpoint.receipt.receipt_hash !== segment.terminal_receipt_hash ||
      terminalCheckpoint.receipt.received_at !== segment.latest_anchor_received_at ||
      terminalCheckpoint.receipt.version !== 2 || terminalCheckpoint.receipt.event_index > value.boundary.anchor_event_index ||
      latestAnchorAt < sealedAt || requestedAt < latestAnchorAt || Number(now) - latestAnchorAt < value.retention_seconds * 1000;
    if (invalid) throw new Error("Audit prune segment has a gap, overlap, substitution, insufficient age, or unanchored coverage");
    ids.add(segment.segment_id);
    for (const name of archiveFiles) files.add(name);
    eventIndex = segment.last_event_index + 1;
    checkpointIndex = segment.last_checkpoint_index + 1;
    receiptIndex = segment.last_receipt_index + 1;
    eventHash = segment.terminal_event_hash;
    checkpointHash = segment.terminal_checkpoint_hash;
    receiptHash = segment.terminal_receipt_hash;
  }
  const last = value.segments.at(-1);
  if (last.last_event_index > checkpoints.at(-1).checkpoint.entries || last.last_checkpoint_index > value.boundary.checkpoint_index || last.last_receipt_index > value.boundary.checkpoint_index) throw new Error("Audit prune segments exceed the current anchored boundary");
  const latestCheckpoint = checkpoints[value.boundary.checkpoint_index - 1];
  const signer = trust.keyHistory.find((item) => item.fingerprint === latestCheckpoint.checkpoint.public_key_fingerprint);
  if (!signer || signer.checkpoint_algorithm !== "p256-sha256" || signer.fingerprint !== value.signer_fingerprint) throw new Error("Audit prune signer is not the active P-256 audit identity");
  const statement = pruneAuthorizationStatement(value);
  if (!verifyAuditKeySignature(signer, statement, value.signature, { requireLowS: requireCanonicalP256 })) throw new Error("Audit prune authorization signature is invalid");
  const signed = { ...statement, signature: value.signature };
  if (hashCanonical(signed) !== value.authorization_hash) throw new Error("Audit prune authorization hash is invalid");
  return { ...signed, authorization_hash: value.authorization_hash };
}

function verifyPruneBoundary(boundary, { checkpoints, transitions, trust, eventState }) {
  assertExactKeys(boundary, ["anchor_event_hash", "anchor_event_index", "audit_key_transition_receipt_hash", "checkpoint_hash", "checkpoint_index", "checkpoint_receipt_hash", "lifecycle_head_hash"], "Audit prune boundary");
  const checkpoint = checkpoints.at(-1);
  const latestTransition = transitions.at(-1);
  if (!checkpoint || checkpoint.receipt.version !== 2 || checkpoint.checkpoint.version !== 2 || checkpoint.checkpoint.public_key_fingerprint !== trust.active.fingerprint || checkpoint.checkpoint.key_generation !== trust.active.generation ||
      boundary.anchor_event_index !== eventState.index || boundary.anchor_event_hash !== eventState.hash || boundary.checkpoint_index !== checkpoints.length || boundary.checkpoint_hash !== checkpoint.checkpoint.checkpoint_hash || boundary.checkpoint_receipt_hash !== checkpoint.receipt.receipt_hash ||
      boundary.audit_key_transition_receipt_hash !== (latestTransition?.receipt.receipt_hash ?? ZERO_HASH) || boundary.lifecycle_head_hash !== checkpoint.checkpoint.lifecycle_head_hash || (latestTransition && boundary.lifecycle_head_hash !== latestTransition.transition.lifecycle_head_hash) ||
      !positiveSafeInteger(boundary.anchor_event_index) || !isHash(boundary.anchor_event_hash) || !positiveSafeInteger(boundary.checkpoint_index) || !isHash(boundary.checkpoint_hash) || !isHash(boundary.checkpoint_receipt_hash) || !isHash(boundary.audit_key_transition_receipt_hash) || !isHash(boundary.lifecycle_head_hash)) {
    throw new Error("Audit prune boundary is stale or does not bind the current checkpoint, transition, lifecycle, and zero-pending event state");
  }
}

function pruneAuthorizationStatement(value) {
  return {
    version: value.version, tenant: value.tenant, operation_id: value.operation_id, sequence: value.sequence,
    previous_authorization_hash: value.previous_authorization_hash, previous_prune_receipt_hash: value.previous_prune_receipt_hash,
    previous_manifest_hash: value.previous_manifest_hash, retention_seconds: value.retention_seconds, requested_at: value.requested_at,
    boundary: value.boundary, segments: value.segments, signer_fingerprint: value.signer_fingerprint
  };
}

function validatePruneSegmentShape(segment) {
  const integers = [segment.first_event_index, segment.last_event_index, segment.first_checkpoint_index, segment.last_checkpoint_index, segment.first_receipt_index, segment.last_receipt_index, segment.anchored_event_index];
  const hashes = [segment.audit_archive_sha256, segment.previous_event_hash, segment.terminal_event_hash, segment.checkpoint_archive_sha256, segment.previous_checkpoint_hash, segment.terminal_checkpoint_hash, segment.receipt_archive_sha256, segment.previous_receipt_hash, segment.terminal_receipt_hash, segment.anchored_event_hash];
  const files = [segment.audit_archive_file, segment.checkpoint_archive_file, segment.receipt_archive_file];
  if (!isRetentionSlug(segment.segment_id) || files.some((value) => !isSafeFileName(value)) || new Set(files).size !== 3 || hashes.some((value) => !isHash(value)) || integers.some((value) => !positiveSafeInteger(value)) || segment.last_event_index >= MAX_SAFE_INTEGER || segment.last_checkpoint_index >= MAX_SAFE_INTEGER || segment.last_receipt_index >= MAX_SAFE_INTEGER || segment.last_event_index < segment.first_event_index || segment.last_checkpoint_index < segment.first_checkpoint_index || segment.last_receipt_index < segment.first_receipt_index || !isDate(segment.sealed_at) || !isDate(segment.latest_anchor_received_at)) throw new Error("Audit prune segment schema is invalid");
}

function verifyTenantPrunes(records, checkpoints, transitions, trust, anchorPublicKey, tenant, tipFile, { repairTip = true } = {}) {
  verifyTenantEventState(checkpoints, transitions, records, tenant);
  let prior;
  const operationIds = new Set();
  const authorizationHashes = new Set();
  for (const record of records) {
    assertExactKeys(record, ["authorization", "receipt"], "Audit prune record");
    const authorization = decodePruneAuthorization(record.authorization);
    if (operationIds.has(authorization.operation_id) || authorizationHashes.has(authorization.authorization_hash)) throw new Error("Audit prune stored operation or authorization hash is duplicated");
    const receipt = verifyAnchorPruneReceipt(record.receipt, anchorPublicKey, {
      tenant, sequence: authorization.sequence, authorizationHash: authorization.authorization_hash,
      previousReceiptHash: prior?.receipt.receipt_hash ?? ZERO_HASH,
      anchorEventIndex: authorization.boundary.anchor_event_index + 1,
      previousAnchorEventHash: authorization.boundary.anchor_event_hash
    });
    verifyPruneAuthorization(authorization, {
      tenant, prior, checkpoints: checkpoints.filter((item) => item.receipt.version === 1 || item.receipt.event_index <= authorization.boundary.anchor_event_index),
      transitions: transitions.filter((item) => item.receipt.version === 1 || item.receipt.event_index <= authorization.boundary.anchor_event_index),
      trust: trustAtPruneBoundary(trust, authorization.boundary.anchor_event_index),
      eventState: { index: authorization.boundary.anchor_event_index, hash: authorization.boundary.anchor_event_hash, receivedAt: Date.parse(receipt.received_at) },
      now: Date.parse(receipt.received_at)
    });
    if (Date.parse(receipt.received_at) < (prior ? Date.parse(prior.receipt.received_at) : 0)) throw new Error("Audit prune receipt timestamp rollback detected");
    operationIds.add(authorization.operation_id);
    authorizationHashes.add(authorization.authorization_hash);
    prior = { authorization, receipt };
  }
  verifyOrRepairPruneTip(tipFile, records, { repair: repairTip });
  return records.map((record) => ({ authorization: record.authorization, receipt: record.receipt }));
}

function trustAtPruneBoundary(trust, eventIndex) {
  const preceding = trust.transitions.filter((item) => item.receipt.version === 1 || item.receipt.event_index <= eventIndex);
  const generation = preceding.length + 1;
  return { ...trust, active: trust.keyHistory.find((item) => item.generation === generation), latestTransition: preceding.at(-1) ?? null };
}

function pruneTipValue(records, authorization, receipt) {
  const statement = { version: 1, records, sequence: authorization.sequence, authorization_hash: authorization.authorization_hash, receipt_hash: receipt.receipt_hash, anchor_event_index: receipt.anchor_event_index, anchor_event_hash: receipt.receipt_hash };
  return { ...statement, tip_hash: hashCanonical(statement) };
}

function writePruneTip(file, records, authorization, receipt) {
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let fd;
  try {
    if (fs.existsSync(file)) assertPrivateRegularFile(file, "Audit prune tip");
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollowFlag(), 0o600);
    fs.writeFileSync(fd, `${JSON.stringify(pruneTipValue(records, authorization, receipt), null, 2)}\n`);
    fs.fsyncSync(fd);
    assertPrivateRegularFd(fd, "Audit prune temporary tip");
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporary, file);
    assertPrivateRegularFile(file, "Audit prune tip");
    fsyncParent(file);
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch {}
    throw error;
  }
}

function verifyOrRepairPruneTip(file, records, { repair = true } = {}) {
  if (records.length === 0) {
    if (fs.existsSync(file)) throw new Error("Audit prune tip exists without its append-only log");
    return;
  }
  const last = records.at(-1);
  const expected = pruneTipValue(records.length, last.authorization, last.receipt);
  if (!fs.existsSync(file)) {
    if (records.length === 1) return repair ? writePruneTip(file, records.length, last.authorization, last.receipt) : undefined;
    throw new Error("Audit prune tip is missing; possible log rollback detected");
  }
  let tip;
  let fd;
  try {
    try { fd = fs.openSync(file, fs.constants.O_RDONLY | noFollowFlag()); }
    catch (error) { throw unsafeOpenError(error, label); }
    assertPrivateRegularFd(fd, "Audit prune tip");
    assertPathRefersToFd(file, fd, "Audit prune tip");
    tip = JSON.parse(fs.readFileSync(fd, "utf8"));
    assertPrivateRegularFd(fd, "Audit prune tip");
    assertPathRefersToFd(file, fd, "Audit prune tip");
  } catch { throw new Error("Audit prune tip is invalid or unsafe"); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
  assertExactKeys(tip, ["anchor_event_hash", "anchor_event_index", "authorization_hash", "receipt_hash", "records", "sequence", "tip_hash", "version"], "Audit prune tip");
  if (canonicalJson(tip) === canonicalJson(expected)) return;
  if (records.length > 1 && canonicalJson(tip) === canonicalJson(pruneTipValue(records.length - 1, records.at(-2).authorization, records.at(-2).receipt))) return repair ? writePruneTip(file, records.length, last.authorization, last.receipt) : undefined;
  throw new Error("Audit prune log and durable tip do not match; possible truncation or rollback detected");
}

function verifyTenantEventState(checkpoints, transitions, prunes, tenant) {
  const streams = [
    { kind: "checkpoint", records: checkpoints },
    { kind: "key_transition", records: transitions }
  ];
  const legacy = [];
  const events = [];
  for (const stream of streams) {
    let sawVersion2 = false;
    for (const record of stream.records) {
      const receipt = record?.receipt;
      if (receipt?.version === 2) {
        sawVersion2 = true;
        events.push({ kind: stream.kind, receipt });
      } else if (receipt?.version === 1) {
        if (sawVersion2) throw new Error("Legacy anchor receipts cannot follow version 2 tenant events");
        legacy.push({ kind: stream.kind, receipt });
      } else {
        throw new Error("Anchor tenant event receipt version is invalid");
      }
    }
  }
  for (const record of prunes) {
    if (record?.receipt?.version !== 1) throw new Error("Audit prune event receipt version is invalid");
    events.push({ kind: "audit_prune", receipt: { ...record.receipt, event_index: record.receipt.anchor_event_index, previous_event_hash: record.receipt.previous_anchor_event_hash } });
  }

  // Migration is deterministic and fail closed: existing v1 receipts form one
  // immutable synthetic origin. New submissions are v2 events and can never add
  // to that legacy prefix after the event chain has started.
  const checkpointLegacy = checkpoints.filter((record) => record.receipt.version === 1);
  const transitionLegacy = transitions.filter((record) => record.receipt.version === 1);
  const legacyCount = legacy.length;
  const legacyHash = legacyCount === 0 ? ZERO_HASH : hashCanonical({
    version: 1,
    type: "agentpass-anchor-legacy-event-state",
    tenant,
    checkpoint_count: checkpointLegacy.length,
    last_checkpoint_hash: checkpointLegacy.at(-1)?.checkpoint.checkpoint_hash ?? ZERO_HASH,
    last_checkpoint_receipt_hash: checkpointLegacy.at(-1)?.receipt.receipt_hash ?? ZERO_HASH,
    transition_count: transitionLegacy.length,
    last_transition_hash: transitionLegacy.at(-1)?.transition.transition_hash ?? ZERO_HASH,
    last_transition_receipt_hash: transitionLegacy.at(-1)?.receipt.receipt_hash ?? ZERO_HASH
  });
  let index = legacyCount;
  let stateHash = legacyHash;
  let receivedAt = legacy.reduce((latest, item) => Math.max(latest, Date.parse(item.receipt.received_at)), 0);
  let latestKind = legacyCount ? "legacy_migration_state" : null;
  events.sort((left, right) => left.receipt.event_index - right.receipt.event_index);
  for (const event of events) {
    if (event.receipt.event_index !== index + 1 || event.receipt.previous_event_hash !== stateHash || Date.parse(event.receipt.received_at) < receivedAt) {
      throw new Error("Anchor tenant event chain is invalid");
    }
    index = event.receipt.event_index;
    stateHash = event.receipt.receipt_hash;
    receivedAt = Date.parse(event.receipt.received_at);
    latestKind = event.kind;
  }
  return { index, hash: stateHash, receivedAt, latestKind, legacyCount };
}

function verifyTransitionBoundaries(transitionRecords, checkpointRecords, trust, tenant) {
  for (let index = 0; index < trust.transitions.length; index += 1) {
    const { transition, receipt } = trust.transitions[index];
    if (transition.version === 1) continue;
    if (receipt.version !== 2) throw new Error("Version 2 or 3 audit key transition requires a version 2 event receipt");
    const checkpointRecord = checkpointRecords[transition.last_checkpoint_index - 1];
    const identity = trust.keyHistory.find((item) => item.generation === transition.from_generation);
    if (!checkpointRecord || !identity || checkpointRecord.checkpoint.checkpoint_hash !== transition.last_checkpoint_hash || checkpointRecord.receipt.receipt_hash !== transition.last_checkpoint_receipt_hash || checkpointRecord.checkpoint.public_key_fingerprint !== identity.fingerprint) {
      throw new Error("Audit key transition checkpoint boundary is invalid");
    }
    if (transition.from_generation > 1 && (checkpointRecord.checkpoint.version !== 2 || checkpointRecord.checkpoint.key_generation !== transition.from_generation)) {
      throw new Error("Audit key transition checkpoint generation boundary is invalid");
    }
    const previousTransitionReceiptHash = index ? trust.transitions[index - 1].receipt.receipt_hash : ZERO_HASH;
    if (transition.previous_transition_receipt_hash !== previousTransitionReceiptHash || receipt.previous_event_hash !== transition.previous_anchor_event_hash || receipt.event_index !== transition.previous_anchor_event_index + 1 || receipt.last_checkpoint_index !== transition.last_checkpoint_index || receipt.last_checkpoint_hash !== transition.last_checkpoint_hash || receipt.last_checkpoint_receipt_hash !== transition.last_checkpoint_receipt_hash) {
      throw new Error("Audit key transition receipt/event boundary is invalid");
    }
    if (checkpointRecord.receipt.version === 2) {
      if (transition.previous_anchor_event_index !== checkpointRecord.receipt.event_index || transition.previous_anchor_event_hash !== checkpointRecord.receipt.receipt_hash) {
        throw new Error("Audit key transition did not immediately follow its final checkpoint event");
      }
    } else {
      const legacyCheckpointCount = checkpointRecords.filter((record) => record.receipt.version === 1).length;
      const legacyTransitionCount = transitionRecords.filter((record) => record.receipt.version === 1).length;
      if (receipt.event_index !== legacyCheckpointCount + legacyTransitionCount + 1 || transition.last_checkpoint_index !== legacyCheckpointCount) {
        throw new Error("Audit key transition legacy migration boundary is invalid");
      }
    }
    if (Date.parse(transition.created_at) < Math.max(Date.parse(checkpointRecord.checkpoint.created_at), Date.parse(checkpointRecord.receipt.received_at))) {
      throw new Error("Audit key transition predates its checkpoint boundary");
    }
    if (transition.version === 3 && Date.parse(receipt.received_at) > Date.parse(transition.expires_at)) throw new Error("Audit key recovery receipt postdates its authorization expiry");
    if (transition.tenant !== tenant) throw new Error("Audit key transition tenant boundary is invalid");
  }
}

function assertCurrentTransitionBoundary(transition, checkpoints, transitionRecords, trust, eventState) {
  const checkpointRecord = checkpoints.at(-1);
  if (!checkpointRecord) throw new Error("Audit key transition requires an anchored checkpoint from the retiring generation");
  const identity = trust.keyHistory.find((item) => item.fingerprint === checkpointRecord.checkpoint.public_key_fingerprint);
  if (!identity || identity.generation !== trust.active.generation) throw new Error("Audit key transition requires the latest checkpoint to use the retiring generation");
  if (eventState.latestKind !== "checkpoint") throw new Error("Audit key transition requires a checkpoint immediately before the transition event");
  const previousTransitionReceiptHash = transitionRecords.at(-1)?.receipt.receipt_hash ?? ZERO_HASH;
  if (transition.last_checkpoint_index !== checkpoints.length || transition.last_checkpoint_hash !== checkpointRecord.checkpoint.checkpoint_hash || transition.last_checkpoint_receipt_hash !== checkpointRecord.receipt.receipt_hash || transition.previous_transition_receipt_hash !== previousTransitionReceiptHash || transition.previous_anchor_event_index !== eventState.index || transition.previous_anchor_event_hash !== eventState.hash) {
    throw new Error("Audit key transition does not bind the current checkpoint receipt/event state; submit all retiring-generation checkpoints first");
  }
  if (Date.parse(transition.created_at) < Math.max(Date.parse(checkpointRecord.checkpoint.created_at), Date.parse(checkpointRecord.receipt.received_at))) {
    throw new Error("Audit key transition predates the final retiring-generation checkpoint");
  }
}

function verifyAuditKeySignature(identity, statement, encoded, { requireLowS = false } = {}) {
  if (!isCanonicalBase64(encoded)) return false;
  try {
    const signature = Buffer.from(encoded, "base64");
    const bytes = Buffer.from(canonicalJson(statement));
    if (identity.checkpoint_algorithm === "p256-sha256") {
      const parsed = parseNativeAuditPublicKey(identity.audit_public_key);
      const scalarEncodingValid = requireLowS ? isCanonicalP256P1363Signature(signature) : hasValidP256P1363Scalars(signature);
      return scalarEncodingValid && crypto.verify("sha256", bytes, { key: parsed.key, dsaEncoding: "ieee-p1363" }, signature);
    }
    const key = assertEd25519PublicKey(identity.audit_public_key, "Audit checkpoint public key");
    return signature.length === 64 && crypto.verify(null, bytes, key, signature);
  } catch { return false; }
}

function isCanonicalP256P1363Signature(signature) {
  return hasValidP256P1363Scalars(signature) && Buffer.compare(signature.subarray(32, 64), P256_HALF_ORDER) <= 0;
}

function hasValidP256P1363Scalars(signature) {
  if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
  const r = signature.subarray(0, 32);
  const s = signature.subarray(32, 64);
  // Buffer.compare is an unsigned lexicographic comparison. Because all four
  // values are exactly 32 bytes, it is also a strict unsigned integer compare.
  return Buffer.compare(r, P256_ZERO_SCALAR) > 0 &&
    Buffer.compare(r, P256_ORDER) < 0 &&
    Buffer.compare(s, P256_ZERO_SCALAR) > 0 &&
    Buffer.compare(s, P256_ORDER) < 0;
}

function loadAnchorPrivateKey(directory) {
  const file = path.join(directory, "anchor-private.pem");
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("Anchor private key permissions are unsafe");
  const key = crypto.createPrivateKey(fs.readFileSync(file));
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Anchor private key must be Ed25519");
  const expected = publicKeyFingerprint(readAnchorPublicKey(directory));
  if (publicKeyFingerprint(crypto.createPublicKey(key)) !== expected) throw new Error("Anchor private and public keys do not match");
  return key;
}

function readAnchorPublicKey(directory) {
  return fs.readFileSync(path.join(directory, "anchor-public.pem"), "utf8");
}

function readRecords(file) {
  const log = openRecordLog(file);
  try { return log.records; }
  finally { log.close(); }
}

function openRecordLog(file, { create = false, requireCanonical = false } = {}) {
  const label = "Anchor tenant record log";
  let fd;
  let created = false;
  const baseFlags = (create ? fs.constants.O_RDWR | fs.constants.O_APPEND : fs.constants.O_RDONLY) | noFollowFlag();
  try {
    fd = fs.openSync(file, baseFlags);
  } catch (error) {
    if (error.code !== "ENOENT" || !create) {
      if (error.code === "ENOENT") return { records: [], append: unavailableAppend, close() {} };
      throw unsafeOpenError(error, label);
    }
    try {
      fd = fs.openSync(file, baseFlags | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
      created = true;
    } catch (createError) {
      throw unsafeOpenError(createError, label);
    }
  }

  try {
    const stat = assertPrivateRegularFd(fd, label);
    assertPathRefersToFd(file, fd, label);
    if (stat.size > 128 * 1024 * 1024) throw new Error("Anchor tenant record log exceeds the verification limit");
    const content = fs.readFileSync(fd, "utf8");
    assertPrivateRegularFd(fd, label);
    assertPathRefersToFd(file, fd, label);
    if (content && (!content.endsWith("\n") || content.includes("\n\n"))) throw new Error("Anchor tenant record log framing is invalid");
    const lines = content.trim().split("\n").filter(Boolean);
    const records = lines.map((line) => JSON.parse(line));
    if (requireCanonical && lines.some((line, index) => line !== canonicalJson(records[index]))) throw new Error("Anchor tenant record log is noncanonical");
    if (created) fsyncParent(file);
    return {
      records,
      size() {
        const current = assertPrivateRegularFd(fd, label);
        assertPathRefersToFd(file, fd, label);
        return current.size;
      },
      append(value) {
        const bytes = Buffer.from(value);
        const before = assertPrivateRegularFd(fd, label);
        assertPathRefersToFd(file, fd, label);
        if (before.size + bytes.length > 128 * 1024 * 1024) throw new Error("Anchor tenant record log exceeds the verification limit");
        fs.writeFileSync(fd, bytes);
        fs.fsyncSync(fd);
        assertPrivateRegularFd(fd, label);
        assertPathRefersToFd(file, fd, label);
        fsyncParent(file);
      },
      close() {
        if (fd !== undefined) {
          fs.closeSync(fd);
          fd = undefined;
        }
      }
    };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function assertPrivateRegularFd(fd, label) {
  const stat = fs.fstatSync(fd);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error(`${label} permissions are unsafe`);
  return stat;
}

function assertPrivateRegularFile(file, label) {
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error(`${label} permissions are unsafe`);
}

function assertPrivateDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error(`${label} permissions are unsafe`);
}

function assertPathRefersToFd(file, fd, label) {
  let pathStat;
  try { pathStat = fs.lstatSync(file); }
  catch { throw new Error(`${label} path changed while open`); }
  const fdStat = fs.fstatSync(fd);
  if (pathStat.isSymbolicLink() || pathStat.dev !== fdStat.dev || pathStat.ino !== fdStat.ino) throw new Error(`${label} path changed while open`);
}

function noFollowFlag() {
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error("O_NOFOLLOW is required for anchor record storage");
  return fs.constants.O_NOFOLLOW;
}

function unsafeOpenError(error, label) {
  if (["ELOOP", "EMLINK", "EEXIST"].includes(error.code)) return new Error(`${label} path is unsafe`, { cause: error });
  return error;
}

function unavailableAppend() {
  throw new Error("Anchor tenant record log was not opened for append");
}

function fsyncParent(file) {
  const directoryFlags = fs.constants.O_RDONLY | noFollowFlag() | (fs.constants.O_DIRECTORY ?? 0);
  let directoryFd;
  try {
    directoryFd = fs.openSync(path.dirname(file), directoryFlags);
    const stat = fs.fstatSync(directoryFd);
    const uid = process.getuid?.();
    if (!stat.isDirectory() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("Anchor tenant directory permissions are unsafe");
    fs.fsyncSync(directoryFd);
  } finally {
    if (directoryFd !== undefined) fs.closeSync(directoryFd);
  }
}

// Node does not expose openat(2)/renameat(2). Pinning the private parent by fd
// and comparing dev/inode before every pathname operation gives the equivalent
// fail-closed property for a root-private directory: a renamed/substituted
// parent is detected instead of silently redirecting the atomic replacement.
function writePrivateCanonicalAtomic(file, value, label) {
  const parent = path.dirname(file);
  const directoryFlags = fs.constants.O_RDONLY | noFollowFlag() | (fs.constants.O_DIRECTORY ?? 0);
  const directoryFd = fs.openSync(parent, directoryFlags);
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(16).toString("hex")}.tmp`;
  let fd;
  try {
    assertPrivateDirectoryFd(directoryFd, label);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    if (fs.existsSync(file)) assertPrivateRegularFile(file, label);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollowFlag(), 0o600);
    fs.writeFileSync(fd, canonicalJson(value));
    fs.fsyncSync(fd);
    assertPrivateRegularFd(fd, `${label} temporary file`);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    fs.closeSync(fd); fd = undefined;
    assertPrivateRegularFile(temporary, `${label} temporary file`);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    fs.renameSync(temporary, file);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    assertPrivateRegularFile(file, label);
    fs.fsyncSync(directoryFd);
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    try {
      assertDirectoryPathRefersToFd(parent, directoryFd, label);
      if (fs.existsSync(temporary)) {
        assertPrivateRegularFile(temporary, `${label} temporary file`);
        fs.unlinkSync(temporary);
        fs.fsyncSync(directoryFd);
      }
    } catch {}
    throw error;
  } finally {
    fs.closeSync(directoryFd);
  }
}

function readPrivateFilePinned(file, label, maximumBytes) {
  const parent = path.dirname(file);
  const directoryFlags = fs.constants.O_RDONLY | noFollowFlag() | (fs.constants.O_DIRECTORY ?? 0);
  const directoryFd = fs.openSync(parent, directoryFlags);
  let fd;
  try {
    assertPrivateDirectoryFd(directoryFd, label);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    try { fd = fs.openSync(file, fs.constants.O_RDONLY | noFollowFlag()); }
    catch (error) { throw unsafeOpenError(error, label); }
    const stat = assertPrivateRegularFd(fd, label);
    assertPathRefersToFd(file, fd, label);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    if (stat.size > maximumBytes) throw new Error(`${label} size is invalid`);
    const bytes = fs.readFileSync(fd);
    assertPrivateRegularFd(fd, label);
    assertPathRefersToFd(file, fd, label);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    return bytes;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.closeSync(directoryFd);
  }
}

function removePrivateFilePinned(file, label) {
  const parent = path.dirname(file);
  const directoryFlags = fs.constants.O_RDONLY | noFollowFlag() | (fs.constants.O_DIRECTORY ?? 0);
  const directoryFd = fs.openSync(parent, directoryFlags);
  let fd;
  try {
    assertPrivateDirectoryFd(directoryFd, label);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    fd = fs.openSync(file, fs.constants.O_RDONLY | noFollowFlag());
    assertPrivateRegularFd(fd, label);
    assertPathRefersToFd(file, fd, label);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    fs.unlinkSync(file);
    assertDirectoryPathRefersToFd(parent, directoryFd, label);
    fs.fsyncSync(directoryFd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.closeSync(directoryFd);
  }
}

function assertPrivateDirectoryFd(fd, label) {
  const stat = fs.fstatSync(fd);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error(`${label} parent directory permissions are unsafe`);
  return stat;
}

function assertDirectoryPathRefersToFd(directory, fd, label) {
  let pathStat;
  try { pathStat = fs.lstatSync(directory); }
  catch { throw new Error(`${label} parent directory changed while open`); }
  const fdStat = fs.fstatSync(fd);
  if (pathStat.isSymbolicLink() || !pathStat.isDirectory() || pathStat.dev !== fdStat.dev || pathStat.ino !== fdStat.ino) throw new Error(`${label} parent directory changed while open`);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    request.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) request.destroy(new Error("Request body is too large"));
      else chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function acquireTenantLock(file) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const lease = { pid: process.pid, nonce: crypto.randomBytes(16).toString("hex"), created_at: Date.now() };
    try {
      const fd = fs.openSync(file, "wx", 0o600);
      fs.writeFileSync(fd, JSON.stringify(lease));
      fs.closeSync(fd);
      return lease;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let existing;
      try { existing = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new Error("Anchor tenant lock is invalid; inspect it before removal"); }
      if (!Number.isInteger(existing.pid)) throw new Error("Anchor tenant lock is invalid; inspect it before removal");
      try {
        process.kill(existing.pid, 0);
        throw new Error("Another anchor process is updating this tenant");
      } catch (probeError) {
        if (probeError.code !== "ESRCH") throw probeError;
        const stat = fs.lstatSync(file);
        const uid = process.getuid?.();
        if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("Refusing to replace an unsafe anchor tenant lock");
        fs.unlinkSync(file);
      }
    }
  }
  throw new Error("Unable to acquire the anchor tenant lock");
}

function releaseTenantLock(file, lease) {
  try {
    const current = JSON.parse(fs.readFileSync(file, "utf8"));
    if (current.pid === lease.pid && current.nonce === lease.nonce) fs.unlinkSync(file);
  } catch {}
}

export const PRUNE_LEASE_TTL_MILLISECONDS = 30_000;
const PRUNE_LEASE_PURPOSES = new Set(["prepare", "submit", "execute", "reconcile"]);
const PRUNE_LEASE_REQUEST_MAX_AGE_MILLISECONDS = 60_000;

export function createAnchorPruneLeaseRuntime({ epoch = crypto.randomBytes(32).toString("base64url"), monotonicNow = () => process.hrtime.bigint() } = {}) {
  if (!isPruneHeadNonce(epoch) || typeof monotonicNow !== "function") throw new Error("Audit prune lease runtime is invalid");
  return { epoch, monotonicNow, foreignLeaseFirstObserved: new Map() };
}

const defaultPruneLeaseRuntime = createAnchorPruneLeaseRuntime();

function pruneHeadValue(tenant, receipt, configured, requestNonce, now, privateKey) {
  const statement = {
    version: 2,
    tenant,
    configured,
    sequence: receipt?.sequence ?? 0,
    receipt_hash: receipt?.receipt_hash ?? ZERO_HASH,
    receipt,
    request_nonce: requestNonce,
    issued_at: new Date(now).toISOString()
  };
  const anchorKeyFingerprint = publicKeyFingerprint(crypto.createPublicKey(privateKey));
  const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64");
  const value = { ...statement, anchor_key_fingerprint: anchorKeyFingerprint, signature };
  if (Buffer.byteLength(canonicalJson(value)) > MAX_DOCUMENT_BYTES) throw new Error("Audit prune head exceeds the response limit");
  return value;
}

function isPruneHeadNonce(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function isPruneLeaseBinding(purpose, operationId) {
  if (!PRUNE_LEASE_PURPOSES.has(purpose)) return false;
  return typeof operationId === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(operationId);
}

function verifyPruneLease(value, tenant, anchorPublicKey) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Audit prune lease is invalid");
  const statementKeys = ["issued_at", "lease_expires_at", "lease_id", "operation_id", "principal_fingerprint", "process_epoch", "purpose", "receipt_hash", "request_nonce", "sequence", "tenant", "version"];
  const expected = [...statementKeys, "anchor_key_fingerprint", "signature"].sort();
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson(expected)) throw new Error("Audit prune lease schema is invalid");
  const { anchor_key_fingerprint, signature, ...statement } = value;
  if (statement.version !== 4 || statement.tenant !== tenant || !isPruneHeadNonce(statement.request_nonce) || !isPruneHeadNonce(statement.process_epoch) ||
      !isPruneLeaseBinding(statement.purpose, statement.operation_id) || typeof statement.lease_id !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(statement.lease_id) ||
      !isFingerprint(statement.principal_fingerprint) || !Number.isSafeInteger(statement.sequence) || statement.sequence < 0 || !isHash(statement.receipt_hash) || !Number.isFinite(Date.parse(statement.issued_at)) ||
      !Number.isFinite(Date.parse(statement.lease_expires_at)) || Date.parse(statement.lease_expires_at) - Date.parse(statement.issued_at) !== PRUNE_LEASE_TTL_MILLISECONDS) {
    throw new Error("Audit prune lease statement is invalid");
  }
  const key = assertEd25519PublicKey(anchorPublicKey, "Audit prune lease key");
  if (anchor_key_fingerprint !== publicKeyFingerprint(key) || !isCanonicalBase64(signature)) throw new Error("Audit prune lease signature is invalid");
  const bytes = Buffer.from(signature, "base64");
  if (bytes.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(statement)), key, bytes)) throw new Error("Audit prune lease signature is invalid");
  if (statement.sequence === 0 && statement.receipt_hash !== ZERO_HASH) throw new Error("Audit prune lease zero head is invalid");
  if (statement.sequence > 0 && statement.receipt_hash === ZERO_HASH) throw new Error("Audit prune lease receipt position is invalid");
  return value;
}

function verifyPruneLeaseRequest(value, tenant, activeIdentity, receipt, now) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Authenticated audit prune lease request is required");
  const keys = ["audit_key_fingerprint", "expected_receipt_hash", "expected_sequence", "issued_at", "nonce", "operation_id", "purpose", "signature", "tenant", "version"];
  assertExactKeys(value, keys, "Audit prune lease request");
  const { signature, ...statement } = value;
  const issuedAt = Date.parse(statement.issued_at);
  const expectedSequence = receipt?.sequence ?? 0;
  const expectedHash = receipt?.receipt_hash ?? ZERO_HASH;
  if (statement.version !== 1 || statement.tenant !== tenant || !isPruneHeadNonce(statement.nonce) || !isPruneLeaseBinding(statement.purpose, statement.operation_id) ||
      !Number.isSafeInteger(statement.expected_sequence) || statement.expected_sequence !== expectedSequence || statement.expected_receipt_hash !== expectedHash ||
      !isFingerprint(statement.audit_key_fingerprint) || statement.audit_key_fingerprint !== activeIdentity.fingerprint || !isDate(statement.issued_at) ||
      issuedAt > now + MAX_RECOVERY_CLOCK_SKEW_MS || now - issuedAt > PRUNE_LEASE_REQUEST_MAX_AGE_MILLISECONDS ||
      activeIdentity.checkpoint_algorithm !== "p256-sha256" || !verifyAuditKeySignature(activeIdentity, statement, signature, { requireLowS: true })) {
    throw new Error("Audit prune lease request authentication, head, or freshness is invalid");
  }
  return value;
}

function verifyPruneLeaseReleaseRequest(value, tenant, activeIdentity, lease, now) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Authenticated audit prune lease release request is required");
  const keys = ["action", "audit_key_fingerprint", "issued_at", "lease_hash", "lease_id", "nonce", "operation_id", "purpose", "signature", "tenant", "version"];
  assertExactKeys(value, keys, "Audit prune lease release request");
  const { signature, ...statement } = value;
  const issuedAt = Date.parse(statement.issued_at);
  if (statement.version !== 1 || statement.action !== "release" || statement.tenant !== tenant || !isPruneHeadNonce(statement.nonce) ||
      statement.purpose !== lease.purpose || statement.operation_id !== lease.operation_id || statement.lease_id !== lease.lease_id ||
      statement.lease_hash !== hashCanonical(lease) || statement.audit_key_fingerprint !== lease.principal_fingerprint ||
      statement.audit_key_fingerprint !== activeIdentity.fingerprint || !isDate(statement.issued_at) ||
      issuedAt > now + MAX_RECOVERY_CLOCK_SKEW_MS || now - issuedAt > PRUNE_LEASE_REQUEST_MAX_AGE_MILLISECONDS ||
      activeIdentity.checkpoint_algorithm !== "p256-sha256" || !verifyAuditKeySignature(activeIdentity, statement, signature, { requireLowS: true })) {
    throw new Error("Audit prune lease release principal, binding, freshness, or signature is invalid");
  }
}

function pruneLeaseValue(tenant, receipt, request, now, privateKey, runtime) {
  const statement = {
    version: 4, tenant, purpose: request.purpose, operation_id: request.operation_id,
    sequence: receipt?.sequence ?? 0, receipt_hash: receipt?.receipt_hash ?? ZERO_HASH,
    principal_fingerprint: request.audit_key_fingerprint, request_nonce: request.nonce,
    lease_id: crypto.randomBytes(32).toString("base64url"), issued_at: new Date(now).toISOString(),
    lease_expires_at: new Date(now + PRUNE_LEASE_TTL_MILLISECONDS).toISOString(), process_epoch: runtime.epoch
  };
  const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64");
  const value = { ...statement, anchor_key_fingerprint: publicKeyFingerprint(crypto.createPublicKey(privateKey)), signature };
  runtime.foreignLeaseFirstObserved.set(statement.lease_id, runtime.monotonicNow());
  return value;
}

function rememberPruneLeaseNonce(directory, tenant, file, nonce, principal, now) {
  const tenantDir = path.dirname(file);
  const anchorPublicKey = readAnchorPublicKey(directory);
  const log = openRecordLog(file, { create: true, requireCanonical: true });
  try {
    const prior = verifyPruneNonceLedgerRecords(log.records, tenantDir, tenant, anchorPublicKey, { includeRecords: true });
    if (prior.records.some((record) => record.nonce === nonce)) throw new Error("Audit prune lease request nonce was replayed");
    const statement = { version: 1, sequence: prior.count + 1, nonce, principal_fingerprint: principal, observed_at: new Date(now).toISOString(), previous_record_hash: prior.headHash };
    const record = { ...statement, record_hash: hashCanonical(statement) };
    const bytes = Buffer.from(`${canonicalJson(record)}\n`);
    const currentSize = log.size();
    if (currentSize + bytes.length > MAX_PRUNE_NONCE_LOG_BYTES) throw new Error("Audit prune lease nonce log reached its fail-closed 64 MiB limit; administrator-signed compaction is required");
    invalidatePruneHeadSnapshot(directory, tenant);
    log.append(bytes);
    const next = { count: record.sequence, headHash: record.record_hash };
    writePruneNonceLedgerTip(directory, tenant, next);
    rebuildPruneHeadSnapshot(directory, tenant);
  } finally { log.close(); }
}

function readPruneNonceLedgerPosition(tenantDir, tenant, anchorPublicKey, { includeRecords = false, repairTip = false } = {}) {
  const file = path.join(tenantDir, ".audit-prune-lease-nonces.jsonl");
  const canonicalLog = openRecordLog(file, { requireCanonical: true });
  try { return verifyPruneNonceLedgerRecords(canonicalLog.records, tenantDir, tenant, anchorPublicKey, { includeRecords, repairTip }); }
  finally { canonicalLog.close(); }
}

function verifyPruneNonceLedgerRecords(records, tenantDir, tenant, anchorPublicKey, { includeRecords = false, repairTip = false } = {}) {
  const tipFile = path.join(tenantDir, ".audit-prune-lease-nonces.tip.json");
  let previous = ZERO_HASH;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    assertExactKeys(record, ["nonce", "observed_at", "previous_record_hash", "principal_fingerprint", "record_hash", "sequence", "version"], "Audit prune lease nonce record");
    const { record_hash, ...statement } = record;
    if (record.version !== 1 || record.sequence !== index + 1 || record.previous_record_hash !== previous || !isPruneHeadNonce(record.nonce) || !isFingerprint(record.principal_fingerprint) || !isDate(record.observed_at) || record_hash !== hashCanonical(statement)) throw new Error("Audit prune lease nonce ledger is invalid");
    previous = record_hash;
  }
  const position = { count: records.length, headHash: previous };
  if (records.length === 0) {
    if (fs.existsSync(tipFile)) throw new Error("Audit prune nonce tip exists without its immutable ledger");
  } else if (!fs.existsSync(tipFile)) {
    if (!repairTip || records.length !== 1) throw new Error("Audit prune nonce tip is missing or rolled back");
    writePruneNonceLedgerTipFromPublicKeyPath(tenantDir, tenant, position);
  } else {
    const tip = readVerifiedPruneNonceTip(tipFile, tenant, anchorPublicKey);
    if (tip.records !== position.count || tip.head_hash !== position.headHash) {
      if (!repairTip || tip.records + 1 !== position.count || records[tip.records]?.previous_record_hash !== tip.head_hash) throw new Error("Audit prune nonce ledger/tip rollback or equivocation detected");
      writePruneNonceLedgerTipFromPublicKeyPath(tenantDir, tenant, position);
    }
  }
  return includeRecords ? { ...position, records } : position;
}

function pruneNonceTipValue(tenant, position, privateKey) {
  const statement = { version: 1, tenant, records: position.count, head_hash: position.headHash };
  const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64");
  const signed = { ...statement, anchor_key_fingerprint: publicKeyFingerprint(crypto.createPublicKey(privateKey)), signature };
  return { ...signed, tip_hash: hashCanonical(signed) };
}

function writePruneNonceLedgerTip(directory, tenant, position) {
  const tenantDir = path.join(directory, "tenants", tenant);
  writePrivateCanonicalAtomic(path.join(tenantDir, ".audit-prune-lease-nonces.tip.json"), pruneNonceTipValue(tenant, position, loadAnchorPrivateKey(directory)), "Audit prune nonce tip");
}

function writePruneNonceLedgerTipFromPublicKeyPath(tenantDir, tenant, position) {
  const directory = path.dirname(path.dirname(tenantDir));
  writePruneNonceLedgerTip(directory, tenant, position);
}

function readVerifiedPruneNonceTip(file, tenant, anchorPublicKey) {
  const bytes = readPrivateFilePinned(file, "Audit prune nonce tip", 4096);
  if (bytes.length === 0 || bytes.length > 4096) throw new Error("Audit prune nonce tip size is invalid");
  const value = JSON.parse(bytes.toString("utf8"));
  if (!bytes.equals(Buffer.from(canonicalJson(value)))) throw new Error("Audit prune nonce tip is noncanonical");
  assertExactKeys(value, ["anchor_key_fingerprint", "head_hash", "records", "signature", "tenant", "tip_hash", "version"], "Audit prune nonce tip");
  const { anchor_key_fingerprint, signature, tip_hash, ...statement } = value;
  const key = assertEd25519PublicKey(anchorPublicKey, "Audit prune nonce tip key");
  if (statement.version !== 1 || statement.tenant !== tenant || !Number.isSafeInteger(statement.records) || statement.records < 1 || !isHash(statement.head_hash) || anchor_key_fingerprint !== publicKeyFingerprint(key) || !isCanonicalBase64(signature)) throw new Error("Audit prune nonce tip statement is invalid");
  const signatureBytes = Buffer.from(signature, "base64");
  if (signatureBytes.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(statement)), key, signatureBytes) || tip_hash !== hashCanonical({ ...statement, anchor_key_fingerprint, signature })) throw new Error("Audit prune nonce tip signature or hash is invalid");
  return value;
}

function writePruneLease(file, value) {
  if (fs.existsSync(file)) throw new Error("Another audit prune lease is active for this tenant");
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollowFlag(), 0o600);
    fs.writeFileSync(fd, canonicalJson(value));
    fs.fsyncSync(fd);
    assertPrivateRegularFd(fd, "Audit prune temporary lease");
    fs.closeSync(fd); fd = undefined;
    fs.renameSync(temporary, file);
    assertPrivateRegularFile(file, "Audit prune lease");
    fsyncParent(file);
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch {}
    throw error;
  }
}

function readActivePruneLease(file, tenant, anchorPublicKey, runtime) {
  if (!fs.existsSync(file)) return null;
  assertPrivateRegularFile(file, "Audit prune lease");
  const bytes = fs.readFileSync(file);
  if (bytes.length === 0 || bytes.length > MAX_DOCUMENT_BYTES) throw new Error("Audit prune lease size is invalid");
  const value = JSON.parse(bytes.toString("utf8"));
  if (!bytes.equals(Buffer.from(canonicalJson(value)))) throw new Error("Audit prune lease is noncanonical");
  verifyPruneLease(value, tenant, anchorPublicKey);
  const now = runtime.monotonicNow();
  if (typeof now !== "bigint" || now < 0n) throw new Error("Audit prune lease monotonic clock is invalid");
  let firstObserved;
  if (value.process_epoch === runtime.epoch) {
    firstObserved = runtime.foreignLeaseFirstObserved.get(value.lease_id);
    if (firstObserved === undefined) { firstObserved = now; runtime.foreignLeaseFirstObserved.set(value.lease_id, firstObserved); }
  } else {
    firstObserved = runtime.foreignLeaseFirstObserved.get(value.lease_id);
    if (firstObserved === undefined) { firstObserved = now; runtime.foreignLeaseFirstObserved.set(value.lease_id, firstObserved); }
  }
  if (now - firstObserved >= BigInt(PRUNE_LEASE_TTL_MILLISECONDS) * 1_000_000n) {
    removePruneLease(file, value.lease_id);
    runtime.foreignLeaseFirstObserved.delete(value.lease_id);
    return null;
  }
  return value;
}

function removePruneLease(file, leaseId) {
  assertPrivateRegularFile(file, "Audit prune lease");
  const current = JSON.parse(fs.readFileSync(file, "utf8"));
  if (current.lease_id !== leaseId) throw new Error("Audit prune lease changed before consume");
  fs.unlinkSync(file);
  fsyncParent(file);
}

function guardSubmittedPruneLease(active, submitted, authorization, priorReceipt, trust) {
  if (!submitted || canonicalJson(active) !== canonicalJson(submitted)) throw new Error("A different audit prune lease is active for this tenant");
  if (active.purpose !== "submit" || active.operation_id !== authorization.operation_id || active.principal_fingerprint !== authorization.signer_fingerprint || active.principal_fingerprint !== trust.active.fingerprint) throw new Error("Audit prune submit lease principal or operation binding is invalid");
  const statement = pruneAuthorizationStatement(authorization);
  if (!verifyAuditKeySignature(trust.active, statement, authorization.signature, { requireLowS: true }) || hashCanonical({ ...statement, signature: authorization.signature }) !== authorization.authorization_hash) {
    throw new Error("Audit prune submit lease principal authorization is invalid");
  }
  const expectedSequence = priorReceipt?.sequence ?? 0;
  const expectedHash = priorReceipt?.receipt_hash ?? ZERO_HASH;
  if (active.sequence !== expectedSequence || active.receipt_hash !== expectedHash) throw new Error("Audit prune head changed after lease acquisition");
}

function assertEd25519PublicKey(value, label) {
  let key;
  try { key = value instanceof crypto.KeyObject && value.type === "public" ? value : crypto.createPublicKey(value); }
  catch { throw new Error(`${label} is invalid`); }
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be Ed25519`);
  return key;
}

function identifyAuditPublicKey(value) {
  try {
    const key = assertEd25519PublicKey(value, "Audit checkpoint public key");
    return { algorithm: "ed25519", publicKey: String(value), fingerprint: publicKeyFingerprint(key) };
  } catch (ed25519Error) {
    try {
      const parsed = parseNativeAuditPublicKey(value);
      return { algorithm: "p256-sha256", publicKey: parsed.authorizedKey, fingerprint: nativeAuditPublicKeyFingerprint(parsed) };
    } catch {
      throw ed25519Error;
    }
  }
}

function verifyTenantCheckpoint(checkpoint, tenantConfig, options = {}) {
  const { requireCanonicalP256 = false, ...verificationOptions } = options;
  if (tenantConfig.checkpoint_algorithm === "p256-sha256") {
    if (!isCanonicalBase64(checkpoint?.signature)) throw new Error("Audit checkpoint P-256 signature is invalid");
    const signature = Buffer.from(checkpoint.signature, "base64");
    const scalarEncodingValid = requireCanonicalP256 ? isCanonicalP256P1363Signature(signature) : hasValidP256P1363Scalars(signature);
    if (!scalarEncodingValid) throw new Error(requireCanonicalP256 ? "Audit checkpoint P-256 signature must be a canonical low-S P1363 signature" : "Audit checkpoint P-256 signature scalars are invalid");
    return verifyNativeCheckpointRecord(checkpoint, tenantConfig.audit_public_key, verificationOptions);
  }
  if (tenantConfig.checkpoint_algorithm === "ed25519" || tenantConfig.version === 1) return verifyCheckpointRecord(checkpoint, tenantConfig.audit_public_key, verificationOptions);
  throw new Error("Anchor tenant checkpoint algorithm is unsupported");
}

function json(response, status, value) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  response.writeHead(status, { "content-type": "application/json", "content-length": body.length, "cache-control": "no-store" });
  response.end(body);
}

function canonicalJsonResponse(response, status, value) {
  const body = Buffer.from(canonicalJson(value));
  if (body.length > MAX_DOCUMENT_BYTES) throw new Error("Canonical response exceeds the response limit");
  response.writeHead(status, { "content-type": "application/json", "content-length": body.length, "cache-control": "no-store" });
  response.end(body);
}

function consumeRate(state, key, capacity, refillPerSecond) {
  const now = process.hrtime.bigint();
  let bucket = state.get(key);
  if (!bucket) bucket = { tokens: capacity, updated: now };
  const elapsed = Number(now - bucket.updated) / 1_000_000_000;
  bucket.tokens = Math.min(capacity, bucket.tokens + elapsed * refillPerSecond);
  bucket.updated = now;
  if (bucket.tokens < 1) { state.set(key, bucket); return false; }
  bucket.tokens -= 1;
  state.delete(key); state.set(key, bucket);
  while (state.size > 1024) state.delete(state.keys().next().value);
  return true;
}

function assertTenant(tenant) {
  if (typeof tenant !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(tenant)) throw new Error("Anchor tenant slug is invalid");
}

function receiptBytes(statement) {
  return Buffer.from(canonicalJson(statement));
}

function hash(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function hashCanonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function isHash(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isSlug(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value);
}

function isInstallationId(value) {
  return isSlug(value);
}

function assertExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) throw new Error(`${label} encoding is invalid`);
}

function positiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0 && value <= MAX_SAFE_INTEGER;
}

function safeIntegerAtLeast(value, minimum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= MAX_SAFE_INTEGER;
}

function isRetentionSlug(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
}

function isSafeFileName(value) {
  return typeof value === "string" && Buffer.byteLength(value) <= 255 && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value) && value !== "." && value !== "..";
}

function isDate(value) {
  return typeof value === "string" && Buffer.byteLength(value) <= 64 && Number.isFinite(Date.parse(value));
}

function isCanonicalDate(value) {
  return isDate(value) && new Date(Date.parse(value)).toISOString() === value;
}

function isEpochMilliseconds(value) {
  return Number.isFinite(Number(value)) && Math.abs(Number(value)) <= 8_640_000_000_000_000;
}

function isFingerprint(value) {
  return typeof value === "string" && /^SHA256:[A-Za-z0-9_-]{43}$/.test(value);
}

function isCanonicalBase64(value) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  try { return Buffer.from(value, "base64").toString("base64") === value; }
  catch { return false; }
}
