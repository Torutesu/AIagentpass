import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { anchorPendingCheckpoints, readAnchorReceipts, verifyStoredAnchorReceipts } from "../lib/anchor-client.mjs";
import { acquireAnchorPruneLease, anchorRecoveryAuthorization, createAnchorPruneLeaseRuntime, createAnchorRecoveryPolicy, createAnchorServer, enrollAnchorTenant, initializeAnchor, readAnchorPruneHead, releaseAnchorPruneLease, submitAnchorCheckpoint, submitAnchorKeyTransition, submitAnchorPrune, verifyAnchorKeyTransitionReceipt, verifyAnchorPruneReceipt, verifyAnchorReceipt, verifyAnchorTenant } from "../lib/anchor.mjs";
import { audit, createAuditCheckpoint, publicKeyFingerprint, readAuditCheckpoints } from "../lib/audit.mjs";
import { canonicalJson, createAuditIdentity } from "../lib/identity.mjs";
import { nativeAuditPublicKeyFingerprint, verifyNativeCheckpointRecord } from "../lib/native-audit.mjs";
import { startInMemoryHttpServer } from "./support/http-test-transport.mjs";

const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_ORDER = P256_ORDER / 2n;
const PRUNE_HEAD_NONCE = Buffer.alloc(32, 0x41).toString("base64url");
const PRUNE_HEAD_NONCE_2 = Buffer.alloc(32, 0x42).toString("base64url");
const PRUNE_HEAD_NOW = Date.parse("2031-01-01T00:00:00.000Z");

function pruneHeadURL(base, tenant, nonce) {
  return `${base}/v1/audit-prunes/${tenant}/head?${new URLSearchParams({ nonce })}`;
}

function pruneLeaseRequest(value, nonce, purpose, operationId, head, now) {
  const statement = { version: 1, tenant: "prune-host", nonce, purpose, operation_id: operationId, expected_sequence: head.sequence, expected_receipt_hash: head.receipt_hash, issued_at: new Date(now).toISOString(), audit_key_fingerprint: nativeAuditPublicKeyFingerprint(value.audit.authorizedKey) };
  return { ...statement, signature: signP256LowS(value.audit.privateKey, statement) };
}

function pruneLeaseReleaseRequest(value, nonce, lease, now) {
  const statement = { version: 1, action: "release", tenant: "prune-host", nonce, purpose: lease.purpose, operation_id: lease.operation_id, lease_id: lease.lease_id, lease_hash: crypto.createHash("sha256").update(canonicalJson(lease)).digest("hex"), issued_at: new Date(now).toISOString(), audit_key_fingerprint: nativeAuditPublicKeyFingerprint(value.audit.authorizedKey) };
  return { ...statement, signature: signP256LowS(value.audit.privateKey, statement) };
}

async function acquireHTTPPruneLease(base, value, nonce, purpose, operationId, now) {
  const headResponse = await fetch(pruneHeadURL(base, "prune-host", nonce));
  assert.equal(headResponse.status, 200);
  const head = await headResponse.json();
  const response = await fetch(`${base}/v1/audit-prunes/prune-host/leases`, { method: "POST", headers: { "content-type": "application/json" }, body: canonicalJson({ request: pruneLeaseRequest(value, nonce, purpose, operationId, head, now) }) });
  if (response.status !== 200) assert.fail(`lease acquisition failed: ${response.status} ${await response.text()}`);
  return response.json();
}

function p256Scalar(value) {
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}

function canonicalizeP256Signature(signature) {
  const raw = Buffer.isBuffer(signature) ? Buffer.from(signature) : Buffer.from(signature, "base64");
  assert.equal(raw.length, 64);
  const s = BigInt(`0x${raw.subarray(32).toString("hex")}`);
  assert.ok(s > 0n && s < P256_ORDER);
  if (s > P256_HALF_ORDER) p256Scalar(P256_ORDER - s).copy(raw, 32);
  return raw;
}

function signP256LowS(privateKey, statement) {
  return canonicalizeP256Signature(crypto.sign("sha256", Buffer.from(canonicalJson(statement)), {
    key: privateKey,
    dsaEncoding: "ieee-p1363"
  })).toString("base64");
}

function malleateP256SignatureToHighS(signature) {
  const raw = canonicalizeP256Signature(signature);
  const s = BigInt(`0x${raw.subarray(32).toString("hex")}`);
  const highS = P256_ORDER - s;
  assert.ok(highS > P256_HALF_ORDER && highS < P256_ORDER);
  p256Scalar(highS).copy(raw, 32);
  return raw.toString("base64");
}

function withTransitionSignature(transition, field, signature) {
  const { transition_hash: ignored, ...body } = { ...transition, [field]: signature };
  return {
    ...body,
    transition_hash: crypto.createHash("sha256").update(canonicalJson(body)).digest("hex")
  };
}

function withPruneSignature(authorization, signature) {
  const { authorization_hash: ignored, ...body } = { ...authorization, signature };
  return {
    ...body,
    authorization_hash: crypto.createHash("sha256").update(canonicalJson(body)).digest("hex")
  };
}

function withCheckpointSignature(checkpoint, signature) {
  const { checkpoint_hash: ignored, ...body } = { ...checkpoint, signature };
  return {
    ...body,
    checkpoint_hash: crypto.createHash("sha256").update(canonicalJson(body)).digest("hex")
  };
}

function fixture() {
  const host = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-anchor-host-"));
  const anchor = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-anchor-server-"));
  const identity = createAuditIdentity(host);
  const initialized = initializeAnchor(anchor);
  enrollAnchorTenant(anchor, "host-one", identity.public_key);
  audit({ operation: "test.one", decision: "allow" }, host);
  const first = createAuditCheckpoint(identity.public_key, host);
  audit({ operation: "test.two", decision: "allow" }, host);
  const second = createAuditCheckpoint(identity.public_key, host);
  return { host, anchor, identity, initialized, first, second };
}

function nativeFixture() {
  const anchor = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-native-anchor-server-"));
  const initialized = initializeAnchor(anchor);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  const publicBlob = Buffer.concat([sshString("ecdsa-sha2-nistp256"), sshString("nistp256"), sshString(point)]);
  const auditPublicKey = `ecdsa-sha2-nistp256 ${publicBlob.toString("base64")}`;
  const enrolled = enrollAnchorTenant(anchor, "native-host", auditPublicKey);
  const checkpoint = (entries, previous, headByte) => {
    const statement = {
      version: 1,
      created_at: new Date(1_800_000_000_000 + entries * 1000).toISOString(),
      entries,
      head_hash: headByte.repeat(64),
      previous_checkpoint_hash: previous
    };
    const signature = signP256LowS(privateKey, statement);
    const record = { ...statement, public_key_fingerprint: nativeAuditPublicKeyFingerprint(auditPublicKey), signature };
    record.checkpoint_hash = crypto.createHash("sha256").update(canonicalJson(record)).digest("hex");
    return record;
  };
  const first = checkpoint(1, "0".repeat(64), "a");
  const second = checkpoint(2, first.checkpoint_hash, "b");
  return { anchor, initialized, enrolled, auditPublicKey, privateKey, first, second };
}

function nativeKeyPair() {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  const blob = Buffer.concat([sshString("ecdsa-sha2-nistp256"), sshString("nistp256"), sshString(point)]);
  return { ...pair, authorizedKey: `ecdsa-sha2-nistp256 ${blob.toString("base64")}` };
}

function nativeCheckpointV2(privateKey, publicKey, { entries, previous, headByte, generation, lifecycleHead }) {
  const statement = { version: 2, created_at: new Date(1_900_000_000_000 + entries * 1000).toISOString(), entries, head_hash: headByte.repeat(64), previous_checkpoint_hash: previous, key_generation: generation, lifecycle_head_hash: lifecycleHead };
  const signature = signP256LowS(privateKey, statement);
  const record = { ...statement, public_key_fingerprint: nativeAuditPublicKeyFingerprint(publicKey), signature };
  record.checkpoint_hash = crypto.createHash("sha256").update(canonicalJson(record)).digest("hex");
  return record;
}

function nativeCheckpointV1(privateKey, publicKey, { entries, previous, headByte, createdAt }) {
  const statement = { version: 1, created_at: createdAt, entries, head_hash: headByte.repeat(64), previous_checkpoint_hash: previous };
  const signature = signP256LowS(privateKey, statement);
  const record = { ...statement, public_key_fingerprint: nativeAuditPublicKeyFingerprint(publicKey), signature };
  record.checkpoint_hash = crypto.createHash("sha256").update(canonicalJson(record)).digest("hex");
  return record;
}

function nativeTransition(privateKey, publicKey, replacement, {
  tenant = "native-host",
  operationId,
  fromGeneration,
  lifecycleHead,
  createdAt,
  previousTransitionHash = "0".repeat(64),
  previousTransitionReceiptHash = "0".repeat(64),
  checkpointIndex,
  checkpoint,
  checkpointReceipt,
  previousEventIndex,
  previousEventHash,
  pendingCheckpointCount = 0
}) {
  const statement = {
    version: 2,
    tenant,
    operation_id: operationId,
    from_generation: fromGeneration,
    to_generation: fromGeneration + 1,
    old_key_fingerprint: nativeAuditPublicKeyFingerprint(publicKey),
    new_key_fingerprint: nativeAuditPublicKeyFingerprint(replacement.authorizedKey),
    new_public_key: replacement.authorizedKey,
    lifecycle_head_hash: lifecycleHead,
    created_at: createdAt,
    previous_transition_hash: previousTransitionHash,
    previous_transition_receipt_hash: previousTransitionReceiptHash,
    last_checkpoint_index: checkpointIndex,
    last_checkpoint_hash: checkpoint.checkpoint_hash,
    last_checkpoint_receipt_hash: checkpointReceipt.receipt_hash,
    previous_anchor_event_index: previousEventIndex,
    previous_anchor_event_hash: previousEventHash,
    retiring_generation_pending_checkpoint_count: pendingCheckpointCount
  };
  const old_signature = signP256LowS(privateKey, statement);
  const new_signature = signP256LowS(replacement.privateKey, statement);
  const transition = { ...statement, old_signature, new_signature };
  transition.transition_hash = crypto.createHash("sha256").update(canonicalJson(transition)).digest("hex");
  return transition;
}

function nativeTransitionV1(privateKey, publicKey, replacement, { operationId, lifecycleHead, createdAt }) {
  const statement = {
    version: 1,
    tenant: "native-host",
    operation_id: operationId,
    from_generation: 1,
    to_generation: 2,
    old_key_fingerprint: nativeAuditPublicKeyFingerprint(publicKey),
    new_key_fingerprint: nativeAuditPublicKeyFingerprint(replacement.authorizedKey),
    new_public_key: replacement.authorizedKey,
    lifecycle_head_hash: lifecycleHead,
    created_at: createdAt,
    previous_transition_hash: "0".repeat(64)
  };
  const old_signature = signP256LowS(privateKey, statement);
  const new_signature = signP256LowS(replacement.privateKey, statement);
  const transition = { ...statement, old_signature, new_signature };
  transition.transition_hash = crypto.createHash("sha256").update(canonicalJson(transition)).digest("hex");
  return transition;
}

function recoveryKey(id) {
  const pair = crypto.generateKeyPairSync("ed25519");
  return { id, ...pair, publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() };
}

function nativeRecoveryFixture() {
  const anchor = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-native-recovery-anchor-"));
  const initialized = initializeAnchor(anchor);
  const audit = nativeKeyPair();
  const recoveryKeys = [recoveryKey("operator-a"), recoveryKey("operator-b"), recoveryKey("operator-c")];
  const recoveryPolicy = createAnchorRecoveryPolicy({
    policy_id: "offline-recovery-2026",
    threshold: 2,
    keys: recoveryKeys.map((item) => ({ id: item.id, public_key: item.publicPem }))
  });
  const enrolled = enrollAnchorTenant(anchor, "recovery-host", audit.authorizedKey, {
    installationId: "installation-primary-001",
    recoveryPolicy
  });
  const checkpoint = nativeCheckpointV1(audit.privateKey, audit.authorizedKey, {
    entries: 1,
    previous: "0".repeat(64),
    headByte: "a",
    createdAt: "2030-01-01T00:00:00.000Z"
  });
  const checkpointReceipt = submitAnchorCheckpoint(anchor, "recovery-host", checkpoint, Date.parse("2030-01-01T00:00:01.000Z"));
  return { anchor, initialized, audit, recoveryKeys, recoveryPolicy, enrolled, checkpoint, checkpointReceipt };
}

function nativeRecoveryTransition(value, replacement, overrides = {}) {
  const fields = {
    version: 3,
    tenant: "recovery-host",
    installation_id: "installation-primary-001",
    role: "audit_checkpoint",
    operation_id: "recovery-operation-001",
    recovery_request_id: "recovery-request-001",
    recovery_policy_id: value.recoveryPolicy.policy_id,
    recovery_policy_hash: value.recoveryPolicy.policy_hash,
    from_generation: 1,
    to_generation: 2,
    old_key_fingerprint: nativeAuditPublicKeyFingerprint(value.audit.authorizedKey),
    new_key_fingerprint: nativeAuditPublicKeyFingerprint(replacement.authorizedKey),
    new_public_key: replacement.authorizedKey,
    lifecycle_head_hash: "c".repeat(64),
    created_at: "2030-01-01T00:00:02.000Z",
    expires_at: "2030-01-01T00:10:02.000Z",
    previous_transition_hash: "0".repeat(64),
    previous_transition_receipt_hash: "0".repeat(64),
    last_checkpoint_index: 1,
    last_checkpoint_hash: value.checkpoint.checkpoint_hash,
    last_checkpoint_receipt_hash: value.checkpointReceipt.receipt_hash,
    previous_anchor_event_index: value.checkpointReceipt.event_index,
    previous_anchor_event_hash: value.checkpointReceipt.receipt_hash,
    retiring_generation_pending_checkpoint_count: 0,
    ...overrides
  };
  const authorization = anchorRecoveryAuthorization(fields);
  const signerKeys = overrides.signerKeys ?? value.recoveryKeys.slice(0, 2);
  const approvals = signerKeys.map((item) => ({
    key_id: item.id,
    signature: crypto.sign(null, Buffer.from(canonicalJson(authorization)), item.privateKey).toString("base64")
  })).sort((left, right) => left.key_id.localeCompare(right.key_id));
  const recovery_evidence = { version: 1, authorization, policy: overrides.evidencePolicy ?? value.recoveryPolicy, approvals };
  const new_signature = signP256LowS(replacement.privateKey, authorization);
  const transition = { ...authorization, recovery_evidence, new_signature };
  transition.transition_hash = crypto.createHash("sha256").update(canonicalJson(transition)).digest("hex");
  return transition;
}

function nativePruneFixture() {
  const anchor = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-prune-anchor-"));
  const initialized = initializeAnchor(anchor);
  const audit = nativeKeyPair();
  const lifecycleHead = "d".repeat(64);
  enrollAnchorTenant(anchor, "prune-host", audit.authorizedKey);
  const first = nativeCheckpointV2(audit.privateKey, audit.authorizedKey, { entries: 1, previous: "0".repeat(64), headByte: "a", generation: 1, lifecycleHead });
  const second = nativeCheckpointV2(audit.privateKey, audit.authorizedKey, { entries: 2, previous: first.checkpoint_hash, headByte: "b", generation: 1, lifecycleHead });
  const firstReceipt = submitAnchorCheckpoint(anchor, "prune-host", first, Date.parse("2029-01-01T00:00:01.000Z"));
  const secondReceipt = submitAnchorCheckpoint(anchor, "prune-host", second, Date.parse("2029-01-01T00:00:02.000Z"));
  return { anchor, initialized, audit, lifecycleHead, first, second, firstReceipt, secondReceipt };
}

function nativePruneAuthorization(value, overrides = {}) {
  const segment = {
    segment_id: "segment-0001",
    audit_archive_file: "audit-0001.jsonl", audit_archive_sha256: "1".repeat(64),
    first_event_index: 1, last_event_index: 2, previous_event_hash: "0".repeat(64), terminal_event_hash: value.second.head_hash,
    checkpoint_archive_file: "checkpoints-0001.jsonl", checkpoint_archive_sha256: "2".repeat(64),
    first_checkpoint_index: 1, last_checkpoint_index: 2, previous_checkpoint_hash: "0".repeat(64), terminal_checkpoint_hash: value.second.checkpoint_hash,
    receipt_archive_file: "receipts-0001.jsonl", receipt_archive_sha256: "3".repeat(64),
    first_receipt_index: 1, last_receipt_index: 2, previous_receipt_hash: "0".repeat(64), terminal_receipt_hash: value.secondReceipt.receipt_hash,
    anchored_event_index: 2, anchored_event_hash: value.second.head_hash,
    sealed_at: "2029-01-01T00:00:01.000Z", latest_anchor_received_at: value.secondReceipt.received_at,
    ...(overrides.segment ?? {})
  };
  const statement = {
    version: 1, tenant: "prune-host", operation_id: "prune-operation-0001", sequence: 1,
    previous_authorization_hash: "0".repeat(64), previous_prune_receipt_hash: "0".repeat(64), previous_manifest_hash: "0".repeat(64),
    retention_seconds: 30 * 24 * 60 * 60, requested_at: "2029-02-01T00:00:03.000Z",
    boundary: {
      lifecycle_head_hash: value.lifecycleHead, audit_key_transition_receipt_hash: "0".repeat(64),
      anchor_event_index: value.secondReceipt.event_index, anchor_event_hash: value.secondReceipt.receipt_hash,
      checkpoint_index: 2, checkpoint_hash: value.second.checkpoint_hash, checkpoint_receipt_hash: value.secondReceipt.receipt_hash,
      ...(overrides.boundary ?? {})
    },
    segments: overrides.segments ?? [segment], signer_fingerprint: nativeAuditPublicKeyFingerprint(value.audit.authorizedKey),
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => !["segment", "segments", "boundary"].includes(key)))
  };
  const signature = signP256LowS(value.audit.privateKey, statement);
  const authorization = { ...statement, signature };
  authorization.authorization_hash = crypto.createHash("sha256").update(canonicalJson(authorization)).digest("hex");
  return authorization;
}

function submitPruneWithLease(value, authorization, now, runtime = undefined) {
  const nonce = crypto.randomBytes(32).toString("base64url");
  const head = readAnchorPruneHead(value.anchor, "prune-host", nonce, now);
  const request = pruneLeaseRequest(value, nonce, "submit", authorization.operation_id, head, now);
  const lease = acquireAnchorPruneLease(value.anchor, "prune-host", request, now, runtime);
  try {
    return submitAnchorPrune(value.anchor, "prune-host", authorization, now, lease, runtime);
  } catch (error) {
    try {
      releaseAnchorPruneLease(value.anchor, "prune-host", lease, pruneLeaseReleaseRequest(value, crypto.randomBytes(32).toString("base64url"), lease, now), now, runtime);
    } catch {}
    throw error;
  }
}

function recordPruneLeaseNonce(value, nonce, operationId, now, runtime = undefined) {
  const head = readAnchorPruneHead(value.anchor, "prune-host", nonce, now);
  const lease = acquireAnchorPruneLease(value.anchor, "prune-host", pruneLeaseRequest(value, nonce, "execute", operationId, head, now), now, runtime);
  const release = pruneLeaseReleaseRequest(value, crypto.randomBytes(32).toString("base64url"), lease, now + 1);
  releaseAnchorPruneLease(value.anchor, "prune-host", lease, release, now + 1, runtime);
  return lease;
}

function legacyAnchorReceipt(anchor, tenant, kind, index, valueHash, previousReceiptHash, receivedAt) {
  const hashKey = kind === "checkpoint" ? "checkpoint_hash" : "transition_hash";
  const statement = { version: 1, tenant, index, [hashKey]: valueHash, received_at: receivedAt, previous_receipt_hash: previousReceiptHash };
  const privateKey = crypto.createPrivateKey(fs.readFileSync(path.join(anchor, "anchor-private.pem")));
  const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64");
  const receipt = { ...statement, anchor_key_fingerprint: publicKeyFingerprint(crypto.createPublicKey(privateKey)), signature };
  receipt.receipt_hash = crypto.createHash("sha256").update(JSON.stringify(receipt)).digest("hex");
  return receipt;
}

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

test("anchor signs an append-only checkpoint and receipt chain", () => {
  const value = fixture();
  const firstReceipt = submitAnchorCheckpoint(value.anchor, "host-one", value.first, Date.parse("2026-08-11T00:00:00Z"));
  assert.deepEqual(submitAnchorCheckpoint(value.anchor, "host-one", value.first), firstReceipt, "retries must be idempotent");
  const secondReceipt = submitAnchorCheckpoint(value.anchor, "host-one", value.second, Date.parse("2026-08-11T00:01:00Z"));
  assert.equal(secondReceipt.index, 2);
  assert.equal(secondReceipt.previous_receipt_hash, firstReceipt.receipt_hash);
  assert.equal(verifyAnchorReceipt(secondReceipt, fs.readFileSync(value.initialized.public_file), {
    tenant: "host-one",
    checkpointHash: value.second.checkpoint_hash,
    previousReceiptHash: firstReceipt.receipt_hash
  }).receipt_hash, secondReceipt.receipt_hash);
  assert.deepEqual(verifyAnchorTenant(value.anchor, "host-one"), {
    valid: true,
    records: 2,
    latest_checkpoint: value.second.checkpoint_hash,
    latest_receipt: secondReceipt.receipt_hash
  });
});

test("anchor enrolls and verifies native P-256 checkpoint chains", () => {
  const value = nativeFixture();
  assert.equal(value.enrolled.version, 2);
  assert.equal(value.enrolled.checkpoint_algorithm, "p256-sha256");
  assert.equal(verifyNativeCheckpointRecord(value.first, value.auditPublicKey).checkpoint_hash, value.first.checkpoint_hash);
  const firstReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.first);
  assert.deepEqual(submitAnchorCheckpoint(value.anchor, "native-host", value.first), firstReceipt);
  const secondReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.second);
  assert.equal(secondReceipt.index, 2);
  assert.deepEqual(verifyAnchorTenant(value.anchor, "native-host"), {
    valid: true,
    records: 2,
    latest_checkpoint: value.second.checkpoint_hash,
    latest_receipt: secondReceipt.receipt_hash
  });
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "native-host", { ...value.second, entries: 3 }), /signature|hash/i);
  const configFile = path.join(value.anchor, "tenants", "native-host", "config.json");
  const config = JSON.parse(fs.readFileSync(configFile, "utf8"));
  config.checkpoint_algorithm = "ed25519";
  fs.writeFileSync(configFile, `${JSON.stringify(config)}\n`, { mode: 0o600 });
  assert.throws(() => verifyAnchorTenant(value.anchor, "native-host"), /algorithm|identity/i);
});

test("new native checkpoints reject a high-S equivalent before anchoring", () => {
  const value = nativeFixture();
  const malleated = withCheckpointSignature(value.first, malleateP256SignatureToHighS(value.first.signature));
  assert.notEqual(malleated.checkpoint_hash, value.first.checkpoint_hash);
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "native-host", malleated), /canonical low-S/i);
  assert.equal(submitAnchorCheckpoint(value.anchor, "native-host", value.first).index, 1, "the rejected equivalent must not consume the checkpoint boundary");
});

test("anchor rotates native audit keys with dual possession proofs and lifecycle binding", () => {
  const value = nativeFixture();
  submitAnchorCheckpoint(value.anchor, "native-host", value.first);
  const secondReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.second);
  const replacement = nativeKeyPair();
  const lifecycleHead = "c".repeat(64);
  const transition = nativeTransition(value.privateKey, value.auditPublicKey, replacement, {
    operationId: "rotation-0001",
    fromGeneration: 1,
    lifecycleHead,
    createdAt: "2030-03-17T17:46:40.000Z",
    checkpointIndex: 2,
    checkpoint: value.second,
    checkpointReceipt: secondReceipt,
    previousEventIndex: secondReceipt.event_index,
    previousEventHash: secondReceipt.receipt_hash
  });
  const receipt = submitAnchorKeyTransition(value.anchor, "native-host", transition, Date.parse("2030-03-17T17:47:00Z"));
  assert.deepEqual(submitAnchorKeyTransition(value.anchor, "native-host", transition), receipt);
  assert.equal(verifyAnchorKeyTransitionReceipt(receipt, fs.readFileSync(value.initialized.public_file), { tenant: "native-host", transitionHash: transition.transition_hash, previousReceiptHash: "0".repeat(64) }).receipt_hash, receipt.receipt_hash);

  assert.deepEqual(submitAnchorCheckpoint(value.anchor, "native-host", value.second), secondReceipt, "an already-anchored old-generation retry remains idempotent");
  const next = nativeCheckpointV2(replacement.privateKey, replacement.authorizedKey, { entries: 3, previous: value.second.checkpoint_hash, headByte: "d", generation: 2, lifecycleHead });
  const nextReceipt = submitAnchorCheckpoint(value.anchor, "native-host", next);
  assert.equal(nextReceipt.index, 3);
  assert.deepEqual(submitAnchorKeyTransition(value.anchor, "native-host", transition), receipt, "transition retry remains idempotent after newer checkpoint events");
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", { ...transition, lifecycle_head_hash: "e".repeat(64) }), /equivocation/i);
  assert.equal(verifyAnchorTenant(value.anchor, "native-host").records, 3);

  const forged = { ...transition, operation_id: "rotation-forged" };
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", forged), /statement|proof|hash/i);
  const wrongLifecycle = nativeCheckpointV2(replacement.privateKey, replacement.authorizedKey, { entries: 4, previous: next.checkpoint_hash, headByte: "e", generation: 2, lifecycleHead: "f".repeat(64) });
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "native-host", wrongLifecycle), /lifecycle/i);

  const reused = nativeTransition(replacement.privateKey, replacement.authorizedKey, { privateKey: value.privateKey, authorizedKey: value.auditPublicKey }, {
    operationId: "rotation-reuses-generation-one-key", fromGeneration: 2, lifecycleHead: "e".repeat(64),
    createdAt: "2030-03-17T17:48:00.000Z", previousTransitionHash: transition.transition_hash,
    previousTransitionReceiptHash: receipt.receipt_hash, checkpointIndex: 3, checkpoint: next,
    checkpointReceipt: nextReceipt, previousEventIndex: nextReceipt.event_index, previousEventHash: nextReceipt.receipt_hash
  });
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", reused), /used|replacement identity/i);
});

test("v2 transition rejects high-S malleation and invalid P-256 scalars before anchoring", () => {
  const value = nativeFixture();
  submitAnchorCheckpoint(value.anchor, "native-host", value.first);
  const checkpointReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.second);
  const replacement = nativeKeyPair();
  const transition = nativeTransition(value.privateKey, value.auditPublicKey, replacement, {
    operationId: "rotation-low-s-v2",
    fromGeneration: 1,
    lifecycleHead: "c".repeat(64),
    createdAt: "2030-03-17T17:46:40.000Z",
    checkpointIndex: 2,
    checkpoint: value.second,
    checkpointReceipt,
    previousEventIndex: checkpointReceipt.event_index,
    previousEventHash: checkpointReceipt.receipt_hash
  });

  const highS = withTransitionSignature(transition, "new_signature", malleateP256SignatureToHighS(transition.new_signature));
  assert.notEqual(highS.transition_hash, transition.transition_hash);
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", highS, Date.parse("2030-03-17T17:47:00Z")), /possession proof/i);

  const validRaw = Buffer.from(transition.old_signature, "base64");
  const invalidScalars = [
    Buffer.concat([Buffer.alloc(32), validRaw.subarray(32)]),
    Buffer.concat([p256Scalar(P256_ORDER), validRaw.subarray(32)]),
    Buffer.concat([validRaw.subarray(0, 32), Buffer.alloc(32)]),
    Buffer.concat([validRaw.subarray(0, 32), p256Scalar(P256_ORDER)])
  ];
  for (const signature of invalidScalars) {
    const invalid = withTransitionSignature(transition, "old_signature", signature.toString("base64"));
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", invalid, Date.parse("2030-03-17T17:47:00Z")), /possession proof/i);
  }

  assert.equal(submitAnchorKeyTransition(value.anchor, "native-host", transition, Date.parse("2030-03-17T17:47:00Z")).index, 1, "rejected variants must not consume the transition boundary");
});

test("anchor accepts an offline-authorized v3 recovery transition and preserves v2 receipt/event compatibility", () => {
  const value = nativeRecoveryFixture();
  const replacement = nativeKeyPair();
  const transition = nativeRecoveryTransition(value, replacement);
  const now = Date.parse("2030-01-01T00:00:03.000Z");
  const receipt = submitAnchorKeyTransition(value.anchor, "recovery-host", transition, now);

  assert.equal(receipt.version, 2, "v3 transitions deliberately retain the v2 receipt/event schema");
  assert.equal(receipt.event_index, value.checkpointReceipt.event_index + 1);
  assert.deepEqual(submitAnchorKeyTransition(value.anchor, "recovery-host", transition, Date.parse("2031-01-01T00:00:00.000Z")), receipt, "an accepted recovery remains idempotent after its authorization expires");
  assert.equal(verifyAnchorKeyTransitionReceipt(receipt, fs.readFileSync(value.initialized.public_file), {
    tenant: "recovery-host",
    transitionHash: transition.transition_hash,
    previousReceiptHash: "0".repeat(64)
  }).receipt_hash, receipt.receipt_hash);
  assert.equal(verifyAnchorTenant(value.anchor, "recovery-host").records, 1, "history verifies from durable tenant configuration and logs after restart");

  const checkpoint2 = nativeCheckpointV2(replacement.privateKey, replacement.authorizedKey, {
    entries: 2,
    previous: value.checkpoint.checkpoint_hash,
    headByte: "d",
    generation: 2,
    lifecycleHead: transition.lifecycle_head_hash
  });
  assert.equal(submitAnchorCheckpoint(value.anchor, "recovery-host", checkpoint2, Date.parse("2030-01-01T00:00:04.000Z")).index, 2);
});

test("v3 recovery transition rejects a high-S replacement proof before anchoring", () => {
  const value = nativeRecoveryFixture();
  const transition = nativeRecoveryTransition(value, nativeKeyPair());
  const highS = withTransitionSignature(transition, "new_signature", malleateP256SignatureToHighS(transition.new_signature));
  assert.notEqual(highS.transition_hash, transition.transition_hash);
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", highS, Date.parse("2030-01-01T00:00:03.000Z")), /replacement-key possession proof/i);
  assert.equal(submitAnchorKeyTransition(value.anchor, "recovery-host", transition, Date.parse("2030-01-01T00:00:03.000Z")).index, 1, "the rejected equivalent must not consume the recovery boundary");
});

test("v3 recovery rejects equivocation, replay, stale boundaries, expiry, and duplicate signers", () => {
  {
    const value = nativeRecoveryFixture();
    const replacement = nativeKeyPair();
    const transition = nativeRecoveryTransition(value, replacement);
    const receipt = submitAnchorKeyTransition(value.anchor, "recovery-host", transition, Date.parse("2030-01-01T00:00:03.000Z"));
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", { ...transition, expires_at: "2030-01-01T02:00:02.000Z" }), /equivocation/i);

    const checkpoint2 = nativeCheckpointV2(replacement.privateKey, replacement.authorizedKey, {
      entries: 2, previous: value.checkpoint.checkpoint_hash, headByte: "d", generation: 2, lifecycleHead: transition.lifecycle_head_hash
    });
    const checkpointReceipt2 = submitAnchorCheckpoint(value.anchor, "recovery-host", checkpoint2, Date.parse("2030-01-01T00:00:04.000Z"));
    const generation3 = nativeKeyPair();
    const replay = nativeRecoveryTransition(value, generation3, {
      operation_id: "recovery-operation-002",
      recovery_request_id: transition.recovery_request_id,
      from_generation: 2,
      to_generation: 3,
      old_key_fingerprint: nativeAuditPublicKeyFingerprint(replacement.authorizedKey),
      created_at: "2030-01-01T00:00:05.000Z",
      expires_at: "2030-01-01T00:10:05.000Z",
      lifecycle_head_hash: "e".repeat(64),
      previous_transition_hash: transition.transition_hash,
      previous_transition_receipt_hash: receipt.receipt_hash,
      last_checkpoint_index: 2,
      last_checkpoint_hash: checkpoint2.checkpoint_hash,
      last_checkpoint_receipt_hash: checkpointReceipt2.receipt_hash,
      previous_anchor_event_index: checkpointReceipt2.event_index,
      previous_anchor_event_hash: checkpointReceipt2.receipt_hash
    });
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", replay, Date.parse("2030-01-01T00:00:06.000Z")), /replayed/i);
  }

  {
    const value = nativeRecoveryFixture();
    const replacement = nativeKeyPair();
    const stale = nativeRecoveryTransition(value, replacement);
    const checkpoint2 = nativeCheckpointV1(value.audit.privateKey, value.audit.authorizedKey, {
      entries: 2, previous: value.checkpoint.checkpoint_hash, headByte: "b", createdAt: "2030-01-01T00:00:01.500Z"
    });
    submitAnchorCheckpoint(value.anchor, "recovery-host", checkpoint2, Date.parse("2030-01-01T00:00:01.750Z"));
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", stale, Date.parse("2030-01-01T00:00:03.000Z")), /current checkpoint receipt.event state|submit all/i);
  }

  {
    const value = nativeRecoveryFixture();
    const replacement = nativeKeyPair();
    const expired = nativeRecoveryTransition(value, replacement, { expires_at: "2030-01-01T00:00:02.500Z" });
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", expired, Date.parse("2030-01-01T00:00:03.000Z")), /expired/i);
    const overlong = nativeRecoveryTransition(value, replacement, { expires_at: "2030-01-01T00:20:02.000Z" });
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", overlong, Date.parse("2030-01-01T00:00:03.000Z")), /authorization statement/i);
    const duplicate = nativeRecoveryTransition(value, replacement, { signerKeys: [value.recoveryKeys[0], value.recoveryKeys[0]] });
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", duplicate, Date.parse("2030-01-01T00:00:03.000Z")), /unique policy signers|canonical order/i);
  }
});

test("v3 recovery trust is enrollment-pinned and exact request bindings cannot be substituted", () => {
  const attacks = [
    ["tenant", { tenant: "another-tenant" }, /statement|tenant/i],
    ["installation", { installation_id: "installation-attacker" }, /authorization statement/i],
    ["role", { role: "service" }, /authorization statement/i],
    ["generation", { from_generation: 2, to_generation: 3 }, /statement/i],
    ["old fingerprint", { old_key_fingerprint: "f".repeat(64) }, /statement/i],
    ["lifecycle head", { lifecycle_head_hash: "not-a-hash" }, /statement/i],
    ["checkpoint receipt", { last_checkpoint_receipt_hash: "e".repeat(64) }, /current checkpoint|boundary/i],
    ["event boundary", { previous_anchor_event_hash: "e".repeat(64) }, /current checkpoint|boundary/i]
  ];
  for (const [label, overrides, expected] of attacks) {
    const value = nativeRecoveryFixture();
    const transition = nativeRecoveryTransition(value, nativeKeyPair(), overrides);
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", transition, Date.parse("2030-01-01T00:00:03.000Z")), expected, label);
  }

  {
    const value = nativeRecoveryFixture();
    const attackerKeys = [recoveryKey("attacker-a"), recoveryKey("attacker-b")];
    const attackerPolicy = createAnchorRecoveryPolicy({ policy_id: "attacker-policy", threshold: 2, keys: attackerKeys.map((item) => ({ id: item.id, public_key: item.publicPem })) });
    const substituted = nativeRecoveryTransition(value, nativeKeyPair(), {
      recovery_policy_id: attackerPolicy.policy_id,
      recovery_policy_hash: attackerPolicy.policy_hash,
      evidencePolicy: attackerPolicy,
      signerKeys: attackerKeys
    });
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", substituted, Date.parse("2030-01-01T00:00:03.000Z")), /authorization statement/i);
  }

  {
    const value = nativeRecoveryFixture();
    const impostors = [recoveryKey("operator-a"), recoveryKey("operator-b")];
    const substitutedKeys = nativeRecoveryTransition(value, nativeKeyPair(), { signerKeys: impostors });
    assert.throws(() => submitAnchorKeyTransition(value.anchor, "recovery-host", substitutedKeys, Date.parse("2030-01-01T00:00:03.000Z")), /signature|signer/i);
  }
});

test("HTTP key-transitions endpoint accepts v3 and restart history remains verifiable", async (t) => {
  const value = nativeRecoveryFixture();
  const transition = nativeRecoveryTransition(value, nativeKeyPair());
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  const endpoint = `http://127.0.0.1:${server.address().port}/v1/key-transitions/recovery-host`;
  const originalNow = Date.now;
  Date.now = () => Date.parse("2030-01-01T00:00:03.000Z");
  let accepted;
  try {
    accepted = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ transition }) });
  } finally {
    Date.now = originalNow;
  }
  assert.equal(accepted.status, 200);
  assert.equal((await accepted.json()).receipt.transition_hash, transition.transition_hash);
  await new Promise((resolve) => server.close(resolve));

  const restarted = createAnchorServer(value.anchor);
  startInMemoryHttpServer(restarted);
  t.after(() => new Promise((resolve) => restarted.close(resolve)));
  const latest = await fetch(`http://127.0.0.1:${restarted.address().port}/v1/key-transitions/recovery-host/latest`);
  assert.equal(latest.status, 200);
  assert.equal((await latest.json()).transition.transition_hash, transition.transition_hash);
  assert.equal(verifyAnchorTenant(value.anchor, "recovery-host").records, 1);
});

test("audit prune endpoint signs the exact v1 receipt, replays safely, and survives restart", async (t) => {
  const value = nativePruneFixture();
  const authorization = nativePruneAuthorization(value);
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  const endpoint = `http://127.0.0.1:${server.address().port}/v1/audit-prunes/prune-host`;
  const base = `http://127.0.0.1:${server.address().port}`;
  const originalNow = Date.now;
  Date.now = () => Date.parse("2029-02-01T00:00:04.000Z");
  const receipts = [];
  try {
    for (let index = 0; index < 8; index += 1) {
      const nonce = Buffer.alloc(32, 0x20 + index).toString("base64url");
      const lease = await acquireHTTPPruneLease(base, value, nonce, "submit", authorization.operation_id, Date.now());
      const response = await fetch(endpoint, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ authorization, lease })
      });
      if (response.status !== 200) assert.fail(`prune submit failed: ${response.status} ${await response.text()}`);
      receipts.push((await response.json()).receipt);
    }
  } finally { Date.now = originalNow; }
  const receipt = receipts[0];
  assert.ok(receipts.every((candidate) => candidate.receipt_hash === receipt.receipt_hash));
  assert.equal(fs.readFileSync(path.join(value.anchor, "tenants", "prune-host", "audit-prunes.jsonl"), "utf8").trim().split("\n").length, 1);
  assert.equal(receipt.anchor_event_index, value.secondReceipt.event_index + 1);
  assert.equal(receipt.previous_anchor_event_hash, value.secondReceipt.receipt_hash);
  assert.equal(verifyAnchorPruneReceipt(receipt, fs.readFileSync(value.initialized.public_file), {
    tenant: "prune-host", sequence: 1, authorizationHash: authorization.authorization_hash,
    previousReceiptHash: "0".repeat(64), anchorEventIndex: 3, previousAnchorEventHash: value.secondReceipt.receipt_hash
  }).receipt_hash, receipt.receipt_hash);
  await new Promise((resolve) => server.close(resolve));
  const restarted = createAnchorServer(value.anchor);
  startInMemoryHttpServer(restarted);
  t.after(() => new Promise((resolve) => restarted.close(resolve)));
  assert.equal(verifyAnchorTenant(value.anchor, "prune-host").records, 2);
  const replacement = nativeKeyPair();
  const transitionAfterPrune = nativeTransition(value.audit.privateKey, value.audit.authorizedKey, replacement, {
    tenant: "prune-host", operationId: "rotation-after-prune", fromGeneration: 1, lifecycleHead: "e".repeat(64),
    createdAt: "2029-02-01T00:00:04.500Z", checkpointIndex: 2, checkpoint: value.second, checkpointReceipt: value.secondReceipt,
    previousEventIndex: receipt.anchor_event_index, previousEventHash: receipt.receipt_hash
  });
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "prune-host", transitionAfterPrune, Date.parse("2029-02-01T00:00:04.750Z")), /checkpoint immediately before/i);
  const third = nativeCheckpointV2(value.audit.privateKey, value.audit.authorizedKey, { entries: 3, previous: value.second.checkpoint_hash, headByte: "c", generation: 1, lifecycleHead: value.lifecycleHead });
  const thirdReceipt = submitAnchorCheckpoint(value.anchor, "prune-host", third, Date.parse("2029-02-01T00:00:05.000Z"));
  assert.equal(thirdReceipt.event_index, receipt.anchor_event_index + 1);
  assert.equal(thirdReceipt.previous_event_hash, receipt.receipt_hash, "checkpoint events must continue from the prune receipt");
  assert.equal(verifyAnchorTenant(value.anchor, "prune-host").records, 3);
});

test("audit prune head is canonical, read-only, exact, and survives restart", async (t) => {
  const value = nativePruneFixture();
  const verifyHead = (head, nonce, configured, receipt = null) => {
    assert.deepEqual(Object.keys(head).sort(), ["anchor_key_fingerprint", "configured", "issued_at", "receipt", "receipt_hash", "request_nonce", "sequence", "signature", "tenant", "version"]);
    assert.equal(head.version, 2); assert.equal(head.tenant, "prune-host"); assert.equal(head.configured, configured);
    assert.equal(head.request_nonce, nonce); assert.deepEqual(head.receipt, receipt);
    assert.equal(head.sequence, receipt?.sequence ?? 0); assert.equal(head.receipt_hash, receipt?.receipt_hash ?? "0".repeat(64));
    assert.equal(head.anchor_key_fingerprint, publicKeyFingerprint(crypto.createPublicKey(fs.readFileSync(value.initialized.public_file))));
    const { anchor_key_fingerprint: ignoredFingerprint, signature, ...statement } = head;
    assert.equal(Buffer.from(signature, "base64").toString("base64"), signature);
    assert.equal(crypto.verify(null, Buffer.from(canonicalJson(statement)), fs.readFileSync(value.initialized.public_file), Buffer.from(signature, "base64")), true);
    assert.equal(new Date(head.issued_at).toISOString(), head.issued_at);
  };
  const empty = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, PRUNE_HEAD_NOW);
  verifyHead(empty, PRUNE_HEAD_NONCE, true);
  assert.equal(fs.existsSync(path.join(value.anchor, "tenants", "prune-host", "audit-prunes.jsonl")), false);
  assert.equal(fs.existsSync(path.join(value.anchor, "tenants", "prune-host", "audit-prunes.tip.json")), false);

  const authorization = nativePruneAuthorization(value);
  const receipt = submitPruneWithLease(value, authorization, Date.parse("2029-02-01T00:00:04.000Z"));
  const expected = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, PRUNE_HEAD_NOW);
  verifyHead(expected, PRUNE_HEAD_NONCE, true, receipt);
  const { receipt_hash: ignoredReceiptHash, ...receiptWithoutHash } = receipt;
  assert.equal(crypto.createHash("sha256").update(canonicalJson(receiptWithoutHash)).digest("hex"), receipt.receipt_hash);
  assert.equal(verifyAnchorPruneReceipt(expected.receipt, fs.readFileSync(value.initialized.public_file), {
    tenant: "prune-host", sequence: expected.sequence, authorizationHash: authorization.authorization_hash,
    previousReceiptHash: "0".repeat(64), anchorEventIndex: receipt.anchor_event_index,
    previousAnchorEventHash: receipt.previous_anchor_event_hash
  }).receipt_hash, expected.receipt_hash);

  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  const endpoint = pruneHeadURL(`http://127.0.0.1:${server.address().port}`, "prune-host", PRUNE_HEAD_NONCE);
  const response = await fetch(endpoint);
  assert.equal(response.status, 200);
  const responseText = await response.text();
  assert.equal(responseText, canonicalJson(JSON.parse(responseText)));
  const httpHead = JSON.parse(responseText);
  verifyHead(httpHead, PRUNE_HEAD_NONCE, true, receipt);
  await new Promise((resolve) => server.close(resolve));

  const restarted = createAnchorServer(value.anchor);
  startInMemoryHttpServer(restarted);
  t.after(() => new Promise((resolve) => restarted.close(resolve)));
  const restartedResponse = await fetch(pruneHeadURL(`http://127.0.0.1:${restarted.address().port}`, "prune-host", PRUNE_HEAD_NONCE_2));
  assert.equal(restartedResponse.status, 200);
  const restartedHead = JSON.parse(await restartedResponse.text());
  verifyHead(restartedHead, PRUNE_HEAD_NONCE_2, true, receipt);
  assert.notEqual(restartedHead.request_nonce, expected.request_nonce);
  assert.notEqual(restartedHead.signature, expected.signature);

  const cli = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-head", value.anchor, "prune-host", PRUNE_HEAD_NONCE], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  const cliHead = JSON.parse(cli.stdout);
  verifyHead(cliHead, PRUNE_HEAD_NONCE, true, receipt);
  const cliRequestPath = path.join(value.anchor, "cli-prune-lease-request.json");
  const cliRequest = pruneLeaseRequest(value, PRUNE_HEAD_NONCE_2, "execute", authorization.operation_id, cliHead, Date.now());
  fs.writeFileSync(cliRequestPath, canonicalJson(cliRequest), { mode: 0o600 });
  const cliAcquire = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-lease-acquire", value.anchor, "prune-host", cliRequestPath], { encoding: "utf8" });
  assert.equal(cliAcquire.status, 0, cliAcquire.stderr); const cliLease = JSON.parse(cliAcquire.stdout);
  const cliLeasePath = path.join(value.anchor, "cli-prune-lease.json"); fs.writeFileSync(cliLeasePath, canonicalJson(cliLease), { mode: 0o600 });
  const cliReleasePath = path.join(value.anchor, "cli-prune-release-request.json");
  fs.writeFileSync(cliReleasePath, canonicalJson(pruneLeaseReleaseRequest(value, Buffer.alloc(32, 0x66).toString("base64url"), cliLease, Date.now())), { mode: 0o600 });
  const cliRelease = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-lease-release", value.anchor, "prune-host", cliLeasePath, cliReleasePath], { encoding: "utf8" });
  assert.equal(cliRelease.status, 0, cliRelease.stderr); assert.equal(JSON.parse(cliRelease.stdout).released, true);
});

test("audit prune head distinguishes empty and unknown tenants without path confusion", async (t) => {
  const value = nativePruneFixture();
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  const empty = await fetch(pruneHeadURL(base, "prune-host", PRUNE_HEAD_NONCE));
  assert.equal(empty.status, 200);
  const emptyValue = await empty.json();
  assert.equal(emptyValue.request_nonce, PRUNE_HEAD_NONCE); assert.equal(emptyValue.signature.length > 0, true);
  const unknown = await fetch(pruneHeadURL(base, "not-enrolled", PRUNE_HEAD_NONCE));
  assert.equal(unknown.status, 404);
  const unknownValue = await unknown.json();
  assert.deepEqual(unknownValue, { configured: false, error: "not_configured", version: 1 });
  const missingNonce = await fetch(`${base}/v1/audit-prunes/prune-host/head`);
  assert.equal(missingNonce.status, 400);
  const duplicateNonce = await fetch(`${base}/v1/audit-prunes/prune-host/head?nonce=${PRUNE_HEAD_NONCE}&nonce=${PRUNE_HEAD_NONCE_2}`);
  assert.equal(duplicateNonce.status, 400);
  const traversal = await fetch(`${base}/v1/audit-prunes/%2e%2e%2fprune-host/head?nonce=${PRUNE_HEAD_NONCE}`);
  assert.equal(traversal.status, 404);
  assert.throws(() => readAnchorPruneHead(value.anchor, "../prune-host", PRUNE_HEAD_NONCE), /tenant slug/i);
  assert.throws(() => readAnchorPruneHead(value.anchor, "prune-host", "short"), /nonce/i);

  const cli = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-head", value.anchor, "not-enrolled", PRUNE_HEAD_NONCE], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout).configured, false);
});

test("audit prune lease fences writers, CAS-consumes submit, rejects replay, and expires", () => {
  const value = nativePruneFixture();
  const authorization = nativePruneAuthorization(value);
  const now = Date.parse("2029-02-01T00:00:04.000Z");
  let monotonic = 1_000_000_000n;
  const runtime = createAnchorPruneLeaseRuntime({ epoch: PRUNE_HEAD_NONCE, monotonicNow: () => monotonic });
  const head = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, now);
  const request = pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "submit", authorization.operation_id, head, now);
  const submitLease = acquireAnchorPruneLease(value.anchor, "prune-host", request, now, runtime);
  assert.throws(() => submitAnchorPrune(value.anchor, "prune-host", authorization, now), /lease.*active|different.*lease/i);
  assert.throws(() => submitAnchorPrune(value.anchor, "prune-host", authorization, now, { ...submitLease, operation_id: "substituted" }), /different.*lease|binding/i);
  const receipt = submitAnchorPrune(value.anchor, "prune-host", authorization, now, submitLease, runtime);
  assert.equal(receipt.sequence, 1);
  assert.throws(() => submitAnchorPrune(value.anchor, "prune-host", authorization, now, submitLease, runtime), /expired|replayed|active/i);

  const nextHead = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE_2, now + 1);
  const executeRequest = pruneLeaseRequest(value, PRUNE_HEAD_NONCE_2, "execute", authorization.operation_id, nextHead, now + 1);
  const executeLease = acquireAnchorPruneLease(value.anchor, "prune-host", executeRequest, now + 1, runtime);
  assert.doesNotThrow(() => readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, now + 2), "GET head must not create or contend on a persistent lease");
  const releaseRequest = pruneLeaseReleaseRequest(value, Buffer.alloc(32, 0x55).toString("base64url"), executeLease, now + 2);
  assert.throws(() => releaseAnchorPruneLease(value.anchor, "prune-host", { ...executeLease, purpose: "submit" }, releaseRequest, now + 2, runtime), /substituted/i);
  assert.deepEqual(releaseAnchorPruneLease(value.anchor, "prune-host", executeLease, releaseRequest, now + 2, runtime), { released: true, lease_id: executeLease.lease_id });
  assert.throws(() => releaseAnchorPruneLease(value.anchor, "prune-host", executeLease, releaseRequest, now + 3, runtime), /expired|replayed/i);

  const expiryRequest = pruneLeaseRequest(value, Buffer.alloc(32, 0x56).toString("base64url"), "execute", authorization.operation_id, nextHead, now + 4);
  const expiring = acquireAnchorPruneLease(value.anchor, "prune-host", expiryRequest, now + 4, runtime);
  monotonic += 30_000_000_000n;
  const recoveredRequest = pruneLeaseRequest(value, Buffer.alloc(32, 0x57).toString("base64url"), "execute", authorization.operation_id, nextHead, now - 86_400_000);
  const recovered = acquireAnchorPruneLease(value.anchor, "prune-host", recoveredRequest, now - 86_400_000, runtime);
  assert.notEqual(recovered.lease_id, expiring.lease_id, "wall-clock rollback must not extend an expired monotonic lease");
});

test("audit prune lease authentication rejects unauthenticated, wrong-principal, stale-head, and replay requests", () => {
  const value = nativePruneFixture();
  const now = Date.parse("2029-02-01T00:00:04.000Z");
  const head = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, now);
  const valid = pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "execute", "operation-1", head, now);
  assert.throws(() => acquireAnchorPruneLease(value.anchor, "prune-host", { ...valid, signature: undefined }, now), /exact keys|authentication|required/i);
  const other = nativeKeyPair();
  const wrongStatement = { ...valid, audit_key_fingerprint: nativeAuditPublicKeyFingerprint(other.authorizedKey) };
  delete wrongStatement.signature;
  const wrong = { ...wrongStatement, signature: signP256LowS(other.privateKey, wrongStatement) };
  assert.throws(() => acquireAnchorPruneLease(value.anchor, "prune-host", wrong, now), /authentication|fingerprint/i);
  const staleStatement = { ...valid, expected_sequence: 1, expected_receipt_hash: "a".repeat(64) };
  delete staleStatement.signature;
  const stale = { ...staleStatement, signature: signP256LowS(value.audit.privateKey, staleStatement) };
  assert.throws(() => acquireAnchorPruneLease(value.anchor, "prune-host", stale, now), /head|authentication/i);
  const runtime = createAnchorPruneLeaseRuntime({ epoch: PRUNE_HEAD_NONCE });
  const lease = acquireAnchorPruneLease(value.anchor, "prune-host", valid, now, runtime);
  const authorization = nativePruneAuthorization(value);
  const foreignStatement = { ...authorization, signer_fingerprint: nativeAuditPublicKeyFingerprint(other.authorizedKey) };
  delete foreignStatement.signature; delete foreignStatement.authorization_hash;
  const foreignSigned = { ...foreignStatement, signature: signP256LowS(other.privateKey, foreignStatement) };
  foreignSigned.authorization_hash = crypto.createHash("sha256").update(canonicalJson(foreignSigned)).digest("hex");
  assert.throws(() => submitAnchorPrune(value.anchor, "prune-host", foreignSigned, now, lease, runtime), /principal|binding/i);
  const wrongRelease = pruneLeaseReleaseRequest({ ...value, audit: other }, Buffer.alloc(32, 0x59).toString("base64url"), lease, now + 1);
  assert.throws(() => releaseAnchorPruneLease(value.anchor, "prune-host", lease, wrongRelease, now + 1, runtime), /principal|signature/i);
  assert.throws(() => releaseAnchorPruneLease(value.anchor, "not-enrolled", lease, wrongRelease, now + 1, runtime), /directory|tenant/i);
  const release = pruneLeaseReleaseRequest(value, PRUNE_HEAD_NONCE_2, lease, now + 1);
  releaseAnchorPruneLease(value.anchor, "prune-host", lease, release, now + 1, runtime);
  assert.throws(() => acquireAnchorPruneLease(value.anchor, "prune-host", valid, now + 2, runtime), /nonce.*replay/i);
  assert.throws(() => releaseAnchorPruneLease(value.anchor, "prune-host", lease, release, now + 2, runtime), /expired|replayed/i);
});

test("audit prune lease HTTP requires canonical authenticated acquisition and GET never creates a writer fence", async (t) => {
  const value = nativePruneFixture();
  const authorization = nativePruneAuthorization(value);
  const fixedNow = Date.parse("2029-02-01T00:00:04.000Z");
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const originalNow = Date.now; Date.now = () => fixedNow;
  try {
    for (let index = 0; index < 3; index += 1) assert.equal((await fetch(pruneHeadURL(base, "prune-host", Buffer.alloc(32, 0x70 + index).toString("base64url")))).status, 200);
    assert.equal(fs.existsSync(path.join(value.anchor, "tenants", "prune-host", ".audit-prune-lease.json")), false);
    const leaseEndpoint = `${base}/v1/audit-prunes/prune-host/leases`;
    for (let index = 0; index < 3; index += 1) {
      const rejected = await fetch(leaseEndpoint, { method: "POST", headers: { "content-type": "application/json" }, body: canonicalJson({ request: { version: 1, nonce: Buffer.alloc(32, index).toString("base64url") } }) });
      assert.equal(rejected.status, 400);
    }
    assert.equal(fs.existsSync(path.join(value.anchor, "tenants", "prune-host", ".audit-prune-lease.json")), false, "unauthenticated attempts must not allocate lease state");
    const head = await (await fetch(pruneHeadURL(base, "prune-host", PRUNE_HEAD_NONCE))).json();
    const request = pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "submit", authorization.operation_id, head, fixedNow);
    const noncanonical = await fetch(leaseEndpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }, null, 2) });
    assert.equal(noncanonical.status, 400);
    const accepted = await fetch(leaseEndpoint, { method: "POST", headers: { "content-type": "application/json" }, body: canonicalJson({ request }) });
    assert.equal(accepted.status, 200); const lease = await accepted.json();
    assert.equal((await fetch(pruneHeadURL(base, "prune-host", PRUNE_HEAD_NONCE_2))).status, 200, "GET remains available and cannot extend or replace the exclusive lease");
    const submitted = await fetch(`${base}/v1/audit-prunes/prune-host`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ authorization, lease }) });
    assert.equal(submitted.status, 200, await submitted.text());
    const burst = await Promise.all(Array.from({ length: 80 }, (_, index) => fetch(pruneHeadURL(base, "prune-host", crypto.createHash("sha256").update(`rate-${index}`).digest().toString("base64url")))));
    assert.ok(burst.some((response) => response.status === 429), "the bounded per-client/tenant bucket must shed an abusive GET burst");
    assert.ok(burst.every((response) => response.status === 200 || response.status === 429));
  } finally { Date.now = originalNow; }
});

test("audit prune lease restart epoch waits a full monotonic TTL despite wall-clock jumps", () => {
  const value = nativePruneFixture();
  const wall = Date.parse("2029-02-01T00:00:04.000Z");
  const head = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, wall);
  let firstClock = 100n;
  const firstRuntime = createAnchorPruneLeaseRuntime({ epoch: PRUNE_HEAD_NONCE, monotonicNow: () => firstClock });
  const lease = acquireAnchorPruneLease(value.anchor, "prune-host", pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "execute", "operation-epoch", head, wall), wall, firstRuntime);
  assert.equal(lease.process_epoch, PRUNE_HEAD_NONCE);
  let restartedClock = 1_000n;
  const restarted = createAnchorPruneLeaseRuntime({ epoch: PRUNE_HEAD_NONCE_2, monotonicNow: () => restartedClock });
  const replacementNonce = Buffer.alloc(32, 0x61).toString("base64url");
  const replacement = pruneLeaseRequest(value, replacementNonce, "execute", "operation-epoch", head, wall + 86_400_000);
  assert.throws(() => acquireAnchorPruneLease(value.anchor, "prune-host", replacement, wall + 86_400_000, restarted), /lease.*active/i, "wall-clock advance must not expire a foreign-epoch lease early");
  restartedClock += 29_999_999_999n;
  assert.throws(() => acquireAnchorPruneLease(value.anchor, "prune-host", replacement, wall + 86_400_000, restarted), /lease.*active/i);
  restartedClock += 1n;
  const replacementLease = acquireAnchorPruneLease(value.anchor, "prune-host", replacement, wall + 86_400_000, restarted);
  assert.notEqual(replacementLease.lease_id, lease.lease_id);
});

test("audit prune head fails closed on rollback, corruption, unsafe paths, and a concurrent writer", async (t) => {
  {
    const value = nativePruneFixture();
    submitPruneWithLease(value, nativePruneAuthorization(value), Date.parse("2029-02-01T00:00:04.000Z"));
    fs.truncateSync(path.join(value.anchor, "tenants", "prune-host", "audit-prunes.jsonl"), 0);
    assert.throws(() => readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE), /tip|rollback|truncation/i);
  }
  {
    const value = nativePruneFixture();
    submitPruneWithLease(value, nativePruneAuthorization(value), Date.parse("2029-02-01T00:00:04.000Z"));
    const log = path.join(value.anchor, "tenants", "prune-host", "audit-prunes.jsonl");
    fs.appendFileSync(log, "not-json\n");
    assert.throws(() => readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE), /JSON|invalid|framing/i);
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const lock = path.join(tenantDir, ".update.lock");
    const authorization = nativePruneAuthorization(value);
    const server = createAnchorServer(value.anchor);
    startInMemoryHttpServer(server);
    const base = `http://127.0.0.1:${server.address().port}`;
    const initialHead = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, Date.parse("2029-02-01T00:00:04.000Z"));
    const signedLeaseRequest = pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "submit", authorization.operation_id, initialHead, Date.parse("2029-02-01T00:00:04.000Z"));
    const writerScript = `
      import fs from "node:fs";
      const [lock, moduleFile, anchor, encodedAuthorization, encodedRequest] = process.argv.slice(1);
      fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, nonce: "writer-race", created_at: Date.now() }), { flag: "wx", mode: 0o600 });
      process.stdout.write("locked\\n");
      await new Promise((resolve) => setTimeout(resolve, 300));
      fs.unlinkSync(lock);
      const { acquireAnchorPruneLease, submitAnchorPrune } = await import(moduleFile);
      const now = Date.parse("2029-02-01T00:00:04.000Z");
      const authorization = JSON.parse(Buffer.from(encodedAuthorization, "base64").toString("utf8"));
      const request = JSON.parse(Buffer.from(encodedRequest, "base64").toString("utf8"));
      const lease = acquireAnchorPruneLease(anchor, "prune-host", request, now);
      submitAnchorPrune(anchor, "prune-host", authorization, now, lease);
    `;
    const writer = spawn(process.execPath, ["--input-type=module", "-e", writerScript, lock, new URL("../lib/anchor.mjs", import.meta.url).href, value.anchor, Buffer.from(canonicalJson(authorization)).toString("base64"), Buffer.from(canonicalJson(signedLeaseRequest)).toString("base64")], { stdio: ["ignore", "pipe", "pipe"] });
    const writerResultPromise = new Promise((resolve) => {
      let stderr = "";
      writer.stderr.on("data", (chunk) => { stderr += chunk; });
      writer.once("close", (code) => resolve({ code, stderr }));
    });
    await new Promise((resolve, reject) => {
      writer.stdout.once("data", (chunk) => chunk.toString().includes("locked") ? resolve() : reject(new Error("Writer did not acquire the tenant lease")));
      writer.once("error", reject);
      writer.once("exit", (code) => { if (code !== null) reject(new Error(`Writer exited before the read race: ${code}`)); });
    });
    const responses = await Promise.all(Array.from({ length: 32 }, (_, index) => fetch(pruneHeadURL(base, "prune-host", Buffer.alloc(32, 0x80 + index).toString("base64url")))));
    assert.ok(responses.every((response) => response.status === 200), "parallel read-only GETs must not acquire or wait for the writer lock");
    const headBeforeWriter = await responses[0].json();
    assert.equal(headBeforeWriter.sequence, 0);
    const writerResult = await writerResultPromise;
    assert.equal(writerResult.code, 0, writerResult.stderr);
    await new Promise((resolve) => server.close(resolve));
    const staleLeaseRequest = pruneLeaseRequest(value, PRUNE_HEAD_NONCE_2, "execute", authorization.operation_id, headBeforeWriter, Date.parse("2029-02-01T00:00:04.000Z"));
    assert.throws(
      () => acquireAnchorPruneLease(value.anchor, "prune-host", staleLeaseRequest, Date.parse("2029-02-01T00:00:04.000Z")),
      /head|authentication/i,
      "the mutating lease POST must CAS-reject a head observed before the concurrent writer"
    );
    const afterWriter = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE);
    assert.equal(afterWriter.sequence, 1, "the first successful read after the writer must observe its monotonic receipt");
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const moved = path.join(value.anchor, "tenant-moved");
    fs.renameSync(tenantDir, moved);
    fs.symlinkSync(moved, tenantDir);
    assert.throws(() => readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE), /directory.*unsafe|permissions/i);
  }
});

test("HTTP prune head uses only the fixed snapshot while startup repairs absence and rejects rollback or unsafe snapshots", async (t) => {
  {
    const value = nativePruneFixture();
    const server = createAnchorServer(value.anchor);
    startInMemoryHttpServer(server);
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const records = path.join(value.anchor, "tenants", "prune-host", "records.jsonl");
    const hidden = `${records}.offline`;
    fs.renameSync(records, hidden);
    const response = await fetch(pruneHeadURL(`http://127.0.0.1:${server.address().port}`, "prune-host", PRUNE_HEAD_NONCE));
    assert.equal(response.status, 200, "HTTP GET must not synchronously scan checkpoint history");
    assert.equal((await response.json()).sequence, 0);
    fs.renameSync(hidden, records);
  }
  {
    const value = nativePruneFixture();
    const snapshot = path.join(value.anchor, "tenants", "prune-host", ".audit-prune-head.snapshot.json");
    fs.unlinkSync(snapshot);
    createAnchorServer(value.anchor);
    assert.equal(fs.existsSync(snapshot), true, "startup full verification repairs an absent invalidated snapshot");
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const snapshot = path.join(tenantDir, ".audit-prune-head.snapshot.json");
    const old = fs.readFileSync(snapshot);
    const third = nativeCheckpointV2(value.audit.privateKey, value.audit.authorizedKey, { entries: 3, previous: value.second.checkpoint_hash, headByte: "c", generation: 1, lifecycleHead: value.lifecycleHead });
    submitAnchorCheckpoint(value.anchor, "prune-host", third, Date.parse("2029-01-01T00:00:03.000Z"));
    fs.writeFileSync(snapshot, old, { mode: 0o600 });
    assert.throws(() => createAnchorServer(value.anchor), /snapshot.*(rollback|match|history)/i);
  }
  for (const attack of ["symlink", "hardlink", "mode"]) {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const snapshot = path.join(tenantDir, ".audit-prune-head.snapshot.json");
    if (attack === "mode") fs.chmodSync(snapshot, 0o644);
    else {
      const target = path.join(tenantDir, `${attack}-snapshot-target`);
      fs.renameSync(snapshot, target);
      if (attack === "symlink") fs.symlinkSync(target, snapshot);
      else fs.linkSync(target, snapshot);
    }
    assert.throws(() => createAnchorServer(value.anchor), /snapshot.*unsafe|permissions/i);
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const remnant = path.join(tenantDir, ".audit-prune-head.snapshot.json.crash.tmp");
    fs.writeFileSync(remnant, "partial", { mode: 0o600 });
    createAnchorServer(value.anchor);
    assert.equal(fs.existsSync(remnant), false);
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const target = path.join(tenantDir, "unsafe-temp-target");
    const remnant = path.join(tenantDir, ".audit-prune-lease-nonces.tip.json.crash.tmp");
    fs.writeFileSync(target, "do-not-delete", { mode: 0o600 });
    fs.symlinkSync(target, remnant);
    assert.throws(() => createAnchorServer(value.anchor), /temporary.*unsafe|permissions/i);
    assert.equal(fs.readFileSync(target, "utf8"), "do-not-delete");
  }
});

test("running server monotonic floor rejects replay, coherent nonce rollback, equivocation, and storage replacement while accepting an external CLI advance", async (t) => {
  const value = nativePruneFixture();
  const tenantDir = path.join(value.anchor, "tenants", "prune-host");
  const snapshotFile = path.join(tenantDir, ".audit-prune-head.snapshot.json");
  const initialSnapshot = fs.readFileSync(snapshotFile);
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  const now = Date.now();
  const head = await (await fetch(pruneHeadURL(base, "prune-host", PRUNE_HEAD_NONCE))).json();
  const requestFile = path.join(value.anchor, "external-floor-request.json");
  fs.writeFileSync(requestFile, canonicalJson(pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "execute", "external-floor-advance", head, now)), { mode: 0o600 });
  const acquired = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-lease-acquire", value.anchor, "prune-host", requestFile], { encoding: "utf8" });
  assert.equal(acquired.status, 0, acquired.stderr);
  const lease = JSON.parse(acquired.stdout);
  const advanced = await fetch(pruneHeadURL(base, "prune-host", PRUNE_HEAD_NONCE_2));
  assert.equal(advanced.status, 200, await advanced.text());
  const advancedSnapshot = fs.readFileSync(snapshotFile);

  const releaseFile = path.join(value.anchor, "external-floor-lease.json");
  const releaseRequestFile = path.join(value.anchor, "external-floor-release.json");
  fs.writeFileSync(releaseFile, canonicalJson(lease), { mode: 0o600 });
  fs.writeFileSync(releaseRequestFile, canonicalJson(pruneLeaseReleaseRequest(value, crypto.randomBytes(32).toString("base64url"), lease, Date.now())), { mode: 0o600 });
  const released = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-lease-release", value.anchor, "prune-host", releaseFile, releaseRequestFile], { encoding: "utf8" });
  assert.equal(released.status, 0, released.stderr);

  fs.writeFileSync(snapshotFile, initialSnapshot, { mode: 0o600 });
  const replay = await fetch(pruneHeadURL(base, "prune-host", crypto.randomBytes(32).toString("base64url")));
  assert.equal(replay.status, 400); assert.match((await replay.json()).error, /floor|regressed/i);

  fs.writeFileSync(snapshotFile, advancedSnapshot, { mode: 0o600 });
  const current = JSON.parse(advancedSnapshot);
  const { anchor_key_fingerprint: ignoredFingerprint, signature: ignoredSignature, snapshot_hash: ignoredHash, ...statement } = current;
  statement.event_hash = "f".repeat(64);
  const anchorPrivateKey = crypto.createPrivateKey(fs.readFileSync(path.join(value.anchor, "anchor-private.pem")));
  const signature = crypto.sign(null, Buffer.from(canonicalJson(statement)), anchorPrivateKey).toString("base64");
  const signed = { ...statement, anchor_key_fingerprint: current.anchor_key_fingerprint, signature };
  const equivocated = { ...signed, snapshot_hash: crypto.createHash("sha256").update(canonicalJson(signed)).digest("hex") };
  fs.writeFileSync(snapshotFile, canonicalJson(equivocated), { mode: 0o600 });
  const equivocation = await fetch(pruneHeadURL(base, "prune-host", crypto.randomBytes(32).toString("base64url")));
  assert.equal(equivocation.status, 400); assert.match((await equivocation.json()).error, /equivocat/i);

  fs.writeFileSync(snapshotFile, initialSnapshot, { mode: 0o600 });
  fs.unlinkSync(path.join(tenantDir, ".audit-prune-lease-nonces.jsonl"));
  fs.unlinkSync(path.join(tenantDir, ".audit-prune-lease-nonces.tip.json"));
  const coherentRollback = await fetch(pruneHeadURL(base, "prune-host", crypto.randomBytes(32).toString("base64url")));
  assert.equal(coherentRollback.status, 400); assert.match((await coherentRollback.json()).error, /floor|regressed/i);

  fs.writeFileSync(snapshotFile, advancedSnapshot, { mode: 0o600 });
  const moved = `${value.anchor}-moved`;
  fs.renameSync(value.anchor, moved);
  fs.cpSync(moved, value.anchor, { recursive: true, mode: fs.constants.COPYFILE_FICLONE });
  const replacement = await fetch(pruneHeadURL(base, "prune-host", crypto.randomBytes(32).toString("base64url")));
  assert.equal(replacement.status, 400); assert.match((await replacement.json()).error, /volume|identity|changed|permissions/i);
});

test("strict-ahead snapshot is rejected when its durable nonce history was rolled back before floor verification", async (t) => {
  const value = nativePruneFixture();
  const tenantDir = path.join(value.anchor, "tenants", "prune-host");
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const now = Date.now();
  const head = await (await fetch(pruneHeadURL(base, "prune-host", PRUNE_HEAD_NONCE))).json();
  const requestFile = path.join(value.anchor, "historical-ahead-request.json");
  fs.writeFileSync(requestFile, canonicalJson(pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "execute", "historical-ahead", head, now)), { mode: 0o600 });
  const acquired = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-lease-acquire", value.anchor, "prune-host", requestFile], { encoding: "utf8" });
  assert.equal(acquired.status, 0, acquired.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(tenantDir, ".audit-prune-head.snapshot.json"), "utf8")).nonce_ledger_count, 1);
  fs.unlinkSync(path.join(tenantDir, ".audit-prune-lease-nonces.jsonl"));
  fs.unlinkSync(path.join(tenantDir, ".audit-prune-lease-nonces.tip.json"));
  const rejected = await fetch(pruneHeadURL(base, "prune-host", PRUNE_HEAD_NONCE_2));
  assert.equal(rejected.status, 400);
  assert.match((await rejected.json()).error, /durable history|tips|match/i);
});

test("unknown prune-head tenants consume the global IP bucket without loading or using the anchor private key", async (t) => {
  const value = nativePruneFixture();
  const server = createAnchorServer(value.anchor);
  assert.equal(server.maxConnections, 128); assert.equal(server.maxRequestsPerSocket, 100);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const originalReadFileSync = fs.readFileSync;
  const originalSign = crypto.sign;
  let privateKeyReads = 0;
  let signatures = 0;
  fs.readFileSync = function(target, ...args) {
    if (String(target).endsWith("anchor-private.pem")) privateKeyReads += 1;
    return originalReadFileSync.call(fs, target, ...args);
  };
  crypto.sign = function(...args) { signatures += 1; return originalSign.apply(crypto, args); };
  const statuses = [];
  const bodies = new Set();
  try {
    for (let batch = 0; batch < 157; batch += 1) {
      const count = Math.min(32, 5_000 - statuses.length);
      const responses = await Promise.all(Array.from({ length: count }, (_, index) => {
        const tenant = `unknown-${batch}-${index}`;
        return fetch(pruneHeadURL(base, tenant, crypto.createHash("sha256").update(tenant).digest().toString("base64url")));
      }));
      for (const response of responses) {
        statuses.push(response.status);
        if (response.status === 404) bodies.add(await response.text());
        else await response.arrayBuffer();
      }
    }
  } finally {
    fs.readFileSync = originalReadFileSync;
    crypto.sign = originalSign;
  }
  assert.equal(statuses.length, 5_000);
  assert.ok(statuses.includes(429));
  assert.ok(statuses.filter((status) => status === 404).length <= 256, "different unknown tenant names must not evade the IP-global bucket");
  assert.ok(statuses.every((status) => status === 404 || status === 429));
  assert.deepEqual([...bodies], [canonicalJson({ configured: false, error: "not_configured", version: 1 })]);
  assert.equal(privateKeyReads, 0); assert.equal(signatures, 0);
});

test("prune lease nonce ledger repairs one-record crashes and rejects rollback, torn writes, and path links", () => {
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const tip = path.join(tenantDir, ".audit-prune-lease-nonces.tip.json");
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x91).toString("base64url"), "nonce-repair-1", Date.parse("2029-02-01T00:00:04.000Z"));
    const firstTip = fs.readFileSync(tip);
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x92).toString("base64url"), "nonce-repair-2", Date.parse("2029-02-01T00:00:06.000Z"));
    fs.writeFileSync(tip, firstTip, { mode: 0o600 });
    fs.unlinkSync(path.join(tenantDir, ".audit-prune-head.snapshot.json"));
    createAnchorServer(value.anchor);
    assert.equal(JSON.parse(fs.readFileSync(tip, "utf8")).records, 2, "startup repairs exactly one append persisted before its signed tip");
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const tip = path.join(tenantDir, ".audit-prune-lease-nonces.tip.json");
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x93).toString("base64url"), "nonce-rollback-1", Date.parse("2029-02-01T00:00:04.000Z"));
    const firstTip = fs.readFileSync(tip);
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x94).toString("base64url"), "nonce-rollback-2", Date.parse("2029-02-01T00:00:06.000Z"));
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x95).toString("base64url"), "nonce-rollback-3", Date.parse("2029-02-01T00:00:08.000Z"));
    fs.writeFileSync(tip, firstTip, { mode: 0o600 });
    assert.throws(() => createAnchorServer(value.anchor), /nonce.*rollback|ledger\/tip/i);
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x96).toString("base64url"), "nonce-torn", Date.parse("2029-02-01T00:00:04.000Z"));
    fs.appendFileSync(path.join(tenantDir, ".audit-prune-lease-nonces.jsonl"), "{torn");
    assert.throws(() => createAnchorServer(value.anchor), /framing|JSON|nonce.*invalid/i);
  }
  {
    const value = nativePruneFixture();
    const log = path.join(value.anchor, "tenants", "prune-host", ".audit-prune-lease-nonces.jsonl");
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x99).toString("base64url"), "nonce-noncanonical", Date.parse("2029-02-01T00:00:04.000Z"));
    const canonicalRecord = fs.readFileSync(log, "utf8");
    fs.writeFileSync(log, canonicalRecord.replace("{", "{ "), { mode: 0o600 });
    assert.throws(() => createAnchorServer(value.anchor), /noncanonical/i);
  }
  for (const fileName of [".audit-prune-lease-nonces.jsonl", ".audit-prune-lease-nonces.tip.json"]) {
    for (const attack of ["symlink", "hardlink"]) {
      const value = nativePruneFixture();
      const tenantDir = path.join(value.anchor, "tenants", "prune-host");
      recordPruneLeaseNonce(value, crypto.randomBytes(32).toString("base64url"), `nonce-${fileName}-${attack}`, Date.parse("2029-02-01T00:00:04.000Z"));
      const file = path.join(tenantDir, fileName);
      const target = path.join(tenantDir, `${attack}-${path.basename(fileName)}-target`);
      fs.renameSync(file, target);
      if (attack === "symlink") fs.symlinkSync(target, file);
      else fs.linkSync(target, file);
      assert.throws(() => createAnchorServer(value.anchor), /unsafe|permissions|path/i);
    }
  }
  {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const log = path.join(tenantDir, ".audit-prune-lease-nonces.jsonl");
    const displaced = path.join(tenantDir, "displaced-prune-nonces.jsonl");
    recordPruneLeaseNonce(value, Buffer.alloc(32, 0x97).toString("base64url"), "nonce-swap-1", Date.parse("2029-02-01T00:00:04.000Z"));
    const originalWriteFileSync = fs.writeFileSync;
    let swapped = false;
    fs.writeFileSync = function(target, data, options) {
      if (!swapped && typeof target === "number") {
        const targetStat = fs.fstatSync(target);
        const logStat = fs.statSync(log);
        if (targetStat.dev === logStat.dev && targetStat.ino === logStat.ino) {
          fs.renameSync(log, displaced);
          originalWriteFileSync.call(fs, log, "", { flag: "wx", mode: 0o600 });
          swapped = true;
        }
      }
      return originalWriteFileSync.call(fs, target, data, options);
    };
    try {
      assert.throws(() => recordPruneLeaseNonce(value, Buffer.alloc(32, 0x98).toString("base64url"), "nonce-swap-2", Date.parse("2029-02-01T00:00:06.000Z")), /path changed while open/i);
    } finally { fs.writeFileSync = originalWriteFileSync; }
    assert.equal(swapped, true);
    assert.equal(fs.readFileSync(log, "utf8"), "", "the substituted path must not receive nonce data");
    assert.throws(() => createAnchorServer(value.anchor), /tip|rollback|ledger/i);
  }
});

test("audit prune rejects a high-S authorization equivalent before anchoring", () => {
  const value = nativePruneFixture();
  const authorization = nativePruneAuthorization(value);
  const highS = withPruneSignature(authorization, malleateP256SignatureToHighS(authorization.signature));
  assert.notEqual(highS.authorization_hash, authorization.authorization_hash);
  assert.throws(() => submitPruneWithLease(value, highS, Date.parse("2029-02-01T00:00:04.000Z")), /authorization.*invalid/i);
  assert.equal(submitPruneWithLease(value, authorization, Date.parse("2029-02-01T00:00:04.000Z")).sequence, 1, "the rejected equivalent must not consume the prune boundary");
});

test("audit prune CLI is equivalent and tenant/path confusion fails before storage access", async (t) => {
  const value = nativePruneFixture();
  const authorization = nativePruneAuthorization(value);
  const receipt = submitPruneWithLease(value, authorization, Date.parse("2029-02-01T00:00:04.000Z"));
  const input = path.join(value.anchor, "prune-authorization.json");
  fs.writeFileSync(input, canonicalJson(authorization), { mode: 0o600 });
  const cliNow = Date.now();
  const cliHead = readAnchorPruneHead(value.anchor, "prune-host", PRUNE_HEAD_NONCE, cliNow);
  const requestFile = path.join(value.anchor, "prune-submit-request.json");
  fs.writeFileSync(requestFile, canonicalJson(pruneLeaseRequest(value, PRUNE_HEAD_NONCE, "submit", authorization.operation_id, cliHead, cliNow)), { mode: 0o600 });
  const acquired = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune-lease-acquire", value.anchor, "prune-host", requestFile], { encoding: "utf8" });
  assert.equal(acquired.status, 0, acquired.stderr);
  const leaseFile = path.join(value.anchor, "prune-submit-lease.json");
  fs.writeFileSync(leaseFile, canonicalJson(JSON.parse(acquired.stdout)), { mode: 0o600 });
  const legacyBypass = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune", value.anchor, "prune-host", input], { encoding: "utf8" });
  assert.equal(legacyBypass.status, 1); assert.match(legacyBypass.stderr, /FILE LEASE/i);
  const cli = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune", value.anchor, "prune-host", input, leaseFile], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout).receipt_hash, receipt.receipt_hash);
  fs.writeFileSync(input, `${canonicalJson(authorization)}\n`, { mode: 0o600 });
  const noncanonical = spawnSync(process.execPath, [path.resolve("bin/agentpass-anchor.mjs"), "prune", value.anchor, "prune-host", input, leaseFile], { encoding: "utf8" });
  assert.equal(noncanonical.status, 1);
  assert.match(noncanonical.stderr, /exact canonical JSON without trailing bytes/i);
  assert.throws(() => submitAnchorPrune(value.anchor, "../prune-host", authorization), /tenant slug/i);

  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const traversal = await fetch(`${base}/v1/audit-prunes/%2e%2e%2fprune-host`, { method: "POST", body: "{}" });
  assert.equal(traversal.status, 404);
  const unknown = await fetch(`${base}/v1/audit-prunes/prune-host`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ authorization, tenant: "prune-host" })
  });
  assert.equal(unknown.status, 400);
  assert.match((await unknown.json()).error, /request.*encoding/i);
});

test("audit prune rejects forgery, stale and pending boundaries, signer substitution, retention failures, and segment gaps", () => {
  {
    const value = nativePruneFixture();
    const authorization = nativePruneAuthorization(value);
    assert.throws(() => submitPruneWithLease(value, { ...authorization, retention_seconds: authorization.retention_seconds + 1 }, Date.parse("2029-02-01T00:00:04.000Z")), /signature|hash|authorization.*invalid/i);
  }
  {
    const value = nativePruneFixture();
    const third = nativeCheckpointV2(value.audit.privateKey, value.audit.authorizedKey, { entries: 3, previous: value.second.checkpoint_hash, headByte: "c", generation: 1, lifecycleHead: value.lifecycleHead });
    submitAnchorCheckpoint(value.anchor, "prune-host", third, Date.parse("2029-01-01T00:00:03.000Z"));
    assert.throws(() => submitPruneWithLease(value, nativePruneAuthorization(value), Date.parse("2029-02-01T00:00:04.000Z")), /boundary|stale|pending/i);
  }
  {
    const value = nativePruneFixture();
    const replacement = nativeKeyPair();
    const substituted = nativePruneAuthorization(value, { signer_fingerprint: nativeAuditPublicKeyFingerprint(replacement.authorizedKey) });
    assert.throws(() => submitPruneWithLease(value, substituted, Date.parse("2029-02-01T00:00:04.000Z")), /principal|active P-256|signer/i);
    const tooYoung = nativePruneAuthorization(value, { requested_at: "2029-01-15T00:00:03.000Z" });
    assert.throws(() => submitPruneWithLease(value, tooYoung, Date.parse("2029-01-15T00:00:04.000Z")), /age|retention/i);
    const gap = nativePruneAuthorization(value, { segment: { first_event_index: 2 } });
    assert.throws(() => submitPruneWithLease(value, gap, Date.parse("2029-02-01T00:00:04.000Z")), /gap|overlap/i);
    const base = nativePruneAuthorization(value);
    const overlappingSegment = {
      ...base.segments[0], segment_id: "segment-0002", audit_archive_file: "audit-0002.jsonl",
      checkpoint_archive_file: "checkpoints-0002.jsonl", receipt_archive_file: "receipts-0002.jsonl",
      first_event_index: 2, first_checkpoint_index: 2, first_receipt_index: 2
    };
    const overlap = nativePruneAuthorization(value, { segments: [base.segments[0], overlappingSegment] });
    assert.throws(() => submitPruneWithLease(value, overlap, Date.parse("2029-02-01T00:00:04.000Z")), /gap|overlap/i);
  }
  {
    const value = nativePruneFixture();
    const first = nativePruneAuthorization(value, { retention_seconds: 60 * 24 * 60 * 60, requested_at: "2029-03-05T00:00:03.000Z" });
    const receipt = submitPruneWithLease(value, first, Date.parse("2029-03-05T00:00:04.000Z"));
    const downgrade = nativePruneAuthorization(value, {
      operation_id: "prune-operation-0002", sequence: 2, previous_authorization_hash: first.authorization_hash,
      previous_prune_receipt_hash: receipt.receipt_hash, previous_manifest_hash: "4".repeat(64), retention_seconds: 30 * 24 * 60 * 60,
      requested_at: "2029-03-06T00:00:03.000Z"
    });
    assert.throws(() => submitPruneWithLease(value, downgrade, Date.parse("2029-03-06T00:00:04.000Z")), /retention|chain/i);
  }
});

test("audit prune detects equivocation, corruption, truncation, live locks, symlinks, and hard links", () => {
  {
    const value = nativePruneFixture();
    const authorization = nativePruneAuthorization(value);
    submitPruneWithLease(value, authorization, Date.parse("2029-02-01T00:00:04.000Z"));
    const conflicting = nativePruneAuthorization(value, { previous_manifest_hash: "9".repeat(64) });
    assert.throws(() => submitPruneWithLease(value, conflicting, Date.parse("2029-02-01T00:00:05.000Z")), /equivocation/i);
    const log = path.join(value.anchor, "tenants", "prune-host", "audit-prunes.jsonl");
    fs.truncateSync(log, 0);
    assert.throws(() => verifyAnchorTenant(value.anchor, "prune-host"), /tip|rollback|truncation/i);
  }
  {
    const value = nativePruneFixture();
    const lock = path.join(value.anchor, "tenants", "prune-host", ".update.lock");
    fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, nonce: "live", created_at: Date.now() }), { mode: 0o600 });
    assert.throws(() => submitPruneWithLease(value, nativePruneAuthorization(value), Date.parse("2029-02-01T00:00:04.000Z")), /Another anchor process/i);
  }
  for (const attack of ["symlink", "hardlink"]) {
    const value = nativePruneFixture();
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const log = path.join(tenantDir, "audit-prunes.jsonl");
    const target = path.join(tenantDir, `${attack}-target`);
    fs.writeFileSync(target, "", { mode: 0o600 });
    if (attack === "symlink") fs.symlinkSync(target, log);
    else fs.linkSync(target, log);
    assert.throws(() => submitPruneWithLease(value, nativePruneAuthorization(value), Date.parse("2029-02-01T00:00:04.000Z")), /unsafe|symbolic|permissions/i);
  }
  for (const attack of ["symlink", "hardlink"]) {
    const value = nativePruneFixture();
    submitPruneWithLease(value, nativePruneAuthorization(value), Date.parse("2029-02-01T00:00:04.000Z"));
    const tenantDir = path.join(value.anchor, "tenants", "prune-host");
    const tip = path.join(tenantDir, "audit-prunes.tip.json");
    const target = path.join(tenantDir, `${attack}-tip-target`);
    fs.renameSync(tip, target);
    if (attack === "symlink") fs.symlinkSync(target, tip);
    else fs.linkSync(target, tip);
    assert.throws(() => verifyAnchorTenant(value.anchor, "prune-host"), /tip.*unsafe|permissions/i);
  }
});

test("restart verification rejects recovery policy and stored evidence substitution", () => {
  {
    const value = nativeRecoveryFixture();
    submitAnchorKeyTransition(value.anchor, "recovery-host", nativeRecoveryTransition(value, nativeKeyPair()), Date.parse("2030-01-01T00:00:03.000Z"));
    const configFile = path.join(value.anchor, "tenants", "recovery-host", "config.json");
    const config = JSON.parse(fs.readFileSync(configFile, "utf8"));
    config.recovery_policy.keys[0].public_key = recoveryKey("substituted").publicPem;
    fs.writeFileSync(configFile, `${JSON.stringify(config)}\n`, { mode: 0o600 });
    assert.throws(() => verifyAnchorTenant(value.anchor, "recovery-host"), /fingerprint|policy hash|canonical/i);
  }

  {
    const value = nativeRecoveryFixture();
    submitAnchorKeyTransition(value.anchor, "recovery-host", nativeRecoveryTransition(value, nativeKeyPair()), Date.parse("2030-01-01T00:00:03.000Z"));
    const transitionsFile = path.join(value.anchor, "tenants", "recovery-host", "key-transitions.jsonl");
    const record = JSON.parse(fs.readFileSync(transitionsFile, "utf8"));
    record.transition.recovery_evidence.approvals[0].key_id = "operator-c";
    fs.writeFileSync(transitionsFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    assert.throws(() => verifyAnchorTenant(value.anchor, "recovery-host"), /canonical order|signature|hash/i);
  }
});

test("transition rejects a stale checkpoint boundary and an unanchored retiring-key checkpoint", () => {
  const value = nativeFixture();
  submitAnchorCheckpoint(value.anchor, "native-host", value.first, Date.parse("2029-01-01T00:00:00Z"));
  const secondReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.second, Date.parse("2029-01-01T00:01:00Z"));
  const replacement = nativeKeyPair();
  const transition = nativeTransition(value.privateKey, value.auditPublicKey, replacement, {
    operationId: "rotation-stale-boundary",
    fromGeneration: 1,
    lifecycleHead: "c".repeat(64),
    createdAt: "2030-01-01T00:00:00.000Z",
    checkpointIndex: 2,
    checkpoint: value.second,
    checkpointReceipt: secondReceipt,
    previousEventIndex: secondReceipt.event_index,
    previousEventHash: secondReceipt.receipt_hash
  });
  const declaredPending = nativeTransition(value.privateKey, value.auditPublicKey, replacement, {
    operationId: "rotation-declares-pending",
    fromGeneration: 1,
    lifecycleHead: "c".repeat(64),
    createdAt: "2030-01-01T00:00:00.000Z",
    checkpointIndex: 2,
    checkpoint: value.second,
    checkpointReceipt: secondReceipt,
    previousEventIndex: secondReceipt.event_index,
    previousEventHash: secondReceipt.receipt_hash,
    pendingCheckpointCount: 1
  });
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", declaredPending), /statement.*invalid/i);
  const third = nativeCheckpointV1(value.privateKey, value.auditPublicKey, { entries: 3, previous: value.second.checkpoint_hash, headByte: "c", createdAt: "2029-01-01T00:02:00.000Z" });
  const thirdReceipt = submitAnchorCheckpoint(value.anchor, "native-host", third, Date.parse("2029-01-01T00:02:30Z"));
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", transition), /current checkpoint receipt.event state|submit all/i);

  const fresh = nativeTransition(value.privateKey, value.auditPublicKey, replacement, {
    operationId: "rotation-current-boundary",
    fromGeneration: 1,
    lifecycleHead: "c".repeat(64),
    createdAt: "2030-01-01T00:00:01.000Z",
    checkpointIndex: 3,
    checkpoint: third,
    checkpointReceipt: thirdReceipt,
    previousEventIndex: thirdReceipt.event_index,
    previousEventHash: thirdReceipt.receipt_hash
  });
  submitAnchorKeyTransition(value.anchor, "native-host", fresh, Date.parse("2030-01-01T00:00:02Z"));
  const unanchored = nativeCheckpointV1(value.privateKey, value.auditPublicKey, { entries: 4, previous: third.checkpoint_hash, headByte: "d", createdAt: "2029-01-01T00:03:00.000Z" });
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "native-host", unanchored), /active audit key|public.key/i);
});

test("transition created_at is strictly monotonic across generations", () => {
  const value = nativeFixture();
  const firstReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.first, Date.parse("2029-01-01T00:00:00Z"));
  const generation2 = nativeKeyPair();
  const lifecycle2 = "b".repeat(64);
  const firstTransition = nativeTransition(value.privateKey, value.auditPublicKey, generation2, {
    operationId: "rotation-time-1", fromGeneration: 1, lifecycleHead: lifecycle2, createdAt: "2030-01-01T00:00:00.000Z",
    checkpointIndex: 1, checkpoint: value.first, checkpointReceipt: firstReceipt, previousEventIndex: firstReceipt.event_index, previousEventHash: firstReceipt.receipt_hash
  });
  const transitionReceipt = submitAnchorKeyTransition(value.anchor, "native-host", firstTransition, Date.parse("2030-01-01T00:00:01Z"));
  const checkpoint2 = nativeCheckpointV2(generation2.privateKey, generation2.authorizedKey, { entries: 2, previous: value.first.checkpoint_hash, headByte: "c", generation: 2, lifecycleHead: lifecycle2 });
  const checkpoint2Receipt = submitAnchorCheckpoint(value.anchor, "native-host", checkpoint2, Date.parse("2030-01-01T00:00:02Z"));
  const generation3 = nativeKeyPair();
  const rollback = nativeTransition(generation2.privateKey, generation2.authorizedKey, generation3, {
    operationId: "rotation-time-2", fromGeneration: 2, lifecycleHead: "d".repeat(64), createdAt: firstTransition.created_at,
    previousTransitionHash: firstTransition.transition_hash, previousTransitionReceiptHash: transitionReceipt.receipt_hash,
    checkpointIndex: 2, checkpoint: checkpoint2, checkpointReceipt: checkpoint2Receipt, previousEventIndex: checkpoint2Receipt.event_index, previousEventHash: checkpoint2Receipt.receipt_hash
  });
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", rollback), /statement.*invalid/i);
});

test("legacy high-S v1 transition history remains readable and migrates once into the v2 tenant event chain", () => {
  const value = nativeFixture();
  const checkpointReceipt = legacyAnchorReceipt(value.anchor, "native-host", "checkpoint", 1, value.first.checkpoint_hash, "0".repeat(64), "2029-01-01T00:00:00.000Z");
  fs.writeFileSync(path.join(value.anchor, "tenants", "native-host", "records.jsonl"), `${JSON.stringify({ checkpoint: value.first, receipt: checkpointReceipt })}\n`, { mode: 0o600 });
  const generation2 = nativeKeyPair();
  const lifecycle2 = "b".repeat(64);
  const canonicalLegacyTransition = nativeTransitionV1(value.privateKey, value.auditPublicKey, generation2, { operationId: "legacy-rotation", lifecycleHead: lifecycle2, createdAt: "2029-01-01T00:01:00.000Z" });
  const legacyTransition = withTransitionSignature(canonicalLegacyTransition, "new_signature", malleateP256SignatureToHighS(canonicalLegacyTransition.new_signature));
  const legacyTransitionReceipt = legacyAnchorReceipt(value.anchor, "native-host", "transition", 1, legacyTransition.transition_hash, "0".repeat(64), "2029-01-01T00:01:01.000Z");
  fs.writeFileSync(path.join(value.anchor, "tenants", "native-host", "key-transitions.jsonl"), `${JSON.stringify({ transition: legacyTransition, receipt: legacyTransitionReceipt })}\n`, { mode: 0o600 });
  assert.equal(verifyAnchorTenant(value.anchor, "native-host").records, 1, "stored v1 history remains readable");
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "native-host", { ...legacyTransition, operation_id: "new-v1" }), /encoding|version 2/i);

  const checkpoint2 = nativeCheckpointV2(generation2.privateKey, generation2.authorizedKey, { entries: 2, previous: value.first.checkpoint_hash, headByte: "c", generation: 2, lifecycleHead: lifecycle2 });
  const receipt2 = submitAnchorCheckpoint(value.anchor, "native-host", checkpoint2, Date.parse("2030-01-01T00:00:00Z"));
  assert.equal(receipt2.version, 2);
  assert.equal(receipt2.event_index, 3, "the two legacy receipts become a deterministic migration prefix");
  const generation3 = nativeKeyPair();
  const transition2 = nativeTransition(generation2.privateKey, generation2.authorizedKey, generation3, {
    operationId: "v2-after-migration", fromGeneration: 2, lifecycleHead: "d".repeat(64), createdAt: "2031-01-01T00:00:00.000Z",
    previousTransitionHash: legacyTransition.transition_hash, previousTransitionReceiptHash: legacyTransitionReceipt.receipt_hash,
    checkpointIndex: 2, checkpoint: checkpoint2, checkpointReceipt: receipt2, previousEventIndex: receipt2.event_index, previousEventHash: receipt2.receipt_hash
  });
  assert.equal(submitAnchorKeyTransition(value.anchor, "native-host", transition2, Date.parse("2031-01-01T00:00:01Z")).event_index, 4);
});

test("HTTP anchor accepts native checkpoints and rejects algorithm confusion", async (t) => {
  const value = nativeFixture();
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const endpoint = `http://127.0.0.1:${server.address().port}/v1/checkpoints/native-host`;
  const accepted = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ checkpoint: value.first }) });
  assert.equal(accepted.status, 200);

  const ed25519 = fixture();
  const confused = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ checkpoint: ed25519.first }) });
  assert.equal(confused.status, 400);
  assert.match((await confused.json()).error, /Native audit checkpoint|P-256 signature|public.key/i);
});

test("anchor rejects forged, rolled-back, and locally corrupted records", () => {
  const value = fixture();
  const forged = { ...value.first, entries: value.first.entries + 1 };
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", forged), /signature|hash/i);

  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.second), /chain origin/i);
  submitAnchorCheckpoint(value.anchor, "host-one", value.first);
  submitAnchorCheckpoint(value.anchor, "host-one", value.second);
  const rollbackStatement = {
    version: 1,
    created_at: new Date().toISOString(),
    entries: value.first.entries,
    head_hash: value.first.head_hash,
    previous_checkpoint_hash: value.second.checkpoint_hash
  };
  const signature = crypto.sign(null, Buffer.from(JSON.stringify(rollbackStatement)), fs.readFileSync(path.join(value.host, "audit", "checkpoint.pem"))).toString("base64");
  const rollback = { ...rollbackStatement, public_key_fingerprint: publicKeyFingerprint(value.identity.public_key), signature };
  rollback.checkpoint_hash = crypto.createHash("sha256").update(JSON.stringify(rollback)).digest("hex");
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", rollback), /rollback/i);

  const recordsFile = path.join(value.anchor, "tenants", "host-one", "records.jsonl");
  const records = fs.readFileSync(recordsFile, "utf8").trim().split("\n").map(JSON.parse);
  records[0].receipt.signature = `${records[0].receipt.signature.slice(0, -2)}AA`;
  fs.writeFileSync(recordsFile, `${records.map(JSON.stringify).join("\n")}\n`, { mode: 0o600 });
  assert.throws(() => verifyAnchorTenant(value.anchor, "host-one"), /signature|hash/i);
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.second), /signature|hash/i);
});

test("client pushes checkpoints in order, verifies receipts, and retries safely", async (t) => {
  const value = fixture();
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  const config = {
    audit_signing: { public_key: value.identity.public_key },
    audit_anchor: {
      url: `http://127.0.0.1:${address.port}`,
      tenant: "host-one",
      public_key: fs.readFileSync(value.initialized.public_file, "utf8")
    }
  };

  await assert.rejects(anchorPendingCheckpoints(config, value.host), /requires HTTPS/);
  const pushed = await anchorPendingCheckpoints(config, value.host, { allowHttp: true });
  assert.equal(pushed.anchored, 2);
  assert.equal(verifyStoredAnchorReceipts(config, value.host).receipts, 2);

  audit({ operation: "test.three", decision: "allow" }, value.host);
  const third = createAuditCheckpoint(value.identity.public_key, value.host);
  const accepted = await fetch(`${config.audit_anchor.url}/v1/checkpoints/host-one`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ checkpoint: third })
  });
  assert.equal(accepted.status, 200);
  assert.equal(readAnchorReceipts(value.host).length, 2, "simulates losing the response before local persistence");
  const retried = await anchorPendingCheckpoints(config, value.host, { allowHttp: true });
  assert.equal(retried.anchored, 1);
  assert.equal(verifyAnchorTenant(value.anchor, "host-one").records, 3);
});

test("stored receipt tampering fails closed", async (t) => {
  const value = fixture();
  const server = createAnchorServer(value.anchor);
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = {
    audit_signing: { public_key: value.identity.public_key },
    audit_anchor: {
      url: `http://127.0.0.1:${server.address().port}`,
      tenant: "host-one",
      public_key: fs.readFileSync(value.initialized.public_file, "utf8")
    }
  };
  await anchorPendingCheckpoints(config, value.host, { allowHttp: true });
  const receiptFile = path.join(value.host, "anchor.receipts.jsonl");
  const receipts = readAnchorReceipts(value.host);
  receipts[0].checkpoint_hash = "f".repeat(64);
  fs.writeFileSync(receiptFile, `${receipts.map(JSON.stringify).join("\n")}\n`, { mode: 0o600 });
  assert.throws(() => verifyStoredAnchorReceipts(config, value.host), /checkpoint mismatch|signature|hash/i);
  await assert.rejects(anchorPendingCheckpoints(config, value.host, { allowHttp: true }), /checkpoint mismatch|signature|hash/i);
});

test("anchor private/public key substitution is rejected", () => {
  const first = fixture();
  const second = fixture();
  fs.copyFileSync(second.initialized.public_file, first.initialized.public_file);
  assert.throws(() => createAnchorServer(first.anchor), /do not match/);
});

test("tenant append locking rejects a live writer and recovers a dead lease", () => {
  const value = fixture();
  const lockFile = path.join(value.anchor, "tenants", "host-one", ".update.lock");
  fs.writeFileSync(lockFile, JSON.stringify({ pid: process.pid, nonce: "active", created_at: Date.now() }), { mode: 0o600 });
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.first), /Another anchor process/);
  assert.throws(() => submitAnchorKeyTransition(value.anchor, "host-one", {}), /Another anchor process/, "checkpoint and transition submissions share one tenant lock");
  fs.writeFileSync(lockFile, JSON.stringify({ pid: 2_147_483_647, nonce: "dead", created_at: 0 }), { mode: 0o600 });
  assert.equal(submitAnchorCheckpoint(value.anchor, "host-one", value.first).index, 1);
  assert.equal(fs.existsSync(lockFile), false);
});

test("anchor refuses to follow a symlink used as a tenant record log", () => {
  const value = fixture();
  const recordsFile = path.join(value.anchor, "tenants", "host-one", "records.jsonl");
  const victimFile = path.join(value.anchor, "symlink-victim.jsonl");
  const victim = "must-not-be-overwritten\n";
  fs.writeFileSync(victimFile, victim, { mode: 0o600 });
  fs.symlinkSync(victimFile, recordsFile);

  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.first), /unsafe|symbolic|too many levels/i);
  assert.equal(fs.readFileSync(victimFile, "utf8"), victim);
});

test("anchor refuses to append to a hard-linked tenant record log", () => {
  const value = fixture();
  const recordsFile = path.join(value.anchor, "tenants", "host-one", "records.jsonl");
  const aliasFile = path.join(value.anchor, "records-hardlink.jsonl");
  submitAnchorCheckpoint(value.anchor, "host-one", value.first);
  fs.linkSync(recordsFile, aliasFile);
  const before = fs.readFileSync(aliasFile, "utf8");

  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.second), /permissions are unsafe/i);
  assert.equal(fs.readFileSync(aliasFile, "utf8"), before);
});

test("anchor detects a pathname swap after FD validation without writing to the replacement", () => {
  const value = fixture();
  const recordsFile = path.join(value.anchor, "tenants", "host-one", "records.jsonl");
  const displacedFile = path.join(value.anchor, "displaced-records.jsonl");
  submitAnchorCheckpoint(value.anchor, "host-one", value.first);
  const originalWriteFileSync = fs.writeFileSync;
  let swapped = false;

  fs.writeFileSync = function(target, data, options) {
    if (!swapped && typeof target === "number") {
      const targetStat = fs.fstatSync(target);
      const recordsStat = fs.statSync(recordsFile);
      if (targetStat.dev === recordsStat.dev && targetStat.ino === recordsStat.ino) {
        fs.renameSync(recordsFile, displacedFile);
        originalWriteFileSync.call(fs, recordsFile, "", { flag: "wx", mode: 0o600 });
        swapped = true;
      }
    }
    return originalWriteFileSync.call(fs, target, data, options);
  };
  try {
    assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.second), /path changed while open/i);
  } finally {
    fs.writeFileSync = originalWriteFileSync;
  }

  assert.equal(swapped, true, "the test must exercise the post-validation swap window");
  assert.equal(fs.readFileSync(recordsFile, "utf8"), "", "the replacement pathname must not receive the append");
  assert.equal(fs.readFileSync(displacedFile, "utf8").trim().split("\n").length, 2, "the open inode received the append but no receipt was returned");
});

test("checkpoint list remains independently readable", () => {
  const value = fixture();
  assert.deepEqual(readAuditCheckpoints(value.host).map((item) => item.checkpoint_hash), [value.first.checkpoint_hash, value.second.checkpoint_hash]);
});
