import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import {
  canonicalJson,
  normalizeAgentDescriptor,
  normalizeAuditEvent,
  normalizeScope
} from "../../../packages/protocol/src/index.mjs";
import { auditCursorBinding, createAuditCursorCodec, normalizeAuditPageInput } from "./audit-pagination.mjs";
import { normalizeDeviceReadModel } from "./device-read-model.mjs";
import {
  POSSESSION_RECEIPT_PURPOSE,
  POSSESSION_RECEIPT_VERSION,
  normalizePossessionReceiptStatement
} from "./possession-receipt-signer.mjs";

const SCHEMA_VERSION = 1;
const ZERO_HASH = "0".repeat(64);
const MAX_BYTES = 16 * 1024;
const MAX_STATE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH = 64;
const MAX_AUDIT_EVENTS = 100_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const SENSITIVE_KEY = /(?:private(?:[_-]?key)?|bearer(?:[_-]?token)?|(?<!s)session(?:[_-]?token)?|access(?:[_-]?token)?|refresh(?:[_-]?token)?|secret|password|token)/i;
const RELEASE_CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/;
const TEAM_ID = /^[A-Z0-9]{10}$/;
const DEVICE_KEY_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;

export class CloudStoreError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "CloudStoreError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export class TenantScopeError extends CloudStoreError {
  constructor(message = "organization_id is required for tenant-scoped access") {
    super("ERR_TENANT_SCOPE", message);
    this.name = "TenantScopeError";
  }
}

export class VersionConflictError extends CloudStoreError {
  constructor(expected, actual) {
    super("ERR_VERSION_CONFLICT", `optimistic version check failed: expected ${expected}, actual ${actual}`, { expected, actual });
    this.name = "VersionConflictError";
  }
}

export function createCapabilityNonce(randomBytes = crypto.randomBytes) {
  const bytes = randomBytes(32);
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) throw new CloudStoreError("ERR_INVALID_INPUT", "capability nonce source must return 32 bytes");
  const encoded = bytes.toString("base64url");
  return /^[A-Za-z0-9]/.test(encoded) ? encoded : `A${encoded.slice(1)}`;
}

/**
 * Return the SHA-256 hash used by the device audit chain.
 *
 * The preimage is the canonical JSON encoding of the exact protocol-v1
 * redacted event, with only `event_hash` removed. `previous_hash` remains in
 * the preimage so the hash authenticates both the event fields and its chain
 * predecessor. This matches the object emitted by `redactAuditEvent` in the
 * local cloud-audit client.
 */
export function auditEventHashPreimage(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new CloudStoreError("ERR_INVALID_INPUT", "audit event must be an object");
  }
  const { event_hash: _eventHash, ...preimage } = event;
  return preimage;
}

export function computeAuditEventHash(event) {
  return crypto.createHash("sha256").update(canonicalJson(auditEventHashPreimage(event)), "utf8").digest("hex");
}

/**
 * Create a small, file-backed cloud control-plane store.
 *
 * The returned methods all take one object argument. Every method that reads
 * or writes a tenant resource requires organizationId. Mutations additionally
 * require idempotencyKey (or idempotency_key).
 */
export async function createCloudStore(options = {}) {
  const storage = await prepareStorage(options);
  const processLock = await acquireStoreLock(storage);
  const auditCursorCodec = options.auditCursorCodec ?? createAuditCursorCodec({ secret: options.auditCursorSecret ?? crypto.randomBytes(32) });
  let state;
  try { state = await loadState(storage); }
  catch (error) { await releaseStoreLock(processLock); throw error; }
  let closed = false;
  let mutationQueue = Promise.resolve();

  if (state === undefined) {
    state = emptyState();
    try { await persistState(storage, state); }
    catch (error) { await releaseStoreLock(processLock); throw error; }
  }

  const enqueue = (operation) => {
    if (closed) return Promise.reject(new CloudStoreError("ERR_STORE_CLOSED", "cloud store is closed"));
    const result = mutationQueue.then(operation, operation);
    mutationQueue = result.catch(() => undefined);
    return result;
  };

  const read = async (operation) => {
    if (closed) throw new CloudStoreError("ERR_STORE_CLOSED", "cloud store is closed");
    await mutationQueue;
    return operation();
  };

  const requireTenant = (input) => {
    const organizationId = input?.organizationId ?? input?.organization_id;
    assertUuid(organizationId, "organization_id");
    const organization = state.organizations[organizationId];
    if (!organization) throw notFound("organization", organizationId);
    return organizationId;
  };

  const mutate = ({ organizationId = "__global__", operation, idempotencyKey, input, action }) => enqueue(async () => {
    const key = requireIdempotencyKey(idempotencyKey);
    const idempotencyId = `${organizationId}\u0000${operation}\u0000${key}`;
    const fingerprint = digest(input);
    const previous = state.idempotency[idempotencyId];
    if (previous) {
      if (previous.fingerprint !== fingerprint) {
        throw new CloudStoreError("ERR_IDEMPOTENCY_CONFLICT", "idempotency key was already used for a different mutation");
      }
      return clone(previous.result);
    }
    const before = clone(state);
    try {
      const result = action();
      assertSafeValue(result, "result");
      state.idempotency[idempotencyId] = { fingerprint, result: clone(result) };
      await persistState(storage, state);
      return clone(result);
    } catch (error) {
      // A failed atomic write must not leave later queued mutations observing
      // changes that were never made durable.
      state = before;
      throw error;
    }
  });

  const tenantRecord = (collection, organizationId, id, label) => {
    const record = state[collection][id];
    if (!record || record.organization_id !== organizationId) throw notFound(label, id);
    return record;
  };

  const list = (collection, organizationId) => Object.values(state[collection])
    .filter((record) => record.organization_id === organizationId)
    .sort((a, b) => String(a.created_at ?? a.ingested_at ?? a.revoked_at ?? "").localeCompare(String(b.created_at ?? b.ingested_at ?? b.revoked_at ?? "")) || idOf(a).localeCompare(idOf(b)))
    .map(clone);

  const createOrganization = async (input = {}) => {
    assertSafeValue(input, "organization");
    const organizationId = input.organizationId ?? input.organization_id ?? input.id ?? crypto.randomUUID();
    assertUuid(organizationId, "organization_id");
    const name = boundedText(input.name, "name", 128, true);
    const slug = boundedText(input.slug ?? slugify(name), "slug", 128, true);
    const createdAt = timestamp(input.createdAt ?? input.created_at ?? now());
    return mutate({
      operation: "create_organization",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { ...(input.organizationId ?? input.organization_id ?? input.id ? { organization_id: organizationId } : {}), name, slug, ...(input.createdAt ?? input.created_at ? { created_at: createdAt } : {}) },
      action: () => {
        if (state.organizations[organizationId] || hasAnyResourceId(state, organizationId)) throw unique("organization_id", organizationId);
        if (Object.values(state.organizations).some((item) => item.slug === slug)) throw unique("slug", slug);
        const record = { organization_id: organizationId, name, slug, created_at: createdAt, version: 1 };
        state.organizations[organizationId] = record;
        return record;
      }
    });
  };

  const getOrganization = async (input) => read(() => clone(state.organizations[requireTenant(input)]));
  const listOrganizations = async (input) => {
    const organizationId = requireTenant(input);
    return read(() => [clone(state.organizations[organizationId])]);
  };

  const createMembership = async (input = {}) => {
    assertSafeValue(input, "membership");
    const organizationId = requireTenant(input);
    const principalId = boundedText(input.principalId ?? input.principal_id ?? input.userId ?? input.user_id, "principal_id", 256, true);
    const role = enumText(input.role ?? "viewer", "role", ["owner", "admin", "auditor", "viewer"]);
    const membershipId = input.membershipId ?? input.membership_id ?? input.id ?? crypto.randomUUID();
    assertUuid(membershipId, "membership_id");
    return mutate({
      organizationId,
      operation: "create_membership",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, ...(input.membershipId ?? input.membership_id ?? input.id ? { membership_id: membershipId } : {}), principal_id: principalId, role },
      action: () => {
        if (state.memberships[membershipId] || hasAnyResourceId(state, membershipId)) throw unique("membership_id", membershipId);
        if (Object.values(state.memberships).some((item) => item.organization_id === organizationId && item.principal_id === principalId)) throw unique("principal_id", principalId);
        const record = { membership_id: membershipId, organization_id: organizationId, principal_id: principalId, role, status: "active", created_at: now(), version: 1 };
        state.memberships[membershipId] = record;
        return record;
      }
    });
  };

  const createDevice = async (input = {}) => {
    assertSafeValue(input, "device");
    const organizationId = requireTenant(input);
    const deviceId = input.deviceId ?? input.device_id ?? input.id ?? crypto.randomUUID();
    assertUuid(deviceId, "device_id");
    const name = boundedText(input.name, "name", 128, true);
    const publicKey = boundedText(input.publicKey ?? input.public_key ?? input.devicePublicKey ?? input.device_public_key, "device_public_key", 8192, true, true);
    rejectPrivateKey(publicKey, "device_public_key");
    const metadata = input.metadata === undefined ? {} : safeMetadata(input.metadata, "metadata");
    return mutate({
      organizationId,
      operation: "create_device",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, ...(input.deviceId ?? input.device_id ?? input.id ? { device_id: deviceId } : {}), name, public_key: publicKey, metadata },
      action: () => {
        if (state.devices[deviceId] || hasAnyResourceId(state, deviceId)) throw unique("device_id", deviceId);
        if (Object.values(state.devices).some((item) => item.device_public_key === publicKey)) throw unique("device_public_key", publicKey);
        const record = { device_id: deviceId, organization_id: organizationId, name, device_public_key: publicKey, key_epoch: 1, status: "active", metadata, created_at: now(), version: 1 };
        state.devices[deviceId] = record;
        return record;
      }
    });
  };

  const createDeviceEnrollment = async (input = {}) => {
    if ((input.proofVersion ?? input.proof_version) === 2) return createDeviceEnrollmentV2(input);
    const organizationId = requireTenant(input);
    const enrollmentId = input.enrollmentId ?? input.enrollment_id ?? crypto.randomUUID();
    const deviceId = input.deviceId ?? input.device_id ?? crypto.randomUUID();
    assertUuid(enrollmentId, "enrollment_id");
    assertUuid(deviceId, "device_id");
    const label = boundedText(input.label ?? input.name, "label", 128, true);
    const platform = enumText(input.platform ?? "macos", "platform", ["macos"]);
    const credentialDigest = boundedText(input.credentialDigest ?? input.credential_digest, "credential_digest", 64, true);
    if (!SHA256.test(credentialDigest)) throw new CloudStoreError("ERR_INVALID_INPUT", "credential_digest must be SHA-256");
    const createdAt = timestamp(input.createdAt ?? input.created_at ?? now());
    const expiresAt = timestamp(input.expiresAt ?? input.expires_at);
    if (Date.parse(expiresAt) <= Date.parse(createdAt) || Date.parse(expiresAt) - Date.parse(createdAt) > 24 * 60 * 60 * 1000) throw new CloudStoreError("ERR_INVALID_INPUT", "enrollment expiry must be within 24 hours after creation");
    return mutate({
      organizationId,
      operation: "create_device_enrollment",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, enrollment_id: enrollmentId, device_id: deviceId, label, platform, credential_digest: credentialDigest, ttl_ms: Date.parse(expiresAt) - Date.parse(createdAt) },
      action: () => {
        if (state.device_enrollments[enrollmentId] || state.devices[deviceId] || hasAnyResourceId(state, enrollmentId) || hasAnyResourceId(state, deviceId)) throw unique("enrollment_or_device_id", enrollmentId);
        if (Object.values(state.device_enrollments).some((item) => item.credential_digest === credentialDigest)) throw unique("credential_digest", credentialDigest);
        state.devices[deviceId] = { device_id: deviceId, organization_id: organizationId, name: label, device_public_key: null, status: "pending", metadata: { platform }, created_at: createdAt, version: 1 };
        const record = { enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label, platform, credential_digest: credentialDigest, created_at: createdAt, expires_at: expiresAt, consumed_at: null, completion_hash: null };
        state.device_enrollments[enrollmentId] = record;
        return publicEnrollment(record);
      }
    });
  };

  const completeDeviceEnrollment = async (input = {}) => {
    if ((input.proofVersion ?? input.proof_version) === 2) return completeDeviceEnrollmentV2(input);
    return enqueue(async () => {
    const enrollmentId = input.enrollmentId ?? input.enrollment_id;
    assertUuid(enrollmentId, "enrollment_id");
    const record = state.device_enrollments[enrollmentId];
    const credentialDigest = boundedText(input.credentialDigest ?? input.credential_digest, "credential_digest", 64, true);
    const credentialMatches = SHA256.test(credentialDigest) && timingSafeHex(record?.credential_digest ?? "0".repeat(64), credentialDigest);
    if (!record || !credentialMatches) throw new CloudStoreError("ERR_ENROLLMENT_AUTH", "device enrollment authentication failed");
    const organizationId = input.organizationId ?? input.organization_id;
    const deviceId = input.deviceId ?? input.device_id;
    assertUuid(organizationId, "organization_id");
    assertUuid(deviceId, "device_id");
    const label = boundedText(input.label, "label", 128, true);
    const platform = enumText(input.platform, "platform", ["macos"]);
    const algorithm = enumText(input.algorithm, "algorithm", ["p256-sha256", "ed25519"]);
    const publicKey = boundedText(input.publicKey ?? input.public_key, "device_public_key", 8192, true, true);
    rejectPrivateKey(publicKey, "device_public_key");
    if (organizationId !== record.organization_id || deviceId !== record.device_id || label !== record.label || platform !== record.platform) throw new CloudStoreError("ERR_ENROLLMENT_BINDING", "device enrollment request does not match its reservation");
    const completionHash = digest({ version: 1, enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label, platform, algorithm, public_key: publicKey });
    if (record.consumed_at !== null) {
      if (record.completion_hash !== completionHash) throw new CloudStoreError("ERR_ENROLLMENT_CONSUMED", "device enrollment was already consumed");
      return clone(state.devices[deviceId]);
    }
    const completedAt = timestamp(input.completedAt ?? input.completed_at ?? now());
    if (Date.parse(completedAt) > Date.parse(record.expires_at)) throw new CloudStoreError("ERR_ENROLLMENT_EXPIRED", "device enrollment has expired");
    const device = state.devices[deviceId];
    if (!device || device.organization_id !== organizationId || device.status !== "pending" || device.device_public_key !== null) throw new CloudStoreError("ERR_ENROLLMENT_STATE", "pending device state is invalid");
    if (Object.values(state.devices).some((item) => item.device_id !== deviceId && item.device_public_key === publicKey)) throw unique("device_public_key", publicKey);
    const before = clone(state);
    try {
      device.device_public_key = publicKey;
      device.key_algorithm = algorithm;
      device.key_epoch = nextDeviceKeyEpoch(device.key_epoch);
      device.status = "active";
      device.version += 1;
      record.consumed_at = completedAt;
      record.completion_hash = completionHash;
      await persistState(storage, state);
      return clone(device);
    } catch (error) { state = before; throw error; }
    });
  };

  const registerReleaseCandidate = async (input = {}) => {
    assertSafeValue(input, "release_candidate");
    const candidateId = boundedPattern(input.candidateId ?? input.candidate_id, "candidate_id", RELEASE_CANDIDATE_ID);
    const sourceCommit = boundedPattern(input.sourceCommit ?? input.source_commit, "source_commit", SOURCE_COMMIT);
    const artifactSha256 = boundedPattern(input.artifactSha256 ?? input.artifact_sha256, "artifact_sha256", SHA256);
    const manifestSha256 = boundedPattern(input.manifestSha256 ?? input.manifest_sha256, "manifest_sha256", SHA256);
    const teamId = boundedPattern(input.teamId ?? input.team_id, "team_id", TEAM_ID);
    const createdAt = timestamp(input.createdAt ?? input.created_at ?? now());
    const request = { candidate_id: candidateId, source_commit: sourceCommit, artifact_sha256: artifactSha256, manifest_sha256: manifestSha256, team_id: teamId, created_at: createdAt };
    return mutate({
      organizationId: "__global__",
      operation: "register_release_candidate",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: request,
      action: () => {
        const existing = state.release_candidates[candidateId];
        if (existing) {
          if (canonicalJson(existing) === canonicalJson({ ...request, status: "active", retired_at: null })) return existing;
          throw unique("candidate_id", candidateId);
        }
        const record = { ...request, status: "active", retired_at: null };
        state.release_candidates[candidateId] = record;
        return record;
      }
    });
  };

  const getReleaseCandidate = async (input = {}) => read(() => {
    const candidateId = boundedPattern(input.candidateId ?? input.candidate_id, "candidate_id", RELEASE_CANDIDATE_ID);
    const record = state.release_candidates[candidateId];
    if (!record) throw notFound("release candidate", candidateId);
    return clone(record);
  });

  const createDeviceEnrollmentV2 = async (input = {}) => {
    const organizationId = requireTenant(input);
    if (input.proofVersion !== undefined || input.proof_version !== undefined) {
      if ((input.proofVersion ?? input.proof_version) !== 2) throw new CloudStoreError("ERR_INVALID_INPUT", "proof_version must be 2");
    }
    const candidateId = boundedPattern(input.candidateId ?? input.candidate_id, "candidate_id", RELEASE_CANDIDATE_ID);
    const deviceKeyFingerprint = boundedPattern(input.deviceKeyFingerprint ?? input.device_key_fingerprint, "device_key_fingerprint", DEVICE_KEY_FINGERPRINT);
    const credentialDigest = boundedPattern(input.credentialDigest ?? input.credential_digest, "credential_digest", SHA256);
    const challengeNonceDigest = boundedPattern(input.challengeNonceDigest ?? input.challenge_nonce_digest, "challenge_nonce_digest", SHA256);
    if (Object.hasOwn(input, "challengeNonce") || Object.hasOwn(input, "challenge_nonce") || Object.hasOwn(input, "nonce")) throw new CloudStoreError("ERR_INVALID_INPUT", "raw challenge nonce is not accepted by the v2 store");
    const enrollmentId = input.enrollmentId ?? input.enrollment_id ?? crypto.randomUUID();
    const deviceId = input.deviceId ?? input.device_id ?? crypto.randomUUID();
    assertUuid(enrollmentId, "enrollment_id");
    assertUuid(deviceId, "device_id");
    const label = boundedText(input.label ?? input.name, "label", 128, true);
    const platform = enumText(input.platform ?? "macos", "platform", ["macos"]);
    const createdAt = timestamp(input.createdAt ?? input.created_at ?? now());
    const ttlMs = input.ttlMs ?? input.ttl_ms ?? 15 * 60 * 1000;
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 60 * 1000 || ttlMs > 24 * 60 * 60 * 1000) throw new CloudStoreError("ERR_INVALID_INPUT", "v2 enrollment ttl must be between 60 seconds and 24 hours");
    const expiresAt = timestamp(input.expiresAt ?? input.expires_at ?? new Date(Date.parse(createdAt) + ttlMs).toISOString());
    if (Date.parse(expiresAt) <= Date.parse(createdAt) || Date.parse(expiresAt) - Date.parse(createdAt) > 24 * 60 * 60 * 1000) throw new CloudStoreError("ERR_INVALID_INPUT", "enrollment expiry must be within 24 hours after creation");
    const candidate = state.release_candidates[candidateId];
    if (!candidate || candidate.status !== "active") throw new CloudStoreError("ERR_CANDIDATE_UNAVAILABLE", "release candidate is not active");
    const request = { proof_version: 2, organization_id: organizationId, enrollment_id: enrollmentId, device_id: deviceId, label, platform, candidate_id: candidateId, device_key_fingerprint: deviceKeyFingerprint, created_at: createdAt, expires_at: expiresAt };
    const result = await mutate({
      organizationId,
      operation: "create_device_enrollment_v2",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: request,
      action: () => {
        const activeCandidate = state.release_candidates[candidateId];
        if (!activeCandidate || activeCandidate.status !== "active") throw new CloudStoreError("ERR_CANDIDATE_UNAVAILABLE", "release candidate is not active");
        if (state.device_enrollments[enrollmentId] || state.devices[deviceId] || hasAnyResourceId(state, enrollmentId) || hasAnyResourceId(state, deviceId)) throw unique("enrollment_or_device_id", enrollmentId);
        const record = {
          enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId,
          label, platform, proof_version: 2, candidate_id: candidateId,
          device_key_fingerprint: deviceKeyFingerprint, credential_digest: credentialDigest, challenge_nonce_digest: challengeNonceDigest,
          created_at: createdAt, expires_at: expiresAt, consumed_at: null, completion_hash: null
        };
        state.devices[deviceId] = { device_id: deviceId, organization_id: organizationId, name: label, device_public_key: null, status: "pending", metadata: { platform, proof_version: 2, candidate_id: candidateId }, created_at: createdAt, version: 1 };
        state.device_enrollments[enrollmentId] = record;
        return publicEnrollment(record);
      }
    });
    return publicV2Enrollment(result);
  };

  const completeDeviceEnrollmentV2 = async (input = {}) => {
    const completed = await enqueue(async () => {
    const enrollmentId = assertUuid(input.enrollmentId ?? input.enrollment_id, "enrollment_id");
    const organizationId = assertUuid(input.organizationId ?? input.organization_id, "organization_id");
    const deviceId = assertUuid(input.deviceId ?? input.device_id, "device_id");
    const record = state.device_enrollments[enrollmentId];
    if (!record || record.organization_id !== organizationId || record.proof_version !== 2) throw new CloudStoreError("ERR_ENROLLMENT_AUTH", "v2 device enrollment authentication failed");
    const credentialDigest = boundedPattern(input.credentialDigest ?? input.credential_digest, "credential_digest", SHA256);
    if (!timingSafeHex(record.credential_digest, credentialDigest)) throw new CloudStoreError("ERR_ENROLLMENT_AUTH", "v2 device enrollment authentication failed");
    const label = boundedText(input.label, "label", 128, true);
    const platform = enumText(input.platform, "platform", ["macos"]);
    const candidateId = boundedPattern(input.candidateId ?? input.candidate_id, "candidate_id", RELEASE_CANDIDATE_ID);
    const deviceKeyFingerprint = boundedPattern(input.deviceKeyFingerprint ?? input.device_key_fingerprint, "device_key_fingerprint", DEVICE_KEY_FINGERPRINT);
    const challengeNonceDigest = boundedPattern(input.challengeNonceDigest ?? input.challenge_nonce_digest, "challenge_nonce_digest", SHA256);
    if (Object.hasOwn(input, "challenge") || Object.hasOwn(input, "challengeNonce") || Object.hasOwn(input, "challenge_nonce") || Object.hasOwn(input, "nonce")) throw new CloudStoreError("ERR_INVALID_INPUT", "raw challenge nonce is not accepted by the v2 store");
    const deviceKey = normalizeV2DeviceKey(input.deviceKey ?? input.device_key);
    const possessionReceipt = input.possessionReceipt ?? input.possession_receipt ?? input.receipt;
    const normalizedReceipt = possessionReceipt === undefined ? null : normalizeStoredPossessionReceipt(possessionReceipt);
    if (deviceId !== record.device_id || label !== record.label || platform !== record.platform || candidateId !== record.candidate_id || deviceKeyFingerprint !== record.device_key_fingerprint) throw new CloudStoreError("ERR_ENROLLMENT_BINDING", "v2 device enrollment request does not match its reservation");
    if (challengeNonceDigest !== record.challenge_nonce_digest) throw new CloudStoreError("ERR_ENROLLMENT_BINDING", "v2 device enrollment challenge does not match its reservation");
    const completionHash = digest({ version: 2, proof_version: 2, enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label, platform, candidate_id: candidateId, device_key_fingerprint: deviceKeyFingerprint, challenge_id: enrollmentId, challenge_nonce_digest: record.challenge_nonce_digest, algorithm: deviceKey.algorithm, public_key: deviceKey.spki_pem, ...(normalizedReceipt ? { statement_hash: normalizedReceipt.statement_hash } : {}) });
    if (record.consumed_at !== null) {
      if (record.completion_hash !== completionHash) throw new CloudStoreError("ERR_ENROLLMENT_CONSUMED", "device enrollment was already consumed");
      if (normalizedReceipt) {
        const existing = state.device_possession_receipts.find((item) => item.organization_id === organizationId && item.enrollment_id === enrollmentId);
        if (!existing || existing.statement_hash !== normalizedReceipt.statement_hash) throw new CloudStoreError("ERR_ENROLLMENT_CONSUMED", "device enrollment receipt does not match the consumed request");
      }
      return clone(state.devices[deviceId]);
    }
    const completedAt = timestamp(input.completedAt ?? input.completed_at ?? now());
    if (Date.parse(completedAt) > Date.parse(record.expires_at)) throw new CloudStoreError("ERR_ENROLLMENT_EXPIRED", "device enrollment has expired");
    const device = state.devices[deviceId];
    if (!device || device.organization_id !== organizationId || device.status !== "pending" || device.device_public_key !== null) throw new CloudStoreError("ERR_ENROLLMENT_STATE", "pending device state is invalid");
    if (Object.values(state.devices).some((item) => item.device_id !== deviceId && item.device_public_key === deviceKey.spki_pem)) throw unique("device_public_key", deviceKey.spki_pem);
    const before = clone(state);
    try {
      device.device_public_key = deviceKey.spki_pem;
      device.key_algorithm = deviceKey.algorithm;
      device.key_epoch = nextDeviceKeyEpoch(device.key_epoch);
      device.status = "active";
      device.version += 1;
      record.device_key_epoch = device.key_epoch;
      record.consumed_at = completedAt;
      record.completion_hash = completionHash;
      if (normalizedReceipt) {
        const receiptRecord = buildPossessionReceiptRecord(state, organizationId, deviceId, normalizedReceipt);
        appendPossessionReceiptRecord(state, receiptRecord);
      }
      await persistState(storage, state);
      return clone(device);
    } catch (error) { state = before; throw error; }
    });
    return completed;
  };

  const appendDevicePossessionReceipt = async (input = {}) => {
    const organizationId = requireTenant(input);
    const deviceId = assertUuid(input.deviceId ?? input.device_id, "device_id");
    tenantRecord("devices", organizationId, deviceId, "device");
    const normalizedReceipt = normalizeStoredPossessionReceipt(input.receipt ?? input.possessionReceipt ?? input);
    const record = buildPossessionReceiptRecord(state, organizationId, deviceId, normalizedReceipt);
    return mutate({
      organizationId,
      operation: "append_device_possession_receipt",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, device_id: deviceId, enrollment_id: record.enrollment_id, purpose: record.purpose, signer_key_id: record.signer_key_id, signature_algorithm: record.signature_algorithm, statement_json: record.statement_json, statement_hash: record.statement_hash, signature_base64url: record.signature_base64url, issued_at: record.issued_at },
      action: () => {
        return publicPossessionReceipt(appendPossessionReceiptRecord(state, record));
      }
    });
  };

  const listDevicePossessionReceipts = async (input = {}) => read(() => {
    const organizationId = requireTenant(input);
    const deviceId = assertUuid(input.deviceId ?? input.device_id, "device_id");
    tenantRecord("devices", organizationId, deviceId, "device");
    return state.device_possession_receipts
      .filter((item) => item.organization_id === organizationId && item.device_id === deviceId)
      .sort((left, right) => right.issued_at.localeCompare(left.issued_at) || right.enrollment_id.localeCompare(left.enrollment_id))
      .map(publicPossessionReceipt);
  });

  const getDevicePossessionReceipt = async (input = {}) => read(() => {
    const receipts = listDevicePossessionReceiptsSync(state, input);
    if (receipts.length === 0) throw notFound("device possession receipt", `${input.organizationId ?? input.organization_id}:${input.deviceId ?? input.device_id}`);
    return publicPossessionReceipt(receipts[0]);
  });

  const createAgent = async (input = {}) => {
    assertSafeValue(input, "agent");
    const organizationId = requireTenant(input);
    const source = input.descriptor ?? input;
    const descriptor = normalizeAgentDescriptor({
      version: source.version,
      agent_id: source.agent_id ?? source.agentId ?? source.id ?? crypto.randomUUID(),
      name: source.name,
      kind: source.kind,
      public_key: source.public_key ?? source.publicKey,
      created_at: source.created_at ?? source.createdAt ?? now()
    });
    const deviceId = input.deviceId ?? input.device_id ?? source.device_id ?? source.deviceId;
    if (deviceId !== undefined) {
      assertUuid(deviceId, "device_id");
      tenantRecord("devices", organizationId, deviceId, "device");
    }
    return mutate({
      organizationId,
      operation: "create_agent",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, descriptor: { ...(source.agent_id ?? source.agentId ?? source.id ? { agent_id: descriptor.agent_id } : {}), name: descriptor.name, kind: descriptor.kind, public_key: descriptor.public_key, ...(source.created_at ?? source.createdAt ? { created_at: descriptor.created_at } : {}) }, ...(deviceId ? { device_id: deviceId } : {}) },
      action: () => {
        if (state.agents[descriptor.agent_id] || hasAnyResourceId(state, descriptor.agent_id)) throw unique("agent_id", descriptor.agent_id);
        if (Object.values(state.agents).some((item) => item.organization_id === organizationId && item.public_key === descriptor.public_key)) throw unique("public_key", descriptor.public_key);
        const record = { ...descriptor, organization_id: organizationId, ...(deviceId ? { device_id: deviceId } : {}), status: "active", version: 1 };
        state.agents[record.agent_id] = record;
        return record;
      }
    });
  };

  const createPolicy = async (input = {}) => {
    assertSafeValue(input, "policy");
    const organizationId = requireTenant(input);
    const policyId = input.policyId ?? input.policy_id ?? input.id ?? crypto.randomUUID();
    assertUuid(policyId, "policy_id");
    const name = boundedText(input.name, "name", 128, true);
    const scope = normalizeScope(input.scope);
    const sequence = sequenceValue(input.sequence ?? 1, "sequence");
    return mutate({
      organizationId,
      operation: "create_policy",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, ...(input.policyId ?? input.policy_id ?? input.id ? { policy_id: policyId } : {}), name, scope, sequence },
      action: () => {
        if (state.policies[policyId] || hasAnyResourceId(state, policyId)) throw unique("policy_id", policyId);
        if (Object.values(state.policies).some((item) => item.organization_id === organizationId && item.name === name)) throw unique("name", name);
        const record = { policy_id: policyId, organization_id: organizationId, name, scope, sequence, status: "active", created_at: now(), updated_at: now(), version: 1 };
        state.policies[policyId] = record;
        return record;
      }
    });
  };

  const createCapability = async (input = {}) => {
    assertSafeValue(input, "capability");
    const organizationId = requireTenant(input);
    const source = input.capability ?? input;
    const capabilityId = source.capability_id ?? source.capabilityId ?? input.capabilityId ?? crypto.randomUUID();
    assertUuid(capabilityId, "capability_id");
    const audience = source.audience ?? {};
    const agentId = source.agent_id ?? source.subject_agent_id ?? input.agentId ?? input.agent_id ?? audience.agent_id ?? audience.agentId;
    const deviceId = source.device_id ?? source.target_device_id ?? input.deviceId ?? input.device_id ?? audience.device_id ?? audience.deviceId;
    assertUuid(agentId, "agent_id");
    assertUuid(deviceId, "device_id");
    tenantRecord("agents", organizationId, agentId, "agent");
    tenantRecord("devices", organizationId, deviceId, "device");
    const issuer = boundedText(source.issuer, "issuer", 256, true);
    const keyId = boundedText(source.key_id ?? source.keyId, "key_id", 256, true);
    const scope = source.scope === undefined ? undefined : normalizeScope(source.scope);
    const operations = boundedArray(source.operations ?? scope?.operations, "operations", 64, 128, true);
    const notBefore = timestamp(source.not_before ?? source.notBefore);
    const expiresAt = timestamp(source.expires_at ?? source.expiresAt);
    if (new Date(expiresAt).getTime() <= new Date(notBefore).getTime()) throw new CloudStoreError("ERR_INVALID_INPUT", "capability expires_at must be after not_before");
    const sequence = sequenceValue(source.sequence, "sequence");
    const nonce = boundedText(source.nonce, "nonce", 128, true);
    const capabilityHash = crypto.createHash("sha256").update(canonicalJson({
      capability_id: capabilityId, issuer, key_id: keyId, agent_id: agentId, device_id: deviceId,
      operations, ...(scope ? { scope } : {}), not_before: notBefore, expires_at: expiresAt, sequence, nonce
    })).digest("hex");
    const record = {
      capability_id: capabilityId, organization_id: organizationId, issuer, key_id: keyId,
      agent_id: agentId, device_id: deviceId, operations, ...(scope ? { scope } : {}),
      not_before: notBefore, expires_at: expiresAt, sequence, nonce, capability_hash: capabilityHash,
      issued_at: now(), status: "active", version: 1
    };
    return mutate({
      organizationId,
      operation: "create_capability",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, ...(source.capability_id ?? source.capabilityId ?? input.capabilityId ? { capability_id: capabilityId } : {}), issuer, key_id: keyId, agent_id: agentId, device_id: deviceId, operations, ...(scope ? { scope } : {}), not_before: notBefore, expires_at: expiresAt, sequence, nonce },
      action: () => {
        if (state.capabilities[capabilityId] || hasAnyResourceId(state, capabilityId)) throw unique("capability_id", capabilityId);
        state.capabilities[capabilityId] = record;
        return record;
      }
    });
  };

  // Allocate capability identity and validity inside the idempotent mutation.
  // This keeps retries stable without persisting the signed bearer envelope.
  const reserveCapability = async (input = {}) => {
    assertSafeValue(input, "capability_reservation");
    const organizationId = requireTenant(input);
    const requestedCapabilityId = input.capabilityId ?? input.capability_id;
    if (requestedCapabilityId !== undefined) assertUuid(requestedCapabilityId, "capability_id");
    const agentId = input.agentId ?? input.agent_id;
    const deviceId = input.deviceId ?? input.device_id;
    assertUuid(agentId, "agent_id");
    assertUuid(deviceId, "device_id");
    tenantRecord("agents", organizationId, agentId, "agent");
    tenantRecord("devices", organizationId, deviceId, "device");
    const issuer = boundedText(input.issuer, "issuer", 256, true);
    const keyId = boundedText(input.keyId ?? input.key_id, "key_id", 256, true);
    const scope = normalizeScope(input.scope);
    const ttlMs = input.ttlMs ?? input.ttl_ms;
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 15 * 60 * 1000) throw new CloudStoreError("ERR_INVALID_INPUT", "capability ttl is invalid");
    const sequence = sequenceValue(input.sequence, "sequence");
    const requestedAt = timestamp(input.issuedAt ?? input.issued_at ?? now());
    const request = { organization_id: organizationId, ...(requestedCapabilityId ? { capability_id: requestedCapabilityId } : {}), issuer, key_id: keyId, agent_id: agentId, device_id: deviceId, scope, ttl_ms: ttlMs, sequence };
    return mutate({
      organizationId,
      operation: "reserve_capability",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: request,
      action: () => {
        const capabilityId = requestedCapabilityId ?? crypto.randomUUID();
        if (state.capabilities[capabilityId] || hasAnyResourceId(state, capabilityId)) throw unique("capability_id", capabilityId);
        const notBefore = requestedAt;
        const expiresAt = new Date(Date.parse(notBefore) + ttlMs).toISOString();
        const nonce = createCapabilityNonce();
        const operations = scope.operations;
        const capabilityHash = crypto.createHash("sha256").update(canonicalJson({ capability_id: capabilityId, issuer, key_id: keyId, agent_id: agentId, device_id: deviceId, operations, scope, not_before: notBefore, expires_at: expiresAt, sequence, nonce })).digest("hex");
        const record = { capability_id: capabilityId, organization_id: organizationId, issuer, key_id: keyId, agent_id: agentId, device_id: deviceId, operations, scope, not_before: notBefore, expires_at: expiresAt, sequence, nonce, capability_hash: capabilityHash, issued_at: notBefore, status: "active", version: 1 };
        state.capabilities[capabilityId] = record;
        return record;
      }
    });
  };

  const createRevocation = async (input = {}) => {
    assertSafeValue(input, "revocation");
    const organizationId = requireTenant(input);
    const targetType = enumText(input.targetType ?? input.target_type, "target_type", ["organization", "device", "agent", "capability"]);
    const targetId = input.targetId ?? input.target_id;
    assertUuid(targetId, "target_id");
    if (targetType === "organization" && targetId !== organizationId) throw notFound("target", targetId);
    if (targetType !== "organization") tenantRecord(targetType === "capability" ? "capabilities" : `${targetType}s`, organizationId, targetId, targetType);
    const reason = boundedText(input.reason, "reason", 128, true);
    const revocationId = input.revocationId ?? input.revocation_id ?? input.id ?? crypto.randomUUID();
    assertUuid(revocationId, "revocation_id");
    return mutate({
      organizationId,
      operation: "create_revocation",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, ...(input.revocationId ?? input.revocation_id ?? input.id ? { revocation_id: revocationId } : {}), target_type: targetType, target_id: targetId, reason },
      action: () => {
        if (state.revocations[revocationId] || hasAnyResourceId(state, revocationId)) throw unique("revocation_id", revocationId);
        if (Object.values(state.revocations).some((item) => item.organization_id === organizationId && item.target_type === targetType && item.target_id === targetId && item.status === "active")) throw unique("active_revocation", `${targetType}:${targetId}`);
        const record = { revocation_id: revocationId, organization_id: organizationId, target_type: targetType, target_id: targetId, reason, status: "active", revoked_at: now(), version: 1 };
        state.revocations[revocationId] = record;
        return record;
      }
    });
  };

  const appendAdminAuditEvent = async (input = {}) => {
    assertSafeValue(input, "admin_audit");
    const organizationId = requireTenant(input);
    const auditEventId = input.auditEventId ?? input.audit_event_id ?? input.eventId ?? input.event_id ?? crypto.randomUUID();
    assertUuid(auditEventId, "audit_event_id");
    const eventType = boundedText(input.eventType ?? input.event_type, "event_type", 128, true);
    const actorId = boundedText(input.actorId ?? input.actor_id, "actor_id", 256, true);
    const targetType = input.targetType ?? input.target_type;
    const targetId = input.targetId ?? input.target_id;
    if (targetType !== undefined) boundedText(targetType, "target_type", 128, true);
    if (targetId !== undefined) { assertUuid(targetId, "target_id"); }
    const details = input.details === undefined ? {} : safeMetadata(input.details, "details");
    return mutate({
      organizationId,
      operation: "append_admin_audit",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, ...(input.auditEventId ?? input.audit_event_id ?? input.eventId ?? input.event_id ? { audit_event_id: auditEventId } : {}), event_type: eventType, actor_id: actorId, ...(targetType ? { target_type: targetType } : {}), ...(targetId ? { target_id: targetId } : {}), details },
      action: () => {
        if (state.admin_audit_events.some((item) => item.audit_event_id === auditEventId)) throw unique("audit_event_id", auditEventId);
        const record = { audit_event_id: auditEventId, organization_id: organizationId, event_type: eventType, actor_id: actorId, ...(targetType ? { target_type: targetType } : {}), ...(targetId ? { target_id: targetId } : {}), details, recorded_at: now() };
        state.admin_audit_events.push(record);
        return record;
      }
    });
  };

  const ingestDeviceAuditEvents = async (input = {}) => {
    assertSafeValue(input, "device_audit_ingestion");
    const organizationId = requireTenant(input);
    const events = input.events;
    if (!Array.isArray(events) || events.length === 0 || events.length > MAX_BATCH) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", `events must contain 1-${MAX_BATCH} items`);
    const deviceId = input.deviceId ?? input.device_id;
    assertUuid(deviceId, "device_id");
    tenantRecord("devices", organizationId, deviceId, "device");
    const normalizedEvents = events.map((event) => normalizeAuditEvent(event));
    for (const event of normalizedEvents) {
      const expectedHash = computeAuditEventHash(event);
      if (event.event_hash !== expectedHash) {
        throw new CloudStoreError("ERR_AUDIT_HASH_MISMATCH", `event_hash does not match event ${event.event_id}`, {
          event_id: event.event_id,
          expected_hash: expectedHash,
          received_hash: event.event_hash
        });
      }
    }
    for (const event of normalizedEvents) {
      const agent = tenantRecord("agents", organizationId, event.agent_id, "agent");
      if (agent.device_id !== undefined && agent.device_id !== deviceId) throw new CloudStoreError("ERR_AUDIT_DEVICE_MISMATCH", `agent ${event.agent_id} is not bound to authenticated device ${deviceId}`);
    }
    return mutate({
      organizationId,
      operation: "ingest_device_audit",
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, device_id: deviceId, events: normalizedEvents },
      action: () => {
        const accepted = [];
        const duplicates = [];
        const gaps = [];
        let head = state.device_audit_heads[deviceId] ?? { last_hash: ZERO_HASH, last_event_id: null, chain_status: "continuous", gap_count: 0 };
        for (const event of normalizedEvents) {
          const duplicate = state.device_audit_events.find((item) => item.organization_id === organizationId && item.device_id === deviceId && item.event_id === event.event_id);
          if (duplicate) {
            if (canonicalJson(duplicate.event) !== canonicalJson(event)) throw new CloudStoreError("ERR_AUDIT_DEDUP_CONFLICT", `event_id ${event.event_id} was already ingested with different evidence`);
            duplicates.push(event.event_id);
            continue;
          }
          const gap = event.previous_hash !== head.last_hash;
          const record = { organization_id: organizationId, device_id: deviceId, event, event_id: event.event_id, agent_id: event.agent_id, ingested_at: now(), chain_status: gap ? "gap" : head.chain_status };
          state.device_audit_events.push(record);
          accepted.push(event.event_id);
          if (gap) {
            const gapRecord = { gap_id: crypto.randomUUID(), organization_id: organizationId, device_id: deviceId, event_id: event.event_id, expected_previous_hash: head.last_hash, received_previous_hash: event.previous_hash, recorded_at: now() };
            state.device_audit_gaps.push(gapRecord);
            gaps.push(gapRecord);
            head = { ...head, chain_status: "gap", gap_count: head.gap_count + 1 };
          }
          head = { ...head, last_hash: event.event_hash, last_event_id: event.event_id };
        }
        state.device_audit_heads[deviceId] = head;
        if (state.device_audit_events.length > MAX_AUDIT_EVENTS) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", "device audit retention bound exceeded");
        return { device_id: deviceId, accepted, duplicates, gaps: gaps.map(clone), head: clone(head) };
      }
    });
  };

  const appendDeviceAuditEvent = async (input = {}) => ingestDeviceAuditEvents({ ...input, events: [input.event ?? input.auditEvent ?? input.audit_event] });

  const updateResource = async (input, collection, label, idNames, allowed, normalize = (value) => value) => {
    assertSafeValue(input, label);
    const organizationId = requireTenant(input);
    const resourceId = idNames.map((name) => input[name]).find((value) => value !== undefined);
    assertUuid(resourceId, `${label}_id`);
    const expectedVersion = input.expectedVersion ?? input.expected_version;
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) throw new CloudStoreError("ERR_VERSION_REQUIRED", "expectedVersion must be a positive safe integer");
    const patch = input.patch;
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) throw new CloudStoreError("ERR_INVALID_INPUT", "patch must be an object");
    for (const key of Object.keys(patch)) {
      if (!allowed.includes(key)) throw new CloudStoreError("ERR_IMMUTABLE_FIELD", `${label}.${key} is not mutable`);
    }
    const record = tenantRecord(collection, organizationId, resourceId, label);
    let candidate = normalize({ ...record, ...patch });
    if (collection === "devices" && candidate.device_public_key !== record.device_public_key) {
      candidate = { ...candidate, key_epoch: nextDeviceKeyEpoch(record.key_epoch) };
    }
    assertSafeValue(candidate, label);
    return mutate({
      organizationId,
      operation: `update_${label}`,
      idempotencyKey: input.idempotencyKey ?? input.idempotency_key,
      input: { organization_id: organizationId, resource_id: resourceId, expected_version: expectedVersion, patch },
      action: () => {
        const current = tenantRecord(collection, organizationId, resourceId, label);
        if (current.version !== expectedVersion) throw new VersionConflictError(expectedVersion, current.version);
        const updated = { ...candidate, version: current.version + 1, updated_at: now() };
        state[collection][resourceId] = updated;
        return updated;
      }
    });
  };

  const get = (collection, label, idNames) => async (input) => read(() => {
    const organizationId = requireTenant(input);
    const resourceId = idNames.map((name) => input?.[name]).find((value) => value !== undefined);
    assertUuid(resourceId, `${label}_id`);
    return clone(tenantRecord(collection, organizationId, resourceId, label));
  });
  const listTenant = (collection) => async (input) => read(() => list(collection, requireTenant(input)));

  const getMembership = get("memberships", "membership", ["membershipId", "membership_id", "id"]);
  const getDevice = get("devices", "device", ["deviceId", "device_id", "id"]);
  const getAgent = get("agents", "agent", ["agentId", "agent_id", "id"]);
  const getPolicy = get("policies", "policy", ["policyId", "policy_id", "id"]);
  const getCapability = get("capabilities", "capability", ["capabilityId", "capability_id", "id"]);
  const getRevocation = get("revocations", "revocation", ["revocationId", "revocation_id", "id"]);

  const listDeviceReadModels = async (input = {}) => read(() => {
    const organizationId = requireTenant(input);
    return Object.values(state.devices)
      .filter((device) => device.organization_id === organizationId)
      .sort((left, right) => String(left.created_at).localeCompare(String(right.created_at)) || left.device_id.localeCompare(right.device_id))
      .map((device) => {
        const head = state.bundle_heads[device.device_id];
        return normalizeDeviceReadModel({
          device_id: device.device_id,
          organization_id: device.organization_id,
          name: device.name,
          ...(device.device_public_key === null ? {} : { device_public_key: device.device_public_key }),
          status: device.status,
          metadata: device.metadata,
          created_at: device.created_at,
          version: device.version,
          desired_generation: null,
          observed_generation: null,
          refresh_state: device.status === "revoked" ? "revoked" : "offline",
          current_bundle_sequence: head?.sequence ?? null,
          current_bundle_expires_at: head?.expires_at ?? null,
          last_ack_observed_at: null,
          last_ack_received_at: null,
          blocked_reason: null
        });
      });
  });

  const requestDeviceWake = async (input = {}) => {
    const organizationId = requireTenant(input);
    const deviceId = assertUuid(input.deviceId ?? input.device_id, "device_id");
    const device = tenantRecord("devices", organizationId, deviceId, "device");
    if (device.status !== "active") throw new CloudStoreError("ERR_DEVICE_REVOKED", "device is not active");
    const principalId = boundedText(input.principalId ?? input.principal_id ?? input.createdBy ?? input.created_by, "principal_id", 256, true);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const requestedAt = timestamp(input.requestedAt ?? input.requested_at ?? now());
    const requestId = deterministicWakeRequestId({ organizationId, deviceId, principalId, idempotencyKey });
    return mutate({
      organizationId,
      operation: `device-wake:${principalId}`,
      idempotencyKey,
      input: { version: 1, device_id: deviceId },
      action: () => Object.freeze({
        version: 1,
        request_id: requestId,
        device_id: deviceId,
        desired_generation: null,
        status: "no_pending_refresh",
        requested_at: requestedAt
      })
    });
  };

  const listAdminAuditEvents = async (input) => read(() => listAudit(state.admin_audit_events, requireTenant(input), input?.limit));
  const listDeviceAuditEvents = async (input) => read(() => {
    const organizationId = requireTenant(input);
    const page = normalizeAuditPageInput(input);
    const deviceId = page.device_id;
    if (deviceId !== null) tenantRecord("devices", organizationId, deviceId, "device");
    const position = page.cursor === undefined
      ? null
      : auditCursorCodec.decode(page.cursor, auditCursorBinding(organizationId, deviceId));
    const records = state.device_audit_events
      .filter((item) => item.organization_id === organizationId && item.device_id === deviceId)
      .filter((item) => position === null || compareAuditPosition(item, position) < 0)
      .sort(compareAuditRecords);
    const selected = records.slice(0, page.limit + 1);
    const hasNext = selected.length > page.limit;
    const events = selected.slice(0, page.limit).map(publicAuditRecord);
    const next_cursor = hasNext
      ? auditCursorCodec.encode({
        organization_id: organizationId,
        device_id: deviceId,
        device_timestamp: auditDeviceTimestamp(events.at(-1)),
        event_id: events.at(-1).event_id
      })
      : null;
    return Object.freeze({ events: Object.freeze(events), next_cursor });
  });
  const getAuditHealth = async (input) => read(() => {
    const organizationId = requireTenant(input);
    const devices = Object.values(state.devices).filter((item) => item.organization_id === organizationId);
    return devices.map((device) => ({ device_id: device.device_id, ...(state.device_audit_heads[device.device_id] ?? { last_hash: ZERO_HASH, last_event_id: null, chain_status: "continuous", gap_count: 0 }) }));
  });
  const assignBundleHead = async (input = {}) => {
    assertSafeValue(input, "bundle_head");
    const organizationId = requireTenant(input);
    const deviceId = input.deviceId ?? input.device_id;
    assertUuid(deviceId, "device_id");
    tenantRecord("devices", organizationId, deviceId, "device");
    const stateFingerprint = boundedText(input.stateFingerprint ?? input.state_fingerprint, "state_fingerprint", 64, true);
    if (!SHA256.test(stateFingerprint)) throw new CloudStoreError("ERR_INVALID_INPUT", "state_fingerprint must be SHA-256");
    const minimumSequence = sequenceValue(input.minimumSequence ?? input.minimum_sequence ?? 1, "minimum_sequence");
    const issuedAt = timestamp(input.issuedAt ?? input.issued_at);
    const expiresAt = timestamp(input.expiresAt ?? input.expires_at);
    if (Date.parse(expiresAt) <= Date.parse(issuedAt)) throw new CloudStoreError("ERR_INVALID_INPUT", "bundle head expiry must be after issuance");
    return enqueue(async () => {
      const current = state.bundle_heads[deviceId];
      if (current && current.organization_id !== organizationId) throw notFound("device", deviceId);
      if (current && current.state_fingerprint === stateFingerprint && Date.parse(current.expires_at) > Date.parse(issuedAt)) return clone(current);
      const sequence = Math.max(minimumSequence, (current?.sequence ?? 0) + 1);
      const record = { organization_id: organizationId, device_id: deviceId, sequence, state_fingerprint: stateFingerprint, issued_at: issuedAt, expires_at: expiresAt };
      const before = clone(state);
      try {
        state.bundle_heads[deviceId] = record;
        await persistState(storage, state);
        return clone(record);
      } catch (error) { state = before; throw error; }
    });
  };
  const snapshot = async (input) => read(() => {
    const organizationId = requireTenant(input);
    const scoped = (collection) => list(collection, organizationId);
    return {
      organizations: [clone(state.organizations[organizationId])], memberships: scoped("memberships"), devices: scoped("devices"), device_enrollments: scoped("device_enrollments").map(publicEnrollment), device_possession_receipts: state.device_possession_receipts.filter((item) => item.organization_id === organizationId).map(publicPossessionReceipt), agents: scoped("agents"), policies: scoped("policies"), capabilities: scoped("capabilities"), revocations: scoped("revocations"), admin_audit_events: state.admin_audit_events.filter((item) => item.organization_id === organizationId).map(clone), device_audit_events: state.device_audit_events.filter((item) => item.organization_id === organizationId).map(clone), device_audit_gaps: state.device_audit_gaps.filter((item) => item.organization_id === organizationId).map(clone), audit_health: devicesHealth(state, organizationId)
    };
  });

  const api = {
    createOrganization, getOrganization, listOrganizations,
    createMembership, getMembership, listMemberships: listTenant("memberships"), updateMembership: (input) => updateResource(input, "memberships", "membership", ["membershipId", "membership_id", "id"], ["role", "status"], (value) => ({ ...value, role: enumText(value.role, "role", ["owner", "admin", "auditor", "viewer"]), status: enumText(value.status, "status", ["active", "revoked"]) })),
    createDevice, getDevice, listDevices: listTenant("devices"), listDeviceReadModels, requestDeviceWake, updateDevice: (input) => updateResource(input, "devices", "device", ["deviceId", "device_id", "id"], ["name", "device_public_key", "metadata", "status"], (value) => { const publicKey = boundedText(value.device_public_key, "device_public_key", 8192, true, true); rejectPrivateKey(publicKey, "device_public_key"); return { ...value, name: boundedText(value.name, "name", 128, true), device_public_key: publicKey, metadata: safeMetadata(value.metadata, "metadata"), status: enumText(value.status, "status", ["active", "revoked"]) }; }),
    createDeviceEnrollment, completeDeviceEnrollment,
    registerReleaseCandidate, createReleaseCandidate: registerReleaseCandidate, getReleaseCandidate, lookupReleaseCandidate: getReleaseCandidate,
    createDeviceEnrollmentV2, createCandidateBoundDeviceEnrollment: createDeviceEnrollmentV2,
    completeDeviceEnrollmentV2, completeCandidateBoundDeviceEnrollment: completeDeviceEnrollmentV2,
    appendDevicePossessionReceipt, appendPossessionReceipt: appendDevicePossessionReceipt,
    getDevicePossessionReceipt, getPossessionReceipt: getDevicePossessionReceipt,
    getDeviceEnrollmentPossessionReceipt: getDevicePossessionReceipt,
    listDevicePossessionReceipts, listPossessionReceipts: listDevicePossessionReceipts,
    createAgent, getAgent, listAgents: listTenant("agents"), updateAgent: (input) => updateResource(input, "agents", "agent", ["agentId", "agent_id", "id"], ["name", "kind", "public_key", "device_id", "status"], (value) => { const descriptor = normalizeAgentDescriptor({ version: value.version, agent_id: value.agent_id, name: value.name, kind: value.kind, public_key: value.public_key, created_at: value.created_at }); return { ...value, ...descriptor, status: enumText(value.status, "status", ["active", "revoked"]) }; }),
    createPolicy, getPolicy, listPolicies: listTenant("policies"), updatePolicy: (input) => updateResource(input, "policies", "policy", ["policyId", "policy_id", "id"], ["name", "scope", "sequence", "status"], (value) => ({ ...value, name: boundedText(value.name, "name", 128, true), scope: normalizeScope(value.scope), sequence: sequenceValue(value.sequence, "sequence"), status: enumText(value.status, "status", ["active", "disabled"]) })),
    createCapability, reserveCapability, getCapability, listCapabilities: listTenant("capabilities"),
    createRevocation, revoke: createRevocation, getRevocation, listRevocations: listTenant("revocations"),
    appendAdminAuditEvent, listAdminAuditEvents,
    ingestDeviceAuditEvents, appendDeviceAuditEvent, listDeviceAuditEvents, getAuditHealth,
    assignBundleHead,
    snapshot,
    async close() { if (closed) return; await mutationQueue; closed = true; await releaseStoreLock(processLock); }
  };
  return Object.freeze(api);
}

function emptyState() {
  return {
    schema_version: SCHEMA_VERSION,
    organizations: {}, memberships: {}, devices: {}, device_enrollments: {}, release_candidates: {}, device_possession_receipts: [], agents: {}, policies: {}, capabilities: {}, revocations: {},
    admin_audit_events: [], device_audit_events: [], device_audit_gaps: [], device_audit_heads: {}, bundle_heads: {}, idempotency: {}
  };
}

async function prepareStorage(options) {
  const requestedFile = options.filePath ?? options.storePath;
  const requestedDirectory = options.dataDir ?? options.directory ?? options.dir ?? (requestedFile ? path.dirname(requestedFile) : undefined);
  if (!requestedDirectory) throw new CloudStoreError("ERR_STORAGE_PATH_REQUIRED", "createCloudStore requires dataDir or filePath");
  const directory = path.resolve(requestedDirectory);
  await ensureDirectory(directory);
  const file = path.resolve(requestedFile ?? path.join(directory, "cloud-store.json"));
  if (path.dirname(file) !== directory) throw new CloudStoreError("ERR_UNSAFE_PATH", "store file must be directly inside the secure data directory");
  await ensureFileIfPresent(file);
  const temporary = `${file}.tmp`;
  await ensureFileIfPresent(temporary);
  const main = await exists(file);
  const tmp = await exists(temporary);
  if (!main && tmp) {
    await fs.rename(temporary, file);
    await ensureFileIfPresent(file);
  }
  return { directory, file, temporary, lock: path.join(directory, ".cloud-store.lock") };
}

async function acquireStoreLock(storage) {
  const token = crypto.randomBytes(24).toString("base64url");
  const record = { pid: process.pid, token, created_at: new Date().toISOString() };
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const handle = await fs.open(storage.lock, "wx", 0o600);
      try { await handle.writeFile(canonicalJson(record), "utf8"); await handle.sync(); }
      finally { await handle.close(); }
      return { path: storage.lock, token };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let existing;
      let stat;
      try { stat = await fs.lstat(storage.lock); existing = JSON.parse(await fs.readFile(storage.lock, "utf8")); }
      catch { throw new CloudStoreError("ERR_STORE_LOCKED", "cloud store lock is invalid; operator inspection is required"); }
      ensureOwnershipAndMode(stat, storage.lock, false);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || !Number.isSafeInteger(existing?.pid) || existing.pid < 1 || typeof existing.token !== "string") throw new CloudStoreError("ERR_STORE_LOCKED", "cloud store lock is unsafe");
      try { process.kill(existing.pid, 0); throw new CloudStoreError("ERR_STORE_LOCKED", `cloud store is already open by process ${existing.pid}`); }
      catch (probe) {
        if (probe instanceof CloudStoreError || probe.code === "EPERM") throw probe instanceof CloudStoreError ? probe : new CloudStoreError("ERR_STORE_LOCKED", `cloud store process ${existing.pid} cannot be inspected`);
        if (probe.code !== "ESRCH") throw probe;
      }
      await fs.unlink(storage.lock);
    }
  }
  throw new CloudStoreError("ERR_STORE_LOCKED", "cloud store lock could not be acquired");
}

async function releaseStoreLock(lock) {
  let current;
  try { current = JSON.parse(await fs.readFile(lock.path, "utf8")); }
  catch (error) { if (error.code === "ENOENT") return; throw new CloudStoreError("ERR_STORE_LOCKED", "cloud store lock changed before close"); }
  if (current?.token !== lock.token || current?.pid !== process.pid) throw new CloudStoreError("ERR_STORE_LOCKED", "cloud store lock ownership changed before close");
  await fs.unlink(lock.path);
}

async function ensureDirectory(directory) {
  const absolute = path.resolve(directory);
  const root = path.parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let item;
    try { item = await fs.lstat(current); } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await fs.mkdir(current, { mode: 0o700 });
      item = await fs.lstat(current);
    }
    // System temporary roots such as macOS /var are commonly symlinked. The
    // caller-selected data directory itself may not be a symlink; ancestors
    // are allowed as long as the resolved final directory is private.
    if (item.isSymbolicLink() && current === absolute) throw new CloudStoreError("ERR_UNSAFE_PATH", `symlink is not allowed: ${current}`);
    if (item.isSymbolicLink()) continue;
    if (!item.isDirectory()) throw new CloudStoreError("ERR_UNSAFE_PATH", `storage path is not a directory: ${current}`);
    if (current === absolute) ensureOwnershipAndMode(item, current, true);
  }
}

async function ensureFileIfPresent(file) {
  try {
    const item = await fs.lstat(file);
    if (item.isSymbolicLink() || !item.isFile()) throw new CloudStoreError("ERR_UNSAFE_PATH", `store path must be a regular file: ${file}`);
    ensureOwnershipAndMode(item, file, false);
    if (item.size > MAX_STATE_BYTES) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", "store file exceeds the maximum supported size");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

async function exists(file) {
  try { await fs.lstat(file); return true; } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function ensureOwnershipAndMode(stat, label, directory) {
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) throw new CloudStoreError("ERR_UNSAFE_STORAGE", `storage ${label} is not owned by the current user`);
  if ((stat.mode & 0o077) !== 0) throw new CloudStoreError("ERR_UNSAFE_STORAGE", `storage ${label} must not be group/world accessible`);
  if (directory && (stat.mode & 0o700) !== 0o700) throw new CloudStoreError("ERR_UNSAFE_STORAGE", `storage directory ${label} must be owner accessible`);
}

async function loadState(storage) {
  let text;
  try { text = await fs.readFile(storage.file, "utf8"); } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw new CloudStoreError("ERR_STORE_CORRUPT", "store file is not valid JSON"); }
  // Schema-v1 stores created before durable bundle heads are upgraded in
  // memory and persisted on the next mutation. No authorization data is
  // inferred; the first subsequent bundle receives a fresh head.
  if (parsed?.schema_version === SCHEMA_VERSION && parsed.bundle_heads === undefined) parsed.bundle_heads = {};
  if (parsed?.schema_version === SCHEMA_VERSION && parsed.device_enrollments === undefined) parsed.device_enrollments = {};
  if (parsed?.schema_version === SCHEMA_VERSION && parsed.release_candidates === undefined) parsed.release_candidates = {};
  if (parsed?.schema_version === SCHEMA_VERSION && parsed.device_possession_receipts === undefined) parsed.device_possession_receipts = [];
  validateState(parsed);
  return parsed;
}

async function persistState(storage, state) {
  validateState(state);
  const encoded = canonicalJson(state);
  if (Buffer.byteLength(encoded, "utf8") > MAX_STATE_BYTES) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", "store state exceeds the maximum supported size");
  await ensureFileIfPresent(storage.file);
  await ensureFileIfPresent(storage.temporary);
  try { await fs.unlink(storage.temporary); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const handle = await fs.open(storage.temporary, "wx", 0o600);
  try {
    await handle.writeFile(encoded, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  await ensureFileIfPresent(storage.temporary);
  await fs.rename(storage.temporary, storage.file);
  await ensureFileIfPresent(storage.file);
  try { const directoryHandle = await fs.open(storage.directory, "r"); await directoryHandle.sync(); await directoryHandle.close(); } catch { /* Directory fsync is not available on every platform. */ }
}

function validateState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.schema_version !== SCHEMA_VERSION) throw new CloudStoreError("ERR_STORE_CORRUPT", "store schema is invalid");
  for (const collection of ["organizations", "memberships", "devices", "device_enrollments", "release_candidates", "agents", "policies", "capabilities", "revocations", "device_audit_heads", "bundle_heads", "idempotency"]) {
    if (!value[collection] || typeof value[collection] !== "object" || Array.isArray(value[collection])) throw new CloudStoreError("ERR_STORE_CORRUPT", `store collection ${collection} is invalid`);
  }
  for (const collection of ["admin_audit_events", "device_audit_events", "device_audit_gaps", "device_possession_receipts"]) {
    if (!Array.isArray(value[collection])) throw new CloudStoreError("ERR_STORE_CORRUPT", `store collection ${collection} is invalid`);
  }
  assertSafeValue(value, "store");
  for (const device of Object.values(value.devices)) validateDeviceEpoch(device);
  for (const enrollment of Object.values(value.device_enrollments)) {
    if (Object.hasOwn(enrollment, "challenge_nonce") || Object.hasOwn(enrollment, "nonce") || Object.hasOwn(enrollment, "credential")) throw new CloudStoreError("ERR_STORE_CORRUPT", "store contains raw enrollment secret material");
  }
  for (const receipt of value.device_possession_receipts) {
    if (Object.hasOwn(receipt, "challenge_nonce") || Object.hasOwn(receipt, "nonce") || Object.hasOwn(receipt, "credential") || Object.hasOwn(receipt, "private_key")) throw new CloudStoreError("ERR_STORE_CORRUPT", "store contains raw possession secret material");
  }
}

function validateDeviceEpoch(device) {
  if (!device || typeof device !== "object") throw new CloudStoreError("ERR_STORE_CORRUPT", "device record is invalid");
  if (device.status === "pending") {
    if (device.device_public_key !== null || device.key_epoch !== undefined) throw new CloudStoreError("ERR_STORE_CORRUPT", "pending device contains authentication epoch material");
    return;
  }
  if (device.device_public_key !== null && device.device_public_key !== undefined) {
    if (!Number.isSafeInteger(device.key_epoch) || device.key_epoch < 1) throw new CloudStoreError("ERR_STORE_CORRUPT", "active device authentication key epoch is unavailable");
  }
}

function assertSafeValue(value, label, seen = new Set(), depth = 0) {
  if (depth > 20) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", `${label} is too deeply nested`);
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    const publicKeyField = /public[_-]?key/i.test(label);
    if (typeof value === "string" && ((publicKeyField ? CONTROL.test(value.replace(/[\r\n]/g, "") ) : CONTROL.test(value)) || Buffer.byteLength(value, "utf8") > MAX_BYTES)) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", `${label} contains an unsafe or oversized string`);
    if (typeof value === "number" && !Number.isFinite(value)) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} contains a non-finite number`);
    return;
  }
  if (typeof value !== "object" || seen.has(value)) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} must contain plain JSON values`);
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null && !Array.isArray(value)) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} must contain plain JSON values`);
  seen.add(value);
  if (Array.isArray(value)) {
    const arrayLimit = label === "store" || label.startsWith("store.") ? MAX_AUDIT_EVENTS : MAX_BATCH;
    if (value.length > arrayLimit) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", `${label} contains too many items`);
    for (let index = 0; index < value.length; index += 1) assertSafeValue(value[index], `${label}[${index}]`, seen, depth + 1);
  } else {
    for (const [key, item] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(key)) throw new CloudStoreError("ERR_SECRET_MATERIAL", `${label}.${key} is not allowed to persist`);
      assertSafeValue(item, `${label}.${key}`, seen, depth + 1);
    }
  }
  seen.delete(value);
}

function safeMetadata(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} must be an object`);
  assertSafeValue(value, label);
  if (Buffer.byteLength(canonicalJson(value), "utf8") > MAX_BYTES) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", `${label} exceeds ${MAX_BYTES} bytes`);
  return clone(value);
}

function assertUuid(value, label) {
  if (typeof value !== "string" || !UUID.test(value)) throw new CloudStoreError("ERR_INVALID_UUID", `${label} must be a canonical UUID`);
  return value.toLowerCase();
}

function boundedText(value, label, max, required = false, allowNewlines = false) {
  if (typeof value !== "string" || (required && value.length === 0)) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} must be a non-empty string`);
  const checked = allowNewlines ? value.replace(/[\r\n]/g, "") : value;
  if (CONTROL.test(checked) || Buffer.byteLength(value, "utf8") > max) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", `${label} exceeds ${max} bytes or contains control characters`);
  return value;
}

function boundedPattern(value, label, pattern) {
  const text = boundedText(value, label, 256, true);
  if (!pattern.test(text)) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} has an invalid format`);
  return text;
}

function sha256Text(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeV2DeviceKey(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new CloudStoreError("ERR_INVALID_INPUT", "device_key must be an object");
  const algorithm = enumText(value.algorithm, "device_key.algorithm", ["p256-sha256"]);
  const pem = boundedText(value.spki_pem ?? value.spkiPem, "device_key.spki_pem", 8192, true, true);
  rejectPrivateKey(pem, "device_key.spki_pem");
  let key;
  try { key = crypto.createPublicKey(pem); }
  catch { throw new CloudStoreError("ERR_INVALID_INPUT", "device_key.spki_pem is not a public key"); }
  if (key.type !== "public" || key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new CloudStoreError("ERR_INVALID_INPUT", "device_key must be a P-256 public key");
  const canonicalPem = key.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
  return { algorithm, spki_pem: canonicalPem, fingerprint };
}

function normalizeStoredPossessionReceipt(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== ["algorithm", "key_id", "purpose", "signature", "statement", "statement_hash", "version"].sort().join("\0")) throw new CloudStoreError("ERR_INVALID_INPUT", "possession receipt envelope is invalid");
  const statementInput = value.statement;
  let statement;
  try { statement = normalizePossessionReceiptStatement(statementInput); }
  catch { throw new CloudStoreError("ERR_INVALID_INPUT", "possession receipt statement is invalid"); }
  const version = value.version;
  const purpose = value.purpose;
  const keyId = boundedPattern(value.key_id, "signer_key_id", /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/);
  const algorithm = enumText(value.algorithm, "receipt.algorithm", ["ed25519", "p256-sha256"]);
  if (version !== POSSESSION_RECEIPT_VERSION || purpose !== POSSESSION_RECEIPT_PURPOSE) throw new CloudStoreError("ERR_INVALID_INPUT", "possession receipt metadata is invalid");
  const statementHash = boundedPattern(value.statement_hash, "statement_hash", SHA256);
  const expectedHash = digest(statement);
  if (statementHash !== expectedHash) throw new CloudStoreError("ERR_RECEIPT_BINDING", "possession receipt statement hash does not match");
  const signature = value.signature;
  if (typeof signature !== "string" || !BASE64URL_SIGNATURE.test(signature)) throw new CloudStoreError("ERR_INVALID_INPUT", "possession receipt signature is invalid");
  const signatureBytes = Buffer.from(signature, "base64url");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64url") !== signature) throw new CloudStoreError("ERR_INVALID_INPUT", "possession receipt signature is invalid");
  const receipt = { version: POSSESSION_RECEIPT_VERSION, purpose, key_id: keyId, algorithm, statement: clone(statement), statement_hash: statementHash, signature };
  return { version, purpose, key_id: keyId, algorithm, statement, statement_hash: statementHash, signature, signatureBytes, receipt };
}

function publicV2Enrollment(record) {
  const value = publicEnrollment(record);
  return {
    ...value,
    challenge: {
      challenge_id: record.enrollment_id,
      expires_at: record.expires_at,
      candidate_id: record.candidate_id,
      device_key_fingerprint: record.device_key_fingerprint,
      challenge_nonce_digest: record.challenge_nonce_digest
    }
  };
}

function publicPossessionReceipt(record) {
  return clone(record.receipt ?? {
    version: POSSESSION_RECEIPT_VERSION,
    purpose: record.purpose,
    key_id: record.signer_key_id,
    algorithm: record.signature_algorithm,
    statement: record.statement_json,
    statement_hash: record.statement_hash,
    signature: record.signature_base64url
  });
}

function buildPossessionReceiptRecord(state, organizationId, deviceId, normalizedReceipt) {
  const statement = normalizedReceipt.statement;
  if (statement.organization_id !== organizationId || statement.device_id !== deviceId) throw new CloudStoreError("ERR_RECEIPT_BINDING", "possession receipt tenant or device binding is invalid");
  const enrollment = state.device_enrollments[statement.enrollment_id];
  if (!enrollment || enrollment.organization_id !== organizationId || enrollment.device_id !== deviceId || enrollment.proof_version !== 2 || enrollment.consumed_at === null) throw new CloudStoreError("ERR_RECEIPT_BINDING", "possession receipt enrollment binding is invalid");
  const candidate = state.release_candidates[statement.candidate_id];
  if (!candidate || candidate.source_commit !== statement.source_commit || candidate.artifact_sha256 !== statement.artifact_sha256 || candidate.team_id !== statement.team_id) throw new CloudStoreError("ERR_RECEIPT_BINDING", "possession receipt release binding is invalid");
  if (statement.enrollment_id !== enrollment.enrollment_id || statement.candidate_id !== enrollment.candidate_id || statement.device_key_fingerprint !== enrollment.device_key_fingerprint || statement.challenge_nonce_digest !== enrollment.challenge_nonce_digest || statement.device_key_epoch !== enrollment.device_key_epoch) throw new CloudStoreError("ERR_RECEIPT_BINDING", "possession receipt does not match the completed enrollment");
  return {
    organization_id: organizationId, enrollment_id: statement.enrollment_id, device_id: deviceId,
    candidate_id: statement.candidate_id, artifact_sha256: statement.artifact_sha256, source_commit: statement.source_commit,
    team_id: statement.team_id, device_key_fingerprint: statement.device_key_fingerprint,
    device_key_epoch: statement.device_key_epoch, challenge_nonce_digest: statement.challenge_nonce_digest,
    purpose: normalizedReceipt.purpose, signer_key_id: normalizedReceipt.key_id,
    signature_algorithm: normalizedReceipt.algorithm, statement_json: statement,
    statement_hash: normalizedReceipt.statement_hash, signature_base64url: normalizedReceipt.signature,
    issued_at: statement.issued_at, receipt: normalizedReceipt.receipt
  };
}

function appendPossessionReceiptRecord(state, record) {
  const existing = state.device_possession_receipts.find((item) => item.organization_id === record.organization_id && (item.enrollment_id === record.enrollment_id || (item.device_id === record.device_id && item.device_key_epoch === record.device_key_epoch)));
  if (existing) {
    if (canonicalJson(existing) === canonicalJson(record)) return existing;
    throw new CloudStoreError("ERR_RECEIPT_REPLAY", "a different possession receipt already exists for this enrollment or device key epoch");
  }
  state.device_possession_receipts.push(record);
  return record;
}

function listDevicePossessionReceiptsSync(state, input) {
  const organizationId = assertUuid(input?.organizationId ?? input?.organization_id, "organization_id");
  const deviceId = assertUuid(input?.deviceId ?? input?.device_id, "device_id");
  const device = state.devices[deviceId];
  if (!device || device.organization_id !== organizationId) throw notFound("device", deviceId);
  return state.device_possession_receipts
    .filter((item) => item.organization_id === organizationId && item.device_id === deviceId)
    .sort((left, right) => right.issued_at.localeCompare(left.issued_at) || right.enrollment_id.localeCompare(left.enrollment_id));
}

function boundedArray(value, label, maxItems, maxBytes, required = false) {
  if (!Array.isArray(value) || (required && value.length === 0) || value.length > maxItems) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", `${label} must contain 1-${maxItems} items`);
  return value.map((item, index) => boundedText(item, `${label}[${index}]`, maxBytes, true));
}

function enumText(value, label, allowed) { const text = boundedText(value, label, 128, true); if (!allowed.includes(text)) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} must be one of ${allowed.join(", ")}`); return text; }
function sequenceValue(value, label) { if (!Number.isSafeInteger(value) || value < 0) throw new CloudStoreError("ERR_INVALID_INPUT", `${label} must be a non-negative safe integer`); return value; }
function nextDeviceKeyEpoch(value) {
  if (value === undefined) return 1;
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) throw new CloudStoreError("ERR_DEVICE_AUTH_UNAVAILABLE", "device authentication key epoch cannot advance safely");
  return value + 1;
}
function timestamp(value) { if (typeof value !== "string" || !RFC3339_UTC.test(value) || !Number.isFinite(new Date(value).getTime())) throw new CloudStoreError("ERR_INVALID_INPUT", "timestamp must be a valid RFC 3339 UTC value"); return new Date(value).toISOString(); }
function now() { return new Date().toISOString(); }
function requireIdempotencyKey(value) {
  if (value === undefined || value === null) throw new CloudStoreError("ERR_IDEMPOTENCY_KEY_REQUIRED", "mutation requires an idempotency key");
  return boundedText(value, "idempotency_key", 256, true);
}
function rejectPrivateKey(value, label) { if (/PRIVATE\s+KEY|BEGIN\s+RSA|BEGIN\s+EC/i.test(value)) throw new CloudStoreError("ERR_SECRET_MATERIAL", `${label} contains private key material`); }
function clone(value) { return structuredClone(value); }
function digest(value) { return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex"); }
function deterministicWakeRequestId({ organizationId, deviceId, principalId, idempotencyKey }) {
  const bytes = crypto.createHash("sha256").update("AgentPass-Device-Wake-Request-Id-v1\0").update(canonicalJson({ organization_id: organizationId, device_id: deviceId, principal_id: principalId, idempotency_key: idempotencyKey })).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
function idOf(record) { return record.enrollment_id ?? record.organization_id ?? record.membership_id ?? record.device_id ?? record.agent_id ?? record.policy_id ?? record.capability_id ?? record.revocation_id ?? record.audit_event_id ?? ""; }
function unique(field, value) { return new CloudStoreError("ERR_UNIQUE_CONSTRAINT", `${field} must be unique: ${value}`); }
function notFound(label, id) { return new CloudStoreError("ERR_NOT_FOUND", `${label} not found: ${id}`); }
function slugify(value) { return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "organization"; }
function hasAnyResourceId(state, id) {
  return ["organizations", "memberships", "devices", "device_enrollments", "agents", "policies", "capabilities", "revocations"]
    .some((collection) => Object.hasOwn(state[collection], id));
}
function publicEnrollment(record) {
  const { credential_digest: _credential, completion_hash: _completion, ...value } = record;
  return clone(value);
}
function timingSafeHex(left, right) {
  const a = Buffer.from(left, "ascii"), b = Buffer.from(right, "ascii");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function boundedLimit(value) { if (value === undefined) return 100; if (!Number.isSafeInteger(value) || value < 1 || value > MAX_BATCH * 16) throw new CloudStoreError("ERR_LIMIT_EXCEEDED", "limit is out of bounds"); return value; }
function listAudit(values, organizationId, limit) { return values.filter((item) => item.organization_id === organizationId).slice(-boundedLimit(limit)).map(clone); }
function devicesHealth(state, organizationId) { return Object.values(state.devices).filter((item) => item.organization_id === organizationId).map((device) => ({ device_id: device.device_id, ...(state.device_audit_heads[device.device_id] ?? { last_hash: ZERO_HASH, last_event_id: null, chain_status: "continuous", gap_count: 0 }) })); }
function compareAuditRecords(left, right) { return -compareAuditPosition(left, right); }
function compareAuditPosition(left, right) {
  const leftTimestamp = auditDeviceTimestamp(left);
  const rightTimestamp = auditDeviceTimestamp(right);
  return leftTimestamp.localeCompare(rightTimestamp) || String(left.device_id).localeCompare(String(right.device_id)) || String(left.event_id).localeCompare(String(right.event_id));
}
function auditDeviceTimestamp(record) {
  const value = record?.event?.device_timestamp ?? record?.device_timestamp;
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new CloudStoreError("ERR_INVALID_INPUT", "audit event device_timestamp is invalid");
  return new Date(value).toISOString();
}
function publicAuditRecord(record) {
  const event = clone(record.event);
  const eventId = assertUuid(record.event_id, "event_id");
  const deviceId = assertUuid(record.device_id, "device_id");
  if (event.event_id !== eventId || event.device_timestamp !== auditDeviceTimestamp(record)) throw new CloudStoreError("ERR_INVALID_INPUT", "audit event key is inconsistent");
  return { organization_id: assertUuid(record.organization_id, "organization_id"), device_id: deviceId, event_id: eventId, event, received_at: timestamp(record.ingested_at) };
}
