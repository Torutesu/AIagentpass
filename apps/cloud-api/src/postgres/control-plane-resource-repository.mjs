import crypto from "node:crypto";

import { normalizeAgentDescriptor, normalizeScope, canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { normalizeDeviceReadModel } from "../device-read-model.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/;
const PUBLIC_KEY_BEGIN = /^-----BEGIN PUBLIC KEY-----/;
const PUBLIC_KEY_END = /-----END PUBLIC KEY-----\s*$/;
const MAX_TEXT_BYTES = 8192;
const MAX_METADATA_BYTES = 16 * 1024;
const MAX_IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const DEVICE_STATUSES = new Set(["active", "revoked"]);
const AGENT_STATUSES = new Set(["active", "revoked"]);
const POLICY_STATUSES = new Set(["active", "disabled"]);

const DEVICE_AUTH_SELECT = `SELECT devices.organization_id,devices.id,devices.label,devices.key_algorithm,devices.public_key_pem,devices.status,devices.metadata,devices.version,devices.created_at,devices.last_seen_at,
        active_epoch.key_epoch AS active_key_epoch,active_epoch.public_key_pem AS active_public_key_pem,active_epoch.status AS active_key_epoch_status,
        (SELECT count(*) FROM device_key_epochs epoch_count
          WHERE epoch_count.organization_id=devices.organization_id AND epoch_count.device_id=devices.id AND epoch_count.status='active') AS active_key_epoch_count
      FROM devices
      LEFT JOIN device_key_epochs active_epoch
        ON active_epoch.organization_id=devices.organization_id AND active_epoch.device_id=devices.id AND active_epoch.status='active'`;

const DEVICE_READ_MODEL_SELECT = `SELECT devices.organization_id,devices.id,devices.label,devices.key_algorithm,devices.public_key_pem,devices.status,devices.metadata,devices.version,devices.created_at,devices.last_seen_at,
        active_epoch.key_epoch AS active_key_epoch,active_epoch.public_key_pem AS active_public_key_pem,active_epoch.status AS active_key_epoch_status,
        (SELECT count(*) FROM device_key_epochs epoch_count
          WHERE epoch_count.organization_id=devices.organization_id AND epoch_count.device_id=devices.id AND epoch_count.status='active') AS active_key_epoch_count,
        refresh_state.desired_generation,refresh_state.observed_generation,refresh_state.refresh_state,
        current_statement.sequence AS current_bundle_sequence,current_statement.expires_at AS current_bundle_expires_at,
        latest_ack.observed_at AS last_ack_observed_at,latest_ack.received_at AS last_ack_received_at,
        CASE WHEN refresh_state.refresh_state='blocked' THEN COALESCE(latest_ack.reason_code,refresh_state.last_error_code) ELSE NULL END AS blocked_reason
      FROM devices
      LEFT JOIN device_key_epochs active_epoch
        ON active_epoch.organization_id=devices.organization_id AND active_epoch.device_id=devices.id AND active_epoch.status='active'
      LEFT JOIN device_control_plane_state refresh_state
        ON refresh_state.organization_id=devices.organization_id AND refresh_state.device_id=devices.id
      LEFT JOIN bundle_heads current_head
        ON current_head.organization_id=devices.organization_id AND current_head.device_id=devices.id
      LEFT JOIN control_bundle_statements current_statement
        ON current_statement.organization_id=current_head.organization_id AND current_statement.device_id=current_head.device_id
        AND current_statement.format_epoch=current_head.format_epoch AND current_statement.sequence=current_head.sequence
        AND current_statement.statement_hash=current_head.statement_hash
      LEFT JOIN LATERAL (
        SELECT acknowledgement.observed_at,acknowledgement.received_at,acknowledgement.reason_code
        FROM device_bundle_acknowledgements acknowledgement
        WHERE acknowledgement.organization_id=devices.organization_id AND acknowledgement.device_id=devices.id
        ORDER BY acknowledgement.sequence DESC,acknowledgement.received_at DESC
        LIMIT 1
      ) latest_ack ON true`;

/**
 * A CloudStore-compatible PostgreSQL adapter for the control-plane resources
 * that are currently read and mutated by server.mjs.
 *
 * Every SQL statement carries organization_id as a predicate or value. The
 * two mutations with an actor-owned NOT NULL column (enrollment and policy)
 * require createdBy/member_id explicitly; silently attributing either action
 * to an arbitrary organization member would make the audit record false.
 */
export class ControlPlaneResourceRepositoryError extends Error {
  constructor(code, message, details = undefined, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ControlPlaneResourceRepositoryError";
    this.code = code;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

export function createPostgresControlPlaneResourceRepository({ client, now = () => new Date().toISOString(), idempotencyTtlMs = MAX_IDEMPOTENCY_TTL_MS, onAuthorityReduction } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(idempotencyTtlMs) || idempotencyTtlMs < 1_000 || idempotencyTtlMs > MAX_IDEMPOTENCY_TTL_MS) {
    throw new TypeError("idempotencyTtlMs must be between 1000 and 86400000");
  }
  if (onAuthorityReduction !== undefined && typeof onAuthorityReduction !== "function") throw new TypeError("onAuthorityReduction must be a function");

  const api = {
    createDevice: (input = {}) => createDevice(input),
    getDevice: (input = {}) => getDevice(input),
    listDevices: (input = {}) => listDevices(input),
    listDeviceReadModels: (input = {}) => listDeviceReadModels(input),
    updateDevice: (input = {}) => updateDevice(input),
    createDeviceEnrollment: (input = {}) => createDeviceEnrollment(input),
    completeDeviceEnrollment: (input = {}) => completeDeviceEnrollment(input),
    createAgent: (input = {}) => createAgent(input),
    getAgent: (input = {}) => getAgent(input),
    listAgents: (input = {}) => listAgents(input),
    updateAgent: (input = {}) => updateAgent(input),
    createPolicy: (input = {}) => createPolicy(input),
    getPolicy: (input = {}) => getPolicy(input),
    listPolicies: (input = {}) => listPolicies(input),
    updatePolicy: (input = {}) => updatePolicy(input)
  };

  // The legacy CloudStore surface remains enumerable and unchanged. These
  // opt-in methods are deliberately non-enumerable so v1 adapters cannot
  // accidentally start depending on the v2 release/possession contract.
  Object.defineProperties(api, {
    createReleaseCandidate: { enumerable: false, value: (input = {}) => createReleaseCandidate(input) },
    getReleaseCandidate: { enumerable: false, value: (input = {}) => getReleaseCandidate(input) },
    resolveActiveReleaseCandidate: { enumerable: false, value: (input = {}) => resolveActiveReleaseCandidate(input) },
    retireReleaseCandidate: { enumerable: false, value: (input = {}) => retireReleaseCandidate(input) },
    createDeviceEnrollmentV2: { enumerable: false, value: (input = {}) => createDeviceEnrollmentV2(input) },
    completeDeviceEnrollmentV2: { enumerable: false, value: (input = {}) => completeDeviceEnrollmentV2(input) },
    getDeviceEnrollmentPossessionReceipt: { enumerable: false, value: (input = {}) => getDeviceEnrollmentPossessionReceipt(input) }
  });

  return Object.freeze(api);

  async function createDevice(input) {
    const organizationId = tenant(input);
    const principalId = requiredPrincipalId(input);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const deviceId = optionalUuid(input.deviceId ?? input.device_id ?? input.id, "device_id") ?? deterministicUuid("device", organizationId, principalId, idempotencyKey);
    const name = text(input.name, "name", 128, true);
    const publicKey = publicKeyText(input.publicKey ?? input.public_key ?? input.devicePublicKey ?? input.device_public_key, "device_public_key");
    const metadata = metadataValue(input.metadata);
    const algorithm = requiredDeviceAlgorithm(input.keyAlgorithm ?? input.key_algorithm);
    const request = { organization_id: organizationId, device_id: deviceId, name, public_key: publicKey, metadata, key_algorithm: algorithm };
    return runDatabase(async () => inTransaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      const result = await tx.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
        VALUES ($1,$2,$3,$4,$5,'active',$6::jsonb)
        RETURNING organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at`,
      [organizationId, deviceId, name, algorithm, publicKey, JSON.stringify(metadata)]);
      if (rowCount(result) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "device creation did not return a row");
      const device = mapDevice(result.rows[0]);
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 201, device);
      return device;
    }));
  }

  async function getDevice(input) {
    const organizationId = tenant(input);
    const deviceId = requiredUuid(input.deviceId ?? input.device_id ?? input.id, "device_id");
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`${DEVICE_AUTH_SELECT}
        WHERE devices.organization_id=$1 AND devices.id=$2`, [organizationId, deviceId]);
      if (rowCount(result) !== 1) throw notFound("device", deviceId);
      return mapDevice(result.rows[0], { requireActiveEpoch: true });
    });
  }

  async function listDevices(input) {
    const organizationId = tenant(input);
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`${DEVICE_AUTH_SELECT}
        WHERE devices.organization_id=$1 ORDER BY devices.created_at ASC,devices.id ASC`, [organizationId]);
      return (result.rows ?? []).map((row) => mapDevice(row, { requireActiveEpoch: true }));
    });
  }

  async function listDeviceReadModels(input) {
    const organizationId = tenant(input);
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`${DEVICE_READ_MODEL_SELECT}
        WHERE devices.organization_id=$1 ORDER BY devices.created_at ASC,devices.id ASC`, [organizationId]);
      return (result.rows ?? []).map((row) => mapDeviceReadModel(row));
    });
  }

  async function updateDevice(input) {
    const organizationId = tenant(input);
    const deviceId = requiredUuid(input.deviceId ?? input.device_id ?? input.id, "device_id");
    const expectedVersion = requiredVersion(input.expectedVersion ?? input.expected_version);
    const patch = object(input.patch, "patch");
    assertAllowedPatch(patch, new Set(["name", "device_public_key", "metadata", "status"]), "device");
    const name = patch.name === undefined ? undefined : text(patch.name, "name", 128, true);
    const publicKey = patch.device_public_key === undefined ? undefined : publicKeyText(patch.device_public_key, "device_public_key");
    const metadata = patch.metadata === undefined ? undefined : metadataValue(patch.metadata);
    const status = patch.status === undefined ? undefined : enumValue(patch.status, "status", DEVICE_STATUSES);
    const principalId = requiredPrincipalId(input);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const request = { organization_id: organizationId, resource_id: deviceId, expected_version: expectedVersion, patch };
    return runDatabase(async () => inTransaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      const current = await selectDevice(tx, organizationId, deviceId, true);
      const values = [];
      const assignments = [];
      if (name !== undefined) { values.push(name); assignments.push(`label=$${values.length + 3}`); }
      if (publicKey !== undefined) { values.push(publicKey); assignments.push(`public_key_pem=$${values.length + 3}`); }
      if (status !== undefined) { values.push(status); assignments.push(`status=$${values.length + 3}`); }
      if (metadata !== undefined) { values.push(JSON.stringify(metadata)); assignments.push(`metadata=$${values.length + 3}::jsonb`); }
      if (assignments.length === 0) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "device patch must contain a mutable field");
      values.unshift(organizationId, deviceId, expectedVersion);
      const result = await tx.query(`UPDATE devices SET ${assignments.join(", ")},version=version+1
        WHERE organization_id=$1 AND id=$2 AND version=$3
        RETURNING organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at`, values);
      if (rowCount(result) === 0) throw new ControlPlaneResourceRepositoryError("ERR_VERSION_CONFLICT", "optimistic version check failed", { expected: expectedVersion, actual: current.version });
      const device = mapDevice(result.rows[0]);
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 200, device);
      return device;
    }));
  }

  async function createDeviceEnrollment(input) {
    if ((input.proofVersion ?? input.proof_version) === 2) return createDeviceEnrollmentV2(input);
    const organizationId = tenant(input);
    const createdBy = requiredCreatedBy(input);
    const principalId = requiredPrincipalId(input);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const enrollmentId = optionalUuid(input.enrollmentId ?? input.enrollment_id, "enrollment_id") ?? deterministicUuid("enrollment", organizationId, principalId, idempotencyKey);
    const deviceId = optionalUuid(input.deviceId ?? input.device_id, "device_id") ?? deterministicUuid("enrollment-device", organizationId, principalId, idempotencyKey);
    const label = text(input.label ?? input.name, "label", 128, true);
    const platform = enumValue(input.platform ?? "macos", "platform", new Set(["macos"]));
    const credentialDigest = sha256(input.credentialDigest ?? input.credential_digest, "credential_digest");
    const createdAt = timestamp(input.createdAt ?? input.created_at ?? now(), "created_at");
    const expiresAt = timestamp(input.expiresAt ?? input.expires_at, "expires_at");
    if (Date.parse(expiresAt) <= Date.parse(createdAt) || Date.parse(expiresAt) - Date.parse(createdAt) > 24 * 60 * 60 * 1000) {
      throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "enrollment expiry must be within 24 hours after creation");
    }
    const request = { organization_id: organizationId, enrollment_id: enrollmentId, device_id: deviceId, label, platform, credential_digest: credentialDigest, ttl_ms: Date.parse(expiresAt) - Date.parse(createdAt), created_by: createdBy };
    return runDatabase(async () => inTransaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      const deviceResult = await tx.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status)
        VALUES ($1,$2,$3,NULL,NULL,'pending')
        RETURNING organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at`,
      [organizationId, deviceId, label]);
      if (rowCount(deviceResult) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "pending device creation did not return a row");
      const enrollmentResult = await tx.query(`INSERT INTO device_enrollments (id,organization_id,device_id,secret_hash,created_by,created_at,expires_at,label,platform)
        VALUES ($1,$2,$3,decode($4,'hex'),$5,$6,$7,$8,$9)
        RETURNING id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash`,
      [enrollmentId, organizationId, deviceId, credentialDigest, createdBy, createdAt, expiresAt, label, platform]);
      if (rowCount(enrollmentResult) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "device enrollment creation did not return a row");
      const enrollment = mapEnrollment(enrollmentResult.rows[0]);
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 201, enrollment);
      return enrollment;
    }));
  }

  async function completeDeviceEnrollment(input) {
    if ((input.proofVersion ?? input.proof_version) === 2) return completeDeviceEnrollmentV2(input);
    const enrollmentId = requiredUuid(input.enrollmentId ?? input.enrollment_id, "enrollment_id");
    const organizationId = requiredUuid(input.organizationId ?? input.organization_id, "organization_id");
    const deviceId = requiredUuid(input.deviceId ?? input.device_id, "device_id");
    const label = text(input.label, "label", 128, true);
    const platform = enumValue(input.platform, "platform", new Set(["macos"]));
    const algorithm = enumValue(input.algorithm, "algorithm", new Set(["p256-sha256", "ed25519"]));
    const publicKey = publicKeyText(input.publicKey ?? input.public_key, "device_public_key");
    const credentialDigest = sha256(input.credentialDigest ?? input.credential_digest, "credential_digest");
    const completedAt = timestamp(input.completedAt ?? input.completed_at ?? now(), "completed_at");
    const completionHash = sha256Hex({ version: 1, enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label, platform, algorithm, public_key: publicKey });
    return runDatabase(async () => inTransaction(async (tx) => {
      const enrollmentResult = await tx.query(`SELECT id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash
        FROM device_enrollments
        WHERE organization_id=$1 AND id=$2 AND encode(secret_hash,'hex')=$3
        FOR UPDATE`, [organizationId, enrollmentId, credentialDigest]);
      if (rowCount(enrollmentResult) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_AUTH", "device enrollment authentication failed");
      const enrollment = enrollmentResult.rows[0];
      if (enrollment.device_id !== deviceId) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_BINDING", "device enrollment request does not match its reservation");
      if (enrollment.label !== label || enrollment.platform !== platform) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_BINDING", "device enrollment request does not match its reservation");
      const device = await selectDevice(tx, organizationId, deviceId, true);
      if (enrollment.consumed_at !== null) {
        if (enrollment.completion_hash !== completionHash || device.label !== label || device.key_algorithm !== algorithm || device.public_key_pem !== publicKey || device.status !== "active") {
          throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_CONSUMED", "device enrollment was already consumed");
        }
        return await mapCompletedDevice(tx, organizationId, deviceId, device);
      }
      if (Date.parse(completedAt) > dateValue(enrollment.expires_at)) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_EXPIRED", "device enrollment has expired");
      if (device.status !== "pending" || device.public_key_pem !== null || device.label !== label) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_STATE", "pending device state is invalid");
      const update = await tx.query(`UPDATE devices SET key_algorithm=$3,public_key_pem=$4,status='active',version=version+1
        WHERE organization_id=$1 AND id=$2 AND status='pending' AND public_key_pem IS NULL
        RETURNING organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at`, [organizationId, deviceId, algorithm, publicKey]);
      if (rowCount(update) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_STATE", "pending device state is invalid");
      const consumed = await tx.query(`UPDATE device_enrollments SET consumed_at=$3,completion_hash=$4
        WHERE organization_id=$1 AND id=$2 AND consumed_at IS NULL
        RETURNING id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash`, [organizationId, enrollmentId, completedAt, completionHash]);
      if (rowCount(consumed) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_CONSUMED", "device enrollment was already consumed");
      return await mapCompletedDevice(tx, organizationId, deviceId, update.rows[0]);
    }));
  }

  async function createReleaseCandidate(input) {
    const values = normalizeReleaseCandidateInput(input);
    const createdAt = timestamp(input.createdAt ?? input.created_at ?? now(), "created_at");
    return runDatabase(async () => inTransaction(async (tx) => {
      const inserted = await tx.query(`INSERT INTO release_candidates
        (candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,created_at)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (candidate_id) DO NOTHING
        RETURNING candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at`,
      [values.candidateId, values.sourceCommit, values.artifactSha256, values.manifestSha256, values.teamId, createdAt]);
      if (rowCount(inserted) === 1) return mapReleaseCandidate(inserted.rows[0]);
      const existing = await tx.query(`SELECT candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at
        FROM release_candidates WHERE candidate_id=$1 FOR SHARE`, [values.candidateId]);
      if (rowCount(existing) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "release candidate disappeared during creation");
      const candidate = mapReleaseCandidate(existing.rows[0]);
      if (candidate.source_commit !== values.sourceCommit
        || candidate.artifact_sha256 !== values.artifactSha256
        || candidate.manifest_sha256 !== values.manifestSha256
        || candidate.team_id !== values.teamId) {
        throw new ControlPlaneResourceRepositoryError("ERR_IDENTITY_CONFLICT", "release candidate identity conflicts with an existing candidate");
      }
      return candidate;
    }));
  }

  async function getReleaseCandidate(input) {
    const candidateId = candidateIdValue(input.candidateId ?? input.candidate_id);
    return runDatabase(async () => {
      const result = await client.query(`SELECT candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at
        FROM release_candidates WHERE candidate_id=$1`, [candidateId]);
      if (rowCount(result) !== 1) throw notFound("release candidate", candidateId);
      return mapReleaseCandidate(result.rows[0]);
    });
  }

  async function resolveActiveReleaseCandidate(input) {
    const candidateId = candidateIdValue(input.candidateId ?? input.candidate_id);
    return runDatabase(async () => {
      const result = await client.query(`SELECT candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at
        FROM release_candidates WHERE candidate_id=$1 AND status='active'`, [candidateId]);
      if (rowCount(result) !== 1) throw notFound("active release candidate", candidateId);
      return mapReleaseCandidate(result.rows[0]);
    });
  }

  async function retireReleaseCandidate(input) {
    const candidateId = candidateIdValue(input.candidateId ?? input.candidate_id);
    const retiredAt = timestamp(input.retiredAt ?? input.retired_at ?? now(), "retired_at");
    return runDatabase(async () => inTransaction(async (tx) => {
      const result = await tx.query(`UPDATE release_candidates SET status='retired',retired_at=$2
        WHERE candidate_id=$1 AND status='active'
        RETURNING candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at`, [candidateId, retiredAt]);
      if (rowCount(result) === 1) return mapReleaseCandidate(result.rows[0]);
      const existing = await tx.query(`SELECT candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at
        FROM release_candidates WHERE candidate_id=$1`, [candidateId]);
      if (rowCount(existing) !== 1) throw notFound("release candidate", candidateId);
      const candidate = mapReleaseCandidate(existing.rows[0]);
      if (candidate.status === "retired") return candidate;
      throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "release candidate could not be retired");
    }));
  }

  async function createDeviceEnrollmentV2(input) {
    const organizationId = tenant(input);
    const createdBy = requiredCreatedBy(input);
    const principalId = requiredPrincipalId(input);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const enrollmentId = optionalUuid(input.enrollmentId ?? input.enrollment_id, "enrollment_id") ?? deterministicUuid("enrollment", organizationId, principalId, idempotencyKey);
    const deviceId = optionalUuid(input.deviceId ?? input.device_id, "device_id") ?? deterministicUuid("enrollment-device", organizationId, principalId, idempotencyKey);
    const label = text(input.label ?? input.name, "label", 128, true);
    const platform = enumValue(input.platform ?? "macos", "platform", new Set(["macos"]));
    const credentialDigest = sha256(input.credentialDigest ?? input.credential_digest, "credential_digest");
    const challengeDigest = sha256(input.challengeNonceDigest ?? input.challenge_nonce_digest, "challenge_nonce_digest");
    rejectRawPossessionMaterial(input);
    const fingerprint = deviceKeyFingerprint(input.deviceKeyFingerprint ?? input.device_key_fingerprint);
    const candidateId = candidateIdValue(input.candidateId ?? input.candidate_id);
    const createdAt = timestamp(input.createdAt ?? input.created_at ?? now(), "created_at");
    const expiresAt = timestamp(input.expiresAt ?? input.expires_at, "expires_at");
    if (Date.parse(expiresAt) <= Date.parse(createdAt) || Date.parse(expiresAt) - Date.parse(createdAt) > 24 * 60 * 60 * 1000) {
      throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "enrollment expiry must be within 24 hours after creation");
    }
    const request = {
      proof_version: 2, organization_id: organizationId, enrollment_id: enrollmentId, device_id: deviceId,
      label, platform, credential_digest: credentialDigest, challenge_nonce_digest: challengeDigest,
      candidate_id: candidateId, device_key_fingerprint: fingerprint,
      ttl_ms: Date.parse(expiresAt) - Date.parse(createdAt), created_by: createdBy
    };
    return runDatabase(async () => inTransaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      const candidate = await selectActiveReleaseCandidate(tx, candidateId);
      const deviceResult = await tx.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status)
        VALUES ($1,$2,$3,NULL,NULL,'pending')
        RETURNING organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at`,
      [organizationId, deviceId, label]);
      if (rowCount(deviceResult) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "pending device creation did not return a row");
      const enrollmentResult = await tx.query(`INSERT INTO device_enrollments
        (id,organization_id,device_id,secret_hash,created_by,created_at,expires_at,label,platform,proof_version,candidate_id,device_key_fingerprint,challenge_nonce_digest)
        VALUES ($1,$2,$3,decode($4,'hex'),$5,$6,$7,$8,$9,2,$10,$11,decode($12,'hex'))
        RETURNING id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash,proof_version,candidate_id,device_key_fingerprint,encode(challenge_nonce_digest,'hex') AS challenge_nonce_digest`,
      [enrollmentId, organizationId, deviceId, credentialDigest, createdBy, createdAt, expiresAt, label, platform, candidateId, fingerprint, challengeDigest]);
      if (rowCount(enrollmentResult) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "device enrollment creation did not return a row");
      const enrollment = mapEnrollmentV2(enrollmentResult.rows[0], candidate);
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 201, enrollment);
      return enrollment;
    }));
  }

  async function completeDeviceEnrollmentV2(input) {
    const enrollmentId = requiredUuid(input.enrollmentId ?? input.enrollment_id, "enrollment_id");
    const organizationId = requiredUuid(input.organizationId ?? input.organization_id, "organization_id");
    const deviceId = requiredUuid(input.deviceId ?? input.device_id, "device_id");
    const label = text(input.label, "label", 128, true);
    const platform = enumValue(input.platform, "platform", new Set(["macos"]));
    const algorithm = enumValue(input.algorithm ?? input.deviceKey?.algorithm ?? input.device_key?.algorithm, "algorithm", new Set(["p256-sha256"]));
    const publicKey = publicKeyText(input.publicKey ?? input.public_key ?? input.deviceKey?.spki_pem ?? input.device_key?.spki_pem, "device_public_key");
    const credentialDigest = sha256(input.credentialDigest ?? input.credential_digest, "credential_digest");
    const candidateId = candidateIdValue(input.candidateId ?? input.candidate_id);
    const fingerprint = deviceKeyFingerprint(input.deviceKeyFingerprint ?? input.device_key_fingerprint);
    const challengeDigest = sha256(input.challengeNonceDigest ?? input.challenge_nonce_digest, "challenge_nonce_digest");
    rejectRawPossessionMaterial(input);
    const completedAt = timestamp(input.completedAt ?? input.completed_at ?? now(), "completed_at");
    const receipt = normalizePossessionReceipt(input.possessionReceipt ?? input.possession_receipt ?? input.receipt);
    const receiptEnvelopeHash = sha256Hex(receipt);
    const completionHash = sha256Hex({ version: 2, enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label, platform, algorithm, public_key: publicKey, candidate_id: candidateId, device_key_fingerprint: fingerprint, challenge_nonce_digest: challengeDigest, receipt_hash: receiptEnvelopeHash });
    return runDatabase(async () => inTransaction(async (tx) => {
      const enrollmentResult = await tx.query(`SELECT id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash,proof_version,candidate_id,device_key_fingerprint,encode(challenge_nonce_digest,'hex') AS challenge_nonce_digest
        FROM device_enrollments
        WHERE organization_id=$1 AND id=$2 AND encode(secret_hash,'hex')=$3
        FOR UPDATE`, [organizationId, enrollmentId, credentialDigest]);
      if (rowCount(enrollmentResult) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_AUTH", "device enrollment authentication failed");
      const enrollment = enrollmentResult.rows[0];
      if (enrollment.proof_version !== 2 && Number(enrollment.proof_version) !== 2) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_BINDING", "device enrollment is not a v2 possession challenge");
      if (enrollment.device_id !== deviceId || enrollment.label !== label || enrollment.platform !== platform
        || enrollment.candidate_id !== candidateId || enrollment.device_key_fingerprint !== fingerprint
        || String(enrollment.challenge_nonce_digest).toLowerCase() !== challengeDigest) {
        throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_BINDING", "device enrollment request does not match its possession binding");
      }
      const candidate = await selectReleaseCandidate(tx, candidateId);
      assertPossessionReceiptBinding(receipt, { enrollmentId, organizationId, deviceId, candidate, fingerprint, challengeDigest });
      const device = await selectDevice(tx, organizationId, deviceId, true);
      if (enrollment.consumed_at !== null) {
        if (enrollment.completion_hash !== completionHash || device.label !== label || device.key_algorithm !== algorithm || device.public_key_pem !== publicKey || device.status !== "active") {
          throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_CONSUMED", "device enrollment was already consumed");
        }
        const existingReceipt = await selectPossessionReceipt(tx, organizationId, enrollmentId);
        if (sha256Hex(existingReceipt) !== receiptEnvelopeHash) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_CONSUMED", "device enrollment was already consumed");
        return mapCompletedDevice(tx, organizationId, deviceId, device);
      }
      if (Date.parse(completedAt) > dateValue(enrollment.expires_at)) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_EXPIRED", "device enrollment has expired");
      if (device.status !== "pending" || device.public_key_pem !== null || device.label !== label) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_STATE", "pending device state is invalid");
      const update = await tx.query(`UPDATE devices SET key_algorithm=$3,public_key_pem=$4,status='active',version=version+1
        WHERE organization_id=$1 AND id=$2 AND status='pending' AND public_key_pem IS NULL
        RETURNING organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at`, [organizationId, deviceId, algorithm, publicKey]);
      if (rowCount(update) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_STATE", "pending device state is invalid");
      const completedDevice = await mapCompletedDevice(tx, organizationId, deviceId, update.rows[0]);
      const keyEpoch = completedDevice.key_epoch;
      if (receipt.statement.device_key_epoch !== keyEpoch) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_BINDING", "possession receipt key epoch does not match the enrolled device");
      const insertedReceipt = await tx.query(`INSERT INTO device_enrollment_possession_receipts
        (organization_id,enrollment_id,device_id,candidate_id,artifact_sha256,source_commit,team_id,device_key_fingerprint,device_key_epoch,challenge_nonce_digest,purpose,signer_key_id,signature_algorithm,statement_json,statement_hash,signature_base64url,issued_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,decode($10,'hex'),$11,$12,$13,$14::jsonb,$15,$16,$17)
        RETURNING organization_id,enrollment_id,device_id,candidate_id,artifact_sha256,source_commit,team_id,device_key_fingerprint,device_key_epoch,encode(challenge_nonce_digest,'hex') AS challenge_nonce_digest,purpose,signer_key_id,signature_algorithm,statement_json,statement_hash,signature_base64url,issued_at`,
      [organizationId, enrollmentId, deviceId, candidateId, candidate.artifact_sha256, candidate.source_commit, candidate.team_id, fingerprint, keyEpoch, challengeDigest, receipt.purpose, receipt.key_id, receipt.algorithm, JSON.stringify(receipt.statement), receipt.statement_hash, receipt.signature, receipt.statement.issued_at]);
      if (rowCount(insertedReceipt) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "device possession receipt insertion did not return a row");
      const consumed = await tx.query(`UPDATE device_enrollments SET consumed_at=$3,completion_hash=$4
        WHERE organization_id=$1 AND id=$2 AND consumed_at IS NULL
        RETURNING id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash`, [organizationId, enrollmentId, completedAt, completionHash]);
      if (rowCount(consumed) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_CONSUMED", "device enrollment was already consumed");
      return completedDevice;
    }));
  }

  async function getDeviceEnrollmentPossessionReceipt(input) {
    const organizationId = tenant(input);
    const deviceId = requiredUuid(input.deviceId ?? input.device_id, "device_id");
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`SELECT organization_id,enrollment_id,device_id,candidate_id,artifact_sha256,source_commit,team_id,device_key_fingerprint,device_key_epoch,encode(challenge_nonce_digest,'hex') AS challenge_nonce_digest,purpose,signer_key_id,signature_algorithm,statement_json,statement_hash,signature_base64url,issued_at
        FROM device_enrollment_possession_receipts
        WHERE organization_id=$1 AND device_id=$2
        ORDER BY issued_at DESC,enrollment_id DESC LIMIT 1`, [organizationId, deviceId]);
      if (rowCount(result) !== 1) throw notFound("device possession receipt", deviceId);
      return mapPossessionReceiptRow(result.rows[0]);
    });
  }

  async function createAgent(input) {
    const organizationId = tenant(input);
    const principalId = requiredPrincipalId(input);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const source = object(input.descriptor ?? input, "agent");
    const agentId = optionalUuid(source.agent_id ?? source.agentId ?? source.id, "agent_id") ?? deterministicUuid("agent", organizationId, principalId, idempotencyKey);
    const descriptor = normalizeAgent({
      version: source.version,
      agent_id: agentId,
      name: source.name,
      kind: source.kind,
      public_key: source.public_key ?? source.publicKey,
      created_at: source.created_at ?? source.createdAt ?? now()
    });
    const deviceId = requiredUuid(input.deviceId ?? input.device_id ?? source.device_id ?? source.deviceId, "device_id");
    const request = { organization_id: organizationId, agent_id: descriptor.agent_id, device_id: deviceId, descriptor };
    return runDatabase(async () => inTransaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      await requireDevice(tx, organizationId, deviceId);
      const result = await tx.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
        VALUES ($1,$2,$3,$4,$5,$6,'active')
        RETURNING organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at`,
      [organizationId, descriptor.agent_id, deviceId, descriptor.kind, descriptor.name, descriptor.public_key]);
      if (rowCount(result) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "agent creation did not return a row");
      const agent = mapAgent(result.rows[0]);
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 201, agent);
      return agent;
    }));
  }

  async function getAgent(input) {
    const organizationId = tenant(input);
    const agentId = requiredUuid(input.agentId ?? input.agent_id ?? input.id, "agent_id");
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`SELECT organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at
        FROM agents WHERE organization_id=$1 AND id=$2`, [organizationId, agentId]);
      if (rowCount(result) !== 1) throw notFound("agent", agentId);
      return mapAgent(result.rows[0]);
    });
  }

  async function listAgents(input) {
    const organizationId = tenant(input);
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`SELECT organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at
        FROM agents WHERE organization_id=$1 ORDER BY created_at ASC,id ASC`, [organizationId]);
      return (result.rows ?? []).map(mapAgent);
    });
  }

  async function updateAgent(input) {
    const organizationId = tenant(input);
    const agentId = requiredUuid(input.agentId ?? input.agent_id ?? input.id, "agent_id");
    const expectedVersion = requiredVersion(input.expectedVersion ?? input.expected_version);
    const patch = object(input.patch, "patch");
    assertAllowedPatch(patch, new Set(["name", "kind", "public_key", "device_id", "status"]), "agent");
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const principalId = requiredPrincipalId(input);
    const normalizedPatch = {};
    if (patch.name !== undefined) normalizedPatch.name = text(patch.name, "name", 128, true);
    if (patch.kind !== undefined) normalizedPatch.kind = enumValue(patch.kind, "kind", new Set(["claude-code", "cursor", "mcp", "cli", "custom"]));
    if (patch.public_key !== undefined) normalizedPatch.public_key = publicKeyText(patch.public_key, "public_key");
    if (patch.device_id !== undefined) normalizedPatch.device_id = requiredUuid(patch.device_id, "device_id");
    if (patch.status !== undefined) normalizedPatch.status = enumValue(patch.status, "status", AGENT_STATUSES);
    const request = { organization_id: organizationId, resource_id: agentId, expected_version: expectedVersion, patch };
    return runDatabase(async () => inTransaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      const current = await selectAgent(tx, organizationId, agentId, true);
      if (normalizedPatch.device_id !== undefined) await requireDevice(tx, organizationId, normalizedPatch.device_id);
      const values = [organizationId, agentId, expectedVersion];
      const assignments = [];
      for (const [key, value] of Object.entries(normalizedPatch)) { values.push(value); assignments.push(`${key === "public_key" ? "public_key_pem" : key}=$${values.length}`); }
      if (assignments.length === 0) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "agent patch must contain a mutable field");
      const result = await tx.query(`UPDATE agents SET ${assignments.join(", ")},version=version+1
        WHERE organization_id=$1 AND id=$2 AND version=$3
        RETURNING organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at`, values);
      if (rowCount(result) === 0) throw new ControlPlaneResourceRepositoryError("ERR_VERSION_CONFLICT", "optimistic version check failed", { expected: expectedVersion, actual: current.version });
      const agent = mapAgent(result.rows[0]);
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 200, agent);
      return agent;
    }));
  }

  async function createPolicy(input) {
    const organizationId = tenant(input);
    const createdBy = requiredCreatedBy(input);
    const principalId = requiredPrincipalId(input);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const policyId = optionalUuid(input.policyId ?? input.policy_id ?? input.id, "policy_id") ?? deterministicUuid("policy", organizationId, principalId, idempotencyKey);
    const name = text(input.name, "name", 128, true);
    const scope = normalizePolicyScope(input.scope);
    const sequence = sequenceValue(input.sequence ?? 1, "sequence");
    const request = { organization_id: organizationId, policy_id: policyId, name, scope, sequence, created_by: createdBy };
    return runDatabase(async () => inTransaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      const result = await tx.query(`INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
        VALUES ($1,$2,$3,$4,$5::jsonb,'active',$6)
        RETURNING organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version`, [organizationId, policyId, sequence, name, JSON.stringify(scope), createdBy]);
      if (rowCount(result) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "policy creation did not return a row");
      const policy = mapPolicy(result.rows[0]);
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 201, policy);
      return policy;
    }));
  }

  async function getPolicy(input) {
    const organizationId = tenant(input);
    const policyId = requiredUuid(input.policyId ?? input.policy_id ?? input.id, "policy_id");
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`SELECT organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version
        FROM policies WHERE organization_id=$1 AND id=$2`, [organizationId, policyId]);
      if (rowCount(result) !== 1) throw notFound("policy", policyId);
      return mapPolicy(result.rows[0]);
    });
  }

  async function listPolicies(input) {
    const organizationId = tenant(input);
    return runDatabase(async () => {
      await assertOrganization(client, organizationId);
      const result = await client.query(`SELECT organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version
        FROM policies WHERE organization_id=$1 ORDER BY created_at ASC,id ASC`, [organizationId]);
      return (result.rows ?? []).map(mapPolicy);
    });
  }

  async function updatePolicy(input) {
    const organizationId = tenant(input);
    const policyId = requiredUuid(input.policyId ?? input.policy_id ?? input.id, "policy_id");
    const expectedVersion = requiredVersion(input.expectedVersion ?? input.expected_version);
    const patch = object(input.patch, "patch");
    assertAllowedPatch(patch, new Set(["name", "scope", "sequence", "status"]), "policy");
    const normalizedPatch = {};
    if (patch.name !== undefined) normalizedPatch.name = text(patch.name, "name", 128, true);
    if (patch.scope !== undefined) normalizedPatch.scope_json = normalizePolicyScope(patch.scope);
    if (patch.sequence !== undefined) normalizedPatch.sequence = sequenceValue(patch.sequence, "sequence");
    if (patch.status !== undefined) normalizedPatch.status = enumValue(patch.status, "status", POLICY_STATUSES);
    const idempotencyKey = requireIdempotencyKey(input.idempotencyKey ?? input.idempotency_key);
    const principalId = requiredPrincipalId(input);
    const request = { organization_id: organizationId, resource_id: policyId, expected_version: expectedVersion, patch };
    return runDatabase(async () => withTransaction(client, async (tx) => {
      await lockOrganization(tx, organizationId);
      const replay = await acquireIdempotency(tx, organizationId, principalId, idempotencyKey, request);
      if (replay !== undefined) return replay;
      const current = await selectPolicy(tx, organizationId, policyId, true);
      const values = [organizationId, policyId, expectedVersion];
      const assignments = [];
      for (const [key, value] of Object.entries(normalizedPatch)) {
        values.push(key === "scope_json" ? JSON.stringify(value) : value);
        assignments.push(`${key}=$${values.length}${key === "scope_json" ? "::jsonb" : ""}`);
      }
      if (assignments.length === 0) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "policy patch must contain a mutable field");
      const result = await tx.query(`UPDATE policies SET ${assignments.join(", ")},version=version+1,updated_at=clock_timestamp()
        WHERE organization_id=$1 AND id=$2 AND version=$3
        RETURNING organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version`, values);
      if (rowCount(result) === 0) throw new ControlPlaneResourceRepositoryError("ERR_VERSION_CONFLICT", "optimistic version check failed", { expected: expectedVersion, actual: safeInteger(current.version, "version") });
      const policy = mapPolicy(result.rows[0]);
      if (onAuthorityReduction && requiresPolicyAuthorityReduction(current, policy, normalizedPatch)) {
        const authority = await onAuthorityReduction(Object.freeze({
          tx,
          organization_id: organizationId,
          policy: freezePolicyForAuthorityHook(policy),
          actor_member_id: principalId,
          idempotency_key: idempotencyKey
        }));
        if (!authority || typeof authority !== "object" || !Number.isSafeInteger(authority.generation) || authority.generation < 1) {
          throw new ControlPlaneResourceRepositoryError("ERR_AUTHORITY_REDUCTION_UNAVAILABLE", "authority reduction propagation is unavailable");
        }
      }
      await finishIdempotency(tx, organizationId, principalId, idempotencyKey, 200, policy);
      return policy;
    }));
  }

  async function runDatabase(operation) {
    try { return await operation(); }
    catch (error) {
      if (error instanceof ControlPlaneResourceRepositoryError) throw error;
      if (error?.code === "23505") throw new ControlPlaneResourceRepositoryError("ERR_UNIQUE_CONSTRAINT", "resource uniqueness constraint was violated");
      if (error?.code === "23503") throw new ControlPlaneResourceRepositoryError("ERR_NOT_FOUND", "referenced control-plane resource was not found");
      throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "control-plane database operation failed", undefined, error);
    }
  }

  async function inTransaction(operation) {
    const transactionClient = typeof client.connect === "function" ? await client.connect() : client;
    try { return await withTransaction(transactionClient, operation); }
    finally { if (transactionClient !== client) transactionClient.release?.(); }
  }

  async function acquireIdempotency(tx, organizationId, principalId, key, request) {
    const requestHash = sha256Hex(request);
    await tx.query(`DELETE FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3 AND expires_at<=clock_timestamp()`, [organizationId, principalId, key]);
    const inserted = await tx.query(`INSERT INTO idempotency_records (organization_id,principal_id,idempotency_key,request_hash,response_status,response_json,expires_at)
      VALUES ($1,$2,$3,$4,202,'{}'::jsonb,clock_timestamp()+$5::interval)
      ON CONFLICT (organization_id,principal_id,idempotency_key) DO NOTHING`, [organizationId, principalId, key, requestHash, `${idempotencyTtlMs} milliseconds`]);
    if (rowCount(inserted) === 1) return undefined;
    const existing = await tx.query(`SELECT request_hash,response_status,response_json
      FROM idempotency_records WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3 FOR UPDATE`, [organizationId, principalId, key]);
    if (rowCount(existing) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "idempotency record disappeared during a transaction");
    if (existing.rows[0].request_hash !== requestHash) throw new ControlPlaneResourceRepositoryError("ERR_IDEMPOTENCY_CONFLICT", "idempotency key was already used for a different mutation");
    if (existing.rows[0].response_status === 202) throw new ControlPlaneResourceRepositoryError("ERR_IDEMPOTENCY_IN_PROGRESS", "idempotency mutation is still in progress");
    return cloneJson(existing.rows[0].response_json);
  }

  async function finishIdempotency(tx, organizationId, principalId, key, status, response) {
    const result = await tx.query(`UPDATE idempotency_records SET response_status=$4,response_json=$5::jsonb,expires_at=clock_timestamp()+$6::interval
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3`, [organizationId, principalId, key, status, JSON.stringify(response), `${idempotencyTtlMs} milliseconds`]);
    if (rowCount(result) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "idempotency record could not be finalized");
  }
}

async function lockOrganization(client, organizationId) {
  const result = await client.query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE", [organizationId]);
  if (rowCount(result) !== 1) throw notFound("organization", organizationId);
}

async function assertOrganization(client, organizationId) {
  const result = await client.query("SELECT id FROM organizations WHERE id=$1", [organizationId]);
  if (rowCount(result) !== 1) throw notFound("organization", organizationId);
}

async function selectReleaseCandidate(client, candidateId) {
  const result = await client.query(`SELECT candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at
    FROM release_candidates WHERE candidate_id=$1 FOR SHARE`, [candidateId]);
  if (rowCount(result) !== 1) throw notFound("release candidate", candidateId);
  return mapReleaseCandidate(result.rows[0]);
}

async function selectActiveReleaseCandidate(client, candidateId) {
  const result = await client.query(`SELECT candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id,status,created_at,retired_at
    FROM release_candidates WHERE candidate_id=$1 AND status='active' FOR SHARE`, [candidateId]);
  if (rowCount(result) !== 1) throw notFound("active release candidate", candidateId);
  return mapReleaseCandidate(result.rows[0]);
}

async function selectPossessionReceipt(client, organizationId, enrollmentId) {
  const result = await client.query(`SELECT organization_id,enrollment_id,device_id,candidate_id,artifact_sha256,source_commit,team_id,device_key_fingerprint,device_key_epoch,encode(challenge_nonce_digest,'hex') AS challenge_nonce_digest,purpose,signer_key_id,signature_algorithm,statement_json,statement_hash,signature_base64url,issued_at
    FROM device_enrollment_possession_receipts
    WHERE organization_id=$1 AND enrollment_id=$2 FOR SHARE`, [organizationId, enrollmentId]);
  if (rowCount(result) !== 1) throw notFound("device possession receipt", enrollmentId);
  return mapPossessionReceiptRow(result.rows[0]);
}

async function requireDevice(client, organizationId, deviceId) {
  const result = await client.query("SELECT id FROM devices WHERE organization_id=$1 AND id=$2", [organizationId, deviceId]);
  if (rowCount(result) !== 1) throw notFound("device", deviceId);
}

async function selectDevice(client, organizationId, deviceId, forUpdate = false) {
  const result = await client.query(`SELECT organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at
    FROM devices WHERE organization_id=$1 AND id=$2${forUpdate ? " FOR UPDATE" : ""}`, [organizationId, deviceId]);
  if (rowCount(result) !== 1) throw notFound("device", deviceId);
  return result.rows[0];
}

async function mapCompletedDevice(client, organizationId, deviceId, row) {
  // The devices UPDATE trigger creates the active epoch in this same
  // transaction. Read it back from the authoritative epoch table before the
  // transaction commits; never infer epoch 1 from enrollment state.
  const result = await client.query(`SELECT key_epoch,public_key_pem,status
    FROM device_key_epochs
    WHERE organization_id=$1 AND device_id=$2 AND status='active'
    ORDER BY key_epoch ASC
    FOR SHARE`, [organizationId, deviceId]);
  if (rowCount(result) !== 1) throw new ControlPlaneResourceRepositoryError("ERR_DEVICE_AUTH_UNAVAILABLE", "active device authentication key epoch is unavailable");
  const epoch = result.rows[0];
  return mapDevice({ ...row, active_key_epoch: epoch.key_epoch, active_public_key_pem: epoch.public_key_pem, active_key_epoch_status: epoch.status, active_key_epoch_count: 1 }, { requireActiveEpoch: true });
}

async function selectAgent(client, organizationId, agentId, forUpdate = false) {
  const result = await client.query(`SELECT organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at
    FROM agents WHERE organization_id=$1 AND id=$2${forUpdate ? " FOR UPDATE" : ""}`, [organizationId, agentId]);
  if (rowCount(result) !== 1) throw notFound("agent", agentId);
  return result.rows[0];
}

async function selectPolicy(client, organizationId, policyId, forUpdate = false) {
  const result = await client.query(`SELECT organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version
    FROM policies WHERE organization_id=$1 AND id=$2${forUpdate ? " FOR UPDATE" : ""}`, [organizationId, policyId]);
  if (rowCount(result) !== 1) throw notFound("policy", policyId);
  return result.rows[0];
}

function mapDevice(row, { requireActiveEpoch = false } = {}) {
  const deviceStatus = row.status;
  const devicePublicKey = row.public_key_pem ?? row.device_public_key;
  const activeEpoch = requireActiveEpoch ? activeDeviceKeyEpoch(row, deviceStatus, devicePublicKey) : undefined;
  const device = {
    device_id: requiredUuid(row.id ?? row.device_id, "device_id"),
    organization_id: requiredUuid(row.organization_id, "organization_id"),
    name: text(row.label ?? row.name, "name", 128, true),
    device_public_key: devicePublicKey,
    ...(row.key_algorithm === undefined ? {} : { key_algorithm: row.key_algorithm }),
    status: deviceStatus,
    metadata: metadataValue(row.metadata ?? {}),
    created_at: timestamp(row.created_at, "created_at"),
    ...(row.last_seen_at === null || row.last_seen_at === undefined ? {} : { last_seen_at: timestamp(row.last_seen_at, "last_seen_at") }),
    version: safeInteger(row.version, "version")
  };
  if (activeEpoch !== undefined) {
    Object.defineProperties(device, {
      key_epoch: { value: activeEpoch.keyEpoch, enumerable: false },
      authentication_public_key: { value: activeEpoch.publicKey, enumerable: false }
    });
  }
  return device;
}

function mapDeviceReadModel(row) {
  const device = mapDevice(row, { requireActiveEpoch: true });
  return normalizeDeviceReadModel({
    ...device,
    desired_generation: row.desired_generation,
    observed_generation: row.observed_generation,
    refresh_state: row.refresh_state ?? (row.status === "revoked" ? "revoked" : "offline"),
    current_bundle_sequence: row.current_bundle_sequence,
    current_bundle_expires_at: nullableStoredTimestamp(row.current_bundle_expires_at, "current_bundle_expires_at"),
    last_ack_observed_at: nullableStoredTimestamp(row.last_ack_observed_at, "last_ack_observed_at"),
    last_ack_received_at: nullableStoredTimestamp(row.last_ack_received_at, "last_ack_received_at"),
    blocked_reason: row.blocked_reason
  });
}

function activeDeviceKeyEpoch(row, deviceStatus, devicePublicKey) {
  // Pending and revoked records remain visible to the administrative resource
  // API, but they are never eligible for device authentication. An active
  // device must have exactly one current immutable epoch; ambiguity or any
  // missing/stale/mismatched material is an authentication outage, not a
  // reason to guess which key should be trusted.
  if (deviceStatus !== "active") return undefined;
  const count = typeof row.active_key_epoch_count === "string" ? Number(row.active_key_epoch_count) : row.active_key_epoch_count;
  const keyEpoch = typeof row.active_key_epoch === "string" ? Number(row.active_key_epoch) : row.active_key_epoch;
  if (count !== 1 || !Number.isSafeInteger(keyEpoch) || keyEpoch < 1 || row.active_key_epoch_status !== "active") {
    throw new ControlPlaneResourceRepositoryError("ERR_DEVICE_AUTH_UNAVAILABLE", "active device authentication key epoch is unavailable");
  }
  let publicKey;
  try {
    publicKey = publicKeyText(row.active_public_key_pem, "active_device_public_key");
  } catch {
    throw new ControlPlaneResourceRepositoryError("ERR_DEVICE_AUTH_UNAVAILABLE", "active device authentication key is unavailable");
  }
  if (publicKey !== devicePublicKey) {
    throw new ControlPlaneResourceRepositoryError("ERR_DEVICE_AUTH_UNAVAILABLE", "active device authentication key does not match the enrolled public key");
  }
  return { keyEpoch, publicKey };
}

function mapEnrollment(row) {
  return {
    enrollment_id: requiredUuid(row.id ?? row.enrollment_id, "enrollment_id"),
    organization_id: requiredUuid(row.organization_id, "organization_id"),
    device_id: requiredUuid(row.device_id, "device_id"),
    label: text(row.label, "label", 128, true),
    platform: enumValue(row.platform, "platform", new Set(["macos"])),
    created_at: timestamp(row.created_at, "created_at"),
    expires_at: timestamp(row.expires_at, "expires_at"),
    consumed_at: row.consumed_at === null || row.consumed_at === undefined ? null : timestamp(row.consumed_at, "consumed_at")
  };
}

function mapEnrollmentV2(row, candidate) {
  const enrollment = mapEnrollment(row);
  const proofVersion = Number(row.proof_version);
  if (proofVersion !== 2 || candidate.status !== "active") throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "stored v2 enrollment binding is invalid");
  return {
    ...enrollment,
    proof_version: 2,
    candidate_id: candidate.candidate_id,
    device_key_fingerprint: deviceKeyFingerprint(row.device_key_fingerprint),
    challenge_nonce_digest: sha256(row.challenge_nonce_digest, "challenge_nonce_digest"),
    candidate_binding: {
      candidate_id: candidate.candidate_id,
      artifact_sha256: candidate.artifact_sha256,
      source_commit: candidate.source_commit,
      manifest_sha256: candidate.manifest_sha256,
      team_id: candidate.team_id
    }
  };
}

function mapReleaseCandidate(row) {
  const status = enumValue(row.status, "status", new Set(["active", "retired"]));
  return {
    candidate_id: candidateIdValue(row.candidate_id),
    source_commit: exactLowerPattern(row.source_commit, /^[0-9a-f]{40}$/u, "source_commit"),
    artifact_sha256: exactLowerPattern(row.artifact_sha256, SHA256, "artifact_sha256"),
    manifest_sha256: exactLowerPattern(row.manifest_sha256, SHA256, "manifest_sha256"),
    team_id: exactPattern(row.team_id, /^[A-Z0-9]{10}$/u, "team_id"),
    status,
    created_at: timestamp(row.created_at, "created_at"),
    retired_at: row.retired_at === null || row.retired_at === undefined ? null : timestamp(row.retired_at, "retired_at")
  };
}

function mapPossessionReceiptRow(row) {
  const statement = normalizePossessionReceiptStatement(row.statement_json);
  const statementHash = sha256(row.statement_hash, "statement_hash");
  if (sha256Hex(statement) !== statementHash) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "stored possession receipt hash is invalid");
  if (safeInteger(row.device_key_epoch, "device_key_epoch") !== statement.device_key_epoch
    || sha256(row.challenge_nonce_digest, "challenge_nonce_digest") !== statement.challenge_nonce_digest) {
    throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", "stored possession receipt binding is invalid");
  }
  const receipt = {
    version: 1,
    purpose: text(row.purpose, "purpose", 128, true),
    key_id: signerKeyId(row.signer_key_id),
    algorithm: enumValue(row.signature_algorithm, "signature_algorithm", new Set(["ed25519", "p256-sha256"])),
    statement,
    statement_hash: statementHash,
    signature: signatureBase64Url(row.signature_base64url)
  };
  assertPossessionReceiptBinding(receipt, {
    enrollmentId: requiredUuid(row.enrollment_id, "enrollment_id"),
    organizationId: requiredUuid(row.organization_id, "organization_id"),
    deviceId: requiredUuid(row.device_id, "device_id"),
    candidate: {
      candidate_id: candidateIdValue(row.candidate_id),
      artifact_sha256: exactLowerPattern(row.artifact_sha256, SHA256, "artifact_sha256"),
      source_commit: exactLowerPattern(row.source_commit, /^[0-9a-f]{40}$/u, "source_commit"),
      team_id: exactPattern(row.team_id, /^[A-Z0-9]{10}$/u, "team_id")
    },
    fingerprint: deviceKeyFingerprint(row.device_key_fingerprint),
    challengeDigest: sha256(row.challenge_nonce_digest, "challenge_nonce_digest")
  });
  return receipt;
}

function mapAgent(row) {
  return {
    version: safeInteger(row.version, "version"),
    agent_id: requiredUuid(row.id ?? row.agent_id, "agent_id"),
    name: text(row.name, "name", 128, true),
    kind: enumValue(row.kind, "kind", new Set(["claude-code", "cursor", "mcp", "cli", "custom"])),
    public_key: publicKeyText(row.public_key_pem ?? row.public_key, "public_key"),
    created_at: timestamp(row.created_at, "created_at"),
    organization_id: requiredUuid(row.organization_id, "organization_id"),
    device_id: requiredUuid(row.device_id, "device_id"),
    status: enumValue(row.status, "status", AGENT_STATUSES),
    ...(row.last_seen_at === null || row.last_seen_at === undefined ? {} : { last_seen_at: timestamp(row.last_seen_at, "last_seen_at") })
  };
}

function mapPolicy(row) {
  return {
    policy_id: requiredUuid(row.id ?? row.policy_id, "policy_id"),
    organization_id: requiredUuid(row.organization_id, "organization_id"),
    name: text(row.name, "name", 128, true),
    scope: normalizePolicyScope(row.scope_json ?? row.scope),
    sequence: sequenceValue(row.sequence, "sequence"),
    status: enumValue(row.status, "status", POLICY_STATUSES),
    created_at: timestamp(row.created_at, "created_at"),
    updated_at: timestamp(row.updated_at, "updated_at"),
    version: safeInteger(row.version, "version")
  };
}

function normalizeAgent(input) {
  try { return normalizeAgentDescriptor(input); }
  catch (error) { throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "agent descriptor is invalid", undefined, error); }
}

function normalizePolicyScope(value) {
  try { return normalizeScope(value); }
  catch (error) { throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "policy scope is invalid", undefined, error); }
}

function requiresPolicyAuthorityReduction(currentRow, nextPolicy, normalizedPatch) {
  if (currentRow.status !== "active") return false;
  if (nextPolicy.status === "disabled") return true;
  // A policy update can affect which authority is effective even when its
  // scope is not touched (for example, a sequence change). Treat every such
  // active update as reducing unless the whole mutation is a proven widening.
  if (normalizedPatch.scope_json === undefined) return true;
  if (Object.keys(normalizedPatch).some((key) => key !== "scope_json" && key !== "status")) return true;
  return !isProvablyStrictScopeWidening(normalizePolicyScope(currentRow.scope_json), nextPolicy.scope);
}

function isProvablyStrictScopeWidening(previous, next) {
  if (!isSubset(previous.operations, next.operations) || !isSubset(previous.repositories, next.repositories)) return false;
  for (const key of ["branches", "remotes"]) {
    if (!isPatternSetWidening(previous[key], next[key])) return false;
  }
  // An omitted optional tag filter has semantics that are enforced elsewhere;
  // do not infer whether adding/removing it widens access.
  if (Object.hasOwn(previous, "tags") || Object.hasOwn(next, "tags")) {
    if (!Object.hasOwn(previous, "tags") || !Object.hasOwn(next, "tags") || !isPatternSetWidening(previous.tags, next.tags)) return false;
  }
  return isStrictSuperset(previous.operations, next.operations)
    || isStrictSuperset(previous.repositories, next.repositories)
    || ["branches", "remotes", "tags"].some((key) => Object.hasOwn(previous, key) && Object.hasOwn(next, key) && isPatternSetStrictlyWider(previous[key], next[key]));
}

function isPatternSetWidening(previous, next) {
  return isSubset(previous.allow, next.allow) && sameSet(previous.deny, next.deny);
}

function isPatternSetStrictlyWider(previous, next) {
  return isPatternSetWidening(previous, next) && isStrictSuperset(previous.allow, next.allow);
}

function isSubset(previous, next) {
  const nextSet = new Set(next);
  return previous.every((value) => nextSet.has(value));
}

function isStrictSuperset(previous, next) {
  return isSubset(previous, next) && new Set(next).size > new Set(previous).size;
}

function sameSet(left, right) {
  return left.length === right.length && isSubset(left, right);
}

function freezePolicyForAuthorityHook(policy) {
  return Object.freeze({
    policy_id: policy.policy_id,
    organization_id: policy.organization_id,
    name: policy.name,
    scope: policy.scope,
    sequence: policy.sequence,
    status: policy.status,
    created_at: policy.created_at,
    updated_at: policy.updated_at,
    version: policy.version
  });
}

function requiredCreatedBy(input) {
  const value = input.createdBy ?? input.created_by ?? input.memberId ?? input.member_id;
  if (value === undefined || value === null) throw new ControlPlaneResourceRepositoryError("ERR_ACTOR_REQUIRED", "mutation requires an authenticated member actor");
  return requiredUuid(value, "created_by");
}

function normalizeReleaseCandidateInput(input) {
  return {
    candidateId: candidateIdValue(input.candidateId ?? input.candidate_id),
    sourceCommit: exactLowerPattern(input.sourceCommit ?? input.source_commit, /^[0-9a-f]{40}$/u, "source_commit"),
    artifactSha256: exactLowerPattern(input.artifactSha256 ?? input.artifact_sha256, SHA256, "artifact_sha256"),
    manifestSha256: exactLowerPattern(input.manifestSha256 ?? input.manifest_sha256, SHA256, "manifest_sha256"),
    teamId: exactPattern(input.teamId ?? input.team_id, /^[A-Z0-9]{10}$/u, "team_id")
  };
}

function candidateIdValue(value) {
  return exactPattern(value, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u, "candidate_id");
}

function deviceKeyFingerprint(value) {
  return exactPattern(value, /^SHA256:[A-Za-z0-9_-]{43}$/u, "device_key_fingerprint");
}

function signerKeyId(value) {
  return exactPattern(value, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u, "signer_key_id");
}

function signatureBase64Url(value) {
  return exactPattern(value, /^[A-Za-z0-9_-]{86}$/u, "signature");
}

function exactPattern(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} is invalid`);
  return value;
}

function exactLowerPattern(value, pattern, label) {
  const result = exactPattern(value, pattern, label);
  return result.toLowerCase();
}

function normalizePossessionReceipt(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession_receipt must be an object");
  const keys = Object.keys(input);
  if (keys.length !== 7 || keys.some((key) => !["version", "purpose", "key_id", "algorithm", "statement", "statement_hash", "signature"].includes(key))) {
    throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession_receipt has invalid fields");
  }
  if (input.version !== 1) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession_receipt version is invalid");
  if (input.purpose !== "device-enrollment-possession-receipt") throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession_receipt purpose is invalid");
  const statement = normalizePossessionReceiptStatement(input.statement);
  const statementHash = sha256(input.statement_hash, "statement_hash");
  if (sha256Hex(statement) !== statementHash) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession_receipt statement hash is invalid");
  return {
    version: 1,
    purpose: input.purpose,
    key_id: signerKeyId(input.key_id),
    algorithm: enumValue(input.algorithm, "signature_algorithm", new Set(["ed25519", "p256-sha256"])),
    statement,
    statement_hash: statementHash,
    signature: signatureBase64Url(input.signature)
  };
}

function normalizePossessionReceiptStatement(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession receipt statement must be an object");
  const keys = Object.keys(input);
  const allowed = ["version", "enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint", "device_key_epoch", "challenge_nonce_digest", "issued_at"];
  if (keys.length !== allowed.length || keys.some((key) => !allowed.includes(key))) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession receipt statement has invalid fields");
  const issuedAt = input.issued_at;
  if (typeof issuedAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(issuedAt) || timestamp(issuedAt, "issued_at") !== issuedAt) {
    throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "issued_at is not canonical");
  }
  const statement = {
    version: input.version,
    enrollment_id: requiredUuid(input.enrollment_id, "enrollment_id"),
    organization_id: requiredUuid(input.organization_id, "organization_id"),
    device_id: requiredUuid(input.device_id, "device_id"),
    candidate_id: candidateIdValue(input.candidate_id),
    artifact_sha256: exactLowerPattern(input.artifact_sha256, SHA256, "artifact_sha256"),
    source_commit: exactLowerPattern(input.source_commit, /^[0-9a-f]{40}$/u, "source_commit"),
    team_id: exactPattern(input.team_id, /^[A-Z0-9]{10}$/u, "team_id"),
    device_key_fingerprint: deviceKeyFingerprint(input.device_key_fingerprint),
    device_key_epoch: safeInteger(input.device_key_epoch, "device_key_epoch"),
    challenge_nonce_digest: exactLowerPattern(input.challenge_nonce_digest, SHA256, "challenge_nonce_digest"),
    issued_at: issuedAt
  };
  if (statement.version !== 1) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "possession receipt statement version is invalid");
  return statement;
}

function assertPossessionReceiptBinding(receipt, { enrollmentId, organizationId, deviceId, candidate, fingerprint, challengeDigest }) {
  if (receipt.purpose !== "device-enrollment-possession-receipt"
    || receipt.statement.enrollment_id !== enrollmentId
    || receipt.statement.organization_id !== organizationId
    || receipt.statement.device_id !== deviceId
    || receipt.statement.candidate_id !== candidate.candidate_id
    || receipt.statement.artifact_sha256 !== candidate.artifact_sha256
    || receipt.statement.source_commit !== candidate.source_commit
    || receipt.statement.team_id !== candidate.team_id
    || receipt.statement.device_key_fingerprint !== fingerprint
    || receipt.statement.challenge_nonce_digest !== challengeDigest) {
    throw new ControlPlaneResourceRepositoryError("ERR_ENROLLMENT_BINDING", "possession receipt does not match its enrollment binding");
  }
}

function rejectRawPossessionMaterial(input) {
  const forbidden = new Set(["nonce", "rawnonce", "noncevalue", "challengenonce", "challenge", "challengeid", "credential", "credentialsecret", "privatekey", "privatekeypem"]);
  const visit = (value) => {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (forbidden.has(key.replace(/[_-]/gu, "").toLowerCase())) throw new ControlPlaneResourceRepositoryError("ERR_SECRET_MATERIAL", "raw possession material is not accepted");
      visit(child);
    }
  };
  visit(input);
}

function requiredPrincipalId(input) {
  const value = input.principalId ?? input.principal_id ?? input.createdBy ?? input.created_by ?? input.memberId ?? input.member_id;
  if (typeof value !== "string" || value.length < 1 || value.length > 255 || CONTROL.test(value)) throw new ControlPlaneResourceRepositoryError("ERR_PRINCIPAL_REQUIRED", "mutation requires an authenticated principal identifier");
  return value;
}

function tenant(input) { return requiredUuid(input?.organizationId ?? input?.organization_id, "organization_id"); }
function requiredUuid(value, label) { const result = optionalUuid(value, label); if (result === undefined) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_UUID", `${label} must be a canonical UUID`); return result; }
function optionalUuid(value, label) { if (value === undefined || value === null) return undefined; if (typeof value !== "string" || !UUID.test(value)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_UUID", `${label} must be a canonical UUID`); return value.toLowerCase(); }
function text(value, label, max, required = false) { if (typeof value !== "string" || (required && value.length === 0)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} must be a non-empty string`); if (CONTROL.test(value) || Buffer.byteLength(value, "utf8") > max) throw new ControlPlaneResourceRepositoryError("ERR_LIMIT_EXCEEDED", `${label} exceeds ${max} bytes or contains control characters`); return value; }
function publicKeyText(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} must be a non-empty string`);
  if (CONTROL.test(value.replace(/[\r\n]/g, "")) || Buffer.byteLength(value, "utf8") > MAX_TEXT_BYTES) throw new ControlPlaneResourceRepositoryError("ERR_LIMIT_EXCEEDED", `${label} exceeds ${MAX_TEXT_BYTES} bytes or contains control characters`);
  if (/PRIVATE\s+KEY|BEGIN\s+RSA|BEGIN\s+EC/i.test(value)) throw new ControlPlaneResourceRepositoryError("ERR_SECRET_MATERIAL", `${label} contains private key material`);
  if (!PUBLIC_KEY_BEGIN.test(value) || !PUBLIC_KEY_END.test(value)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} must be an SPKI public-key PEM`);
  return value;
}
function metadataValue(value) { if (value === undefined) return {}; if (!value || typeof value !== "object" || Array.isArray(value)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", "metadata must be an object"); if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_METADATA_BYTES) throw new ControlPlaneResourceRepositoryError("ERR_LIMIT_EXCEEDED", "metadata exceeds 16384 bytes"); return cloneJson(value); }
function object(value, label) { if (!value || typeof value !== "object" || Array.isArray(value)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} must be an object`); return value; }
function enumValue(value, label, allowed) { const result = text(value, label, 128, true); if (!allowed.has(result)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} is invalid`); return result; }
function sequenceValue(value, label) { const result = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value; if (!Number.isSafeInteger(result) || result < 0) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} must be a non-negative safe integer`); return result; }
function requiredVersion(value) { if (!Number.isSafeInteger(value) || value < 1) throw new ControlPlaneResourceRepositoryError("ERR_VERSION_REQUIRED", "expectedVersion must be a positive safe integer"); return value; }
function safeInteger(value, label) { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < 1) throw new ControlPlaneResourceRepositoryError("ERR_DATABASE", `stored ${label} is invalid`); return number; }
function timestamp(value, label) { if (value instanceof Date) value = value.toISOString(); if (typeof value !== "string" || !RFC3339_UTC.test(value) || !Number.isFinite(Date.parse(value))) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} must be a valid RFC 3339 UTC value`); return new Date(value).toISOString(); }
function nullableStoredTimestamp(value, label) { return value === null || value === undefined ? null : timestamp(value, label); }
function dateValue(value) { return Date.parse(value instanceof Date ? value.toISOString() : value); }
function sha256(value, label) { const result = text(value, label, 64, true); if (!SHA256.test(result)) throw new ControlPlaneResourceRepositoryError("ERR_INVALID_INPUT", `${label} must be SHA-256 hex`); return result.toLowerCase(); }
function sha256Hex(value) { return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex"); }
function deterministicUuid(kind, organizationId, principalId, idempotencyKey) { const bytes=crypto.createHash("sha256").update("AgentPass-Control-Resource-Id-v1\0").update(canonicalJson({kind,organization_id:organizationId,principal_id:principalId,idempotency_key:idempotencyKey})).digest().subarray(0,16); bytes[6]=(bytes[6]&0x0f)|0x50; bytes[8]=(bytes[8]&0x3f)|0x80; const hex=bytes.toString("hex"); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`; }
function requiredDeviceAlgorithm(value) { return enumValue(value, "key_algorithm", new Set(["p256-sha256", "ed25519"])); }
function assertAllowedPatch(patch, allowed, label) { for (const key of Object.keys(patch)) if (!allowed.has(key)) throw new ControlPlaneResourceRepositoryError("ERR_IMMUTABLE_FIELD", `${label}.${key} is not mutable`); }
function requireIdempotencyKey(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw new ControlPlaneResourceRepositoryError("ERR_IDEMPOTENCY_KEY_REQUIRED", "mutation requires an idempotency key of 8-255 safe characters"); return value; }
function notFound(label, id) { return new ControlPlaneResourceRepositoryError("ERR_NOT_FOUND", `${label} not found: ${id}`); }
function rowCount(result) { return result?.rowCount ?? result?.rows?.length ?? 0; }
function cloneJson(value) { return value === undefined ? undefined : structuredClone(value); }
function isEmptyObject(value) { return Object.keys(value).length === 0; }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)"); }
