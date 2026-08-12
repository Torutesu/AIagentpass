import crypto from "node:crypto";

import { normalizeAgentDescriptor, normalizeScope, canonicalJson } from "../../../../packages/protocol/src/index.mjs";
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
        return mapDevice(device);
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
      return mapDevice(update.rows[0]);
    }));
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
