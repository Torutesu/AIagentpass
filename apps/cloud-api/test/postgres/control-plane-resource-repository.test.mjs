import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  ControlPlaneResourceRepositoryError,
  createPostgresControlPlaneResourceRepository
} from "../../src/postgres/control-plane-resource-repository.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  organization2: "22222222-2222-4222-8222-222222222222",
  device: "33333333-3333-4333-8333-333333333333",
  device2: "44444444-4444-4444-8444-444444444444",
  enrollment: "55555555-5555-4555-8555-555555555555",
  agent: "66666666-6666-4666-8666-666666666666",
  policy: "77777777-7777-4777-8777-777777777777",
  member: "88888888-8888-4888-8888-888888888888"
};
const NOW = "2026-08-12T00:00:00.000Z";
const EXPIRES = "2026-08-12T00:15:00.000Z";
const DIGEST = "a".repeat(64);
const SCOPE = { operations: ["git.commit.sign"], repositories: ["/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } };
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----";

class FakeClient {
  constructor() {
    this.calls = [];
    this.idempotency = new Map();
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result();
    if (text.startsWith("SELECT id FROM organizations")) return result([{ id: params[0] }]);
    if (text.startsWith("DELETE FROM idempotency_records")) return result();
    if (text.startsWith("INSERT INTO idempotency_records")) {
      const key = params.slice(0, 3).join("/");
      if (this.idempotency.has(key)) return result();
      this.idempotency.set(key, { request_hash: params[3], response_status: 202, response_json: {} });
      return result([], 1);
    }
    if (text.startsWith("SELECT request_hash,response_status,response_json")) {
      const key = params.slice(0, 3).join("/");
      const row = this.idempotency.get(key);
      return row ? result([row]) : result();
    }
    if (text.startsWith("UPDATE idempotency_records")) {
      const key = params.slice(0, 3).join("/");
      const row = this.idempotency.get(key);
      if (!row) return result();
      row.response_status = params[3];
      row.response_json = JSON.parse(params[4]);
      return result([], 1);
    }
    if (text.startsWith("SELECT organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at\n        FROM devices")) return result([deviceRow()]);
    if (text.startsWith("SELECT organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at\n    FROM agents")) return result([agentRow()]);
    if (text.startsWith("SELECT organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version\n    FROM policies")) return result([policyRow()]);
    if (text.startsWith("SELECT organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at\n        FROM agents")) return result([agentRow()]);
    if (text.startsWith("SELECT organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version\n        FROM policies")) return result([policyRow()]);
    if (text.startsWith("INSERT INTO devices")) return result([deviceRow()], 1);
    if (text.startsWith("INSERT INTO device_enrollments")) return result([enrollmentRow()], 1);
    if (text.startsWith("INSERT INTO agents")) return result([agentRow()], 1);
    if (text.startsWith("INSERT INTO policies")) return result([policyRow()], 1);
    if (text.startsWith("UPDATE devices")) return result([deviceRow({ version: 2 })], 1);
    if (text.startsWith("UPDATE agents")) return result([agentRow({ version: 2 })], 1);
    if (text.startsWith("UPDATE policies")) return result([policyRow({ version: 2 })], 1);
    if (text.startsWith("SELECT id FROM devices")) return result([{ id: ids.device }]);
    if (text.startsWith("SELECT id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash")) return result([enrollmentRow()]);
    if (text.startsWith("SELECT organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at\n    FROM devices") && params[1] === ids.device2) return result([deviceRow({ id: ids.device2, label: "New Mac", key_algorithm: null, status: "pending", public_key_pem: null })]);
    if (text.startsWith("SELECT organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at\n    FROM devices")) return result([deviceRow()]);
    if (text.startsWith("UPDATE device_enrollments")) return result([enrollmentRow({ consumed_at: NOW, completion_hash: params[3] })], 1);
    if (text.startsWith("UPDATE devices SET key_algorithm")) return result([deviceRow({ status: "active", public_key_pem: PUBLIC_KEY, version: 2 })], 1);
    throw new Error(`unexpected SQL: ${text}`);
  }
}

function result(rows = [], rowCount = rows.length) { return { rows, rowCount }; }
function deviceRow(overrides = {}) { return { organization_id: ids.organization, id: ids.device, label: "Build Mac", key_algorithm: "ed25519", public_key_pem: PUBLIC_KEY, status: "active", metadata: {}, version: 1, created_at: NOW, last_seen_at: null, ...overrides }; }
function agentRow(overrides = {}) { return { organization_id: ids.organization, id: ids.agent, device_id: ids.device, kind: "claude-code", name: "Claude", public_key_pem: PUBLIC_KEY, status: "active", version: 1, created_at: NOW, last_seen_at: null, ...overrides }; }
function policyRow(overrides = {}) { return { organization_id: ids.organization, id: ids.policy, sequence: 1, name: "default", scope_json: SCOPE, status: "active", created_by: ids.member, created_at: NOW, updated_at: NOW, version: 1, ...overrides }; }
function enrollmentRow(overrides = {}) { return { id: ids.enrollment, organization_id: ids.organization, device_id: ids.device2, label: "New Mac", platform: "macos", created_at: NOW, expires_at: EXPIRES, consumed_at: null, completion_hash: null, ...overrides }; }
function repo(client = new FakeClient()) { return { repository: createPostgresControlPlaneResourceRepository({ client, now: () => NOW }), client }; }

test("exposes the CloudStore resource API and requires tenant-scoped identity", () => {
  const { repository } = repo();
  assert.equal(Object.isFrozen(repository), true);
  assert.deepEqual(Object.keys(repository).sort(), [
    "completeDeviceEnrollment", "createAgent", "createDevice", "createDeviceEnrollment", "createPolicy",
    "getAgent", "getDevice", "getPolicy", "listAgents", "listDevices", "listPolicies", "updateAgent", "updateDevice", "updatePolicy"
  ].sort());
  assert.rejects(repository.listDevices({ organization_id: "not-a-uuid" }), { code: "ERR_INVALID_UUID" });
});

test("creates a device with tenant-qualified SQL, safe idempotency, and the CloudStore shape", async () => {
  const { repository, client } = repo();
  const device = await repository.createDevice({ organization_id: ids.organization, device_id: ids.device, name: "Build Mac", public_key: PUBLIC_KEY, key_algorithm: "ed25519", principal_id: ids.member, idempotency_key: "device-create-1" });
  assert.deepEqual(device, { device_id: ids.device, organization_id: ids.organization, name: "Build Mac", device_public_key: PUBLIC_KEY, key_algorithm: "ed25519", status: "active", metadata: {}, created_at: NOW, version: 1 });
  const insert = client.calls.find((call) => call.text.startsWith("INSERT INTO devices"));
  assert.match(insert.text, /organization_id,id,label,key_algorithm,public_key_pem,status/);
  assert.equal(insert.params[0], ids.organization);
  assert.equal(client.calls.some((call) => /FROM devices/.test(call.text) && !/organization_id=\$1/.test(call.text)), false);
  const replay = await repository.createDevice({ organization_id: ids.organization, device_id: ids.device, name: "Build Mac", public_key: PUBLIC_KEY, key_algorithm: "ed25519", principal_id: ids.member, idempotency_key: "device-create-1" });
  assert.deepEqual(replay, device);
});

test("lists and updates resources with tenant scope and optimistic versions", async () => {
  const { repository, client } = repo();
  const devices = await repository.listDevices({ organization_id: ids.organization });
  assert.equal(devices[0].device_id, ids.device);
  const updated = await repository.updateDevice({ organization_id: ids.organization, device_id: ids.device, expected_version: 1, patch: { status: "revoked" }, principal_id: ids.member, idempotency_key: "device-update-1" });
  assert.equal(updated.version, 2);
  const update = client.calls.find((call) => call.text.startsWith("UPDATE devices"));
  assert.match(update.text, /WHERE organization_id=\$1 AND id=\$2 AND version=\$3/);
  assert.equal((await repository.listAgents({ organization_id: ids.organization }))[0].agent_id, ids.agent);
});

test("persists device metadata and updates policies with optimistic versions", async () => {
  const { repository } = repo();
  assert.equal((await repository.updateDevice({ organization_id: ids.organization, device_id: ids.device, expected_version: 1, patch: { metadata: { environment: "prod" } }, principal_id: ids.member, idempotency_key: "device-metadata-1" })).version, 2);
  assert.equal((await repository.updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: { status: "disabled" }, principal_id: ids.member, idempotency_key: "policy-update-1" })).version, 2);
});

test("fails closed for schema-required actor attribution instead of inventing it", async () => {
  const { repository } = repo();
  await assert.rejects(repository.createDeviceEnrollment({ organization_id: ids.organization, enrollment_id: ids.enrollment, device_id: ids.device2, label: "New Mac", platform: "macos", credential_digest: DIGEST, created_at: NOW, expires_at: EXPIRES, principal_id: ids.member, idempotency_key: "enrollment-1" }), { code: "ERR_ACTOR_REQUIRED" });
  await assert.rejects(repository.createPolicy({ organization_id: ids.organization, policy_id: ids.policy, name: "default", scope: SCOPE, sequence: 1, principal_id: ids.member, idempotency_key: "policy-2" }), { code: "ERR_ACTOR_REQUIRED" });
});

test("reserves a pending device before its hardware key algorithm is known", async () => {
  const { repository, client } = repo();
  const enrollment = await repository.createDeviceEnrollment({ organization_id: ids.organization, enrollment_id: ids.enrollment, device_id: ids.device2, label: "New Mac", platform: "macos", credential_digest: DIGEST, created_at: NOW, expires_at: EXPIRES, created_by: ids.member, principal_id: ids.member, idempotency_key: "enrollment-2" });
  assert.equal(enrollment.device_id, ids.device2);
  const replay = await repository.createDeviceEnrollment({ organization_id: ids.organization, enrollment_id: ids.enrollment, device_id: ids.device2, label: "New Mac", platform: "macos", credential_digest: DIGEST, created_at: "2026-08-12T00:01:00.000Z", expires_at: "2026-08-12T00:16:00.000Z", created_by: ids.member, principal_id: ids.member, idempotency_key: "enrollment-2" });
  assert.deepEqual(replay, enrollment);
  assert.equal(client.calls.filter(({ text }) => text.startsWith("INSERT INTO device_enrollments")).length, 1);
});

test("maps agent and policy rows into the exact resource field names", async () => {
  const { repository } = repo();
  const agent = await repository.createAgent({ organization_id: ids.organization, agent_id: ids.agent, device_id: ids.device, version: 1, name: "Claude", kind: "claude-code", public_key: PUBLIC_KEY, created_at: NOW, principal_id: ids.member, idempotency_key: "agent-create-1" });
  assert.equal(agent.agent_id, ids.agent);
  assert.equal(agent.public_key, PUBLIC_KEY);
  assert.equal(agent.device_id, ids.device);
  const policy = await repository.getPolicy({ organization_id: ids.organization, policy_id: ids.policy });
  assert.deepEqual(policy.scope, SCOPE);
});

test("uses row locks and one-time credential matching for completion", async () => {
  const { repository, client } = repo();
  const completed = await repository.completeDeviceEnrollment({ organization_id: ids.organization, enrollment_id: ids.enrollment, device_id: ids.device2, label: "New Mac", platform: "macos", algorithm: "ed25519", public_key: PUBLIC_KEY, credential_digest: DIGEST, completed_at: NOW });
  assert.equal(completed.status, "active");
  const lookup = client.calls.find((call) => call.text.startsWith("SELECT id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash"));
  assert.match(lookup.text, /organization_id=\$1 AND id=\$2 AND encode\(secret_hash,'hex'\)=\$3/);
  assert.match(lookup.text, /FOR UPDATE/);
  assert.equal(client.calls.some((call) => call.text.includes("secret_hash") && /SELECT\s+\*/.test(call.text)), false);
});

test("does not leak database error details", async () => {
  const client = new FakeClient();
  const originalQuery = client.query.bind(client);
  client.query = async (text, params) => {
    if (text.startsWith("INSERT INTO agents")) { const error = new Error("password=do-not-leak"); error.code = "XX000"; throw error; }
    return originalQuery(text, params);
  };
  const { repository } = repo(client);
  await assert.rejects(repository.createAgent({ organization_id: ids.organization, agent_id: ids.agent, device_id: ids.device, version: 1, name: "Claude", kind: "claude-code", public_key: PUBLIC_KEY, created_at: NOW, principal_id: ids.member, idempotency_key: "agent-error-1" }), (error) => error instanceof ControlPlaneResourceRepositoryError && error.code === "ERR_DATABASE" && !error.message.includes("do-not-leak"));
});
