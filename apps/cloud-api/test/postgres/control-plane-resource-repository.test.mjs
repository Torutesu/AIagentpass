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
  constructor({ deviceAuthRow = undefined, policySelectRow = undefined, policyUpdateRow = undefined } = {}) {
    this.calls = [];
    this.idempotency = new Map();
    this.deviceAuthRow = deviceAuthRow;
    this.policySelectRow = policySelectRow;
    this.policyUpdateRow = policyUpdateRow;
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
    if (text.startsWith("SELECT devices.organization_id,devices.id,devices.label,devices.key_algorithm") && text.includes("device_control_plane_state")) return result([deviceRow({
      desired_generation: "7",
      observed_generation: "6",
      refresh_state: "blocked",
      current_bundle_sequence: "12",
      current_bundle_expires_at: new Date(EXPIRES),
      last_ack_observed_at: new Date(NOW),
      last_ack_received_at: new Date(NOW),
      blocked_reason: "bundle_signature_invalid"
    })]);
    if (text.startsWith("SELECT devices.organization_id,devices.id,devices.label,devices.key_algorithm")) return result([this.deviceAuthRow ?? deviceRow()]);
    if (text.startsWith("SELECT organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at\n    FROM agents")) return result([agentRow()]);
    if (text.startsWith("SELECT organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version\n    FROM policies")) return result([this.policySelectRow ?? policyRow()]);
    if (text.startsWith("SELECT organization_id,id,device_id,kind,name,public_key_pem,status,version,created_at,last_seen_at\n        FROM agents")) return result([agentRow()]);
    if (text.startsWith("SELECT organization_id,id,sequence,name,scope_json,status,created_by,created_at,updated_at,version\n        FROM policies")) return result([this.policySelectRow ?? policyRow()]);
    if (text.startsWith("INSERT INTO devices")) return result([deviceRow()], 1);
    if (text.startsWith("INSERT INTO device_enrollments")) return result([enrollmentRow()], 1);
    if (text.startsWith("INSERT INTO agents")) return result([agentRow()], 1);
    if (text.startsWith("INSERT INTO policies")) return result([policyRow()], 1);
    if (text.startsWith("UPDATE devices")) return result([deviceRow({ version: 2 })], 1);
    if (text.startsWith("UPDATE agents")) return result([agentRow({ version: 2 })], 1);
    if (text.startsWith("UPDATE policies")) return result([this.policyUpdateRow ?? policyRow({ version: 2 })], 1);
    if (text.startsWith("SELECT id FROM devices")) return result([{ id: ids.device }]);
    if (text.startsWith("SELECT id,organization_id,device_id,label,platform,created_at,expires_at,consumed_at,completion_hash")) return result([enrollmentRow()]);
    if (text.startsWith("SELECT key_epoch,public_key_pem,status")) return result([{ key_epoch: 1, public_key_pem: PUBLIC_KEY, status: "active" }]);
    if (text.startsWith("SELECT organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at\n    FROM devices") && params[1] === ids.device2) return result([deviceRow({ id: ids.device2, label: "New Mac", key_algorithm: null, status: "pending", public_key_pem: null })]);
    if (text.startsWith("SELECT organization_id,id,label,key_algorithm,public_key_pem,status,metadata,version,created_at,last_seen_at\n    FROM devices")) return result([deviceRow()]);
    if (text.startsWith("UPDATE device_enrollments")) return result([enrollmentRow({ consumed_at: NOW, completion_hash: params[3] })], 1);
    if (text.startsWith("UPDATE devices SET key_algorithm")) return result([deviceRow({ status: "active", public_key_pem: PUBLIC_KEY, version: 2 })], 1);
    throw new Error(`unexpected SQL: ${text}`);
  }
}

function result(rows = [], rowCount = rows.length) { return { rows, rowCount }; }
function deviceRow(overrides = {}) {
  const row = { organization_id: ids.organization, id: ids.device, label: "Build Mac", key_algorithm: "ed25519", public_key_pem: PUBLIC_KEY, status: "active", metadata: {}, version: 1, created_at: NOW, last_seen_at: null, active_key_epoch: 1, active_public_key_pem: PUBLIC_KEY, active_key_epoch_status: "active", active_key_epoch_count: "1", ...overrides };
  if (row.status !== "active" || row.public_key_pem === null) {
    if (!Object.hasOwn(overrides, "active_key_epoch")) row.active_key_epoch = null;
    if (!Object.hasOwn(overrides, "active_public_key_pem")) row.active_public_key_pem = null;
    if (!Object.hasOwn(overrides, "active_key_epoch_status")) row.active_key_epoch_status = null;
    if (!Object.hasOwn(overrides, "active_key_epoch_count")) row.active_key_epoch_count = "0";
  }
  return row;
}
function agentRow(overrides = {}) { return { organization_id: ids.organization, id: ids.agent, device_id: ids.device, kind: "claude-code", name: "Claude", public_key_pem: PUBLIC_KEY, status: "active", version: 1, created_at: NOW, last_seen_at: null, ...overrides }; }
function policyRow(overrides = {}) { return { organization_id: ids.organization, id: ids.policy, sequence: 1, name: "default", scope_json: SCOPE, status: "active", created_by: ids.member, created_at: NOW, updated_at: NOW, version: 1, ...overrides }; }
function enrollmentRow(overrides = {}) { return { id: ids.enrollment, organization_id: ids.organization, device_id: ids.device2, label: "New Mac", platform: "macos", created_at: NOW, expires_at: EXPIRES, consumed_at: null, completion_hash: null, ...overrides }; }
function repo(client = new FakeClient()) { return { repository: createPostgresControlPlaneResourceRepository({ client, now: () => NOW }), client }; }

test("exposes the CloudStore resource API and requires tenant-scoped identity", () => {
  const { repository } = repo();
  assert.equal(Object.isFrozen(repository), true);
  assert.deepEqual(Object.keys(repository).sort(), [
    "completeDeviceEnrollment", "createAgent", "createDevice", "createDeviceEnrollment", "createPolicy",
    "getAgent", "getDevice", "getPolicy", "listAgents", "listDeviceReadModels", "listDevices", "listPolicies", "updateAgent", "updateDevice", "updatePolicy"
  ].sort());
  assert.rejects(repository.listDevices({ organization_id: "not-a-uuid" }), { code: "ERR_INVALID_UUID" });
});

test("lists the authoritative device read model with one bounded query and no sensitive bundle fields", async () => {
  const { repository, client } = repo();
  const [device] = await repository.listDeviceReadModels({ organization_id: ids.organization });
  assert.deepEqual(device, {
    device_id: ids.device,
    name: "Build Mac",
    status: "active",
    created_at: NOW,
    last_seen_at: null,
    version: 1,
    desired_generation: 7,
    observed_generation: 6,
    refresh_state: "blocked",
    bundle_sequence: 12,
    bundle_expires_at: EXPIRES,
    last_ack_at: NOW,
    blocked_reason: "bundle_signature_invalid"
  });
  assert.deepEqual(Object.keys(device).filter((key) => /signature|nonce|policy|statement_hash|refresh_nonce_digest|private_key/iu.test(key)), []);
  const readModelQueries = client.calls.filter(({ text }) => text.includes("device_control_plane_state"));
  assert.equal(readModelQueries.length, 1);
  assert.match(readModelQueries[0].text, /WHERE devices\.organization_id=\$1/);
  assert.match(readModelQueries[0].text, /LEFT JOIN LATERAL/);
  assert.equal(readModelQueries[0].params[0], ids.organization);
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

test("returns active immutable key metadata without changing the public device shape", async () => {
  const { repository, client } = repo();
  const device = await repository.getDevice({ organization_id: ids.organization, device_id: ids.device });
  assert.equal(device.key_epoch, 1);
  assert.equal(device.authentication_public_key, PUBLIC_KEY);
  assert.equal(Object.prototype.propertyIsEnumerable.call(device, "key_epoch"), false);
  assert.equal(Object.prototype.propertyIsEnumerable.call(device, "authentication_public_key"), false);
  assert.equal(Object.hasOwn(device, "private_key"), false);
  assert.doesNotMatch(JSON.stringify(device), /key_epoch|PRIVATE KEY/u);
  const listed = (await repository.listDevices({ organization_id: ids.organization }))[0];
  assert.equal(listed.key_epoch, 1);
  assert.equal(listed.authentication_public_key, PUBLIC_KEY);
  assert.equal(Object.prototype.propertyIsEnumerable.call(listed, "key_epoch"), false);
  assert.doesNotMatch(JSON.stringify(listed), /key_epoch|PRIVATE KEY/u);
  const lookup = client.calls.find(({ text }) => text.startsWith("SELECT devices.organization_id"));
  assert.match(lookup.text, /device_key_epochs/u);
  assert.doesNotMatch(lookup.text, /private[_ ]key/iu);
});

test("fails closed when an active device has no unique current epoch or exact public key", async () => {
  const invalidRows = [
    { active_key_epoch_count: "0", active_key_epoch: null, active_public_key_pem: null, active_key_epoch_status: null },
    { active_key_epoch_count: "2" },
    { active_key_epoch_status: "retired" },
    { active_public_key_pem: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----" },
    { active_public_key_pem: PUBLIC_KEY.replace("MCow", "MCox") }
  ];
  for (const overrides of invalidRows) {
    const client = new FakeClient({ deviceAuthRow: deviceRow(overrides) });
    const { repository } = repo(client);
    for (const lookup of [
      () => repository.listDevices({ organization_id: ids.organization }),
      () => repository.getDevice({ organization_id: ids.organization, device_id: ids.device })
    ]) {
      await assert.rejects(lookup, (error) => {
        assert.ok(error instanceof ControlPlaneResourceRepositoryError);
        assert.equal(error.code, "ERR_DEVICE_AUTH_UNAVAILABLE");
        assert.doesNotMatch(error.message, /PRIVATE KEY|secret/u);
        return true;
      });
    }
  }
});

test("persists device metadata and updates policies with optimistic versions", async () => {
  const { repository } = repo();
  assert.equal((await repository.updateDevice({ organization_id: ids.organization, device_id: ids.device, expected_version: 1, patch: { metadata: { environment: "prod" } }, principal_id: ids.member, idempotency_key: "device-metadata-1" })).version, 2);
  assert.equal((await repository.updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: { status: "disabled" }, principal_id: ids.member, idempotency_key: "policy-update-1" })).version, 2);
});

test("invokes the frozen authority hook inside the transaction for active policy reductions", async () => {
  const reductions = [];
  const client = new FakeClient({ policyUpdateRow: policyRow({ status: "disabled", version: 2 }) });
  const updated = await createPostgresControlPlaneResourceRepository({
    client,
    now: () => NOW,
    onAuthorityReduction: async (input) => {
      reductions.push(input);
      assert.equal(input.tx, client);
      assert.equal(Object.isFrozen(input), true);
      assert.equal(Object.isFrozen(input.policy), true);
      assert.equal(Object.isFrozen(input.policy.scope), true);
      assert.equal(input.organization_id, ids.organization);
      assert.equal(input.policy.policy_id, ids.policy);
      assert.equal(input.actor_member_id, ids.member);
      assert.equal(input.idempotency_key, "policy-reduce-1");
      assert.throws(() => { input.policy.status = "active"; }, TypeError);
      return { generation: 2 };
    }
  }).updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: { status: "disabled" }, principal_id: ids.member, idempotency_key: "policy-reduce-1" });
  assert.equal(updated.status, "disabled");
  assert.equal(reductions.length, 1);
  assert.ok(client.calls.findIndex(({ text }) => text.startsWith("UPDATE policies")) < client.calls.findIndex(({ text }) => text.startsWith("UPDATE idempotency_records")));
});

test("rolls back a policy reduction when generation propagation is unavailable", async () => {
  for (const onAuthorityReduction of [async () => undefined, async () => { throw new Error("authority backend unavailable"); }]) {
    const client = new FakeClient({ policyUpdateRow: policyRow({ status: "disabled", version: 2 }) });
    const repository = createPostgresControlPlaneResourceRepository({ client, now: () => NOW, onAuthorityReduction });
    await assert.rejects(
      repository.updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: { status: "disabled" }, principal_id: ids.member, idempotency_key: "policy-fail-closed-1" }),
      (error) => ["ERR_AUTHORITY_REDUCTION_UNAVAILABLE", "ERR_DATABASE"].includes(error.code)
    );
    assert.equal(client.calls.at(-1).text, "ROLLBACK");
    assert.equal(client.calls.some(({ text }) => text.startsWith("UPDATE idempotency_records")), false);
  }
});

test("does not invoke the policy authority hook for a proven widening, but does so conservatively for ambiguous active changes", async () => {
  const wideningScope = { ...SCOPE, operations: ["git.commit.sign"], repositories: ["/repo", "/other"] };
  const wideningCalls = [];
  const wideningClient = new FakeClient({
    policySelectRow: policyRow(),
    policyUpdateRow: policyRow({ scope_json: wideningScope, version: 2 })
  });
  await createPostgresControlPlaneResourceRepository({ client: wideningClient, now: () => NOW, onAuthorityReduction: async (input) => { wideningCalls.push(input); return { generation: 2 }; } }).updatePolicy({
    organization_id: ids.organization, policy_id: ids.policy, expected_version: 1,
    patch: { scope: wideningScope }, principal_id: ids.member, idempotency_key: "policy-widen-1"
  });
  assert.equal(wideningCalls.length, 0);

  const ambiguousCalls = [];
  const ambiguousClient = new FakeClient({ policyUpdateRow: policyRow({ version: 2, name: "renamed" }) });
  await createPostgresControlPlaneResourceRepository({ client: ambiguousClient, now: () => NOW, onAuthorityReduction: async (input) => { ambiguousCalls.push(input); return { generation: 2 }; } }).updatePolicy({
    organization_id: ids.organization, policy_id: ids.policy, expected_version: 1,
    patch: { name: "renamed" }, principal_id: ids.member, idempotency_key: "policy-ambiguous-1"
  });
  assert.equal(ambiguousCalls.length, 1);
});

test("treats scope narrowing, deny changes, tag ambiguity, and active-to-disabled as reductions, while exact replay stays silent", async () => {
  const cases = [
    { name: "narrow repository", patch: { scope: { ...SCOPE, repositories: ["/repo/sub"] } }, update: { scope_json: { ...SCOPE, repositories: ["/repo/sub"] } } },
    { name: "add deny", patch: { scope: { ...SCOPE, branches: { allow: ["main"], deny: ["release/*"] } } }, update: { scope_json: { ...SCOPE, branches: { allow: ["main"], deny: ["release/*"] } } } },
    { name: "ambiguous optional tags", patch: { scope: { ...SCOPE, tags: { allow: ["v1"], deny: [] } } }, update: { scope_json: { ...SCOPE, tags: { allow: ["v1"], deny: [] } } } },
    { name: "disable", patch: { status: "disabled" }, update: { status: "disabled" } }
  ];
  for (const [index, item] of cases.entries()) {
    const calls = [];
    const key = `policy-reduce-${index + 2}`;
    const client = new FakeClient({ policyUpdateRow: policyRow({ ...item.update, version: 2 }) });
    const repository = createPostgresControlPlaneResourceRepository({ client, now: () => NOW, onAuthorityReduction: async (input) => { calls.push(input); return { generation: 2 }; } });
    await repository.updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: item.patch, principal_id: ids.member, idempotency_key: key });
    await repository.updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: item.patch, principal_id: ids.member, idempotency_key: key });
    assert.equal(calls.length, 1, item.name);
  }
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
  assert.equal(completed.key_epoch, 1);
  const epochLookup = client.calls.find((call) => call.text.startsWith("SELECT key_epoch,public_key_pem,status"));
  assert.match(epochLookup.text, /device_key_epochs/);
  assert.match(epochLookup.text, /FOR SHARE/);
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
