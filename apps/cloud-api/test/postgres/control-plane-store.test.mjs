import assert from "node:assert/strict";
import test from "node:test";

import {
  CONTROL_PLANE_STORE_ERROR_CODES,
  CONTROL_PLANE_STORE_METHODS,
  ControlPlaneStoreError,
  createPostgresControlPlaneStore
} from "../../src/postgres/control-plane-store.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const memberId = "22222222-2222-4222-8222-222222222222";
const deviceId = "33333333-3333-4333-8333-333333333333";

function repositories(overrides = {}) {
  const calls = [];
  const methods = [
    "appendAdminAuditEvent", "assignBundleHead", "completeDeviceEnrollment", "createAgent", "createDevice",
    "createDeviceEnrollment", "createPolicy", "createRevocation", "getAuditHealth", "getOrganization",
    "ingestDeviceAuditEvents", "issueCapabilityMetadata", "listAdminAuditEvents", "listAgents", "listCapabilities",
    "listDeviceAuditEvents", "listDevices", "listPolicies", "listRevocations", "listRevokedCapabilityIds",
    "reserveCapability", "updatePolicy", "snapshotAndAssignBundleHead", "pollDeviceRefresh",
    "getDeviceRefreshState", "acknowledgeBundle"
  ];
  const repository = Object.fromEntries(methods.map((method) => [method, async (input) => {
    calls.push({ method, input });
    return { method };
  }]));
  return { calls, repository: { ...repository, ...overrides } };
}

test("exposes exactly the Cloud server contract and freezes the facade", () => {
  const { repository } = repositories();
  const store = createPostgresControlPlaneStore({
    organizationRepository: repository,
    resourceRepository: repository,
    authorityRepository: repository,
    auditRepository: repository,
    adminAuditRepository: repository,
    capabilityAuthorityRepository: repository,
    sharedControlRepository: { withTransaction() {} }
  });
  assert.equal(Object.isFrozen(store), true);
  assert.deepEqual(Object.keys(store).sort(), [...CONTROL_PLANE_STORE_METHODS].sort());
});

test("exposes hosted device-plane methods without widening the enumerable admin contract", async () => {
  const { repository, calls } = repositories();
  const store = createPostgresControlPlaneStore({ authorityRepository: repository });
  for (const method of ["snapshotAndAssignBundleHead", "pollDeviceRefresh", "getDeviceRefreshState", "acknowledgeBundle"]) {
    const descriptor = Object.getOwnPropertyDescriptor(store, method);
    assert.equal(typeof store[method], "function");
    assert.equal(descriptor.enumerable, false);
  }

  await store.snapshotAndAssignBundleHead({ organizationId, deviceId, private_key: "-----BEGIN PRIVATE KEY-----secret" });
  await store.pollDeviceRefresh({ organizationId, deviceId, after_generation: 4, privateKey: "private-secret" });
  await store.getDeviceRefreshState({ organizationId, deviceId, secret_key: "secret", principal: { private_key: "nested-private" } });
  await store.acknowledgeBundle({ organizationId, deviceId, type: "bundle-ack.v1", signature: "public-signature", private_key_pem: "private-secret" });

  assert.deepEqual(calls.map(({ method }) => method), [
    "snapshotAndAssignBundleHead", "pollDeviceRefresh", "getDeviceRefreshState", "acknowledgeBundle"
  ]);
  for (const { input } of calls) {
    assert.equal(input.organization_id, organizationId);
    assert.equal(Object.hasOwn(input, "private_key"), false);
    assert.equal(Object.hasOwn(input, "privateKey"), false);
    assert.equal(Object.hasOwn(input, "private_key_pem"), false);
    assert.equal(Object.hasOwn(input, "secret_key"), false);
    assert.doesNotMatch(JSON.stringify(input), /private-secret|nested-private|BEGIN PRIVATE KEY/u);
    assert.equal(input.principal?.private_key, undefined);
  }
  assert.deepEqual(Object.keys(store).sort(), [...CONTROL_PLANE_STORE_METHODS].sort());
});

test("qualifies every delegated tenant request without accepting an unscoped call", async () => {
  const { repository, calls } = repositories();
  const store = createPostgresControlPlaneStore({ resourceRepository: repository });
  await store.listDevices({ organizationId, limit: 12 });
  assert.deepEqual(calls[0].input, { organizationId, organization_id: organizationId, limit: 12 });
  await assert.rejects(store.listDevices({}), (error) => error.code === CONTROL_PLANE_STORE_ERROR_CODES.TENANT_SCOPE);
  assert.equal(calls.length, 1);
});

test("propagates safe actor/principal identity while dropping session and bearer material", async () => {
  const { repository, calls } = repositories();
  const store = createPostgresControlPlaneStore({ authorityRepository: repository });
  await store.createRevocation({
    organizationId,
    targetType: "device",
    targetId: deviceId,
    reason: "operator request",
    idempotencyKey: "revoke-device-1",
    actor: { member_id: memberId, organization_id: organizationId, role: "admin", session_id: "session-secret" },
    principal: { member_id: memberId, bearer_token: "bearer-secret", private_key: "private-secret" }
  });
  const input = calls[0].input;
  assert.equal(input.organization_id, organizationId);
  assert.equal(input.actor_member_id, memberId);
  assert.equal(input.principal_id, memberId);
  assert.equal(input.created_by, memberId);
  assert.deepEqual(input.actor, { member_id: memberId, organization_id: organizationId, role: "admin" });
  assert.deepEqual(input.principal, { member_id: memberId });
  assert.equal(Object.hasOwn(input, "session_id"), false);
  assert.equal(Object.hasOwn(input, "bearer_token"), false);
  assert.equal(Object.hasOwn(input, "private_key"), false);
});

test("routes hosted revocations through the commit-coupled generation and outbox reduction", async () => {
  const calls = [];
  const revocation = { revocation_id: "44444444-4444-4444-8444-444444444444", organization_id: organizationId };
  const store = createPostgresControlPlaneStore({
    authorityRepository: {
      async reduceAuthorityAndEnqueueRefresh(input) {
        calls.push(input);
        return { organization_id: organizationId, generation: 3, devices: [], revocation };
      }
    }
  });
  const result = await store.createRevocation({ organizationId, targetType: "device", targetId: deviceId, reason: "operator", createdBy: memberId, idempotencyKey: "revoke-device-3" });
  assert.equal(result, revocation);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].organization_id, organizationId);
  assert.equal(calls[0].reduction.organization_id, organizationId);
  assert.equal(calls[0].reduction.targetId, deviceId);
});

test("maps database failures to one constant public error without a cause", async () => {
  const { repository } = repositories({ listDevices: async () => { throw new Error("password=secret relation=private"); } });
  const store = createPostgresControlPlaneStore({ resourceRepository: repository });
  const first = await assert.rejects(store.listDevices({ organizationId }), (error) => {
    assert.ok(error instanceof ControlPlaneStoreError);
    assert.equal(error.code, CONTROL_PLANE_STORE_ERROR_CODES.DATABASE);
    assert.equal(error.status, 503);
    assert.equal(error.message, "control-plane database operation failed");
    assert.equal(Object.hasOwn(error, "cause"), false);
    assert.doesNotMatch(error.message, /secret|password|private/);
    return true;
  });
  await assert.rejects(store.listDevices({ organizationId }), (error) => {
    assert.equal(error.code, CONTROL_PLANE_STORE_ERROR_CODES.DATABASE);
    assert.equal(error.message, "control-plane database operation failed");
    return true;
  });
  assert.equal(first, undefined);
});

test("fails closed for server methods with no safe PostgreSQL mapping", async () => {
  const store = createPostgresControlPlaneStore({});
  for (const method of ["getOrganization", "reserveCapability", "listCapabilities", "appendAdminAuditEvent", "listAdminAuditEvents", "snapshotAndAssignBundleHead", "pollDeviceRefresh", "getDeviceRefreshState", "acknowledgeBundle"]) {
    await assert.rejects(store[method]({ organizationId }), (error) => {
      assert.equal(error.code, CONTROL_PLANE_STORE_ERROR_CODES.METHOD_UNAVAILABLE);
      assert.equal(error.status, 503);
      assert.equal(error.message, "control-plane operation is unavailable");
      return true;
    });
  }
});

test("runs a mutation and its audit append through one caller-owned transaction boundary", async () => {
  const calls = [];
  const tx = { marker: "tx" };
  const sharedControlRepository = {
    async withTransaction(operation) {
      calls.push("begin");
      try {
        const result = await operation(tx);
        calls.push("commit");
        return result;
      } catch (error) {
        calls.push("rollback");
        throw error;
      }
    }
  };
  const adminAuditRepository = {
    async appendAdminAuditEventInTransaction(input) {
      calls.push({ audit: input, tx: input.tx });
      return { audit_event_id: "44444444-4444-4444-8444-444444444444" };
    }
  };
  const store = createPostgresControlPlaneStore({ sharedControlRepository, adminAuditRepository });
  const result = await store.runAtomicMutation({
    organizationId,
    mutation: async ({ tx: receivedTx }) => {
      calls.push({ mutation: receivedTx });
      return { device_id: deviceId };
    },
    audit: ({ mutation }) => ({
      organizationId, actorId: memberId, eventType: "device.revoked", targetType: "device", targetId: deviceId,
      idempotencyKey: "device-revoke-0001:audit", details: { device_id: mutation.device_id }
    })
  });
  assert.deepEqual(result, {
    mutation: { device_id: deviceId },
    audit: { audit_event_id: "44444444-4444-4444-8444-444444444444" }
  });
  assert.equal(calls[0], "begin");
  assert.equal(calls[1].mutation, tx);
  assert.equal(calls[2].audit.tx, tx);
  assert.equal(calls[3], "commit");
});

test("rolls back the caller-owned boundary when the audit append fails", async () => {
  const calls = [];
  const sharedControlRepository = {
    async withTransaction(operation) {
      calls.push("begin");
      try {
        return await operation({ marker: "tx" });
      } catch (error) {
        calls.push("rollback");
        throw error;
      }
    }
  };
  const store = createPostgresControlPlaneStore({
    sharedControlRepository,
    adminAuditRepository: { async appendAdminAuditEventInTransaction() { calls.push("audit"); throw new Error("audit unavailable"); } }
  });
  await assert.rejects(store.runAtomicMutation({
    organizationId,
    mutation: async () => { calls.push("mutation"); return { changed: true }; },
    audit: { organizationId, actorId: memberId, eventType: "device.revoked", targetType: "device", targetId: deviceId, idempotencyKey: "device-revoke-0002:audit" }
  }), (error) => error instanceof ControlPlaneStoreError && error.status === 503);
  assert.deepEqual(calls, ["begin", "mutation", "audit", "rollback"]);
});
