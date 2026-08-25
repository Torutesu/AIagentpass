import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { createPostgresAgentSessionConsumptionRepository } from "../src/postgres/agent-session-consumption-repository.mjs";

const ids = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  grant: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  device: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555",
  event: "66666666-6666-4666-8666-666666666666"
});
const HASHES = Object.freeze({
  statement: "b".repeat(64),
  process: "c".repeat(64),
  ancestry: "d".repeat(64),
  worktree: "e".repeat(64),
  event: "f".repeat(64)
});
const CONSUMED_AT = "2026-08-13T10:00:00.000Z";
const KEY_ID = "agent-session-key-v1";
const PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----do-not-publish-----END PRIVATE KEY-----";
const RAW_BODY = "raw grant body that must remain outside the outbox";

const grant = Object.freeze({
  version: 1,
  type: "agentpass.agent-session-grant",
  statement: Object.freeze({
    organization_id: ids.organization,
    grant_id: ids.grant,
    device_id: ids.device,
    agent_id: ids.agent,
    key_id: KEY_ID,
    private_key: PRIVATE_KEY,
    raw_body: RAW_BODY
  }),
  statement_hash: HASHES.statement,
  signature: "signed-envelope-value",
  private_key: PRIVATE_KEY,
  raw_body: RAW_BODY
});
const GRANT_HASH = crypto.createHash("sha256").update(canonicalJson(grant), "utf8").digest("hex");

const lease = Object.freeze({
  organization_id: ids.organization,
  grant_id: ids.grant,
  session_id: ids.session,
  device_id: ids.device,
  agent_id: ids.agent,
  grant_hash: GRANT_HASH,
  statement_hash: HASHES.statement,
  process_binding_sha256: HASHES.process,
  ancestry_binding_sha256: HASHES.ancestry,
  worktree_binding_sha256: HASHES.worktree,
  control_sequence: 17,
  authority_generation: 23
});

const auditEvent = Object.freeze({
  event_id: ids.event,
  event_hash: HASHES.event,
  grant_id: ids.grant,
  session_id: ids.session,
  device_id: ids.device,
  agent_id: ids.agent,
  grant_hash: GRANT_HASH,
  statement_hash: HASHES.statement,
  consumed_at: CONSUMED_AT,
  signature: "audit signature must not be published",
  private_key: PRIVATE_KEY,
  raw_body: RAW_BODY
});

function createHarness({ existingStatus, existingChanges = {}, auditError, outboxError } = {}) {
  const calls = [];
  let successfulOutboxInsertions = 0;
  const tx = {
    async query(text, params = []) {
      calls.push({ text, params: structuredClone(params) });
      if (text.startsWith("INSERT INTO outbox_events")) {
        if (outboxError) throw outboxError;
        const [, id, serializedPayload] = params;
        this.outboxId = id;
        this.insertedPayload = JSON.parse(serializedPayload);
        if (existingStatus) return { rowCount: 0, rows: [] };
        successfulOutboxInsertions += 1;
        return { rowCount: 1, rows: [{ id }] };
      }
      if (text.startsWith("SELECT id,aggregate,action,payload,status")) {
        const payload = { ...expectedPayload(), ...existingChanges };
        return {
          rowCount: 1,
          rows: [{
            id: this.outboxId,
            aggregate: "agent-session-grant",
            action: "agent_session_grant.consumed",
            payload,
            status: existingStatus
          }]
        };
      }
      throw new Error(`unexpected transaction query: ${text}`);
    }
  };

  const state = {
    authorityInput: undefined,
    auditInput: undefined,
    transaction: undefined,
    committed: false,
    rolledBack: false
  };
  const authorityRepository = {
    async consumeAgentSessionGrantInTransaction(input) {
      state.authorityInput = input;
      return { lease };
    }
  };
  const auditRepository = {
    async appendAgentSessionGrantConsumedInTransaction(input) {
      state.auditInput = input;
      if (auditError) throw auditError;
      return auditEvent;
    }
  };
  const sharedControls = {
    async withTransaction(work) {
      state.transaction = tx;
      try {
        const result = await work(tx);
        state.committed = true;
        return result;
      } catch (error) {
        state.rolledBack = true;
        throw error;
      }
    }
  };
  const repository = createPostgresAgentSessionConsumptionRepository({
    client: { async query() {} },
    authorityRepository,
    auditRepository,
    sharedControls
  });
  return { repository, state, tx, calls, get successfulOutboxInsertions() { return successfulOutboxInsertions; } };
}

function input() {
  return {
    organization_id: ids.organization,
    device_id: ids.device,
    grant_id: ids.grant,
    process_binding_sha256: HASHES.process,
    ancestry_binding_sha256: HASHES.ancestry,
    grant
  };
}

function expectedPayload() {
  return {
    version: 1,
    audit_event_id: ids.event,
    audit_event_hash: HASHES.event,
    grant_id: ids.grant,
    session_id: ids.session,
    device_id: ids.device,
    agent_id: ids.agent,
    grant_hash: GRANT_HASH,
    statement_hash: HASHES.statement,
    consumed_at: CONSUMED_AT
  };
}

test("consumes a Lease, appends Cloud audit, and publishes through one exact transaction", async () => {
  const fixture = createHarness();
  const consumed = await fixture.repository.consumeAgentSessionGrant(input());

  assert.deepEqual(consumed, { lease });
  assert.equal(fixture.state.authorityInput.tx, fixture.tx);
  assert.equal(fixture.state.auditInput.tx, fixture.tx);
  assert.equal(fixture.state.transaction, fixture.tx);
  assert.equal(fixture.state.committed, true);
  assert.equal(fixture.state.rolledBack, false);
  assert.equal(fixture.successfulOutboxInsertions, 1);
  assert.equal(fixture.calls.length, 1);
  assert.match(fixture.calls[0].text, /ON CONFLICT \(organization_id,id\) DO NOTHING/u);
  assert.deepEqual(fixture.calls[0].params[0], ids.organization);
  assert.deepEqual(JSON.parse(fixture.calls[0].params[2]), expectedPayload());
  assert.deepEqual(fixture.tx.insertedPayload, expectedPayload());
  assert.deepEqual(fixture.state.auditInput, {
    tx: fixture.tx,
    organization_id: ids.organization,
    grant_id: ids.grant,
    session_id: ids.session,
    device_id: ids.device,
    agent_id: ids.agent,
    grant_hash: GRANT_HASH,
    statement_hash: HASHES.statement,
    signer_key_id: KEY_ID,
    process_binding_sha256: HASHES.process,
    ancestry_binding_sha256: HASHES.ancestry,
    worktree_binding_sha256: HASHES.worktree,
    control_sequence: 17,
    authority_generation: 23
  });

  const serializedPayload = fixture.calls[0].params[2];
  assert.deepEqual(Object.keys(JSON.parse(serializedPayload)).sort(), Object.keys(expectedPayload()).sort());
  assert.doesNotMatch(serializedPayload, /private_key|raw_body|signature|BEGIN PRIVATE KEY|do-not-publish/u);
});

for (const status of ["pending", "published"]) {
  test(`accepts an exact retry with an existing ${status} outbox without duplicate publication`, async () => {
    const fixture = createHarness({ existingStatus: status });

    const first = await fixture.repository.consumeAgentSessionGrant(input());
    const second = await fixture.repository.consumeAgentSessionGrant(input());

    assert.deepEqual(first, { lease });
    assert.deepEqual(second, { lease });
    assert.equal(fixture.state.committed, true);
    assert.equal(fixture.state.rolledBack, false);
    assert.equal(fixture.successfulOutboxInsertions, 0);
    assert.equal(fixture.calls.filter((call) => call.text.startsWith("INSERT INTO outbox_events")).length, 2);
    assert.equal(fixture.calls.filter((call) => call.text.startsWith("SELECT id,aggregate,action,payload,status")).length, 2);
  });
}

test("rejects an existing outbox whose payload changed", async () => {
  const fixture = createHarness({ existingStatus: "published", existingChanges: { session_id: ids.device } });

  await assert.rejects(
    fixture.repository.consumeAgentSessionGrant(input()),
    { name: "TypeError", message: "cloud consume publication is unavailable" }
  );
  assert.equal(fixture.state.committed, false);
  assert.equal(fixture.state.rolledBack, true);
  assert.equal(fixture.calls.length, 2);
});

test("rejects audit failure so the shared transaction wrapper can roll back before publishing", async () => {
  const fixture = createHarness({ auditError: new Error("audit append failed") });

  await assert.rejects(fixture.repository.consumeAgentSessionGrant(input()), { message: "audit append failed" });
  assert.equal(fixture.state.committed, false);
  assert.equal(fixture.state.rolledBack, true);
  assert.equal(fixture.calls.length, 0);
});

test("rejects outbox failure so the shared transaction wrapper can roll back", async () => {
  const fixture = createHarness({ outboxError: new Error("outbox write failed") });

  await assert.rejects(fixture.repository.consumeAgentSessionGrant(input()), { message: "outbox write failed" });
  assert.equal(fixture.state.committed, false);
  assert.equal(fixture.state.rolledBack, true);
  assert.equal(fixture.state.auditInput.tx, fixture.tx);
  assert.equal(fixture.calls.length, 1);
});

test("records invalid input without a false rollback and ignores metric failures after commit", async () => {
  const calls = [];
  const methods = [
    "recordAgentSessionConsumeSuccess", "recordAgentSessionConsumeReplay", "recordAgentSessionConsumeConflict",
    "recordAgentSessionConsumeStale", "recordAgentSessionConsumeFailure", "recordAgentSessionConsumeRollback",
    "recordCloudAuditAppend", "recordCloudAuditFailure"
  ];
  const metrics = Object.fromEntries(methods.map((method) => [method, () => {
    calls.push(method);
    if (method === "recordAgentSessionConsumeSuccess") throw new Error("metrics unavailable");
  }]));
  const fixture = createHarness();
  const repository = createPostgresAgentSessionConsumptionRepository({
    client: { async query() {} },
    authorityRepository: { async consumeAgentSessionGrantInTransaction(value) { return fixture.repository.consumeGrant(value); } },
    auditRepository: { async appendAgentSessionGrantConsumedInTransaction() { return auditEvent; } },
    sharedControls: { async withTransaction(work) { return work(fixture.tx); } },
    metrics
  });
  await assert.rejects(repository.consumeAgentSessionGrant({}), /grant is required/u);
  assert.deepEqual(calls, ["recordAgentSessionConsumeFailure"]);
  calls.length = 0;
  const committed = createPostgresAgentSessionConsumptionRepository({
    client: { async query() {} },
    authorityRepository: { async consumeAgentSessionGrantInTransaction() { return { lease }; } },
    auditRepository: { async appendAgentSessionGrantConsumedInTransaction() { return auditEvent; } },
    sharedControls: { async withTransaction(work) { return work(fixture.tx); } },
    metrics
  });
  assert.deepEqual(await committed.consumeAgentSessionGrant(input()), { lease });
  assert.equal(calls.includes("recordAgentSessionConsumeSuccess"), true);
  assert.equal(calls.includes("recordAgentSessionConsumeRollback"), false);
});
