import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createAgentSessionGrantIssuanceService } from "../../src/human-auth/agent-sessions/issuance-service.mjs";
import { createOperationalMetrics } from "../../src/postgres/operational-health.mjs";
import {
  AgentSessionIssuanceRepositoryError,
  createPostgresAgentSessionIssuanceRepository
} from "../../src/postgres/agent-session-issuance-repository.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const AGENT_ID = "22222222-2222-4222-8222-222222222222";
const DEVICE_ID = "33333333-3333-4333-8333-333333333333";
const ADAPTER_ID = "44444444-4444-4444-8444-444444444444";
const MEMBER_ID = "55555555-5555-4555-8555-555555555555";
const SESSION_ID = "66666666-6666-4666-8666-666666666666";
const RECENT_AUTH_ID = "77777777-7777-4777-8777-777777777777";
const GRANT_ID = "88888888-8888-4888-8888-888888888888";
const REQUEST_ID = "99999999-9999-4999-8999-999999999999";
const NOW = Date.parse("2026-08-13T00:00:00.000Z");

function actor(overrides = {}) {
  return { session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, role: "admin", ...overrides };
}

function intent(overrides = {}) {
  return {
    device_id: DEVICE_ID,
    agent_kind: "claude-code",
    adapter_id: ADAPTER_ID,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/Users/example/repository"],
      branches: { allow: ["main"], deny: [] },
      remotes: { allow: ["origin"], deny: [] }
    },
    max_signatures: 2,
    ttl_seconds: 600,
    ...overrides
  };
}

function harness({ role = "admin", agentStatus = "active", deviceStatus = "active", agentKind = "claude-code", revoked = false, policyScope = intent().scope, controlAvailable = true, processPolicyAllowed = true, metrics = undefined, clock = undefined } = {}) {
  let committedIdempotency = new Map();
  const committedGrants = new Map();
  const calls = { signer: 0, audit: 0, processPolicy: 0, queries: [] };
  const client = { async query() { throw new Error("pool query must not be used directly"); } };
  const tx = {
    async query(sql, params = []) {
      calls.queries.push(String(sql));
      if (/set_config\('agentpass\.organization_id'/u.test(sql)) return result([{ organization_id: params[0] }]);
      if (/current_setting\('agentpass\.organization_id'/u.test(sql)) return result([{ organization_id: ORGANIZATION_ID }]);
      if (/pg_advisory_xact_lock/u.test(sql)) return result([{ locked: null }]);
      if (/FROM organizations/u.test(sql)) return result([{ "?column?": 1 }]);
      if (/FROM human_sessions/u.test(sql)) return result([{ role }]);
      if (/FROM agents a JOIN devices d/u.test(sql)) return result([{ agent_kind: agentKind, agent_status: agentStatus, device_status: deviceStatus }]);
      if (/FROM revocations/u.test(sql)) return result(revoked ? [{ "?column?": 1 }] : []);
      if (/FROM policies/u.test(sql)) return result([{ id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", sequence: 9, scope_json: policyScope, created_at: "2026-08-12T00:00:00.000Z", updated_at: "2026-08-12T00:00:00.000Z" }]);
      if (/FROM bundle_heads h/u.test(sql)) return result(controlAvailable ? [{ sequence: 12, authority_generation: 7 }] : []);
      if (/INSERT INTO outbox_events/u.test(sql)) return result([{ id: params[1] }]);
      throw new Error(`unexpected SQL: ${String(sql).slice(0, 80)}`);
    }
  };
  const controls = {
    async withTransaction(operation) {
      const working = new Map(committedIdempotency);
      const previous = committedIdempotency;
      committedIdempotency = working;
      try {
        const output = await operation(tx);
        return output;
      } catch (error) {
        committedIdempotency = previous;
        throw error;
      }
    },
    async acquireIdempotency({ idempotencyKey, requestHash }) {
      const existing = committedIdempotency.get(idempotencyKey);
      if (!existing) { committedIdempotency.set(idempotencyKey, { requestHash, status: 102, response: {} }); return { state: "new" }; }
      if (existing.requestHash !== requestHash) return { state: "conflict" };
      if (existing.status === 102) return { state: "in_progress" };
      return { state: "replay", responseStatus: existing.status, response: structuredClone(existing.response) };
    },
    async completeIdempotency({ idempotencyKey, requestHash, responseStatus, response }) {
      const existing = committedIdempotency.get(idempotencyKey);
      assert.equal(existing?.requestHash, requestHash);
      assert.equal(existing?.status, 102);
      committedIdempotency.set(idempotencyKey, { requestHash, status: responseStatus, response: structuredClone(response) });
      return { completed: true };
    },
    async abandonIdempotency({ idempotencyKey, requestHash }) {
      const existing = committedIdempotency.get(idempotencyKey);
      if (existing?.requestHash === requestHash && existing.status === 102) committedIdempotency.delete(idempotencyKey);
      return { removed: true };
    }
  };
  const authorityRepository = {
    async issueAgentSessionGrantInTransaction(input) {
      const grantId = input.grant.statement.grant_id;
      if (committedGrants.has(grantId)) return { grant: committedGrants.get(grantId), replayed: true };
      committedGrants.set(grantId, structuredClone(input.grant));
      return { grant: structuredClone(input.grant), replayed: false };
    },
    async getAgentSessionGrantInTransaction({ grant_id }) {
      const grant = committedGrants.get(grant_id);
      if (!grant) throw new Error("grant missing");
      return { grant: structuredClone(grant), replayed: true };
    }
  };
  const auditRepository = {
    async appendAdminAuditEventInTransaction(input) {
      calls.audit += 1;
      assert.equal(input.event_type, "agent_session_grant.issued");
      assert.equal(input.details.control_sequence, 12);
      assert.equal(input.details.authority_generation, 7);
      return { audit_event_id: crypto.randomUUID() };
    }
  };
  const repository = createPostgresAgentSessionIssuanceRepository({
    client,
    authorityRepository,
    sharedControls: controls,
    auditRepository,
    metrics,
    clock,
    async resolveProcessBindingPolicy(input) {
      calls.processPolicy += 1;
      assert.equal(input.process_binding_policy_id, "claude-code-v1");
      return processPolicyAllowed;
    }
  });
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const signer = {
    key_id: "grant-key-v1",
    async sign({ message }) { calls.signer += 1; return crypto.sign(null, message, privateKey); }
  };
  let uuidIndex = 0;
  const service = createAgentSessionGrantIssuanceService({ repository, signer, clock: { now: () => NOW }, uuid: () => [GRANT_ID, REQUEST_ID][uuidIndex++ % 2] });
  const issueInput = (overrides = {}) => ({
    actor: actor(), organization_id: ORGANIZATION_ID, agent_id: AGENT_ID,
    intent: intent(), idempotency_key: "grant-request-1",
    recent_authorization: { authorization_id: RECENT_AUTH_ID, authenticated_at: NOW },
    ...overrides
  });
  return { service, repository, calls, issueInput, idempotency: () => committedIdempotency };
}

test("issues once with current Human, audience, policy, generation, process policy, audit, and idempotency authority", async () => {
  const fixture = harness();
  const issued = await fixture.service.issue(fixture.issueInput());
  assert.equal(issued.grant.statement.control_sequence, 12);
  assert.match(issued.request_id, /^[0-9a-f-]{36}$/u);
  assert.equal(fixture.calls.signer, 1);
  assert.equal(fixture.calls.audit, 1);
  assert.equal(fixture.calls.processPolicy, 1);
  assert.equal(fixture.idempotency().get("grant-request-1").status, 201);
});

test("records label-free issue, signer success, and integer signer latency metrics", async () => {
  const metrics = createOperationalMetrics();
  const clockValues = [100, 102.6];
  const fixture = harness({ metrics, clock: () => clockValues.shift() });
  await fixture.service.issue(fixture.issueInput());
  const counters = metrics.snapshot().counters;
  assert.equal(counters.agent_session_issue_success_total, 1);
  assert.equal(counters.agent_session_signer_success_total, 1);
  assert.equal(counters.agent_session_signer_latency_count, 1);
  assert.equal(counters.agent_session_signer_latency_total_ms, 3);
  assert.equal(counters.agent_session_issue_failure_total, 0);
  assert.equal(counters.agent_session_issue_rollback_total, 0);
});

test("pre-WebAuthn replay returns the exact committed Grant and never signs or audits twice", async () => {
  const fixture = harness();
  const first = await fixture.service.issue(fixture.issueInput());
  const replayed = await fixture.service.replay(fixture.issueInput({ recent_authorization: undefined }));
  assert.deepEqual(replayed.grant, first.grant);
  assert.equal(replayed.request_id, first.request_id);
  assert.equal(replayed.replayed, true);
  assert.equal(fixture.calls.signer, 1);
  assert.equal(fixture.calls.audit, 1);
});

test("records exact replay without recording signer metrics", async () => {
  const metrics = createOperationalMetrics();
  const fixture = harness({ metrics });
  await fixture.service.issue(fixture.issueInput());
  await fixture.service.issue(fixture.issueInput());
  const counters = metrics.snapshot().counters;
  assert.equal(counters.agent_session_issue_success_total, 1);
  assert.equal(counters.agent_session_issue_replay_total, 1);
  assert.equal(counters.agent_session_signer_success_total, 1);
  assert.equal(counters.agent_session_signer_failure_total, 0);
  assert.equal(counters.agent_session_signer_latency_count, 1);
});

test("same idempotency key with a changed canonical request is a stable conflict", async () => {
  const fixture = harness();
  await fixture.service.issue(fixture.issueInput());
  await assert.rejects(() => fixture.service.replay(fixture.issueInput({ intent: intent({ max_signatures: 3 }) })), (error) => error.code === "agent_session_grant_idempotency_conflict");
});

test("records idempotency conflict and transaction rollback without labels", async () => {
  const calls = [];
  const metrics = Object.fromEntries([
    "recordAgentSessionIssueSuccess",
    "recordAgentSessionIssueReplay",
    "recordAgentSessionIssueConflict",
    "recordAgentSessionIssueFailure",
    "recordAgentSessionIssueRollback",
    "recordAgentSessionSignerSuccess",
    "recordAgentSessionSignerFailure"
  ].map((method) => [method, (...args) => calls.push([method, ...args])]));
  metrics.recordAgentSessionSignerLatency = (...args) => calls.push(["recordAgentSessionSignerLatency", ...args]);
  const fixture = harness({ metrics });
  await fixture.service.issue(fixture.issueInput());
  await assert.rejects(() => fixture.service.replay(fixture.issueInput({ intent: intent({ max_signatures: 3 }) })), (error) => error.code === "agent_session_grant_idempotency_conflict");
  assert.deepEqual(calls.filter(([method]) => method === "recordAgentSessionIssueConflict"), [["recordAgentSessionIssueConflict"]]);
  assert.deepEqual(calls.filter(([method]) => method === "recordAgentSessionIssueRollback"), [["recordAgentSessionIssueRollback"]]);
  assert.equal(calls.some((entry) => entry[0] === "recordAgentSessionIssueConflict" && entry.length !== 1), false);
  assert.equal(calls.some((entry) => entry[0] === "recordAgentSessionIssueRollback" && entry.length !== 1), false);
});

test("fails closed for inactive or mismatched audience, revoked authority, policy escalation, stale control, and untrusted process policy", async () => {
  for (const options of [
    { role: "viewer" },
    { agentStatus: "revoked" },
    { deviceStatus: "revoked" },
    { agentKind: "cursor" },
    { revoked: true },
    { policyScope: { ...intent().scope, repositories: ["/other"] } },
    { controlAvailable: false },
    { processPolicyAllowed: false }
  ]) {
    const fixture = harness(options);
    await assert.rejects(() => fixture.service.issue(fixture.issueInput()), (error) => ["agent_session_grant_forbidden", "agent_session_grant_not_found", "agent_session_grant_invalid_request", "agent_session_grant_unavailable"].includes(error.code), JSON.stringify(options));
    assert.equal(fixture.calls.signer, 0, JSON.stringify(options));
    assert.equal(fixture.calls.audit, 0, JSON.stringify(options));
  }
});

test("signer failure rolls back provisional idempotency so an exact retry can issue", async () => {
  const fixture = harness();
  const repository = fixture.repository;
  await assert.rejects(() => repository.issueAgentSessionGrant({
    actor: actor(), organization_id: ORGANIZATION_ID, agent_id: AGENT_ID, intent: intent(),
    idempotency_key: "grant-request-1", request_fingerprint: requestFingerprint(intent()), request_id: REQUEST_ID,
    issued_at: new Date(NOW).toISOString(), recent_auth: { authorization_id: RECENT_AUTH_ID, authenticated_at: new Date(NOW).toISOString() },
    async buildGrant() { throw new Error("KMS private detail"); }
  }), (error) => error instanceof AgentSessionIssuanceRepositoryError && error.code === "unavailable");
  assert.equal(fixture.idempotency().has("grant-request-1"), false);
  const issued = await fixture.service.issue(fixture.issueInput());
  assert.match(issued.grant.statement.grant_id, /^[0-9a-f-]{36}$/u);
});

test("records signer failure, latency, issue failure, and rollback while hiding the signer error", async () => {
  const metrics = createOperationalMetrics();
  const clockValues = [50, 53.1];
  const fixture = harness({ metrics, clock: () => clockValues.shift() });
  await assert.rejects(() => fixture.repository.issueAgentSessionGrant({
    actor: actor(), organization_id: ORGANIZATION_ID, agent_id: AGENT_ID, intent: intent(),
    idempotency_key: "grant-request-1", request_fingerprint: requestFingerprint(intent()), request_id: REQUEST_ID,
    issued_at: new Date(NOW).toISOString(), recent_auth: { authorization_id: RECENT_AUTH_ID, authenticated_at: new Date(NOW).toISOString() },
    async buildGrant() { throw new Error("private signer detail"); }
  }), (error) => error instanceof AgentSessionIssuanceRepositoryError && error.code === "unavailable");
  const counters = metrics.snapshot().counters;
  assert.equal(counters.agent_session_signer_success_total, 0);
  assert.equal(counters.agent_session_signer_failure_total, 1);
  assert.equal(counters.agent_session_signer_latency_count, 1);
  assert.equal(counters.agent_session_signer_latency_total_ms, 3);
  assert.equal(counters.agent_session_issue_failure_total, 1);
  assert.equal(counters.agent_session_issue_rollback_total, 1);
});

test("validates all fixed metrics methods when metrics are supplied and preserves omission", async () => {
  const fixture = harness();
  await fixture.service.issue(fixture.issueInput());
  assert.throws(() => createPostgresAgentSessionIssuanceRepository({
    client: { query() {} },
    resolveProcessBindingPolicy: async () => true,
    metrics: { recordAgentSessionIssueSuccess() {} }
  }), /metrics must expose/u);
});

test("rejects a caller-supplied request fingerprint that does not match the canonical intent", async () => {
  const fixture = harness();
  await assert.rejects(() => fixture.repository.issueAgentSessionGrant({
    actor: actor(), organization_id: ORGANIZATION_ID, agent_id: AGENT_ID, intent: intent(),
    idempotency_key: "grant-request-1", request_fingerprint: "b".repeat(64), request_id: REQUEST_ID,
    issued_at: new Date(NOW).toISOString(), recent_auth: { authorization_id: RECENT_AUTH_ID, authenticated_at: new Date(NOW).toISOString() },
    async buildGrant() { throw new Error("must not be called"); }
  }), (error) => error instanceof AgentSessionIssuanceRepositoryError && error.code === "invalid_input");
  assert.equal(fixture.idempotency().size, 0);
});

function requestFingerprint(value) {
  return crypto.createHash("sha256").update(canonicalJson({ organization_id: ORGANIZATION_ID, agent_id: AGENT_ID, ...value })).digest("hex");
}

function result(rows) { return { rowCount: rows.length, rows }; }
