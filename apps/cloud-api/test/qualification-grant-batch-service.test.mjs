import assert from "node:assert/strict";
import test from "node:test";

import {
  QUALIFICATION_GRANT_BATCH_ERROR_CODES,
  QUALIFICATION_GRANT_BATCH_KIND,
  QUALIFICATION_GRANT_BATCH_STEPS,
  createQualificationGrantBatchService
} from "../src/human-auth/agent-sessions/qualification-batch-service.mjs";

const ids = Array.from({ length: 40 }, (_, index) => `${String(index + 1).padStart(8, "0")}-0000-4000-8000-000000000000`);
const ORG = "10000000-0000-4000-8000-000000000000";
const MEMBER = "20000000-0000-4000-8000-000000000000";
const SESSION = "30000000-0000-4000-8000-000000000000";
const DEVICE = "40000000-0000-4000-8000-000000000000";
const AGENT = "50000000-0000-4000-8000-000000000000";
const ADAPTER = "60000000-0000-4000-8000-000000000000";
const NOW = Date.parse("2026-08-14T00:00:00.000Z");

function input(overrides = {}) {
  return {
    actor: { session_id: SESSION, member_id: MEMBER, organization_id: ORG, role: "admin" },
    organization_id: ORG,
    agent_id: AGENT,
    idempotency_key: "qualification-batch-0001",
    recent_authorization: { authorization_id: "70000000-0000-4000-8000-000000000000", organization_id: ORG, member_id: MEMBER, operation: "qualification.grant_batch.issue", authenticated_at: NOW },
    request: {
      candidate_sha256: "a".repeat(64), artifact_sha256: "b".repeat(64), candidate_checkpoint_sha256: "c".repeat(64), release_trust_sha256: "d".repeat(64), source_commit: "e".repeat(40), team_id: "ABCDEFGHIJ",
      grant_intent: { device_id: DEVICE, agent_kind: "claude-code", adapter_id: ADAPTER, adapter_version: "1.2.3", worktree_binding_sha256: "f".repeat(64), process_binding_policy_id: "qualification-v1", scope: { operations: ["git.commit.sign"], repositories: ["/Users/agentpass/qualification"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } }, max_signatures: 1, ttl_seconds: 600 }
    },
    ...overrides
  };
}

function fixture(repositoryOverride = {}) {
  let cursor = 0;
  const calls = [];
  const grantCalls = [];
  const manifestCalls = [];
  const repository = {
    async issueQualificationGrantBatch(value) {
      calls.push(value);
      const allocations = value.steps.map((step, index) => ({ grant_id: step.grant_id, control_sequence: index + 10, authority_generation: 7 }));
      const grants = await value.buildGrants({ allocations });
      assert.equal(grants.length, 7);
      const manifest = await value.buildManifest({ grants });
      assert.equal(manifest.statement.batch_id, value.batch_id);
      return { request_id: value.request_id, batch: { schema_version: 1, kind: QUALIFICATION_GRANT_BATCH_KIND, batch_id: value.batch_id, organization_id: value.organization_id, device_id: value.device_id, agent_id: value.agent_id, candidate_sha256: value.request.candidate_sha256, artifact_sha256: value.request.artifact_sha256, candidate_checkpoint_sha256: value.request.candidate_checkpoint_sha256, release_trust_sha256: value.request.release_trust_sha256, source_commit: value.request.source_commit, team_id: value.request.team_id, issued_at: value.issued_at, expires_at: value.expires_at, status: "issued" } };
    },
    ...repositoryOverride
  };
  const service = createQualificationGrantBatchService({
    repository,
    grantBuilder: { async buildSignedGrant(value) { grantCalls.push(value); return { grant: { statement: { grant_id: value.grantId } }, grant_hash: "1".repeat(64), statement_hash: "2".repeat(64), control_sequence: value.controlSequence, authority_generation: value.authorityGeneration }; } },
    manifestSigner: {
      async publicKeyMetadata() { return { key_id: "qualification-manifest-v1" }; },
      async signQualificationGrantBatchManifest(statement) { manifestCalls.push(statement); return { version: 1, type: statement.type, statement, statement_hash: "3".repeat(64), signature: "A".repeat(86) }; }
    },
    now: () => NOW,
    uuid: () => ids[cursor++]
  });
  return { service, calls, grantCalls, manifestCalls };
}

test("authorizes one atomic seven-Grant batch without returning grants to the human", async () => {
  const { service, calls, grantCalls, manifestCalls } = fixture();
  const result = await service.issue(input());
  assert.equal(result.batch.kind, QUALIFICATION_GRANT_BATCH_KIND);
  assert.equal(Object.hasOwn(result.batch, "steps"), false);
  assert.equal(Object.hasOwn(result.batch, "grants"), false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].steps.length, 7);
  assert.deepEqual(calls[0].steps.map(({ index, kind, scenario, phase }) => ({ index, kind, scenario, phase })), QUALIFICATION_GRANT_BATCH_STEPS);
  assert.equal(new Set(calls[0].steps.map((step) => step.grant_id)).size, 7);
  assert.equal(new Set(calls[0].steps.map((step) => step.run_binding)).size, 7);
  assert.equal(grantCalls.length, 7);
  assert.deepEqual(grantCalls.map((call) => call.controlSequence), [10, 11, 12, 13, 14, 15, 16]);
  assert.equal(manifestCalls.length, 1);
  assert.equal(manifestCalls[0].steps.length, 7);
  assert.equal(manifestCalls[0].team_id, "ABCDEFGHIJ");
  assert.equal(manifestCalls[0].requested_ttl_seconds, 600);
});

test("binds actor, recent WebAuthn, candidate, and one-signature intent", async () => {
  const invalid = [
    input({ actor: { session_id: SESSION, member_id: MEMBER, organization_id: ORG, role: "viewer" } }),
    input({ organization_id: "90000000-0000-4000-8000-000000000000" }),
    input({ recent_authorization: { authorization_id: "70000000-0000-4000-8000-000000000000", organization_id: ORG, member_id: MEMBER, operation: "agent.session_grant.issue", authenticated_at: NOW } }),
    input({ request: { ...input().request, source_commit: "a".repeat(64) } }),
    input({ request: { ...input().request, grant_intent: { ...input().request.grant_intent, max_signatures: 2 } } })
  ];
  for (const value of invalid) await assert.rejects(() => fixture().service.issue(value), (error) => [QUALIFICATION_GRANT_BATCH_ERROR_CODES.INVALID_REQUEST, QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN, QUALIFICATION_GRANT_BATCH_ERROR_CODES.NOT_FOUND].includes(error.code));
});

test("rejects allocation omission, duplicate sequence, and grant substitution", async () => {
  const cases = [
    (value) => value.buildGrants({ allocations: [] }),
    (value) => value.buildGrants({ allocations: value.steps.map((step) => ({ grant_id: step.grant_id, control_sequence: 1, authority_generation: 2 })) }),
    (value) => value.buildGrants({ allocations: value.steps.map((step, index) => ({ grant_id: index === 3 ? AGENT : step.grant_id, control_sequence: index + 1, authority_generation: 2 })) })
  ];
  for (const invoke of cases) {
    const { service } = fixture({ async issueQualificationGrantBatch(value) { await invoke(value); } });
    await assert.rejects(() => service.issue(input()), { code: QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE });
  }
});

test("maps repository failures to stable secret-free errors", async () => {
  for (const [repositoryCode, expected] of [["idempotency_key_reused", QUALIFICATION_GRANT_BATCH_ERROR_CODES.IDEMPOTENCY_CONFLICT], ["device_not_found", QUALIFICATION_GRANT_BATCH_ERROR_CODES.NOT_FOUND], ["driver dumped secret", QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE]]) {
    const { service } = fixture({ async issueQualificationGrantBatch() { const error = new Error("sensitive database diagnostics"); error.code = repositoryCode; throw error; } });
    await assert.rejects(() => service.issue(input()), (error) => error.code === expected && !error.message.includes("sensitive"));
  }
});
