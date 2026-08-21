import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { agentSessionGrantSigningData, agentSessionGrantStatementHash } from "../../src/agent-session-grant.mjs";
import {
  AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES,
  AGENT_LAUNCH_AUTHORITY_HANDOFF_SQL,
  createPostgresAgentLaunchAuthorityHandoffRepository
} from "../../src/postgres/agent-launch-authority-handoff-repository.mjs";

const GRANT_KEYS = crypto.generateKeyPairSync("ed25519");
const GRANT_STATEMENT = Object.freeze({
  version: 1,
  grant_id: "88888888-8888-4888-8888-888888888888",
  organization_id: "11111111-1111-4111-8111-111111111111",
  device_id: "22222222-2222-4222-8222-222222222222",
  agent_id: "44444444-4444-4444-8444-444444444444",
  agent_kind: "claude-code",
  adapter_id: "55555555-5555-4555-8555-555555555555",
  adapter_version: "1.2.3",
  worktree_binding_sha256: "c".repeat(64),
  process_binding_policy_id: "claude-code-default",
  scope: { operations: ["git.commit.sign"], repositories: ["/work/project"], branches: { allow: ["feature/*"], deny: [] }, remotes: { allow: ["origin"], deny: [] } },
  max_signatures: 2,
  not_before: "2026-08-19T02:59:59.000Z",
  expires_at: "2026-08-19T03:01:00.000Z",
  control_sequence: 12,
  authority_generation: 7,
  issuer: "agentpass-cloud",
  key_id: "agent-session-2026-08"
});
const GRANT = Object.freeze({
  version: 1,
  type: "agentpass.agent-session-grant",
  statement: GRANT_STATEMENT,
  statement_hash: agentSessionGrantStatementHash(GRANT_STATEMENT),
  signature: crypto.sign(null, agentSessionGrantSigningData(GRANT_STATEMENT), GRANT_KEYS.privateKey).toString("base64url")
});
const BINDING = Object.freeze({
  version: 1,
  type: "agentpass.agent-launch-authority-handoff-binding",
  request_id: "66666666-6666-4666-8666-666666666666",
  grant_id: "88888888-8888-4888-8888-888888888888",
  organization_id: "11111111-1111-4111-8111-111111111111",
  device_id: "22222222-2222-4222-8222-222222222222",
  agent_id: "44444444-4444-4444-8444-444444444444",
  agent_kind: "claude-code",
  adapter_id: "55555555-5555-4555-8555-555555555555",
  adapter_version: "1.2.3",
  session_id: "33333333-3333-4333-8333-333333333333",
  not_before: "2026-08-19T02:59:59.000Z",
  worktree_binding_sha256: "c".repeat(64),
  expires_at: "2026-08-19T03:01:00.000Z",
  control_sequence: 12,
  authority_generation: 7,
  nonce_sha256: "a".repeat(64),
  lease_sha256: "b".repeat(64),
  grant_hash: crypto.createHash("sha256").update(canonicalJson(GRANT), "utf8").digest("hex"),
  grant: GRANT
});

test("validates the closed public binding and explicitly refuses native proof issuance", async () => {
  const repository = createPostgresAgentLaunchAuthorityHandoffRepository();
  await assert.rejects(
    repository.issueAgentLaunchAuthorityHandoff(BINDING),
    { code: AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE }
  );
});

test("the explicit atomic production seam receives only the exact public digest binding", async () => {
  let received;
  const repository = createPostgresAgentLaunchAuthorityHandoffRepository({
    atomicHandoff: async (input) => {
      received = input;
      assert.equal(Object.hasOwn(input, "grant"), false);
      return { state: "issued" };
    }
  });
  const result = await repository.issueAgentLaunchAuthorityHandoff(BINDING);
  assert.deepEqual(result, { state: "issued", grant: GRANT });
  assert.equal(received.grant_hash, BINDING.grant_hash);
  await assert.rejects(
    createPostgresAgentLaunchAuthorityHandoffRepository({ atomicHandoff: async () => ({ state: "already_returned" }) }).issueAgentLaunchAuthorityHandoff(BINDING),
    { code: AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.REPLAYED }
  );
});

test("the explicit PostgreSQL client path uses one transaction and sends only typed digests", async () => {
  const calls = [];
  const client = {
    async query(text, params = []) {
      calls.push({ text, params });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return { rowCount: 0, rows: [] };
      if (text.startsWith("SELECT set_config")) return { rowCount: 1, rows: [{ organization_id: BINDING.organization_id }] };
      if (text === AGENT_LAUNCH_AUTHORITY_HANDOFF_SQL) return { rowCount: 1, rows: [{ result: { state: "issued" } }] };
      throw new Error("unexpected SQL");
    }
  };
  const result = await createPostgresAgentLaunchAuthorityHandoffRepository({ client })
    .issueAgentLaunchAuthorityHandoff(BINDING);
  assert.deepEqual(result, { state: "issued", grant: GRANT });
  assert.deepEqual(calls.map(({ text }) => text), [
    "BEGIN",
    "SELECT set_config('agentpass.organization_id',$1,true) AS organization_id",
    AGENT_LAUNCH_AUTHORITY_HANDOFF_SQL,
    "COMMIT"
  ]);
  const sqlCall = calls.find(({ text }) => text === AGENT_LAUNCH_AUTHORITY_HANDOFF_SQL);
  assert.equal(sqlCall.params.length, 17);
  assert.deepEqual(sqlCall.params.slice(0, 9), [
    BINDING.request_id,
    BINDING.grant_id,
    BINDING.organization_id,
    BINDING.device_id,
    BINDING.agent_id,
    BINDING.agent_kind,
    BINDING.adapter_id,
    BINDING.adapter_version,
    BINDING.session_id
  ]);
  for (const value of sqlCall.params.slice(9)) assert.notEqual(value, BINDING.grant);
  assert.equal(Buffer.isBuffer(sqlCall.params[9]), true);
  assert.equal(Buffer.isBuffer(sqlCall.params[14]), true);
  assert.equal(Buffer.isBuffer(sqlCall.params[15]), true);
  assert.equal(Buffer.isBuffer(sqlCall.params[16]), true);
});

test("the PostgreSQL client path maps one-time replay and unavailable SQL states without returning a grant", async () => {
  for (const state of ["already_returned", "unavailable"]) {
    const client = {
      async query(text, params = []) {
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return { rowCount: 0, rows: [] };
        if (text.startsWith("SELECT set_config")) return { rowCount: 1, rows: [{ organization_id: params[0] }] };
        return { rowCount: 1, rows: [{ result: { state } }] };
      }
    };
    await assert.rejects(
      createPostgresAgentLaunchAuthorityHandoffRepository({ client }).issueAgentLaunchAuthorityHandoff(BINDING),
      { code: state === "already_returned"
        ? AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.REPLAYED
        : AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE }
    );
  }
});

test("the PostgreSQL client path fails closed and rolls back on SQL or result failure", async () => {
  for (const mode of ["database", "result"]) {
    const calls = [];
    const client = {
      async query(text, params = []) {
        calls.push({ text, params });
        if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
        if (text.startsWith("SELECT set_config")) return { rowCount: 1, rows: [{ organization_id: params[0] }] };
        if (mode === "database") throw Object.assign(new Error("password=should-not-escape"), { code: "XX000" });
        return { rowCount: 1, rows: [{ result: { state: "unexpected", secret: "should-not-escape" } }] };
      }
    };
    await assert.rejects(
      createPostgresAgentLaunchAuthorityHandoffRepository({ client }).issueAgentLaunchAuthorityHandoff(BINDING),
      (error) => {
        assert.equal(error.code, mode === "result"
          ? AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.RESULT
          : AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE);
        assert.doesNotMatch(error.message, /password|should-not-escape|secret/iu);
        return true;
      }
    );
    assert.equal(calls.at(-1).text, "ROLLBACK");
  }
});

test("rejects ambiguous adapter configuration before any SQL can run", () => {
  const client = { query: async () => ({ rows: [] }) };
  for (const options of [
    { client, atomicHandoff: async () => ({ state: "issued" }) },
    { client, transaction: "not-a-function" },
    { client: { query: "not-a-function" } },
    null
  ]) {
    assert.throws(
      () => createPostgresAgentLaunchAuthorityHandoffRepository(options),
      { code: AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG }
    );
  }
});

test("rejects malformed or authority-bearing repository input without exposing values", async () => {
  const repository = createPostgresAgentLaunchAuthorityHandoffRepository();
  for (const input of [
    { ...BINDING, nonce: "raw-nonce-must-not-cross-the-boundary" },
    { ...BINDING, expires_at: "not-a-timestamp" },
    { ...BINDING, unexpected: true }
  ]) {
    await assert.rejects(repository.issueAgentLaunchAuthorityHandoff(input), (error) => {
      assert.equal(error.code, AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.INVALID_INPUT);
      assert.doesNotMatch(error.message, /raw-nonce|timestamp|unexpected|private|secret|token/iu);
      return true;
    });
  }
});
