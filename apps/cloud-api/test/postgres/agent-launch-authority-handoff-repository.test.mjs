import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { agentSessionGrantSigningData, agentSessionGrantStatementHash } from "../../src/agent-session-grant.mjs";
import {
  AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES,
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
