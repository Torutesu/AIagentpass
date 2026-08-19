import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES,
  createPostgresAgentLaunchAuthorityHandoffRepository
} from "../../src/postgres/agent-launch-authority-handoff-repository.mjs";

const BINDING = Object.freeze({
  version: 1,
  type: "agentpass.agent-launch-authority-handoff-binding",
  request_id: "66666666-6666-4666-8666-666666666666",
  organization_id: "11111111-1111-4111-8111-111111111111",
  device_id: "22222222-2222-4222-8222-222222222222",
  agent_id: "44444444-4444-4444-8444-444444444444",
  agent_kind: "claude-code",
  adapter_id: "55555555-5555-4555-8555-555555555555",
  adapter_version: "1.2.3",
  session_id: "33333333-3333-4333-8333-333333333333",
  not_before: "2026-08-19T02:59:59.000Z",
  expires_at: "2026-08-19T03:01:00.000Z",
  nonce_sha256: "a".repeat(64),
  lease_sha256: "b".repeat(64)
});

test("validates the closed public binding and explicitly refuses native proof issuance", async () => {
  const repository = createPostgresAgentLaunchAuthorityHandoffRepository();
  await assert.rejects(
    repository.issueAgentLaunchAuthorityHandoff(BINDING),
    { code: AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE }
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
