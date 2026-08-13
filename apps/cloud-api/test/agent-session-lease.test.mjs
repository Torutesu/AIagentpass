import assert from "node:assert/strict";
import test from "node:test";

import { agentSessionLeaseFromRow, normalizeAgentSessionLease } from "../src/agent-session-lease.mjs";

const statement = Object.freeze({
  grant_id: "11111111-1111-4111-8111-111111111111",
  organization_id: "22222222-2222-4222-8222-222222222222",
  device_id: "33333333-3333-4333-8333-333333333333",
  agent_id: "44444444-4444-4444-8444-444444444444",
  agent_kind: "claude-code",
  adapter_id: "55555555-5555-4555-8555-555555555555",
  adapter_version: "1.2.3",
  worktree_binding_sha256: "a".repeat(64),
  max_signatures: 2,
  not_before: "2026-08-13T10:00:00.000Z",
  expires_at: "2026-08-13T10:15:00.000Z",
  control_sequence: 12,
  authority_generation: 7
});

function lease(overrides = {}) {
  return {
    version: 1,
    type: "agentpass.agent-session-lease",
    session_id: "66666666-6666-4666-8666-666666666666",
    ...statement,
    process_binding_sha256: "b".repeat(64),
    ancestry_binding_sha256: "c".repeat(64),
    used_signatures: 0,
    ...overrides
  };
}

test("normalizes a lease and proves every grant and process binding", () => {
  const value = normalizeAgentSessionLease(lease(), { expectedGrant: { statement }, processBindingSha256: "b".repeat(64), ancestryBindingSha256: "c".repeat(64), now: Date.parse(statement.not_before), allowExpired: false });
  assert.deepEqual(value, lease());
  assert.equal(Object.isFrozen(value), true);
});

test("rejects unknown fields, budget/time errors, and every binding substitution", () => {
  const invalid = [
    { ...lease(), extra: true },
    lease({ used_signatures: 3 }),
    lease({ expires_at: statement.not_before }),
    lease({ process_binding_sha256: "d".repeat(64) }),
    lease({ organization_id: "77777777-7777-4777-8777-777777777777" })
  ];
  for (const value of invalid) assert.throws(() => normalizeAgentSessionLease(value, { expectedGrant: statement, processBindingSha256: "b".repeat(64), ancestryBindingSha256: "c".repeat(64) }), { code: "ERR_AGENT_SESSION_LEASE_INVALID" });
  assert.throws(() => normalizeAgentSessionLease(lease(), { now: Date.parse(statement.expires_at), allowExpired: false }), { code: "ERR_AGENT_SESSION_LEASE_INVALID" });
});

test("maps PostgreSQL rows without exposing lifecycle or private columns", () => {
  const row = {
    ...lease(),
    max_signatures: "2",
    used_signatures: "0",
    control_sequence: "12",
    authority_generation: "7",
    not_before: new Date(statement.not_before),
    expires_at: new Date(statement.expires_at),
    status: "challenge_pending",
    grant_hash: "d".repeat(64),
    reserved_signatures: 0
  };
  const output = agentSessionLeaseFromRow(row);
  assert.deepEqual(output, lease());
  assert.equal(Object.hasOwn(output, "status"), false);
  assert.equal(Object.hasOwn(output, "grant_hash"), false);
});
