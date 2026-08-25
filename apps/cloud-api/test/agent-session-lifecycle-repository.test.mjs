import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentSessionLifecycleRepositoryError,
  createPostgresAgentSessionLifecycleRepository
} from "../src/postgres/agent-session-lifecycle-repository.mjs";

const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  agent: "33333333-3333-4333-8333-333333333333",
  grant: "44444444-4444-4444-8444-444444444444",
  session: "55555555-5555-4555-8555-555555555555"
});

test("expireDue uses the tenant-bound SECURITY DEFINER function and returns frozen counts", async () => {
  const client = new MockClient({ results: [{ counts: [3, 2], expired: 5, revoked: 0 }] });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });
  const result = await repository.expireDue({ organization_id: IDS.organization, limit: 7, expired_at: "2026-08-13T00:00:00.000Z" });
  assert.deepEqual(result, [3, 2]);
  assert.ok(Object.isFrozen(result));
  assert.deepEqual(client.calls.map(({ text }) => text), [
    "BEGIN",
    "SELECT set_config('agentpass.organization_id',$1,true) AS organization_id",
    "SELECT current_setting('agentpass.organization_id',true) AS organization_id",
    "SELECT public.agentpass_agent_session_lifecycle_expire_due($1::uuid,$2::integer,$3::timestamptz) AS result",
    "COMMIT"
  ]);
  assert.deepEqual(client.calls[3].params, [IDS.organization, 7, "2026-08-13T00:00:00.000Z"]);
});

test("expireDue does not accept an unbounded batch", async () => {
  const repository = createPostgresAgentSessionLifecycleRepository({ client: new MockClient() });
  await assert.rejects(repository.expireDue({ organization_id: IDS.organization, limit: 501 }), { code: "ERR_INPUT" });
});

test("revokeAuthority passes the complete selector to the tenant-bound function", async () => {
  const client = new MockClient({ results: [{ counts: [4, 5], expired: 2, revoked: 7 }] });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });
  await assert.rejects(repository.revokeAuthority({ organization_id: IDS.organization }), { code: "ERR_INPUT" });
  const result = await repository.revokeAuthority({
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    grant_id: IDS.grant,
    session_id: IDS.session,
    revoked_at: "2026-08-12T00:00:00.000Z"
  });
  assert.deepEqual(result, [4, 5]);
  const call = client.calls.find(({ text }) => text.includes("agentpass_agent_session_lifecycle_revoke"));
  assert.deepEqual(call.params, [IDS.organization, IDS.device, IDS.agent, IDS.grant, IDS.session, false, "2026-08-12T00:00:00.000Z"]);
});

test("organization-wide revocation requires an explicit true opt-in", async () => {
  const client = new MockClient({ results: [{ counts: [2, 3], expired: 1, revoked: 4 }] });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });
  await assert.rejects(repository.revokeAuthority({ organization_id: IDS.organization, organization_wide: false }), { code: "ERR_INPUT" });
  assert.deepEqual(await repository.revokeAuthority({ organization_id: IDS.organization, organization_wide: true }), [2, 3]);
  const call = client.calls.find(({ text }) => text.includes("agentpass_agent_session_lifecycle_revoke"));
  assert.deepEqual(call.params, [IDS.organization, undefined, undefined, undefined, undefined, true, null]);
});

test("database failures become stable opaque errors without SQL diagnostics", async () => {
  const client = new MockClient({ fail: new Error("password=super-secret SQL SELECT leaked") });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });
  await assert.rejects(repository.expireDue({ organization_id: IDS.organization }), (error) => {
    assert.ok(error instanceof AgentSessionLifecycleRepositoryError);
    assert.equal(error.code, "ERR_DATABASE");
    assert.equal(error.message, "Agent session lifecycle storage is unavailable");
    assert.equal("cause" in error, false);
    assert.doesNotMatch(JSON.stringify(error), /super-secret|SELECT/iu);
    return true;
  });
});

test("retries exactly once on the documented expiry-boundary race", async () => {
  const expiryRace = Object.assign(new Error("deadline crossed"), { code: "23514", constraint: "agent_sessions_expiry_forward_only" });
  const client = new MockClient({ failOnce: expiryRace, results: [{ counts: [0, 1], expired: 0, revoked: 1 }] });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });
  assert.deepEqual(await repository.revokeAuthority({ organization_id: IDS.organization, session_id: IDS.session }), [0, 1]);
  assert.equal(client.calls.filter(({ text }) => text === "BEGIN").length, 2);
  assert.equal(client.calls.filter(({ text }) => text === "ROLLBACK").length, 1);
  assert.equal(client.calls.filter(({ text }) => text === "COMMIT").length, 1);
});

test("metrics cannot change a committed lifecycle outcome", async () => {
  const client = new MockClient({ results: [{ counts: [1, 0], expired: 1, revoked: 0 }] });
  const repository = createPostgresAgentSessionLifecycleRepository({
    client,
    metrics: {
      recordAgentSessionLifecycleExpired() { throw new Error("metrics unavailable"); },
      recordAgentSessionLifecycleRevoked() { throw new Error("metrics unavailable"); }
    }
  });
  assert.deepEqual(await repository.expireDue({ organization_id: IDS.organization }), [1, 0]);
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

class MockClient {
  constructor({ results = [], fail = undefined, failOnce = undefined } = {}) {
    this.calls = [];
    this.results = [...results];
    this.fail = fail;
    this.failOnce = failOnce;
  }

  async query(text, params = []) {
    this.calls.push({ text, params: [...params] });
    if (this.fail) throw this.fail;
    if (this.failOnce && text.includes("agentpass_agent_session_lifecycle_revoke")) {
      const error = this.failOnce;
      this.failOnce = undefined;
      throw error;
    }
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (text.startsWith("SELECT set_config")) return { rows: [{ organization_id: params[0] }], rowCount: 1 };
    if (text.startsWith("SELECT current_setting")) return { rows: [{ organization_id: IDS.organization }], rowCount: 1 };
    if (text.includes("agent_session_lifecycle_")) return { rows: [{ result: this.results.shift() ?? { counts: [0, 0], expired: 0, revoked: 0 } }], rowCount: 1 };
    throw new Error(`unexpected SQL: ${text}`);
  }
}
