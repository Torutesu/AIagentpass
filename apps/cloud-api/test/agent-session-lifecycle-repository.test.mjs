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
const LATER = "2026-08-13T01:00:00.000Z";

test("expireDue uses tenant context, bounded locked CTEs, DB-clock expiry, and returns frozen counts", async () => {
  const client = new MockClient({ updateCounts: [3, 2] });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });

  const result = await repository.expireDue({ organization_id: IDS.organization, limit: 7, expired_at: "2026-08-13T00:00:00.000Z" });

  assert.deepEqual(result, [3, 2]);
  assert.ok(Object.isFrozen(result));
  assert.equal(client.calls[0].text, "BEGIN");
  assert.equal(client.calls[1].text, "SELECT set_config('agentpass.organization_id',$1,true) AS organization_id");
  assert.equal(client.calls[2].text, "SELECT current_setting('agentpass.organization_id',true) AS organization_id");
  const [grantUpdate, sessionUpdate] = client.calls.filter(({ text }) => text.startsWith("WITH db_clock"));
  for (const query of [grantUpdate, sessionUpdate]) {
    assert.match(query.text, /FOR UPDATE OF [a-z_]+ SKIP LOCKED/u);
    assert.match(query.text, /LIMIT \$2/u);
    assert.match(query.text, /clock_timestamp\(\)/u);
    assert.match(query.text, /GREATEST\(/u);
    assert.doesNotMatch(query.text, /\bDELETE\b/iu);
    assert.match(query.text, /RETURNING [a-z_]+\.status/iu);
    assert.equal(query.params[0], IDS.organization);
    assert.equal(query.params[1], 7);
  }
  assert.match(grantUpdate.text, /grant_record\.status='issued'/u);
  assert.match(sessionUpdate.text, /session_record\.status IN \('challenge_pending','active','request_reserved','signed'\)/u);
  assert.doesNotMatch(sessionUpdate.text, /'signing_intent'/u, "ambiguous signer outcomes must not be auto-expired");
  assert.match(sessionUpdate.text, /last_request_id=COALESCE\(session_record\.last_request_id,session_record\.active_request_id\)/u);
  assert.match(sessionUpdate.text, /active_request_id=NULL/u);
});

test("expireDue does not accept an unbounded batch", async () => {
  const repository = createPostgresAgentSessionLifecycleRepository({ client: new MockClient() });
  await assert.rejects(repository.expireDue({ organization_id: IDS.organization, limit: 501 }), (error) => {
    assert.ok(error instanceof AgentSessionLifecycleRepositoryError);
    assert.equal(error.code, "ERR_INPUT");
    assert.equal(error.message, "Agent session lifecycle input is invalid");
    return true;
  });
});

test("revokeAuthority requires an exact selector and applies every supplied selector tenant-qualified", async () => {
  const client = new MockClient({ updateCounts: [4, 5] });
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
  assert.ok(Object.isFrozen(result));
  const updates = client.calls.filter(({ text }) => text.startsWith("WITH db_clock"));
  assert.equal(updates.length, 2);
  for (const query of updates) {
    assert.match(query.text, /LIMIT 500/u);
    assert.match(query.text, /FOR UPDATE OF [a-z_]+(?! SKIP LOCKED)/u);
    assert.doesNotMatch(query.text, /SKIP LOCKED/u, "explicit revocation must wait for a concurrent consume decision");
    assert.match(query.text, /organization_id=\$1/u);
    assert.match(query.text, /device_id=\$2/u);
    assert.match(query.text, /agent_id=\$3/u);
    assert.match(query.text, /grant_id=\$4/u);
    assert.match(query.text, /session_id=\$5|consumed_session_id=\$5/u);
    assert.match(query.text, /CASE WHEN [a-z_]+\.expires_at <= db_clock\.now THEN 'expired' ELSE 'revoked' END/u);
    assert.doesNotMatch(query.text, /\bDELETE\b/iu);
    assert.deepEqual(query.params, [IDS.organization, IDS.device, IDS.agent, IDS.grant, IDS.session, "2026-08-12T00:00:00.000Z"]);
    assert.equal(query.params.at(-1), "2026-08-12T00:00:00.000Z");
  }
});

test("organization-wide revocation requires an explicit true opt-in", async () => {
  const client = new MockClient({ updateCounts: [2, 3] });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });

  await assert.rejects(repository.revokeAuthority({ organization_id: IDS.organization, organization_wide: false }), { code: "ERR_INPUT" });
  const result = await repository.revokeAuthority({
    organization_id: IDS.organization,
    organization_wide: true,
    revoked_at: "2026-08-12T00:00:00.000Z"
  });

  assert.deepEqual(result, [2, 3]);
  for (const query of client.calls.filter(({ text }) => text.startsWith("WITH db_clock"))) {
    assert.match(query.text, /AND TRUE/u);
    assert.deepEqual(query.params, [IDS.organization, "2026-08-12T00:00:00.000Z"]);
  }
});

test("revokeAuthority clamps caller timestamps to DB and creation/deadline bounds", async () => {
  const client = new MockClient();
  const repository = createPostgresAgentSessionLifecycleRepository({ client });

  await repository.revokeAuthority({ organization_id: IDS.organization, session_id: IDS.session, revoked_at: "2000-01-01T00:00:00.000Z" });
  const queries = client.calls.filter(({ text }) => text.startsWith("WITH db_clock"));
  assert.equal(queries.length, 2);
  assert.match(queries[0].text, /GREATEST\(db_clock\.now,COALESCE\(\$3::timestamptz,db_clock\.now\),grant_record\.issued_at\)/u);
  assert.match(queries[1].text, /GREATEST\(db_clock\.now,COALESCE\(\$3::timestamptz,db_clock\.now\),session_record\.created_at\)/u);
  assert.match(queries[0].text, /grant_record\.expires_at\)/u);
  assert.match(queries[1].text, /session_record\.expires_at\)/u);
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

test("retries exactly once when a row crosses expiry during revocation", async () => {
  const expiryRace = Object.assign(new Error("deadline crossed"), {
    code: "23514",
    constraint: "agent_sessions_expiry_forward_only"
  });
  const client = new MockClient({ failOnce: expiryRace, updateCounts: [0, 1] });
  const repository = createPostgresAgentSessionLifecycleRepository({ client });
  assert.deepEqual(await repository.revokeAuthority({ organization_id: IDS.organization, session_id: IDS.session }), [0, 1]);
  assert.equal(client.calls.filter(({ text }) => text === "BEGIN").length, 2);
  assert.equal(client.calls.filter(({ text }) => text === "ROLLBACK").length, 1);
  assert.equal(client.calls.filter(({ text }) => text === "COMMIT").length, 1);
});

test("metrics cannot change a committed lifecycle outcome", async () => {
  const client = new MockClient({ updateCounts: [1, 0] });
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
  constructor({ updateCounts = [0, 0], fail = undefined, failOnce = undefined } = {}) {
    this.calls = [];
    this.updateCounts = [...updateCounts];
    this.fail = fail;
    this.failOnce = failOnce;
  }

  async query(text, params = []) {
    this.calls.push({ text, params: [...params] });
    if (this.fail) throw this.fail;
    if (this.failOnce && text.startsWith("WITH db_clock")) {
      const error = this.failOnce;
      this.failOnce = undefined;
      throw error;
    }
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (text.startsWith("SELECT set_config")) return { rows: [{ organization_id: params[0] }], rowCount: 1 };
    if (text.startsWith("SELECT current_setting")) return { rows: [{ organization_id: IDS.organization }], rowCount: 1 };
    if (text.startsWith("WITH db_clock")) {
      const rowCount = this.updateCounts.shift() ?? 0;
      const status = text.includes("CASE WHEN") ? "revoked" : "expired";
      return { rows: Array.from({ length: rowCount }, () => ({ status })), rowCount };
    }
    throw new Error(`unexpected SQL: ${text}`);
  }
}
