/* M2-A2Q real-PostgreSQL Human HTTP qualification. */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createLocalAgentSessionGrantSigner, verifyAgentSessionGrant } from "../../src/agent-session-grant.mjs";
import { createHumanAgentSessionGrantHttpApi } from "../../src/human-auth/agent-sessions/http-api.mjs";
import { createCloudApi } from "../../src/server.mjs";
import { createAgentSessionHumanHttpFixture } from "./agent-session-human-http-fixture.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const ORIGIN = "https://console.agentpass.test";
const SESSION_TOKEN = "s".repeat(43);
const CSRF_TOKEN = "c".repeat(43);
const IDEMPOTENCY_KEY = "m2-a2q-human-http-request-1";

test("M2-A2Q: real PostgreSQL Human HTTP issuance survives restart without duplicate signing, audit, or publication", {
  skip: !DATABASE_URL,
  timeout: 45_000
}, async (t) => {
  const fixture = await createAgentSessionHumanHttpFixture({ connectionString: DATABASE_URL, applicationVersion: "m2-a2q-human-http" });
  const servers = new Set();
  const signerKeys = crypto.generateKeyPairSync("ed25519");
  const localSigner = createLocalAgentSessionGrantSigner({ privateKey: signerKeys.privateKey, keyId: "m2-a2q-human-http-v1" });
  let signCalls = 0;
  let recentAuthCalls = 0;
  let authenticationCalls = 0;
  const signer = {
    key_id: "m2-a2q-human-http-v1",
    async signAgentSessionGrant(statement) {
      signCalls += 1;
      return localSigner.signAgentSessionGrant(statement);
    }
  };
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      authenticationCalls += 1;
      assert.equal(input.origin, ORIGIN);
      assert.match(input.cookie, /__Host-agentpass_session=/u);
      assert.equal(input.csrfToken, CSRF_TOKEN);
      return { session: fixture.actor };
    }
  };
  const recentAuthService = {
    async authorize(input) {
      recentAuthCalls += 1;
      assert.equal(input.proof, fixture.ids.recentAuth);
      return {
        verified: true,
        consumed: true,
        challenge_id: fixture.ids.recentAuth,
        member_id: fixture.actor.member_id,
        organization_id: fixture.ids.organization,
        operation: "agent.session_grant.issue",
        authenticated_at: fixture.issuedAtMs
      };
    }
  };

  const startServer = async () => {
    const api = createHumanAgentSessionGrantHttpApi({ humanSession, recentAuthService, repository: fixture.repository, signer, origin: ORIGIN });
    const server = createCloudApi({ store: {}, humanAuthApi: api });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    server.base = `http://127.0.0.1:${server.address().port}`;
    servers.add(server);
    server.once("close", () => servers.delete(server));
    return server;
  };

  t.after(async () => {
    let firstError;
    for (const server of [...servers]) {
      try { await stopServer(server); } catch (error) { firstError ??= error; }
    }
    try { await fixture.cleanup(); } catch (error) { firstError ??= error; }
    if (firstError) throw firstError;
  });

  const path = `/api/v1/organizations/${fixture.ids.organization}/agents/${fixture.ids.agent}/session-grants`;
  const firstServer = await startServer();
  const first = await issue(firstServer, path, fixture);
  assert.equal(first.response.status, 201, JSON.stringify(first.body));
  assert.equal(first.body.grant.statement.organization_id, fixture.ids.organization);
  assert.equal(first.body.grant.statement.agent_id, fixture.ids.agent);
  assert.doesNotThrow(() => verifyAgentSessionGrant(first.body.grant, { publicKey: signerKeys.publicKey, now: Date.now() }));

  await stopServer(firstServer);
  const restartedServer = await startServer();
  const retry = await issue(restartedServer, path, fixture);
  assert.equal(retry.response.status, 201, JSON.stringify(retry.body));
  assert.deepEqual(retry.body, first.body);
  assert.equal(signCalls, 1, "a committed HTTP retry must not invoke the signer");
  assert.equal(recentAuthCalls, 1, "exact replay must be resolved before consuming recent auth again");

  const counts = await fixture.pool.query(`SELECT
    (SELECT count(*)::int FROM agent_session_grants WHERE organization_id=$1) AS grants,
    (SELECT count(*)::int FROM admin_audit_events WHERE organization_id=$1) AS audits,
    (SELECT count(*)::int FROM outbox_events WHERE organization_id=$1) AS publications`, [fixture.ids.organization]);
  assert.deepEqual(counts.rows, [{ grants: 1, audits: 1, publications: 1 }]);

  const changed = await issue(restartedServer, path, fixture, { intent: { ...fixture.intent, max_signatures: fixture.intent.max_signatures + 1 } });
  assert.equal(changed.response.status, 409, JSON.stringify(changed.body));
  assert.equal(changed.body.error.code, "human_agent_session_grant_idempotency_conflict");
  assert.equal(signCalls, 1);
  assert.equal(recentAuthCalls, 1);

  const query = await issue(restartedServer, `${path}?fallback=1`, fixture);
  assert.equal(query.response.status, 400, JSON.stringify(query.body));
  assert.equal(query.body.error.code, "human_agent_session_grant_invalid_request");
  const method = await fetch(`${restartedServer.base}${path}`, {
    method: "GET",
    headers: {
      origin: ORIGIN,
      cookie: `__Host-agentpass_session=${SESSION_TOKEN}`,
      "agentpass-csrf": CSRF_TOKEN
    }
  });
  assert.equal(method.status, 405);
  assert.equal((await method.json()).error.code, "human_agent_session_grant_method_not_allowed");
  assert.equal(authenticationCalls, 5, "query and method variants must remain inside the hardened Human boundary");
});

async function issue(server, path, fixture, { intent = fixture.intent } = {}) {
  const response = await fetch(`${server.base}${path}`, {
    method: "POST",
    headers: {
      origin: ORIGIN,
      cookie: `__Host-agentpass_session=${SESSION_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict`,
      "agentpass-csrf": CSRF_TOKEN,
      "agentpass-recent-auth": fixture.ids.recentAuth,
      "idempotency-key": IDEMPOTENCY_KEY,
      "content-type": "application/json"
    },
    body: JSON.stringify(intent)
  });
  const text = await response.text();
  return { response, body: text.length === 0 ? null : JSON.parse(text) };
}

async function stopServer(server) {
  if (!server?.listening) return;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
