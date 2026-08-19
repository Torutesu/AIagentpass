import assert from "node:assert/strict";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_PATHS } from "../src/agent-launch-authority-handoff-api.mjs";

const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333"
});
const PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/agent-sessions/${IDS.session}/launch-authority-handoff`;
const RESULT = { status: 503, body: { error: { code: "agent_launch_authority_handoff_native_proof_unavailable" } }, headers: { "Cache-Control": "no-store" } };
const DECISION = Object.freeze({ allowed: true, limit: 100, remaining: 99, retryAfterSeconds: 0, resetAt: 1_800_000_000_000 });

async function startServer(t, options = {}) {
  const server = createCloudApi({
    store: options.store ?? {},
    admissionRateLimiter: { acquire: async () => DECISION },
    rateLimiter: { acquire: async () => DECISION },
    agentLaunchAuthorityHandoffApi: options.api
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test("routes only the exact launch handoff path through its raw boundary", async (t) => {
  const calls = [];
  const rawBody = Buffer.from("not-json-yet", "utf8");
  const api = {
    paths: AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_PATHS,
    async handle(input) {
      calls.push(input);
      return { ...RESULT, body: { accepted: false, reason: "native_proof_unavailable" } };
    }
  };
  const base = await startServer(t, { api });
  const response = await fetch(`${base}${PATH}`, { method: "POST", headers: { "AgentPass-Nonce": "raw-header", "Content-Type": "application/json" }, body: rawBody });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { accepted: false, reason: "native_proof_unavailable" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, PATH);
  assert.deepEqual(Buffer.from(calls[0].body), rawBody);

  for (const path of [`${PATH}?query=forbidden`, `${PATH}/`, PATH.replace("launch-authority-handoff", "launch-authority")]) {
    const rejected = await fetch(`${base}${path}`, { method: "POST", body: rawBody });
    assert.equal(rejected.status, 404, path);
  }
  assert.equal(calls.length, 1);
});

test("does not expose an absent handoff adapter through a generic route", async (t) => {
  const base = await startServer(t);
  const response = await fetch(`${base}${PATH}`, { method: "POST", body: "{}" });
  assert.equal(response.status, 404);
  assert.equal((await response.json()).error.code, "not_found");
});
