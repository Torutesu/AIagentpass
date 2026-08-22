import assert from "node:assert/strict";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { startInMemoryHttpServer } from "../../../test/support/http-test-transport.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const BATCH_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PATH = `/v1/organizations/${ORGANIZATION_ID}/devices/${DEVICE_ID}/qualification-grant-batches/${BATCH_ID}/claim`;

async function startServer(t, options = {}) {
  const server = createCloudApi({ store: options.store ?? {}, ...options });
  startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test("routes the exact qualification batch claim to the raw device boundary", async (t) => {
  const calls = [];
  const raw = Buffer.from('{"not":"parsed"}', "utf8");
  const base = await startServer(t, {
    store: { listDevices: async () => { throw new Error("generic route must not run"); } },
    qualificationGrantBatchDeviceApi: {
      async handle(input) { calls.push(input); return { status: 200, body: { request_id: BATCH_ID, accepted: true }, headers: { "Cache-Control": "no-store" } }; }
    }
  });
  const response = await fetch(`${base}${PATH}`, { method: "POST", headers: { "AgentPass-Nonce": "public-nonce" }, body: raw });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { request_id: BATCH_ID, accepted: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, PATH);
  assert.deepEqual(Buffer.from(calls[0].body), raw);
  assert.equal(calls[0].headers["agentpass-nonce"], "public-nonce");
});

test("does not expose aliases, queries, trailing slash, method variants, or an absent adapter", async (t) => {
  const calls = [];
  const base = await startServer(t, { qualificationGrantBatchDeviceApi: { async handle(input) { calls.push(input); return { status: 200, body: { ok: true }, headers: {} }; } } });
  for (const [method, path] of [["GET", PATH], ["POST", `${PATH}?x=1`], ["POST", `${PATH}/`], ["POST", PATH.replace("qualification-grant-batches", "Qualification-Grant-Batches")], ["POST", PATH.replace(BATCH_ID, BATCH_ID.toUpperCase())]]) {
    const response = await fetch(`${base}${path}`, { method, body: method === "POST" ? "{}" : undefined });
    assert.equal(response.status, 404, `${method} ${path}`);
  }
  assert.equal(calls.length, 0);

  const absent = await startServer(t);
  const response = await fetch(`${absent}${PATH}`, { method: "POST", body: "not-json" });
  assert.equal(response.status, 404);
});

test("rejects an invalid qualification batch Device API adapter", () => {
  assert.throws(() => createCloudApi({ store: {}, qualificationGrantBatchDeviceApi: {} }), /qualificationGrantBatchDeviceApi must expose handle/);
});
