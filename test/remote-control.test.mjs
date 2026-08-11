import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { applyControlBundle, evaluateRemoteControl, fetchControlBundle, generateControlKeyPair, loadControlBundle, signControlBundle, startControlRefresh, verifyControlBundle } from "../lib/remote-control.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-control-"));
  const keys = generateControlKeyPair(path.join(root, "offline"));
  const publicKey = fs.readFileSync(keys.public_file, "utf8");
  const config = { control: { required: true, public_key: publicKey } };
  return { root, keys, publicKey, config };
}

test("offline control bundles are signed, verified, and evaluated", () => {
  const data = fixture();
  const agentId = cryptoRandomUuid();
  const bundle = signControlBundle({ sequence: 1, expiresAt: Date.now() + 60_000, revokedAgents: [agentId] }, data.keys.private_file);
  assert.equal(verifyControlBundle(bundle, data.publicKey).sequence, 1);
  assert.equal(evaluateRemoteControl(bundle, agentId).reason, "remote_agent_revoked");
  assert.equal(evaluateRemoteControl(bundle, cryptoRandomUuid()).allowed, true);
  assert.throws(() => verifyControlBundle({ ...bundle, global_revoked: true }, data.publicKey), /signature is invalid/);
  const stopped = signControlBundle({ sequence: 2, expiresAt: Date.now() + 60_000, globalRevoked: true }, data.keys.private_file);
  assert.equal(evaluateRemoteControl(stopped, cryptoRandomUuid()).reason, "remote_global_revocation");
});

test("expired, overlong, and runtime-rollback bundles fail closed", () => {
  const data = fixture();
  const historical = signControlBundle({ sequence: 2, expiresAt: 60_000 }, data.keys.private_file, 0);
  assert.throws(() => verifyControlBundle(historical, data.publicKey, { now: 120_000 }), /expired/);
  assert.throws(() => signControlBundle({ sequence: 3, expiresAt: 8 * 24 * 60 * 60 * 1000 }, data.keys.private_file, 0), /must not exceed 7 days/);
  const older = signControlBundle({ sequence: 1, expiresAt: Date.now() + 60_000 }, data.keys.private_file);
  assert.throws(() => verifyControlBundle(older, data.publicKey, { highestSequence: 2 }), /rollback/);
});

test("control persistence rejects rollback and same-sequence equivocation", () => {
  const data = fixture();
  const first = signControlBundle({ sequence: 2, expiresAt: Date.now() + 60_000 }, data.keys.private_file);
  applyControlBundle(first, data.config, data.root);
  assert.equal(loadControlBundle(data.config, data.root).sequence, 2);

  const rollback = signControlBundle({ sequence: 1, expiresAt: Date.now() + 60_000 }, data.keys.private_file);
  assert.throws(() => applyControlBundle(rollback, data.config, data.root), /rollback/);
  const equivocation = signControlBundle({ sequence: 2, expiresAt: Date.now() + 120_000, globalRevoked: true }, data.keys.private_file);
  assert.throws(() => applyControlBundle(equivocation, data.config, data.root), /equivocation/);
});

test("control fetch requires HTTPS and bounds the response", async () => {
  const data = fixture();
  const bundle = signControlBundle({ sequence: 1, expiresAt: Date.now() + 60_000 }, data.keys.private_file);
  const fetched = await fetchControlBundle("https://control.example/bundle.json", { fetchImpl: async () => new Response(JSON.stringify(bundle), { status: 200, headers: { "content-type": "application/json" } }) });
  assert.equal(fetched.sequence, 1);
  await assert.rejects(fetchControlBundle("http://control.example/bundle.json"), /requires HTTPS/);
  await assert.rejects(fetchControlBundle("https://control.example/large", { fetchImpl: async () => new Response("x", { status: 200, headers: { "content-length": String(300 * 1024) } }) }), /too large/);
});

test("background refresh installs a higher signed sequence and reports it", async () => {
  const data = fixture();
  data.config.control.url = "https://control.example/bundle.json";
  data.config.control.refresh_seconds = 15;
  const first = signControlBundle({ sequence: 1, expiresAt: Date.now() + 60_000 }, data.keys.private_file);
  applyControlBundle(first, data.config, data.root);
  const second = signControlBundle({ sequence: 2, expiresAt: Date.now() + 60_000 }, data.keys.private_file);
  const cache = { highestSequence: 1, bundle: first };
  const events = [];
  const timer = startControlRefresh(data.config, data.root, cache, { fetchImpl: async () => new Response(JSON.stringify(second), { status: 200 }), onEvent: (event) => events.push(event) });
  try {
    for (let attempt = 0; attempt < 50 && cache.highestSequence !== 2; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(cache.highestSequence, 2);
    assert.equal(events[0].result, "updated");
  } finally {
    clearInterval(timer);
  }
});

function cryptoRandomUuid() {
  return globalThis.crypto.randomUUID();
}
