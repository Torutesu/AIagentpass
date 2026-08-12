import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadCapabilityState, reserveCapabilityUse } from "../lib/capability-state.mjs";

function capability(sequence = 1, id = crypto.randomUUID()) {
  return { version: 1, capability_id: id, nonce: crypto.randomBytes(32).toString("base64url"), issuer: "cloud", key_id: "key-1", audience: { agent_id: crypto.randomUUID(), device_id: crypto.randomUUID() }, scope: { operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["feature/*"], deny: [] }, remotes: { allow: ["git@example.test:repo.git"], deny: [] } }, not_before: new Date(Date.now() - 1_000).toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(), sequence, signature: Buffer.alloc(64).toString("base64") };
}

test("capability replay evidence survives restart and exact request retry is idempotent", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cap-state-"));
  const file = path.join(root, "capability.state.json");
  const agentId = crypto.randomUUID();
  const requestId = crypto.randomUUID();
  const value = capability();
  assert.equal(reserveCapabilityUse(file, { capability: value, agentId, requestId }).replayed, false);
  assert.equal(loadCapabilityState(file).consumed[value.capability_id].request_id, requestId);
  assert.equal(reserveCapabilityUse(file, { capability: value, agentId, requestId }).replayed, true);
  assert.throws(() => reserveCapabilityUse(file, { capability: value, agentId, requestId: crypto.randomUUID() }), /already been consumed/);
});

test("capability ledger rejects rollback, same-sequence equivocation, and unsafe links", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cap-state-"));
  const file = path.join(root, "capability.state.json");
  const agentId = crypto.randomUUID();
  reserveCapabilityUse(file, { capability: capability(2), agentId, requestId: crypto.randomUUID() });
  assert.throws(() => reserveCapabilityUse(file, { capability: capability(1), agentId, requestId: crypto.randomUUID() }), /rolled back/);
  assert.throws(() => reserveCapabilityUse(file, { capability: capability(2), agentId, requestId: crypto.randomUUID() }), /conflicts/);
  const link = path.join(root, "linked.json");
  fs.symlinkSync(file, link);
  assert.throws(() => loadCapabilityState(link), /unsafe/);
});
