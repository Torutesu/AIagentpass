import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { bundleAcknowledgementSigningData } from "../packages/protocol/src/index.mjs";
import { normalizeNativeControlRefreshResponse } from "../bin/agentpass.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";
const statementHash = "a".repeat(64);
const halfOrder = Buffer.from("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "hex");

function response(overrides = {}) {
  const key = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey;
  const acknowledgement = {
    version: 1,
    type: "agentpass.bundle-ack",
    organization_id: organizationId,
    device_id: deviceId,
    device_key_epoch: 4,
    format_epoch: 2,
    sequence: 7,
    statement_hash: statementHash,
    result: "applied",
    observed_at: "2026-08-16T00:00:00.000Z",
    nonce: "EREREREREREREREREREREQ",
    signature_algorithm: "p256-sha256"
  };
  const placeholder = { ...acknowledgement, signature: Buffer.alloc(64, 1).toString("base64url") };
  let signature;
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const candidate = crypto.sign("sha256", bundleAcknowledgementSigningData(placeholder), { key, dsaEncoding: "ieee-p1363" });
    if (candidate.subarray(32).compare(halfOrder) <= 0) { signature = candidate; break; }
  }
  if (!signature) throw new Error("could not create a canonical low-S test ACK");
  return {
    status: "enabled",
    control_refreshed: true,
    control_ack: {
      acknowledgement: { ...acknowledgement, signature: signature.toString("base64url") },
      server_accepted: true,
      observed_generation: 3,
      refresh_state: "applied"
    },
    refresh_generation: 3,
    refresh_sequence: 7,
    control_statement_hash: statementHash,
    ...overrides
  };
}

test("normalizes the closed native refresh response to the onboarding shape", () => {
  const normalized = normalizeNativeControlRefreshResponse(response());
  assert.deepEqual(Object.keys(normalized), ["status", "control_refreshed", "control_ack", "refresh_generation", "refresh_sequence", "control_statement_hash"]);
  assert.equal(normalized.control_ack.server_accepted, true);
  assert.equal(normalized.control_ack.refresh_state, "applied");
  assert.equal(normalized.control_ack.acknowledgement.result, "applied");
  assert.equal(normalized.refresh_generation, 3);
  assert.equal(normalized.refresh_sequence, 7);
});

test("rejects blocked, mismatched, expanded, and path-bearing responses", () => {
  assert.throws(() => normalizeNativeControlRefreshResponse(response({ control_ack: { ...response().control_ack, refresh_state: "blocked" } })), /accepted as applied/u);
  assert.throws(() => normalizeNativeControlRefreshResponse(response({ refresh_sequence: 8 })), /binding is invalid/u);
  assert.throws(() => normalizeNativeControlRefreshResponse({ ...response(), unexpected: true }), /closed public schema/u);
  assert.throws(() => normalizeNativeControlRefreshResponse({ ...response(), source_url: "https://example.test/v1" }), /closed public schema/u);
});
