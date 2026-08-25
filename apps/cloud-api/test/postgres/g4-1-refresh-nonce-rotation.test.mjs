import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  REFRESH_HINT_SERVICE_ERROR_CODES,
  createRefreshHintService
} from "../../src/refresh-hint-service.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const OTHER_ORGANIZATION_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_DEVICE_ID = "44444444-4444-4444-8444-444444444444";
const OUTBOX_ID = "55555555-5555-4555-8555-555555555555";
const OTHER_OUTBOX_ID = "66666666-6666-4666-8666-666666666666";
const OLD_KEY_ID = "refresh-nonce-v1";
const NEW_KEY_ID = "refresh-nonce-v3";
const OLD_KEY = Buffer.alloc(32, 0x11);
const NEW_KEY = Buffer.alloc(32, 0x33);
const NOW = Date.parse("2026-08-13T00:00:00.000Z");

const TUPLE = Object.freeze({
  organization_id: ORGANIZATION_ID,
  device_id: DEVICE_ID,
  authority_generation: 41,
  outbox_id: OUTBOX_ID
});

function codec(activeKeyId, keys = { [OLD_KEY_ID]: OLD_KEY, [NEW_KEY_ID]: NEW_KEY }) {
  return createRefreshNonceCodec({ keys, activeKeyId });
}

function metadata(derived, generation = TUPLE.authority_generation) {
  return {
    organization_id: derived.organization_id,
    device_id: derived.device_id,
    desired_generation: generation,
    refresh_state: "pending",
    outbox_id: derived.outbox_id,
    refresh_nonce_key_id: derived.key_id,
    refresh_nonce_digest: derived.nonce_digest,
    published_at: "2026-08-13T00:00:00.000Z",
    expires_at: "2026-08-13T00:05:00.000Z"
  };
}

function serviceFor(row, nonceDeriver) {
  const signingKeys = crypto.generateKeyPairSync("ed25519");
  let delivered;
  return {
    delivered: () => delivered,
    service: createRefreshHintService({
      source: {
        async pollDeviceRefresh() { return row; },
        async markDeviceRefreshDelivered(input) { delivered = input; }
      },
      nonceDeriver,
      signer: {
        async publicKeyMetadata() { return { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: signingKeys.publicKey }; },
        async signRefreshHint(bytes) { return crypto.sign(null, bytes, signingKeys.privateKey); }
      },
      now: () => NOW,
      hintTtlMs: 60_000
    })
  };
}

test("dual-read runtime instances reconstruct retained old rows and single-write uses active new key", async () => {
  const preRotation = codec(OLD_KEY_ID, { [OLD_KEY_ID]: OLD_KEY });
  const runtimeA = codec(NEW_KEY_ID);
  const runtimeB = codec(NEW_KEY_ID);
  const oldRow = metadata(preRotation.derive(TUPLE));
  const oldA = serviceFor(oldRow, runtimeA);
  const oldB = serviceFor(oldRow, runtimeB);
  const [oldHintA, oldHintB] = await Promise.all([
    oldA.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 40 }),
    oldB.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 40 })
  ]);

  assert.equal(oldRow.refresh_nonce_key_id, OLD_KEY_ID);
  assert.equal(oldHintA.nonce, oldHintB.nonce);
  assert.equal(oldHintA.nonce, preRotation.derive(TUPLE).nonce_base64url);
  assert.equal(oldA.delivered().outbox_id, OUTBOX_ID);
  assert.equal(oldB.delivered().outbox_id, OUTBOX_ID);

  const newTuple = { ...TUPLE, authority_generation: 42, outbox_id: OTHER_OUTBOX_ID };
  const newWrite = runtimeB.derive(newTuple);
  const newRow = metadata(newWrite, newTuple.authority_generation);
  const newA = serviceFor(newRow, runtimeA);
  const newB = serviceFor(newRow, runtimeB);
  const [newHintA, newHintB] = await Promise.all([
    newA.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 41 }),
    newB.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 41 })
  ]);

  assert.equal(newRow.refresh_nonce_key_id, NEW_KEY_ID);
  assert.equal(newHintA.nonce, newHintB.nonce);
  assert.equal(newHintA.nonce, newWrite.nonce_base64url);
  assert.notEqual(newHintA.nonce, oldHintA.nonce);
});

test("old-key removal fails closed for a retained old row, while removed rows return no refresh", async () => {
  const dualRead = codec(NEW_KEY_ID);
  const oldRow = metadata(codec(OLD_KEY_ID, { [OLD_KEY_ID]: OLD_KEY }).derive(TUPLE));
  const newOnly = codec(NEW_KEY_ID, { [NEW_KEY_ID]: NEW_KEY });
  const retained = serviceFor(oldRow, newOnly);

  await assert.rejects(
    retained.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 40 }),
    { code: REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE }
  );
  assert.equal(dualRead.derive({ ...TUPLE, key_id: OLD_KEY_ID }).nonce_digest, oldRow.refresh_nonce_digest);
  assert.throws(() => newOnly.derive({ ...TUPLE, key_id: OLD_KEY_ID }), { code: "ERR_REFRESH_NONCE_KEY_UNAVAILABLE" });

  const cleanedSource = {
    async pollDeviceRefresh() { return null; },
    async markDeviceRefreshDelivered() {}
  };
  const cleaned = createRefreshHintService({
    source: cleanedSource,
    nonceDeriver: newOnly,
    signer: {
      async publicKeyMetadata() { return { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: crypto.generateKeyPairSync("ed25519").publicKey }; },
      async signRefreshHint() { return Buffer.alloc(64); }
    },
    now: () => NOW
  });
  assert.equal(await cleaned.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 40 }), null);
});

test("organization, device, generation, and outbox substitutions never match the retained digest", () => {
  const derived = codec(NEW_KEY_ID).derive(TUPLE);
  const substitutions = [
    { organization_id: OTHER_ORGANIZATION_ID },
    { device_id: OTHER_DEVICE_ID },
    { authority_generation: TUPLE.authority_generation + 1 },
    { outbox_id: OTHER_OUTBOX_ID }
  ];
  for (const substitution of substitutions) {
    const candidate = codec(NEW_KEY_ID).derive({ ...TUPLE, ...substitution });
    assert.equal(candidate.nonce_digest === derived.nonce_digest, false);
    assert.equal(codec(NEW_KEY_ID).matchesDigest(candidate, derived.nonce_digest), false);
  }
});

test("SQL/report-shaped metadata and logs contain only key id and digest, never the raw nonce", () => {
  const derived = codec(NEW_KEY_ID).derive(TUPLE);
  const row = metadata(derived);
  const report = JSON.stringify({ sql: "SELECT refresh_nonce_key_id,refresh_nonce_digest FROM device_refresh_outbox", row });
  const log = JSON.stringify({ event: "refresh_poll", ...row });

  assert.equal(report.includes(derived.nonce_base64url), false);
  assert.equal(log.includes(derived.nonce_base64url), false);
  assert.equal(JSON.stringify(derived).includes(derived.nonce_base64url), false);
  assert.deepEqual(Object.keys(row).sort(), [
    "desired_generation", "device_id", "expires_at", "organization_id", "outbox_id",
    "published_at", "refresh_nonce_digest", "refresh_nonce_key_id", "refresh_state"
  ]);
});
