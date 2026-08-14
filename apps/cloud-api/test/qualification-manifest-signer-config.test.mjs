import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createHostedQualificationManifestSigner, parseQualificationManifestSignerConfig } from "../src/qualification-manifest-signer-config.mjs";

const NOW = Date.parse("2026-08-14T00:00:00.000Z");

function fixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const pem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const env = {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID: "qualification-2026-08",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY: pem
  };
  const provider = {
    async publicKeyMetadata({ key_id }) { return { key_id, algorithm: "ed25519", public_key: pem }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, keys.privateKey); }
  };
  return { keys, pem, env, provider };
}

test("hosted qualification signer exposes bounded public health and a purpose-separated key ring", async () => {
  const value = fixture();
  const signer = createHostedQualificationManifestSigner({ provider: value.provider, env: value.env, now: () => NOW });
  assert.equal(signer.key_id, "qualification-2026-08");
  assert.deepEqual(await signer.publicKeyMetadata(), {
    key_id: "qualification-2026-08",
    algorithm: "ed25519",
    public_key: value.pem
  });
  assert.deepEqual((await signer.verificationKeyMetadata()).keys.map(({ key_id, status }) => ({ key_id, status })), [
    { key_id: "qualification-2026-08", status: "active" }
  ]);
  const health = await signer.health();
  assert.equal(health.ready, true);
  assert.equal(health.purpose, "agentpass.qualification-grant-batch-manifest");
  assert.match(health.public_key_fingerprint, /^[0-9a-f]{64}$/u);
  assert.equal(JSON.stringify(signer).includes("PRIVATE KEY"), false);
});

test("configuration rejects cross-purpose key reuse and provider substitution", async () => {
  const value = fixture();
  assert.throws(() => parseQualificationManifestSignerConfig(value.env, { agentSession: [{ publicKey: value.pem }] }, { now: () => NOW }), { code: "ERR_QUALIFICATION_MANIFEST_SIGNER_CONFIG" });
  const other = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
  const signer = createHostedQualificationManifestSigner({
    env: value.env,
    now: () => NOW,
    provider: { ...value.provider, async publicKeyMetadata({ key_id }) { return { key_id, algorithm: "ed25519", public_key: other }; } }
  });
  await assert.rejects(() => signer.health(), { code: "ERR_QUALIFICATION_MANIFEST_SIGNER_CONFIG" });
});

test("retiring verification keys require a bounded future expiry", async () => {
  const value = fixture();
  const retiring = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
  const env = {
    ...value.env,
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_VERIFICATION_KEYS_JSON: JSON.stringify([{
      key_id: "qualification-2026-07",
      public_key: retiring,
      not_after: new Date(NOW + 60_000).toISOString()
    }])
  };
  const signer = createHostedQualificationManifestSigner({ provider: value.provider, env, now: () => NOW });
  assert.equal((await signer.verificationKeyMetadata()).keys.length, 2);
  await assert.rejects(() => signer.verificationKeyMetadata("qualification-2026-07", { at: NOW + 60_000 }), { code: "ERR_QUALIFICATION_MANIFEST_SIGNER_CONFIG" });
});
