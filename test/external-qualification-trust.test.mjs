import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../packages/protocol/src/index.mjs";
import { externalQualificationTrustSigningData, externalQualificationTrustPublicKeyFingerprint, verifyExternalQualificationTrustManifest } from "../scripts/release/external-qualification-trust.mjs";

const NOW = Date.parse("2026-08-21T00:00:00.000Z");

function makeTrust() {
  const root = generateKeyPairSync("ed25519");
  const aggregate = generateKeyPairSync("ed25519");
  const child = generateKeyPairSync("ed25519");
  const payload = {
    schema_version: 1,
    type: "agentpass.external-qualification-trust",
    authority_id: "qualification-authority-v1",
    aggregate_fingerprint: externalQualificationTrustPublicKeyFingerprint(aggregate.publicKey),
    child_fingerprint: externalQualificationTrustPublicKeyFingerprint(child.publicKey),
    not_before: "2026-08-20T00:00:00.000Z",
    not_after: "2026-09-20T00:00:00.000Z"
  };
  const manifest = { ...payload, signature_algorithm: "ed25519", signer_key_fingerprint: externalQualificationTrustPublicKeyFingerprint(root.publicKey), signature: sign(null, externalQualificationTrustSigningData(payload), root.privateKey).toString("base64url") };
  return { root, aggregate, child, manifest };
}

test("verifies an external qualification trust manifest signed by the protected toolchain root", () => {
  const value = makeTrust();
  const verified = verifyExternalQualificationTrustManifest(value.manifest, { rootPublicKey: value.root.publicKey, now: NOW });
  assert.equal(verified.authority_id, "qualification-authority-v1");
});

test("rejects trust manifest substitution, root substitution, duplicate signer roles, and expiry", () => {
  const value = makeTrust();
  assert.throws(() => verifyExternalQualificationTrustManifest({ ...value.manifest, aggregate_fingerprint: value.manifest.child_fingerprint }, { rootPublicKey: value.root.publicKey, now: NOW }), /invalid/);
  const otherRoot = generateKeyPairSync("ed25519");
  assert.throws(() => verifyExternalQualificationTrustManifest(value.manifest, { rootPublicKey: otherRoot.publicKey, now: NOW }), /signature is invalid/);
  assert.throws(() => verifyExternalQualificationTrustManifest(value.manifest, { rootPublicKey: value.root.privateKey, now: NOW }), /must be public/);
  assert.throws(() => verifyExternalQualificationTrustManifest(value.manifest, { rootPublicKey: value.root.publicKey, now: Date.parse("2026-10-01T00:00:00.000Z") }), /validity window/);
  assert.doesNotMatch(canonicalJson(value.manifest), /PRIVATE KEY/);
});
