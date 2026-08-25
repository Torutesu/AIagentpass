import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../packages/protocol/src/index.mjs";
import { verifyExternalQualificationSignature } from "../scripts/release/verify-external-qualification-signature.mjs";
import { externalQualificationTrustPublicKeyFingerprint, externalQualificationTrustSigningData } from "../scripts/release/external-qualification-trust.mjs";

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const evidence = { kind: "agentpass-external-qualification", qualified: true, status: "passed" };
  const binding = { repository: "Torutesu/AIagentpass", source_commit: "a".repeat(40) };
  const payload = Buffer.from(canonicalJson({ evidence, binding }));
  const publicKeyBytes = publicKey.export({ type: "spki", format: "der" });
  const fingerprint = `SHA256:${createHash("sha256").update(publicKeyBytes).digest("base64url")}`;
  return { evidence, binding, publicKeyBytes, expectedFingerprint: fingerprint, signatureBase64: sign(null, payload, privateKey).toString("base64") };
}

test("verifies a detached Ed25519 signature over canonical aggregate evidence and binding", () => {
  const value = fixture();
  assert.deepEqual(verifyExternalQualificationSignature(value), { verified: true, fingerprint: value.expectedFingerprint, payload_sha256: createHash("sha256").update(canonicalJson({ evidence: value.evidence, binding: value.binding })).digest("hex") });
});

test("rejects substituted evidence, binding, signature, and public-key trust root", () => {
  const value = fixture();
  assert.throws(() => verifyExternalQualificationSignature({ ...value, evidence: { ...value.evidence, qualified: false } }), /signature is invalid/);
  assert.throws(() => verifyExternalQualificationSignature({ ...value, binding: { ...value.binding, source_commit: "b".repeat(40) } }), /signature is invalid/);
  assert.throws(() => verifyExternalQualificationSignature({ ...value, signatureBase64: Buffer.alloc(64).toString("base64") }), /signature is invalid/);
  const other = fixture();
  assert.throws(() => verifyExternalQualificationSignature({ ...value, publicKeyBytes: other.publicKeyBytes, expectedFingerprint: other.expectedFingerprint }), /signature is invalid/);
  assert.throws(() => verifyExternalQualificationSignature({ ...value, expectedFingerprint: "SHA256:" + "A".repeat(43) }), /fingerprint mismatch/);
  const privatePem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
  assert.throws(() => verifyExternalQualificationSignature({ ...value, publicKeyBytes: Buffer.from(privatePem) }), /must not contain private key/);
});

test("binds the detached child-evidence signature to aggregate evidence and binding", () => {
  const value = fixture();
  const childEvidence = { provider: "postgresql", status: "passed", evidence_sha256: "c".repeat(64) };
  const payload = Buffer.from(canonicalJson({ evidence: value.evidence, binding: value.binding, child_evidence: childEvidence }));
  const matching = generateKeyPairSync("ed25519");
  // A signature must be verified by the matching trusted key, not merely parse as Ed25519.
  const matchingBytes = matching.publicKey.export({ type: "spki", format: "der" });
  const signed = { ...value, childEvidence, signatureBase64: sign(null, payload, matching.privateKey).toString("base64"), publicKeyBytes: matchingBytes, expectedFingerprint: `SHA256:${createHash("sha256").update(matchingBytes).digest("base64url")}` };
  assert.equal(verifyExternalQualificationSignature(signed).verified, true);
  assert.throws(() => verifyExternalQualificationSignature({ ...signed, childEvidence: { ...childEvidence, status: "failed" } }), /signature is invalid/);
});

test("requires the evidence signer fingerprint to be authorized by the toolchain-signed trust manifest", () => {
  const value = fixture();
  const root = generateKeyPairSync("ed25519");
  const child = generateKeyPairSync("ed25519");
  const trustPayload = {
    schema_version: 1,
    type: "agentpass.external-qualification-trust",
    authority_id: "qualification-authority-v1",
    aggregate_fingerprint: value.expectedFingerprint,
    child_fingerprint: externalQualificationTrustPublicKeyFingerprint(child.publicKey),
    not_before: "2026-08-20T00:00:00.000Z",
    not_after: "2026-09-20T00:00:00.000Z"
  };
  const trustManifest = { ...trustPayload, signature_algorithm: "ed25519", signer_key_fingerprint: externalQualificationTrustPublicKeyFingerprint(root.publicKey), signature: sign(null, externalQualificationTrustSigningData(trustPayload), root.privateKey).toString("base64url") };
  assert.equal(verifyExternalQualificationSignature({ ...value, trustManifest, trustRole: "aggregate", now: Date.parse("2026-08-21T00:00:00.000Z") }).trust.authority_id, "qualification-authority-v1");
  assert.throws(() => verifyExternalQualificationSignature({ ...value, trustManifest, trustRole: "child", now: Date.parse("2026-08-21T00:00:00.000Z") }), /not trusted/);
});
