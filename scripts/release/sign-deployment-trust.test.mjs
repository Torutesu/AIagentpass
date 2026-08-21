import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  DEPLOYMENT_ATTESTATION_TYPE,
  deploymentAttestationPublicKeyFingerprint,
  deploymentAttestationSigningData,
  deploymentAttestationStatementHash,
  readDeploymentAttestationTrust,
  verifyDeploymentAttestationTrust
} from "./deployment-attestation.mjs";
import {
  PLACEHOLDER_FINGERPRINT,
  PLACEHOLDER_SIGNATURE,
  buildSignedDeploymentTrustManifest,
  signDeploymentTrust
} from "./sign-deployment-trust.mjs";

const NOW = Date.parse("2026-08-20T00:00:00.000Z");
const TRUST_TYPE = "agentpass.deployment-attestation-trust";

function keyEntry(publicKey, { keyId = "deployment-attestation-staging-v1", keyVersion = 1, status = "active", notBefore = "2026-01-01T00:00:00.000Z", notAfter = "2027-01-01T00:00:00.000Z" } = {}) {
  return { environment: "staging", key_id: keyId, key_version: keyVersion, fingerprint: deploymentAttestationPublicKeyFingerprint(publicKey), status, not_before: notBefore, not_after: notAfter };
}

function placeholderManifest() {
  return {
    keys: [{ environment: "staging", fingerprint: PLACEHOLDER_FINGERPRINT, key_id: "deployment-attestation-staging-v1", key_version: 1, not_after: "2027-01-01T00:00:00.000Z", not_before: "2026-01-01T00:00:00.000Z", status: "active" }],
    schema_version: 1,
    signature: PLACEHOLDER_SIGNATURE,
    signature_algorithm: "ed25519",
    signer_key_fingerprint: PLACEHOLDER_FINGERPRINT,
    type: TRUST_TYPE
  };
}

function writeCanonical(filePath, value, mode = 0o600) {
  fs.writeFileSync(filePath, `${canonicalJson(value)}\n`, { mode });
}

function tempFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-deployment-trust-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rootPair = crypto.generateKeyPairSync("ed25519");
  const attestationPair = crypto.generateKeyPairSync("ed25519");
  const rootPrivatePath = path.join(root, "root-private.pem");
  fs.writeFileSync(rootPrivatePath, rootPair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const manifestPath = path.join(root, "placeholder.json");
  writeCanonical(manifestPath, placeholderManifest());
  const keysPath = path.join(root, "keys.json");
  writeCanonical(keysPath, [keyEntry(attestationPair.publicKey)]);
  return { root, rootPair, attestationPair, rootPrivatePath, manifestPath, keysPath };
}

function attestation(pair, { expiresAt = "2026-08-20T00:10:00.000Z" } = {}) {
  const statement = {
    version: 1, type: DEPLOYMENT_ATTESTATION_TYPE, deployment_id: "deploy-1", environment: "staging", service: "agentpass-cloud-api",
    candidate_id: `release-pkg-sha256-v1-${"3".repeat(64)}`, revision: "rev-current", rollback_target_revision: "rev-previous",
    source_commit: "a".repeat(40), source_tree: "b".repeat(40), artifact_sha256: "c".repeat(64), release_manifest_sha256: "d".repeat(64),
    image_digest: `sha256:${"e".repeat(64)}`, schema_digest: "f".repeat(64), catalog_digest: "0".repeat(64), database_schema_digest: "2".repeat(64),
    run_id: "100", run_attempt: "1", job_id: "deploy", evidence_sha256: "1".repeat(64), key_id: "deployment-attestation-staging-v1", key_version: 1,
    issued_at: "2026-08-19T23:59:00.000Z", expires_at: expiresAt
  };
  return {
    version: 1, type: DEPLOYMENT_ATTESTATION_TYPE, statement,
    statement_hash: deploymentAttestationStatementHash(statement, { now: NOW, allowExpired: true, allowFuture: true }),
    signature_algorithm: "ed25519", signer_key_fingerprint: deploymentAttestationPublicKeyFingerprint(pair.publicKey),
    signature: crypto.sign(null, deploymentAttestationSigningData(statement, { now: NOW, allowExpired: true, allowFuture: true }), pair.privateKey).toString("base64url")
  };
}

test("updates the placeholder, emits a canonical mode-0600 envelope, and round-trips through the reader", (t) => {
  const fixture = tempFixture(t);
  const outputPath = path.join(fixture.root, "signed.json");
  const result = signDeploymentTrust({ manifestPath: fixture.manifestPath, privateKeyPath: fixture.rootPrivatePath, keysPath: fixture.keysPath, outputPath, now: NOW });
  assert.equal(result.key_count, 1);
  const outputBytes = fs.readFileSync(outputPath);
  assert.equal(outputBytes.toString("utf8"), `${canonicalJson(JSON.parse(outputBytes))}\n`);
  const stat = fs.statSync(outputPath);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(stat.nlink, 1);
  const trust = readDeploymentAttestationTrust(outputPath, { rootPublicKey: fixture.rootPair.publicKey });
  assert.equal(trust.keys[0].fingerprint, keyEntry(fixture.attestationPair.publicKey).fingerprint);
  assert.equal(verifyDeploymentAttestationTrust({ attestation: attestation(fixture.attestationPair), publicKey: fixture.attestationPair.publicKey, trustManifest: trust, now: NOW }).key_version, 1);
});

test("preserves an active key during rotation and rejects revoked or expired trust entries", (t) => {
  const fixture = tempFixture(t);
  const first = path.join(fixture.root, "first.json");
  signDeploymentTrust({ manifestPath: fixture.manifestPath, privateKeyPath: fixture.rootPrivatePath, keysPath: fixture.keysPath, outputPath: first, now: NOW });
  const replacement = crypto.generateKeyPairSync("ed25519");
  const rotationKeys = [
    keyEntry(fixture.attestationPair.publicKey, { status: "revoked" }),
    keyEntry(replacement.publicKey, { keyId: "deployment-attestation-staging-v2", keyVersion: 2 })
  ];
  const rotationKeysPath = path.join(fixture.root, "rotation-keys.json");
  writeCanonical(rotationKeysPath, rotationKeys);
  const rotated = path.join(fixture.root, "rotated.json");
  signDeploymentTrust({ manifestPath: first, privateKeyPath: fixture.rootPrivatePath, keysPath: rotationKeysPath, outputPath: rotated, now: NOW });
  const trust = readDeploymentAttestationTrust(rotated, { rootPublicKey: fixture.rootPair.publicKey });
  assert.throws(() => verifyDeploymentAttestationTrust({ attestation: attestation(fixture.attestationPair), publicKey: fixture.attestationPair.publicKey, trustManifest: trust, now: NOW }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
  const replacementAttestation = attestation(replacement);
  const replacementStatement = { ...replacementAttestation.statement, key_id: "deployment-attestation-staging-v2", key_version: 2 };
  const replacementValue = { ...replacementAttestation, statement: replacementStatement, statement_hash: deploymentAttestationStatementHash(replacementStatement, { now: NOW, allowExpired: true, allowFuture: true }), signature: crypto.sign(null, deploymentAttestationSigningData(replacementStatement, { now: NOW, allowExpired: true, allowFuture: true }), replacement.privateKey).toString("base64url") };
  assert.equal(verifyDeploymentAttestationTrust({ attestation: replacementValue, publicKey: replacement.publicKey, trustManifest: trust, now: NOW }).key_version, 2);

  const expiredTrust = buildSignedDeploymentTrustManifest({ keys: [keyEntry(replacement.publicKey, { keyId: "deployment-attestation-staging-v2", keyVersion: 2, notAfter: "2026-08-19T23:00:00.000Z" })], privateKey: fixture.rootPair.privateKey });
  assert.throws(() => verifyDeploymentAttestationTrust({ attestation: replacementValue, publicKey: replacement.publicKey, trustManifest: expiredTrust, now: NOW }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
});

test("rejects symlink, malformed, duplicate, and unsafe rotation inputs", (t) => {
  const fixture = tempFixture(t);
  const outputPath = path.join(fixture.root, "output.json");
  const symlinkManifest = path.join(fixture.root, "manifest-link.json");
  fs.symlinkSync(fixture.manifestPath, symlinkManifest);
  assert.throws(() => signDeploymentTrust({ manifestPath: symlinkManifest, privateKeyPath: fixture.rootPrivatePath, keysPath: fixture.keysPath, outputPath, now: NOW }), /cannot open trust manifest/u);

  const malformedKeysPath = path.join(fixture.root, "malformed-keys.json");
  writeCanonical(malformedKeysPath, [{ ...keyEntry(fixture.attestationPair.publicKey), unexpected: true }]);
  assert.throws(() => signDeploymentTrust({ manifestPath: fixture.manifestPath, privateKeyPath: fixture.rootPrivatePath, keysPath: malformedKeysPath, outputPath, now: NOW }), /malformed/u);

  const duplicateKeysPath = path.join(fixture.root, "duplicate-keys.json");
  writeCanonical(duplicateKeysPath, [keyEntry(fixture.attestationPair.publicKey), keyEntry(fixture.attestationPair.publicKey, { keyVersion: 2 })]);
  assert.throws(() => signDeploymentTrust({ manifestPath: fixture.manifestPath, privateKeyPath: fixture.rootPrivatePath, keysPath: duplicateKeysPath, outputPath, now: NOW }), /malformed/u);

  const signed = path.join(fixture.root, "signed.json");
  signDeploymentTrust({ manifestPath: fixture.manifestPath, privateKeyPath: fixture.rootPrivatePath, keysPath: fixture.keysPath, outputPath: signed, now: NOW });
  const removalKeysPath = path.join(fixture.root, "removal-keys.json");
  const unrelatedKey = crypto.generateKeyPairSync("ed25519");
  writeCanonical(removalKeysPath, [keyEntry(unrelatedKey.publicKey, { keyId: "deployment-attestation-staging-v2", keyVersion: 2 })]);
  assert.throws(() => signDeploymentTrust({ manifestPath: signed, privateKeyPath: fixture.rootPrivatePath, keysPath: removalKeysPath, outputPath, now: NOW }), /active unexpired/u);

  fs.writeFileSync(outputPath, "do not overwrite\n", { mode: 0o600 });
  assert.throws(() => signDeploymentTrust({ manifestPath: fixture.manifestPath, privateKeyPath: fixture.rootPrivatePath, keysPath: fixture.keysPath, outputPath, now: NOW }), /cannot create trust manifest output/u);
  assert.equal(fs.readFileSync(outputPath, "utf8"), "do not overwrite\n");
});
