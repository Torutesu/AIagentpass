import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../packages/protocol/src/index.mjs";
import {
  DEPLOYMENT_ATTESTATION_TYPE, deploymentAttestationPublicKeyFingerprint, deploymentAttestationSigningData,
  deploymentAttestationStatementHash, deploymentAttestationTrustSigningData, DEPLOYMENT_OBSERVATION_TYPE, deploymentObservationSigningData,
  deploymentObservationStatementHash, normalizeDeploymentAttestation, normalizeDeploymentAttestationTrust, readDeploymentAttestationTrust, verifyDeploymentAttestation, verifyDeploymentAttestationTrust, verifyDeploymentAttestationTrustManifest, verifyDeploymentObservation
} from "../scripts/release/deployment-attestation.mjs";

const NOW = Date.parse("2026-08-20T00:00:00.000Z");
const pair = crypto.generateKeyPairSync("ed25519");
const statement = Object.freeze({ version: 1, type: DEPLOYMENT_ATTESTATION_TYPE, deployment_id: "deploy-1", environment: "staging", service: "agentpass-cloud-api", candidate_id: `release-pkg-sha256-v1-${"3".repeat(64)}`, revision: "rev-current", rollback_target_revision: "rev-previous", source_commit: "a".repeat(40), source_tree: "b".repeat(40), artifact_sha256: "c".repeat(64), release_manifest_sha256: "d".repeat(64), image_digest: `sha256:${"e".repeat(64)}`, schema_digest: "f".repeat(64), catalog_digest: "0".repeat(64), database_schema_digest: "2".repeat(64), run_id: "100", run_attempt: "1", job_id: "deploy", evidence_sha256: "1".repeat(64), key_id: "deployment-attestation-staging-v1", key_version: 1, issued_at: "2026-08-19T23:59:00.000Z", expires_at: "2026-08-20T00:10:00.000Z" });
const envelope = () => {
  const signature = crypto.sign(null, deploymentAttestationSigningData(statement, { now: NOW, allowExpired: true, allowFuture: true }), pair.privateKey).toString("base64url");
  return { version: 1, type: DEPLOYMENT_ATTESTATION_TYPE, statement, statement_hash: deploymentAttestationStatementHash(statement, { now: NOW, allowExpired: true, allowFuture: true }), signature_algorithm: "ed25519", signer_key_fingerprint: deploymentAttestationPublicKeyFingerprint(pair.publicKey), signature };
};

test("verifies a signed deployment attestation against the exact evidence binding", () => {
  const value = envelope();
  const verified = verifyDeploymentAttestation(value, { publicKey: pair.publicKey, expected: { deployment_id: "deploy-1", revision: "rev-current", rollback_target_revision: "rev-previous", evidence_sha256: statement.evidence_sha256 }, now: NOW });
  assert.equal(verified.statement.source_tree, statement.source_tree);
});

test("rejects statement substitution, signer substitution, and expired attestations", () => {
  const value = envelope();
  assert.throws(() => verifyDeploymentAttestation({ ...value, statement: { ...value.statement, revision: "rev-other" } }, { publicKey: pair.publicKey, now: NOW }), /ERR_DEPLOYMENT_ATTESTATION/u);
  const other = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => verifyDeploymentAttestation(value, { publicKey: other.publicKey, now: NOW }), /ERR_DEPLOYMENT_ATTESTATION/u);
  assert.throws(() => normalizeDeploymentAttestation({ ...value, statement: { ...value.statement, expires_at: "2026-08-20T00:00:00.000Z" } }, { now: NOW }), /ERR_DEPLOYMENT_ATTESTATION_TIME/u);
});

test("verifies independently signed health and traffic observations with immutable deployment bindings", () => {
  const observer = crypto.generateKeyPairSync("ed25519");
  const observation = {
    version: 1, type: DEPLOYMENT_OBSERVATION_TYPE, kind: "health", phase: "rollback", deployment_id: statement.deployment_id,
    revision: statement.rollback_target_revision, rollback_target_revision: statement.rollback_target_revision,
    image_digest: statement.image_digest, schema_digest: statement.schema_digest, catalog_digest: statement.catalog_digest,
    database_schema_digest: statement.database_schema_digest, status: "restored", observed_at: "2026-08-19T23:59:30.000Z",
    observer_id: "health-controller", observer_run_id: "101", observer_job_id: "health-check"
  };
  const value = {
    version: 1, type: DEPLOYMENT_OBSERVATION_TYPE, statement: observation, statement_hash: deploymentObservationStatementHash(observation, { now: NOW }),
    signature_algorithm: "ed25519", signer_key_fingerprint: deploymentAttestationPublicKeyFingerprint(observer.publicKey),
    signature: crypto.sign(null, deploymentObservationSigningData(observation, { now: NOW }), observer.privateKey).toString("base64url")
  };
  const verified = verifyDeploymentObservation(value, { publicKey: observer.publicKey, now: NOW, expected: { deployment_id: statement.deployment_id, revision: statement.rollback_target_revision, image_digest: statement.image_digest, database_schema_digest: statement.database_schema_digest } });
  assert.equal(verified.statement.observer_job_id, "health-check");
  assert.throws(() => verifyDeploymentObservation({ ...value, statement: { ...observation, image_digest: `sha256:${"a".repeat(64)}` } }, { publicKey: observer.publicKey, now: NOW }), /ERR_DEPLOYMENT_OBSERVATION/u);
  assert.throws(() => verifyDeploymentObservation(value, { publicKey: pair.publicKey, now: NOW }), /ERR_DEPLOYMENT_OBSERVATION/u);
});

test("requires the public key fingerprint and key version to be present in the reviewed trust manifest", () => {
  const value = envelope();
  const trust = { schema_version: 1, type: "agentpass.deployment-attestation-trust", keys: [{ environment: "staging", key_id: value.statement.key_id, key_version: value.statement.key_version, fingerprint: deploymentAttestationPublicKeyFingerprint(pair.publicKey), status: "active", not_before: "2026-01-01T00:00:00.000Z", not_after: "2027-01-01T00:00:00.000Z" }] };
  assert.equal(verifyDeploymentAttestationTrust({ attestation: value, publicKey: pair.publicKey, trustManifest: trust, now: NOW }).key_id, value.statement.key_id);
  assert.throws(() => verifyDeploymentAttestationTrust({ attestation: value, publicKey: pair.publicKey, trustManifest: { ...trust, keys: [{ ...trust.keys[0], key_version: 2 }] }, now: NOW }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
  assert.throws(() => verifyDeploymentAttestationTrust({ attestation: value, publicKey: pair.publicKey, trustManifest: { ...trust, keys: [{ ...trust.keys[0], status: "revoked" }] }, now: NOW }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
  assert.throws(() => verifyDeploymentAttestationTrust({ attestation: value, publicKey: pair.publicKey, trustManifest: { ...trust, keys: [{ ...trust.keys[0], not_after: "2026-01-01T00:00:00.000Z" }] }, now: NOW }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
});

test("does not accept a partial or unsigned attestation as trusted deployment evidence", () => {
  const value = envelope();
  const trust = { schema_version: 1, type: "agentpass.deployment-attestation-trust", keys: [{ environment: "staging", key_id: value.statement.key_id, key_version: value.statement.key_version, fingerprint: deploymentAttestationPublicKeyFingerprint(pair.publicKey), status: "active", not_before: "2026-01-01T00:00:00.000Z", not_after: "2027-01-01T00:00:00.000Z" }] };
  assert.throws(() => verifyDeploymentAttestationTrust({
    attestation: { statement: { environment: "staging", key_id: value.statement.key_id, key_version: value.statement.key_version } },
    publicKey: pair.publicKey,
    trustManifest: trust,
    now: NOW
  }), /ERR_DEPLOYMENT_ATTESTATION/u);
});

test("rejects malformed, duplicate, and reused trust-root entries", () => {
  const fingerprint = deploymentAttestationPublicKeyFingerprint(pair.publicKey);
  const entry = { environment: "staging", key_id: "deployment-attestation-staging-v1", key_version: 1, fingerprint, status: "active", not_before: "2026-01-01T00:00:00.000Z", not_after: "2027-01-01T00:00:00.000Z" };
  assert.deepEqual(normalizeDeploymentAttestationTrust({ schema_version: 1, type: "agentpass.deployment-attestation-trust", keys: [entry] }).keys[0], entry);
  assert.throws(() => normalizeDeploymentAttestationTrust({ schema_version: 1, type: "agentpass.deployment-attestation-trust", keys: [{ ...entry, extra: true }] }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
  assert.throws(() => normalizeDeploymentAttestationTrust({ schema_version: 1, type: "agentpass.deployment-attestation-trust", keys: [entry, { ...entry, key_version: 2 }] }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
  assert.throws(() => normalizeDeploymentAttestationTrust({ schema_version: 1, type: "agentpass.deployment-attestation-trust", keys: [entry, { ...entry, key_id: "other", fingerprint }] }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
});

test("rejects accessor-backed security envelopes instead of evaluating them", () => {
  const value = envelope();
  let evaluated = false;
  value.statement = { ...value.statement };
  Object.defineProperty(value.statement, "revision", { enumerable: true, configurable: true, get() { evaluated = true; return "rev-current"; } });
  assert.throws(() => normalizeDeploymentAttestation(value, { now: NOW }), /ERR_DEPLOYMENT_ATTESTATION_INPUT/u);
  assert.equal(evaluated, false);
});

test("requires a root-signed canonical trust manifest on the file boundary", (t) => {
  const rootPair = crypto.generateKeyPairSync("ed25519");
  const payload = { schema_version: 1, type: "agentpass.deployment-attestation-trust", keys: [{ environment: "staging", key_id: statement.key_id, key_version: 1, fingerprint: deploymentAttestationPublicKeyFingerprint(pair.publicKey), status: "active", not_before: "2026-01-01T00:00:00.000Z", not_after: "2027-01-01T00:00:00.000Z" }] };
  const signed = { ...payload, signature_algorithm: "ed25519", signer_key_fingerprint: deploymentAttestationPublicKeyFingerprint(rootPair.publicKey), signature: crypto.sign(null, deploymentAttestationTrustSigningData(payload), rootPair.privateKey).toString("base64url") };
  assert.equal(verifyDeploymentAttestationTrustManifest(signed, { rootPublicKey: rootPair.publicKey }).keys[0].key_id, statement.key_id);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-trust-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "trust.json");
  fs.writeFileSync(file, `${canonicalJson(signed)}\n`, { mode: 0o600 });
  assert.equal(readDeploymentAttestationTrust(file, { rootPublicKey: rootPair.publicKey }).keys.length, 1);
  const unsigned = path.join(root, "unsigned.json");
  fs.writeFileSync(unsigned, `${canonicalJson(payload)}\n`, { mode: 0o600 });
  assert.throws(() => readDeploymentAttestationTrust(unsigned, { rootPublicKey: rootPair.publicKey }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
  fs.rmSync(file);
  fs.symlinkSync(unsigned, file);
  assert.throws(() => readDeploymentAttestationTrust(file, { rootPublicKey: rootPair.publicKey }), /ERR_DEPLOYMENT_ATTESTATION_TRUST/u);
});
