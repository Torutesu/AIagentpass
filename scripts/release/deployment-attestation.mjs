#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const DEPLOYMENT_ATTESTATION_VERSION = 1;
export const DEPLOYMENT_ATTESTATION_TYPE = "agentpass.deployment-attestation";
export const DEPLOYMENT_ATTESTATION_ALGORITHM = "ed25519";
export const DEPLOYMENT_ATTESTATION_DOMAIN = "AgentPass-Deployment-Attestation-v1\0";
export const DEPLOYMENT_ATTESTATION_TRUST_DOMAIN = "AgentPass-Deployment-Attestation-Trust-v1\0";
export const DEPLOYMENT_ATTESTATION_MAX_TTL_MS = 15 * 60 * 1000;
const SHA = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const RUN = /^[1-9][0-9]{0,19}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const IMAGE = /^sha256:[0-9a-f]{64}$/u;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;

export const DEPLOYMENT_ATTESTATION_STATEMENT_KEYS = Object.freeze([
  "version", "type", "deployment_id", "environment", "service", "candidate_id", "revision", "rollback_target_revision",
  "source_commit", "source_tree", "artifact_sha256", "release_manifest_sha256", "image_digest", "schema_digest", "catalog_digest", "database_schema_digest",
  "run_id", "run_attempt", "job_id", "evidence_sha256", "key_id", "key_version", "issued_at", "expires_at"
]);
export const DEPLOYMENT_ATTESTATION_ENVELOPE_KEYS = Object.freeze(["version", "type", "statement", "statement_hash", "signature_algorithm", "signer_key_fingerprint", "signature"]);
const DEPLOYMENT_ATTESTATION_TRUST_PAYLOAD_KEYS = Object.freeze(["schema_version", "type", "keys"]);
const DEPLOYMENT_ATTESTATION_TRUST_ENVELOPE_KEYS = Object.freeze([...DEPLOYMENT_ATTESTATION_TRUST_PAYLOAD_KEYS, "signature_algorithm", "signer_key_fingerprint", "signature"]);

export class DeploymentAttestationError extends Error {
  constructor(code) { super(code); this.name = "DeploymentAttestationError"; this.code = code; }
}

export function normalizeDeploymentAttestationStatement(input, { now = Date.now(), allowExpired = false, allowFuture = false, maxTtlMs = DEPLOYMENT_ATTESTATION_MAX_TTL_MS } = {}) {
  exactObject(input, DEPLOYMENT_ATTESTATION_STATEMENT_KEYS);
  const value = { ...input };
  if (value.version !== 1 || value.type !== DEPLOYMENT_ATTESTATION_TYPE || !ID.test(value.deployment_id) || !["staging", "production"].includes(value.environment) || !ID.test(value.service) || !/^release-pkg-sha256-v1-[0-9a-f]{64}$/u.test(value.candidate_id) || !ID.test(value.revision) || !ID.test(value.rollback_target_revision)
    || !COMMIT.test(value.source_commit) || !COMMIT.test(value.source_tree) || !SHA.test(value.artifact_sha256) || !SHA.test(value.release_manifest_sha256) || !IMAGE.test(value.image_digest) || !SHA.test(value.schema_digest) || !SHA.test(value.catalog_digest) || !SHA.test(value.database_schema_digest)
    || !RUN.test(value.run_id) || !RUN.test(value.run_attempt) || !ID.test(value.job_id) || !SHA.test(value.evidence_sha256) || !ID.test(value.key_id) || !Number.isSafeInteger(value.key_version) || value.key_version < 1 || !TIME.test(value.issued_at) || !TIME.test(value.expires_at)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_INPUT");
  const issued = Date.parse(value.issued_at); const expires = Date.parse(value.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > maxTtlMs || (!allowFuture && now < issued) || (!allowExpired && now >= expires)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TIME");
  return Object.freeze(value);
}

export function deploymentAttestationStatementBytes(statement, options = {}) { return Buffer.from(canonicalJson(normalizeDeploymentAttestationStatement(statement, options)), "utf8"); }
export function deploymentAttestationStatementHash(statement, options = {}) { return crypto.createHash("sha256").update(deploymentAttestationStatementBytes(statement, options)).digest("hex"); }
export function deploymentAttestationSigningData(statement, options = {}) { return Buffer.concat([Buffer.from(DEPLOYMENT_ATTESTATION_DOMAIN, "utf8"), deploymentAttestationStatementBytes(statement, options)]); }

export function normalizeDeploymentAttestation(input, options = {}) {
  exactObject(input, DEPLOYMENT_ATTESTATION_ENVELOPE_KEYS);
  const statement = normalizeDeploymentAttestationStatement(input.statement, options);
  if (input.version !== 1 || input.type !== DEPLOYMENT_ATTESTATION_TYPE || input.signature_algorithm !== DEPLOYMENT_ATTESTATION_ALGORITHM || input.statement_hash !== deploymentAttestationStatementHash(statement, options) || !FINGERPRINT.test(input.signer_key_fingerprint) || !SIGNATURE.test(input.signature)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_SIGNATURE");
  return Object.freeze({ ...input, statement });
}

export function deploymentAttestationPublicKeyFingerprint(publicKey) {
  const key = publicKey instanceof crypto.KeyObject ? publicKey : crypto.createPublicKey(publicKey);
  return `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

export function verifyDeploymentAttestation(input, { publicKey, expected = {}, now = Date.now() } = {}) {
  const envelope = normalizeDeploymentAttestation(input, { now });
  if (typeof publicKey !== "string" && !Buffer.isBuffer(publicKey) && !(publicKey instanceof crypto.KeyObject)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_CONFIG");
  if (envelope.signer_key_fingerprint !== deploymentAttestationPublicKeyFingerprint(publicKey)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_BINDING");
  for (const key of DEPLOYMENT_ATTESTATION_STATEMENT_KEYS) if (expected[key] !== undefined && envelope.statement[key] !== expected[key]) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_BINDING");
  const key = publicKey instanceof crypto.KeyObject ? publicKey : crypto.createPublicKey(publicKey);
  if (!crypto.verify(null, deploymentAttestationSigningData(envelope.statement, { now, allowExpired: true, allowFuture: true }), key, Buffer.from(envelope.signature, "base64url"))) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_SIGNATURE");
  return envelope;
}

export function verifyDeploymentAttestationTrust({ attestation, publicKey, trustManifest, now = Date.now() } = {}) {
  const normalizedTrust = normalizeDeploymentAttestationTrust(trustManifest);
  // Trust membership is not sufficient on its own: callers must not be able
  // to turn a partial statement-shaped object into an accepted deployment
  // identity. Verify the complete, time-valid, signed envelope before using
  // any statement fields for trust matching.
  const verifiedAttestation = verifyDeploymentAttestation(attestation, { publicKey, now });
  const key = publicKey instanceof crypto.KeyObject ? publicKey : crypto.createPublicKey(publicKey);
  const fingerprint = deploymentAttestationPublicKeyFingerprint(key);
  const statement = verifiedAttestation.statement;
  const match = normalizedTrust.keys.find((item) => item.environment === statement?.environment && item.key_id === statement?.key_id && item.key_version === statement?.key_version && item.fingerprint === fingerprint);
  if (!match) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
  if (!Number.isFinite(now) || match.status !== "active" || now < Date.parse(match.not_before) || now >= Date.parse(match.not_after)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
  return Object.freeze({ environment: match.environment, key_id: match.key_id, key_version: match.key_version, fingerprint });
}

export function normalizeDeploymentAttestationTrust(input) {
  exactObject(input, DEPLOYMENT_ATTESTATION_TRUST_PAYLOAD_KEYS, "ERR_DEPLOYMENT_ATTESTATION_TRUST");
  if (input.schema_version !== 1 || input.type !== "agentpass.deployment-attestation-trust" || !Array.isArray(input.keys) || input.keys.length === 0 || input.keys.length > 32) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
  const keys = input.keys.map((entry) => {
    exactObject(entry, ["environment", "key_id", "key_version", "fingerprint", "status", "not_before", "not_after"], "ERR_DEPLOYMENT_ATTESTATION_TRUST");
    const notBefore = Date.parse(entry.not_before); const notAfter = Date.parse(entry.not_after);
    if (!["staging", "production"].includes(entry.environment) || !ID.test(entry.key_id) || !Number.isSafeInteger(entry.key_version) || entry.key_version < 1 || !FINGERPRINT.test(entry.fingerprint) || !["active", "revoked"].includes(entry.status) || !TIME.test(entry.not_before) || !TIME.test(entry.not_after) || !Number.isFinite(notBefore) || !Number.isFinite(notAfter) || notAfter <= notBefore) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
    return Object.freeze({ ...entry });
  });
  const identities = new Set();
  const fingerprints = new Set();
  for (const entry of keys) {
    const identity = `${entry.environment}\0${entry.key_id}\0${entry.key_version}`;
    if (identities.has(identity) || fingerprints.has(entry.fingerprint)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
    identities.add(identity);
    fingerprints.add(entry.fingerprint);
  }
  return Object.freeze({ schema_version: 1, type: input.type, keys: Object.freeze(keys) });
}

export function deploymentAttestationTrustSigningData(input) {
  const payload = normalizeDeploymentAttestationTrust(input);
  return Buffer.concat([Buffer.from(DEPLOYMENT_ATTESTATION_TRUST_DOMAIN, "utf8"), Buffer.from(canonicalJson(payload), "utf8")]);
}

export function verifyDeploymentAttestationTrustManifest(input, { rootPublicKey } = {}) {
  exactObject(input, DEPLOYMENT_ATTESTATION_TRUST_ENVELOPE_KEYS, "ERR_DEPLOYMENT_ATTESTATION_TRUST");
  if (input.signature_algorithm !== DEPLOYMENT_ATTESTATION_ALGORITHM || !FINGERPRINT.test(input.signer_key_fingerprint) || !SIGNATURE.test(input.signature)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
  if (typeof rootPublicKey !== "string" && !Buffer.isBuffer(rootPublicKey) && !(rootPublicKey instanceof crypto.KeyObject)) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
  const key = rootPublicKey instanceof crypto.KeyObject ? rootPublicKey : crypto.createPublicKey(rootPublicKey);
  if (input.signer_key_fingerprint !== deploymentAttestationPublicKeyFingerprint(key) || !crypto.verify(null, deploymentAttestationTrustSigningData({ schema_version: input.schema_version, type: input.type, keys: input.keys }), key, Buffer.from(input.signature, "base64url"))) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
  return normalizeDeploymentAttestationTrust({ schema_version: input.schema_version, type: input.type, keys: input.keys });
}

export function readDeploymentAttestationTrust(filePath, { rootPublicKey } = {}) {
  if (typeof filePath !== "string" || !filePath.startsWith("/")) throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST");
  try {
    const stat = fs.lstatSync(filePath, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || (stat.mode & 0o022n) !== 0n) throw new Error("unsafe trust manifest");
    const bytes = fs.readFileSync(filePath);
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (bytes.toString("utf8") !== `${canonicalJson(parsed)}\n`) throw new Error("trust manifest is not canonical JSON");
    return verifyDeploymentAttestationTrustManifest(parsed, { rootPublicKey });
  } catch { throw new DeploymentAttestationError("ERR_DEPLOYMENT_ATTESTATION_TRUST"); }
}

function exactObject(value, keys, errorCode = "ERR_DEPLOYMENT_ATTESTATION_INPUT") {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new DeploymentAttestationError(errorCode);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value") || descriptor.get || descriptor.set || descriptor.enumerable !== true) throw new DeploymentAttestationError(errorCode);
  }
}
