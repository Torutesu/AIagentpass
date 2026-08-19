#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { verifyBackupRestoreQualification } from "../postgres/backup-restore-qualification.mjs";
import { parseKmsQualificationReport, verifyKmsQualificationReport } from "../kms-qualification/schema.mjs";
import { validateReleaseEvidence } from "./validate-release-evidence.mjs";

export const PRODUCTION_EVIDENCE_MANIFEST_VERSION = 1;
export const PRODUCTION_EVIDENCE_MANIFEST_KIND = "agentpass.production-evidence-manifest";

const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40,64}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const SAFE_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024 * 1024;

export const PRODUCTION_EVIDENCE_NOT_PROVEN = Object.freeze({
  status: "not_proven",
  reason: "production_evidence_unavailable",
  required: Object.freeze(["signed_candidate_manifest", "protected_kms", "protected_postgres", "protected_release"])
});

export class ProductionEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProductionEvidenceError";
    this.code = code;
  }
}

function fail(code) { throw new ProductionEvidenceError(code); }
function plain(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys, label) {
  if (!plain(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`invalid_${label}`);
}
function digest(value, label) { if (typeof value !== "string" || !DIGEST.test(value)) fail(`invalid_${label}`); return value; }
function descriptor(value, label) {
  exact(value, ["name", "bytes", "sha256"], label);
  if (typeof value.name !== "string" || !SAFE_NAME.test(value.name) || value.name !== path.basename(value.name)
    || !Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > MAX_EVIDENCE_BYTES) fail(`invalid_${label}`);
  digest(value.sha256, `${label}_digest`);
  return value;
}
function canonical(value) { return Buffer.from(`${canonicalJson(value)}\n`, "utf8"); }
function hash(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }

function readDescriptor(root, value, label, maximum = MAX_EVIDENCE_BYTES) {
  descriptor(value, label);
  const target = path.resolve(root, value.name);
  const rootPath = path.resolve(root);
  if (target !== rootPath && !target.startsWith(`${rootPath}${path.sep}`)) fail(`${label}_path_escape`);
  let fd;
  try { fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { fail(`${label}_unavailable`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(value.bytes) || before.size > BigInt(maximum)) fail(`${label}_unsafe_file`);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail(`${label}_changed`);
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if ([before.dev, before.ino, before.mode, before.nlink, before.size, before.mtimeNs, before.ctimeNs].join(":")
      !== [after.dev, after.ino, after.mode, after.nlink, after.size, after.mtimeNs, after.ctimeNs].join(":")) fail(`${label}_changed`);
    if (hash(bytes) !== value.sha256) fail(`${label}_digest_mismatch`);
    return bytes;
  } finally { fs.closeSync(fd); }
}

function parseCanonical(bytes, label) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { fail(`${label}_invalid_json`); }
  if (!bytes.equals(canonical(value))) fail(`${label}_noncanonical`);
  return value;
}

function candidate(value) {
  exact(value, ["artifact_name", "artifact_sha256", "candidate_id", "source_commit", "version"], "candidate");
  if (!SAFE_NAME.test(value.artifact_name) || !value.artifact_name.endsWith("-macos-universal.pkg")) fail("invalid_candidate");
  digest(value.artifact_sha256, "candidate_artifact");
  if (!CANDIDATE.test(value.candidate_id) || value.candidate_id !== `release-pkg-sha256-v1-${value.artifact_sha256}`) fail("invalid_candidate");
  if (!COMMIT.test(value.source_commit) || typeof value.version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(value.version)) fail("invalid_candidate");
  return value;
}

function validateProtectedReleaseAttestation(value, expected) {
  exact(value, ["artifact_sha256", "candidate_id", "evidence_origin", "gatekeeper_verified", "kind", "notarytool_verified", "schema_version", "source_commit", "stapler_verified", "status", "verification_mode", "workflow_commit", "workflow_run_id", "workflow_tree"], "release_attestation");
  if (value.schema_version !== 1 || value.kind !== "agentpass.protected-release-gate-attestation"
    || value.status !== "passed" || value.verification_mode !== "protected_macos" || value.evidence_origin !== "protected_external"
    || value.candidate_id !== expected.candidate_id || value.artifact_sha256 !== expected.artifact_sha256 || value.source_commit !== expected.source_commit
    || value.workflow_commit !== expected.source_commit || !DIGEST.test(value.workflow_tree) || !COMMIT.test(value.workflow_commit)
    || typeof value.workflow_run_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,255}$/u.test(value.workflow_run_id)
    || value.notarytool_verified !== true || value.stapler_verified !== true || value.gatekeeper_verified !== true) fail("protected_release_not_proven");
}

function signatureInput(manifest) {
  const { signature: _signature, ...unsigned } = manifest;
  void _signature;
  return canonical(unsigned);
}

function verifyManifestSignature(manifest, trustedPublicKeyDer, trustedKeyId) {
  exact(manifest.signature, ["algorithm", "key_id", "public_key_fingerprint", "signature_base64url"], "signature");
  if (manifest.signature.algorithm !== "ed25519" || !KEY_ID.test(manifest.signature.key_id)
    || !FINGERPRINT.test(manifest.signature.public_key_fingerprint) || !BASE64URL.test(manifest.signature.signature_base64url)) fail("invalid_signature");
  if (!(trustedPublicKeyDer instanceof Uint8Array) || trustedPublicKeyDer.length !== 44 || manifest.signature.key_id !== trustedKeyId) fail("trusted_key_required");
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(trustedPublicKeyDer).digest("base64url")}`;
  if (manifest.signature.public_key_fingerprint !== fingerprint) fail("untrusted_signature_key");
  let key;
  try { key = crypto.createPublicKey({ key: trustedPublicKeyDer, format: "der", type: "spki" }); } catch { fail("untrusted_signature_key"); }
  if (key.asymmetricKeyType !== "ed25519" || !crypto.verify(null, signatureInput(manifest), key, Buffer.from(manifest.signature.signature_base64url, "base64url"))) fail("invalid_signature");
}

export function verifyProductionEvidenceManifest({ manifest, root, repositoryRoot, trustedPublicKeyDer, trustedKeyId } = {}) {
  exact(manifest, ["candidate", "gates", "kind", "schema_version", "signature"], "manifest");
  if (manifest.schema_version !== PRODUCTION_EVIDENCE_MANIFEST_VERSION || manifest.kind !== PRODUCTION_EVIDENCE_MANIFEST_KIND) fail("invalid_manifest");
  const expected = candidate(manifest.candidate);
  verifyManifestSignature(manifest, trustedPublicKeyDer, trustedKeyId);
  const seen = new Set();
  const take = (entry, label, max = MAX_EVIDENCE_BYTES) => {
    descriptor(entry, label);
    if (seen.has(entry.name)) fail("duplicate_evidence_file");
    seen.add(entry.name);
    return parseCanonical(readDescriptor(root, entry, label, max), label);
  };
  exact(manifest.gates, ["kms", "postgres", "release"], "gates");
  exact(manifest.gates.kms, ["report", "trusted_key_id", "trusted_public_key"], "kms_gate");
  const kms = take(manifest.gates.kms.report, "kms_report", 16 * 1024 * 1024);
  const kmsKey = readDescriptor(root, manifest.gates.kms.trusted_public_key, "kms_trusted_public_key", 16 * 1024);
  if (manifest.gates.kms.trusted_key_id !== kms.signature?.key_id) fail("kms_trusted_key_mismatch");
  const kmsResult = verifyKmsQualificationReport(kms, { repositoryRoot, requireProduction: true, trustedPublicKeyDer: kmsKey, trustedKeyId: manifest.gates.kms.trusted_key_id });
  if (kmsResult.source_commit !== expected.source_commit) fail("kms_candidate_source_mismatch");

  exact(manifest.gates.postgres, ["qualification"], "postgres_gate");
  const postgres = take(manifest.gates.postgres.qualification, "postgres_qualification", 256 * 1024);
  const postgresResult = verifyBackupRestoreQualification(postgres, { expectedCandidateId: expected.candidate_id, expectedSourceCommit: expected.source_commit });
  if (postgresResult.status !== "closed") fail("postgres_not_proven");

  exact(manifest.gates.release, ["attestation", "offline_evidence"], "release_gate");
  const offlineEvidence = take(manifest.gates.release.offline_evidence, "release_offline_evidence", 4 * 1024 * 1024);
  const releaseResult = validateReleaseEvidence({ evidence: offlineEvidence, root, expectedSourceCommit: expected.source_commit });
  if (releaseResult.candidate_id !== expected.candidate_id || releaseResult.candidate_sha256 !== expected.artifact_sha256) fail("release_candidate_mismatch");
  const attestation = take(manifest.gates.release.attestation, "release_attestation", 64 * 1024);
  validateProtectedReleaseAttestation(attestation, expected);
  return Object.freeze({ status: "closed", candidate_id: expected.candidate_id, source_commit: expected.source_commit, artifact_sha256: expected.artifact_sha256, manifest_sha256: hash(signatureInput(manifest)) });
}

function readRegular(file, maximum) {
  const stat = fs.lstatSync(file, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size < 1n || stat.size > BigInt(maximum)) fail("invalid_manifest_file");
  return fs.readFileSync(file);
}

async function main() {
  const [manifestFile, rootArg, trustedKeyFile, trustedKeyId] = process.argv.slice(2);
  if (!manifestFile || !rootArg || !trustedKeyFile || !trustedKeyId || process.argv.length !== 6 || !path.isAbsolute(manifestFile) || !path.isAbsolute(rootArg) || !path.isAbsolute(trustedKeyFile)) {
    process.stdout.write(`${JSON.stringify(PRODUCTION_EVIDENCE_NOT_PROVEN)}\n`); process.exitCode = 2; return;
  }
  try {
    const root = path.resolve(rootArg);
    const manifest = parseCanonical(readRegular(manifestFile, MAX_MANIFEST_BYTES), "manifest");
    const result = verifyProductionEvidenceManifest({ manifest, root, repositoryRoot: path.resolve(import.meta.dirname, "../.."), trustedPublicKeyDer: readRegular(trustedKeyFile, 16 * 1024), trustedKeyId });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ status: "not_proven", reason: error instanceof ProductionEvidenceError ? error.code : "verification_failed" })}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
