#!/usr/bin/env node
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { RELEASE_MANIFEST_SCHEMA_VERSION } from '../../lib/release-candidate-identity.mjs';

export const RELEASE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION = 1;
export const RELEASE_PREFLIGHT_EVIDENCE_KIND = 'agentpass-release-preflight-evidence';

const DIGEST = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const SAFE_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const MAX_EVIDENCE_JSON_BYTES = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_RELEASE_FILE_BYTES = 16 * 1024 * 1024 * 1024;

const fail = (message, code = 'not_proven') => {
  const error = new Error(message);
  error.code = code;
  throw error;
};

const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`, 'invalid_evidence');
  const actual = Object.keys(value);
  const expected = [...keys];
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing, unknown, or non-canonical fields`, 'invalid_evidence');
};

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const parseCanonicalJSON = (bytes, label) => {
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`${label} is not valid UTF-8 JSON`, 'invalid_evidence'); }
  if (!bytes.equals(canonicalJSON(value))) fail(`${label} is not canonical JSON`, 'invalid_evidence');
  return value;
};

const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');

const snapshotFile = (root, descriptor, maximum, label) => {
  exactKeys(descriptor, ['name', 'bytes', 'sha256'], `${label} descriptor`);
  if (typeof descriptor.name !== 'string' || !SAFE_NAME.test(descriptor.name) || descriptor.name !== basename(descriptor.name)) fail(`${label} has an unsafe file name`);
  if (!Number.isSafeInteger(descriptor.bytes) || descriptor.bytes < 1 || descriptor.bytes > maximum || !DIGEST.test(descriptor.sha256)) fail(`${label} has an invalid size or digest`);
  const path = resolve(root, descriptor.name);
  const rootPath = resolve(root);
  if (path !== rootPath && !path.startsWith(`${rootPath}/`)) fail(`${label} escapes the evidence root`);
  let fd;
  try { fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { fail(`${label} is missing or cannot be opened`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(descriptor.bytes) || before.size > BigInt(maximum)) fail(`${label} is not the declared single-link regular file`);
    const hash = createHash('sha256');
    const chunks = [];
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, descriptor.bytes));
    let offset = 0;
    while (offset < descriptor.bytes) {
      const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, descriptor.bytes - offset), offset);
      if (count === 0) fail(`${label} changed while being read`);
      hash.update(buffer.subarray(0, count));
      chunks.push(Buffer.from(buffer.subarray(0, count)));
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) fail(`${label} changed while being read`);
    const sha256 = hash.digest('hex');
    if (sha256 !== descriptor.sha256) fail(`${label} digest does not match its descriptor`);
    return { path, bytes: descriptor.bytes, sha256, content: Buffer.concat(chunks, descriptor.bytes) };
  } finally { fs.closeSync(fd); }
};

const validateDescriptor = (root, descriptor, label, seen, maximum = MAX_RELEASE_FILE_BYTES) => {
  if (seen.has(descriptor.name)) fail(`${label} reuses an evidence file name`);
  seen.add(descriptor.name);
  return snapshotFile(root, descriptor, maximum, label);
};

const validateTypedEvidence = (snapshot, expected, label) => {
  const value = parseCanonicalJSON(snapshot.content, label);
  exactKeys(value, Object.keys(expected), label);
  for (const [key, wanted] of Object.entries(expected)) {
    if (wanted instanceof RegExp) {
      if (typeof value[key] !== 'string' || !wanted.test(value[key])) fail(`${label}.${key} is invalid`);
    } else if (value[key] !== wanted) fail(`${label}.${key} is not bound to the candidate`);
  }
  return value;
};

const validateManifestBinding = (manifestBytes, candidate) => {
  const manifest = parseCanonicalJSON(manifestBytes, 'release manifest');
  if (manifest?.schema_version !== RELEASE_MANIFEST_SCHEMA_VERSION || manifest.product !== 'AgentPass' || manifest.version !== candidate.version) fail('release manifest identity does not match the candidate');
  if (manifest.candidate_id !== candidate.candidate_id) fail('release manifest candidate_id does not match the candidate');
  if (!Array.isArray(manifest.artifacts)) fail('release manifest has no artifact inventory');
  const products = manifest.artifacts.filter((item) => item?.role === 'product');
  if (products.length !== 1 || products[0].name !== candidate.artifact_name || products[0].media_type !== 'application/vnd.apple.installer+xml' || products[0].bytes !== candidate.artifact_bytes || products[0].sha256 !== candidate.artifact_sha256) fail('release manifest does not bind the exact candidate PKG');
  return manifest;
};

const validateEvidenceDocument = (value) => {
  exactKeys(value, ['schema_version', 'kind', 'verification_mode', 'candidate', 'signature', 'notarization', 'staple', 'gatekeeper'], 'release preflight evidence');
  if (value.schema_version !== RELEASE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION || value.kind !== RELEASE_PREFLIGHT_EVIDENCE_KIND || value.verification_mode !== 'offline_evidence') fail('unsupported release preflight evidence identity', 'invalid_evidence');
  exactKeys(value.candidate, ['version', 'artifact_name', 'artifact_bytes', 'artifact_sha256', 'candidate_id'], 'candidate');
  if (!VERSION.test(value.candidate.version) || !SAFE_NAME.test(value.candidate.artifact_name) || !value.candidate.artifact_name.endsWith('-macos-universal.pkg') || !Number.isSafeInteger(value.candidate.artifact_bytes) || value.candidate.artifact_bytes < 1 || !DIGEST.test(value.candidate.artifact_sha256) || value.candidate.artifact_sha256 === '0'.repeat(64) || value.candidate.candidate_id !== `release-pkg-sha256-v1-${value.candidate.artifact_sha256}`) fail('candidate identity is invalid', 'invalid_evidence');
  exactKeys(value.signature, ['manifest', 'detached_signature', 'public_key', 'public_key_fingerprint'], 'signature');
  if (!FINGERPRINT.test(value.signature.public_key_fingerprint)) fail('signature public key fingerprint is invalid', 'invalid_evidence');
  exactKeys(value.notarization, ['submission_id', 'notary_result', 'ticket'], 'notarization');
  if (!UUID.test(value.notarization.submission_id)) fail('notarization submission_id is invalid', 'invalid_evidence');
  exactKeys(value.staple, ['validation'], 'staple');
  exactKeys(value.gatekeeper, ['assessment'], 'gatekeeper');
};

export const validateReleaseEvidence = ({ evidence, root }) => {
  validateEvidenceDocument(evidence);
  const rootStat = fs.lstatSync(root, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || rootStat.nlink <= 0n || (rootStat.mode & 0o022n) !== 0n) fail('evidence root is not a safe non-symlink directory');
  const seen = new Set();
  const candidate = evidence.candidate;
  const artifact = validateDescriptor(root, { name: candidate.artifact_name, bytes: candidate.artifact_bytes, sha256: candidate.artifact_sha256 }, 'candidate PKG', seen);

  const manifest = validateDescriptor(root, evidence.signature.manifest, 'release manifest', seen, MAX_MANIFEST_BYTES);
  const detachedSignature = validateDescriptor(root, evidence.signature.detached_signature, 'detached signature', seen, MAX_SIGNATURE_BYTES);
  const publicKey = validateDescriptor(root, evidence.signature.public_key, 'release public key', seen, MAX_PUBLIC_KEY_BYTES);
  const manifestObject = validateManifestBinding(manifest.content, candidate);
  let key;
  try { key = createPublicKey(publicKey.content); } catch { fail('release public key is not parseable'); }
  if (key.asymmetricKeyType !== 'ed25519') fail('release public key is not Ed25519');
  const fingerprint = `SHA256:${createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  if (fingerprint !== evidence.signature.public_key_fingerprint) fail('release public key fingerprint does not match the pinned fingerprint');
  const signatureText = detachedSignature.content.toString('utf8');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(signatureText)) fail('detached signature encoding is not canonical');
  const signature = Buffer.from(signatureText.trim(), 'base64');
  if (signature.length !== 64 || !verify(null, manifest.content, key, signature)) fail('release manifest detached signature is invalid');

  const notaryResult = validateDescriptor(root, evidence.notarization.notary_result, 'notarytool result', seen, 4 * 1024 * 1024);
  let notary;
  try { notary = JSON.parse(notaryResult.content.toString('utf8')); } catch { fail('notarytool result is not valid JSON'); }
  if (notary === null || typeof notary !== 'object' || Array.isArray(notary) || notary.status !== 'Accepted' || typeof notary.id !== 'string' || notary.id.toLowerCase() !== evidence.notarization.submission_id) fail('notarytool result does not prove the declared Accepted submission');
  const ticket = validateDescriptor(root, evidence.notarization.ticket, 'notary ticket evidence', seen, 1024 * 1024);
  validateTypedEvidence(ticket, { schema_version: 1, kind: 'apple-notary-ticket-v1', status: 'accepted', submission_id: evidence.notarization.submission_id, artifact_sha256: candidate.artifact_sha256 }, 'notary ticket evidence');
  const staple = validateDescriptor(root, evidence.staple.validation, 'staple validation evidence', seen, 1024 * 1024);
  validateTypedEvidence(staple, { schema_version: 1, kind: 'apple-staple-validation-v1', status: 'validated', ticket_status: 'present', artifact_sha256: candidate.artifact_sha256 }, 'staple validation evidence');
  const gatekeeper = validateDescriptor(root, evidence.gatekeeper.assessment, 'Gatekeeper evidence', seen, 1024 * 1024);
  validateTypedEvidence(gatekeeper, { schema_version: 1, kind: 'apple-gatekeeper-assessment-v1', assessment: 'accepted', assessment_type: 'install', artifact_sha256: candidate.artifact_sha256 }, 'Gatekeeper evidence');

  return {
    ok: true,
    status: 'validated_offline',
    verification_mode: 'offline_evidence',
    candidate_id: candidate.candidate_id,
    candidate_sha256: artifact.sha256,
    manifest_sha256: manifest.sha256,
    signature_verified: true,
    notary_evidence_bound: true,
    ticket_evidence_bound: true,
    staple_evidence_bound: true,
    gatekeeper_evidence_bound: true,
    // This tool never contacts Apple and never runs spctl/stapler. Keep these
    // false so an offline evidence pass cannot become a production gate.
    apple_ticket_verified: false,
    gatekeeper_verified: false,
    promotion_ready: false,
    source_manifest_version: manifestObject.version
  };
};

const usage = 'Usage: validate-release-evidence.mjs EVIDENCE.json [EVIDENCE-ROOT]';
const main = () => {
  const args = process.argv.slice(2);
  if (!args[0] || args.length > 2) { console.error(usage); process.exitCode = 2; return; }
  const evidencePath = resolve(args[0]);
  const root = resolve(args[1] ?? dirname(evidencePath));
  let evidenceBytes;
  try {
    const stat = fs.lstatSync(evidencePath, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size < 1n || stat.size > BigInt(MAX_EVIDENCE_JSON_BYTES)) fail('evidence input is not a safe regular file', 'invalid_evidence');
    evidenceBytes = fs.readFileSync(evidencePath);
  } catch (error) {
    console.error(JSON.stringify({ ok: false, status: error.code === 'invalid_evidence' ? 'invalid_evidence' : 'not_proven', reason: error.message }));
    process.exitCode = error.code === 'invalid_evidence' ? 2 : 1;
    return;
  }
  try {
    const evidence = parseCanonicalJSON(evidenceBytes, 'release preflight evidence');
    const result = validateReleaseEvidence({ evidence, root });
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, status: error.code === 'invalid_evidence' ? 'invalid_evidence' : 'not_proven', reason: error.message }));
    process.exitCode = error.code === 'invalid_evidence' ? 2 : 1;
  }
};

if (import.meta.url === `file://${process.argv[1]}`) main();
