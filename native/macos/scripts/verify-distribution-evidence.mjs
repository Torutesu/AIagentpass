#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { basename, resolve } from 'node:path';

const [evidenceArg, inventoryArg, rootArg, evidenceRootArg, verificationArg, expectedTeamArg] = process.argv.slice(2);
if (!evidenceArg || !inventoryArg || !rootArg || !evidenceRootArg || !verificationArg) throw new Error('Usage: verify-distribution-evidence.mjs EVIDENCE INVENTORY ROOT EVIDENCE_ROOT VERIFICATION');
const DIGEST = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TEAM = /^[A-Z0-9]{10}$/u;
const DEVELOPER_ID_INSTALLER = /^Developer ID Installer: [^\r\n()]+ \([A-Z0-9]{10}\)$/u;
const SAFE = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
if (expectedTeamArg !== undefined && !TEAM.test(expectedTeamArg)) throw new Error('expected Team ID is invalid');
const canonical = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const readCanonical = (path, label) => {
  const stat = fs.lstatSync(path, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size < 1n || stat.size > 16n * 1024n * 1024n) throw new Error(`${label} is missing or unsafe`);
  const bytes = fs.readFileSync(path);
  let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error(`${label} is not valid JSON`); }
  if (!bytes.equals(canonical(value))) throw new Error(`${label} is not canonical JSON`);
  return { value, bytes, sha256: createHash('sha256').update(bytes).digest('hex') };
};
const exact = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || JSON.stringify(Object.keys(value)) !== JSON.stringify(keys)) throw new Error(`${label} has missing or unknown fields`);
};
const descriptor = (value, label) => {
  exact(value, ['name', 'bytes', 'sha256'], label);
  if (!SAFE.test(value.name) || value.name !== basename(value.name) || !Number.isSafeInteger(value.bytes) || value.bytes < 1 || !DIGEST.test(value.sha256)) throw new Error(`${label} is invalid`);
};
const evidencePath = (root, value, label) => {
  if (typeof value !== 'string' || !SAFE.test(value) || value !== basename(value)) throw new Error(`${label} has an unsafe file name`);
  return resolve(root, value);
};
const rootedPath = (root, value, label) => {
  if (typeof value !== 'string' || value.startsWith('/') || value.length === 0) throw new Error(`${label} has an unsafe path`);
  const components = value.split('/');
  if (components.some((component) => component.length === 0 || component === '.' || component === '..')) throw new Error(`${label} has an unsafe path`);
  let current = resolve(root);
  for (const component of components.slice(0, -1)) {
    current = resolve(current, component);
    const stat = fs.lstatSync(current, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} has an unsafe parent directory`);
  }
  return resolve(root, value);
};
const fileDigest = (path, label) => {
  const stat = fs.lstatSync(path, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) throw new Error(`${label} is missing or unsafe`);
  const bytes = fs.readFileSync(path);
  return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
};
const fail = (message) => { throw new Error(message); };
for (const [path, label] of [[resolve(rootArg), 'artifact root'], [resolve(evidenceRootArg), 'evidence root']]) {
  const stat = fs.lstatSync(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} must be a real directory`);
}
const evidence = readCanonical(resolve(evidenceArg), 'distribution evidence').value;
const inventoryRead = readCanonical(resolve(inventoryArg), 'artifact inventory');
const inventory = inventoryRead.value;
exact(evidence, ['schema_version', 'kind', 'artifact', 'inventory', 'signature', 'notarization', 'staple', 'gatekeeper', 'verification'], 'distribution evidence');
if (evidence.schema_version !== 1 || evidence.kind !== 'agentpass.macos-distribution-evidence') fail('unsupported evidence kind');
exact(inventory, ['schema_version', 'kind', 'artifact', 'root_entries'], 'artifact inventory');
if (inventory.schema_version !== 1 || inventory.kind !== 'agentpass.macos-artifact-inventory' || !Array.isArray(inventory.root_entries)) fail('invalid artifact inventory');
descriptor(evidence.artifact, 'evidence artifact');
descriptor(inventory.artifact, 'inventory artifact');
if (JSON.stringify(evidence.artifact) !== JSON.stringify(inventory.artifact)) fail('evidence artifact does not match inventory');
if (!DIGEST.test(evidence.inventory.sha256) || evidence.inventory.sha256 !== inventoryRead.sha256 || evidence.inventory.name !== basename(resolve(inventoryArg)) || evidence.inventory.bytes !== inventoryRead.bytes.length) fail('inventory digest or descriptor mismatch');
const artifact = fileDigest(resolve(rootArg, evidence.artifact.name), 'candidate artifact');
if (artifact.bytes !== evidence.artifact.bytes || artifact.sha256 !== evidence.artifact.sha256) fail('candidate artifact digest mismatch');
const seen = new Set();
for (const entry of inventory.root_entries) {
  exact(entry, ['path', 'bytes', 'sha256'], 'inventory entry');
  if (typeof entry.path !== 'string' || entry.path.startsWith('/') || entry.path.includes('..') || seen.has(entry.path) || !DIGEST.test(entry.sha256)) fail('inventory entry is unsafe');
  seen.add(entry.path);
  const actual = fileDigest(rootedPath(rootArg, entry.path, `inventory entry ${entry.path}`), `inventory entry ${entry.path}`);
  if (actual.bytes !== entry.bytes || actual.sha256 !== entry.sha256) fail(`inventory digest mismatch: ${entry.path}`);
}
exact(evidence.signature, ['format', 'identity', 'team_id', 'verified'], 'signature evidence');
const signatureIdentity = evidence.signature.identity;
const signatureTeam = typeof signatureIdentity === 'string' ? signatureIdentity.match(/\(([A-Z0-9]{10})\)$/u)?.[1] : undefined;
if (evidence.signature.format !== 'Developer ID Installer' || !DEVELOPER_ID_INSTALLER.test(signatureIdentity ?? '') || !TEAM.test(evidence.signature.team_id ?? '') || evidence.signature.team_id !== signatureTeam || evidence.signature.verified !== true) fail('Developer ID signature evidence is absent or invalid');
if (expectedTeamArg !== undefined && evidence.signature.team_id !== expectedTeamArg) fail('Developer ID signature Team ID does not match the expected Team ID');
exact(evidence.notarization, ['status', 'submission_id', 'artifact_sha256', 'evidence_file'], 'notarization evidence');
if (evidence.notarization.status !== 'Accepted' || !UUID.test(evidence.notarization.submission_id) || evidence.notarization.artifact_sha256 !== evidence.artifact.sha256) fail('notarization evidence is absent or unbound');
const notary = readCanonical(evidencePath(evidenceRootArg, evidence.notarization.evidence_file, 'notarization evidence'), 'notarization evidence file').value;
if (notary.status !== 'Accepted' || String(notary.id).toLowerCase() !== evidence.notarization.submission_id.toLowerCase() || String(notary.artifact_sha256) !== evidence.artifact.sha256) fail('notary result is absent or mismatched');
exact(evidence.staple, ['status', 'artifact_sha256', 'evidence_file'], 'staple evidence');
if (evidence.staple.status !== 'validated' || evidence.staple.artifact_sha256 !== evidence.artifact.sha256) fail('staple evidence is absent or mismatched');
const staple = readCanonical(evidencePath(evidenceRootArg, evidence.staple.evidence_file, 'staple evidence'), 'staple evidence file').value;
if (staple.status !== 'validated' || staple.artifact_sha256 !== evidence.artifact.sha256) fail('staple result is absent or mismatched');
exact(evidence.gatekeeper, ['assessment', 'artifact_sha256', 'evidence_file'], 'Gatekeeper evidence');
if (evidence.gatekeeper.assessment !== 'accepted' || evidence.gatekeeper.artifact_sha256 !== evidence.artifact.sha256) fail('Gatekeeper evidence is absent or mismatched');
const gatekeeper = readCanonical(evidencePath(evidenceRootArg, evidence.gatekeeper.evidence_file, 'Gatekeeper evidence'), 'Gatekeeper evidence file').value;
if (gatekeeper.assessment !== 'accepted' || gatekeeper.artifact_sha256 !== evidence.artifact.sha256) fail('Gatekeeper result is absent or mismatched');
descriptor(evidence.verification, 'independent verification evidence');
const verificationFile = fileDigest(resolve(verificationArg), 'independent verification evidence');
if (evidence.verification.name !== basename(resolve(verificationArg)) || evidence.verification.bytes !== verificationFile.bytes || evidence.verification.sha256 !== verificationFile.sha256) fail('independent verification descriptor mismatch');
const verification = readCanonical(resolve(verificationArg), 'independent verification evidence').value;
exact(verification, ['schema_version', 'kind', 'status', 'artifact_sha256', 'signature_verified', 'notarization_verified', 'staple_verified', 'gatekeeper_verified'], 'independent verification result');
if (verification.schema_version !== 1 || verification.kind !== 'agentpass.macos-distribution-verification-v1' || verification.status !== 'verified'
  || verification.artifact_sha256 !== evidence.artifact.sha256 || verification.signature_verified !== true || verification.notarization_verified !== true
  || verification.staple_verified !== true || verification.gatekeeper_verified !== true) fail('independent verification result is absent or mismatched');
process.stdout.write(`${JSON.stringify({ status: 'verified', artifact_sha256: evidence.artifact.sha256, inventory_sha256: inventoryRead.sha256, verification_sha256: evidence.verification.sha256, signature_verified: true, notarization_verified: true, staple_verified: true, gatekeeper_verified: true })}\n`);
