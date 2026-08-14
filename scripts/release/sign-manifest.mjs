#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { assertReleaseCandidateIdMatchesProduct, RELEASE_MANIFEST_SCHEMA_VERSION } from '../../lib/release-candidate-identity.mjs';
import { parseCanonicalExternalQualificationControllerIdentity, validateExternalQualificationControllerIdentity } from './n3e/controller-identity-contract.mjs';

const [manifestArg, privateKeyArg, signatureArg] = process.argv.slice(2);
if (!manifestArg || !privateKeyArg || !signatureArg || process.argv.slice(2).length !== 3) throw new Error('Usage: sign-manifest.mjs MANIFEST PRIVATE-KEY SIGNATURE');
if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');
const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const readRegular = (value, maximum, requirePrivate) => {
  const path = resolve(value); const descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`unsafe release input: ${value}`);
    if (requirePrivate && ((before.mode & 0o077n) !== 0n || before.uid !== BigInt(process.getuid()))) throw new Error(`release private key must be owner-only and owned by the current user: ${value}`);
    const data = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < data.length) { const count = fs.readSync(descriptor, data, offset, data.length - offset, offset); if (!count) throw new Error(`truncated release input: ${value}`); offset += count; }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`release input changed while reading: ${value}`);
    return data;
  } finally { fs.closeSync(descriptor); }
};
const manifest = readRegular(manifestArg, 16 * 1024 * 1024, false);
let parsedManifest;
try { parsedManifest = JSON.parse(manifest.toString('utf8')); } catch { throw new Error('release manifest is not valid UTF-8 JSON'); }
const expectedTopLevel = ['artifacts', 'candidate_id', 'evidence', 'external_qualification_controller', 'generated_at', 'product', 'schema_version', 'source', 'version'];
if (JSON.stringify(Object.keys(parsedManifest).sort()) !== JSON.stringify(expectedTopLevel) || parsedManifest.schema_version !== RELEASE_MANIFEST_SCHEMA_VERSION || parsedManifest.product !== 'AgentPass' || !manifest.equals(Buffer.from(`${JSON.stringify(parsedManifest, null, 2)}\n`, 'utf8'))) throw new Error('refusing to sign a noncanonical or unsupported release manifest');
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new Error(`${label} has missing or unknown fields`);
};
const external = parsedManifest.external_qualification_controller;
const productArtifacts = Array.isArray(parsedManifest.artifacts) ? parsedManifest.artifacts.filter((item) => item?.role === 'product') : [];
if (productArtifacts.length !== 1 || typeof productArtifacts[0].name !== 'string' || !productArtifacts[0].name.endsWith('.pkg') || !/^[0-9a-f]{64}$/.test(productArtifacts[0].sha256)) throw new Error('release manifest requires exactly one product PKG artifact');
assertReleaseCandidateIdMatchesProduct(parsedManifest.candidate_id, productArtifacts[0].sha256);
exactKeys(external, ['identity_document', 'identity', 'notarization'], 'external qualification controller');
exactKeys(external.identity_document, ['name', 'bytes', 'sha256'], 'controller identity document');
exactKeys(external.notarization, ['status', 'submission_ids', 'evidence'], 'controller notarization');
const identity = validateExternalQualificationControllerIdentity(external.identity);
if (typeof external.identity_document.name !== 'string' || external.identity_document.name !== basename(external.identity_document.name) || !/^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(external.identity_document.name) || !Number.isSafeInteger(external.identity_document.bytes) || external.identity_document.bytes <= 0 || !/^[0-9a-f]{64}$/.test(external.identity_document.sha256)) throw new Error('controller identity document binding is invalid');
const identityDocumentBytes = readRegular(join(dirname(resolve(manifestArg)), external.identity_document.name), 1024 * 1024, false);
if (identityDocumentBytes.length !== external.identity_document.bytes || crypto.createHash('sha256').update(identityDocumentBytes).digest('hex') !== external.identity_document.sha256) throw new Error('controller identity document digest mismatch');
const documentIdentity = parseCanonicalExternalQualificationControllerIdentity(identityDocumentBytes);
if (JSON.stringify(documentIdentity) !== JSON.stringify(identity)) throw new Error('embedded controller identity differs from its document');
const controllerArtifacts = Array.isArray(parsedManifest.artifacts) ? parsedManifest.artifacts.filter((item) => item?.role === 'external_qualification_controller') : [];
if (controllerArtifacts.length !== 1 || controllerArtifacts[0].name !== identity.archive_name || controllerArtifacts[0].bytes !== identity.archive_bytes || controllerArtifacts[0].sha256 !== identity.archive_sha256) throw new Error('controller identity does not bind the declared external archive');
if (external.notarization.status !== 'accepted_stapled' || !Array.isArray(external.notarization.submission_ids) || external.notarization.submission_ids.length === 0 || !Array.isArray(external.notarization.evidence) || external.notarization.evidence.length !== 2) throw new Error('controller notarization binding is incomplete');
for (const item of external.notarization.evidence) exactKeys(item, ['kind', 'name', 'bytes', 'sha256'], 'controller notarization evidence item');
const privateBytes = readRegular(privateKeyArg, 16 * 1024, true);
let key;
try { key = crypto.createPrivateKey(privateBytes); }
finally { privateBytes.fill(0); }
if (key.asymmetricKeyType !== 'ed25519') throw new Error('Release manifest key must be Ed25519');
const signature = crypto.sign(null, manifest, key);
fs.writeFileSync(resolve(signatureArg), `${signature.toString('base64')}\n`, { flag: 'wx', mode: 0o644 });
console.log(JSON.stringify({ ok: true, signature_bytes: signature.length }));
