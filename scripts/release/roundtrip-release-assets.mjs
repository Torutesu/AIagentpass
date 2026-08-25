#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const INVENTORY_VERSION = 2;
const INVENTORY_TYPE = 'agentpass.release-asset-inventory';
const ROUNDTRIP_TYPE = 'agentpass.release-asset-roundtrip';
const NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const KINDS = new Set([
  'manifest',
  'manifest_signature',
  'manifest_public_key',
  'release_artifact',
  'sbom',
  'checksum',
  'release_evidence',
  'macos_supplemental',
  'qualification_supplemental'
]);
const CORE_KINDS = Object.freeze(['manifest', 'manifest_signature', 'manifest_public_key', 'release_artifact', 'sbom', 'checksum']);
const EXACT_ONE_KINDS = Object.freeze(['manifest', 'manifest_signature', 'manifest_public_key', 'sbom', 'checksum']);
const SUPPLEMENTAL_KINDS = Object.freeze(['macos_supplemental', 'qualification_supplemental']);

const fail = (message) => { throw new TypeError(message); };
const canonicalJson = (value) => `${JSON.stringify(value)}\n`;
const digestJson = (value) => crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
const safeName = (value) => typeof value === 'string' && NAME.test(value) && value === path.basename(value);
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown fields`);
}

function statIdentity(stat) {
  return ['dev', 'ino', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].map((key) => String(stat[key])).join(':');
}

export function classifyReleaseAsset(name) {
  if (!safeName(name)) fail('release asset name is unsafe');
  if (/\.release-manifest\.json$/u.test(name)) return 'manifest';
  if (/\.release-manifest\.sig$/u.test(name)) return 'manifest_signature';
  if (/\.public\.pem$/u.test(name) || name === 'release-manifest.public.pem') return 'manifest_public_key';
  if (name.endsWith('.spdx.json')) return 'sbom';
  if (name === 'SHA256SUMS' || name === 'P0C-SHA256SUMS') return 'checksum';
  if (/^macos-/u.test(name)) return 'macos_supplemental';
  if (/^p0c-/iu.test(name) || /^P0C-/u.test(name)) return 'qualification_supplemental';
  if (/\.(pkg|zip|tgz|tar\.gz)$/u.test(name) || /^AgentPassQualificationController-[0-9A-Za-z.-]+-macos-universal\.tar$/u.test(name)) return 'release_artifact';
  return 'release_evidence';
}

export function snapshotReleaseAsset(input, { maximum = MAX_FILE_BYTES } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || !safeName(input.name) || typeof input.path !== 'string' || !path.isAbsolute(input.path)) fail('release asset input is invalid');
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) fail('O_NOFOLLOW is unavailable on this platform');
  const descriptor = fs.openSync(input.path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(`unsafe release input: ${input.name}`);
    const size = Number(before.size);
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const count = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (count <= 0) fail(`release asset changed while reading: ${input.name}`);
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) fail(`release asset changed while reading: ${input.name}`);
    return Object.freeze({ name: input.name, bytes: size, sha256: hash.digest('hex') });
  } finally {
    fs.closeSync(descriptor);
  }
}

function normalizeInputs(input) {
  if (Array.isArray(input)) return input;
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('release asset inventory input is invalid');
  const groups = [];
  for (const key of ['manifest', 'signature', 'publicKey', 'public_key']) if (input[key] !== undefined && input[key] !== null) groups.push(input[key]);
  for (const key of ['assets', 'supplemental']) {
    if (input[key] === undefined || input[key] === null) continue;
    if (!Array.isArray(input[key])) fail(`release asset inventory ${key} group is invalid`);
    groups.push(...input[key]);
  }
  if (groups.length === 0) fail('release asset inventory is empty');
  return groups;
}

function normalizeInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('release asset input is invalid');
  const snapshot = snapshotReleaseAsset(input);
  const inferred = classifyReleaseAsset(snapshot.name);
  const kind = input.kind === undefined ? inferred : input.kind;
  if (typeof kind !== 'string' || !KINDS.has(kind)) fail(`unknown release asset kind: ${String(kind)}`);
  if (kind !== inferred && ['manifest', 'manifest_signature', 'manifest_public_key', 'sbom', 'checksum', 'macos_supplemental', 'qualification_supplemental'].includes(inferred)) fail(`release asset kind does not match its name: ${snapshot.name}`);
  return Object.freeze({ kind, ...snapshot });
}

function inventoryBody(inventory) {
  const { inventory_sha256: ignored, ...body } = inventory;
  return body;
}

export function validateReleaseAssetInventory(inventory, { requireSupplemental = false } = {}) {
  if (!inventory || typeof inventory !== 'object' || Array.isArray(inventory)) fail('release asset inventory is invalid');
  exactKeys(inventory, ['version', 'type', 'required_kinds', 'assets', 'inventory_sha256'], 'release asset inventory');
  if (inventory.version !== INVENTORY_VERSION || inventory.type !== INVENTORY_TYPE || !DIGEST.test(inventory.inventory_sha256)) fail('release asset inventory identity is invalid');
  if (inventory.inventory_sha256 !== digestJson(inventoryBody(inventory))) fail('release asset inventory digest mismatch');
  if (!Array.isArray(inventory.required_kinds) || inventory.required_kinds.length === 0 || inventory.required_kinds.some((kind) => typeof kind !== 'string' || !KINDS.has(kind))) fail('release asset required-kind inventory is invalid');
  if (new Set(inventory.required_kinds).size !== inventory.required_kinds.length || inventory.required_kinds.some((kind, index) => index > 0 && lexicalCompare(inventory.required_kinds[index - 1], kind) >= 0)) fail('release asset required-kind inventory is unsorted or duplicated');
  if (requireSupplemental && SUPPLEMENTAL_KINDS.some((kind) => !inventory.required_kinds.includes(kind))) fail('release asset inventory omits required macOS or qualification supplemental kinds');
  if (!Array.isArray(inventory.assets) || inventory.assets.length === 0 || inventory.assets.length > 1024) fail('release asset inventory is empty or too large');
  const seen = new Set();
  const kinds = new Set();
  let previous = '';
  for (const asset of inventory.assets) {
    exactKeys(asset, ['kind', 'name', 'bytes', 'sha256'], 'release asset inventory item');
    if (!KINDS.has(asset.kind) || !safeName(asset.name) || seen.has(asset.name) || lexicalCompare(previous, asset.name) >= 0 || !Number.isSafeInteger(asset.bytes) || asset.bytes <= 0 || !DIGEST.test(asset.sha256)) fail('release asset inventory item is unsafe, duplicated, or unsorted');
    seen.add(asset.name); kinds.add(asset.kind); previous = asset.name;
  }
  for (const kind of inventory.required_kinds) if (!kinds.has(kind)) fail(`release asset inventory is missing required kind: ${kind}`);
  if (EXACT_ONE_KINDS.some((kind) => inventory.required_kinds.includes(kind) && inventory.assets.filter((asset) => asset.kind === kind).length !== 1)) fail('release asset inventory core kind cardinality is invalid');
  if (inventory.required_kinds.includes('release_artifact') && !inventory.assets.some((asset) => asset.kind === 'release_artifact')) fail('release asset inventory has no release artifact');
  return inventory;
}

export function buildReleaseAssetInventory(input, { requiredKinds = CORE_KINDS, requireSupplemental = false } = {}) {
  const inputs = normalizeInputs(input);
  if (!Array.isArray(requiredKinds) || requiredKinds.length === 0 || requiredKinds.some((kind) => !KINDS.has(kind))) fail('release asset required kinds are invalid');
  const required = [...new Set(requiredKinds)].sort(lexicalCompare);
  if (requireSupplemental) for (const kind of SUPPLEMENTAL_KINDS) if (!required.includes(kind)) required.push(kind);
  required.sort(lexicalCompare);
  const assets = inputs.map(normalizeInput).sort((left, right) => lexicalCompare(left.name, right.name));
  if (new Set(assets.map((asset) => asset.name)).size !== assets.length) fail('release asset inventory has duplicate names');
  const inventory = { version: INVENTORY_VERSION, type: INVENTORY_TYPE, required_kinds: required, assets };
  inventory.inventory_sha256 = digestJson(inventory);
  validateReleaseAssetInventory(inventory, { requireSupplemental });
  return Object.freeze({ ...inventory, assets: Object.freeze(assets), required_kinds: Object.freeze(required) });
}

export function verifyReleaseAssetRoundTrip(inventory, remoteDirectory, { requireSupplemental = false } = {}) {
  validateReleaseAssetInventory(inventory, { requireSupplemental });
  if (typeof remoteDirectory !== 'string' || !path.isAbsolute(remoteDirectory)) fail('release round-trip directory must be absolute');
  const root = fs.lstatSync(remoteDirectory);
  if (!root.isDirectory() || root.isSymbolicLink()) fail('release round-trip directory is unsafe');
  const expected = new Map(inventory.assets.map((asset) => [asset.name, asset]));
  const entries = fs.readdirSync(remoteDirectory, { withFileTypes: true });
  if (entries.some((entry) => entry.isSymbolicLink() || !entry.isFile())) fail('release round-trip directory contains a non-regular entry');
  const names = entries.map((entry) => entry.name).sort(lexicalCompare);
  if (names.length !== expected.size || names.some((name) => !expected.has(name))) fail('release round-trip asset set mismatch');
  const observed = names.map((name) => snapshotReleaseAsset({ name, path: path.join(remoteDirectory, name) }));
  for (const asset of observed) {
    const expectedAsset = expected.get(asset.name);
    if (asset.bytes !== expectedAsset.bytes || asset.sha256 !== expectedAsset.sha256) fail(`release round-trip asset digest mismatch: ${asset.name}`);
  }
  return Object.freeze({ version: INVENTORY_VERSION, type: ROUNDTRIP_TYPE, inventory_sha256: inventory.inventory_sha256, assets: Object.freeze(observed) });
}

function manifestReferences(manifest) {
  if (!manifest || typeof manifest !== 'object' || !Array.isArray(manifest.artifacts) || !manifest.evidence || !manifest.external_qualification_controller) fail('release manifest asset references are incomplete');
  const references = [];
  for (const artifact of manifest.artifacts) references.push({ kind: artifact.role === 'sbom' ? 'sbom' : 'release_artifact', ...artifact });
  for (const evidence of manifest.evidence.notarization?.evidence || []) references.push({ kind: 'release_evidence', ...evidence });
  references.push({ kind: 'release_evidence', ...manifest.external_qualification_controller.identity_document });
  for (const evidence of manifest.external_qualification_controller.notarization?.evidence || []) references.push({ kind: 'release_evidence', ...evidence });
  references.push({ kind: 'checksum', ...manifest.evidence.checksums });
  return references;
}

export function verifyManifestDeclaredAssets(manifest, manifestDirectory) {
  if (typeof manifestDirectory !== 'string' || !path.isAbsolute(manifestDirectory)) fail('release manifest directory must be absolute');
  const references = manifestReferences(manifest);
  const seen = new Set();
  const snapshots = [];
  for (const reference of references) {
    if (!safeName(reference.name) || seen.has(reference.name) || !Number.isSafeInteger(reference.bytes) || reference.bytes <= 0 || !DIGEST.test(reference.sha256)) fail('release manifest asset reference is invalid or duplicated');
    seen.add(reference.name);
    const actual = snapshotReleaseAsset({ name: reference.name, path: path.join(manifestDirectory, reference.name) });
    if (actual.bytes !== reference.bytes || actual.sha256 !== reference.sha256) fail(`release manifest asset ${reference.name} digest mismatch`);
    snapshots.push({ kind: reference.kind, ...actual });
  }
  const checksum = manifest.evidence.checksums;
  const checksumAsset = snapshots.find((asset) => asset.name === checksum.name);
  const checksumEntries = snapshots.filter((asset) => asset.name !== checksum.name).sort((left, right) => lexicalCompare(left.name, right.name));
  const checksumBytes = fs.readFileSync(path.join(manifestDirectory, checksum.name));
  const expected = Buffer.from(`${checksumEntries.map((asset) => `${asset.sha256}  ${asset.name}`).join('\n')}\n`, 'utf8');
  if (!checksumAsset || !checksumBytes.equals(expected)) fail('release SHA256SUMS content does not match the complete manifest asset inventory');
  return Object.freeze(snapshots);
}

export { CORE_KINDS, INVENTORY_TYPE, INVENTORY_VERSION, ROUNDTRIP_TYPE, SUPPLEMENTAL_KINDS };
