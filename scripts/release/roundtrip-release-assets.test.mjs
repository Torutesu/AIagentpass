import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  buildReleaseAssetInventory,
  classifyReleaseAsset,
  validateReleaseAssetInventory,
  verifyReleaseAssetRoundTrip
} from './roundtrip-release-assets.mjs';

const write = (root, name, value) => {
  const target = path.join(root, name);
  fs.writeFileSync(target, value);
  return target;
};

test('v2 inventory requires the signed manifest core and classifies supplemental assets', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-release-inventory-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const names = [
    ['AgentPass-v1.0.0.release-manifest.json', 'manifest'],
    ['AgentPass-v1.0.0.release-manifest.sig', 'signature'],
    ['release-manifest.public.pem', 'public key'],
    ['AgentPass-v1.0.0-macos-universal.pkg', 'package'],
    ['AgentPass-v1.0.0.spdx.json', '{}'],
    ['SHA256SUMS', 'sums'],
    ['macos-distribution-evidence.json', '{}'],
    ['p0c-apple-silicon-report.json', '{}']
  ];
  const inputs = names.map(([name, value]) => ({ name, path: write(root, name, value) }));
  const inventory = buildReleaseAssetInventory(inputs, { requireSupplemental: true });
  assert.equal(inventory.version, 2);
  assert.equal(inventory.assets.length, inputs.length);
  assert.deepEqual(inventory.required_kinds, [...inventory.required_kinds].sort());
  assert.equal(inventory.assets.find((asset) => asset.name.startsWith('macos-')).kind, 'macos_supplemental');
  assert.equal(inventory.assets.find((asset) => asset.name.startsWith('p0c-')).kind, 'qualification_supplemental');
  assert.doesNotThrow(() => validateReleaseAssetInventory(inventory, { requireSupplemental: true }));
  assert.equal(classifyReleaseAsset('AgentPass-v1.0.0.spdx.json'), 'sbom');
  assert.throws(() => buildReleaseAssetInventory(inputs.slice(0, 6), { requireSupplemental: true }), /missing required kind|supplemental/u);
});

test('roundtrip is exact, digest-bound, and rejects substitution or extra supplemental files', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-release-roundtrip-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'); const remote = path.join(root, 'remote');
  fs.mkdirSync(source); fs.mkdirSync(remote);
  const names = [
    ['AgentPass-v1.0.0.release-manifest.json', 'manifest'],
    ['AgentPass-v1.0.0.release-manifest.sig', 'signature'],
    ['release-manifest.public.pem', 'public'],
    ['AgentPass-v1.0.0-macos-universal.pkg', 'pkg'],
    ['AgentPassQualificationController-1.0.0-macos-universal.tar', 'controller'],
    ['AgentPass-v1.0.0.spdx.json', '{}'],
    ['SHA256SUMS', 'sums'],
    ['macos-verification.json', '{}'],
    ['p0c-summary.json', '{}']
  ];
  const inputs = names.map(([name, value]) => {
    const sourcePath = write(source, name, value);
    fs.copyFileSync(sourcePath, path.join(remote, name));
    return { name, path: sourcePath };
  });
  const inventory = buildReleaseAssetInventory(inputs, { requiredKinds: ['manifest', 'manifest_signature', 'manifest_public_key', 'release_artifact', 'sbom', 'checksum', 'macos_supplemental', 'qualification_supplemental'] });
  const result = verifyReleaseAssetRoundTrip(inventory, remote, { requireSupplemental: true });
  assert.equal(result.inventory_sha256, inventory.inventory_sha256);
  assert.equal(result.assets.length, inventory.assets.length);
  fs.writeFileSync(path.join(remote, 'p0c-summary.json'), 'substituted');
  assert.throws(() => verifyReleaseAssetRoundTrip(inventory, remote, { requireSupplemental: true }), /digest mismatch/u);
  fs.writeFileSync(path.join(remote, 'p0c-summary.json'), 'p0c-summary');
  fs.writeFileSync(path.join(remote, 'unexpected.json'), 'extra');
  assert.throws(() => verifyReleaseAssetRoundTrip(inventory, remote), /set mismatch/u);
  const tampered = { ...inventory, inventory_sha256: crypto.createHash('sha256').update('wrong').digest('hex') };
  assert.throws(() => verifyReleaseAssetRoundTrip(tampered, remote), /inventory digest mismatch/u);
});

test('inventory rejects symlinks, hardlinks, missing required kinds, and unknown fields', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-release-inventory-negative-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = write(root, 'AgentPass-v1.0.0-macos-universal.pkg', 'pkg');
  const symlink = path.join(root, 'symlink.pkg');
  fs.symlinkSync(target, symlink);
  assert.throws(() => buildReleaseAssetInventory([{ name: 'symlink.pkg', path: symlink }]), /unsafe|ELOOP/u);
  const hardlink = path.join(root, 'hardlink.pkg');
  fs.linkSync(target, hardlink);
  assert.throws(() => buildReleaseAssetInventory([{ name: 'hardlink.pkg', path: hardlink }]), /unsafe/u);
  assert.throws(() => validateReleaseAssetInventory({ version: 2, type: 'agentpass.release-asset-inventory', required_kinds: ['manifest'], assets: [], inventory_sha256: '0'.repeat(64) }), /digest mismatch|empty/u);
});
