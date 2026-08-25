import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  FIXED_CANDIDATE_CHECKPOINT_PATH,
  FIXED_QUALIFICATION_RELEASE_DIRECTORY,
  FIXED_QUALIFICATION_RELEASE_TRUST_PATH,
  QUALIFICATION_RELEASE_TRUST_KIND,
  QUALIFICATION_RELEASE_TRUST_SCHEMA_VERSION,
  normalizeQualificationReleaseTrust,
  parseQualificationReleaseTrust,
  resolveQualificationReleaseTrust
} from './qualification-release-trust.mjs';

const UID = process.getuid?.();
const trust = (overrides = {}) => ({
  schema_version: QUALIFICATION_RELEASE_TRUST_SCHEMA_VERSION,
  artifact_sha256: 'a'.repeat(64),
  candidate_checkpoint_sha256: 'b'.repeat(64),
  expected_fingerprint: `SHA256:${'A'.repeat(43)}`,
  kind: QUALIFICATION_RELEASE_TRUST_KIND,
  manifest_name: 'release-manifest.json',
  product_name: 'AgentPass.pkg',
  public_key_name: 'release-public.pem',
  run_binding_name: 'run-binding',
  signature_name: 'release-manifest.sig',
  source_commit: 'c'.repeat(40),
  team_id: 'ABCDE12345',
  ...overrides
});
const canonical = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);

const fixture = () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-release-trust-')));
  const releaseDirectory = path.join(root, 'release');
  fs.mkdirSync(releaseDirectory, { mode: 0o700 });
  fs.chmodSync(root, 0o700);
  const trustPath = path.join(root, 'release-trust.json');
  fs.writeFileSync(trustPath, canonical(trust()), { mode: 0o600 });
  return { root, releaseDirectory, trustPath };
};

test('exports fixed production trust and checkpoint paths', () => {
  assert.equal(FIXED_QUALIFICATION_RELEASE_DIRECTORY, '/private/var/db/agentpass-qualification/release');
  assert.equal(FIXED_QUALIFICATION_RELEASE_TRUST_PATH, '/private/var/db/agentpass-qualification/release-trust.json');
  assert.equal(FIXED_CANDIDATE_CHECKPOINT_PATH, '/private/var/db/agentpass-qualification/candidate-checkpoint.json');
});

test('release trust is closed, canonical, and rejects duplicate or unsafe names', () => {
  assert.deepEqual(parseQualificationReleaseTrust(canonical(trust())), normalizeQualificationReleaseTrust(trust()));
  assert.throws(() => parseQualificationReleaseTrust(Buffer.from(JSON.stringify(trust()))), /canonical/u);
  const duplicate = canonical(trust()).toString().replace('  "artifact_sha256"', `  "artifact_sha256": "${'a'.repeat(64)}",\n  "artifact_sha256"`);
  assert.throws(() => parseQualificationReleaseTrust(Buffer.from(duplicate)), /canonical|invalid/u);
  assert.throws(() => normalizeQualificationReleaseTrust(trust({ product_name: '../AgentPass.pkg' })), /invalid/u);
  assert.throws(() => normalizeQualificationReleaseTrust(trust({ product_name: 'release-manifest.json' })), /not unique/u);
});

test('trust resolution binds fixed release paths to the exact candidate checkpoint', () => {
  const value = fixture();
  try {
    const checkpoint = { checkpoint_sha256: 'b'.repeat(64), artifact_sha256: 'a'.repeat(64), source_commit: 'c'.repeat(40), team_id: 'ABCDE12345' };
    const result = resolveQualificationReleaseTrust({ checkpoint, trustPath: value.trustPath, releaseDirectory: value.releaseDirectory, expectedUid: UID, uid: UID, production: false });
    assert.equal(result.expectedFingerprint, `SHA256:${'A'.repeat(43)}`);
    assert.equal(result.manifestPath, path.join(value.releaseDirectory, 'release-manifest.json'));
    assert.equal(result.productPath, path.join(value.releaseDirectory, 'AgentPass.pkg'));
    assert.equal(result.expectedArtifactSha256, 'a'.repeat(64));
    for (const changed of [
      { ...checkpoint, checkpoint_sha256: 'd'.repeat(64) },
      { ...checkpoint, artifact_sha256: 'd'.repeat(64) },
      { ...checkpoint, source_commit: 'd'.repeat(40) },
      { ...checkpoint, team_id: 'ZZZZZ99999' }
    ]) assert.throws(() => resolveQualificationReleaseTrust({ checkpoint: changed, trustPath: value.trustPath, releaseDirectory: value.releaseDirectory, expectedUid: UID, uid: UID, production: false }), /does not match/u);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test('trust resolution rejects unsafe modes, links, and production path substitution', () => {
  const value = fixture();
  const checkpoint = { checkpoint_sha256: 'b'.repeat(64), artifact_sha256: 'a'.repeat(64), source_commit: 'c'.repeat(40), team_id: 'ABCDE12345' };
  try {
    fs.chmodSync(value.trustPath, 0o644);
    assert.throws(() => resolveQualificationReleaseTrust({ checkpoint, trustPath: value.trustPath, releaseDirectory: value.releaseDirectory, expectedUid: UID, uid: UID, production: false }), /unsafe/u);
    fs.chmodSync(value.trustPath, 0o600);
    const link = path.join(value.root, 'linked-trust.json');
    fs.symlinkSync(value.trustPath, link);
    assert.throws(() => resolveQualificationReleaseTrust({ checkpoint, trustPath: link, releaseDirectory: value.releaseDirectory, expectedUid: UID, uid: UID, production: false }), /unavailable|unsafe/u);
    assert.throws(() => resolveQualificationReleaseTrust({ checkpoint, trustPath: value.trustPath, releaseDirectory: value.releaseDirectory, platform: 'darwin', uid: 0, expectedUid: 0, production: true }), /fixed paths/u);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});
