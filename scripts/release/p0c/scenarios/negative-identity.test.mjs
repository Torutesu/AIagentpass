import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createNegativeProbeManifest, canonicalNegativeProbeManifest } from '../../../../native/macos/Qualification/negative-probe-manifest.mjs';
import { performNegativeIdentityQualification } from './negative-identity-and-entitlement-cases';

const release = {
  artifactSha256: 'a'.repeat(64),
  sourceCommit: 'b'.repeat(40),
  teamId: 'ABCDE12345',
};

const canonicalReleaseManifest = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const makeFixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-negative-probe-'));
  const releaseManifest = canonicalReleaseManifest({ source: { commit: release.sourceCommit }, artifacts: [{ role: 'product', sha256: release.artifactSha256 }] });
  const releaseManifestPath = path.join(root, 'release-manifest.json');
  fs.writeFileSync(releaseManifestPath, releaseManifest, { mode: 0o600 });
  const manifest = createNegativeProbeManifest({
    sourceCommit: release.sourceCommit,
    artifactSha256: release.artifactSha256,
    releaseManifestSha256: crypto.createHash('sha256').update(releaseManifest).digest('hex'),
    teamId: release.teamId,
    wrongTeamId: 'ZZZZZ98765',
  });
  const manifestPath = path.join(root, 'negative-probe-manifest.json');
  fs.writeFileSync(manifestPath, canonicalNegativeProbeManifest(manifest), { mode: 0o600 });
  const probeRoot = path.join(root, 'probes-root');
  fs.mkdirSync(path.join(probeRoot, 'probes'), { mode: 0o700, recursive: true });
  for (const probe of manifest.probes) {
    fs.mkdirSync(path.join(probeRoot, probe.relative_path, 'Contents', 'MacOS'), { mode: 0o700, recursive: true });
    fs.writeFileSync(path.join(probeRoot, probe.relative_path, 'Contents', 'MacOS', 'agentpass-negative-xpc-probe'), '#!/bin/sh\n', { mode: 0o500 });
  }
  return { root, manifest, manifestPath, releaseManifestPath, probeRoot };
};

const machine = (checkpointDirectory) => ({
  applicationPath: '/Applications/AgentPass.app',
  serviceLabel: 'dev.agentpass.native-service',
  checkpointDirectory,
});

const runPinned = async (entry, args) => {
  const role = path.basename(path.dirname(path.dirname(path.dirname(entry.path)))).replace('-client.app', '');
  if (args[0] === 'identity') {
    const identities = {
      approved: { bundle_id: 'dev.agentpass.native-client', team_id: release.teamId, designated_requirement: `anchor apple generic and identifier "dev.agentpass.native-client" and certificate leaf[subject.OU] = "${release.teamId}"`, entitlements: { 'keychain-access-groups': [`${release.teamId}.dev.agentpass.approval-keys`] }, signature_kind: 'developer-id' },
      'missing-entitlement': { bundle_id: 'dev.agentpass.native-client', team_id: release.teamId, designated_requirement: `anchor apple generic and identifier "dev.agentpass.native-client" and certificate leaf[subject.OU] = "${release.teamId}"`, entitlements: {}, signature_kind: 'developer-id' },
      'wrong-team': { bundle_id: 'dev.agentpass.native-client', team_id: 'ZZZZZ98765', designated_requirement: `anchor apple generic and identifier "dev.agentpass.native-client" and certificate leaf[subject.OU] = "ZZZZZ98765"`, entitlements: { 'keychain-access-groups': ['ZZZZZ98765.dev.agentpass.approval-keys'] }, signature_kind: 'developer-id' },
      'ad-hoc': { bundle_id: 'dev.agentpass.native-client', team_id: null, designated_requirement: '(adhoc)', entitlements: {}, signature_kind: 'ad-hoc' },
    };
    return { ok: true, stdout: Buffer.from(`${JSON.stringify({ schema_version: 1, ...identities[role] })}\n`) };
  }
  const allowed = role === 'approved';
  return { ok: true, stdout: Buffer.from(`${JSON.stringify({ schema_version: 1, operation: 'qualification-health', outcome: allowed ? 'allowlisted-method-reached' : 'denied-before-signing', service_protocol_version: allowed ? 13 : null })}\n`) };
};

test('negative identity qualification validates all four canonical roles and only health for the approved role', async () => {
  const fixture = makeFixture();
  const result = await performNegativeIdentityQualification({
    release,
    machine: machine(fixture.root),
    production: false,
    getUid: () => 0,
    manifestPath: fixture.manifestPath,
    releaseManifestPath: fixture.releaseManifestPath,
    probeRoot: fixture.probeRoot,
    runPinned,
    withCheckpoint: async (_path, operation) => operation(),
  });
  assert.deepEqual(result, ['unrelated-process-denied']);
});

test('negative identity qualification rejects a negative probe that reaches the exported method', async () => {
  const fixture = makeFixture();
  await assert.rejects(() => performNegativeIdentityQualification({
    release,
    machine: machine(fixture.root),
    production: false,
    getUid: () => 0,
    manifestPath: fixture.manifestPath,
    releaseManifestPath: fixture.releaseManifestPath,
    probeRoot: fixture.probeRoot,
    runPinned: async (entry, args) => {
      const value = await runPinned(entry, args);
      if (args[0] !== 'identity' && !entry.path.includes('approved-client.app')) value.stdout = Buffer.from(`${JSON.stringify({ schema_version: 1, operation: 'qualification-health', outcome: 'allowlisted-method-reached', service_protocol_version: 13 })}\n`);
      return value;
    },
    withCheckpoint: async (_path, operation) => operation(),
  }), /denied before signing/u);
});

test('negative probe signing helper is fail-closed and never substitutes a local identity', () => {
  const source = fs.readFileSync(path.resolve('native/macos/Qualification/sign-negative-probes.sh'), 'utf8');
  assert.match(source, /AGENTPASS_PROBE_APPROVED_SIGNING_IDENTITY/);
  assert.match(source, /AGENTPASS_PROBE_WRONG_TEAM_SIGNING_IDENTITY/);
  assert.match(source, /codesign --force/);
  assert.match(source, /codesign --verify --strict/);
  assert.match(source, /sign -/);
  assert.doesNotMatch(source, /openssl gen|security create-keychain|fake|placeholder/iu);
});
