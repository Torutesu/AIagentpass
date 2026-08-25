import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  emitControllerCandidate,
  makeControllerCandidate,
  parseArguments,
  canonicalJSON,
  MANIFEST_KIND,
  QUALIFICATION_MACH_SERVICE,
  QUALIFICATION_MODE
} from './generate-controller-candidate.mjs';

const SCRIPT = path.join(path.dirname(new URL(import.meta.url).pathname), 'generate-controller-candidate.mjs');
const digest = (letter) => letter.repeat(64);
const cdhash = (letter) => letter.repeat(40);

const fixture = () => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), 'agentpass-n3e-controller-'));
  const pair = crypto.generateKeyPairSync('ed25519');
  const serviceConfigPath = path.join(root, 'native-service.json');
  const privateKeyPath = path.join(root, 'release-private.pem');
  const publicKeyPath = path.join(root, 'release-public-input.pem');
  const outputDirectory = path.join(root, 'candidate');
  const service = {
    unrelated_service_field: 'ignored by this producer',
    qualification_mode: QUALIFICATION_MODE,
    qualification_mach_service_name: QUALIFICATION_MACH_SERVICE,
    qualification_candidate_sha256: digest('a'),
    qualification_source_commit_sha256: digest('b'),
    qualification_code_identities_sha256: digest('c'),
    qualification_controller_cdhash: cdhash('e'),
    qualification_run_id_sha256: digest('d'),
    qualification_expires_at_epoch_seconds: Math.ceil(Date.now() / 1000) + 300,
    qualification_scenario: 'pre-cloud-kill',
    qualification_phase: 'pre-cloud'
  };
  fs.writeFileSync(serviceConfigPath, JSON.stringify(service), { mode: 0o600 });
  fs.writeFileSync(privateKeyPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(publicKeyPath, pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  fs.chmodSync(serviceConfigPath, 0o600);
  fs.chmodSync(privateKeyPath, 0o600);
  fs.chmodSync(publicKeyPath, 0o600);
  return { root, serviceConfigPath, privateKeyPath, publicKeyPath, outputDirectory, service, pair };
};

const inputs = (value) => ({
  serviceConfigPath: value.serviceConfigPath,
  privateKeyPath: value.privateKeyPath,
  publicKeyPath: value.publicKeyPath,
  outputDirectory: value.outputDirectory
});

const writeService = (value, changes = {}) => {
  const next = { ...value.service, ...changes };
  fs.writeFileSync(value.serviceConfigPath, JSON.stringify(next), { mode: 0o600 });
  fs.chmodSync(value.serviceConfigPath, 0o600);
};

test('valid config emits compact sorted signed context and protected files', () => {
  const value = fixture();
  const result = emitControllerCandidate(inputs(value));
  assert.deepEqual(result, { manifestBytes: result.manifestBytes, signatureBytes: 89, files: 3 });
  const manifestPath = path.join(value.outputDirectory, 'controller-candidate.json');
  const signaturePath = path.join(value.outputDirectory, 'controller-candidate.sig');
  const publicPath = path.join(value.outputDirectory, 'release-public.pem');
  const manifestBytes = fs.readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  assert.deepEqual(Object.keys(manifest), [...Object.keys(manifest).sort()]);
  assert.equal(manifestBytes.toString(), JSON.stringify(manifest));
  assert.deepEqual(manifest, {
    schema_version: 2,
    kind: MANIFEST_KIND,
    candidate_sha256: digest('a'),
    source_commit_sha256: digest('b'),
    code_identities_sha256: digest('c'),
    controller_cdhash: cdhash('e'),
    run_id_sha256: digest('d'),
    expires_at_epoch_seconds: value.service.qualification_expires_at_epoch_seconds,
    scenario: 'pre-cloud-kill',
    phase: 'pre-cloud'
  });
  const signature = Buffer.from(fs.readFileSync(signaturePath, 'utf8').trim(), 'base64');
  const publicKey = crypto.createPublicKey(fs.readFileSync(publicPath));
  assert.equal(signature.length, 64);
  assert.equal(crypto.verify(null, manifestBytes, publicKey, signature), true);
  for (const name of ['controller-candidate.json', 'controller-candidate.sig', 'release-public.pem']) {
    assert.equal(fs.statSync(path.join(value.outputDirectory, name)).mode & 0o777, 0o600);
  }
  assert.equal(fs.statSync(value.outputDirectory).mode & 0o777, 0o700);
  assert.equal(result.files, 3);
});

test('identity substitutions come only from service config and unknown identity options are refused', () => {
  const value = fixture();
  writeService(value, { qualification_candidate_sha256: digest('e') });
  emitControllerCandidate(inputs(value));
  const manifest = JSON.parse(fs.readFileSync(path.join(value.outputDirectory, 'controller-candidate.json')));
  assert.equal(manifest.candidate_sha256, digest('e'));
  assert.throws(() => parseArguments([
    '--service-config', value.serviceConfigPath,
    '--private-key', value.privateKeyPath,
    '--public-key', value.publicKeyPath,
    '--output', path.join(value.root, 'other'),
    '--run-id', 'must-not-be-an-option'
  ]), /Usage/u);
  assert.throws(() => parseArguments([
    '--service-config', value.serviceConfigPath,
    '--private-key', value.privateKeyPath,
    '--public-key', value.publicKeyPath,
    '--output', path.join(value.root, 'third'),
    '--controller-cdhash', cdhash('e')
  ]), /Usage/u);
});

test('service config rejects mode, service, closed-pair, digest, and expiry substitutions', () => {
  for (const changes of [
    { qualification_mode: 'production' },
    { qualification_mach_service_name: 'dev.agentpass.other' },
    { qualification_scenario: 'pre-cloud-kill', qualification_phase: 'transport-reply' },
    { qualification_candidate_sha256: digest('A') },
    { qualification_candidate_sha256: '0'.repeat(64) },
    { qualification_controller_cdhash: cdhash('A') },
    { qualification_controller_cdhash: '0'.repeat(40) },
    { qualification_controller_cdhash: undefined },
    // Keep the invalid expiry well outside the 900-second window even when
    // the full parallel suite delays this assertion by several seconds.
    { qualification_expires_at_epoch_seconds: Math.ceil(Date.now() / 1000) + 3_600 }
  ]) {
    const value = fixture();
    writeService(value, changes);
    assert.throws(() => emitControllerCandidate(inputs(value)), /invalid|substitution|pair|expiry|mode|service/iu);
    assert.equal(fs.existsSync(value.outputDirectory), false);
  }
});

test('input symlinks and insecure modes are refused', () => {
  const symlink = fixture();
  const replacement = path.join(symlink.root, 'service-real.json');
  fs.renameSync(symlink.serviceConfigPath, replacement);
  fs.symlinkSync(replacement, symlink.serviceConfigPath);
  assert.throws(() => emitControllerCandidate(inputs(symlink)), /unavailable|unsafe/iu);

  const privateMode = fixture();
  fs.chmodSync(privateMode.privateKeyPath, 0o640);
  assert.throws(() => emitControllerCandidate(inputs(privateMode)), /private key.*protected/iu);

  const serviceMode = fixture();
  fs.chmodSync(serviceMode.serviceConfigPath, 0o644);
  assert.throws(() => emitControllerCandidate(inputs(serviceMode)), /service config.*protected/iu);

  const publicMode = fixture();
  fs.chmodSync(publicMode.publicKeyPath, 0o644);
  assert.throws(() => emitControllerCandidate(inputs(publicMode)), /public key.*protected/iu);
});

test('output parent must be current-user-owned and not attacker-writable, with safe ancestry', () => {
  const writable = fixture();
  const parent = path.join(writable.root, 'writable-parent');
  fs.mkdirSync(parent, { mode: 0o777 });
  fs.chmodSync(parent, 0o777);
  writable.outputDirectory = path.join(parent, 'candidate');
  assert.throws(() => emitControllerCandidate(inputs(writable)), /output ancestry|writable/iu);

  const symlinkParent = fixture();
  const realAncestor = path.join(symlinkParent.root, 'real-ancestor');
  const realParent = path.join(realAncestor, 'real-parent');
  fs.mkdirSync(realParent, { recursive: true, mode: 0o700 });
  const linkedAncestor = path.join(symlinkParent.root, 'linked-ancestor');
  fs.symlinkSync(realAncestor, linkedAncestor);
  symlinkParent.outputDirectory = path.join(linkedAncestor, 'real-parent', 'candidate');
  assert.throws(() => emitControllerCandidate(inputs(symlinkParent)), /output ancestry|unsafe/iu);
});

test('mismatched keys and existing output are refused without overwriting', () => {
  const mismatch = fixture();
  const other = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(mismatch.publicKeyPath, other.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  assert.throws(() => emitControllerCandidate(inputs(mismatch)), /does not match/iu);

  const existing = fixture();
  fs.mkdirSync(existing.outputDirectory, { mode: 0o700 });
  fs.writeFileSync(path.join(existing.outputDirectory, 'keep'), 'preserve');
  assert.throws(() => emitControllerCandidate(inputs(existing)), /already exists/iu);
  assert.equal(fs.readFileSync(path.join(existing.outputDirectory, 'keep'), 'utf8'), 'preserve');

  const outputSymlink = fixture();
  const target = path.join(outputSymlink.root, 'target');
  fs.mkdirSync(target, { mode: 0o700 });
  fs.symlinkSync(target, outputSymlink.outputDirectory);
  assert.throws(() => emitControllerCandidate(inputs(outputSymlink)), /already exists|unsafe/iu);
});

test('CLI is strict and stdout is a fixed bounded summary', () => {
  const value = fixture();
  const result = spawnSync(process.execPath, [SCRIPT,
    '--service-config', value.serviceConfigPath,
    '--private-key', value.privateKeyPath,
    '--public-key', value.publicKeyPath,
    '--output', value.outputDirectory
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '{"ok":true,"files":3}\n');
  assert.doesNotMatch(result.stdout, /[a-f0-9]{40,}|PRIVATE KEY|run/iu);

  const unknown = spawnSync(process.execPath, [SCRIPT,
    '--service-config', value.serviceConfigPath,
    '--private-key', value.privateKeyPath,
    '--public-key', value.publicKeyPath,
    '--output', path.join(value.root, 'other'),
    '--unknown', 'x'
  ], { encoding: 'utf8' });
  assert.notEqual(unknown.status, 0);
  assert.equal(unknown.stdout, '');
  assert.doesNotMatch(unknown.stderr, /[a-f0-9]{40,}|PRIVATE KEY|run_id/iu);
});

test('manifest helper is canonical and has the native context keys', () => {
  const value = makeControllerCandidate({
    candidate: digest('a'), source: digest('b'), identities: digest('c'), controller: cdhash('e'), run: digest('d'),
    expiry: 1_900_000_000, scenario: 'transport-reply-loss', phase: 'transport-reply'
  });
  assert.equal(canonicalJSON(value).toString(), '{"candidate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","code_identities_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","controller_cdhash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","expires_at_epoch_seconds":1900000000,"kind":"agentpass-n3e-controller-candidate","phase":"transport-reply","run_id_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","scenario":"transport-reply-loss","schema_version":2,"source_commit_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}');
  assert.deepEqual(Object.keys(value).sort(), [
    'candidate_sha256', 'code_identities_sha256', 'controller_cdhash', 'expires_at_epoch_seconds', 'kind',
    'phase', 'run_id_sha256', 'scenario', 'schema_version', 'source_commit_sha256'
  ]);
});
