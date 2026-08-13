import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  candidateCheckpointHash,
  mintCandidateCheckpoint,
  observeInstalledFileIdentity,
  readCandidateCheckpoint,
  validateCandidateCheckpoint,
  verifyCandidateCheckpoint,
  withVerifiedCandidateCheckpoint
} from '../scripts/release/p0c/lib/candidate-checkpoint.mjs';

const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');

const fixture = () => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'agentpass-candidate-checkpoint-'));
  const app = path.join(root, 'AgentPass.app');
  const contents = path.join(app, 'Contents');
  const nested = path.join(contents, 'MacOS', 'agentpass-native-client');
  const checkpoint = path.join(root, 'candidate-checkpoint.json');
  fs.mkdirSync(path.dirname(nested), { recursive: true, mode: 0o700 });
  fs.writeFileSync(nested, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  fs.chmodSync(nested, 0o755);
  fs.chmodSync(contents, 0o755);
  fs.chmodSync(app, 0o755);
  const teamId = 'A1B2C3D4E5';
  const metadata = new Map([
    [app, { bundle_id: 'dev.agentpass', team_id: teamId, code_directory_hash: 'a'.repeat(40), designated_requirement: 'identifier "dev.agentpass" and anchor apple generic' }],
    [nested, { bundle_id: 'dev.agentpass.native-client', team_id: teamId, code_directory_hash: 'b'.repeat(40), designated_requirement: 'identifier "dev.agentpass.native-client" and anchor apple generic' }]
  ]);
  const codeObjects = [
    { path: app, role: 'application', ...metadata.get(app) },
    { path: nested, role: 'native-client', ...metadata.get(nested) }
  ].sort((left, right) => left.path.localeCompare(right.path));
  const identityReader = (input) => metadata.get(input);
  return { root, app, nested, checkpoint, teamId, codeObjects, identityReader };
};

const request = (value) => ({
  checkpoint_path: value.checkpoint,
  artifact_sha256: '1'.repeat(64),
  source_commit: '2'.repeat(40),
  team_id: value.teamId,
  application_path: value.app,
  code_objects: value.codeObjects
});

test('mints a canonical checkpoint from the exact installed file identities', () => {
  const value = fixture();
  const checkpoint = mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader });
  assert.equal(checkpoint.schema_version, 1);
  assert.equal(checkpoint.application_path, value.app);
  assert.deepEqual(checkpoint.code_objects.map((item) => item.path), value.codeObjects.map((item) => item.path));
  assert.ok(Number(checkpoint.code_objects[0].file_identity.nlink) > 1);
  assert.equal(checkpoint.checkpoint_sha256, candidateCheckpointHash(checkpoint));
  assert.deepEqual(readCandidateCheckpoint(value.checkpoint, { production: false }), checkpoint);
  assert.equal(fs.statSync(value.checkpoint).mode & 0o7777, 0o600);
});

test('publication is exclusive and never overwrites an existing checkpoint', () => {
  const value = fixture();
  const first = mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader });
  const replacement = { ...request(value), source_commit: '3'.repeat(40) };
  assert.throws(() => mintCandidateCheckpoint(replacement, { production: false, identityReader: value.identityReader }), /EEXIST|exist|unavailable/i);
  assert.deepEqual(readCandidateCheckpoint(value.checkpoint, { production: false }), first);
});

test('canonical and schema validation reject tampering, reordered objects, and mismatched application bindings', () => {
  const value = fixture();
  const checkpoint = mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader });
  const reordered = { ...checkpoint, code_objects: [...checkpoint.code_objects].reverse() };
  reordered.checkpoint_sha256 = candidateCheckpointHash(reordered);
  assert.throws(() => validateCandidateCheckpoint(reordered), /strictly sorted/);
  const wrongApplication = { ...checkpoint, application_path: path.join(value.root, 'Other.app') };
  wrongApplication.checkpoint_sha256 = candidateCheckpointHash(wrongApplication);
  assert.throws(() => validateCandidateCheckpoint(wrongApplication), /application identity|application binding|roles|escapes/);
  const altered = { ...checkpoint, artifact_sha256: '4'.repeat(64) };
  assert.throws(() => validateCandidateCheckpoint(altered), /digest mismatch/);
  const bytes = fs.readFileSync(value.checkpoint, 'utf8').replace('"artifact_sha256": "' + '1'.repeat(64), '"artifact_sha256": "' + '4'.repeat(64));
  fs.writeFileSync(value.checkpoint, bytes, { mode: 0o600 });
  assert.throws(() => readCandidateCheckpoint(value.checkpoint, { production: false }), /digest mismatch|canonical/);
});

test('symlink, hard-link, mode, owner, and digest substitutions fail closed', () => {
  const value = fixture();
  const linkPath = path.join(value.root, 'link.app');
  fs.symlinkSync(value.app, linkPath);
  const symlinkRequest = { ...request(value), application_path: linkPath, code_objects: value.codeObjects.map((item) => item.path === value.app ? { ...item, path: linkPath } : item).sort((left, right) => left.path.localeCompare(right.path)) };
  assert.throws(() => mintCandidateCheckpoint(symlinkRequest, { production: false, identityReader: value.identityReader }), /unavailable|unsafe|identity|outside/);

  const hardlink = path.join(value.root, 'hardlink');
  fs.linkSync(value.nested, hardlink);
  const hardlinkRequest = { ...request(value), code_objects: [...value.codeObjects, { ...value.codeObjects[1], path: hardlink }].sort((left, right) => left.path.localeCompare(right.path)) };
  assert.throws(() => mintCandidateCheckpoint(hardlinkRequest, { production: false, identityReader: value.identityReader }), /outside|unsafe|identity|roles/);
  fs.unlinkSync(hardlink);

  fs.chmodSync(value.nested, 0o775);
  assert.throws(() => mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader }), /unsafe/);
  fs.chmodSync(value.nested, 0o755);
  mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader });
  fs.appendFileSync(value.nested, 'tamper');
  assert.throws(() => verifyCandidateCheckpoint(value.checkpoint, { production: false, identityReader: value.identityReader }), /digest|identity|mismatch|unsafe/);
});

test('verification re-observes every object and catches substitution during use', async () => {
  const value = fixture();
  mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader });
  assert.doesNotThrow(() => verifyCandidateCheckpoint(value.checkpoint, { production: false, identityReader: value.identityReader, expected: { artifactSha256: '1'.repeat(64), sourceCommit: '2'.repeat(40), teamId: value.teamId, applicationPath: value.app } }));
  await assert.rejects(() => withVerifiedCandidateCheckpoint(value.checkpoint, async () => { fs.appendFileSync(value.nested, 'replacement'); }, { production: false, identityReader: value.identityReader }), /digest|identity|mismatch/);
  assert.throws(() => verifyCandidateCheckpoint(value.checkpoint, { production: false, identityReader: value.identityReader }), /digest|identity|mismatch/);
});

test('rejects a same-content inode replacement after the checkpoint was minted', async () => {
  const value = fixture();
  mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader });
  const original = fs.readFileSync(value.nested);
  const replacement = `${value.nested}.replacement`;
  fs.renameSync(value.nested, replacement);
  fs.writeFileSync(value.nested, original, { mode: 0o755 });
  fs.chmodSync(value.nested, 0o755);
  assert.throws(() => verifyCandidateCheckpoint(value.checkpoint, { production: false, identityReader: value.identityReader }), /digest|identity mismatch|changed/);
  await assert.rejects(() => withVerifiedCandidateCheckpoint(value.checkpoint, async () => {}, { production: false, identityReader: value.identityReader }), /digest|identity mismatch|changed/);
});

test('injected identity metadata cannot bypass the real file digest and file identity checks', () => {
  const value = fixture();
  const forged = (input) => ({ ...value.identityReader(input), code_directory_hash: 'c'.repeat(40) });
  assert.throws(() => mintCandidateCheckpoint(request(value), { production: false, identityReader: forged }), /signature identity mismatch/);
  const missing = () => ({ bundle_id: 'dev.agentpass', team_id: value.teamId, code_directory_hash: 'a'.repeat(40), designated_requirement: 'identifier "dev.agentpass"' });
  const altered = value.codeObjects.map((item) => item.path === value.nested ? { ...item, designated_requirement: 'identifier "other"' } : item);
  assert.throws(() => mintCandidateCheckpoint({ ...request(value), code_objects: altered }, { production: false, identityReader: missing }), /signature identity mismatch/);
});

test('directory traversal rejects replacement between the pre-read and post-read directory identities', () => {
  const value = fixture();
  let readdirCalls = 0;
  const raceFs = {
    ...fs,
    constants: fs.constants,
    readdirSync: (...args) => {
      const result = fs.readdirSync(...args);
      if (readdirCalls++ === 0) {
        const contents = path.join(value.app, 'Contents');
        fs.renameSync(contents, path.join(value.app, 'Contents.replaced'));
        fs.mkdirSync(contents, { mode: 0o755 });
      }
      return result;
    }
  };
  assert.throws(() => observeInstalledFileIdentity(value.app, { production: false, fsImpl: raceFs }), /changed while reading/);
});

test('roles are validated as unique and the application role is the installed bundle directory', () => {
  const value = fixture();
  const duplicateRole = value.codeObjects.map((item) => ({ ...item, role: item.role === 'native-client' ? 'application' : item.role }));
  assert.throws(() => mintCandidateCheckpoint({ ...request(value), code_objects: duplicateRole }, { production: false, identityReader: value.identityReader }), /roles are invalid/);
  const fileApplication = value.codeObjects.map((item) => ({ ...item, role: item.role === 'application' ? 'native-client' : 'application' }));
  assert.throws(() => mintCandidateCheckpoint({ ...request(value), application_path: value.nested, code_objects: fileApplication.sort((left, right) => left.path.localeCompare(right.path)) }, { production: false, identityReader: value.identityReader }), /roles are invalid|not a directory|outside/);
});

test('rejects symlinked checkpoint ancestry and symlinked code-object ancestry', () => {
  const value = fixture();
  const realDirectory = path.join(value.root, 'real-checkpoints');
  const linkedDirectory = path.join(value.root, 'linked-checkpoints');
  fs.mkdirSync(realDirectory, { mode: 0o700 });
  fs.symlinkSync(realDirectory, linkedDirectory);
  assert.throws(() => mintCandidateCheckpoint({ ...request(value), checkpoint_path: path.join(linkedDirectory, 'candidate.json') }, { production: false, identityReader: value.identityReader }), /directory.*unsafe|symlink/);

  const realObjects = path.join(value.app, 'Contents', 'RealObjects');
  const linkedObjects = path.join(value.app, 'Contents', 'LinkedObjects');
  fs.mkdirSync(realObjects, { mode: 0o700 });
  fs.symlinkSync(realObjects, linkedObjects);
  const linkedCode = path.join(linkedObjects, 'agentpass-native-client');
  fs.writeFileSync(path.join(realObjects, 'agentpass-native-client'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const linkedRequest = { ...request(value), code_objects: [...value.codeObjects, { ...value.codeObjects[1], path: linkedCode }].sort((left, right) => left.path.localeCompare(right.path)) };
  assert.throws(() => mintCandidateCheckpoint(linkedRequest, { production: false, identityReader: value.identityReader }), /outside|unavailable|unsafe|identity|roles/);
});

test('uses injected randomness for deterministic staging and still refuses collisions', () => {
  const value = fixture();
  const randomBytes = () => Buffer.alloc(16, 9);
  mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader, randomBytes });
  assert.throws(() => mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader, randomBytes }), /EEXIST|exist|unavailable/i);
});

test('requires protected checkpoint mode and rejects forged file identities', () => {
  const value = fixture();
  const checkpoint = mintCandidateCheckpoint(request(value), { production: false, identityReader: value.identityReader });
  fs.chmodSync(value.checkpoint, 0o640);
  assert.throws(() => readCandidateCheckpoint(value.checkpoint, { production: false }), /unsafe/);
  fs.chmodSync(value.checkpoint, 0o600);
  const forged = { ...checkpoint, code_objects: checkpoint.code_objects.map((item) => item.role === 'native-client' ? { ...item, file_identity: { ...item.file_identity, mode: '33188' } } : item) };
  forged.checkpoint_sha256 = candidateCheckpointHash(forged);
  assert.throws(() => validateCandidateCheckpoint(forged), /file identity is unsafe/);
});
