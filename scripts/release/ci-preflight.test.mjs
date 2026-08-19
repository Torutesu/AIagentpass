import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertCandidateBinding, assertCleanCheckout, assertExternalGates, assertWorkflowBoundary, parseArguments } from './ci-preflight.mjs';

const git = (root, ...args) => {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};

const candidate = () => {
  const root = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-ci-preflight-'));
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'ci@example.invalid');
  git(root, 'config', 'user.name', 'CI');
  fs.writeFileSync(join(root, 'source.txt'), 'source\n');
  git(root, 'add', 'source.txt');
  git(root, 'commit', '-qm', 'candidate');
  return { root, commit: git(root, 'rev-parse', 'HEAD'), tree: git(root, 'rev-parse', 'HEAD^{tree}') };
};

const writeManifest = ({ root, commit, tree, artifact = Buffer.from('product\n') }) => {
  const artifactName = 'AgentPass.pkg';
  fs.writeFileSync(join(root, artifactName), artifact);
  const sha256 = createHash('sha256').update(artifact).digest('hex');
  const manifest = { source: { commit, tree }, artifacts: [{ role: 'product', name: artifactName, bytes: artifact.length, sha256 }], candidate_id: `release-pkg-sha256-v1-${sha256}` };
  const manifestPath = join(root, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  return { manifestPath, manifest, artifactName };
};

test('workflow boundary rejects pull requests and non-main refs', () => {
  assert.throws(() => assertWorkflowBoundary({ eventName: 'pull_request', ref: 'refs/heads/main', repository: 'Torutesu/AIagentpass' }), /cannot access release credentials/);
  assert.throws(() => assertWorkflowBoundary({ eventName: 'workflow_dispatch', ref: 'refs/heads/feature', repository: 'Torutesu/AIagentpass' }), /protected main/);
  assert.throws(() => assertWorkflowBoundary({ eventName: 'workflow_dispatch', ref: 'refs/heads/main', repository: 'fork/AIagentpass' }), /not canonical/);
});

test('clean checkout preflight rejects tracked and untracked changes', () => {
  const { root } = candidate();
  fs.writeFileSync(join(root, 'source.txt'), 'changed\n');
  fs.writeFileSync(join(root, 'untracked.txt'), 'dirty\n');
  assert.throws(() => assertCleanCheckout(root), /checkout is dirty/);
});

test('candidate binding rejects a source tree mismatch', () => {
  const fixture = candidate();
  const expectedTree = 'f'.repeat(40);
  const { manifestPath } = writeManifest({ ...fixture, tree: expectedTree });
  assert.throws(() => assertCandidateBinding({ repoRoot: fixture.root, manifestPath, expectedCommit: fixture.commit, expectedTree }), /checkout HEAD\/tree differs/);
});

test('candidate binding rejects a product artifact digest mismatch', () => {
  const fixture = candidate();
  const { manifestPath, artifactName } = writeManifest(fixture);
  fs.writeFileSync(join(fixture.root, artifactName), 'tampered\n');
  assert.throws(() => assertCandidateBinding({ repoRoot: fixture.root, manifestPath, expectedCommit: fixture.commit, expectedTree: fixture.tree }), /product digest differs/);
});

test('external gate preflight rejects not_proven evidence and requires explicit status', () => {
  const root = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-ci-preflight-'));
  const blocked = join(root, 'blocked.json');
  const passed = join(root, 'passed.json');
  fs.writeFileSync(blocked, JSON.stringify({ qualification: { hardware: { apple: { status: 'not_proven' } } } }));
  fs.writeFileSync(passed, JSON.stringify({ qualified: true, production: true }));
  assert.throws(() => assertExternalGates({ gateFiles: [blocked], required: { qualified: true } }), /not_proven/);
  assert.throws(() => assertExternalGates({ gateFiles: [passed], required: { hardware: true } }), /hardware=true/);
  assert.deepEqual(assertExternalGates({ gateFiles: [passed], required: { qualified: true, production: true } }), { files: 1, required: ['qualified', 'production'] });
});

test('argument parser is explicit and fail-closed', () => {
  assert.deepEqual(parseArguments(['--event-name', 'workflow_dispatch', '--gate-file', 'a.json', '--gate-file', 'b.json', '--require', 'qualified=true', '--require', 'mode=hardware']), {
    eventName: 'workflow_dispatch', gateFiles: ['a.json', 'b.json'], required: { qualified: true, mode: 'hardware' }
  });
  assert.throws(() => parseArguments(['--event-name']), /requires a value/);
  assert.throws(() => parseArguments(['--unknown', 'value']), /unknown argument/);
  assert.throws(() => parseArguments(['--require', 'qualified']), /requires key=value/);
});
