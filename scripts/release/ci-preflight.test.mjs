import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertCandidateBinding, assertCleanCheckout, assertExternalGates, assertGithubCiRun, assertProtectedArtifactDirectory, assertProtectedArtifactSecretScan, assertTerminalResults, assertWorkflowBoundary, EXACT_CI_LANES, parseArguments } from './ci-preflight.mjs';

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

const terminalResults = (commit, tree, overrides = {}) => EXACT_CI_LANES.map((lane) => ({
  lane,
  status: 'completed',
  conclusion: 'success',
  terminal: true,
  source_commit: commit,
  source_tree: tree,
  workflow_path: '.github/workflows/ci.yml',
  workflow_tree: tree,
  ...overrides[lane],
}));

test('exact-SHA qualification requires all six terminal CI lanes and one workflow tree', () => {
  const fixture = candidate();
  assert.deepEqual(assertTerminalResults({ results: terminalResults(fixture.commit, fixture.tree), expectedCommit: fixture.commit, expectedTree: fixture.tree }), {
    lanes: [...EXACT_CI_LANES], sourceCommit: fixture.commit, sourceTree: fixture.tree, workflowPath: '.github/workflows/ci.yml'
  });
  assert.throws(() => assertTerminalResults({ results: terminalResults(fixture.commit, fixture.tree).slice(0, 5), expectedCommit: fixture.commit, expectedTree: fixture.tree }), /exactly 6 lanes/);
  assert.throws(() => assertTerminalResults({ results: terminalResults(fixture.commit, fixture.tree, { test: { source_tree: 'f'.repeat(40) } }), expectedCommit: fixture.commit, expectedTree: fixture.tree }), /exact source SHA\/tree/);
  assert.throws(() => assertTerminalResults({ results: terminalResults(fixture.commit, fixture.tree, { test: { conclusion: 'failure' } }), expectedCommit: fixture.commit, expectedTree: fixture.tree }), /terminal success/);
});

test('GitHub CI API qualification maps the protected six jobs and rejects a different run', () => {
  const fixture = candidate();
  const run = {
    name: 'CI', path: '.github/workflows/ci.yml', status: 'completed', conclusion: 'success', event: 'push',
    head_branch: 'main', head_sha: fixture.commit, head_repository: { full_name: 'Torutesu/AIagentpass' }
  };
  const names = ['PostgreSQL 16 authority qualification', 'PostgreSQL 17 authority qualification', 'postgres-integration', 'browser-e2e', 'p0b-live-process', 'test'];
  assert.deepEqual(assertGithubCiRun({ run, jobs: { jobs: names.map((name) => ({ name, status: 'completed', conclusion: 'success' })) }, expectedCommit: fixture.commit, expectedTree: fixture.tree }).lanes, [...EXACT_CI_LANES]);
  assert.throws(() => assertGithubCiRun({ run: { ...run, head_sha: 'f'.repeat(40) }, jobs: { jobs: names.map((name) => ({ name, status: 'completed', conclusion: 'success' })) }, expectedCommit: fixture.commit, expectedTree: fixture.tree }), /expected source SHA/);
  assert.throws(() => assertGithubCiRun({ run: { ...run, event: 'pull_request' }, jobs: { jobs: names.map((name) => ({ name, status: 'completed', conclusion: 'success' })) }, expectedCommit: fixture.commit, expectedTree: fixture.tree }), /canonical main run/);
});

test('protected artifact secret scan is digest-bound and fail-closed', () => {
  const root = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-ci-preflight-'));
  const safe = join(root, 'safe.pkg');
  const secret = join(root, 'secret.pkg');
  fs.writeFileSync(safe, 'notarized package bytes\n');
  fs.writeFileSync(secret, '-----BEGIN PRIVATE KEY-----\n');
  const safeDigest = createHash('sha256').update(fs.readFileSync(safe)).digest('hex');
  assert.equal(assertProtectedArtifactSecretScan({ artifactPath: safe, expectedSha256: safeDigest }).status, 'passed');
  assert.throws(() => assertProtectedArtifactSecretScan({ artifactPath: secret, expectedSha256: createHash('sha256').update(fs.readFileSync(secret)).digest('hex') }), /secret scan found/);
  assert.throws(() => assertProtectedArtifactSecretScan({ artifactPath: safe, expectedSha256: 'f'.repeat(64) }), /digest is not manifest-bound/);
});

test('protected artifact directory scan rejects nested secrets and symlinks', () => {
  const root = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-ci-preflight-'));
  fs.mkdirSync(join(root, 'nested'));
  fs.writeFileSync(join(root, 'nested', 'report.json'), '{"ok":true}\n', { mode: 0o600 });
  assert.deepEqual(assertProtectedArtifactDirectory({ directory: root }), { status: 'passed', files: 1, bytes: 12 });
  fs.writeFileSync(join(root, 'nested', 'secret.txt'), 'ghp_123456789012345678901234567890\n', { mode: 0o600 });
  assert.throws(() => assertProtectedArtifactDirectory({ directory: root }), /secret scan found/);
  fs.unlinkSync(join(root, 'nested', 'secret.txt'));
  fs.symlinkSync(join(root, 'nested', 'report.json'), join(root, 'link'));
  assert.throws(() => assertProtectedArtifactDirectory({ directory: root }), /contains a symlink/);
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
