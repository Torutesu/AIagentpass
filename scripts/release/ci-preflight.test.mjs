import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertCandidateBinding, assertCleanCheckout, assertExternalGates, assertExternalQualificationEvidence, assertGithubArtifacts, assertGithubCiRun, assertGithubCommit, assertGithubWorkflowEvidence, assertProtectedArtifactDirectory, assertProtectedArtifactSecretScan, assertSourceBinding, assertTerminalResults, assertWorkflowBoundary, EXACT_CI_LANES, parseArguments, scanReleaseArtifacts } from './ci-preflight.mjs';

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

test('candidate binding rejects path escape and linked product artifacts', () => {
  const fixture = candidate();
  const { manifestPath, manifest, artifactName } = writeManifest(fixture);
  manifest.artifacts[0].name = '../outside.pkg';
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.throws(() => assertCandidateBinding({ repoRoot: fixture.root, manifestPath, expectedCommit: fixture.commit, expectedTree: fixture.tree }), /safe product artifact/);

  const linkedFixture = candidate();
  const linked = writeManifest(linkedFixture);
  fs.unlinkSync(join(linkedFixture.root, artifactName));
  fs.symlinkSync(join(linkedFixture.root, 'source.txt'), join(linkedFixture.root, artifactName));
  assert.throws(() => assertCandidateBinding({ repoRoot: linkedFixture.root, manifestPath: linked.manifestPath, expectedCommit: linkedFixture.commit, expectedTree: linkedFixture.tree }), /regular, non-linked/);
});

const terminalResults = (commit, overrides = {}) => EXACT_CI_LANES.map((lane, index) => ({
  lane,
  terminal_result: 'passed',
  head_sha: commit,
  run_id: '101',
  job_id: String(201 + index),
  run_attempt: '1',
  job_status: 'completed',
  job_conclusion: 'success',
  repository: 'Torutesu/AIagentpass',
  workflow: { id: '2', name: 'CI', path: '.github/workflows/ci.yml' },
  ...overrides[lane],
}));

test('exact-SHA qualification requires all six terminal CI lanes and one workflow tree', () => {
  const fixture = candidate();
  assert.deepEqual(assertTerminalResults(terminalResults(fixture.commit), {
    expectedSha: fixture.commit, expectedRunId: '101', expectedRunAttempt: '1', expectedRepository: 'Torutesu/AIagentpass', expectedWorkflow: { id: '2', name: 'CI', path: '.github/workflows/ci.yml' }
  }).map((result) => result.lane), [...EXACT_CI_LANES]);
  assert.throws(() => assertTerminalResults(terminalResults(fixture.commit).slice(0, 5), { expectedSha: fixture.commit, expectedRunId: '101' }), /exactly six lanes/);
  assert.throws(() => assertTerminalResults(terminalResults(fixture.commit, { test: { head_sha: 'f'.repeat(40) } }), { expectedSha: fixture.commit, expectedRunId: '101' }), /expected source SHA/);
  assert.throws(() => assertTerminalResults([...terminalResults(fixture.commit).slice(0, 5), { ...terminalResults(fixture.commit)[0] }], { expectedSha: fixture.commit, expectedRunId: '101' }), /exact, unique, and canonical/);
  assert.throws(() => assertTerminalResults(terminalResults(fixture.commit, { test: { job_conclusion: 'failure' } }), { expectedSha: fixture.commit, expectedRunId: '101' }), /not successful/);
});

test('GitHub CI API qualification maps the protected six jobs and rejects a different run', () => {
  const fixture = candidate();
  const run = {
    id: 101, run_attempt: 1, repository: { id: 1, full_name: 'Torutesu/AIagentpass' },
    head_repository: { id: 1, full_name: 'Torutesu/AIagentpass' }, workflow_id: 2,
    name: 'CI', path: '.github/workflows/ci.yml', status: 'completed', conclusion: 'success', event: 'push',
    head_branch: 'main', head_sha: fixture.commit
  };
  const names = ['PostgreSQL 16 authority qualification', 'PostgreSQL 17 authority qualification', 'postgres-integration', 'browser-e2e', 'p0b-live-process', 'test'];
  const jobs = names.map((name, index) => ({ id: 201 + index, run_id: 101, run_attempt: 1, head_sha: fixture.commit, status: 'completed', conclusion: 'success', workflow_name: 'CI', name }));
  assert.deepEqual(assertGithubCiRun(run, jobs, { expectedSha: fixture.commit, expectedRunId: '101', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length }).terminal_results.map((result) => result.lane), [...EXACT_CI_LANES]);
  assert.throws(() => assertGithubCiRun({ ...run, head_sha: 'f'.repeat(40) }, jobs, { expectedSha: fixture.commit, expectedRunId: '101', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length }), /source SHA/);
  assert.throws(() => assertGithubCiRun({ ...run, event: 'pull_request' }, jobs, { expectedSha: fixture.commit, expectedRunId: '101', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length }), /identity or terminal state/);
});

test('GitHub CI API qualification requires the complete run, attempt, job, and source binding', () => {
  const fixture = candidate();
  const names = ['PostgreSQL 16 authority qualification', 'PostgreSQL 17 authority qualification', 'postgres-integration', 'browser-e2e', 'p0b-live-process', 'test'];
  const run = {
    id: 101, run_attempt: 2, repository: { id: 1, full_name: 'Torutesu/AIagentpass' },
    head_repository: { id: 1, full_name: 'Torutesu/AIagentpass' }, workflow_id: 2,
    name: 'CI', path: '.github/workflows/ci.yml', status: 'completed', conclusion: 'success', event: 'push',
    head_branch: 'main', head_sha: fixture.commit
  };
  const jobs = names.map((name, index) => ({
    id: 201 + index, run_id: 101, run_attempt: 2, head_sha: fixture.commit,
    status: 'completed', conclusion: 'success', workflow_name: 'CI', name
  }));
  const result = assertGithubCiRun(run, jobs, {
    expectedSha: fixture.commit, expectedRunId: '101', expectedRunAttempt: '2', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length
  });
  assert.equal(result.run_attempt, '2');
  assert.equal(result.terminal_results.every((lane) => lane.run_id === '101' && lane.run_attempt === '2' && lane.head_sha === fixture.commit), true);
  assert.throws(() => assertGithubCiRun(run, jobs.map(({ run_id: _runId, ...job }) => job), {
    expectedSha: fixture.commit, expectedRunId: '101', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length
  }), /run ID|binding|invalid/u);
  assert.throws(() => assertGithubCiRun(run, jobs.map((job, index) => index === 0 ? { ...job, head_sha: 'f'.repeat(40) } : job), {
    expectedSha: fixture.commit, expectedRunId: '101', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length
  }), /source-bound|source SHA/u);
  assert.throws(() => assertGithubCiRun({ ...run, run_attempt: 3 }, jobs, {
    expectedSha: fixture.commit, expectedRunId: '101', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length
  }), /run attempt|selected run/u);
  assert.throws(() => assertGithubCiRun(run, jobs, {
    expectedSha: fixture.commit, expectedRunId: '101', expectedRunAttempt: '3', repository: 'Torutesu/AIagentpass', jobsTotalCount: jobs.length
  }), /run attempt/u);
});

test('GitHub workflow evidence requires exact artifact inventory and independently bound source tree', () => {
  const fixture = candidate();
  const run = {
    id: 101, run_attempt: 1, repository: { id: 1, full_name: 'Torutesu/AIagentpass' },
    head_repository: { id: 1, full_name: 'Torutesu/AIagentpass' }, workflow_id: 2,
    name: 'Release candidate', path: '.github/workflows/release-candidate.yml', status: 'completed', conclusion: 'success', event: 'workflow_dispatch',
    head_branch: 'main', head_sha: fixture.commit
  };
  const jobs = [{ id: 201, run_id: 101, run_attempt: 1, head_sha: fixture.commit, status: 'completed', conclusion: 'success', workflow_name: 'Release candidate', name: 'build' }];
  const artifact = {
    id: 301, name: 'notarized-release-candidate', digest: `sha256:${'c'.repeat(64)}`, expired: false,
    workflow_run: {
      id: 101, repository_id: 1, head_repository_id: 1, workflow_id: 2, run_attempt: 1,
      head_sha: fixture.commit, head_branch: 'main', event: 'workflow_dispatch', status: 'completed', conclusion: 'success'
    }
  };
  const options = {
    repository: 'Torutesu/AIagentpass', workflowName: 'Release candidate', workflowPath: '.github/workflows/release-candidate.yml',
    expectedEvent: 'workflow_dispatch', expectedRunId: '101', expectedSha: fixture.commit,
    expectedJobNames: ['build'], expectedArtifactNames: ['notarized-release-candidate']
  };
  const evidence = assertGithubWorkflowEvidence(run, { total_count: 1, jobs }, { total_count: 1, artifacts: [artifact] }, options);
  assert.deepEqual(evidence.artifacts.map((item) => item.name), ['notarized-release-candidate']);
  assert.deepEqual(assertGithubArtifacts({ total_count: 1, artifacts: [artifact] }, evidence, { artifactTotalCount: 1, expectedArtifactNames: ['notarized-release-candidate'] }).map((item) => item.name), ['notarized-release-candidate']);
  assert.throws(() => assertGithubWorkflowEvidence(run, { total_count: 1, jobs }, { total_count: 1, artifacts: [] }, options), /artifact inventory is not exact|incomplete/u);
  assert.throws(() => assertGithubWorkflowEvidence(run, { total_count: 1, jobs }, { total_count: 1, artifacts: [{ ...artifact, workflow_run: { ...artifact.workflow_run, head_sha: 'f'.repeat(40) } }] }, options), /not bound to the selected workflow run/u);
  assert.deepEqual(assertGithubCommit({ sha: fixture.commit, commit: { tree: { sha: fixture.tree } } }, { repository: 'Torutesu/AIagentpass', expectedSha: fixture.commit }), { repository: 'Torutesu/AIagentpass', commit_sha: fixture.commit, tree_sha: fixture.tree });
  assert.throws(() => assertGithubCommit({ sha: fixture.commit, commit: { tree: { sha: 'not-a-tree' } } }, { repository: 'Torutesu/AIagentpass', expectedSha: fixture.commit }), /source or tree/u);
  assert.deepEqual(assertSourceBinding({ releaseHeadSha: fixture.commit, qualificationHeadSha: fixture.commit, ciHeadSha: fixture.commit, manifestSourceCommit: fixture.commit, manifestSourceTree: fixture.tree, independentTreeSha: fixture.tree }), { source_commit: fixture.commit, source_tree: fixture.tree });
  assert.throws(() => assertSourceBinding({ releaseHeadSha: fixture.commit, qualificationHeadSha: fixture.commit, ciHeadSha: fixture.commit, manifestSourceCommit: fixture.commit, manifestSourceTree: fixture.tree, independentTreeSha: 'f'.repeat(40) }), /independent GitHub tree/u);
});

test('release artifact scan returns digest inventory and rejects links or unsupported opaque archives', () => {
  const root = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-release-scan-'));
  fs.mkdirSync(join(root, 'evidence'));
  fs.writeFileSync(join(root, 'manifest.json'), '{"ok":true}\n', { mode: 0o600 });
  fs.writeFileSync(join(root, 'evidence', 'report.json'), '{"status":"passed"}\n', { mode: 0o600 });
  const result = scanReleaseArtifacts(root);
  assert.equal(result.clean, true);
  assert.deepEqual(result.files.map((file) => file.path), ['evidence/report.json', 'manifest.json']);
  assert.equal(result.files.every((file) => /^[0-9a-f]{64}$/u.test(file.sha256) && file.bytes > 0), true);

  fs.symlinkSync(join(root, 'manifest.json'), join(root, 'linked.json'));
  assert.throws(() => scanReleaseArtifacts(root), /unsupported entry: linked\.json/u);
  fs.unlinkSync(join(root, 'linked.json'));
  fs.writeFileSync(join(root, 'opaque.zip'), 'archive placeholder\n', { mode: 0o600 });
  assert.throws(() => scanReleaseArtifacts(root), /dedicated scanner: opaque\.zip/u);
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

test('external qualification contract rejects embedded not_proven markers and oversized run attempts', () => {
  const binding = {
    expectedRepository: 'Torutesu/AIagentpass',
    expectedSourceCommit: 'a'.repeat(40),
    expectedSourceTree: 'b'.repeat(40),
    expectedReleaseArtifactSha256: 'c'.repeat(64),
    expectedCiRunId: '42',
    expectedCiRunAttempt: '3'
  };
  assert.throws(() => assertExternalQualificationEvidence({ not_proven: true }, binding), /contains not_proven/);
  assert.throws(() => assertExternalQualificationEvidence({}, { ...binding, expectedCiRunAttempt: '1234567' }), /expectations are incomplete or invalid/);
});

test('argument parser is explicit and fail-closed', () => {
  assert.deepEqual(parseArguments(['--event-name', 'workflow_dispatch', '--gate-file', 'a.json', '--gate-file', 'b.json', '--require', 'qualified=true', '--require', 'mode=hardware']), {
    eventName: 'workflow_dispatch', gateFiles: ['a.json', 'b.json'], required: { qualified: true, mode: 'hardware' }
  });
  assert.throws(() => parseArguments(['--event-name']), /requires a value/);
  assert.throws(() => parseArguments(['--unknown', 'value']), /unknown argument/);
  assert.throws(() => parseArguments(['--require', 'qualified']), /requires key=value/);
});
