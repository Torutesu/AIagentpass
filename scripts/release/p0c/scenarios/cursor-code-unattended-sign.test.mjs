import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { performCursorCodeUnattendedSign } from './cursor-code-unattended-sign';

const REPOSITORY = '/private/var/db/agentpass-qualification/cursor-repository';
const HEAD = 'b'.repeat(40);
const TEAM = 'ABCDE12345';
const release = { artifactSha256: 'c'.repeat(64), sourceCommit: 'd'.repeat(40), teamId: TEAM };
const request = (overrides = {}) => ({ agent_id: '11111111-1111-4111-8111-111111111111', agent_kind: 'cursor', artifact_sha256: release.artifactSha256, batch_id: '22222222-2222-4222-8222-222222222222', candidate_checkpoint_sha256: 'e'.repeat(64), candidate_sha256: release.artifactSha256, device_id: '33333333-3333-4333-8333-333333333333', expires_at: '2099-08-14T00:00:00.000Z', kind: 'agentpass-n3e-qualification-relay-claim-request', organization_id: '44444444-4444-4444-8444-444444444444', release_trust_sha256: 'f'.repeat(64), request_id: '55555555-5555-4555-8555-555555555555', requested_ttl_seconds: 600, schema_version: 1, source_commit: release.sourceCommit, team_id: TEAM, ...overrides });
const machine = { applicationPath: '/Applications/AgentPass.app', serviceLabel: 'dev.agentpass.native-service', checkpointDirectory: '/private/var/db/agentpass-qualification/checkpoints', testRepository: REPOSITORY, executables: { native_client: { path: '/native-client', sha256: '1'.repeat(64) }, cursor: { path: '/opt/cursor-agent', sha256: '2'.repeat(64) }, qualification_grant_client: { path: '/opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client', sha256: '3'.repeat(64) } } };
const stat = () => ({ dev: 1n, ino: 2n, mode: 0o40700n, uid: 0n, gid: 0n, nlink: 2n, isDirectory: () => true, isFile: () => false, isSymbolicLink: () => false });
const ok = (stdout = '') => ({ ok: true, exitCode: 0, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) });
const envelope = (publicKey = 'ssh-ed25519 AAAAqualification') => ok(JSON.stringify({ error: null, ok: true, public_key: publicKey, stdout_base64: null, version: 13 }));

const harness = ({ requestValue = request(), unsigned = false, dirty = false, agentFailure = false } = {}) => {
  const calls = []; const pinned = [];
  const runCommand = async (command, args) => {
    calls.push([command, args]);
    if (command !== '/usr/bin/git') return ok();
    const index = args.indexOf('--get');
    if (index >= 0) {
      const values = { 'gpg.format': 'ssh', 'commit.gpgsign': 'true', 'gpg.ssh.program': '/Applications/AgentPass.app/Contents/Resources/bin/agentpass-git-sign', 'user.signingkey': 'ssh-ed25519 AAAAqualification', 'user.name': 'AgentPass P0-C Cursor', 'user.email': 'cursor-code@agentpass.invalid' };
      const value = values[args[index + 1]];
      return value === undefined ? { ok: false, exitCode: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) } : ok(value + '\n');
    }
    if (args.includes('--show-toplevel')) return ok(REPOSITORY + '\n');
    if (args.includes('--git-dir')) return ok(REPOSITORY + '/.git\n');
    if (args.includes('--verify')) return ok(HEAD + '\n');
    if (args.includes('status')) return ok(dirty ? ' M unexpected\n' : '');
    if (args.includes('remote')) return ok('');
    if (args.includes('verify-commit')) return unsigned ? { ...ok(''), ok: false, exitCode: 1 } : ok('Good "git" signature\n');
    if (args.includes('--format=%H%n%P%n%an%n%ae%n%T%n%s')) return ok(HEAD + '\n\nAgentPass P0-C Cursor\ncursor-code@agentpass.invalid\n' + 'a'.repeat(40) + '\nP0-C: unattended Cursor signing\n');
    if (args.includes('--name-only')) return ok('p0c-cursor-code-unattended-sign.marker\n');
    if (args.some((value) => value === HEAD + ':p0c-cursor-code-unattended-sign.marker')) return ok('agentpass:p0c:cursor-code:unattended-sign:v1\n');
    return ok();
  };
  const runPinned = async (entry, args) => {
    pinned.push({ path: entry.path, args });
    if (entry.path === '/opt/cursor-agent' && agentFailure) return { ...ok(), ok: false, exitCode: 1 };
    if (args.at(-1) === 'public-key') return envelope();
    return args.at(-1) === 'ping' ? envelope() : ok();
  };
  const fileSystem = { lstatSync: (value) => { if (value === '/private/var/db/agentpass-qualification/device-response.json') { const error = new Error('missing'); error.code = 'ENOENT'; throw error; } return stat(); }, realpathSync: (value) => value, unlinkSync: () => {} };
  return { calls, pinned, runCommand, runPinned, fileSystem, readRequest: () => requestValue, readResponseDigest: () => 'a'.repeat(64), pinSigner: () => ({ sha256: '9'.repeat(64) }) };
};
const checkpoint = async (_path, operation) => operation();

test('Cursor lane performs protected AgentPass claim, real noninteractive agent invocation, and independent Git verification', async () => {
  const h = harness();
  const result = await performCursorCodeUnattendedSign({ release, machine, production: false, getUid: () => 0, withCheckpoint: checkpoint, ...h });
  assert.deepEqual(result, ['cursor-code-unattended-sign']);
  assert.equal(h.pinned[0].args.at(-1), 'ping');
  assert.equal(h.pinned[1].args.at(-1), 'public-key');
  assert.deepEqual(h.pinned[2].args, []);
  assert.equal(h.pinned[3].args.at(-1), '--force');
  assert.match(h.pinned[3].args[1], /p0c-cursor-code-unattended-sign\.marker/u);
  assert.ok(h.calls.some(([, args]) => args.includes('gpg.ssh.program')));
});

test('Cursor lane rejects root, candidate, agent, signature, and working-tree failures', async () => {
  const cases = [
    [{ getUid: () => 501 }, /requires root/u],
    [{ readRequest: () => request({ source_commit: 'a'.repeat(40) }) }, /another release/u],
    [{ agentFailure: true }, /physical command failed/u],
    [{ unsigned: true }, /physical command failed|signature/u],
    [{ dirty: true }, /working tree/u],
  ];
  for (const [overrides, pattern] of cases) {
    const h = harness(overrides);
    await assert.rejects(() => performCursorCodeUnattendedSign({ release, machine, production: false, withCheckpoint: checkpoint, getUid: () => 0, ...h, ...overrides }), pattern);
  }
});

test('Cursor source contains fixed unattended controls and no manual or shell fallback', () => {
  const source = fs.readFileSync(path.resolve('scripts/release/p0c/scenarios/cursor-code-unattended-sign'), 'utf8');
  assert.match(source, /runPinnedExecutable/u);
  assert.match(source, /--force/u);
  assert.match(source, /gpg\.ssh\.program/u);
  assert.doesNotMatch(source, /child_process|spawn\(|spawnSync\(|shell\s*:/u);
  assert.doesNotMatch(source, /security\s+unlock|osascript|open\s+-a|readline/u);
  assert.doesNotMatch(source, /status:\s*['"]passed['"]/u);
});
