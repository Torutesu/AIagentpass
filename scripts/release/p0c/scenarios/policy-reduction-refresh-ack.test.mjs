import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { performPolicyReductionRefreshAck } from './policy-reduction-refresh-ack';

const release = { artifactSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), teamId: 'ABCDE12345' };
const machine = (checkpointDirectory) => ({ applicationPath: '/Applications/AgentPass.app', serviceLabel: 'dev.agentpass.native-service', checkpointDirectory, executables: { native_client: { path: '/private/native-client', sha256: 'c'.repeat(64) } } });
const status = (sequence, generation) => ({ configured: true, device_auth_public_key: null, device_revoked: false, expired: false, format_epoch: 2, global_revoked: false, refresh_configured: true, refresh_consecutive_failures: 0, refresh_generation: generation, refresh_in_flight: false, refresh_last_attempt_at: null, refresh_last_error: null, refresh_last_success_at: null, refresh_next_attempt_at: null, refresh_sequence: sequence, refresh_source_url: null, refresh_state: 'idle', revoked_agents: [], revoked_capabilities: [], sequence, operational: true });
const envelope = (payload, ok = true) => ({ ok, exitCode: ok ? 0 : 1, stdout: Buffer.from(`${JSON.stringify({ error: ok ? null : 'control_policy_scope_denied', ok, public_key: null, stdout_base64: ok ? Buffer.from(payload).toString('base64') : null, version: 13 })}\n`), stderr: Buffer.alloc(0) });
const fixture = () => { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-p0c-policy-')); fs.mkdirSync(path.join(root, 'checkpoint')); return { root, checkpointDirectory: path.join(root, 'checkpoint') }; };

test('policy reduction requires an actual baseline signature, converged refresh, and denial', async () => {
  const f = fixture(); const calls = []; let signCount = 0; let refreshed = false;
  const runPinned = async (_entry, args) => {
    calls.push(args);
    if (args.at(-1) === 'control-status') return envelope(JSON.stringify(refreshed ? status(5, 2) : status(4, 1)));
    if (args.at(-1) === 'control-refresh') {
      refreshed = true;
      const payload = { ...status(5, 2), refreshed: true };
      return { ...envelope(''), stdout: Buffer.from(`${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: Buffer.from(JSON.stringify(payload)).toString('base64'), version: 13 })}\n`) };
    }
    signCount += 1;
    return signCount === 1 ? envelope('signature') : envelope('', false);
  };
  try {
    assert.deepEqual(await performPolicyReductionRefreshAck({ release, machine: machine(f.checkpointDirectory), production: false, getUid: () => 0, signingRequest: Buffer.from('request'), runPinned, probeOperation: async ({ phase }) => phase === 'baseline' ? 'allowed' : 'denied', withCheckpoint: async (_path, operation) => operation() }), ['policy-reduction-denied']);
    assert.equal(signCount, 2);
    assert.ok(calls.some((args) => args.at(-1) === 'control-refresh'));
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('policy reduction fails closed when the refresh generation is stale', async () => {
  const f = fixture(); const runPinned = async (_entry, args) => args.at(-1) === 'control-status' ? envelope(JSON.stringify(status(4, 1))) : args.at(-1) === 'control-refresh' ? { ...envelope(''), stdout: Buffer.from(`${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: Buffer.from(JSON.stringify({ ...status(4, 1), refreshed: true })).toString('base64'), version: 13 })}\n`) } : envelope('signature');
  try { await assert.rejects(() => performPolicyReductionRefreshAck({ release, machine: machine(f.checkpointDirectory), production: false, getUid: () => 0, signingRequest: Buffer.from('request'), runPinned, withCheckpoint: async (_path, operation) => operation() }), /generation|converge/u); } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});
