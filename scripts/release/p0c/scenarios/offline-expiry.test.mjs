import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { performOfflineExpiry } from './offline-expiry';

const release = { artifactSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), teamId: 'ABCDE12345' };
const machine = (checkpointDirectory) => ({ applicationPath: '/Applications/AgentPass.app', serviceLabel: 'dev.agentpass.native-service', checkpointDirectory, executables: { native_client: { path: '/private/native-client', sha256: 'c'.repeat(64) } } });
const status = (expired = false) => ({ configured: true, device_auth_public_key: null, device_revoked: false, expired, format_epoch: 2, global_revoked: false, refresh_configured: true, refresh_consecutive_failures: 0, refresh_generation: 1, refresh_in_flight: false, refresh_last_attempt_at: null, refresh_last_error: null, refresh_last_success_at: null, refresh_next_attempt_at: null, refresh_sequence: 4, refresh_source_url: null, refresh_state: 'idle', revoked_agents: [], revoked_capabilities: [], sequence: 4, operational: !expired });
const envelope = (payload, ok = true) => ({ ok, exitCode: ok ? 0 : 1, stdout: Buffer.from(`${JSON.stringify({ error: ok ? null : 'control_expired', ok, public_key: null, stdout_base64: ok ? Buffer.from(payload).toString('base64') : null, version: 13 })}\n`), stderr: Buffer.alloc(0) });
const f = () => { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-p0c-offline-')); fs.mkdirSync(path.join(root, 'checkpoint')); return { root, checkpointDirectory: path.join(root, 'checkpoint') }; };

test('offline expiry disables network, observes native expiry, restores, and recovers without widening', async () => {
  const fixture = f(); let network = true; let expiredObserved = false; let signCount = 0;
  const runPinned = async (_entry, args) => {
    if (args.at(-1) === 'control-status') return envelope(JSON.stringify(expiredObserved ? status(true) : status(false)));
    if (args.at(-1) === 'control-refresh') {
      expiredObserved = false;
      const payload = { ...status(false), refreshed: true };
      return { ...envelope(''), stdout: Buffer.from(`${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: Buffer.from(JSON.stringify(payload)).toString('base64'), version: 13 })}\n`) };
    }
    signCount += 1;
    return signCount === 1 || signCount === 3 ? envelope('signature') : envelope('', false);
  };
  try {
    assert.deepEqual(await performOfflineExpiry({ release, machine: machine(fixture.checkpointDirectory), production: false, getUid: () => 0, signingRequest: Buffer.from('request'), runPinned, networkControl: async (enabled) => { network = enabled; if (!enabled) expiredObserved = true; }, clock: () => 0, waitFn: async () => {}, withCheckpoint: async (_path, operation) => operation() }), ['offline-expiry-denied']);
    assert.equal(network, true);
    assert.equal(signCount, 3);
  } finally { fs.rmSync(fixture.root, { recursive: true, force: true }); }
});

test('offline expiry restores the network even when the boundary proof fails', async () => {
  const fixture = f(); let restores = 0;
  const runPinned = async (_entry, args) => {
    if (args.at(-1) === 'control-status') return envelope(JSON.stringify(status(false)));
    if (args.at(-1) === 'control-refresh') {
      const payload = { ...status(false), refreshed: true };
      return { ...envelope(''), stdout: Buffer.from(`${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: Buffer.from(JSON.stringify(payload)).toString('base64'), version: 13 })}\n`) };
    }
    return envelope('signature');
  };
  try { await assert.rejects(() => performOfflineExpiry({ release, machine: machine(fixture.checkpointDirectory), production: false, getUid: () => 0, signingRequest: Buffer.from('request'), runPinned, networkControl: async (enabled) => { if (enabled) restores += 1; else throw new Error('network boundary failed'); }, withCheckpoint: async (_path, operation) => operation() }), /network boundary failed/u); assert.equal(restores, 1); } finally { fs.rmSync(fixture.root, { recursive: true, force: true }); }
});
