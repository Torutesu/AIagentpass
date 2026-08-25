import test from 'node:test';
import assert from 'node:assert/strict';
import { createDefaultAgentSigner } from './revoke-emergency-stop';

const machine = { testRepository: '/private/var/db/agentpass-qualification/repository', serviceLabel: 'dev.agentpass.native-service', executables: { native_client: { path: '/private/native-client' } } };
const session = { agent_id: '11111111-1111-4111-8111-111111111111', token: 't'.repeat(40) };
const ok = (stdout = '') => ({ ok: true, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) });

test('production default signer uses the pinned native client and real AgentPass Git path without signWithAgent DI', async () => {
  const commands = [];
  const runCommand = async (command, args, options) => { commands.push([command, args, options]); if (args.includes('hash-object')) return ok(`${'a'.repeat(64)}\n`); if (args.includes('rev-parse')) return ok(`${'b'.repeat(40)}\n`); if (args.includes('verify-commit')) return ok('GOOD ssh signature\n'); return ok(); };
  const runPinned = async (_entry, args) => { assert.deepEqual(args, ['--service', machine.serviceLabel, 'ping']); return ok(); };
  const signer = createDefaultAgentSigner({ machine, production: false, runCommand, runPinned, readSigner: () => ({ sha256: 'c'.repeat(64) }) });
  const result = await signer({ session, phase: 'baseline' });
  assert.equal(result.allowed, true);
  assert.equal(result.session, session.token);
  assert.ok(commands.some(([, args]) => args.includes('commit')));
  assert.ok(commands.some(([command, args, options]) => command === '/usr/bin/git' && !args.some((arg) => arg.includes(session.token)) && options?.sensitiveEnv?.AGENTPASS_SESSION === session.token));
});
