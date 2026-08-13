import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { performCrashRestartRecovery } from './crash-restart-recovery';

const TEAM_ID = 'ABCDE12345';
const release = { artifactSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), teamId: TEAM_ID };
const successful = (stdout = '') => ({ ok: true, exitCode: 0, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) });
const failedNative = (error = 'XPC connection invalidated') => ({ ok: false, exitCode: 1, signal: null, stdout: Buffer.from(`${JSON.stringify({ error, ok: false, public_key: null, stdout_base64: null, version: null })}\n`), stderr: Buffer.alloc(0) });
const nativeSuccess = () => successful(`${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: null, version: 13 })}\n`);
const verifiedCheckpoint = async (_path, operation) => operation();

const makeFixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-p0c-crash-restart-'));
  const checkpointDirectory = path.join(root, 'checkpoint');
  fs.mkdirSync(checkpointDirectory, { mode: 0o700 });
  return { root, checkpointDirectory };
};

const machine = (checkpointDirectory) => ({
  applicationPath: '/Applications/AgentPass.app',
  serviceLabel: 'dev.agentpass.native-service',
  checkpointDirectory,
  executables: { native_client: { path: '/private/agentpass-native-client', sha256: 'c'.repeat(64) } },
});

const launchctlPrint = (pid) => successful(`state = running\npid = ${pid}\n`);

const makeHarness = ({ bootIdentities = ['{ sec = 100, usec = 1 } Thu Aug 13 00:00:00 2026'], firstRefresh = failedNative() } = {}) => {
  const commands = [];
  const pinned = [];
  let pid = 100;
  let killed = 0;
  let bootIndex = 0;
  let refreshCount = 0;
  let releaseLostResponse;
  const runCommand = async (command, args) => {
    commands.push([command, args]);
    if (command === '/usr/sbin/sysctl') return successful(`${bootIdentities[Math.min(bootIndex, bootIdentities.length - 1)]}\n`);
    if (command === '/bin/launchctl' && args[0] === 'print') return launchctlPrint(pid);
    if (command === '/bin/launchctl' && args[0] === 'kill') {
      killed += 1;
      pid += 1;
      releaseLostResponse?.();
      return successful();
    }
    throw new Error(`unexpected command: ${command} ${args.join(' ')}`);
  };
  const runPinned = async (_entry, args) => {
    pinned.push(args);
    if (args.at(-1) === 'control-refresh') {
      refreshCount += 1;
      if (refreshCount % 2 === 1 && firstRefresh.ok !== true) {
        return new Promise((resolvePromise) => {
          releaseLostResponse = () => resolvePromise(firstRefresh);
        });
      }
      return nativeSuccess();
    }
    if (args.at(-1) === 'ping') return nativeSuccess();
    throw new Error(`unexpected pinned command: ${args.join(' ')}`);
  };
  const sleepFn = async () => {};
  return { commands, pinned, get killed() { return killed; }, get bootIndex() { return bootIndex; }, set bootIndex(value) { bootIndex = value; }, runCommand, runPinned, sleepFn };
};

test('crash/restart lane injects kill, lost-response retry, new PID, and boot observation without macOS', async () => {
  const fixture = makeFixture();
  const harness = makeHarness({ bootIdentities: ['{ sec = 100, usec = 1 } Thu Aug 13 00:00:00 2026', '{ sec = 200, usec = 2 } Thu Aug 13 01:00:00 2026'] });
  try {
    await assert.rejects(() => performCrashRestartRecovery({ release, machine: machine(fixture.checkpointDirectory), production: false, getUid: () => 0, runCommand: harness.runCommand, runPinned: harness.runPinned, sleepFn: harness.sleepFn, withCheckpoint: verifiedCheckpoint }), /OS reboot qualification is pending/u);
    assert.equal(harness.killed, 2);
    assert.deepEqual(harness.pinned.map((args) => args.at(-1)), ['ping', 'control-refresh', 'control-refresh', 'ping']);
    assert.deepEqual(harness.commands.filter(([command]) => command === '/bin/launchctl').map(([, args]) => args), [
      ['print', 'system/dev.agentpass.native-service'],
      ['print', 'system/dev.agentpass.native-service'],
      ['kill', 'SIGKILL', 'system/dev.agentpass.native-service'],
      ['print', 'system/dev.agentpass.native-service'],
      ['print', 'system/dev.agentpass.native-service'],
      ['kill', 'SIGKILL', 'system/dev.agentpass.native-service'],
      ['print', 'system/dev.agentpass.native-service'],
    ]);

    harness.bootIndex = 1;
    await assert.deepEqual(await performCrashRestartRecovery({ release, machine: machine(fixture.checkpointDirectory), production: false, getUid: () => 0, runCommand: harness.runCommand, runPinned: harness.runPinned, sleepFn: harness.sleepFn, withCheckpoint: verifiedCheckpoint }), ['service-crash-recovery', 'os-reboot-recovery']);
    assert.equal(fs.existsSync(path.join(fixture.checkpointDirectory, 'crash-restart-recovery.reboot.json')), false);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('reboot lane is fail-closed when boot identity is unchanged or the lost response is absent', async () => {
  const fixture = makeFixture();
  try {
    const unchanged = makeHarness();
    await assert.rejects(() => performCrashRestartRecovery({ release, machine: machine(fixture.checkpointDirectory), production: false, getUid: () => 0, runCommand: unchanged.runCommand, runPinned: unchanged.runPinned, sleepFn: unchanged.sleepFn, withCheckpoint: verifiedCheckpoint }), /OS reboot qualification is pending/u);
    await assert.rejects(() => performCrashRestartRecovery({ release, machine: machine(fixture.checkpointDirectory), production: false, getUid: () => 0, runCommand: unchanged.runCommand, runPinned: unchanged.runPinned, sleepFn: unchanged.sleepFn, withCheckpoint: verifiedCheckpoint }), /OS reboot was not mechanically observed/u);

    const noLostResponse = makeHarness({ firstRefresh: nativeSuccess() });
    await assert.rejects(() => performCrashRestartRecovery({ release, machine: machine(path.join(fixture.root, 'other-checkpoint')), production: false, getUid: () => 0, runCommand: noLostResponse.runCommand, runPinned: noLostResponse.runPinned, sleepFn: noLostResponse.sleepFn, withCheckpoint: verifiedCheckpoint }), /lost-response window was not mechanically observable/u);
    await assert.rejects(() => performCrashRestartRecovery({ release, machine: machine(fixture.checkpointDirectory), production: false, getUid: () => 501, runCommand: unchanged.runCommand, runPinned: unchanged.runPinned, sleepFn: unchanged.sleepFn, withCheckpoint: verifiedCheckpoint }), /requires root/u);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('scenario source has no shell escape, local pass result, or fabricated reboot evidence', () => {
  const source = fs.readFileSync(path.resolve('scripts/release/p0c/scenarios/crash-restart-recovery'), 'utf8');
  assert.match(source, /scenario-runtime\.mjs/u);
  assert.match(source, /launchctl.*kill|kill.*launchctl/su);
  assert.match(source, /kern\.boottime/u);
  assert.match(source, /OS reboot was not mechanically observed/u);
  assert.doesNotMatch(source, /child_process|spawn\(|spawnSync\(|shell\s*:/u);
  assert.doesNotMatch(source, /status:\s*['"]passed['"]/u);
});
