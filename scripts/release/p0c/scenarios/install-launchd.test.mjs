import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { performGatekeeperNotarization } from './gatekeeper-notarization';
import { performCleanInstallLaunchdXpc } from './clean-install-launchd-xpc';

const TEAM_ID = 'ABCDE12345';
const APP_PATH = '/Applications/AgentPass.app';
const CLIENT_BINARY = `${APP_PATH}/Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client`;
const SERVICE_BINARY = `${APP_PATH}/Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service`;
const CODE_IDENTITIES = [
  ['AgentPass.app', 'dev.agentpass'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', 'dev.agentpass.native-client'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', 'dev.agentpass.native-service'],
  ['AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', 'dev.agentpass.atomic-rename'],
  ['AgentPass.app/Contents/MacOS/agentpass-native-manager', 'dev.agentpass.native-manager'],
  ['AgentPass.app/Contents/MacOS/agentpass-onboarding', 'dev.agentpass']
].map(([identityPath, bundleId], index) => ({ path: identityPath, bundle_id: bundleId, team_id: TEAM_ID, code_directory_hash: String(index + 1).repeat(40) }));

const stat = (kind) => ({
  uid: 0,
  gid: 0,
  nlink: 1,
  mode: kind === 'file' ? 0o100755 : 0o40755,
  isDirectory: () => kind === 'directory',
  isFile: () => kind === 'file',
  isSymbolicLink: () => false,
});

const fakeFileSystem = (directories, files) => ({
  lstatSync(target) {
    if (directories.has(target)) return stat('directory');
    if (files.has(target)) return stat('file');
    throw new Error('not found');
  },
});

const release = (artifactPath = '/private/tmp/AgentPass.pkg') => ({ artifactPath, artifactSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), teamId: TEAM_ID, codeIdentities: CODE_IDENTITIES });
const machine = (nativeClientPath = CLIENT_BINARY) => ({
  applicationPath: APP_PATH,
  serviceLabel: 'dev.agentpass.native-service',
  checkpointDirectory: '/private/var/db/agentpass-qualification',
  executables: { native_client: { path: nativeClientPath, sha256: 'c'.repeat(64) } },
});

const successful = (extra = {}) => ({ ok: true, exitCode: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), ...extra });
const verifiedCheckpoint = async (_path, operation) => operation();

test('gatekeeper scenario injects fixed assessment, install, and post-install verification', async () => {
  const commands = [];
  const runCommand = async (command, args) => {
    commands.push([command, args]);
    if (command === '/usr/bin/codesign' && args[0] === '-dv') return successful({ stderr: Buffer.from(`TeamIdentifier=${TEAM_ID}\n`) });
    return successful();
  };
  const fileSystem = fakeFileSystem(new Set([APP_PATH]), new Set());
  let checkpointRequest;
  const result = await performGatekeeperNotarization({ release: release(), machine: machine(), production: false, getUid: () => 0, runCommand, fileSystem, readCodeIdentity: () => ({ designated_requirement: 'fixed requirement' }), mintCheckpoint: (request) => { checkpointRequest = request; } });
  assert.deepEqual(result, ['exact-pkg-install']);
  assert.equal(checkpointRequest.checkpoint_path, '/private/var/db/agentpass-qualification/candidate-checkpoint.json');
  assert.equal(checkpointRequest.code_objects.length, 6);
  assert.deepEqual(checkpointRequest.code_objects.map((item) => item.role).sort(), ['application', 'atomic-rename', 'native-client', 'native-manager', 'native-service', 'onboarding']);
  assert.deepEqual(commands, [
    ['/usr/sbin/spctl', ['--assess', '--type', 'install', '--verbose=4', '/private/tmp/AgentPass.pkg']],
    ['/usr/sbin/pkgutil', ['--check-signature', '/private/tmp/AgentPass.pkg']],
    ['/usr/bin/xcrun', ['stapler', 'validate', '/private/tmp/AgentPass.pkg']],
    ['/usr/sbin/installer', ['-pkg', '/private/tmp/AgentPass.pkg', '-target', '/']],
    ['/usr/bin/codesign', ['--verify', '--strict', '--verbose=2', APP_PATH]],
    ['/usr/bin/codesign', ['-dv', '--verbose=4', APP_PATH]],
  ]);
});

test('clean install scenario injects launchd, signatures, and both pinned XPC commands', async () => {
  const commands = [];
  const runCommand = async (command, args) => {
    commands.push([command, args]);
    if (command === '/usr/bin/codesign' && args[0] === '-dv') return successful({ stderr: Buffer.from(`TeamIdentifier=${TEAM_ID}\n`) });
    return successful();
  };
  const runPinned = async (entry, args) => {
    commands.push(['pinned', entry.path, args]);
    return successful();
  };
  const directories = new Set([
    APP_PATH,
    `${APP_PATH}/Contents/Library/HelperTools/AgentPassNativeClient.app`,
    `${APP_PATH}/Contents/Library/HelperTools/AgentPassNativeService.app`,
  ]);
  const files = new Set([CLIENT_BINARY, SERVICE_BINARY]);
  const result = await performCleanInstallLaunchdXpc({ release: release(), machine: machine(), production: false, getUid: () => 0, runCommand, runPinned, fileSystem: fakeFileSystem(directories, files), withCheckpoint: verifiedCheckpoint });
  assert.deepEqual(result, ['launchd-xpc-approval']);
  assert.deepEqual(commands[0], ['/bin/launchctl', ['print', 'system/dev.agentpass.native-service']]);
  assert.deepEqual(commands.at(-2), ['pinned', CLIENT_BINARY, ['--service', 'dev.agentpass.native-service', 'ping']]);
  assert.deepEqual(commands.at(-1), ['pinned', CLIENT_BINARY, ['--service', 'dev.agentpass.native-service', 'control-status']]);
});

test('physical scenario sources are fixed-path, root-gated, and cannot use a shell or local pass result', () => {
  const root = path.dirname(new URL(import.meta.url).pathname);
  for (const file of ['gatekeeper-notarization', 'clean-install-launchd-xpc']) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    assert.match(source, /^#!\/usr\/bin\/env node\n/u);
    assert.match(source, /scenario-runtime\.mjs/u);
    assert.match(source, /getUid\(\) !== 0/u);
    if (file === 'clean-install-launchd-xpc') assert.match(source, /runPinnedExecutable/u);
    assert.doesNotMatch(source, /child_process|exec\(|spawn\(|spawnSync\(|shell\s*:/u);
    assert.doesNotMatch(source, /console\.(log|error|warn)|process\.(stdout|stderr)\.write/u);
    assert.doesNotMatch(source, /status:\s*['"]passed['"]/u);
  }
});

test('dependency injection still rejects a non-root physical invocation', async () => {
  await assert.rejects(() => performGatekeeperNotarization({ release: release(), machine: machine(), production: false, getUid: () => 501 }), /requires root/u);
  await assert.rejects(() => performCleanInstallLaunchdXpc({ release: release(), machine: machine(), production: false, getUid: () => 501, withCheckpoint: verifiedCheckpoint }), /requires root/u);
});
