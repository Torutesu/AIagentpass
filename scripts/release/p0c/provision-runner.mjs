#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { basename, isAbsolute, join, resolve } from 'node:path';

const PRODUCTION_ROOT = '/opt/agentpass/p0c';
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
export const REQUIRED_GATES = Object.freeze([
  'audit-upload-observation', 'claude-code-unattended-sign', 'clean-install-launchd-xpc',
  'cloud-possession-verification', 'crash-restart-recovery', 'current-user-purge',
  'cursor-code-unattended-sign', 'gatekeeper-notarization', 'negative-identity-and-entitlement-cases',
  'offline-expiry', 'policy-reduction-refresh-ack', 'revoke-emergency-stop',
  'secure-enclave-enrollment', 'sleep-wake-network-clock', 'uninstall-reinstall-recovery',
  'upgrade-preserves-state'
]);

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const safeError = (value) => String(value).replace(/[^A-Za-z0-9 .,;:_()\/-]/gu, '?').slice(0, 200) || 'provisioning refused';

const protectedDirectory = (input, label, { ownerUid, exactEntries } = {}) => {
  if (typeof input !== 'string' || !isAbsolute(input)) throw new Error(`${label} must be an absolute path`);
  const path = resolve(input); let stat;
  try { stat = fs.lstatSync(path); } catch { throw new Error(`${label} is unavailable`); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (ownerUid !== undefined && stat.uid !== ownerUid)) throw new Error(`${label} is not protected`);
  if (exactEntries) {
    const entries = fs.readdirSync(path, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    if (entries.length !== exactEntries.length || entries.some((entry, index) => entry.name !== exactEntries[index] || !entry.isFile() || entry.isSymbolicLink())) throw new Error(`${label} does not contain the exact inventory`);
  }
  return path;
};

const readStableSource = (path, { executable = false, ownerUid } = {}) => {
  let descriptor;
  try { descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { throw new Error('provisioning source is unavailable'); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(MAX_SOURCE_BYTES) || (before.mode & 0o022n) !== 0n || (executable && (before.mode & 0o111n) === 0n) || (ownerUid !== undefined && before.uid !== BigInt(ownerUid))) throw new Error('provisioning source is unsafe');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset); if (count === 0) throw new Error('provisioning source changed'); offset += count; }
    const after = fs.fstatSync(descriptor, { bigint: true }); if (identity(before) !== identity(after)) throw new Error('provisioning source changed');
    return { bytes, sha256: sha256(bytes), identity: identity(after) };
  } finally { fs.closeSync(descriptor); }
};

export const inspectProvisioningSources = ({ sourceRoot, scenarioDirectory, production = true } = {}) => {
  const expectedSourceEntries = ['drivers', 'lib', 'provision-runner.mjs'];
  const sourceOwner = production ? 0 : undefined;
  const source = protectedDirectory(sourceRoot, 'P0-C source root', { ownerUid: sourceOwner });
  const actualSourceEntries = fs.readdirSync(source, { withFileTypes: true }).filter((entry) => !entry.name.endsWith('.test.mjs')).map((entry) => entry.name).sort();
  if (actualSourceEntries.length !== expectedSourceEntries.length || actualSourceEntries.some((name, index) => name !== expectedSourceEntries[index])) throw new Error('P0-C source root has unexpected production entries');
  const driverDirectory = protectedDirectory(join(source, 'drivers'), 'driver source directory', { ownerUid: sourceOwner });
  const driverEntries = fs.readdirSync(driverDirectory, { withFileTypes: true }).filter((entry) => !entry.name.endsWith('.test.mjs')).sort((a, b) => a.name.localeCompare(b.name));
  if (driverEntries.length !== REQUIRED_GATES.length || driverEntries.some((entry, index) => entry.name !== REQUIRED_GATES[index] || !entry.isFile() || entry.isSymbolicLink())) throw new Error('driver source inventory is invalid');
  const runtimeDirectory = protectedDirectory(join(source, 'lib'), 'runtime source directory', { ownerUid: sourceOwner, exactEntries: ['driver-runtime.mjs'] });
  const scenarios = protectedDirectory(scenarioDirectory, 'scenario source directory', { ownerUid: production ? 0 : undefined, exactEntries: REQUIRED_GATES });
  const drivers = REQUIRED_GATES.map((gate) => ({ gate, ...readStableSource(join(driverDirectory, gate), { executable: true, ownerUid: sourceOwner }) }));
  const scenarioFiles = REQUIRED_GATES.map((gate) => ({ gate, executable: gate, ...readStableSource(join(scenarios, gate), { executable: true, ownerUid: production ? 0 : undefined }) }));
  const runtime = readStableSource(join(runtimeDirectory, 'driver-runtime.mjs'), { ownerUid: sourceOwner });
  return { source, scenarios, drivers, scenarioFiles, runtime };
};

const writeInstalledFile = (path, bytes, mode, uid, gid) => {
  let descriptor;
  try {
    descriptor = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
    let offset = 0; while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset); fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, mode); fs.fchownSync(descriptor, uid, gid);
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
  const after = readStableSource(path, { executable: (mode & 0o111) !== 0, ownerUid: uid });
  if (after.sha256 !== sha256(bytes)) throw new Error('installed file verification failed');
};

const fsyncDirectory = (path) => { const descriptor = fs.openSync(path, fs.constants.O_RDONLY); try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); } };

const verifyInstalledTree = (root, expected, uid) => {
  protectedDirectory(join(root, 'gates'), 'installed gate directory', { ownerUid: uid, exactEntries: REQUIRED_GATES });
  protectedDirectory(join(root, 'lib'), 'installed runtime directory', { ownerUid: uid, exactEntries: ['driver-runtime.mjs'] });
  protectedDirectory(join(root, 'scenarios'), 'installed scenario directory', { ownerUid: uid, exactEntries: REQUIRED_GATES });
  const drivers = REQUIRED_GATES.map((gate) => readStableSource(join(root, 'gates', gate), { executable: true, ownerUid: uid }));
  const scenarios = REQUIRED_GATES.map((gate) => readStableSource(join(root, 'scenarios', gate), { executable: true, ownerUid: uid }));
  const runtime = readStableSource(join(root, 'lib', 'driver-runtime.mjs'), { ownerUid: uid });
  const config = readStableSource(join(root, 'driver-config.json'), { ownerUid: uid });
  if (drivers.some((item, index) => item.sha256 !== expected.drivers[index].sha256) || scenarios.some((item, index) => item.sha256 !== expected.scenarioFiles[index].sha256) || runtime.sha256 !== expected.runtime.sha256) throw new Error('installed inventory digest mismatch');
  return { drivers, scenarios, runtime, config };
};

export const provisionRunner = ({ sourceRoot, scenarioDirectory, destinationRoot = PRODUCTION_ROOT, platform = process.platform, uid = process.geteuid?.(), gid = 0, production = true } = {}) => {
  if (production && (platform !== 'darwin' || uid !== 0 || destinationRoot !== PRODUCTION_ROOT)) throw new Error('production provisioning requires root on macOS and the fixed destination');
  if (!production && destinationRoot === PRODUCTION_ROOT) throw new Error('non-production provisioning cannot write the production destination');
  if (!isAbsolute(destinationRoot) || basename(destinationRoot) !== 'p0c') throw new Error('destination root is invalid');
  const destination = resolve(destinationRoot); const parent = resolve(destination, '..');
  protectedDirectory(parent, 'destination parent', { ownerUid: uid });
  if (fs.existsSync(destination)) throw new Error('destination already exists; in-place replacement is forbidden');
  const inspected = inspectProvisioningSources({ sourceRoot, scenarioDirectory, production });
  const staging = join(parent, `.p0c-stage-${crypto.randomBytes(12).toString('hex')}`);
  try {
    fs.mkdirSync(staging, { mode: 0o700 }); fs.chownSync(staging, uid, gid);
    for (const directory of ['gates', 'lib', 'scenarios']) { const path = join(staging, directory); fs.mkdirSync(path, { mode: 0o755 }); fs.chownSync(path, uid, gid); }
    for (const item of inspected.drivers) writeInstalledFile(join(staging, 'gates', item.gate), item.bytes, 0o755, uid, gid);
    writeInstalledFile(join(staging, 'lib', 'driver-runtime.mjs'), inspected.runtime.bytes, 0o644, uid, gid);
    for (const item of inspected.scenarioFiles) writeInstalledFile(join(staging, 'scenarios', item.executable), item.bytes, 0o755, uid, gid);
    const config = { schema_version: 1, scenario_directory: join(destination, 'scenarios'), scenarios: inspected.scenarioFiles.map(({ gate, executable, sha256: digest }) => ({ gate, executable, sha256: digest })) };
    writeInstalledFile(join(staging, 'driver-config.json'), canonicalJSON(config), 0o644, uid, gid);
    fs.chmodSync(staging, 0o755); for (const directory of ['gates', 'lib', 'scenarios']) fsyncDirectory(join(staging, directory)); fsyncDirectory(staging);
    verifyInstalledTree(staging, inspected, uid);
    fs.renameSync(staging, destination); fsyncDirectory(parent);
    const installed = verifyInstalledTree(destination, inspected, uid);
    return Object.freeze({ production: production === true, destination, driver_count: installed.drivers.length, scenario_count: installed.scenarios.length, config_sha256: installed.config.sha256 });
  } catch (error) {
    if (fs.existsSync(staging)) fs.rmSync(staging, { recursive: true, force: false });
    throw error;
  }
};

const parseArgs = (args) => {
  const value = {}; for (let index = 0; index < args.length; index += 2) { const key = args[index]; const item = args[index + 1]; if (!['--source-root', '--scenarios'].includes(key) || !item || value[key]) throw new Error('invalid provisioning arguments'); value[key] = item; }
  if (Object.keys(value).length !== 2) throw new Error('usage: provision-runner.mjs --source-root ABSOLUTE_PATH --scenarios ABSOLUTE_PATH');
  return { sourceRoot: value['--source-root'], scenarioDirectory: value['--scenarios'] };
};

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.stdout.write(`${JSON.stringify(provisionRunner({ ...parseArgs(process.argv.slice(2)), production: true }))}\n`); }
  catch (error) { process.stderr.write(`P0-C provisioning refused: ${safeError(error.message)}\n`); process.exitCode = 1; }
}
