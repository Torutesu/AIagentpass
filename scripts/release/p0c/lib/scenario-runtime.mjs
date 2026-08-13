#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

const DEFAULT_CONFIG = '/opt/agentpass/p0c/scenario-config.json';
export const QUALIFICATION_GRANT_CLIENT_PATH = '/opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client';
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const CODE_HASH = /^[0-9a-f]{40,64}$/u;
const SAFE_NAME = /^[a-z0-9][a-z0-9-]{0,79}$/u;
const HTTPS_URL = /^https:\/\/[^\s/?#]+(?::\d{1,5})?(?:\/[^\s]*)?$/u;
const FIXED_ENV = Object.freeze({ HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
const REQUIRED_CODE_IDENTITIES = Object.freeze([
  Object.freeze({ path: 'AgentPass.app', bundle_id: 'dev.agentpass' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', bundle_id: 'dev.agentpass.native-client' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', bundle_id: 'dev.agentpass.native-service' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', bundle_id: 'dev.agentpass.atomic-rename' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-native-manager', bundle_id: 'dev.agentpass.native-manager' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-onboarding', bundle_id: 'dev.agentpass' })
]);

export const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const fileIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...keys].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`${label} has missing or unknown fields`);
};

export const readProtectedFile = (input, { maximum = MAX_CONFIG_BYTES, executable = false, production = true, expectedSha256 } = {}) => {
  if (typeof input !== 'string' || !isAbsolute(input)) throw new Error('protected file path must be absolute');
  const path = resolve(input); let descriptor;
  try { descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { throw new Error('protected file is unavailable'); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER) || (before.mode & 0o022n) !== 0n || (executable && (before.mode & 0o111n) === 0n) || (production && before.uid !== 0n)) throw new Error('protected file is unsafe');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset); if (count === 0) throw new Error('protected file changed while reading'); offset += count; }
    const after = fs.fstatSync(descriptor, { bigint: true }); if (fileIdentity(before) !== fileIdentity(after)) throw new Error('protected file changed while reading');
    const digest = sha256(bytes); if (expectedSha256 && digest !== expectedSha256) throw new Error('protected file digest mismatch');
    return Object.freeze({ path, bytes, sha256: digest, identity: fileIdentity(after) });
  } finally { fs.closeSync(descriptor); }
};

const validateExecutable = (value, label) => {
  exactKeys(value, ['path', 'sha256'], label);
  if (!isAbsolute(value.path) || !DIGEST.test(value.sha256)) throw new Error(`${label} is invalid`);
  return Object.freeze({ path: resolve(value.path), sha256: value.sha256 });
};

export const validateScenarioConfig = (value) => {
  exactKeys(value, ['schema_version', 'application_path', 'executables', 'service_label', 'service_config_path', 'test_repository', 'cloud_probe_url', 'checkpoint_directory'], 'scenario config');
  if (value.schema_version !== 1 || value.application_path !== '/Applications/AgentPass.app' || value.service_label !== 'dev.agentpass.native-service' || value.service_config_path !== '/Library/Application Support/AgentPass/native-service.json' || !isAbsolute(value.test_repository) || !HTTPS_URL.test(value.cloud_probe_url) || !isAbsolute(value.checkpoint_directory)) throw new Error('scenario config identity is invalid');
  exactKeys(value.executables, ['native_client', 'native_manager', 'native_service', 'claude_code', 'cursor', 'qualification_grant_client'], 'scenario executables');
  if (value.executables.qualification_grant_client?.path !== QUALIFICATION_GRANT_CLIENT_PATH) throw new Error('qualification grant client executable path is not fixed');
  return Object.freeze({
    schemaVersion: 1,
    applicationPath: value.application_path,
    serviceLabel: value.service_label,
    serviceConfigPath: value.service_config_path,
    testRepository: resolve(value.test_repository),
    cloudProbeURL: value.cloud_probe_url,
    checkpointDirectory: resolve(value.checkpoint_directory),
    executables: Object.freeze(Object.fromEntries(Object.entries(value.executables).map(([name, item]) => [name, validateExecutable(item, `${name} executable`)])))
  });
};

export const loadScenarioConfig = (path = DEFAULT_CONFIG, { production = process.platform === 'darwin' } = {}) => {
  const snapshot = readProtectedFile(path, { production }); let value;
  try { value = JSON.parse(snapshot.bytes.toString('utf8')); } catch { throw new Error('scenario config is invalid JSON'); }
  if (!snapshot.bytes.equals(canonicalJSON(value))) throw new Error('scenario config is not canonical JSON');
  return validateScenarioConfig(value);
};

export const releaseBindings = (env = process.env) => {
  const value = { artifactPath: env.AGENTPASS_P0C_ARTIFACT_PATH, artifactSha256: env.AGENTPASS_P0C_ARTIFACT_SHA256, sourceCommit: env.AGENTPASS_P0C_SOURCE_COMMIT, teamId: env.AGENTPASS_P0C_TEAM_ID, gate: env.AGENTPASS_P0C_GATE };
  let tests; let codeIdentities;
  try { tests = JSON.parse(env.AGENTPASS_P0C_TESTS_JSON ?? ''); codeIdentities = JSON.parse(env.AGENTPASS_P0C_CODE_IDENTITIES_JSON ?? ''); } catch { throw new Error('scenario release binding is invalid'); }
  if (!isAbsolute(value.artifactPath ?? '') || !DIGEST.test(value.artifactSha256 ?? '') || !COMMIT.test(value.sourceCommit ?? '') || !TEAM_ID.test(value.teamId ?? '') || !SAFE_NAME.test(value.gate ?? '') || !Array.isArray(tests) || tests.length === 0 || new Set(tests).size !== tests.length || tests.some((test) => !SAFE_NAME.test(test)) || !Array.isArray(codeIdentities) || codeIdentities.length !== REQUIRED_CODE_IDENTITIES.length) throw new Error('scenario release bindings are invalid');
  codeIdentities.forEach((identity, index) => {
    exactKeys(identity, ['path', 'bundle_id', 'team_id', 'code_directory_hash'], 'scenario code identity');
    const expected = REQUIRED_CODE_IDENTITIES[index];
    if (identity.path !== expected.path || identity.bundle_id !== expected.bundle_id || identity.team_id !== value.teamId || !CODE_HASH.test(identity.code_directory_hash)) throw new Error('scenario code identity binding is invalid');
  });
  readProtectedFile(value.artifactPath, { maximum: 16 * 1024 * 1024 * 1024, production: false, expectedSha256: value.artifactSha256 });
  return Object.freeze({ ...value, tests: Object.freeze([...tests]), codeIdentities: Object.freeze(codeIdentities.map((identity) => Object.freeze({ ...identity }))) });
};

const capture = (maximum) => ({ chunks: [], bytes: 0, exceeded: false, append(chunk) { const remaining = Math.max(0, maximum - this.bytes); const accepted = chunk.subarray(0, remaining); if (accepted.length) { this.chunks.push(Buffer.from(accepted)); this.bytes += accepted.length; } if (accepted.length !== chunk.length) this.exceeded = true; }, bytesValue() { return Buffer.concat(this.chunks, this.bytes); } });

export const runFixedCommand = (command, args = [], { timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = MAX_OUTPUT_BYTES, env = {}, cwd = '/', input } = {}) => new Promise((resolveResult) => {
  if (!isAbsolute(command) || !Array.isArray(args) || args.some((arg) => typeof arg !== 'string') || !isAbsolute(cwd) || Object.keys(env).some((key) => !/^AGENTPASS_P0C_[A-Z0-9_]+$/u.test(key)) || (input !== undefined && !Buffer.isBuffer(input))) throw new Error('fixed command request is invalid');
  const stdout = capture(maxOutputBytes); const stderr = capture(maxOutputBytes); let child; let timedOut = false; let settled = false;
  try { child = spawn(command, args, { cwd, env: { ...FIXED_ENV, ...env }, shell: false, stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] }); } catch { resolveResult({ ok: false, exitCode: null, signal: null, timedOut: false, outputLimit: false, spawnError: true, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }); return; }
  if (input) { child.stdin.end(input); }
  const stop = () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); };
  child.stdout.on('data', (chunk) => { stdout.append(chunk); if (stdout.exceeded) stop(); }); child.stderr.on('data', (chunk) => { stderr.append(chunk); if (stderr.exceeded) stop(); });
  const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
  const finish = (exitCode, signal, spawnError = false) => { if (settled) return; settled = true; clearTimeout(timer); const outputLimit = stdout.exceeded || stderr.exceeded; resolveResult({ ok: exitCode === 0 && !signal && !timedOut && !outputLimit && !spawnError, exitCode, signal, timedOut, outputLimit, spawnError, stdout: stdout.bytesValue(), stderr: stderr.bytesValue() }); };
  child.on('error', () => finish(null, null, true)); child.on('close', (code, signal) => finish(code, signal));
});

export const runPinnedExecutable = async (entry, args, options = {}) => {
  const before = readProtectedFile(entry.path, { maximum: 64 * 1024 * 1024, executable: true, production: options.production !== false, expectedSha256: entry.sha256 });
  const production = options.production !== false;
  const stagingRoot = resolve(options.executionStagingRoot ?? (production ? '/private/var/run' : os.tmpdir()));
  const rootStat = fs.lstatSync(stagingRoot, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || (rootStat.mode & 0o022n) !== 0n || (production && rootStat.uid !== 0n)) throw new Error('execution staging root is unsafe');
  const directory = fs.mkdtempSync(join(stagingRoot, 'agentpass-p0c-exec-'));
  const stagedPath = join(directory, 'verified-executable');
  try {
    fs.chmodSync(directory, 0o700);
    const descriptor = fs.openSync(stagedPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o500);
    try { fs.writeFileSync(descriptor, before.bytes); fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
    fs.chmodSync(stagedPath, 0o500);
    const stagedBefore = readProtectedFile(stagedPath, { maximum: 64 * 1024 * 1024, executable: true, production, expectedSha256: entry.sha256 });
    const result = await (options.runCommand ?? runFixedCommand)(stagedBefore.path, args, options);
    const stagedAfter = readProtectedFile(stagedPath, { maximum: 64 * 1024 * 1024, executable: true, production, expectedSha256: entry.sha256 });
    if (stagedBefore.identity !== stagedAfter.identity) throw new Error('staged executable changed during scenario');
    const after = readProtectedFile(entry.path, { maximum: 64 * 1024 * 1024, executable: true, production, expectedSha256: entry.sha256 });
    if (before.identity !== after.identity) throw new Error('pinned executable changed during scenario');
    return result;
  } finally {
    try { fs.unlinkSync(stagedPath); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
    fs.rmdirSync(directory);
  }
};

export const requireCommandSuccess = (result, label) => { if (!result?.ok) throw new Error(`${label} failed`); return result.stdout; };
export const parseJSONOutput = (bytes, label) => { let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error(`${label} returned invalid JSON`); } if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} returned invalid data`); return value; };

export const executePhysicalScenario = async ({ gate, tests, execute, config, bindings, production = process.platform === 'darwin', runCommand = runFixedCommand } = {}) => {
  if (production && process.platform !== 'darwin') throw new Error('physical scenarios require macOS');
  if (!SAFE_NAME.test(gate ?? '') || !Array.isArray(tests) || tests.length === 0 || typeof execute !== 'function') throw new Error('physical scenario declaration is invalid');
  const release = bindings ?? releaseBindings(); if (release.gate !== gate || JSON.stringify(release.tests) !== JSON.stringify(tests)) throw new Error('physical scenario declaration does not match release binding');
  const machine = config ?? loadScenarioConfig(undefined, { production });
  const passed = await execute(Object.freeze({ release, machine, production, runCommand }));
  if (!Array.isArray(passed) || passed.length !== tests.length || passed.some((name, index) => name !== tests[index])) throw new Error('physical scenario did not prove every assigned test');
  return { schema_version: 1, gate, status: 'passed', tests: tests.map((name) => ({ name, status: 'passed' })), bindings: { artifact_sha256: release.artifactSha256, source_commit: release.sourceCommit, team_id: release.teamId, code_identities_sha256: sha256(Buffer.from(JSON.stringify(release.codeIdentities))) } };
};

export const runPhysicalScenario = async (declaration) => {
  try { process.stdout.write(canonicalJSON(await executePhysicalScenario(declaration))); }
  catch { process.stderr.write('P0-C physical scenario refused\n'); process.exitCode = 1; }
};
