#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { basename, isAbsolute, join, resolve } from 'node:path';

const DEFAULT_CONFIG = '/opt/agentpass/p0c/driver-config.json';
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const SAFE_NAME = /^[a-z0-9][a-z0-9-]{0,79}$/u;
const CODE_HASH = /^[0-9a-f]{40,64}$/u;
const BASE_ENV = Object.freeze({ HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
const REQUIRED_CODE_IDENTITIES = Object.freeze([
  Object.freeze({ path: 'AgentPass.app', bundle_id: 'dev.agentpass' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', bundle_id: 'dev.agentpass.native-client' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', bundle_id: 'dev.agentpass.native-service' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', bundle_id: 'dev.agentpass.atomic-rename' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-native-manager', bundle_id: 'dev.agentpass.native-manager' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-onboarding', bundle_id: 'dev.agentpass' })
]);
const REQUIRED_GATES = Object.freeze([
  'audit-upload-observation', 'claude-code-unattended-sign', 'clean-install-launchd-xpc',
  'cloud-possession-verification', 'crash-restart-recovery', 'current-user-purge',
  'cursor-code-unattended-sign', 'gatekeeper-notarization', 'negative-identity-and-entitlement-cases',
  'offline-expiry', 'policy-reduction-refresh-ack', 'revoke-emergency-stop',
  'secure-enclave-enrollment', 'sleep-wake-network-clock', 'uninstall-reinstall-recovery',
  'upgrade-preserves-state'
]);

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const exactKeys = (value, expected, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`${label} has missing or unknown fields`);
};

const readProtectedFile = (input, { maximum, executable = false, production = true, expectedSha256 } = {}) => {
  if (typeof input !== 'string' || !isAbsolute(input)) throw new Error('protected path must be absolute');
  const path = resolve(input); let descriptor;
  try { descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { throw new Error('protected file is unavailable'); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('protected file is unsafe');
    if ((before.mode & 0o022n) !== 0n || (executable && (before.mode & 0o111n) === 0n) || (production && before.uid !== 0n)) throw new Error('protected file permissions are unsafe');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset); if (count === 0) throw new Error('protected file changed while reading'); offset += count; }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const identity = (item) => [item.dev, item.ino, item.mode, item.nlink, item.size, item.mtimeNs, item.ctimeNs].join(':');
    if (identity(before) !== identity(after)) throw new Error('protected file changed while reading');
    const digest = sha256(bytes); if (expectedSha256 && digest !== expectedSha256) throw new Error('protected executable digest mismatch');
    return { path, bytes, sha256: digest, identity: identity(after) };
  } finally { fs.closeSync(descriptor); }
};

export const validateDriverConfig = (value, { production = true } = {}) => {
  exactKeys(value, ['schema_version', 'scenario_directory', 'scenarios'], 'driver config');
  if (value.schema_version !== 1 || !isAbsolute(value.scenario_directory)) throw new Error('driver config identity is invalid');
  const scenarioDirectory = resolve(value.scenario_directory);
  let directoryStat; try { directoryStat = fs.lstatSync(scenarioDirectory); } catch { throw new Error('scenario directory is unavailable'); }
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || (directoryStat.mode & 0o022) !== 0 || (production && directoryStat.uid !== 0)) throw new Error('scenario directory permissions are unsafe');
  if (!Array.isArray(value.scenarios) || value.scenarios.length !== 16) throw new Error('driver config must bind exactly 16 scenarios');
  const scenarios = new Map(); let previous = '';
  for (const item of value.scenarios) {
    exactKeys(item, ['gate', 'executable', 'sha256'], 'driver scenario');
    if (!SAFE_NAME.test(item.gate) || item.gate <= previous || basename(item.executable) !== item.executable || !SAFE_NAME.test(item.executable) || !DIGEST.test(item.sha256) || scenarios.has(item.gate)) throw new Error('driver scenarios are invalid or unsorted');
    previous = item.gate; scenarios.set(item.gate, { ...item, path: join(scenarioDirectory, item.executable) });
  }
  if ([...scenarios.keys()].some((gate, index) => gate !== REQUIRED_GATES[index])) throw new Error('driver config does not bind the exact gate inventory');
  return { production, scenarioDirectory, scenarios };
};

export const loadDriverConfig = (path = process.env.AGENTPASS_P0C_DRIVER_CONFIG || DEFAULT_CONFIG, { production = process.platform === 'darwin' } = {}) => {
  const snapshot = readProtectedFile(path, { maximum: MAX_CONFIG_BYTES, production }); let value;
  try { value = JSON.parse(snapshot.bytes.toString('utf8')); } catch { throw new Error('driver config is not valid JSON'); }
  if (!snapshot.bytes.equals(canonicalJSON(value))) throw new Error('driver config is not canonical JSON');
  return validateDriverConfig(value, { production });
};

export const validateReleaseBindings = (env = process.env) => {
  const artifactPath = env.AGENTPASS_P0C_ARTIFACT_PATH;
  const artifactSha256 = env.AGENTPASS_P0C_ARTIFACT_SHA256;
  const sourceCommit = env.AGENTPASS_P0C_SOURCE_COMMIT;
  const teamId = env.AGENTPASS_P0C_TEAM_ID;
  let codeIdentities;
  try { codeIdentities = JSON.parse(env.AGENTPASS_P0C_CODE_IDENTITIES_JSON ?? ''); } catch { throw new Error('release code identity binding is invalid'); }
  if (!isAbsolute(artifactPath ?? '') || !DIGEST.test(artifactSha256 ?? '') || !COMMIT.test(sourceCommit ?? '') || !TEAM_ID.test(teamId ?? '') || !Array.isArray(codeIdentities) || codeIdentities.length !== REQUIRED_CODE_IDENTITIES.length) throw new Error('release bindings are missing or invalid');
  codeIdentities.forEach((identity, index) => {
    exactKeys(identity, ['path', 'bundle_id', 'team_id', 'code_directory_hash'], 'release code identity');
    const expected = REQUIRED_CODE_IDENTITIES[index];
    if (identity.path !== expected.path || identity.bundle_id !== expected.bundle_id || identity.team_id !== teamId || !CODE_HASH.test(identity.code_directory_hash)) throw new Error('release code identity binding is invalid');
  });
  const artifact = readProtectedFile(artifactPath, { maximum: 16 * 1024 * 1024 * 1024, production: false, expectedSha256: artifactSha256 });
  return { artifactPath: artifact.path, artifactSha256, sourceCommit, teamId, codeIdentities: codeIdentities.map((identity) => ({ ...identity })) };
};

const runScenario = (command, env, { timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = MAX_OUTPUT_BYTES } = {}) => new Promise((resolveResult) => {
  const child = spawn(command, [], { cwd: '/', env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
  const stdout = []; let stdoutBytes = 0; let stderrBytes = 0; let outputLimit = false; let timedOut = false; let settled = false;
  const stop = () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); };
  child.stdout.on('data', (chunk) => { if (stdoutBytes + chunk.length > maxOutputBytes) { outputLimit = true; stop(); return; } stdout.push(Buffer.from(chunk)); stdoutBytes += chunk.length; });
  child.stderr.on('data', (chunk) => { stderrBytes += chunk.length; if (stderrBytes > maxOutputBytes) { outputLimit = true; stop(); } });
  const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
  const finish = (exitCode, signal, spawnError = false) => { if (settled) return; settled = true; clearTimeout(timer); resolveResult({ exitCode, signal, spawnError, timedOut, outputLimit, stdout: Buffer.concat(stdout, stdoutBytes) }); };
  child.on('error', () => finish(null, null, true)); child.on('close', (code, signal) => finish(code, signal));
});

const validateScenarioProtocol = (bytes, gate, tests, bindings) => {
  let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('scenario returned invalid protocol'); }
  if (!bytes.equals(canonicalJSON(value))) throw new Error('scenario protocol is not canonical JSON');
  exactKeys(value, ['schema_version', 'gate', 'status', 'tests', 'bindings'], 'scenario result');
  exactKeys(value.bindings, ['artifact_sha256', 'source_commit', 'team_id', 'code_identities_sha256'], 'scenario bindings');
  const identityDigest = sha256(Buffer.from(JSON.stringify(bindings.codeIdentities)));
  if (value.schema_version !== 1 || value.gate !== gate || value.status !== 'passed' || JSON.stringify(value.bindings) !== JSON.stringify({ artifact_sha256: bindings.artifactSha256, source_commit: bindings.sourceCommit, team_id: bindings.teamId, code_identities_sha256: identityDigest })) throw new Error('scenario result is not bound to this release');
  if (!Array.isArray(value.tests) || value.tests.length !== tests.length || value.tests.some((item, index) => item?.name !== tests[index] || item?.status !== 'passed' || Object.keys(item).sort().join(',') !== 'name,status')) throw new Error('scenario did not pass the exact assigned tests');
  return value.tests;
};

export const executeGateDriver = async ({ gate, tests, scenario = gate, config, env = process.env, production = process.platform === 'darwin', run = runScenario } = {}) => {
  if (!SAFE_NAME.test(gate ?? '') || !SAFE_NAME.test(scenario ?? '') || !Array.isArray(tests) || tests.length === 0 || new Set(tests).size !== tests.length || tests.some((test) => !SAFE_NAME.test(test))) throw new Error('gate driver declaration is invalid');
  if (production && process.platform !== 'darwin') throw new Error('production gate drivers require macOS');
  const release = validateReleaseBindings(env); const loaded = config ?? loadDriverConfig(undefined, { production }); const entry = loaded.scenarios.get(gate);
  if (!entry || entry.executable !== scenario) throw new Error('scenario is not allowlisted for this gate');
  const executable = readProtectedFile(entry.path, { maximum: 16 * 1024 * 1024, executable: true, production, expectedSha256: entry.sha256 });
  const scenarioEnv = { ...BASE_ENV, AGENTPASS_P0C_ARTIFACT_PATH: release.artifactPath, AGENTPASS_P0C_ARTIFACT_SHA256: release.artifactSha256, AGENTPASS_P0C_SOURCE_COMMIT: release.sourceCommit, AGENTPASS_P0C_TEAM_ID: release.teamId, AGENTPASS_P0C_CODE_IDENTITIES_JSON: JSON.stringify(release.codeIdentities), AGENTPASS_P0C_GATE: gate, AGENTPASS_P0C_TESTS_JSON: JSON.stringify(tests) };
  const result = await run(executable.path, scenarioEnv, {});
  const after = readProtectedFile(entry.path, { maximum: 16 * 1024 * 1024, executable: true, production, expectedSha256: entry.sha256 });
  if (after.identity !== executable.identity || result.exitCode !== 0 || result.signal || result.spawnError || result.timedOut || result.outputLimit) throw new Error('physical scenario failed');
  const passedTests = validateScenarioProtocol(result.stdout, gate, tests, release);
  return { schema_version: 1, gate, status: 'passed', tests: passedTests };
};

export const runGateDriver = async (declaration) => {
  try { process.stdout.write(canonicalJSON(await executeGateDriver(declaration))); }
  catch { process.stderr.write('P0-C physical gate refused\n'); process.exitCode = 1; }
};
