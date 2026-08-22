#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { basename, isAbsolute, join, resolve } from 'node:path';
import {
  parseQualificationSuiteEvidence,
  qualificationSuiteEvidenceSHA256
} from './n3e/qualification-suite-evidence.mjs';

const MAX_TEMPLATE_BYTES = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const TERMINATION_GRACE_MS = 250;
const PRODUCTION_GATE_DRIVER_DIRECTORY = '/opt/agentpass/p0c/gates';
const PRODUCTION_GATE_MANIFEST_PATH = '/opt/agentpass/p0c/gate-manifest.json';
const SANITIZED_ENV = Object.freeze({ HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
const REQUIRED_CODE_IDENTITIES = Object.freeze([
  Object.freeze({ path: 'AgentPass.app', bundle_id: 'dev.agentpass' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', bundle_id: 'dev.agentpass.native-client' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', bundle_id: 'dev.agentpass.native-service' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', bundle_id: 'dev.agentpass.atomic-rename' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-native-manager', bundle_id: 'dev.agentpass.native-manager' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-onboarding', bundle_id: 'dev.agentpass' })
]);

export const REQUIRED_GATES = Object.freeze([
  'gatekeeper-notarization', 'clean-install-launchd-xpc', 'secure-enclave-enrollment',
  'cloud-possession-verification', 'claude-code-unattended-sign', 'cursor-code-unattended-sign',
  'audit-upload-observation', 'policy-reduction-refresh-ack', 'offline-expiry',
  'revoke-emergency-stop', 'crash-restart-recovery', 'sleep-wake-network-clock',
  'upgrade-preserves-state', 'uninstall-reinstall-recovery', 'current-user-purge',
  'negative-identity-and-entitlement-cases'
]);

export const REQUIRED_TESTS = Object.freeze([
  'exact-pkg-install', 'launchd-xpc-approval', 'secure-enclave-key-creation',
  'secure-enclave-nonexportability', 'cloud-possession-proof',
  'claude-code-unattended-sign', 'cursor-code-unattended-sign', 'unrelated-process-denied',
  'audit-console-observation', 'policy-reduction-denied', 'offline-expiry-denied',
  'revoke-denied', 'emergency-stop-denied', 'service-crash-recovery', 'os-reboot-recovery',
  'sleep-wake-recovery', 'network-clock-failure', 'upgrade-preserves-state',
  'uninstall-reinstall-recovery', 'current-user-purge'
]);

const REPORT_KEYS = Object.freeze([
  'schema_version', 'source_commit', 'source_tree', 'dependency_lock_sha256', 'release_manifest_sha256',
  'artifact_name', 'artifact_sha256', 'architecture', 'hardware_class', 'model_identifier',
  'macos_version', 'macos_build', 'secure_enclave', 'team_id', 'nested_code_identities',
  'notarization', 'cloud_image_digest', 'database_migration_manifest_sha256',
  'signer_key_versions', 'browser_versions', 'started_at', 'completed_at', 'operator',
  'operator_key_fingerprint', 'qualified', 'tests', 'gates', 'n3e_qualification_suite_evidence'
]);
const LEGACY_REPORT_KEYS = Object.freeze(REPORT_KEYS.filter((key) => key !== 'n3e_qualification_suite_evidence'));
const N3E_REPORT_EVIDENCE_KEY = 'n3e_qualification_suite_evidence';

const METADATA_COMMANDS = Object.freeze({
  architecture: ['/usr/bin/uname', ['-m']],
  modelIdentifier: ['/usr/sbin/sysctl', ['-n', 'hw.model']],
  macosVersion: ['/usr/bin/sw_vers', ['-productVersion']],
  macosBuild: ['/usr/bin/sw_vers', ['-buildVersion']],
  secureEnclaveProbe: ['/usr/sbin/ioreg', ['-rd1', '-c', 'AppleSEPManager']]
});

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const validDigest = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const safeName = (value) => typeof value === 'string' && /^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(value) && value === basename(value);
const utc = (date) => {
  const value = date instanceof Date ? date : new Date(date);
  if (!Number.isFinite(value.getTime())) throw new Error('qualification clock returned an invalid time');
  return value.toISOString();
};
const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};
const failReason = (reason) => String(reason).replace(/[^A-Za-z0-9 .,;:_()\/-]/g, '?').slice(0, 256) || 'physical gate did not pass';

const snapshotFile = (input, maximum, label) => {
  const path = resolve(input); let fd;
  try { fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { throw new Error(`${label} is not a readable regular file`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size === 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} is not a safe regular file`);
    const size = Number(before.size); const bytes = Buffer.allocUnsafe(size); let offset = 0;
    while (offset < size) { const count = fs.readSync(fd, bytes, offset, size - offset, offset); if (count === 0) throw new Error(`${label} changed while reading`); offset += count; }
    const after = fs.fstatSync(fd, { bigint: true }); if (statIdentity(before) !== statIdentity(after)) throw new Error(`${label} changed while reading`);
    return { path, bytes, size, sha256: sha256(bytes) };
  } finally { fs.closeSync(fd); }
};

const assertAbsolutePath = (value, label) => { if (typeof value !== 'string' || !isAbsolute(value)) throw new Error(`${label} must be an absolute path`); return value; };
const assertDirectory = (input, label, privateDirectory = false) => {
  const path = assertAbsolutePath(input, label); let stat;
  try { stat = fs.lstatSync(path); } catch { throw new Error(`${label} is unavailable`); }
  if (!stat.isDirectory() || (privateDirectory && (stat.mode & 0o077) !== 0)) throw new Error(`${label} must be a safe directory`);
  return path;
};
const assertRegularExecutable = (path, label, requireRootOwner = false) => {
  let stat; try { stat = fs.lstatSync(path); } catch { throw new Error(`${label} is unavailable`); }
  if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0 || (requireRootOwner && stat.uid !== 0)) throw new Error(`${label} must be a protected regular executable`);
  return statIdentity(stat);
};
const ensureEmptyEvidenceDirectory = (input) => {
  const path = assertDirectory(input, 'evidence directory', true);
  if (fs.readdirSync(path, { withFileTypes: true }).length !== 0) throw new Error('evidence directory must be empty');
  return path;
};
const writePrivateFile = (path, bytes) => {
  let fd;
  try {
    fd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    const opened = fs.fstatSync(fd); if (!opened.isFile() || opened.nlink !== 1 || (opened.mode & 0o077) !== 0) throw new Error('new evidence file is not private');
    let offset = 0; while (offset < bytes.length) offset += fs.writeSync(fd, bytes, offset, bytes.length - offset); fs.fsyncSync(fd);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  const after = fs.lstatSync(path); if (!after.isFile() || after.nlink !== 1 || (after.mode & 0o077) !== 0 || after.size !== bytes.length) throw new Error('written evidence file is unsafe');
  return { name: basename(path), bytes: bytes.length, sha256: sha256(bytes) };
};

const makeBoundedCapture = (maximum) => ({
  chunks: [], bytes: 0, exceeded: false, hash: crypto.createHash('sha256'),
  append(chunk) { const remaining = Math.max(0, maximum - this.bytes); const accepted = chunk.subarray(0, remaining); if (accepted.length > 0) { this.chunks.push(Buffer.from(accepted)); this.hash.update(accepted); this.bytes += accepted.length; } if (accepted.length !== chunk.length) this.exceeded = true; },
  finish() { return { bytes: this.bytes, sha256: this.hash.digest('hex'), truncated: this.exceeded, content: Buffer.concat(this.chunks, this.bytes) }; }
});

export const runBoundedCommand = (command, args = [], { timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = MAX_OUTPUT_BYTES, cwd = '/', env = SANITIZED_ENV } = {}) => new Promise((resolveResult) => {
  let child;
  try { child = spawn(command, args, { cwd, env: { ...SANITIZED_ENV, ...env }, shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); } catch { const empty = Buffer.alloc(0); resolveResult({ exitCode: null, signal: null, timedOut: false, outputLimit: false, spawnError: true, durationMs: 0, stdout: empty, stderr: empty, stdoutBytes: 0, stderrBytes: 0, stdoutSha256: sha256(empty), stderrSha256: sha256(empty) }); return; }
  const started = Date.now(); const stdout = makeBoundedCapture(maxOutputBytes); const stderr = makeBoundedCapture(maxOutputBytes);
  let timedOut = false; let outputLimit = false; let termTimer; let timeoutTimer; let settled = false;
  const terminate = (kind) => { if (kind === 'timeout') timedOut = true; if (kind === 'output') outputLimit = true; if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); clearTimeout(termTimer); termTimer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }, TERMINATION_GRACE_MS); };
  const onData = (capture, chunk) => { capture.append(chunk); if (capture.exceeded && !outputLimit && !timedOut) terminate('output'); };
  child.stdout.on('data', (chunk) => onData(stdout, chunk)); child.stderr.on('data', (chunk) => onData(stderr, chunk));
  timeoutTimer = setTimeout(() => { if (!settled) terminate('timeout'); }, timeoutMs);
  const finish = (extra) => { if (settled) return; settled = true; clearTimeout(timeoutTimer); clearTimeout(termTimer); const out = stdout.finish(); const err = stderr.finish(); resolveResult({ ...extra, timedOut, outputLimit, durationMs: Date.now() - started, stdout: out.content, stderr: err.content, stdoutBytes: out.bytes, stderrBytes: err.bytes, stdoutSha256: out.sha256, stderrSha256: err.sha256, stdoutTruncated: out.truncated, stderrTruncated: err.truncated }); };
  child.on('error', () => finish({ exitCode: null, signal: null, spawnError: true })); child.on('close', (exitCode, signal) => finish({ exitCode, signal, spawnError: false }));
});

const normalizeCommandResult = (result) => {
  if (!result || typeof result !== 'object') throw new Error('command runner returned an invalid result');
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout ?? ''); const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr ?? '');
  if (!Number.isSafeInteger(result.exitCode) && result.exitCode !== null && result.exitCode !== undefined) throw new Error('command runner returned an invalid exit code');
  return { ...result, stdout, stderr, exitCode: result.exitCode ?? null, signal: result.signal ?? null, timedOut: result.timedOut === true, outputLimit: result.outputLimit === true, spawnError: result.spawnError === true, durationMs: Number.isSafeInteger(result.durationMs) ? result.durationMs : 0, stdoutBytes: stdout.length, stderrBytes: stderr.length, stdoutSha256: sha256(stdout), stderrSha256: sha256(stderr) };
};

export const collectPhysicalMetadata = async ({ runCommand = runBoundedCommand, timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = MAX_OUTPUT_BYTES } = {}) => {
  const execute = async (command, args) => normalizeCommandResult(await runCommand(command, args, { timeoutMs, maxOutputBytes, cwd: '/', env: SANITIZED_ENV, shell: false, stdio: ['ignore', 'pipe', 'pipe'] }));
  const results = {};
  for (const [key, [command, args]] of Object.entries(METADATA_COMMANDS)) { const result = await execute(command, args); if (result.exitCode !== 0 || result.signal || result.timedOut || result.outputLimit || result.spawnError) throw new Error(`physical metadata command failed: ${key}`); results[key] = result.stdout.toString('utf8').trim(); }
  if (!['arm64', 'x86_64'].includes(results.architecture)) throw new Error('unsupported physical architecture');
  if (!/^[A-Za-z0-9,._-]{3,80}$/.test(results.modelIdentifier)) throw new Error('invalid physical model identifier');
  if (!/^\d+\.\d+(?:\.\d+)?$/.test(results.macosVersion) || !/^[A-Za-z0-9]{3,32}$/.test(results.macosBuild)) throw new Error('invalid macOS version metadata');
  const secureEnclave = /AppleSEPManager/i.test(results.secureEnclaveProbe);
  return { architecture: results.architecture, hardwareClass: results.architecture === 'arm64' ? 'apple_silicon' : secureEnclave ? 'intel_t2' : 'intel_without_t2', modelIdentifier: results.modelIdentifier, macosVersion: results.macosVersion, macosBuild: results.macosBuild, secureEnclave };
};

const validateTemplate = (snapshot) => {
  let template; try { template = JSON.parse(snapshot.bytes.toString('utf8')); } catch { throw new Error('production report template is not valid JSON'); }
  if (!snapshot.bytes.equals(canonicalJSON(template))) throw new Error('production report template is not canonical JSON');
  exactKeys(template, Object.hasOwn(template, N3E_REPORT_EVIDENCE_KEY) ? REPORT_KEYS : LEGACY_REPORT_KEYS, 'production report template');
  if (template.schema_version !== 2 || template.qualified !== false) throw new Error('production report template must be unsigned v2 and unqualified');
  if (Object.hasOwn(template, N3E_REPORT_EVIDENCE_KEY) && template[N3E_REPORT_EVIDENCE_KEY] !== null) throw new Error('production report template cannot contain N3-E qualification evidence');
  if (!safeName(template.artifact_name) || !validDigest(template.artifact_sha256) || !/^[0-9a-f]{40}$/.test(template.source_commit) || !/^[0-9a-f]{40}$/.test(template.source_tree) || !validDigest(template.dependency_lock_sha256) || !validDigest(template.release_manifest_sha256) || !validDigest(template.database_migration_manifest_sha256) || template.source_commit === '0'.repeat(40) || template.source_tree === '0'.repeat(40) || [template.artifact_sha256, template.dependency_lock_sha256, template.release_manifest_sha256, template.database_migration_manifest_sha256].some((value) => value === '0'.repeat(64)) || JSON.stringify(template).includes('REPLACE_WITH') || template.team_id === 'TEAMID1234') throw new Error('production report template lacks release bindings');
  if (template.notarization?.status !== 'accepted_stapled') throw new Error('production report template must bind an accepted notarized release');
  if (template.secure_enclave !== true || !/^SHA256:[A-Za-z0-9_-]{43}$/.test(template.operator_key_fingerprint)) throw new Error('production report template is not a production qualification template');
  if (!Array.isArray(template.nested_code_identities) || template.nested_code_identities.length !== REQUIRED_CODE_IDENTITIES.length) throw new Error('production report template must bind all required code identities');
  template.nested_code_identities.forEach((identity, index) => {
    exactKeys(identity, ['path', 'bundle_id', 'team_id', 'code_directory_hash'], 'production code identity');
    const expected = REQUIRED_CODE_IDENTITIES[index];
    if (identity.path !== expected.path || identity.bundle_id !== expected.bundle_id || identity.team_id !== template.team_id || !/^[0-9a-f]{40,64}$/.test(identity.code_directory_hash)) throw new Error('production report template code identity is substituted or out of order');
  });
  return template;
};
export const validateGateDirectory = (input, production, manifestInput = null) => {
  const directory = assertDirectory(input, 'gate-driver directory'); const directoryStat = fs.lstatSync(directory);
  if (production && (directoryStat.uid !== 0 || (directoryStat.mode & 0o022) !== 0)) throw new Error('production gate-driver directory must be root-owned and protected');
  const entries = fs.readdirSync(directory, { withFileTypes: true }).map((entry) => entry.name);
  const expected = [...REQUIRED_GATES].sort(); if (entries.sort().join('\n') !== expected.join('\n')) throw new Error('gate-driver directory must contain exactly the fixed required gate basenames');
  if (production && (!manifestInput || !isAbsolute(manifestInput))) throw new Error('production gate-driver manifest is required');
  const manifest = manifestInput ? snapshotFile(manifestInput, 1024 * 1024, 'gate-driver manifest') : null;
  let manifestValue = null;
  if (manifest) {
    try { manifestValue = JSON.parse(manifest.bytes.toString('utf8')); } catch { throw new Error('gate-driver manifest is not valid JSON'); }
    exactKeys(manifestValue, ['schema_version', 'gates'], 'gate-driver manifest');
    if (manifestValue.schema_version !== 1 || !Array.isArray(manifestValue.gates) || manifestValue.gates.length !== REQUIRED_GATES.length) throw new Error('gate-driver manifest has invalid inventory');
    const names = manifestValue.gates.map((item) => { exactKeys(item, ['gate', 'sha256'], 'gate-driver manifest entry'); if (!REQUIRED_GATES.includes(item.gate) || !validDigest(item.sha256)) throw new Error('gate-driver manifest entry is invalid'); return item.gate; });
    if (new Set(names).size !== names.length || names.some((name, index) => name !== REQUIRED_GATES[index])) throw new Error('gate-driver manifest is not ordered or complete');
    if (!manifest.bytes.equals(canonicalJSON(manifestValue))) throw new Error('gate-driver manifest is not canonical JSON');
    if (production && fs.lstatSync(manifest.path).uid !== 0) throw new Error('production gate-driver manifest must be root-owned');
  }
  const identities = new Map(); const digests = new Map();
  for (const gate of REQUIRED_GATES) {
    const path = join(directory, gate); const identity = assertRegularExecutable(path, `gate driver ${gate}`, production); const bytes = fs.readFileSync(path); const actual = sha256(bytes);
    if (manifestValue && actual !== manifestValue.gates.find((item) => item.gate === gate).sha256) throw new Error(`gate driver ${gate} digest does not match its protected manifest`);
    identities.set(gate, identity); digests.set(gate, actual);
  }
  return { path: directory, identities, digests, manifest };
};
const protocolFor = (bytes, gate) => {
  let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('gate driver protocol is not valid JSON'); }
  exactKeys(value, ['schema_version', 'gate', 'status', 'tests'], 'gate driver protocol'); if (value.schema_version !== 1 || value.gate !== gate || value.status !== 'passed' || !Array.isArray(value.tests) || value.tests.length === 0) throw new Error('gate driver protocol is not a passing result');
  const seen = new Set(); const tests = []; for (const item of value.tests) { exactKeys(item, ['name', 'status'], 'gate driver test'); if (!REQUIRED_TESTS.includes(item.name) || item.status !== 'passed' || seen.has(item.name)) throw new Error('gate driver protocol contains an invalid or duplicate test'); seen.add(item.name); tests.push(item.name); } return tests;
};
const resultEvidence = (kind, name, result, status, driverSha256 = null) => canonicalJSON({ schema_version: 1, kind, name, status, ...(driverSha256 ? { driver_sha256: driverSha256 } : {}), exit_code: result.exitCode, signal: result.signal, timed_out: result.timedOut, output_limit: result.outputLimit, duration_ms: result.durationMs, stdout_bytes: result.stdoutBytes, stdout_sha256: result.stdoutSha256, stderr_bytes: result.stderrBytes, stderr_sha256: result.stderrSha256 });
const failedResult = (name, reason, evidence) => ({ name, status: 'failed', reason: failReason(reason), evidence: [evidence] });
const skippedResult = (name, evidence) => ({ name, status: 'skipped', reason: 'required test did not physically pass', evidence: [evidence] });

export const runQualification = async ({ templatePath, outputPath, artifactPath, gateDriverDirectory, gateDriverManifestPath = null, evidenceDirectory, operator, qualificationSuiteEvidencePath = null, platform = process.platform, production = false, platformMetadata = null, metadataProvider = null, runCommand = runBoundedCommand, now = () => new Date(), timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = MAX_OUTPUT_BYTES } = {}) => {
  if (production && platform !== 'darwin') throw new Error('P0-C production qualification is supported only on darwin');
  if (production && (platformMetadata || metadataProvider || runCommand !== runBoundedCommand)) throw new Error('production qualification cannot use injected runners or metadata');
  // Production qualification is only allowed to consume the root-owned trust
  // anchors provisioned on the qualification host. A caller-selected path
  // would let a substituted CLI/job parameter choose the driver authority.
  // This does not replace the independent executed-byte ceremony; it closes
  // the simpler path-substitution class before the runner starts.
  if (production && (resolve(gateDriverDirectory ?? '') !== PRODUCTION_GATE_DRIVER_DIRECTORY || resolve(gateDriverManifestPath ?? '') !== PRODUCTION_GATE_MANIFEST_PATH)) throw new Error('production gate-driver trust paths are fixed');
  const template = validateTemplate(snapshotFile(assertAbsolutePath(templatePath, 'template path'), MAX_TEMPLATE_BYTES, 'production report template'));
  const output = assertAbsolutePath(outputPath, 'output path'); const artifact = snapshotFile(assertAbsolutePath(artifactPath, 'artifact path'), MAX_ARTIFACT_BYTES, 'production artifact');
  if (basename(artifact.path) !== template.artifact_name || artifact.sha256 !== template.artifact_sha256) throw new Error('exact production artifact does not match report template');
  const drivers = validateGateDirectory(gateDriverDirectory, production, gateDriverManifestPath); const evidence = ensureEmptyEvidenceDirectory(evidenceDirectory); if (resolve(output) === resolve(evidence)) throw new Error('output path must not be the evidence directory'); if (fs.existsSync(output)) throw new Error('output path already exists');
  if (!/^[A-Za-z0-9][A-Za-z0-9@._-]{2,127}$/.test(operator ?? '')) throw new Error('operator is invalid');
  const startedAt = utc(now()); const metadata = platformMetadata ?? (metadataProvider ? await metadataProvider({ runCommand, timeoutMs, maxOutputBytes }) : await collectPhysicalMetadata({ runCommand, timeoutMs, maxOutputBytes }));
  if (!metadata || !['arm64', 'x86_64'].includes(metadata.architecture) || !['apple_silicon', 'intel_t2', 'intel_without_t2'].includes(metadata.hardwareClass) || typeof metadata.modelIdentifier !== 'string' || typeof metadata.macosVersion !== 'string' || typeof metadata.macosBuild !== 'string' || typeof metadata.secureEnclave !== 'boolean') throw new Error('injected physical metadata is invalid');
  if ((metadata.hardwareClass === 'apple_silicon') !== (metadata.architecture === 'arm64') || (metadata.hardwareClass === 'intel_without_t2' && metadata.secureEnclave)) throw new Error('physical metadata hardware identity is inconsistent');
  let suiteBinding = null;
  if (qualificationSuiteEvidencePath !== null) {
    const suiteSnapshot = snapshotFile(assertAbsolutePath(qualificationSuiteEvidencePath, 'N3-E suite evidence path'), 64 * 1024, 'N3-E suite evidence');
    let suiteRecord;
    try { suiteRecord = parseQualificationSuiteEvidence(suiteSnapshot.bytes); } catch { throw new Error('N3-E suite evidence is invalid or non-canonical'); }
    if (suiteRecord.source_commit !== template.source_commit || suiteRecord.artifact_sha256 !== artifact.sha256 || suiteRecord.team_id !== template.team_id || suiteRecord.lane_class !== metadata.hardwareClass) throw new Error('N3-E suite evidence does not bind the exact report lane');
    suiteBinding = { schema_version: 1, record: suiteRecord, record_sha256: qualificationSuiteEvidenceSHA256(suiteRecord) };
  }
  const gateResults = new Map(); const testSources = new Map(); const duplicateTests = new Set(); const writtenEvidence = [];
  const driverEnvironment = Object.freeze({
    ...SANITIZED_ENV,
    AGENTPASS_P0C_ARTIFACT_PATH: artifact.path,
    AGENTPASS_P0C_ARTIFACT_SHA256: artifact.sha256,
    AGENTPASS_P0C_SOURCE_COMMIT: template.source_commit,
    AGENTPASS_P0C_SOURCE_TREE: template.source_tree,
    AGENTPASS_P0C_TEAM_ID: template.team_id,
    AGENTPASS_P0C_CODE_IDENTITIES_JSON: JSON.stringify(template.nested_code_identities)
  });
  for (let index = 0; index < REQUIRED_GATES.length; index += 1) {
    const gate = REQUIRED_GATES[index]; let result; let protocolTests = [];
    try {
      const driverPath = join(drivers.path, gate);
      if (assertRegularExecutable(driverPath, `gate driver ${gate}`, production) !== drivers.identities.get(gate)) throw new Error('gate driver changed before execution');
      result = normalizeCommandResult(await runCommand(driverPath, [], { cwd: '/', env: driverEnvironment, shell: false, stdio: ['ignore', 'pipe', 'pipe'], timeoutMs, maxOutputBytes }));
      if (assertRegularExecutable(driverPath, `gate driver ${gate}`, production) !== drivers.identities.get(gate)) throw new Error('gate driver changed during execution');
      if (result.exitCode === 0 && !result.signal && !result.timedOut && !result.outputLimit && !result.spawnError) { try { protocolTests = protocolFor(result.stdout, gate); } catch { protocolTests = []; } }
    } catch { const empty = Buffer.alloc(0); result = { exitCode: null, signal: null, timedOut: false, outputLimit: false, spawnError: true, durationMs: 0, stdout: empty, stderr: empty, stdoutBytes: 0, stderrBytes: 0, stdoutSha256: sha256(empty), stderrSha256: sha256(empty) }; }
    const passed = result.exitCode === 0 && !result.signal && !result.timedOut && !result.outputLimit && !result.spawnError && protocolTests.length > 0;
    gateResults.set(gate, { status: passed ? 'passed' : 'failed', reason: passed ? null : result.timedOut ? 'gate driver timed out' : result.outputLimit ? 'gate driver exceeded bounded output' : 'gate driver did not return a passing protocol', result });
    for (const test of protocolTests) { if (testSources.has(test)) duplicateTests.add(test); else testSources.set(test, gate); }
    const evidenceName = `gate-${String(index).padStart(2, '0')}-${gate}.json`; const binding = writePrivateFile(join(evidence, evidenceName), resultEvidence('p0c-gate-result', gate, result, passed ? 'passed' : 'failed', drivers.digests.get(gate))); writtenEvidence.push(binding); gateResults.get(gate).evidence = binding;
  }
  const testResults = [];
  for (let index = 0; index < REQUIRED_TESTS.length; index += 1) {
    const test = REQUIRED_TESTS[index]; const sourceGate = testSources.get(test); const gatePassed = sourceGate && gateResults.get(sourceGate)?.status === 'passed' && !duplicateTests.has(test); const status = gatePassed ? 'passed' : duplicateTests.has(test) || sourceGate ? 'failed' : 'skipped';
    const empty = Buffer.alloc(0); const synthetic = { exitCode: gatePassed ? 0 : null, signal: null, timedOut: false, outputLimit: false, spawnError: !gatePassed, durationMs: 0, stdoutBytes: 0, stderrBytes: 0, stdoutSha256: sha256(empty), stderrSha256: sha256(empty) }; const evidenceName = `test-${String(index).padStart(2, '0')}-${test}.json`; const binding = writePrivateFile(join(evidence, evidenceName), resultEvidence('p0c-test-result', test, synthetic, status)); writtenEvidence.push(binding);
    testResults.push(status === 'passed' ? { name: test, status, evidence: [binding] } : status === 'failed' ? failedResult(test, duplicateTests.has(test) ? 'test was reported by multiple gate drivers' : 'source gate did not pass', binding) : skippedResult(test, binding));
  }
  const completedAt = utc(now());
  if (suiteBinding && (Date.parse(suiteBinding.record.started_at) < Date.parse(startedAt) || Date.parse(suiteBinding.record.completed_at) > Date.parse(completedAt))) throw new Error('N3-E suite evidence timestamps fall outside the hardware qualification window');
  const report = { ...template, architecture: metadata.architecture, hardware_class: metadata.hardwareClass, model_identifier: metadata.modelIdentifier, macos_version: metadata.macosVersion, macos_build: metadata.macosBuild, secure_enclave: metadata.secureEnclave, started_at: startedAt, completed_at: completedAt, operator, qualified: production && platform === 'darwin' && metadata.secureEnclave === true && metadata.hardwareClass !== 'intel_without_t2' && suiteBinding !== null && REQUIRED_GATES.every((gate) => gateResults.get(gate)?.status === 'passed') && testResults.every((item) => item.status === 'passed'), tests: testResults, gates: REQUIRED_GATES.map((gate) => { const item = gateResults.get(gate); return item.status === 'passed' ? { name: gate, status: 'passed', evidence: [item.evidence] } : failedResult(gate, item.reason, item.evidence); }), ...(suiteBinding ? { [N3E_REPORT_EVIDENCE_KEY]: suiteBinding } : {}) };
  exactKeys(report, Object.hasOwn(report, N3E_REPORT_EVIDENCE_KEY) ? REPORT_KEYS : LEGACY_REPORT_KEYS, 'generated hardware qualification report'); const reportBytes = canonicalJSON(report); writePrivateFile(output, reportBytes);
  return { report, outputPath: output, evidenceDirectory: evidence, evidence: writtenEvidence };
};

const parseArgs = (args) => {
  const values = {}; for (let index = 0; index < args.length; index += 1) { const key = args[index]; const value = args[index + 1]; if (!key?.startsWith('--') || !value || value.startsWith('--')) throw new Error('invalid P0-C qualification arguments'); const name = key.slice(2); if (!['template', 'output', 'artifact', 'gate-drivers', 'gate-manifest', 'evidence-dir', 'operator', 'n3e-suite-evidence'].includes(name) || values[name]) throw new Error('invalid or duplicate P0-C qualification argument'); values[name] = value; index += 1; }
  if (![7, 8].includes(Object.keys(values).length)) throw new Error('usage: run-p0c-qualification.mjs --template TEMPLATE --output OUTPUT --artifact PKG --gate-drivers DIR --gate-manifest MANIFEST --evidence-dir DIR --operator OPERATOR [--n3e-suite-evidence EVIDENCE]');
  return { templatePath: values.template, outputPath: values.output, artifactPath: values.artifact, gateDriverDirectory: values['gate-drivers'], gateDriverManifestPath: values['gate-manifest'], evidenceDirectory: values['evidence-dir'], operator: values.operator, qualificationSuiteEvidencePath: values['n3e-suite-evidence'] ?? null };
};

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const result = await runQualification({ ...parseArgs(process.argv.slice(2)), platform: process.platform, production: true });
    const qualified = result.report.qualified === true;
    process.stdout.write(`${JSON.stringify({ ok: qualified, qualified, output: result.outputPath, evidence_directory: result.evidenceDirectory })}\n`);
    if (!qualified) process.exitCode = 1;
  }
  catch (error) { process.stderr.write(`p0c qualification refused: ${failReason(error.message)}\n`); process.exitCode = 1; }
}
