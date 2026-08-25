#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';

const MAX_INPUT_BYTES = 64 * 1024 * 1024;
const MAX_SIGNER_KEY_VERSION_BYTES = 1024 * 1024;
const ATTESTATION_SCHEMA_VERSION = 1;
const REQUIRED_TEAM_ID = /^[A-Z0-9]{10}$/;
const HEX_DIGEST = /^[0-9a-f]{64}$/;
const CLOUD_IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const SAFE_VERSION_NAME = /^[A-Za-z0-9._-]{1,80}$/;
const SAFE_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$/;
const CODE_DIRECTORY_HASH = /^[0-9a-f]{40,64}$/;

// These paths and identifiers are part of the release contract. Do not make
// this list configurable: a release attestation must cover every executable
// boundary that the hardware qualification validator relies on.
export const REQUIRED_CODE_IDENTITIES = Object.freeze([
  Object.freeze({ path: 'AgentPass.app', bundle_id: 'dev.agentpass' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', bundle_id: 'dev.agentpass.native-client' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', bundle_id: 'dev.agentpass.native-service' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', bundle_id: 'dev.agentpass.atomic-rename' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-native-manager', bundle_id: 'dev.agentpass.native-manager' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-onboarding', bundle_id: 'dev.agentpass' })
]);

const exactKeys = (value, keys, label) => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};

const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');

const assertNoFollowSupport = () => {
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');
};

const readRegularFile = (input, { maximum = MAX_INPUT_BYTES, label = 'input file' } = {}) => {
  assertNoFollowSupport();
  if (typeof input !== 'string' || input.length === 0) throw new Error(`${label} path is required`);
  const path = resolve(input);
  let descriptor;
  try {
    descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch {
    throw new Error(`cannot open ${label}: ${input}`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`unsafe ${label}: ${input}`);
    }
    const size = Number(before.size);
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const count = fs.readSync(descriptor, bytes, offset, size - offset, offset);
      if (count === 0) throw new Error(`${label} changed while reading: ${input}`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`${label} changed while reading: ${input}`);
    return { path, bytes, size, sha256: createHash('sha256').update(bytes).digest('hex') };
  } finally {
    fs.closeSync(descriptor);
  }
};

const assertSafeBundlePath = (input) => {
  if (typeof input !== 'string' || input.length === 0) throw new Error('signed app path is required');
  const appPath = resolve(input);
  if (basename(appPath) !== 'AgentPass.app') throw new Error('signed app path must end in AgentPass.app');
  const root = resolve(appPath, '..');
  let current = root;
  const parts = relative(root, appPath).split(sep).filter(Boolean);
  for (const part of parts) {
    current = join(current, part);
    let stat;
    try { stat = fs.lstatSync(current); } catch { throw new Error(`signed app path does not exist: ${input}`); }
    if (stat.isSymbolicLink()) throw new Error(`signed app path contains a symlink: ${input}`);
    if (part === 'AgentPass.app' && !stat.isDirectory()) throw new Error('signed app path must be a directory bundle');
  }
  return appPath;
};

const assertSafeIdentityPath = (appPath, identityPath) => {
  const expectedRoot = resolve(appPath);
  const fullPath = resolve(expectedRoot, identityPath.slice('AgentPass.app/'.length));
  const rootParent = resolve(expectedRoot, '..');
  const rel = relative(rootParent, fullPath);
  if (rel.startsWith(`..${sep}`) || rel === '..' || rel.includes(`${sep}..${sep}`) || rel.startsWith(sep)) throw new Error('code identity path escapes the app bundle');
  let current = rootParent;
  for (const part of rel.split(sep)) {
    current = join(current, part);
    let stat;
    try { stat = fs.lstatSync(current); } catch { throw new Error(`required code identity is missing: ${identityPath}`); }
    if (stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1)) throw new Error(`required code identity is not a single-link path: ${identityPath}`);
  }
  return fullPath;
};

const productionCommandRunner = (command, args, options = {}) => {
  if (command !== '/usr/bin/codesign') throw new Error('release attestation permits only the system codesign executable');
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }
  });
  if (result.error) throw new Error('codesign execution failed');
  return { status: result.status, signal: result.signal, stdout: result.stdout || '', stderr: result.stderr || '' };
};

const normalizeCommandResult = (result) => {
  if (!result || !Number.isInteger(result.status) || result.status !== 0 || result.signal) throw new Error('codesign command failed');
  return `${typeof result.stdout === 'string' ? result.stdout : ''}\n${typeof result.stderr === 'string' ? result.stderr : ''}`;
};

const parseCodesignDisplay = (text, expected, expectedTeamId) => {
  const fields = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^(Identifier|TeamIdentifier|CDHash)=([^\s]+)$/);
    if (!match) continue;
    if (fields.has(match[1])) throw new Error(`codesign output contains duplicate ${match[1]}`);
    fields.set(match[1], match[2]);
  }
  if (fields.get('Identifier') !== expected.bundle_id) throw new Error(`codesign identifier mismatch for ${expected.path}`);
  if (fields.get('TeamIdentifier') !== expectedTeamId) throw new Error(`codesign Team ID mismatch for ${expected.path}`);
  const codeDirectoryHash = fields.get('CDHash');
  if (!codeDirectoryHash || !CODE_DIRECTORY_HASH.test(codeDirectoryHash)) throw new Error(`codesign CodeDirectory hash missing or invalid for ${expected.path}`);
  return {
    path: expected.path,
    bundle_id: expected.bundle_id,
    team_id: expectedTeamId,
    code_directory_hash: codeDirectoryHash
  };
};

export const collectCodeIdentities = ({ appPath, expectedTeamId, runCommand = productionCommandRunner, platform = process.platform } = {}) => {
  if (platform !== 'darwin') throw new Error('release attestation identity collection requires macOS');
  if (typeof runCommand !== 'function') throw new Error('codesign command runner is required');
  if (typeof expectedTeamId !== 'string' || !REQUIRED_TEAM_ID.test(expectedTeamId)) throw new Error('invalid expected Team ID');
  const safeAppPath = assertSafeBundlePath(appPath);
  const verification = runCommand('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', safeAppPath], { cwd: dirname(safeAppPath) });
  normalizeCommandResult(verification);
  return REQUIRED_CODE_IDENTITIES.map((expected) => {
    const target = expected.path === 'AgentPass.app' ? safeAppPath : assertSafeIdentityPath(safeAppPath, expected.path);
    const result = runCommand('/usr/bin/codesign', ['--display', '--verbose=4', target], { cwd: dirname(safeAppPath) });
    return parseCodesignDisplay(normalizeCommandResult(result), expected, expectedTeamId);
  });
};

export const validateSignerKeyVersions = (value) => {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) throw new Error('signer key versions must be a non-empty array');
  let previousName = '';
  const names = new Set();
  return value.map((item) => {
    exactKeys(item, ['name', 'version'], 'signer key version');
    if (!SAFE_VERSION_NAME.test(item.name) || !SAFE_VERSION.test(item.version) || names.has(item.name) || item.name <= previousName) throw new Error('signer key versions must be unique and sorted');
    names.add(item.name);
    previousName = item.name;
    return { name: item.name, version: item.version };
  });
};

const parseSignerKeyVersions = (snapshot) => {
  let value;
  try { value = JSON.parse(snapshot.bytes.toString('utf8')); } catch { throw new Error('signer key versions JSON is invalid UTF-8 JSON'); }
  return validateSignerKeyVersions(value);
};

const validateInputs = ({ teamId, cloudImageDigest, dependencyLockSha256, databaseMigrationManifestSha256 }) => {
  if (typeof teamId !== 'string' || !REQUIRED_TEAM_ID.test(teamId)) throw new Error('invalid expected Team ID');
  if (typeof cloudImageDigest !== 'string' || !CLOUD_IMAGE_DIGEST.test(cloudImageDigest)) throw new Error('cloud image must be an immutable sha256 digest, not a tag');
  if (!HEX_DIGEST.test(dependencyLockSha256) || !HEX_DIGEST.test(databaseMigrationManifestSha256)) throw new Error('input digest is invalid');
};

export const buildReleaseAttestation = ({ teamId, cloudImageDigest, dependencyLockSha256, databaseMigrationManifestSha256, nestedCodeIdentities, signerKeyVersions }) => {
  validateInputs({ teamId, cloudImageDigest, dependencyLockSha256, databaseMigrationManifestSha256 });
  if (!Array.isArray(nestedCodeIdentities) || nestedCodeIdentities.length !== REQUIRED_CODE_IDENTITIES.length) throw new Error('all six required code identities are required');
  const expectedByPath = new Map(REQUIRED_CODE_IDENTITIES.map((item) => [item.path, item]));
  const seen = new Set();
  const identities = nestedCodeIdentities.map((identity) => {
    exactKeys(identity, ['path', 'bundle_id', 'team_id', 'code_directory_hash'], 'code identity');
    const expected = expectedByPath.get(identity.path);
    if (!expected || seen.has(identity.path) || identity.bundle_id !== expected.bundle_id || identity.team_id !== teamId || !CODE_DIRECTORY_HASH.test(identity.code_directory_hash)) throw new Error(`code identity omission or substitution: ${identity.path}`);
    seen.add(identity.path);
    return { path: identity.path, bundle_id: identity.bundle_id, team_id: identity.team_id, code_directory_hash: identity.code_directory_hash };
  });
  if (seen.size !== REQUIRED_CODE_IDENTITIES.length || identities.some((item, index) => item.path !== REQUIRED_CODE_IDENTITIES[index].path)) throw new Error('code identities must be in the fixed release order');
  const versions = validateSignerKeyVersions(signerKeyVersions);
  return {
    schema_version: ATTESTATION_SCHEMA_VERSION,
    team_id: teamId,
    nested_code_identities: identities,
    cloud_image_digest: cloudImageDigest,
    dependency_lock_sha256: dependencyLockSha256,
    database_migration_manifest_sha256: databaseMigrationManifestSha256,
    signer_key_versions: versions
  };
};

export const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

export const generateReleaseAttestation = ({ appPath, teamId, dependencyLockPath, databaseMigrationManifestPath, cloudImageDigest, signerKeyVersionsPath, runCommand = productionCommandRunner, platform = process.platform } = {}) => {
  if (platform !== 'darwin') throw new Error('release attestation generation requires macOS');
  const lock = readRegularFile(dependencyLockPath, { label: 'dependency lock file' });
  const migrations = readRegularFile(databaseMigrationManifestPath, { label: 'database migration manifest' });
  const signerVersions = readRegularFile(signerKeyVersionsPath, { maximum: MAX_SIGNER_KEY_VERSION_BYTES, label: 'signer key versions JSON' });
  const identities = collectCodeIdentities({ appPath, expectedTeamId: teamId, runCommand, platform });
  return buildReleaseAttestation({
    teamId,
    cloudImageDigest,
    dependencyLockSha256: lock.sha256,
    databaseMigrationManifestSha256: migrations.sha256,
    nestedCodeIdentities: identities,
    signerKeyVersions: parseSignerKeyVersions(signerVersions)
  });
};

const fsyncDirectory = (directory) => {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
};

export const writeCanonicalAtomically = (outputPath, value) => {
  assertNoFollowSupport();
  if (typeof outputPath !== 'string' || outputPath.length === 0) throw new Error('output path is required');
  const destination = resolve(outputPath);
  const directory = dirname(destination);
  const outputName = basename(destination);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(outputName)) throw new Error('output filename is unsafe');
  let directoryStat;
  try { directoryStat = fs.lstatSync(directory); } catch { throw new Error('output directory does not exist'); }
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error('output directory is unsafe');
  try {
    const existing = fs.lstatSync(destination);
    if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) throw new Error('output path is unsafe');
    throw new Error('output already exists');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('canonical output value must be an object');
  const bytes = canonicalJSON(value);
  let temporary;
  let descriptor;
  try {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const suffix = randomBytes(12).toString('hex');
      temporary = join(directory, `.${outputName}.${process.pid}.${suffix}.tmp`);
      try { descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o644); break; } catch (error) { if (error?.code !== 'EEXIST' || attempt === 7) throw error; }
    }
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.linkSync(temporary, destination);
    fs.unlinkSync(temporary);
    temporary = undefined;
    fsyncDirectory(directory);
  } catch (error) {
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
    if (temporary) { try { fs.unlinkSync(temporary); } catch {} }
    throw error;
  }
  return { path: destination, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
};

const parseArguments = (args) => {
  const values = new Map();
  const names = new Set(['--app', '--team-id', '--dependency-lock', '--database-migration-manifest', '--cloud-image-digest', '--signer-key-versions', '--output']);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!names.has(name) || value === undefined || value.startsWith('--') || values.has(name)) throw new Error('Usage: generate-release-attestation.mjs --app APP --team-id TEAMID --dependency-lock FILE --database-migration-manifest FILE --cloud-image-digest sha256:DIGEST --signer-key-versions FILE --output FILE');
    values.set(name, value);
  }
  if (values.size !== names.size) throw new Error('all explicit release attestation inputs are required');
  return values;
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (process.platform !== 'darwin') throw new Error('release attestation generation requires macOS');
  const values = parseArguments(process.argv.slice(2));
  const attestation = generateReleaseAttestation({
    appPath: values.get('--app'),
    teamId: values.get('--team-id'),
    dependencyLockPath: values.get('--dependency-lock'),
    databaseMigrationManifestPath: values.get('--database-migration-manifest'),
    cloudImageDigest: values.get('--cloud-image-digest'),
    signerKeyVersionsPath: values.get('--signer-key-versions')
  });
  const result = writeCanonicalAtomically(values.get('--output'), attestation);
  console.log(JSON.stringify({ ok: true, schema_version: ATTESTATION_SCHEMA_VERSION, output_bytes: result.bytes, output_sha256: result.sha256, code_identities: attestation.nested_code_identities.length }));
}
