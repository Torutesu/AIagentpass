#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

/**
 * The external qualification controller is a release artifact, not a member
 * of the ordinary AgentPass.app identity inventory.  Keep this schema closed
 * so a caller cannot silently add an identity input that the service does not
 * understand.
 */
export const SCHEMA_VERSION = 1;
export const CONTRACT_KIND = 'agentpass-n3e-external-qualification-controller-identity';
export const CONTROLLER_ARCHIVE_NAME = 'AgentPassQualificationController-0.18.0-macos-universal.tar';
export const CONTROLLER_ARCHIVE_NAME_PATTERN = /^AgentPassQualificationController-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?-macos-universal\.tar$/u;
export const CONTROLLER_BUNDLE_ID = 'dev.agentpass.qualification-controller';
export const CONTROLLER_EXECUTABLE_RELATIVE_PATH = 'Contents/MacOS/agentpass-qualification-controller';
export const CONTROLLER_ARCHITECTURES = Object.freeze(['arm64', 'x86_64']);

export const CONTRACT_FIELDS = Object.freeze([
  'schema_version',
  'kind',
  'archive_name',
  'archive_sha256',
  'archive_bytes',
  'bundle_id',
  'team_id',
  'entitlements_sha256',
  'code_directory_hashes',
  'designated_requirements'
]);

export const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
export const MAX_DESIGNATED_REQUIREMENT_BYTES = 16 * 1024;
export const MAX_ENTITLEMENT_BYTES = 256 * 1024;

const HEX_DIGEST = /^[0-9a-f]{64}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const CODE_DIRECTORY_HASH = /^[0-9a-f]{40}$/u;
const BUNDLE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const ARCHITECTURE = /^[A-Za-z0-9_]{1,32}$/u;
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const FIXED_ENV = Object.freeze({
  HOME: '/var/empty',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin'
});

const fail = (message) => { throw new Error(message); };

export const designatedRequirementForTeam = (teamId, codeDirectoryHash) => {
  if (typeof teamId !== 'string' || !TEAM_ID.test(teamId)) fail('team_id is invalid');
  if (typeof codeDirectoryHash !== 'string' || !CODE_DIRECTORY_HASH.test(codeDirectoryHash)) fail('code_directory_hash is invalid');
  return `anchor apple generic and identifier "${CONTROLLER_BUNDLE_ID}" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "${teamId}" and entitlement["dev.agentpass.qualification-control"] exists and cdhash H"${codeDirectoryHash}"`;
};

const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown fields`);
  }
};

const skipWhitespace = (text, index) => {
  let cursor = index;
  while (cursor < text.length && /\s/u.test(text[cursor])) cursor += 1;
  return cursor;
};

const stringEnd = (text, index) => {
  if (text[index] !== '"') fail('identity contract contains an invalid JSON string');
  let cursor = index + 1;
  while (cursor < text.length) {
    const code = text.charCodeAt(cursor);
    if (code < 0x20) fail('identity contract contains an invalid JSON string');
    if (text[cursor] === '\\') {
      cursor += 2;
      continue;
    }
    if (text[cursor] === '"') return cursor + 1;
    cursor += 1;
  }
  fail('identity contract contains an unterminated JSON string');
};

const scanJsonValue = (text, index) => {
  let cursor = skipWhitespace(text, index);
  if (text[cursor] === '"') return stringEnd(text, cursor);
  if (text[cursor] === '{') {
    const keys = new Set();
    cursor = skipWhitespace(text, cursor + 1);
    if (text[cursor] === '}') return cursor + 1;
    while (cursor < text.length) {
      cursor = skipWhitespace(text, cursor);
      const keyStart = cursor;
      const keyEnd = stringEnd(text, cursor);
      const key = JSON.parse(text.slice(keyStart, keyEnd));
      if (keys.has(key)) fail(`identity contract contains duplicate key: ${key}`);
      keys.add(key);
      cursor = skipWhitespace(text, keyEnd);
      if (text[cursor] !== ':') fail('identity contract contains an invalid JSON object');
      cursor = scanJsonValue(text, cursor + 1);
      cursor = skipWhitespace(text, cursor);
      if (text[cursor] === '}') return cursor + 1;
      if (text[cursor] !== ',') fail('identity contract contains an invalid JSON object');
      cursor = skipWhitespace(text, cursor + 1);
      if (text[cursor] === '}') fail('identity contract contains a trailing object comma');
    }
    fail('identity contract contains an unterminated JSON object');
  }
  if (text[cursor] === '[') {
    cursor = skipWhitespace(text, cursor + 1);
    if (text[cursor] === ']') return cursor + 1;
    while (cursor < text.length) {
      cursor = scanJsonValue(text, cursor);
      cursor = skipWhitespace(text, cursor);
      if (text[cursor] === ']') return cursor + 1;
      if (text[cursor] !== ',') fail('identity contract contains an invalid JSON array');
      cursor = skipWhitespace(text, cursor + 1);
      if (text[cursor] === ']') fail('identity contract contains a trailing array comma');
    }
    fail('identity contract contains an unterminated JSON array');
  }
  const primitiveStart = cursor;
  while (cursor < text.length && !/[\s,\]}]/u.test(text[cursor])) cursor += 1;
  if (cursor === primitiveStart) fail('identity contract contains an invalid JSON value');
  return cursor;
};

const assertNoDuplicateJsonKeys = (bytes) => {
  const text = bytes.toString('utf8');
  const end = scanJsonValue(text, 0);
  if (skipWhitespace(text, end) !== text.length) fail('identity contract contains trailing JSON data');
};

const assertDigest = (value, label) => {
  if (typeof value !== 'string' || !HEX_DIGEST.test(value) || /^0+$/u.test(value)) fail(`${label} is invalid`);
  return value;
};

const assertAbsolutePath = (value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} is invalid`);
  }
  return value;
};

const statIdentity = (stat) => [
  stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.uid, stat.gid
].map((value) => value.toString()).join(':');

const assertNoFollowSupport = () => {
  if (!Number.isInteger(NOFOLLOW)) fail('O_NOFOLLOW is unavailable');
};

const readStableArchive = (input) => {
  assertNoFollowSupport();
  const archivePath = assertAbsolutePath(input, 'archive path');
  if (!CONTROLLER_ARCHIVE_NAME_PATTERN.test(basename(archivePath))) fail('archive name is not a semver universal qualification-controller archive');
  assertNoSymlinkPath(archivePath, 'archive path');

  let descriptor;
  try {
    descriptor = fs.openSync(archivePath, fs.constants.O_RDONLY | NOFOLLOW);
  } catch {
    fail('archive is unavailable');
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(MAX_ARCHIVE_BYTES) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('archive is unsafe');
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail('archive was truncated while reading');
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    let pathStat;
    try { pathStat = fs.lstatSync(archivePath, { bigint: true }); } catch { fail('archive changed while reading'); }
    if (statIdentity(before) !== statIdentity(after) || statIdentity(after) !== statIdentity(pathStat)) fail('archive changed while reading');
    return Object.freeze({
      archive_name: basename(archivePath),
      archive_sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      archive_bytes: bytes.length
    });
  } finally {
    fs.closeSync(descriptor);
  }
};

const assertNoSymlinkPath = (input, label) => {
  const target = assertAbsolutePath(input, label);
  let current = sep;
  const parts = relative(sep, target).split(sep).filter(Boolean);
  for (const part of parts) {
    current = join(current, part);
    let stat;
    try { stat = fs.lstatSync(current); } catch { fail(`${label} is unavailable`); }
    if (stat.isSymbolicLink()) fail(`${label} contains a symlink`);
    if (stat.isDirectory() && (stat.mode & 0o022) !== 0) fail(`${label} contains a writable directory`);
  }
  return target;
};

const assertProtectedDirectory = (input, label) => {
  let stat;
  try { stat = fs.lstatSync(input); } catch { fail(`${label} is unavailable`); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.nlink < 2 || (stat.mode & 0o022) !== 0) fail(`${label} is unsafe`);
  return stat;
};

const assertControllerBundle = (input) => {
  const bundlePath = assertNoSymlinkPath(input, 'controller bundle path');
  if (basename(bundlePath) !== 'AgentPassQualificationController.app') fail('controller bundle name is invalid');
  assertProtectedDirectory(bundlePath, 'controller bundle');
  const contentsPath = join(bundlePath, 'Contents');
  const macOSPath = join(contentsPath, 'MacOS');
  assertNoSymlinkPath(contentsPath, 'controller Contents path');
  assertNoSymlinkPath(macOSPath, 'controller MacOS path');
  assertProtectedDirectory(contentsPath, 'controller Contents directory');
  assertProtectedDirectory(macOSPath, 'controller MacOS directory');
  const executablePath = join(bundlePath, CONTROLLER_EXECUTABLE_RELATIVE_PATH);
  assertNoSymlinkPath(executablePath, 'controller executable path');
  const executableStat = fs.lstatSync(executablePath);
  if (!executableStat.isFile() || executableStat.isSymbolicLink() || executableStat.nlink !== 1 || (executableStat.mode & 0o111) === 0 || (executableStat.mode & 0o022) !== 0) fail('controller executable path is unsafe');
  return Object.freeze({ bundlePath, executablePath });
};

const defaultToolRunner = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    cwd: '/',
    env: FIXED_ENV,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options
  });
  if (result.error) fail(`${command} execution failed`);
  return { status: result.status, signal: result.signal, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
};

export const productionCodesignRunner = (command, args, options = {}) => {
  if (command !== '/usr/bin/codesign') fail('codesign runner permits only /usr/bin/codesign');
  return defaultToolRunner(command, args, options);
};

export const productionLipoRunner = (command, args, options = {}) => {
  if (command !== '/usr/bin/lipo') fail('lipo runner permits only /usr/bin/lipo');
  return defaultToolRunner(command, args, options);
};

const normalizeToolResult = (result, tool) => {
  if (!result || result.error || !Number.isInteger(result.status) || result.status !== 0 || result.signal) fail(`${tool} inspection failed`);
  return result;
};

const textOf = (value, label) => {
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value === undefined || value === null) return '';
  fail(`${label} output is invalid`);
};

const exactlyOneLine = (text, field, pattern) => {
  const matches = [...text.matchAll(pattern)].map((match) => match[1].trim());
  if (matches.length !== 1 || matches[0].length === 0) fail(`codesign ${field} is missing or duplicated`);
  return matches[0];
};

const entitlementBytesFromOutput = (output) => {
  const bytes = Buffer.isBuffer(output) ? output : Buffer.from(textOf(output, 'codesign entitlement'), 'utf8');
  if (bytes.length === 0 || bytes.length > MAX_ENTITLEMENT_BYTES) fail('codesign entitlements are missing or oversized');
  const xmlStart = bytes.indexOf(Buffer.from('<?xml', 'utf8'));
  const plistStart = bytes.indexOf(Buffer.from('<plist', 'utf8'));
  const start = xmlStart >= 0 && (plistStart < 0 || xmlStart < plistStart) ? xmlStart : plistStart;
  const endMarker = Buffer.from('</plist>', 'utf8');
  const end = start >= 0 ? bytes.indexOf(endMarker, start) : -1;
  if (start < 0 || end < 0) fail('codesign entitlements are not a plist');
  const endExclusive = end + endMarker.length;
  const trailing = bytes.subarray(endExclusive).toString('utf8');
  if (!/^\s*$/u.test(trailing)) fail('codesign entitlement output has trailing data');
  const plist = Buffer.from(bytes.subarray(start, endExclusive));
  if (plist.includes(0)) fail('codesign entitlements contain NUL bytes');
  return plist;
};

export const parseCodesignIdentity = ({ stdout = '', stderr = '' } = {}) => {
  const diagnostics = `${textOf(stderr, 'codesign stderr')}\n${textOf(stdout, 'codesign stdout')}`;
  const bundleId = exactlyOneLine(diagnostics, 'bundle identifier', /^Identifier=(.+)$/gmu);
  const teamId = exactlyOneLine(diagnostics, 'Team ID', /^TeamIdentifier=(.+)$/gmu);
  const codeDirectoryHash = exactlyOneLine(diagnostics, 'CodeDirectory hash', /^CDHash=([0-9a-f]{40})$/gmu);
  const designatedRequirement = exactlyOneLine(diagnostics, 'designated requirement', /^designated => (.+)$/gmu);
  const entitlementBytes = entitlementBytesFromOutput(stdout);
  if (bundleId !== CONTROLLER_BUNDLE_ID || !BUNDLE_ID.test(bundleId)) fail('codesign bundle identifier is invalid');
  if (!TEAM_ID.test(teamId)) fail('codesign Team ID is invalid');
  if (!CODE_DIRECTORY_HASH.test(codeDirectoryHash)) fail('codesign CodeDirectory hash is invalid');
  validateDesignatedRequirement(designatedRequirement, 'codesign designated requirement');
  if (designatedRequirement !== designatedRequirementForTeam(teamId, codeDirectoryHash)) fail('codesign designated requirement does not bind the exact controller identity');
  return Object.freeze({
    bundle_id: bundleId,
    team_id: teamId,
    designated_requirement: designatedRequirement,
    hash: codeDirectoryHash,
    entitlements_sha256: crypto.createHash('sha256').update(entitlementBytes).digest('hex')
  });
};

export const parseLipoArchitectures = (output) => {
  const text = textOf(output, 'lipo');
  const tokens = text.trim().split(/\s+/u).filter(Boolean);
  if (tokens.length === 0 || tokens.some((value) => !ARCHITECTURE.test(value))) fail('lipo architecture inventory is invalid');
  const unique = new Set(tokens);
  const sorted = [...tokens].sort();
  if (unique.size !== tokens.length || sorted.some((value, index) => value !== tokens[index])) fail('lipo architectures must be unique and strictly sorted');
  if (tokens.length !== CONTROLLER_ARCHITECTURES.length || tokens.some((value, index) => value !== CONTROLLER_ARCHITECTURES[index])) fail('lipo architectures are not the exact controller universal set');
  return Object.freeze(tokens);
};

const validateDesignatedRequirement = (value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim() || Buffer.byteLength(value, 'utf8') > MAX_DESIGNATED_REQUIREMENT_BYTES || /[\u0000\r\n]/u.test(value)) fail(`${label} is invalid`);
  return value;
};

const validateArchitectures = (value) => {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) fail('architectures are invalid');
  const normalized = value.map((architecture) => {
    if (typeof architecture !== 'string' || !ARCHITECTURE.test(architecture)) fail('architectures are invalid');
    return architecture;
  });
  const sorted = [...normalized].sort();
  if (new Set(normalized).size !== normalized.length || sorted.some((value, index) => value !== normalized[index])) fail('architectures must be unique and sorted');
  return Object.freeze(normalized);
};

const validateCodeDirectoryHashes = (value) => {
  if (!Array.isArray(value) || value.length !== CONTROLLER_ARCHITECTURES.length) fail('code_directory_hashes must contain the exact universal architecture set');
  const normalized = value.map((item, index) => {
    exactKeys(item, ['architecture', 'hash'], `code_directory_hashes[${index}]`);
    if (item.architecture !== CONTROLLER_ARCHITECTURES[index] || !CODE_DIRECTORY_HASH.test(item.hash)) fail('code_directory_hashes are invalid, unsorted, or substituted');
    return Object.freeze({ architecture: item.architecture, hash: item.hash });
  });
  if (new Set(normalized.map((item) => item.architecture)).size !== normalized.length) fail('code_directory_hashes contain duplicate architectures');
  return Object.freeze(normalized);
};

const validateDesignatedRequirements = (value, teamId, hashes) => {
  if (!Array.isArray(value) || value.length !== hashes.length) fail('designated_requirements must contain one exact requirement per architecture');
  const normalized = value.map((item, index) => {
    exactKeys(item, ['architecture', 'requirement'], `designated_requirements[${index}]`);
    const expectedHash = hashes[index].hash;
    if (item.architecture !== hashes[index].architecture) fail('designated_requirements are unsorted or do not match code_directory_hashes');
    validateDesignatedRequirement(item.requirement, `designated_requirements[${index}].requirement`);
    if (item.requirement !== designatedRequirementForTeam(teamId, expectedHash)) fail('designated_requirements do not bind the exact per-architecture CDHash');
    return Object.freeze({ architecture: item.architecture, requirement: item.requirement });
  });
  return Object.freeze(normalized);
};

export const validateExternalQualificationControllerIdentity = (value, { expectedTeamId } = {}) => {
  exactKeys(value, CONTRACT_FIELDS, 'external qualification controller identity');
  if (value.schema_version !== SCHEMA_VERSION || value.kind !== CONTRACT_KIND) fail('external qualification controller identity schema is invalid');
  if (!CONTROLLER_ARCHIVE_NAME_PATTERN.test(value.archive_name)) fail('archive name is invalid');
  assertDigest(value.archive_sha256, 'archive_sha256');
  if (!Number.isSafeInteger(value.archive_bytes) || value.archive_bytes <= 0 || value.archive_bytes > MAX_ARCHIVE_BYTES) fail('archive_bytes is invalid');
  if (value.bundle_id !== CONTROLLER_BUNDLE_ID || !BUNDLE_ID.test(value.bundle_id)) fail('bundle_id is invalid');
  if (typeof value.team_id !== 'string' || !TEAM_ID.test(value.team_id)) fail('team_id is invalid');
  if (expectedTeamId !== undefined && (typeof expectedTeamId !== 'string' || !TEAM_ID.test(expectedTeamId) || value.team_id !== expectedTeamId)) fail('team_id does not match the expected release');
  assertDigest(value.entitlements_sha256, 'entitlements_sha256');
  const codeDirectoryHashes = validateCodeDirectoryHashes(value.code_directory_hashes);
  const designatedRequirements = validateDesignatedRequirements(value.designated_requirements, value.team_id, codeDirectoryHashes);
  return Object.freeze({
    schema_version: SCHEMA_VERSION,
    kind: CONTRACT_KIND,
    archive_name: value.archive_name,
    archive_sha256: value.archive_sha256,
    archive_bytes: value.archive_bytes,
    bundle_id: value.bundle_id,
    team_id: value.team_id,
    entitlements_sha256: value.entitlements_sha256,
    code_directory_hashes: Object.freeze([...codeDirectoryHashes]),
    designated_requirements: Object.freeze([...designatedRequirements])
  });
};

export const canonicalExternalQualificationControllerIdentity = (value) => {
  const normalized = validateExternalQualificationControllerIdentity(value);
  return Object.freeze(Object.fromEntries(CONTRACT_FIELDS.map((field) => [field, normalized[field]])));
};

export const canonicalJSON = (value) => Buffer.from(JSON.stringify(canonicalExternalQualificationControllerIdentity(value)), 'utf8');

export const parseCanonicalExternalQualificationControllerIdentity = (bytes) => {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) fail('identity contract bytes are invalid');
  const raw = Buffer.from(bytes);
  assertNoDuplicateJsonKeys(raw);
  let value;
  try { value = JSON.parse(raw.toString('utf8')); } catch { fail('identity contract is not valid JSON'); }
  const canonical = canonicalJSON(value);
  if (!raw.equals(canonical)) fail('identity contract is not canonical JSON');
  return canonicalExternalQualificationControllerIdentity(value);
};

export const collectExternalQualificationControllerIdentity = ({
  archivePath,
  bundlePath,
  expectedTeamId,
  runCodesign = productionCodesignRunner,
  runLipo = productionLipoRunner,
  platform = process.platform
} = {}) => {
  if (platform !== 'darwin') fail('external qualification controller identity collection requires macOS');
  if (typeof runCodesign !== 'function' || typeof runLipo !== 'function') fail('codesign and lipo runners are required');
  const archive = readStableArchive(archivePath);
  const bundle = assertControllerBundle(bundlePath);
  const architecturesResult = normalizeToolResult(runLipo('/usr/bin/lipo', [
    '-archs', bundle.executablePath
  ], { cwd: dirname(bundle.bundlePath), env: FIXED_ENV, shell: false }), 'lipo');
  const architectures = parseLipoArchitectures(architecturesResult.stdout);
  const slices = architectures.map((architecture) => {
    const codesign = normalizeToolResult(runCodesign('/usr/bin/codesign', [
      '--display', '--verbose=4', '--arch', architecture, '--requirements', '-', '--entitlements', ':-', bundle.bundlePath
    ], { cwd: dirname(bundle.bundlePath), env: FIXED_ENV, shell: false }), 'codesign');
    return Object.freeze({ architecture, ...parseCodesignIdentity(codesign) });
  });
  const first = slices[0];
  if (slices.some((slice) => slice.bundle_id !== first.bundle_id || slice.team_id !== first.team_id || slice.entitlements_sha256 !== first.entitlements_sha256)) fail('per-architecture controller identities do not agree');
  if (expectedTeamId !== undefined && first.team_id !== expectedTeamId) fail('team_id does not match the expected release');
  return validateExternalQualificationControllerIdentity({
    schema_version: SCHEMA_VERSION,
    kind: CONTRACT_KIND,
    ...archive,
    bundle_id: first.bundle_id,
    team_id: first.team_id,
    entitlements_sha256: first.entitlements_sha256,
    code_directory_hashes: slices.map(({ architecture, hash }) => ({ architecture, hash })),
    designated_requirements: slices.map(({ architecture, designated_requirement }) => ({ architecture, requirement: designated_requirement }))
  }, { expectedTeamId });
};

// Short aliases keep the module convenient for release scripts without
// exposing a second schema or a second normalization path.
export const validateControllerIdentity = validateExternalQualificationControllerIdentity;
export const collectControllerIdentity = collectExternalQualificationControllerIdentity;
export const makeControllerIdentity = validateExternalQualificationControllerIdentity;
