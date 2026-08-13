import fs from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

export const QUALIFICATION_RELEASE_TRUST_SCHEMA_VERSION = 1;
export const QUALIFICATION_RELEASE_TRUST_KIND = 'agentpass-n3e-qualification-release-trust';
export const FIXED_QUALIFICATION_ROOT = '/private/var/db/agentpass-qualification';
export const FIXED_QUALIFICATION_RELEASE_DIRECTORY = `${FIXED_QUALIFICATION_ROOT}/release`;
export const FIXED_QUALIFICATION_RELEASE_TRUST_PATH = `${FIXED_QUALIFICATION_ROOT}/release-trust.json`;
export const FIXED_CANDIDATE_CHECKPOINT_PATH = `${FIXED_QUALIFICATION_ROOT}/candidate-checkpoint.json`;
export const QUALIFICATION_RELEASE_TRUST_MAX_BYTES = 32 * 1024;

const TRUST_KEYS = Object.freeze([
  'artifact_sha256',
  'candidate_checkpoint_sha256',
  'expected_fingerprint',
  'kind',
  'manifest_name',
  'product_name',
  'public_key_name',
  'run_binding_name',
  'schema_version',
  'signature_name',
  'source_commit',
  'team_id'
]);
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const NOFOLLOW = fs.constants.O_NOFOLLOW;

const fail = (message) => { throw new Error(message); };

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} is not closed`);
};

const canonical = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const protectedDirectory = (input, { fileSystem, production, expectedUid }) => {
  const path = resolve(input);
  let current = path;
  for (;;) {
    let stat;
    try { stat = fileSystem.lstatSync(current, { bigint: true }); } catch { fail('qualification release trust directory is unavailable'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022n) !== 0n || (production && stat.uid !== BigInt(expectedUid)) || (current === path && (stat.mode & 0o7777n) !== 0o700n)) fail('qualification release trust directory is unsafe');
    if (current === '/') break;
    current = dirname(current);
  }
  let real;
  try { real = resolve(fileSystem.realpathSync(path)); } catch { fail('qualification release trust directory is unavailable'); }
  if (real !== path) fail('qualification release trust directory is unsafe');
  return path;
};

const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.uid, stat.gid].map(String).join(':');

const readProtected = (path, { fileSystem, production, expectedUid, maximum }) => {
  protectedDirectory(dirname(path), { fileSystem, production, expectedUid });
  let descriptor;
  try { descriptor = fileSystem.openSync(path, fileSystem.constants.O_RDONLY | NOFOLLOW); } catch { fail('qualification release trust is unavailable'); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o7777n) !== 0o600n || before.size <= 0n || before.size > BigInt(maximum)) fail('qualification release trust is unsafe');
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail('qualification release trust changed while reading');
      offset += count;
    }
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    const current = fileSystem.lstatSync(path, { bigint: true });
    if (identity(before) !== identity(after) || identity(after) !== identity(current)) fail('qualification release trust changed while reading');
    return bytes;
  } finally { fileSystem.closeSync(descriptor); }
};

const validateName = (value, label) => {
  if (typeof value !== 'string' || !SAFE_NAME.test(value) || basename(value) !== value || value === '.' || value === '..') fail(`${label} is invalid`);
  return value;
};

export const normalizeQualificationReleaseTrust = (value) => {
  exactKeys(value, TRUST_KEYS, 'qualification release trust');
  if (value.schema_version !== QUALIFICATION_RELEASE_TRUST_SCHEMA_VERSION || value.kind !== QUALIFICATION_RELEASE_TRUST_KIND) fail('qualification release trust identity is invalid');
  if (!DIGEST.test(value.artifact_sha256) || !DIGEST.test(value.candidate_checkpoint_sha256) || !COMMIT.test(value.source_commit) || !TEAM_ID.test(value.team_id) || !FINGERPRINT.test(value.expected_fingerprint)) fail('qualification release trust binding is invalid');
  const names = {
    manifest_name: validateName(value.manifest_name, 'qualification release manifest name'),
    signature_name: validateName(value.signature_name, 'qualification release signature name'),
    public_key_name: validateName(value.public_key_name, 'qualification release public key name'),
    product_name: validateName(value.product_name, 'qualification release product name'),
    run_binding_name: validateName(value.run_binding_name, 'qualification run binding name')
  };
  if (names.run_binding_name !== 'run-binding') fail('qualification run binding name is not fixed');
  if (new Set(Object.values(names)).size !== Object.keys(names).length) fail('qualification release trust names are not unique');
  return Object.freeze({
    schema_version: QUALIFICATION_RELEASE_TRUST_SCHEMA_VERSION,
    artifact_sha256: value.artifact_sha256,
    candidate_checkpoint_sha256: value.candidate_checkpoint_sha256,
    expected_fingerprint: value.expected_fingerprint,
    kind: QUALIFICATION_RELEASE_TRUST_KIND,
    manifest_name: names.manifest_name,
    product_name: names.product_name,
    public_key_name: names.public_key_name,
    run_binding_name: names.run_binding_name,
    signature_name: names.signature_name,
    source_commit: value.source_commit,
    team_id: value.team_id
  });
};

export const parseQualificationReleaseTrust = (bytes) => {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > QUALIFICATION_RELEASE_TRUST_MAX_BYTES) fail('qualification release trust document is invalid');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); } catch { fail('qualification release trust document is invalid'); }
  const normalized = normalizeQualificationReleaseTrust(value);
  if (!bytes.equals(canonical(normalized))) fail('qualification release trust is not canonical');
  return normalized;
};

export const resolveQualificationReleaseTrust = ({
  checkpoint,
  fileSystem = fs,
  trustPath = FIXED_QUALIFICATION_RELEASE_TRUST_PATH,
  releaseDirectory = FIXED_QUALIFICATION_RELEASE_DIRECTORY,
  expectedUid = 0,
  platform = process.platform,
  uid = process.getuid?.(),
  production = true
} = {}) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || trustPath !== FIXED_QUALIFICATION_RELEASE_TRUST_PATH || releaseDirectory !== FIXED_QUALIFICATION_RELEASE_DIRECTORY)) fail('qualification release trust requires root on macOS and fixed paths');
  if (!production && uid !== expectedUid) fail('qualification release trust requires the expected owner');
  if (!isAbsolute(trustPath) || resolve(trustPath) !== trustPath || !isAbsolute(releaseDirectory) || resolve(releaseDirectory) !== releaseDirectory) fail('qualification release trust path is invalid');
  protectedDirectory(releaseDirectory, { fileSystem, production, expectedUid });
  const trust = parseQualificationReleaseTrust(readProtected(trustPath, { fileSystem, production, expectedUid, maximum: QUALIFICATION_RELEASE_TRUST_MAX_BYTES }));
  if (!checkpoint || checkpoint.checkpoint_sha256 !== trust.candidate_checkpoint_sha256 || checkpoint.artifact_sha256 !== trust.artifact_sha256 || checkpoint.source_commit !== trust.source_commit || checkpoint.team_id !== trust.team_id) fail('qualification release trust does not match the candidate checkpoint');
  const pathFor = (name) => {
    const path = join(releaseDirectory, name);
    if (dirname(path) !== releaseDirectory) fail('qualification release trust path escaped the fixed directory');
    return path;
  };
  return Object.freeze({
    manifestPath: pathFor(trust.manifest_name),
    signaturePath: pathFor(trust.signature_name),
    publicKeyPath: pathFor(trust.public_key_name),
    expectedFingerprint: trust.expected_fingerprint,
    productPath: pathFor(trust.product_name),
    runBindingPath: pathFor(trust.run_binding_name),
    expectedArtifactSha256: trust.artifact_sha256,
    expectedSourceCommit: trust.source_commit,
    expectedTeamId: trust.team_id,
    trust
  });
};
