#!/usr/bin/env node
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyRunnerAttestation } from './p0c/verify-runner-attestation.mjs';

const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_EVIDENCE_FILES = 512;
const MAX_EVIDENCE_BYTES = 256 * 1024 * 1024;
const MAX_RELEASE_DIRECTORY_BYTES = 32 * 1024 * 1024 * 1024;
const HARDWARE_CLASSES = Object.freeze(['apple_silicon', 'intel_t2']);
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RUN_ATTEMPT = RUN_ID;
const PRODUCTION_RUNNER_ATTESTATION_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const PRODUCTION_RUNNER_ATTESTATION_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const CHILD_KEYS = Object.freeze([
  'ok', 'schema_version', 'qualified', 'production', 'tests', 'gates', 'artifact_name',
  'artifact_sha256', 'source_commit', 'source_tree', 'release_manifest_sha256', 'operator_key_fingerprint',
  'operator_signature_verified', 'release_manifest_signature_verified'
]);

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const validDigest = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const validFingerprint = (value) => typeof value === 'string' && /^SHA256:[A-Za-z0-9_-]{43}$/.test(value);
const safeName = (value) => typeof value === 'string' && /^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(value) && value === basename(value);
const validateRunId = (value, label) => {
  if (typeof value !== 'string' || !RUN_ID.test(value)) throw new Error(`${label} is invalid`);
  return value;
};
const validateRunAttempt = (value, label) => {
  if (typeof value !== 'string' || !RUN_ATTEMPT.test(value)) throw new Error(`${label} is invalid`);
  return value;
};
const exactKeys = (value, keys, label) => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};
const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');

function snapshotFile(pathInput, { maximum = MAX_FILE_BYTES, capture = true, label = 'input' } = {}) {
  const path = resolve(pathInput);
  let descriptor;
  try {
    descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch {
    throw new Error(`${label} cannot be opened`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} is unsafe`);
    const size = Number(before.size);
    const hash = createHash('sha256');
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const count = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (count === 0) throw new Error(`${label} changed while reading`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`${label} changed while reading`);
    return { path, bytes: size, sha256: hash.digest('hex'), identity: statIdentity(after), content: chunks ? Buffer.concat(chunks, size) : undefined };
  } finally {
    fs.closeSync(descriptor);
  }
}

function snapshotDirectory(pathInput, label, { maximumTotalBytes = MAX_EVIDENCE_BYTES } = {}) {
  const path = resolve(pathInput);
  let descriptor;
  try {
    descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  } catch {
    throw new Error(`${label} cannot be opened`);
  }
  try {
    const directoryStat = fs.fstatSync(descriptor, { bigint: true });
    if (!directoryStat.isDirectory() || directoryStat.nlink <= 0n) throw new Error(`${label} is unsafe`);
    const entries = fs.readdirSync(path, { withFileTypes: true });
    if (entries.length > MAX_EVIDENCE_FILES) throw new Error(`${label} has too many files`);
    const files = new Map();
    let totalBytes = 0;
    for (const entry of entries.sort((left, right) => lexicalCompare(left.name, right.name))) {
      if (!safeName(entry.name) || !entry.isFile() || entry.isSymbolicLink()) throw new Error(`${label} contains an unsafe entry`);
      const snapshot = snapshotFile(join(path, entry.name), { maximum: MAX_FILE_BYTES, capture: false, label: `${label} file` });
      totalBytes += snapshot.bytes;
      if (totalBytes > maximumTotalBytes) throw new Error(`${label} is too large`);
      files.set(entry.name, snapshot);
    }
    return { path, identity: statIdentity(directoryStat), files };
  } finally {
    fs.closeSync(descriptor);
  }
}

function compareSnapshot(before, after, label) {
  if (before.identity !== after.identity || before.bytes !== after.bytes || before.sha256 !== after.sha256) throw new Error(`${label} changed during validation`);
}

function compareDirectorySnapshot(before, after, label) {
  if (before.identity !== after.identity || before.files.size !== after.files.size) throw new Error(`${label} changed during validation`);
  for (const [name, snapshot] of before.files) {
    const current = after.files.get(name);
    if (!current) throw new Error(`${label} changed during validation`);
    compareSnapshot(snapshot, current, `${label} file`);
  }
}

function readCanonicalJSON(snapshot, label) {
  let value;
  try { value = JSON.parse(snapshot.content.toString('utf8')); } catch { throw new Error(`${label} is not valid JSON`); }
  if (!snapshot.content.equals(canonicalJSON(value))) throw new Error(`${label} is not canonical JSON`);
  return value;
}

function validateOperatorPolicy(snapshot) {
  const policy = readCanonicalJSON(snapshot, 'approved operator policy');
  exactKeys(policy, ['schema_version', 'operators'], 'approved operator policy');
  if (policy.schema_version !== 1 || !Array.isArray(policy.operators) || policy.operators.length === 0 || policy.operators.length > 1024) throw new Error('approved operator policy is invalid');
  let previousFingerprint = '';
  const entries = [];
  const classesSeen = new Set();
  for (const item of policy.operators) {
    exactKeys(item, ['operator', 'fingerprint', 'hardware_classes'], 'approved operator');
    if (typeof item.operator !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9@._-]{2,127}$/.test(item.operator) || !validFingerprint(item.fingerprint) || lexicalCompare(item.fingerprint, previousFingerprint) <= 0) throw new Error('approved operator policy is not canonical or sorted');
    if (!Array.isArray(item.hardware_classes) || item.hardware_classes.length === 0 || item.hardware_classes.some((value) => !HARDWARE_CLASSES.includes(value)) || new Set(item.hardware_classes).size !== item.hardware_classes.length || item.hardware_classes.some((value, index) => index > 0 && lexicalCompare(item.hardware_classes[index - 1], value) >= 0)) throw new Error('approved operator hardware classes are invalid');
    for (const hardwareClass of item.hardware_classes) classesSeen.add(hardwareClass);
    previousFingerprint = item.fingerprint;
    entries.push(Object.freeze({ operator: item.operator, fingerprint: item.fingerprint, hardware_classes: Object.freeze([...item.hardware_classes]) }));
  }
  for (const hardwareClass of HARDWARE_CLASSES) if (!classesSeen.has(hardwareClass)) throw new Error(`approved operator policy lacks ${hardwareClass}`);
  return Object.freeze({ schema_version: 1, operators: Object.freeze(entries), sha256: snapshot.sha256 });
}

function publicKeyFingerprint(publicKey) {
  return `SHA256:${createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
}

function validateOperatorPolicySignature(policySnapshot, signatureSnapshot, publicKeySnapshot, expectedFingerprint) {
  if (!signatureSnapshot || !publicKeySnapshot || !validFingerprint(expectedFingerprint)) throw new Error('approved operator policy signature binding is required');
  const publicKey = (() => { try { return createPublicKey(publicKeySnapshot.content); } catch { throw new Error('approved operator policy public key is invalid'); } })();
  if (publicKey.asymmetricKeyType !== 'ed25519' || publicKeyFingerprint(publicKey) !== expectedFingerprint) throw new Error('approved operator policy public key fingerprint mismatch');
  const encoded = signatureSnapshot.content.toString('utf8');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) throw new Error('approved operator policy signature encoding is invalid');
  const signature = Buffer.from(encoded.trim(), 'base64');
  if (signature.length !== 64 || !verify(null, policySnapshot.content, publicKey, signature)) throw new Error('approved operator policy signature is invalid');
  return expectedFingerprint;
}

function validateReport(snapshot, expectedClass) {
  const report = readCanonicalJSON(snapshot, `${expectedClass} report`);
  if (report.schema_version !== 2 || report.qualified !== true || report.hardware_class !== expectedClass) throw new Error(`${expectedClass} report is not a qualified v2 report`);
  if (expectedClass === 'apple_silicon' && report.architecture !== 'arm64') throw new Error('apple_silicon report has the wrong architecture');
  if (expectedClass === 'intel_t2' && report.architecture !== 'x86_64') throw new Error('intel_t2 report has the wrong architecture');
  if (report.secure_enclave !== true || typeof report.source_commit !== 'string' || !/^[0-9a-f]{40}$/.test(report.source_commit) || typeof report.source_tree !== 'string' || !/^[0-9a-f]{40}$/.test(report.source_tree)) throw new Error(`${expectedClass} report has invalid binding fields`);
  for (const field of ['release_manifest_sha256', 'artifact_sha256', 'dependency_lock_sha256', 'database_migration_manifest_sha256']) if (!validDigest(report[field])) throw new Error(`${expectedClass} report has invalid ${field}`);
  if (typeof report.artifact_name !== 'string' || !safeName(report.artifact_name) || typeof report.team_id !== 'string' || typeof report.cloud_image_digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(report.cloud_image_digest) || !Array.isArray(report.signer_key_versions)) throw new Error(`${expectedClass} report has invalid binding fields`);
  if (typeof report.operator !== 'string' || !validFingerprint(report.operator_key_fingerprint)) throw new Error(`${expectedClass} report has invalid operator identity`);
  for (const resultList of [report.tests, report.gates]) {
    if (!Array.isArray(resultList) || resultList.length === 0 || resultList.some((item) => !item || item.status !== 'passed' || !Array.isArray(item.evidence) || item.evidence.length === 0)) throw new Error(`${expectedClass} report contains failed or skipped results`);
  }
  return report;
}

function validateChildSummary(stdout, expectedClass, report) {
  let summary;
  try { summary = JSON.parse(String(stdout).trim()); } catch { throw new Error(`${expectedClass} validator returned invalid JSON`); }
  exactKeys(summary, CHILD_KEYS, `${expectedClass} validator result`);
  if (summary.ok !== true || summary.schema_version !== 2 || summary.qualified !== true || summary.production !== true || summary.operator_signature_verified !== true || summary.release_manifest_signature_verified !== true || summary.artifact_name !== report.artifact_name || summary.artifact_sha256 !== report.artifact_sha256 || summary.source_commit !== report.source_commit || summary.source_tree !== report.source_tree || summary.release_manifest_sha256 !== report.release_manifest_sha256 || summary.operator_key_fingerprint !== report.operator_key_fingerprint) throw new Error(`${expectedClass} validator did not prove the qualified report`);
  return summary;
}

function runValidatorChild({ validatorPath, args }) {
  const result = spawnSync(process.execPath, [validatorPath, ...args], {
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
    killSignal: 'SIGKILL',
    maxBuffer: MAX_OUTPUT_BYTES
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout ?? '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr ?? '');
  if (stdout.length > MAX_OUTPUT_BYTES || stderr.length > MAX_OUTPUT_BYTES || result.error || result.status !== 0) throw new Error('hardware qualification child validator failed');
  return { stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') };
}

function normalizeInputs(inputs) {
  const normalized = {
    releaseManifest: resolve(inputs.releaseManifest),
    releaseManifestSignature: resolve(inputs.releaseManifestSignature),
    releaseManifestPublicKey: resolve(inputs.releaseManifestPublicKey),
    releaseManifestFingerprint: inputs.releaseManifestFingerprint,
    artifact: resolve(inputs.artifact),
    approvedOperatorPolicy: resolve(inputs.approvedOperatorPolicy),
    approvedOperatorPolicySignature: inputs.approvedOperatorPolicySignature ? resolve(inputs.approvedOperatorPolicySignature) : null,
    approvedOperatorPolicyPublicKey: inputs.approvedOperatorPolicyPublicKey ? resolve(inputs.approvedOperatorPolicyPublicKey) : null,
    approvedOperatorPolicyFingerprint: inputs.approvedOperatorPolicyFingerprint ?? null,
    appleSilicon: { ...inputs.appleSilicon },
    intelT2: { ...inputs.intelT2 }
  };
  for (const hardwareClass of HARDWARE_CLASSES) {
    const lane = normalized[hardwareClass === 'apple_silicon' ? 'appleSilicon' : 'intelT2'];
    for (const field of ['report', 'signature', 'operatorPublicKey', 'evidenceDirectory']) lane[field] = resolve(lane[field]);
    for (const field of ['runnerAttestation', 'runnerAttestationSignature', 'runnerAttestationPublicKey']) lane[field] = lane[field] ? resolve(lane[field]) : null;
    lane.runnerAttestationFingerprint = lane.runnerAttestationFingerprint ?? null;
    lane.runnerId = lane.runnerId ?? null;
    if (!validFingerprint(lane.operatorFingerprint)) throw new Error(`${hardwareClass} operator fingerprint is invalid`);
  }
  if (!validFingerprint(normalized.releaseManifestFingerprint)) throw new Error('release manifest fingerprint is invalid');
  return normalized;
}

function snapshotInputs(inputs) {
  const manifestDirectory = dirname(inputs.releaseManifest);
  const snapshots = {
    releaseManifest: snapshotFile(inputs.releaseManifest, { maximum: MAX_JSON_BYTES, label: 'release manifest' }),
    releaseManifestSignature: snapshotFile(inputs.releaseManifestSignature, { maximum: 1024, label: 'release manifest signature' }),
    releaseManifestPublicKey: snapshotFile(inputs.releaseManifestPublicKey, { maximum: 16 * 1024, label: 'release manifest public key' }),
    artifact: snapshotFile(inputs.artifact, { maximum: MAX_FILE_BYTES, label: 'product artifact' }),
    approvedOperatorPolicy: snapshotFile(inputs.approvedOperatorPolicy, { maximum: MAX_JSON_BYTES, label: 'approved operator policy' }),
    approvedOperatorPolicySignature: inputs.approvedOperatorPolicySignature ? snapshotFile(inputs.approvedOperatorPolicySignature, { maximum: 1024, label: 'approved operator policy signature' }) : null,
    approvedOperatorPolicyPublicKey: inputs.approvedOperatorPolicyPublicKey ? snapshotFile(inputs.approvedOperatorPolicyPublicKey, { maximum: 16 * 1024, label: 'approved operator policy public key' }) : null,
    manifestDirectory: snapshotDirectory(manifestDirectory, 'release manifest directory', { maximumTotalBytes: MAX_RELEASE_DIRECTORY_BYTES }),
    lanes: {}
  };
  for (const [hardwareClass, key] of [['apple_silicon', 'appleSilicon'], ['intel_t2', 'intelT2']]) {
    const lane = inputs[key];
    snapshots.lanes[hardwareClass] = {
      report: snapshotFile(lane.report, { maximum: MAX_JSON_BYTES, label: `${hardwareClass} report` }),
      signature: snapshotFile(lane.signature, { maximum: 1024, label: `${hardwareClass} report signature` }),
      operatorPublicKey: snapshotFile(lane.operatorPublicKey, { maximum: 16 * 1024, label: `${hardwareClass} operator public key` }),
      evidenceDirectory: snapshotDirectory(lane.evidenceDirectory, `${hardwareClass} evidence directory`),
      runnerAttestation: lane.runnerAttestation ? snapshotFile(lane.runnerAttestation, { maximum: MAX_JSON_BYTES, label: `${hardwareClass} runner attestation` }) : null,
      runnerAttestationSignature: lane.runnerAttestationSignature ? snapshotFile(lane.runnerAttestationSignature, { maximum: 1024, label: `${hardwareClass} runner attestation signature` }) : null,
      runnerAttestationPublicKey: lane.runnerAttestationPublicKey ? snapshotFile(lane.runnerAttestationPublicKey, { maximum: 16 * 1024, label: `${hardwareClass} runner attestation public key` }) : null
    };
  }
  return snapshots;
}

function assertInputsUnchanged(inputs, before) {
  const after = snapshotInputs(inputs);
  for (const key of ['releaseManifest', 'releaseManifestSignature', 'releaseManifestPublicKey', 'artifact', 'approvedOperatorPolicy']) compareSnapshot(before[key], after[key], key);
  if (before.approvedOperatorPolicySignature) compareSnapshot(before.approvedOperatorPolicySignature, after.approvedOperatorPolicySignature, 'approved operator policy signature');
  if (before.approvedOperatorPolicyPublicKey) compareSnapshot(before.approvedOperatorPolicyPublicKey, after.approvedOperatorPolicyPublicKey, 'approved operator policy public key');
  compareDirectorySnapshot(before.manifestDirectory, after.manifestDirectory, 'release manifest directory');
  for (const hardwareClass of HARDWARE_CLASSES) {
    const beforeLane = before.lanes[hardwareClass];
    const afterLane = after.lanes[hardwareClass];
    for (const key of ['report', 'signature', 'operatorPublicKey', 'runnerAttestation', 'runnerAttestationSignature', 'runnerAttestationPublicKey']) if (beforeLane[key]) compareSnapshot(beforeLane[key], afterLane[key], `${hardwareClass} ${key}`);
    compareDirectorySnapshot(beforeLane.evidenceDirectory, afterLane.evidenceDirectory, `${hardwareClass} evidence directory`);
  }
}

function normalizeRunBinding(value) {
  if (value === undefined || value === null) return null;
  exactKeys(value, ['release_run_id', 'release_run_attempt', 'qualification_run_id', 'qualification_run_attempt'], 'qualification run binding');
  const releaseRunId = validateRunId(value.release_run_id, 'release run ID');
  const releaseRunAttempt = validateRunAttempt(value.release_run_attempt, 'release run attempt');
  const qualificationRunId = validateRunId(value.qualification_run_id, 'qualification run ID');
  const qualificationRunAttempt = validateRunAttempt(value.qualification_run_attempt, 'qualification run attempt');
  if (releaseRunId === qualificationRunId) throw new Error('release and qualification run IDs must be distinct');
  return Object.freeze({ release_run_id: releaseRunId, release_run_attempt: releaseRunAttempt, qualification_run_id: qualificationRunId, qualification_run_attempt: qualificationRunAttempt });
}

function assertRunnerAttestationFreshness(attestation, { nowMs, maximumAgeMs, maximumFutureSkewMs }) {
  if (maximumAgeMs === undefined && maximumFutureSkewMs === undefined) return;
  const now = nowMs ?? Date.now();
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(maximumAgeMs) || maximumAgeMs <= 0 || !Number.isSafeInteger(maximumFutureSkewMs) || maximumFutureSkewMs < 0) throw new Error('runner attestation freshness policy is invalid');
  const attestedAt = Date.parse(attestation.attested_at);
  if (!Number.isFinite(attestedAt) || now - attestedAt > maximumAgeMs) throw new Error('runner attestation is stale');
  if (attestedAt - now > maximumFutureSkewMs) throw new Error('runner attestation is from the future');
}

function childArgs(inputs, lane) {
  return [lane.report, '--require-qualified', inputs.artifact, inputs.releaseManifest, inputs.releaseManifestSignature, inputs.releaseManifestPublicKey, inputs.releaseManifestFingerprint, lane.signature, lane.operatorPublicKey, lane.operatorFingerprint, lane.evidenceDirectory];
}

export function verifyHardwareQualificationSet(rawInputs, dependencies = {}) {
  const inputs = normalizeInputs(rawInputs);
  const runBinding = normalizeRunBinding(dependencies.runBinding);
  if (dependencies.requireRunBinding === true && runBinding === null) throw new Error('qualification run binding is required');
  const before = snapshotInputs(inputs);
  if (dependencies.requirePolicySignature === true || before.approvedOperatorPolicySignature || before.approvedOperatorPolicyPublicKey || inputs.approvedOperatorPolicyFingerprint) {
    validateOperatorPolicySignature(before.approvedOperatorPolicy, before.approvedOperatorPolicySignature, before.approvedOperatorPolicyPublicKey, inputs.approvedOperatorPolicyFingerprint);
  }
  const policy = validateOperatorPolicy(before.approvedOperatorPolicy);
  const reports = {};
  const summaries = {};
  const runnerAttestations = {};
  const validatorPath = dependencies.validatorPath ?? resolve(dirname(fileURLToPath(import.meta.url)), 'validate-hardware-qualification.mjs');
  const runChild = dependencies.runValidator ?? ((args) => runValidatorChild({ validatorPath, args }));
  for (const [hardwareClass, key] of [['apple_silicon', 'appleSilicon'], ['intel_t2', 'intelT2']]) {
    const lane = inputs[key];
    const report = validateReport(before.lanes[hardwareClass].report, hardwareClass);
    const child = runChild(childArgs(inputs, lane), hardwareClass);
    summaries[hardwareClass] = validateChildSummary(child.stdout ?? child, hardwareClass, report);
    const hasRunnerAttestation = lane.runnerAttestation && lane.runnerAttestationSignature && lane.runnerAttestationPublicKey && validFingerprint(lane.runnerAttestationFingerprint) && typeof lane.runnerId === 'string';
    if (dependencies.requireRunnerAttestation === true && !hasRunnerAttestation) throw new Error(`${hardwareClass} runner attestation binding is required`);
    if (hasRunnerAttestation) {
      runnerAttestations[hardwareClass] = verifyRunnerAttestation({
        attestation: lane.runnerAttestation,
        signature: lane.runnerAttestationSignature,
        publicKey: lane.runnerAttestationPublicKey,
        fingerprint: lane.runnerAttestationFingerprint,
        expectedArchitecture: hardwareClass === 'apple_silicon' ? 'arm64' : 'x86_64',
        expectedHardwareClass: hardwareClass,
        expectedRunnerId: lane.runnerId,
        production: false
      });
      assertRunnerAttestationFreshness(runnerAttestations[hardwareClass], {
        nowMs: dependencies.attestationNowMs,
        maximumAgeMs: dependencies.maxRunnerAttestationAgeMs,
        maximumFutureSkewMs: dependencies.maxRunnerAttestationFutureSkewMs
      });
      runnerAttestations[hardwareClass] = Object.freeze({
        ...runnerAttestations[hardwareClass],
        report_sha256: before.lanes[hardwareClass].report.sha256
      });
      if (runnerAttestations[hardwareClass].attestation_sha256 !== before.lanes[hardwareClass].runnerAttestation.sha256) throw new Error(`${hardwareClass} runner attestation digest changed during validation`);
    }
    const approved = policy.operators.some((item) => item.operator === report.operator && item.fingerprint === lane.operatorFingerprint && item.fingerprint === report.operator_key_fingerprint && item.hardware_classes.includes(hardwareClass));
    if (!approved) throw new Error(`${hardwareClass} operator is not approved by the external policy`);
    reports[hardwareClass] = report;
  }
  assertInputsUnchanged(inputs, before);
  const apple = reports.apple_silicon;
  const intel = reports.intel_t2;
  const sharedFields = ['source_commit', 'source_tree', 'release_manifest_sha256', 'artifact_name', 'artifact_sha256', 'dependency_lock_sha256', 'team_id', 'cloud_image_digest', 'database_migration_manifest_sha256', 'signer_key_versions'];
  for (const field of sharedFields) if (JSON.stringify(apple[field]) !== JSON.stringify(intel[field])) throw new Error(`hardware reports disagree on ${field}`);
  if (before.lanes.apple_silicon.report.sha256 === before.lanes.intel_t2.report.sha256) throw new Error('hardware reports must be distinct');
  if (before.artifact.sha256 !== apple.artifact_sha256 || before.artifact.sha256 !== intel.artifact_sha256 || before.artifact.bytes <= 0) throw new Error('qualified reports do not bind the exact product artifact');
  const summary = {
    schema_version: 1,
    ok: true,
    qualified: true,
    production: true,
    classes: [...HARDWARE_CLASSES],
    artifact_name: apple.artifact_name,
    artifact_sha256: before.artifact.sha256,
    source_commit: apple.source_commit,
    source_tree: apple.source_tree,
    release_manifest_sha256: apple.release_manifest_sha256,
    team_id: apple.team_id,
    cloud_image_digest: apple.cloud_image_digest,
    database_migration_manifest_sha256: apple.database_migration_manifest_sha256,
    signer_key_versions: apple.signer_key_versions,
    report_sha256: { apple_silicon: before.lanes.apple_silicon.report.sha256, intel_t2: before.lanes.intel_t2.report.sha256 },
    operator_key_fingerprint: { apple_silicon: apple.operator_key_fingerprint, intel_t2: intel.operator_key_fingerprint },
    approved_operator_policy_sha256: policy.sha256,
    ...(runBinding ? { run_binding: runBinding } : {}),
    ...(Object.keys(runnerAttestations).length === 2 ? { runner_attestation: runnerAttestations } : {})
  };
  return Object.freeze({ summary });
}

function parseCLI(argv) {
  if (argv.length !== 33) throw new Error('Usage: verify-hardware-qualification-set.mjs RELEASE-MANIFEST RELEASE-SIGNATURE RELEASE-PUBLIC-KEY RELEASE-FINGERPRINT PRODUCT-PKG APPLE-REPORT APPLE-REPORT-SIGNATURE APPLE-OPERATOR-PUBLIC-KEY APPLE-OPERATOR-FINGERPRINT APPLE-EVIDENCE-DIR APPLE-RUNNER-ATTESTATION APPLE-RUNNER-ATTESTATION-SIGNATURE APPLE-RUNNER-ATTESTATION-PUBLIC-KEY APPLE-RUNNER-ATTESTATION-FINGERPRINT APPLE-RUNNER-ID INTEL-T2-REPORT INTEL-T2-REPORT-SIGNATURE INTEL-T2-OPERATOR-PUBLIC-KEY INTEL-T2-OPERATOR-FINGERPRINT INTEL-T2-EVIDENCE-DIR INTEL-RUNNER-ATTESTATION INTEL-RUNNER-ATTESTATION-SIGNATURE INTEL-RUNNER-ATTESTATION-PUBLIC-KEY INTEL-RUNNER-ATTESTATION-FINGERPRINT INTEL-RUNNER-ID APPROVED-OPERATOR-POLICY.json APPROVED-OPERATOR-POLICY-SIGNATURE APPROVED-OPERATOR-PUBLIC-KEY APPROVED-OPERATOR-POLICY-FINGERPRINT RELEASE-RUN-ID RELEASE-RUN-ATTEMPT QUALIFICATION-RUN-ID QUALIFICATION-RUN-ATTEMPT');
  return {
    releaseManifest: argv[0], releaseManifestSignature: argv[1], releaseManifestPublicKey: argv[2], releaseManifestFingerprint: argv[3], artifact: argv[4],
    appleSilicon: { report: argv[5], signature: argv[6], operatorPublicKey: argv[7], operatorFingerprint: argv[8], evidenceDirectory: argv[9], runnerAttestation: argv[10], runnerAttestationSignature: argv[11], runnerAttestationPublicKey: argv[12], runnerAttestationFingerprint: argv[13], runnerId: argv[14] },
    intelT2: { report: argv[15], signature: argv[16], operatorPublicKey: argv[17], operatorFingerprint: argv[18], evidenceDirectory: argv[19], runnerAttestation: argv[20], runnerAttestationSignature: argv[21], runnerAttestationPublicKey: argv[22], runnerAttestationFingerprint: argv[23], runnerId: argv[24] },
    approvedOperatorPolicy: argv[25], approvedOperatorPolicySignature: argv[26], approvedOperatorPolicyPublicKey: argv[27], approvedOperatorPolicyFingerprint: argv[28],
    runBinding: { release_run_id: argv[29], release_run_attempt: argv[30], qualification_run_id: argv[31], qualification_run_attempt: argv[32] }
  };
}

export { canonicalJSON, parseCLI, runValidatorChild, snapshotFile, snapshotDirectory };

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = verifyHardwareQualificationSet(parseCLI(process.argv.slice(2)), {
      requirePolicySignature: true,
      requireRunnerAttestation: true,
      requireRunBinding: true,
      maxRunnerAttestationAgeMs: PRODUCTION_RUNNER_ATTESTATION_MAX_AGE_MS,
      maxRunnerAttestationFutureSkewMs: PRODUCTION_RUNNER_ATTESTATION_MAX_FUTURE_SKEW_MS
    });
    process.stdout.write(`${JSON.stringify(result.summary, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'hardware qualification set verification failed'}\n`);
    process.exitCode = 1;
  }
}
