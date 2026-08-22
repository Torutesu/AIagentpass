import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { canonicalJSON, parseCLI, verifyHardwareQualificationSet } from '../scripts/release/verify-hardware-qualification-set.mjs';

const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
const fingerprint = (key) => `SHA256:${hash(key.export({ type: 'spki', format: 'der' })).slice(0, 43)}`;
const makeReport = (hardwareClass, operator, operatorFingerprint, shared, directory, index) => {
  const evidence = join(directory, `${hardwareClass}-${index}.txt`);
  writeFileSync(evidence, `${hardwareClass} qualification evidence\n`, { mode: 0o600 });
  const result = (name) => ({ name, status: 'passed', evidence: [{ name: `${hardwareClass}-${index}.txt`, bytes: fs.statSync(evidence).size, sha256: hash(fs.readFileSync(evidence)) }] });
  return {
    schema_version: 2, source_commit: shared.source_commit, source_tree: shared.source_tree, dependency_lock_sha256: shared.dependency_lock_sha256,
    release_manifest_sha256: shared.release_manifest_sha256, artifact_name: shared.artifact_name, artifact_sha256: shared.artifact_sha256,
    architecture: hardwareClass === 'apple_silicon' ? 'arm64' : 'x86_64', hardware_class: hardwareClass,
    model_identifier: hardwareClass === 'apple_silicon' ? 'Mac15,7' : 'Macmini9,1', macos_version: '26.0.1', macos_build: '25A100', secure_enclave: true,
    team_id: shared.team_id, cloud_image_digest: shared.cloud_image_digest, database_migration_manifest_sha256: shared.database_migration_manifest_sha256,
    signer_key_versions: shared.signer_key_versions, browser_versions: [{ name: 'chromium', version: '151.0.1' }],
    nested_code_identities: [], started_at: '2026-08-13T00:00:00.000Z', completed_at: '2026-08-13T00:10:00.000Z',
    operator, operator_key_fingerprint: operatorFingerprint, qualified: true, tests: [result('exact-pkg-install')], gates: [result('gatekeeper-notarization')]
  };
};

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'agentpass-p0c-set-'));
  const releaseDir = join(root, 'release'); const appleEvidence = join(root, 'apple-evidence'); const intelEvidence = join(root, 'intel-evidence');
  fs.mkdirSync(releaseDir); fs.mkdirSync(appleEvidence); fs.mkdirSync(intelEvidence);
  const artifact = Buffer.from('exact notarized package fixture\n'); const artifactPath = join(releaseDir, 'AgentPass-v0.18.0-macos-universal.pkg'); writeFileSync(artifactPath, artifact);
  const manifest = Buffer.from('{}\n'); const manifestPath = join(releaseDir, 'release-manifest.json'); writeFileSync(manifestPath, manifest);
  const manifestSignaturePath = join(root, 'release.sig'); const manifestPublicKey = crypto.generateKeyPairSync('ed25519'); writeFileSync(manifestSignaturePath, 'stub\n'); const manifestPublicKeyPath = join(root, 'release.pub'); writeFileSync(manifestPublicKeyPath, 'stub\n');
  const appleKey = crypto.generateKeyPairSync('ed25519'); const intelKey = crypto.generateKeyPairSync('ed25519');
  const appleFingerprint = fingerprint(appleKey.publicKey); const intelFingerprint = fingerprint(intelKey.publicKey);
  const shared = { source_commit: 'a'.repeat(40), source_tree: 'e'.repeat(40), dependency_lock_sha256: 'b'.repeat(64), release_manifest_sha256: hash(manifest), artifact_name: 'AgentPass-v0.18.0-macos-universal.pkg', artifact_sha256: hash(artifact), team_id: 'TEAMID1234', cloud_image_digest: `sha256:${'c'.repeat(64)}`, database_migration_manifest_sha256: 'd'.repeat(64), signer_key_versions: [{ name: 'capability', version: 'cap-1' }] };
  const apple = makeReport('apple_silicon', 'apple@example.com', appleFingerprint, shared, appleEvidence, 1); const intel = makeReport('intel_t2', 'intel@example.com', intelFingerprint, shared, intelEvidence, 2);
  const applePath = join(root, 'apple.json'); const intelPath = join(root, 'intel.json'); writeFileSync(applePath, canonicalJSON(apple)); writeFileSync(intelPath, canonicalJSON(intel));
  const policyOperators = [{ operator: 'apple@example.com', fingerprint: appleFingerprint, hardware_classes: ['apple_silicon'] }, { operator: 'intel@example.com', fingerprint: intelFingerprint, hardware_classes: ['intel_t2'] }].sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  const policy = { schema_version: 1, operators: policyOperators };
  const policyPath = join(root, 'policy.json'); writeFileSync(policyPath, canonicalJSON(policy));
  const inputs = { releaseManifest: manifestPath, releaseManifestSignature: manifestSignaturePath, releaseManifestPublicKey: manifestPublicKeyPath, releaseManifestFingerprint: 'SHA256:' + 'a'.repeat(43), artifact: artifactPath, appleSilicon: { report: applePath, signature: join(root, 'apple.sig'), operatorPublicKey: join(root, 'apple.pub'), operatorFingerprint: appleFingerprint, evidenceDirectory: appleEvidence }, intelT2: { report: intelPath, signature: join(root, 'intel.sig'), operatorPublicKey: join(root, 'intel.pub'), operatorFingerprint: intelFingerprint, evidenceDirectory: intelEvidence }, approvedOperatorPolicy: policyPath };
  for (const name of ['apple.sig', 'apple.pub', 'intel.sig', 'intel.pub']) writeFileSync(join(root, name), 'stub\n');
  return { root, inputs, reports: { apple, intel }, policyPath, artifactPath, applePath, intelPath };
}

const childPass = (fixtureValue) => (_args, hardwareClass) => {
  const report = fixtureValue.reports[hardwareClass === 'apple_silicon' ? 'apple' : 'intel'];
  return { stdout: JSON.stringify({ ok: true, schema_version: 2, qualified: true, production: true, tests: 1, gates: 1, artifact_name: report.artifact_name, artifact_sha256: report.artifact_sha256, source_commit: report.source_commit, source_tree: report.source_tree, release_manifest_sha256: report.release_manifest_sha256, operator_key_fingerprint: report.operator_key_fingerprint, operator_signature_verified: true, release_manifest_signature_verified: true }) };
};

const makeRunnerAttestation = (root, hardwareClass, runnerId, attestedAt) => {
  const key = crypto.generateKeyPairSync('ed25519');
  const value = {
    schema_version: 1,
    kind: 'agentpass.macos.protected-runner-attestation',
    runner_id: runnerId,
    architecture: hardwareClass === 'apple_silicon' ? 'arm64' : 'x86_64',
    hardware_class: hardwareClass,
    model_identifier: hardwareClass === 'apple_silicon' ? 'Mac15,7' : 'Macmini9,1',
    native_execution: true,
    vm_detected: false,
    rosetta_detected: false,
    attested_at: new Date(attestedAt).toISOString()
  };
  const payload = canonicalJSON(value);
  const publicKey = key.publicKey.export({ type: 'spki', format: 'pem' });
  const publicKeyFingerprint = `SHA256:${crypto.createHash('sha256').update(key.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  const write = (name, bytes) => { const path = join(root, name); writeFileSync(path, bytes, { mode: 0o600 }); return path; };
  return {
    runnerAttestation: write(`${hardwareClass}.runner.json`, payload),
    runnerAttestationSignature: write(`${hardwareClass}.runner.sig`, `${crypto.sign(null, payload, key.privateKey).toString('base64')}\n`),
    runnerAttestationPublicKey: write(`${hardwareClass}.runner.pem`, publicKey),
    runnerAttestationFingerprint: publicKeyFingerprint,
    runnerId
  };
};

test('promotes two distinct, independently approved hardware reports', () => {
  const value = fixture();
  const result = verifyHardwareQualificationSet(value.inputs, { runValidator: childPass(value) });
  assert.equal(result.summary.production, true);
  assert.deepEqual(result.summary.classes, ['apple_silicon', 'intel_t2']);
  assert.equal(result.summary.artifact_sha256, hash(fs.readFileSync(value.artifactPath)));
});

test('rejects artifact mismatch', () => {
  const value = fixture(); value.inputs.artifact = join(value.root, 'wrong.pkg'); writeFileSync(value.inputs.artifact, 'wrong\n');
  assert.throws(() => verifyHardwareQualificationSet(value.inputs, { runValidator: childPass(value) }), /exact product artifact/);
});

test('rejects swapped class and same report', () => {
  const swapped = fixture(); const appleReport = JSON.parse(fs.readFileSync(swapped.applePath)); appleReport.hardware_class = 'intel_t2'; appleReport.architecture = 'x86_64'; writeFileSync(swapped.applePath, canonicalJSON(appleReport));
  assert.throws(() => verifyHardwareQualificationSet(swapped.inputs, { runValidator: childPass(swapped) }), /apple_silicon report/);
  const same = fixture(); same.inputs.intelT2.report = same.inputs.appleSilicon.report; same.inputs.intelT2.signature = same.inputs.appleSilicon.signature; same.inputs.intelT2.operatorPublicKey = same.inputs.appleSilicon.operatorPublicKey; same.inputs.intelT2.operatorFingerprint = same.inputs.appleSilicon.operatorFingerprint; same.inputs.intelT2.evidenceDirectory = same.inputs.appleSilicon.evidenceDirectory;
  assert.throws(() => verifyHardwareQualificationSet(same.inputs, { runValidator: childPass(same) }), /intel_t2 report|distinct/);
});

test('rejects an operator not approved for the report class', () => {
  const value = fixture(); const policy = JSON.parse(fs.readFileSync(value.policyPath)); for (const item of policy.operators) item.hardware_classes = item.operator === 'apple@example.com' ? ['intel_t2'] : ['apple_silicon']; policy.operators.sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)); writeFileSync(value.policyPath, canonicalJSON(policy));
  assert.throws(() => verifyHardwareQualificationSet(value.inputs, { runValidator: childPass(value) }), /not approved/);
});

test('fails closed when the child validator fails', () => {
  const value = fixture();
  assert.throws(() => verifyHardwareQualificationSet(value.inputs, { runValidator: () => { throw new Error('child failure'); } }), /child failure/);
});

test('production policy signature binding rejects unsigned, substituted, and wrong-key policy inputs', () => {
  const value = fixture();
  const policyKey = crypto.generateKeyPairSync('ed25519');
  const policyBytes = fs.readFileSync(value.policyPath);
  const signaturePath = join(value.root, 'policy.sig');
  const publicKeyPath = join(value.root, 'policy.pub');
  writeFileSync(signaturePath, `${crypto.sign(null, policyBytes, policyKey.privateKey).toString('base64')}\n`);
  writeFileSync(publicKeyPath, policyKey.publicKey.export({ type: 'spki', format: 'pem' }));
  const policyFingerprint = `SHA256:${crypto.createHash('sha256').update(policyKey.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  const signedInputs = { ...value.inputs, approvedOperatorPolicySignature: signaturePath, approvedOperatorPolicyPublicKey: publicKeyPath, approvedOperatorPolicyFingerprint: policyFingerprint };
  assert.equal(verifyHardwareQualificationSet(signedInputs, { runValidator: childPass(value), requirePolicySignature: true }).summary.production, true);
  const wrongKey = crypto.generateKeyPairSync('ed25519');
  writeFileSync(publicKeyPath, wrongKey.publicKey.export({ type: 'spki', format: 'pem' }));
  assert.throws(() => verifyHardwareQualificationSet(signedInputs, { runValidator: childPass(value), requirePolicySignature: true }), /fingerprint mismatch/);
  assert.throws(() => verifyHardwareQualificationSet(value.inputs, { runValidator: childPass(value), requirePolicySignature: true }), /signature binding is required/);
});

test('runner attestations are explicitly bound to each signed report digest and qualification run binding', () => {
  const value = fixture();
  const now = Date.parse('2026-08-21T12:00:00.000Z');
  const appleRunner = makeRunnerAttestation(value.root, 'apple_silicon', 'p0c-apple-01', now);
  const intelRunner = makeRunnerAttestation(value.root, 'intel_t2', 'p0c-intel-01', now);
  const inputs = {
    ...value.inputs,
    appleSilicon: { ...value.inputs.appleSilicon, ...appleRunner },
    intelT2: { ...value.inputs.intelT2, ...intelRunner }
  };
  const result = verifyHardwareQualificationSet(inputs, {
    runValidator: childPass(value),
    requireRunnerAttestation: true,
    requireRunBinding: true,
    runBinding: { release_run_id: '1001', release_run_attempt: '2', qualification_run_id: '1002', qualification_run_attempt: '1' },
    attestationNowMs: now,
    maxRunnerAttestationAgeMs: 24 * 60 * 60 * 1000,
    maxRunnerAttestationFutureSkewMs: 5 * 60 * 1000
  });
  assert.deepEqual(result.summary.run_binding, { release_run_id: '1001', release_run_attempt: '2', qualification_run_id: '1002', qualification_run_attempt: '1' });
  assert.equal(result.summary.runner_attestation.apple_silicon.report_sha256, hash(fs.readFileSync(value.applePath)));
  assert.equal(result.summary.runner_attestation.intel_t2.report_sha256, hash(fs.readFileSync(value.intelPath)));
  assert.equal(result.summary.runner_attestation.apple_silicon.runner_id, 'p0c-apple-01');
  assert.equal(result.summary.runner_attestation.intel_t2.runner_id, 'p0c-intel-01');
});

test('runner attestation freshness rejects stale and future-signed payloads', () => {
  const now = Date.parse('2026-08-21T12:00:00.000Z');
  const stale = fixture();
  const staleRunner = makeRunnerAttestation(stale.root, 'apple_silicon', 'p0c-apple-01', now - (2 * 24 * 60 * 60 * 1000));
  const staleIntelRunner = makeRunnerAttestation(stale.root, 'intel_t2', 'p0c-intel-01', now);
  const staleInputs = { ...stale.inputs, appleSilicon: { ...stale.inputs.appleSilicon, ...staleRunner }, intelT2: { ...stale.inputs.intelT2, ...staleIntelRunner } };
  assert.throws(() => verifyHardwareQualificationSet(staleInputs, { runValidator: childPass(stale), requireRunnerAttestation: true, attestationNowMs: now, maxRunnerAttestationAgeMs: 24 * 60 * 60 * 1000, maxRunnerAttestationFutureSkewMs: 5 * 60 * 1000 }), /stale/);

  const future = fixture();
  const futureRunner = makeRunnerAttestation(future.root, 'apple_silicon', 'p0c-apple-01', now + (6 * 60 * 1000));
  const futureIntelRunner = makeRunnerAttestation(future.root, 'intel_t2', 'p0c-intel-01', now);
  const futureInputs = { ...future.inputs, appleSilicon: { ...future.inputs.appleSilicon, ...futureRunner }, intelT2: { ...future.inputs.intelT2, ...futureIntelRunner } };
  assert.throws(() => verifyHardwareQualificationSet(futureInputs, { runValidator: childPass(future), requireRunnerAttestation: true, attestationNowMs: now, maxRunnerAttestationAgeMs: 24 * 60 * 60 * 1000, maxRunnerAttestationFutureSkewMs: 5 * 60 * 1000 }), /future/);
});

test('production CLI positional contract keeps policy and run-binding arguments after both lane blocks', () => {
  const argv = Array.from({ length: 33 }, (_, index) => `arg-${index}`);
  const parsed = parseCLI(argv);
  assert.equal(parsed.appleSilicon.runnerAttestation, 'arg-10');
  assert.equal(parsed.appleSilicon.runnerId, 'arg-14');
  assert.equal(parsed.intelT2.runnerAttestation, 'arg-20');
  assert.equal(parsed.intelT2.runnerId, 'arg-24');
  assert.equal(parsed.approvedOperatorPolicy, 'arg-25');
  assert.deepEqual(parsed.runBinding, { release_run_id: 'arg-29', release_run_attempt: 'arg-30', qualification_run_id: 'arg-31', qualification_run_attempt: 'arg-32' });
  assert.throws(() => parseCLI(argv.slice(0, 32)), /Usage:/);
});
