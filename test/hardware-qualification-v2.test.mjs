import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const root = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const validator = join(root, 'scripts/release/validate-hardware-qualification.mjs');
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');
const fingerprint = (key) => `SHA256:${crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
const writeSignature = (path, bytes, privateKey) => writeFileSync(path, `${crypto.sign(null, bytes, privateKey).toString('base64')}\n`);
const run = (args) => spawnSync(process.execPath, [validator, ...args], { encoding: 'utf8' });

const makeFixture = () => {
  const dir = mkdtempSync(join(tmpdir(), 'agentpass-hardware-v2-'));
  const evidenceDir = join(dir, 'qualification-evidence'); fs.mkdirSync(evidenceDir);
  const releaseDir = join(dir, 'release'); fs.mkdirSync(releaseDir);
  const sourceCommit = 'a'.repeat(40); const sourceTree = 'b'.repeat(40);
  const teamID = 'TEAMID1234';
  const nestedCodeIdentities = [
    { path: 'AgentPass.app', bundle_id: 'dev.agentpass', team_id: teamID, code_directory_hash: 'a'.repeat(40) },
    { path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', bundle_id: 'dev.agentpass.native-client', team_id: teamID, code_directory_hash: 'b'.repeat(40) },
    { path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', bundle_id: 'dev.agentpass.native-service', team_id: teamID, code_directory_hash: 'c'.repeat(40) },
    { path: 'AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', bundle_id: 'dev.agentpass.atomic-rename', team_id: teamID, code_directory_hash: 'd'.repeat(40) },
    { path: 'AgentPass.app/Contents/MacOS/agentpass-native-manager', bundle_id: 'dev.agentpass.native-manager', team_id: teamID, code_directory_hash: 'e'.repeat(40) },
    { path: 'AgentPass.app/Contents/MacOS/agentpass-onboarding', bundle_id: 'dev.agentpass', team_id: teamID, code_directory_hash: 'f'.repeat(40) }
  ];
  const signerKeyVersions = [{ name: 'capability', version: 'cap-2026-08' }, { name: 'receipt', version: 'receipt-2026-08' }];
  const browserVersions = [{ name: 'chromium', version: '151.0.7922.34' }];
  const cloudImageDigest = `sha256:${'d'.repeat(64)}`;
  const migrationContent = Buffer.from('{"schema_version":1,"migration":"0011"}\n');
  const lockContent = Buffer.from('{"name":"agentpass","lockfileVersion":3}\n');
  const productContent = Buffer.from('signed notarized AgentPass package fixture\n');
  const sbomContent = Buffer.from(canonical({ spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT', documentNamespace: 'https://github.com/Torutesu/Agentpass/sbom/fixture', documentDescribes: ['SPDXRef-AgentPass'], packages: [] }));
  const attestation = { schema_version: 1, team_id: teamID, nested_code_identities: nestedCodeIdentities, cloud_image_digest: cloudImageDigest, dependency_lock_sha256: digest(lockContent), database_migration_manifest_sha256: digest(migrationContent), signer_key_versions: signerKeyVersions };
  const files = {
    'AgentPass-0.18.0-macos-universal.pkg': productContent,
    'AgentPass-0.18.0.spdx.json': sbomContent,
    'database-migration-manifest.json': migrationContent,
    'package-lock.json': lockContent,
    'release-attestation.json': Buffer.from(canonical(attestation))
  };
  const artifactMeta = [];
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(releaseDir, name), content);
    artifactMeta.push({ name, role: name.endsWith('.pkg') ? 'product' : name.endsWith('.spdx.json') ? 'sbom' : 'auxiliary', media_type: name.endsWith('.spdx.json') ? 'application/spdx+json' : name.endsWith('.pkg') ? 'application/vnd.apple.installer+xml' : 'application/json', bytes: content.length, sha256: digest(content) });
  }
  artifactMeta.sort((left, right) => left.name.localeCompare(right.name));
  const notaryResult = Buffer.from(canonical({ status: 'Accepted', id: '12345678-1234-1234-1234-123456789abc' }));
  const staplerResult = Buffer.from('The validate action worked!\n');
  writeFileSync(join(releaseDir, 'notarytool-result.json'), notaryResult); writeFileSync(join(releaseDir, 'stapler-result.txt'), staplerResult);
  const notaryEvidence = [
    { kind: 'notarytool_result', name: 'notarytool-result.json', bytes: notaryResult.length, sha256: digest(notaryResult) },
    { kind: 'stapler_result', name: 'stapler-result.txt', bytes: staplerResult.length, sha256: digest(staplerResult) }
  ];
  const checksumEntries = [...artifactMeta, ...notaryEvidence].sort((left, right) => left.name.localeCompare(right.name));
  const checksumContent = Buffer.from(`${checksumEntries.map((item) => `${item.sha256}  ${item.name}`).join('\n')}\n`);
  writeFileSync(join(releaseDir, 'SHA256SUMS'), checksumContent);
  const manifest = {
    schema_version: 2, product: 'AgentPass', version: '0.18.0', source: { commit: sourceCommit, tree: sourceTree, tag: null }, generated_at: '2026-08-13T00:00:00.000Z', artifacts: artifactMeta,
    evidence: {
      checksums: { name: 'SHA256SUMS', bytes: checksumContent.length, sha256: digest(checksumContent), entry_count: checksumEntries.length },
      sbom: { artifact_name: 'AgentPass-0.18.0.spdx.json', sha256: digest(sbomContent), spdx_version: 'SPDX-2.3', document_namespace: 'https://github.com/Torutesu/Agentpass/sbom/fixture', document_spdx_id: 'SPDXRef-DOCUMENT', document_describes: ['SPDXRef-AgentPass'], source_commit: sourceCommit, source_tree: sourceTree },
      notarization: { status: 'accepted_stapled', submission_ids: ['12345678-1234-1234-1234-123456789abc'], evidence: notaryEvidence }
    }
  };
  const manifestBytes = Buffer.from(canonical(manifest));
  const releaseKeys = crypto.generateKeyPairSync('ed25519');
  const manifestPath = join(releaseDir, 'release-manifest.json'); const manifestSignaturePath = join(releaseDir, 'release-manifest.sig'); const manifestPublicKeyPath = join(releaseDir, 'release-public.pem');
  writeFileSync(manifestPath, manifestBytes); writeSignature(manifestSignaturePath, manifestBytes, releaseKeys.privateKey); writeFileSync(manifestPublicKeyPath, releaseKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  const operatorKeys = crypto.generateKeyPairSync('ed25519');
  const operatorSignaturePath = join(dir, 'operator.sig'); const operatorPublicKeyPath = join(dir, 'operator-public.pem');
  const requiredGates = ['gatekeeper-notarization', 'clean-install-launchd-xpc', 'secure-enclave-enrollment', 'cloud-possession-verification', 'claude-code-unattended-sign', 'cursor-unattended-sign', 'audit-upload-observation', 'policy-reduction-refresh-ack', 'offline-expiry', 'revoke-emergency-stop', 'crash-restart-recovery', 'sleep-wake-network-clock', 'upgrade-preserves-state', 'uninstall-reinstall-recovery', 'current-user-purge', 'negative-identity-and-entitlement-cases'];
  const gates = requiredGates.map((name, index) => { const evidence = { name: `gate-${String(index).padStart(2, '0')}.txt`, bytes: Buffer.byteLength(`${name} passed\n`), sha256: digest(Buffer.from(`${name} passed\n`)) }; writeFileSync(join(evidenceDir, evidence.name), `${name} passed\n`); return { name, status: 'passed', evidence: [evidence] }; });
  const requiredTests = ['exact-pkg-install', 'launchd-xpc-approval', 'secure-enclave-key-creation', 'secure-enclave-nonexportability', 'cloud-possession-proof', 'claude-code-unattended-sign', 'cursor-unattended-sign', 'unrelated-process-denied', 'audit-console-observation', 'policy-reduction-denied', 'offline-expiry-denied', 'revoke-denied', 'emergency-stop-denied', 'service-crash-recovery', 'os-reboot-recovery', 'sleep-wake-recovery', 'network-clock-failure', 'upgrade-preserves-state', 'uninstall-reinstall-recovery', 'current-user-purge'];
  const tests = requiredTests.map((name, index) => { const content = Buffer.from(`${name} passed\n`); const evidence = { name: `test-${String(index).padStart(2, '0')}.txt`, bytes: content.length, sha256: digest(content) }; writeFileSync(join(evidenceDir, evidence.name), content); return { name, status: 'passed', evidence: [evidence] }; });
  const report = { schema_version: 2, source_commit: sourceCommit, dependency_lock_sha256: digest(lockContent), release_manifest_sha256: digest(manifestBytes), artifact_name: 'AgentPass-0.18.0-macos-universal.pkg', artifact_sha256: digest(productContent), architecture: 'arm64', hardware_class: 'apple_silicon', model_identifier: 'Mac15,7', macos_version: '26.0.1', macos_build: '25A100', secure_enclave: true, team_id: teamID, nested_code_identities: nestedCodeIdentities, notarization: manifest.evidence.notarization, cloud_image_digest: cloudImageDigest, database_migration_manifest_sha256: digest(migrationContent), signer_key_versions: signerKeyVersions, browser_versions: browserVersions, started_at: '2026-08-13T00:00:00.000Z', completed_at: '2026-08-13T00:10:00.000Z', operator: 'qualification@example.com', operator_key_fingerprint: fingerprint(operatorKeys.publicKey), qualified: true, tests, gates };
  const reportPath = join(dir, 'qualification.json'); writeFileSync(reportPath, canonical(report)); writeSignature(operatorSignaturePath, Buffer.from(canonical(report)), operatorKeys.privateKey); writeFileSync(operatorPublicKeyPath, operatorKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  return { dir, evidenceDir, releaseDir, report, reportPath, manifestPath, manifestSignaturePath, manifestPublicKeyPath, operatorSignaturePath, operatorPublicKeyPath, operatorPrivateKey: operatorKeys.privateKey, artifactPath: join(releaseDir, 'AgentPass-0.18.0-macos-universal.pkg'), releaseFingerprint: fingerprint(releaseKeys.publicKey), operatorFingerprint: fingerprint(operatorKeys.publicKey) };
};

const argsFor = (fixture) => [fixture.reportPath, fixture.artifactPath, fixture.manifestPath, fixture.manifestSignaturePath, fixture.manifestPublicKeyPath, fixture.releaseFingerprint, fixture.operatorSignaturePath, fixture.operatorPublicKeyPath, fixture.operatorFingerprint, fixture.evidenceDir];

test('v2 accepts a qualified report only when the exact signed release and real evidence bind', () => {
  const fixture = makeFixture();
  const result = run(argsFor(fixture));
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.deepEqual({ qualified: output.qualified, production: output.production, release_manifest_signature_verified: output.release_manifest_signature_verified, operator_signature_verified: output.operator_signature_verified }, { qualified: true, production: true, release_manifest_signature_verified: true, operator_signature_verified: true });
  assert.equal(output.artifact_name, fixture.report.artifact_name);
  assert.equal(output.source_commit, fixture.report.source_commit);
});

test('v2 rejects artifact, manifest, provenance, signature, and evidence substitutions', () => {
  const fixture = makeFixture();
  const otherArtifact = join(fixture.dir, 'other.pkg'); writeFileSync(otherArtifact, 'different artifact');
  let result = run([...argsFor(fixture).slice(0, 1), otherArtifact, ...argsFor(fixture).slice(2)]);
  assert.notEqual(result.status, 0); assert.match(result.stderr, /exact product artifact|artifact/);

  const changedReport = { ...fixture.report, dependency_lock_sha256: 'e'.repeat(64) };
  const changedReportPath = join(fixture.dir, 'changed-report.json'); writeFileSync(changedReportPath, canonical(changedReport));
  const changedReportArgs = argsFor(fixture); changedReportArgs[0] = changedReportPath; writeSignature(fixture.operatorSignaturePath, Buffer.from(canonical(changedReport)), fixture.operatorPrivateKey);
  result = run(changedReportArgs); assert.notEqual(result.status, 0); assert.match(result.stderr, /digest|attestation/);

  const missingEvidence = join(fixture.evidenceDir, fixture.report.tests[0].evidence[0].name); fs.unlinkSync(missingEvidence);
  result = run(argsFor(fixture)); assert.notEqual(result.status, 0); assert.match(result.stderr, /evidence|ENOENT/);
});

test('v2 refuses self-asserted qualification and keeps v1 non-production only', () => {
  const fixture = makeFixture();
  const unsigned = run([fixture.reportPath]); assert.notEqual(unsigned.status, 0); assert.match(unsigned.stderr, /signed release manifest|detached operator signature/);
  const v1 = join(fixture.dir, 'v1.json'); writeFileSync(v1, canonical({ schema_version: 1, artifact_sha256: '0'.repeat(64), architecture: 'arm64', hardware_class: 'apple_silicon', model_identifier: 'Mac15,7', macos_version: '26.0', macos_build: '25A100', secure_enclave: true, started_at: '2026-08-13T00:00:00.000Z', completed_at: '2026-08-13T00:01:00.000Z', operator: 'legacy@example.com', qualified: false, tests: [] }));
  const legacy = run([v1]); assert.equal(legacy.status, 0, legacy.stderr); assert.deepEqual(JSON.parse(legacy.stdout), { ok: true, schema_version: 1, qualified: false, production: false, backwards_compatible: true });
  const template = run([join(root, 'scripts/release/hardware-qualification.template.json')]); assert.equal(template.status, 0, template.stderr); assert.equal(JSON.parse(template.stdout).qualified, false);
});
