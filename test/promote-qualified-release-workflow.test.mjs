import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import { parse } from 'yaml';

const root = resolve(import.meta.dirname, '..');
const workflow = readFileSync(resolve(root, '.github/workflows/promote-qualified-release.yml'), 'utf8');

const job = (name) => {
  const start = workflow.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing job: ${name}`);
  const next = workflow.slice(start + 1).search(/^  [A-Za-z0-9_-]+:/m);
  return workflow.slice(start, next === -1 ? workflow.length : start + 1 + next);
};

const promote = job('promote');
const step = (name) => {
  const nameOffset = [name, `'${name}'`, `"${name}"`]
    .map((value) => promote.indexOf(`name: ${value}`))
    .find((offset) => offset !== -1);
  assert.notEqual(nameOffset, -1, `missing step: ${name}`);
  const start = promote.lastIndexOf('      - ', nameOffset);
  assert.notEqual(start, -1, `missing step heading: ${name}`);
  const after = promote.slice(start);
  const next = after.slice(1).search(/^      - /m);
  return after.slice(0, next === -1 ? after.length : next + 1);
};

const stringArray = (source, name) => {
  const match = source.match(new RegExp(`const ${name} = \\[([\\s\\S]*?)\\];`, 'u'));
  assert.ok(match, `missing explicit ${name} inventory`);
  return [...match[1].matchAll(/'([^']+)'/gu)].map(([, value]) => value);
};

test('promotion workflow YAML parses with unique keys', () => {
  const parsed = parse(workflow, { uniqueKeys: true });
  assert.equal(parsed.name, 'Promote qualified release');
  assert.ok(parsed.jobs?.promote);
  assert.ok(parsed.jobs.promote.steps?.length > 0);
});

test('promotion is manual-dispatch only, canonical-main only, and protected with no secret inputs', () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/m);
  for (const event of ['push', 'pull_request', 'pull_request_target', 'repository_dispatch', 'workflow_call', 'schedule', 'workflow_run']) {
    assert.doesNotMatch(workflow, new RegExp(`^\\s{2}${event}:`, 'm'), `unexpected trigger: ${event}`);
  }
  assert.match(promote, /if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.repository == 'Torutesu\/AIagentpass' && github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(promote, /runs-on: macos-15/);
  assert.match(promote, /environment: production-release/);
  assert.match(promote, /permissions:\n      contents: write\n      actions: read/);
  assert.doesNotMatch(workflow, /secrets\./, 'promotion must not consume signing, notary, or operator private secrets');
  assert.doesNotMatch(workflow, /pull_request(?:_target)?:/);
  assert.doesNotMatch(workflow, /^\s{6}PROMOTION_ROOT: \$\{\{ runner\.temp \}\}/mu,
    'runner context is not available in job-level env');
  assert.match(workflow, /PROMOTION_ROOT="\$RUNNER_TEMP\/agentpass-qualified-promotion-\$\{GITHUB_RUN_ID\}-\$\{GITHUB_RUN_ATTEMPT\}"/u,
    'promotion material must be rooted in the runtime-provided protected temporary directory');
});

test('all actions are immutable SHAs and only trusted built-in actions are used', () => {
  const uses = [...workflow.matchAll(/uses:\s*([^\s]+)/g)].map(([, value]) => value);
  assert.equal(uses.length, 8, 'expected checkout, setup-node, and six exact artifact downloads');
  for (const use of uses) {
    assert.match(use, /^actions\/(?:checkout|setup-node|download-artifact)@[0-9a-f]{40}$/);
  }
  assert.doesNotMatch(workflow, /@[vV][0-9]/);
  assert.doesNotMatch(workflow, /^\s*-\s+uses:\s+(?!actions\/)/m);
});

test('inputs identify exact runs and preflight validates both runs and every artifact through the API', () => {
  assert.match(workflow, /release_run_id:\n\s+description: Successful Release candidate workflow run ID/);
  assert.match(workflow, /qualification_run_id:\n\s+description: Successful P0-C hardware qualification workflow run ID/);
  assert.match(workflow, /preflight_run_id:\n\s+description: Successful Release preflight workflow run ID/);
  const preflight = step('Validate exact successful source and qualification runs through the GitHub API');
  assert.match(preflight, /RELEASE_RUN_ID" =~ \^\[1-9\]\[0-9\]\{0,18\}\$/);
  assert.match(preflight, /QUALIFICATION_RUN_ID" =~ \^\[1-9\]\[0-9\]\{0,18\}\$/);
  assert.match(preflight, /actions\/runs\/\$RELEASE_RUN_ID/);
  assert.match(preflight, /actions\/runs\/\$QUALIFICATION_RUN_ID/);
  assert.match(preflight, /actions\/runs\/\$RELEASE_RUN_ID\/artifacts/);
  assert.match(preflight, /actions\/runs\/\$QUALIFICATION_RUN_ID\/artifacts/);
  assert.match(preflight, /actions\/runs\/\$PREFLIGHT_RUN_ID\/artifacts/);
  assert.match(preflight, /\.name == "Release preflight"/);
  assert.match(preflight, /\.path == "\.github\/workflows\/release-preflight\.yml"/);
  assert.match(preflight, /release-preflight-result-\$\{release_head_sha\}-\$\{PREFLIGHT_RUN_ID\}-\$\{preflight_run_attempt\}/);
  for (const expected of [
    '.name == "Release candidate"',
    '.path == ".github/workflows/release-candidate.yml"',
    '.name == "P0-C hardware qualification"',
    '.path == ".github/workflows/p0c-hardware-qualification.yml"',
    '.event == "workflow_dispatch"',
    '.status == "completed"',
    '.conclusion == "success"',
    '.head_branch == "main"',
    '.head_repository.full_name == $repo'
  ]) assert.match(preflight, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(preflight, /aggregate job therefore emits a canonical\n\s+# dispatch binding/);
  assert.match(preflight, /both signed\n\s+# reports' exact artifact\/manifest bindings/);
  for (const artifact of ['EXPECTED_CANDIDATE_ARTIFACT', 'EXPECTED_APPLE_ARTIFACT', 'EXPECTED_INTEL_ARTIFACT', 'EXPECTED_SUMMARY_ARTIFACT']) assert.match(preflight, new RegExp(`\\$${artifact}`));
});

test('downloads preflight, candidate, release integrity, and all three P0-C artifacts from exact runs', () => {
  const downloads = [...promote.matchAll(/uses: actions\/download-artifact@[0-9a-f]{40}[\s\S]*?(?=\n\n      - uses:|\n\n      - id:|\n\n      - name:|$)/g)].map((match) => match[0]);
  assert.equal(downloads.length, 6);
  const preflight = downloads.find((value) => value.includes('preflight_artifact_name'));
  assert.ok(preflight, 'missing release preflight result download');
  assert.match(preflight, /run-id: \$\{\{ steps\.preflight\.outputs\.preflight_run_id \}\}/);
  const candidate = downloads.find((value) => value.includes('name: notarized-release-candidate'));
  assert.ok(candidate, 'missing candidate download');
  assert.match(candidate, /run-id: \$\{\{ steps\.preflight\.outputs\.release_run_id \}\}/);
  const integrity = downloads.find((value) => value.includes('name: release-integrity-evidence'));
  assert.ok(integrity, 'missing release integrity evidence download');
  assert.match(integrity, /run-id: \$\{\{ steps\.preflight\.outputs\.release_run_id \}\}/);
  for (const [name, output] of [['p0c-hardware-apple-silicon', 'qualification_run_id'], ['p0c-hardware-intel-t2', 'qualification_run_id'], ['p0c-hardware-qualification-summary', 'qualification_run_id']]) {
    const found = downloads.find((value) => value.includes(`name: ${name}`));
    assert.ok(found, `missing download for ${name}`);
    assert.match(found, new RegExp(`run-id: \\$\\{\\{ steps\\.preflight\\.outputs\\.${output} \\}\\}`));
    assert.match(found, /repository: Torutesu\/AIagentpass/);
  }
  const catalog = step('Catalog only the exact downloaded candidate and qualification evidence');
  for (const name of ['release-manifest.json', 'release-manifest.sig', 'release-manifest.public.pem', 'report.json', 'report.sig', 'operator-public.pem', 'runner-attestation.payload.json', 'runner-attestation.sig', 'runner-attestation.pem', 'qualification-summary.json', 'qualification-dispatch-binding.json']) assert.match(catalog, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(catalog, /candidate artifact contains unexpected or missing files/);
  assert.match(catalog, /qualification artifact has unexpected files/);
});

test('recomputes GitHub artifact archive digests after download-artifact and binds each archive to source/tree', () => {
  const provenance = step('Recompute every downloaded GitHub artifact archive digest');
  assert.match(provenance, /actions\/artifacts\/\$artifact_id\/zip/u);
  assert.match(provenance, /artifact-provenance\.mjs archive/u);
  assert.match(provenance, /SOURCE_COMMIT/u);
  assert.match(provenance, /SOURCE_TREE/u);
  assert.equal((provenance.match(/fetch_and_verify /g) ?? []).length, 5);
  assert.match(provenance, /PREFLIGHT_ARTIFACTS/);
  assert.match(provenance, /release-preflight-artifact\.metadata\.json/);
  assert.match(provenance, /release-preflight-artifact\.zip/);
  assert.match(provenance, /release-preflight-artifact-provenance\.json/);
  assert.match(provenance, /artifact_id/);
  assert.match(provenance, /digest/);
  assert.match(promote, /downloaded-artifact-provenance\.json/);
});

test('aggregate downloaded-artifact provenance inventories all six downloaded archives, including preflight', () => {
  const provenance = step('Recompute every downloaded GitHub artifact archive digest');
  const namesStart = provenance.indexOf('const names = [');
  const namesEnd = provenance.indexOf('];', namesStart);
  assert.ok(namesStart >= 0 && namesEnd > namesStart, 'missing aggregate downloaded-artifact inventory');
  const names = provenance.slice(namesStart, namesEnd);
  for (const name of ['EXPECTED_CANDIDATE_ARTIFACT', 'EXPECTED_INTEGRITY_ARTIFACT', 'EXPECTED_APPLE_ARTIFACT', 'EXPECTED_INTEL_ARTIFACT', 'EXPECTED_SUMMARY_ARTIFACT', 'PREFLIGHT_ARTIFACT_NAME']) {
    assert.match(names, new RegExp(name, 'u'), `downloaded-artifact provenance is missing ${name}`);
  }
});

test('promotion generates an API-bound external run binding with exact jobs, runner identities, and archive digests', () => {
  const binding = step('Revalidate the external qualification API run and generate its binding');
  for (const value of [
    'actions/runs/$EXTERNAL_QUALIFICATION_RUN_ID',
    'actions/runs/$EXTERNAL_QUALIFICATION_RUN_ID/jobs?per_page=100',
    'actions/runs/$EXTERNAL_QUALIFICATION_RUN_ID/artifacts?per_page=100',
    'git/commits/$EXPECTED_SOURCE_COMMIT',
    'external-qualification-provenance-',
    'runner_id',
    'runner_name',
    'source_tree',
    'run_attempt',
    'workflow_run',
    'digest',
    'archive_sha256',
    'evidence_sha256',
    'external-qualification-run-binding.json',
    'external-qualification-provenance.json',
    'O_EXCL',
    'archive-secret-scan.mjs'
  ]) assert.match(binding, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const job of ['validate', 'kms', 'platform-auth', 'webauthn', 'postgres-authority-16', 'postgres-authority-17', 'postgres-gate', 'external-qualification-provenance']) {
    assert.match(binding, new RegExp(`'${job}'`, 'u'));
  }
  assert.match(binding, /jobsEnvelope\.total_count/);
  assert.match(binding, /artifactsEnvelope\.total_count/);
  assert.match(binding, /external qualification job inventory is missing a required job/);
  assert.match(binding, /external artifact inventory is missing a required artifact/);
});

test('promotion requires canonical, passed, exact-SHA KMS and Platform Auth evidence without changing the existing artifact download contract', () => {
  const catalog = step('Catalog only the exact downloaded candidate and qualification evidence');
  const evidence = step('Verify canonical KMS and Platform Auth qualification evidence for the exact release SHA');
  assert.match(catalog, /expectedIntegrityNames/);
  for (const name of ['kms-qualification.json', 'platform-auth-qualification.json', 'macos-provenance.json', 'macos-distribution-evidence.json', 'macos-promotion-artifact-gate.json', 'release-preflight-artifact-provenance.json']) assert.match(catalog, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(catalog, /agentpass-macos-promotion-artifact-gate/u);
  assert.match(catalog, /gatePackage\.artifact_sha256 !== product\[0\]\.sha256/u);
  assert.match(catalog, /readCanonicalEvidence/);
  assert.match(catalog, /macOS artifact inventory entry is unsafe/);
  assert.match(catalog, /macOS distribution inventory descriptor is mismatched/);
  assert.match(catalog, /macOS notarization evidence is not exact or product-bound/);
  assert.match(evidence, /canonicalJson/);
  assert.match(evidence, /status !== 'passed'/);
  assert.match(evidence, /qualified !== true/);
  assert.match(evidence, /source_commit !== expectedSourceCommit/);
  assert.match(evidence, /kms-qualification/);
  assert.match(evidence, /platform-auth-qualification/);
  assert.match(promote, /EXPECTED_PLATFORM_AUTH_PRIMARY_DEPLOYMENT_DIGEST: \$\{\{ vars\.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_PRIMARY_DEPLOYMENT_DIGEST \}\}/);
  assert.match(promote, /EXPECTED_PLATFORM_AUTH_SECONDARY_DEPLOYMENT_DIGEST: \$\{\{ vars\.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SECONDARY_DEPLOYMENT_DIGEST \}\}/);
  assert.match(evidence, /platform-auth-qualification[^\n]*\$EXPECTED_PLATFORM_AUTH_PRIMARY_DEPLOYMENT_DIGEST[^\n]*\$EXPECTED_PLATFORM_AUTH_SECONDARY_DEPLOYMENT_DIGEST/);
  assert.match(evidence, /evidence_sha256/);
  assert.match(evidence, /GITHUB_STEP_SUMMARY/);
  assert.match(evidence, /source_commit=.*evidence_sha256=/);
  const deployment = step('Verify externally pinned staging deployment and rollback evidence');
  assert.match(deployment, /AGENTPASS_DEPLOYMENT_EVIDENCE_JSON/);
  assert.match(deployment, /AGENTPASS_DEPLOYMENT_BINDING_JSON/);
  assert.match(deployment, /release:deployment-gate/);
  assert.match(deployment, /deployment evidence is not bound to the selected release candidate/);
  assert.match(deployment, /derive-deployment-identity\.mjs/);
  assert.match(deployment, /deployment evidence schema\/catalog identity is not bound to the selected source and candidate migration manifest/);
  assert.match(deployment, /DEPLOYMENT_ATTESTATION_JSON/);
  assert.match(deployment, /DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY/);
  assert.match(deployment, /AGENTPASS_DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY/);
  assert.match(deployment, /trust root public key is required/);
  assert.match(deployment, /verifyDeploymentAttestation/);
  assert.match(deployment, /deploymentEvidenceSHA256/);
  assert.match(deployment, /database_schema_digest/);
  assert.match(deployment, /verifyDeploymentAttestationTrust/);
  assert.match(deployment, /ops\/trust\/deployment-attestation-trust\.v1\.json/);
  assert.match(deployment, /deployment evidence is not bound to this promotion run/);
  assert.match(deployment, /secret-scan/);
  assert.match(deployment, /scripts\/release\/ci-preflight\.mjs/);
  assert.doesNotMatch(deployment, /scripts\/ci-preflight\.mjs/);
  assert.equal([...promote.matchAll(/uses: actions\/download-artifact@[0-9a-f]{40}/g)].length, 6,
    'KMS and Platform Auth evidence must remain inside the existing integrity artifact download');
});

test('promotion requires the aggregate external qualification envelope and candidate binding', () => {
  const aggregate = step('Verify aggregate external qualification before promotion');
  assert.match(promote, /EXTERNAL_QUALIFICATION_EVIDENCE_JSON: \$\{\{ vars\.AGENTPASS_EXTERNAL_QUALIFICATION_EVIDENCE_JSON \}\}/);
  assert.match(promote, /EXTERNAL_QUALIFICATION_BINDING_JSON: \$\{\{ vars\.AGENTPASS_EXTERNAL_QUALIFICATION_BINDING_JSON \}\}/);
  assert.match(promote, /AGENTPASS_EXTERNAL_QUALIFICATION_SIGNATURE_BASE64/);
  assert.match(promote, /AGENTPASS_EXTERNAL_QUALIFICATION_PUBLIC_KEY_BASE64/);
  assert.match(promote, /AGENTPASS_EXTERNAL_QUALIFICATION_PUBLIC_KEY_FINGERPRINT/);
  assert.match(promote, /AGENTPASS_EXTERNAL_QUALIFICATION_TRUST_MANIFEST_JSON/);
  assert.match(aggregate, /ci-preflight\.mjs external-qualification/);
  assert.match(aggregate, /verify-external-qualification-signature\.mjs/);
  assert.match(aggregate, /manifest\.pub.*aggregate/);
  assert.match(aggregate, /protected aggregate qualification signature is required/);
  assert.match(aggregate, /secret-scan/);
  assert.match(aggregate, /EXTERNAL_QUALIFICATION_EVIDENCE_JSON/);
  assert.match(aggregate, /EXPECTED_SOURCE_TREE/);
  assert.match(aggregate, /EXPECTED_RELEASE_ARTIFACT_SHA256/);
  assert.match(aggregate, /ci_run_attempt/);
  assert.match(aggregate, /O_EXCL/);
  assert.match(promote, /external-qualification\.json/);
  assert.match(promote, /external-qualification-binding\.json/);
  assert.match(promote, /external-qualification-verification\.json/);
});

test('promotion recomputes every external child evidence digest and fails closed without the protected bundle', () => {
  assert.match(promote, /EXTERNAL_QUALIFICATION_CHILD_EVIDENCE_JSON: \$\{\{ vars\.AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_EVIDENCE_JSON \}\}/);
  assert.match(promote, /AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_SIGNATURE_BASE64/);
  assert.match(promote, /AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_PUBLIC_KEY_BASE64/);
  assert.match(promote, /AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_PUBLIC_KEY_FINGERPRINT/);
  const child = step('Recompute every external qualification child evidence digest');
  assert.match(child, /child evidence bundle is required/);
  assert.match(child, /external-qualification-child-signature-verification\.json/);
  assert.match(child, /artifact-provenance\.mjs children/);
  assert.match(child, /source_commit/);
  assert.match(child, /independent_tree_sha/);
  assert.match(child, /product_artifact_sha256/);
  assert.match(child, /secret-scan/);
  assert.match(child, /external-qualification-child-evidence-verification\.json/);
  assert.match(promote, /external-qualification-child-evidence\.json/);
});

test('promotion verifies the externally reviewed evidence index against a locally derived signed-manifest candidate', () => {
  const gate = step('Verify externally reviewed release evidence index operator gate');
  assert.match(gate, /EVIDENCE_INDEX_JSON: \$\{\{ env\.RELEASE_EVIDENCE_INDEX_JSON \}\}/);
  assert.match(gate, /INDEX_EXPECTED_CANDIDATE/);
  assert.match(gate, /INDEX_VERIFICATION_OUTPUT/);
  assert.match(gate, /manifestBytes/);
  assert.match(gate, /productBytes/);
  assert.match(gate, /release_manifest_sha256/);
  assert.match(gate, /candidate_id is not product-bound/);
  assert.match(gate, /release-evidence-index\.mjs verify/);
  assert.match(gate, /"\$INDEX_INPUT" "\$INDEX_EXPECTED_CANDIDATE" > "\$INDEX_VERIFICATION_OUTPUT"/);
  assert.match(gate, /fs\.constants\.O_EXCL/);
  assert.match(gate, /archive-secret-scan\.mjs "\$INDEX_OUTPUT"/);
  assert.match(gate, /archive-secret-scan\.mjs "\$INDEX_VERIFICATION_OUTPUT"/);
  assert.doesNotMatch(gate, /DEPLOYMENT_EVIDENCE|RELEASE_RUN|QUALIFICATION_RUN|CI_RUN/);
});

test('raw production readiness is a required fail-closed stage before signed-manifest/evidence-index promotion', () => {
  assert.match(promote, /PRODUCTION_READINESS_EVIDENCE_JSON: \$\{\{ vars\.AGENTPASS_PRODUCTION_READINESS_EVIDENCE_JSON \}\}/);
  assert.match(promote, /PRODUCTION_READINESS_RUN_BINDINGS_JSON: \$\{\{ vars\.AGENTPASS_PRODUCTION_READINESS_RUN_BINDINGS_JSON \}\}/);
  const readiness = step('Verify raw production readiness evidence before release-evidence-index promotion');
  for (const required of [
    'RAW_EVIDENCE_JSON', 'RUN_BINDINGS_JSON', 'RAW_EVIDENCE_INPUT', 'RUN_BINDINGS_INPUT', 'GATE_OUTPUT',
    'EXPECTED_SOURCE_COMMIT', 'EXPECTED_SOURCE_TREE', 'EXPECTED_ARTIFACT_SHA256', 'EXPECTED_CANDIDATE_ID',
    'RELEASE_RUN_ID', 'CI_RUN_ID', 'EXTERNAL_QUALIFICATION_RUN_ID', 'QUALIFICATION_RUN_ID',
    'RELEASE_RUN_RECORD', 'CI_RUN_RECORD', 'EXTERNAL_RUN_RECORD', 'QUALIFICATION_RUN_RECORD'
  ]) assert.match(readiness, new RegExp(required));
  assert.match(readiness, /protected raw production readiness evidence is required/);
  assert.match(readiness, /protected production readiness run bindings are required/);
  assert.match(readiness, /canonical JSON without a trailing newline/);
  assert.match(readiness, /has unknown or missing fields/);
  assert.match(readiness, /unknown or duplicate rows/);
  assert.match(readiness, /missing rows/);
  assert.match(readiness, /run binding mismatch/);
  assert.match(readiness, /candidate binding mismatch/);
  assert.match(readiness, /cannot be derived from workflow and signed manifest/);
  assert.match(readiness, /selected workflow runs/);
  assert.match(readiness, /production-readiness-gate\.mjs verify "\$RAW_EVIDENCE_INPUT"/);
  assert.match(readiness, /archive-secret-scan\.mjs "\$RAW_EVIDENCE_INPUT"/);
  assert.match(readiness, /archive-secret-scan\.mjs "\$RUN_BINDINGS_INPUT"/);
  assert.match(readiness, /archive-secret-scan\.mjs "\$GATE_OUTPUT"/);
  assert.match(readiness, /O_EXCL/);
  assert.doesNotMatch(readiness, /secrets\./);
  const index = step('Verify externally reviewed release evidence index operator gate');
  assert.ok(promote.indexOf('Verify raw production readiness evidence before release-evidence-index promotion') < promote.indexOf('Verify externally reviewed release evidence index operator gate'));
  assert.ok(promote.indexOf('Verify raw production readiness evidence before release-evidence-index promotion') < promote.indexOf('Create draft release after every verification gate'));
  for (const slot of [
    'release:candidate', 'ci:canonical', 'qualification:aggregate', 'external:aggregate',
    'postgresql:protected', 'kms:protected', 'webauthn:external',
    'macos:apple_silicon', 'macos:intel_t2', 'staging:readiness', 'deployment:rollback'
  ]) assert.match(readiness, new RegExp(slot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(index, /release-evidence-index\.mjs verify/);
});

test('promotion catalogs the v4 external controller and keeps its archive out of the product binding', () => {
  const catalog = step('Catalog only the exact downloaded candidate and qualification evidence');
  const release = step('Verify signed release candidate and derive its tag');
  assert.match(catalog, /schema_version !== 4/);
  assert.match(catalog, /external_qualification_controller/);
  assert.match(catalog, /identity_document/);
  assert.match(catalog, /identity/);
  assert.match(catalog, /notarization/);
  assert.match(catalog, /role === 'external_qualification_controller'/);
  assert.match(catalog, /role === 'product'/);
  assert.match(catalog, /controller_archive/);
  assert.match(catalog, /controller_identity/);
  assert.match(release, /release manifest must be v4/);
  assert.match(release, /controller archive role is invalid/);
});

test('re-runs signed macOS and cross-hardware qualification verification, including byte comparison', () => {
  const release = step('Verify signed release candidate and derive its tag');
  assert.match(release, /verify-release\.mjs/);
  assert.match(release, /verify-macos-release\.sh/);
  assert.match(release, /RELEASE_RUN_HEAD_SHA/);
  const source = step('Verify annotated tag and source identity before promotion');
  for (const check of [/git cat-file -t/, /git.*verify-tag/, /git rev-parse/, /git merge-base --is-ancestor/, /refs\/tags\/\$RELEASE_TAG/]) assert.match(source, check);
  const qualification = step('Re-run hardware qualification verification against the exact candidate');
  assert.match(qualification, /verify-hardware-qualification-set\.mjs/);
  assert.match(promote, /APPROVED_OPERATOR_POLICY_JSON: \$\{\{ vars\.AGENTPASS_P0C_APPROVED_OPERATOR_POLICY_JSON \}\}/);
  assert.match(qualification, /APPLE_OPERATOR_FINGERPRINT/);
  assert.match(qualification, /INTEL_OPERATOR_FINGERPRINT/);
  assert.match(qualification, /verify-runner-attestation\.mjs/);
  assert.match(qualification, /AGENTPASS_P0C_APPLE_SILICON_RUNNER_ATTESTATION_FINGERPRINT/);
  assert.match(qualification, /AGENTPASS_P0C_INTEL_T2_RUNNER_ATTESTATION_FINGERPRINT/);
  assert.match(qualification, /cmp -s "\$GENERATED_SUMMARY" "\$RETAINED_SUMMARY"/);
  assert.match(qualification, /summary\.release_manifest_sha256 !== expectedManifestDigest/);
  assert.match(qualification, /summary\.artifact_sha256 !== product\.sha256/);
  assert.match(qualification, /binding\.release_run_id !== process\.env\.RELEASE_RUN_ID/);
  assert.match(qualification, /binding\.qualification_run_id !== process\.env\.QUALIFICATION_RUN_ID/);
});

test('release creation is last, refuses existing tags, and uploads an explicit manifest-bound list', () => {
  const refuse = step('Refuse an existing release before creating the public release');
  assert.match(refuse, /releases\/tags\/\$RELEASE_TAG/);
  assert.match(refuse, /a GitHub Release already exists/);
  const create = step('Create draft release after every verification gate');
  assert.match(create, /gh release create "\$RELEASE_TAG" --repo "\$CANONICAL_REPOSITORY" --draft --verify-tag --target "\$RELEASE_COMMIT"/);
  const upload = step('Upload only the explicit signed-manifest-bound release list');
  assert.match(upload, /manifest\.artifacts\.map/);
  assert.match(upload, /MANIFEST_PUBLIC_KEY: \$\{\{ steps\.catalog\.outputs\.public_key \}\}/);
  assert.match(upload, /archive-secret-scan\.mjs "\$INTEGRITY_DIR"/);
  assert.match(upload, /scanArchives\(files\.filter/);
  assert.match(upload, /manifest\.evidence\.notarization\.evidence\.map/);
  assert.match(upload, /manifest\.evidence\.checksums/);
  assert.match(upload, /manifest\.external_qualification_controller\.identity_document\.name/);
  assert.match(upload, /manifest\.external_qualification_controller\.notarization\.evidence\.map/);
  assert.match(upload, /kms-qualification\.json/);
  assert.match(upload, /platform-auth-qualification\.json/);
  assert.match(upload, /database-schema-evidence\.json/);
  assert.match(upload, /MANIFEST_PUBLIC_KEY/);
  assert.match(upload, /spawnSync\('gh', \['release', 'upload', tag, '--repo', repository, \.\.\.files\]/);
  assert.match(upload, /shell: false/);
  const materialize = step('Materialize the final P0-C release assets');
  for (const name of ['p0c-apple-silicon-report.json', 'p0c-apple-silicon-runner-attestation.json', 'p0c-apple-silicon-runner-attestation.sig', 'p0c-apple-silicon-runner-attestation.pem', 'p0c-intel-t2-report.json', 'p0c-intel-t2-runner-attestation.json', 'p0c-intel-t2-runner-attestation.sig', 'p0c-intel-t2-runner-attestation.pem', 'p0c-hardware-qualification-summary.json', 'p0c-approved-operator-policy.json', 'p0c-approved-operator-policy.sig', 'p0c-approved-operator-policy.pub', 'P0C-SHA256SUMS']) assert.match(materialize, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(materialize, /p0c-apple-silicon-evidence\.tar\.gz/);
  assert.match(materialize, /p0c-intel-t2-evidence\.tar\.gz/);
  assert.doesNotMatch(materialize, /gh release upload/);
  const finalGate = step('Final P0-C asset gate: secret scan, regular-file\/hardlink checks, and SHA256SUMS binding');
  assert.match(finalGate, /ci-preflight\.mjs artifact-scan/);
  assert.match(finalGate, /archive-secret-scan\.mjs "\$QUALIFICATION_ASSETS"/);
  assert.match(finalGate, /P0-C SHA256SUMS is not bound/);
  assert.match(finalGate, /cmp -s "\$expected_sums" "\$QUALIFICATION_ASSETS\/P0C-SHA256SUMS"/);
  assert.doesNotMatch(finalGate, /gh release upload/);
  const qualificationAssets = step('Upload the verified signed qualification evidence');
  assert.match(qualificationAssets, /gh release upload/);
  for (const name of ['p0c-apple-silicon-report.json', 'p0c-apple-silicon-runner-attestation.json', 'p0c-apple-silicon-runner-attestation.sig', 'p0c-apple-silicon-runner-attestation.pem', 'p0c-intel-t2-report.json', 'p0c-intel-t2-runner-attestation.json', 'p0c-intel-t2-runner-attestation.sig', 'p0c-intel-t2-runner-attestation.pem', 'p0c-hardware-qualification-summary.json', 'p0c-approved-operator-policy.json', 'p0c-approved-operator-policy.sig', 'p0c-approved-operator-policy.pub', 'P0C-SHA256SUMS']) assert.match(qualificationAssets, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(qualificationAssets, /p0c-apple-silicon-evidence\.tar\.gz/);
  assert.match(qualificationAssets, /p0c-intel-t2-evidence\.tar\.gz/);
  const reinspect = step('Re-inspect uploaded P0-C assets before publishing');
  assert.match(reinspect, /gh release download/);
  assert.match(reinspect, /pattern 'p0c-\*'/);
  assert.match(reinspect, /pattern 'P0C-SHA256SUMS'/);
  assert.match(reinspect, /ci-preflight\.mjs artifact-scan/);
  assert.match(reinspect, /uploaded P0-C assets no longer match P0C-SHA256SUMS/);
  const allAssets = step('Re-inspect every uploaded release asset before publishing');
  assert.match(allAssets, /release download/);
  assert.match(allAssets, /roundtrip-release-assets\.mjs/);
  assert.doesNotMatch(allAssets, /release-asset-roundtrip\.mjs/);
  assert.match(allAssets, /verifyReleaseAssetRoundTrip/);
  assert.match(allAssets, /requireSupplemental: true/);
  assert.match(allAssets, /release-asset-inventory\.json/);
  assert.match(allAssets, /version !== 2|version: 2/);
  assert.match(allAssets, /verify-release\.mjs/);
  assert.match(allAssets, /database-schema-evidence\.json/);
  const retained = step('Retain release asset round-trip evidence');
  assert.match(retained, /release-asset-roundtrip\.json/);
  assert.match(retained, /gh release upload/);
  const retainedCheck = step('Re-inspect retained release asset evidence before publishing');
  assert.match(retainedCheck, /gh release download/);
  assert.match(retainedCheck, /release-asset-roundtrip\.json/);
  assert.match(retainedCheck, /cmp -s/);
  assert.match(retainedCheck, /canonicalJson/);
  assert.match(retainedCheck, /archive-secret-scan\.mjs/);
  assert.match(retainedCheck, /version !== 2/);
  const publish = step('Publish the fully uploaded public release');
  assert.match(publish, /gh release edit "\$RELEASE_TAG" --repo "\$CANONICAL_REPOSITORY" --draft=false/);
  assert.ok(promote.indexOf('verify-hardware-qualification-set.mjs') < promote.indexOf('gh release create'));
  assert.ok(promote.indexOf('Materialize the final P0-C release assets') < promote.indexOf('Final P0-C asset gate'));
  assert.ok(promote.indexOf('Final P0-C asset gate') < promote.indexOf('Upload the verified signed qualification evidence'));
  assert.ok(promote.indexOf('Upload the verified signed qualification evidence') < promote.indexOf('Re-inspect uploaded P0-C assets before publishing'));
  assert.ok(promote.indexOf('Re-inspect uploaded P0-C assets before publishing') < promote.indexOf('Re-inspect every uploaded release asset before publishing'));
  assert.ok(promote.indexOf('Re-inspect every uploaded release asset before publishing') < promote.indexOf('Retain release asset round-trip evidence'));
  assert.ok(promote.indexOf('Retain release asset round-trip evidence') < promote.indexOf('Re-inspect retained release asset evidence before publishing'));
  assert.ok(promote.indexOf('Re-inspect retained release asset evidence before publishing') < promote.indexOf('Publish the fully uploaded public release'));
  assert.ok(promote.indexOf('Retain release asset round-trip evidence') < promote.indexOf('Publish the fully uploaded public release'));
  assert.ok(promote.indexOf('gh release upload') < promote.indexOf('gh release edit'));
});

test('explicit integrity upload inventory is synchronized with the later full-release round-trip inventory', () => {
  const upload = step('Upload only the explicit signed-manifest-bound release list');
  const roundtrip = step('Re-inspect every uploaded release asset before publishing');
  const uploadedEvidence = stringArray(upload, 'supplementalEvidence');
  const reinspectedEvidence = stringArray(roundtrip, 'supplemental');
  assert.deepEqual([...reinspectedEvidence].sort(), [...uploadedEvidence].sort(), 'round-trip inventory must cover every explicit integrity upload');
});

test('explicit release upload inventory includes every independent macOS evidence artifact', () => {
  const upload = step('Upload only the explicit signed-manifest-bound release list');
  const uploadedEvidence = stringArray(upload, 'supplementalEvidence');
  for (const name of [
    'macos-artifact-inventory.json',
    'macos-notary.json',
    'macos-staple.json',
    'macos-gatekeeper.json',
    'macos-identity.json',
    'macos-verification.json',
    'macos-provenance.json',
    'macos-distribution-evidence.json',
    'macos-promotion-artifact-gate.json'
  ]) assert.ok(uploadedEvidence.includes(name), `independent macOS evidence is not in the upload inventory: ${name}`);
});

test('no untrusted downloaded content is executed and cleanup is unconditional', () => {
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}[\s\S]*?persist-credentials: false/);
  assert.doesNotMatch(workflow, /chmod \+x.*(?:candidate|apple|intel|summary)|bash .*candidate|sh .*candidate|open .*\.pkg/);
  assert.match(workflow, /if: \$\{\{ always\(\) \}\}/);
  assert.match(workflow, /rm -rf -- "\$PROMOTION_ROOT"/);
});
