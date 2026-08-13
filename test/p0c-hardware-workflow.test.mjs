import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const workflowPath = resolve(root, '.github/workflows/p0c-hardware-qualification.yml');
const workflow = fs.readFileSync(workflowPath, 'utf8');

const job = (name) => {
  const headings = [...workflow.matchAll(/^  ([A-Za-z0-9_-]+):\s*$/gm)];
  const current = headings.find((match) => match[1] === name);
  assert.ok(current, `missing job: ${name}`);
  const next = headings.find((match) => match.index > current.index);
  return workflow.slice(current.index, next?.index ?? workflow.length);
};

test('P0-C workflow is manually dispatched only, canonical-repository only, and action pins are immutable', () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/m);
  for (const event of ['push', 'pull_request', 'pull_request_target', 'workflow_call', 'schedule']) {
    assert.doesNotMatch(workflow, new RegExp(`^\\s{2}${event}:`, 'm'), `unexpected trigger: ${event}`);
  }
  assert.match(workflow, /github\.repository == 'Torutesu\/AIagentpass'/g);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/g);
  assert.match(workflow, /permissions:\n  contents: read\n  actions: read/);
  assert.doesNotMatch(workflow, /contents:\s*write|actions:\s*write|id-token:\s*write/);
  const uses = [...workflow.matchAll(/^\s*- uses:\s*([^\s@]+)@([^\s#]+)(?:\s+#.*)?$/gm)];
  assert.ok(uses.length >= 8, 'expected pinned checkout, setup-node, artifact download, and artifact upload actions');
  for (const [, action, ref] of uses) {
    assert.match(action, /^actions\/(checkout|setup-node|download-artifact|upload-artifact)$/);
    assert.match(ref, /^[0-9a-f]{40}$/i, `${action} is not pinned to a full commit`);
  }
  assert.doesNotMatch(workflow, /@[vV][0-9]/, 'floating action tag found');
  assert.doesNotMatch(workflow, /\bgh\s+release\b|^\s{2}publish:/m, 'publication is outside this workflow');
});

test('preflight accepts only a successful same-repository main-branch Release candidate run', () => {
  const section = job('validate-candidate');
  assert.match(workflow, /release_run_id:/);
  assert.match(workflow, /release_artifact_name:/);
  assert.match(section, /RELEASE_RUN_ID"\s*\=~\s*\^\[1-9\]\[0-9\]\{0,18\}\$/);
  assert.match(section, /RELEASE_ARTIFACT_NAME" == "\$EXPECTED_CANDIDATE_ARTIFACT"/);
  assert.match(section, /gh api --method GET "repos\/\$GITHUB_REPOSITORY\/actions\/runs\/\$RELEASE_RUN_ID"/);
  for (const condition of [
    /\.name == "Release candidate"/,
    /\.path == "\.github\/workflows\/release-candidate\.yml"/,
    /\.event == "workflow_dispatch"/,
    /\.status == "completed"/,
    /\.conclusion == "success"/,
    /\.head_branch == "main"/,
    /\.head_repository\.full_name == \$repo/,
    /\.head_sha \| test\("\^\[0-9a-f\]\{40\}\$"\)/
  ]) assert.match(section, condition);
  assert.match(section, /candidate_head_sha=/);
});

test('hardware lanes are distinct protected self-hosted environments and expose only lane operator secrets', () => {
  const apple = job('apple-silicon-qualification');
  const intel = job('intel-t2-qualification');
  assert.match(apple, /needs: validate-candidate/);
  assert.match(intel, /needs: validate-candidate/);
  assert.match(apple, /environment: p0c-hardware-apple-silicon/);
  assert.match(intel, /environment: p0c-hardware-intel-t2/);
  assert.match(apple, /runs-on: \[self-hosted, macOS, agentpass-p0c-apple-silicon\]/);
  assert.match(intel, /runs-on: \[self-hosted, macOS, agentpass-p0c-intel-t2\]/);
  assert.doesNotMatch(apple, /inputs\./);
  assert.doesNotMatch(intel, /inputs\./);
  const secretRefs = [...workflow.matchAll(/\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g)].map(([, name]) => name).sort();
  assert.deepEqual(secretRefs, [
    'AGENTPASS_P0C_APPLE_SILICON_OPERATOR_PRIVATE_KEY_BASE64',
    'AGENTPASS_P0C_INTEL_T2_OPERATOR_PRIVATE_KEY_BASE64'
  ]);
  assert.doesNotMatch(workflow, /secrets\.(?:AGENTPASS_(?:SIGNING|INSTALLER|NOTARY|SERVICE_PROFILE|CLIENT_PROFILE)|[A-Za-z0-9_]*(?:CERTIFICATE|PROVISION|KEYCHAIN))/);
  assert.match(workflow, /P0C_GATE_DRIVER_DIR: \/opt\/agentpass\/p0c\/gates/);
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
});

test('each lane checks out only the trusted workflow commit, verifies the candidate before fixed qualification, and uploads all evidence', () => {
  for (const [name, hardwareClass] of [['apple-silicon-qualification', 'apple-silicon'], ['intel-t2-qualification', 'intel-t2']]) {
    const section = job(name);
    assert.match(section, /ref: \$\{\{ github\.sha \}\}/);
    assert.match(section, /persist-credentials: false/);
    assert.match(section, /clean: true/);
    assert.match(section, /run-id: \$\{\{ needs\.validate-candidate\.outputs\.run_id \}\}/);
    assert.match(section, /repository: \$\{\{ github\.repository \}\}/);
    assert.match(section, /github-token: \$\{\{ github\.token \}\}/);
    assert.match(section, /release-attestation\.json/);
    assert.match(section, /database-migration-manifest\.json/);
    assert.match(section, /verify-release\.mjs/);
    assert.match(section, /verify-macos-release\.sh/);
    assert.match(section, /generate-hardware-qualification-template\.mjs/);
    assert.match(section, /run-p0c-qualification\.mjs/);
    assert.match(section, /--gate-drivers "\$GATE_DRIVER_DIR"/);
    assert.match(section, /sign-hardware-qualification\.mjs/);
    assert.match(section, /validate-hardware-qualification\.mjs/);
    assert.match(section, new RegExp(`name: p0c-hardware-${hardwareClass}`));
    for (const required of ['report.json', 'report.sig', 'operator-public.pem', 'evidence/']) assert.match(section, new RegExp(required.replace(/[./]/g, '\\$&')));
    const verificationEnd = section.indexOf('verify-macos-release.sh');
    const templateStart = section.indexOf('generate-hardware-qualification-template.mjs');
    const qualificationStart = section.indexOf('run-p0c-qualification.mjs');
    const signingStart = section.indexOf('sign-hardware-qualification.mjs');
    assert.ok(verificationEnd > 0 && templateStart > verificationEnd && qualificationStart > templateStart, `${name} runs qualification before signed template generation`);
    assert.ok(signingStart > qualificationStart, `${name} signs before qualification`);
    assert.match(section, /if: \$\{\{ always\(\) \}\}/);
  }
});

test('each lane binds the v3 external controller and exports only its architecture CDHash for later root provisioning', () => {
  for (const [name, architecture] of [['apple-silicon-qualification', 'arm64'], ['intel-t2-qualification', 'x86_64']]) {
    const section = job(name);
    assert.match(section, new RegExp(`CONTROLLER_ARCHITECTURE: ${architecture}`));
    assert.match(section, /schema_version !== 3/);
    assert.match(section, /external_qualification_controller/);
    assert.match(section, /identity_document/);
    assert.match(section, /identity/);
    assert.match(section, /notarization/);
    assert.match(section, /role === 'external_qualification_controller'/);
    assert.match(section, /role === 'product'/);
    assert.match(section, /archive_sha256/);
    assert.match(section, /archive_bytes/);
    assert.match(section, /code_directory_hashes/);
    assert.match(section, /process\.env\.CONTROLLER_ARCHITECTURE/);
    assert.match(section, /AGENTPASS_P0C_QUALIFICATION_CONTROLLER_CDHASH=/);
    assert.match(section, /QUALIFICATION_CONTROLLER_CDHASH=/);
    const selector = section.slice(section.indexOf('id: controller-cdhash'));
    assert.match(selector, /without claiming physical execution/);
    assert.doesNotMatch(selector, /qualified\s*[:=]\s*true/);
  }
});

test('each lane accepts only the root-owned digest-pinned qualification config tool', () => {
  for (const laneName of ['apple-silicon-qualification', 'intel-t2-qualification']) {
    const section = job(laneName);
    assert.match(section, /QUALIFICATION_CONFIG_TOOL_ROOT:\s*\/opt\/agentpass\/p0c\/qualification-tool/u);
    assert.match(section, /Verify root-owned qualification config tool matches the trusted workflow commit/u);
    assert.match(section, /stat\.uid !== 0/u);
    assert.match(section, /stat\.mode & 0o022/u);
    assert.match(section, /stat\.nlink !== 1/u);
    assert.match(section, /digest\(installed\) !== item\.sha256 \|\| digest\(sourceName\) !== item\.sha256/u);
    assert.doesNotMatch(section, /sudo\s+node\s+scripts\/release\/n3e\/provision-qualification-config/u);
  }
});

test('candidate and aggregate catalogs retain the controller archive outside the product role', () => {
  const aggregate = job('aggregate-qualification');
  assert.match(workflow, /parseCanonicalExternalQualificationControllerIdentity/);
  assert.match(workflow, /validateExternalQualificationControllerIdentity/);
  assert.match(aggregate, /aggregate candidate contains unexpected or missing files/);
  assert.match(aggregate, /controllerArchive\.name/);
  assert.match(aggregate, /controllerEvidence/);
  assert.match(aggregate, /controllerArchive\.role === 'product'/);
});

test('aggregate is secret-free, depends fail-closed on both successful lanes, and verifies external policy', () => {
  const section = job('aggregate-qualification');
  assert.match(section, /needs: \[validate-candidate, apple-silicon-qualification, intel-t2-qualification\]/);
  for (const dependency of ['validate-candidate', 'apple-silicon-qualification', 'intel-t2-qualification']) assert.match(section, new RegExp(`needs\\.${dependency.replaceAll('-', '\\-')}\\.result == 'success'`));
  assert.doesNotMatch(section, /secrets\./);
  assert.match(section, /APPROVED_OPERATOR_POLICY_JSON: \$\{\{ vars\.AGENTPASS_P0C_APPROVED_OPERATOR_POLICY_JSON \}\}/);
  assert.match(section, /Write externally supplied approved operator policy/);
  assert.match(section, /verify-hardware-qualification-set\.mjs/);
  assert.match(section, /p0c-hardware-apple-silicon/);
  assert.match(section, /p0c-hardware-intel-t2/);
  assert.match(section, /qualification-summary\.json/);
  assert.match(section, /qualification-dispatch-binding\.json/);
  assert.match(section, /release_run_id: process\.env\.CANDIDATE_RUN_ID/);
  assert.match(section, /qualification_run_id: process\.env\.GITHUB_RUN_ID/);
  assert.doesNotMatch(section, /environment:/);
  assert.doesNotMatch(section, /if: \$\{\{ always\(\) \}\}/);
});

test('candidate and operator bindings are not accepted from arbitrary workflow inputs', () => {
  const preflight = job('validate-candidate');
  assert.match(workflow, /EXPECTED_CANDIDATE_ARTIFACT: notarized-release-candidate/);
  assert.match(preflight, /Only the exact notarized-release-candidate artifact is accepted/);
  const laneText = `${job('apple-silicon-qualification')}\n${job('intel-t2-qualification')}`;
  assert.doesNotMatch(laneText, /ref: \$\{\{\s*inputs\./);
  assert.doesNotMatch(laneText, /run:\s*[^\n]*\$\{\{\s*inputs\./);
  assert.match(laneText, /GATE_DRIVER_DIR: \/opt\/agentpass\/p0c\/gates/);
  assert.match(laneText, /--operator "\$OPERATOR_ID"/);
  assert.match(laneText, /--expected-fingerprint "\$OPERATOR_FINGERPRINT"/);
});
