import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../../../packages/protocol/src/index.mjs';
import {
  createLocalAgentSessionGrantSigner,
  verifyAgentSessionGrant
} from '../../../apps/cloud-api/src/agent-session-grant.mjs';
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES,
  createLocalQualificationGrantBatchManifestSigner,
  verifyQualificationGrantBatchManifest
} from '../../../apps/cloud-api/src/qualification-grant-batch-manifest.mjs';
import {
  QUALIFICATION_RELAY_BATCH_KIND,
  QUALIFICATION_RELAY_INBOX_PATH,
  QUALIFICATION_RELAY_MAX_TTL_SECONDS,
  QUALIFICATION_RELAY_REQUEST_KIND,
  canonicalQualificationRelayRequest,
  claimQualificationDeviceRelay,
  normalizeQualificationDeviceRelayResponse,
  parseQualificationDeviceRelayCLI,
  parseQualificationRelayRequest,
  qualificationRelayResponseToSuiteInput,
  recoverQualificationDeviceRelay
} from './qualification-device-relay.mjs';

const UID = process.getuid?.();
const NOW = Date.parse('2026-08-14T10:00:00.000Z');
const ISSUED_AT = new Date(NOW).toISOString();
const EXPIRES_AT = new Date(NOW + 600_000).toISOString();
const IDS = Object.freeze({
  organization: '11111111-1111-4111-8111-111111111111',
  device: '22222222-2222-4222-8222-222222222222',
  agent: '33333333-3333-4333-8333-333333333333',
  adapter: '44444444-4444-4444-8444-444444444444',
  batch: '55555555-5555-4555-8555-555555555555',
  localRequest: '66666666-6666-4666-8666-666666666666',
  serverRequest: '77777777-7777-4777-8777-777777777777'
});
const BINDINGS = Object.freeze({
  candidate_sha256: 'a'.repeat(64),
  artifact_sha256: 'b'.repeat(64),
  source_commit: 'c'.repeat(40),
  team_id: 'TEAMID1234',
  release_trust_sha256: 'd'.repeat(64),
  candidate_checkpoint_sha256: 'e'.repeat(64)
});

const grantKeys = crypto.generateKeyPairSync('ed25519');
const manifestKeys = crypto.generateKeyPairSync('ed25519');

const digest = (value) => crypto.createHash('sha256').update(value, 'utf8').digest('hex');

const request = (overrides = {}) => ({
  schema_version: 1,
  kind: QUALIFICATION_RELAY_REQUEST_KIND,
  request_id: IDS.localRequest,
  batch_id: IDS.batch,
  organization_id: IDS.organization,
  device_id: IDS.device,
  agent_id: IDS.agent,
  agent_kind: 'claude-code',
  requested_ttl_seconds: 600,
  expires_at: EXPIRES_AT,
  ...BINDINGS,
  ...overrides
});

function grantStatement(index) {
  return {
    version: 1,
    grant_id: `80000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: 'claude-code',
    adapter_id: IDS.adapter,
    adapter_version: '1.2.3',
    worktree_binding_sha256: 'f'.repeat(64),
    process_binding_policy_id: 'qualification-v1',
    scope: {
      operations: ['git.commit.sign'],
      repositories: ['/work/project'],
      branches: { allow: ['feature/*'], deny: ['main'] },
      remotes: { allow: ['origin'], deny: [] }
    },
    max_signatures: 1,
    not_before: ISSUED_AT,
    expires_at: EXPIRES_AT,
    control_sequence: index + 1,
    authority_generation: 7,
    issuer: 'agentpass-cloud',
    key_id: 'agent-session-2026-08'
  };
}

async function signedGrants() {
  const signer = createLocalAgentSessionGrantSigner({
    privateKey: grantKeys.privateKey,
    keyId: 'agent-session-2026-08',
    now: () => NOW
  });
  return Promise.all(QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES.map(async (identity) => {
    const grant = await signer.signAgentSessionGrant(grantStatement(identity.index));
    return Object.freeze({
      ...identity,
      run_binding: `qualification-run-${identity.index}`,
      grant_id: grant.statement.grant_id,
      grant_hash: digest(canonicalJson(grant)),
      statement_hash: grant.statement_hash,
      grant
    });
  }));
}

async function signedResponse(overrides = {}) {
  const steps = await signedGrants();
  const manifestSigner = createLocalQualificationGrantBatchManifestSigner({
    privateKey: manifestKeys.privateKey,
    keyId: 'qualification-batch-2026-08',
    now: () => NOW
  });
  const manifest = await manifestSigner.signQualificationGrantBatchManifest({
    version: 1,
    type: 'agentpass.qualification-grant-batch-manifest',
    batch_id: IDS.batch,
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: 'claude-code',
    requested_ttl_seconds: 600,
    ...BINDINGS,
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    steps,
    issuer: 'agentpass-cloud',
    key_id: 'qualification-batch-2026-08'
  });
  const batch = {
    schema_version: 1,
    kind: QUALIFICATION_RELAY_BATCH_KIND,
    batch_id: IDS.batch,
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: 'claude-code',
    requested_ttl_seconds: 600,
    ...BINDINGS,
    expires_at: EXPIRES_AT,
    steps: steps.map(({ index, kind, scenario, phase, run_binding, grant }) => ({ index, kind, scenario, phase, run_binding, grant })),
    manifest
  };
  return {
    request: request(),
    response: { request_id: IDS.serverRequest, batch: { ...batch, ...overrides } },
    manifest,
    steps
  };
}

function manifestVerifier() {
  return (manifest, context) => {
    assert.equal(context.request.batch_id, IDS.batch);
    assert.equal(context.batch.batch_id, IDS.batch);
    return verifyQualificationGrantBatchManifest(manifest, {
      publicKey: manifestKeys.publicKey,
      grantPublicKey: grantKeys.publicKey,
      grantKeyId: 'agent-session-2026-08',
      now: NOW
    });
  };
}

function tempRoot() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-relay-')));
  fs.chmodSync(root, 0o700);
  return root;
}

function paths(root) {
  return {
    root,
    requestPath: path.join(root, 'relay-request.json'),
    inboxPath: path.join(root, 'input.inbox.json')
  };
}

function writeRequest(requestPath, value = request()) {
  fs.writeFileSync(requestPath, canonicalQualificationRelayRequest(value), { mode: 0o600 });
  fs.chmodSync(requestPath, 0o600);
}

function testOptions(value, extra = {}) {
  return {
    ...value,
    ...extra,
    production: false,
    expectedUid: UID,
    uid: UID,
    proveNoActiveRelay: () => true
  };
}

test('request is closed, canonical, includes batch_id/team_id, and has no request_nonce', () => {
  const bytes = canonicalQualificationRelayRequest(request());
  const parsed = parseQualificationRelayRequest(bytes);
  assert.equal(parsed.batch_id, IDS.batch);
  assert.equal(parsed.team_id, BINDINGS.team_id);
  assert.equal('request_nonce' in parsed, false);
  assert.throws(() => canonicalQualificationRelayRequest({ ...request(), request_nonce: 'forbidden' }), /not closed/u);
  assert.throws(() => canonicalQualificationRelayRequest({ ...request(), requested_ttl_seconds: QUALIFICATION_RELAY_MAX_TTL_SECONDS + 1 }), /invalid/u);
});

test('signed existing Agent Session Grant envelopes are verified through the manifest and transformed unchanged', async () => {
  const value = await signedResponse();
  const suite = qualificationRelayResponseToSuiteInput(value.response, value.request, { verifyBatchManifest: manifestVerifier() });
  assert.equal(suite.suite.steps.length, 7);
  assert.equal(suite.request_id, IDS.serverRequest);
  assert.equal(suite.suite.steps[0].input.provision.scenario, 'pre-cloud-kill');
  assert.equal(suite.suite.steps[0].input.activation.agent_kind, 'claude_code');
  assert.equal(suite.suite.steps[1].input.activation.agent_kind, 'claude_code');
  assert.equal(suite.suite.steps[0].input.activation.proof, canonicalJson(value.steps[0].grant));
  assert.equal(suite.suite.steps[6].input.activation.proof, canonicalJson(value.steps[6].grant));
  assert.equal(verifyAgentSessionGrant(JSON.parse(suite.suite.steps[0].input.activation.proof), { publicKey: grantKeys.publicKey, keyId: 'agent-session-2026-08', now: NOW }).statement.grant_id, value.steps[0].grant.statement.grant_id);
});

test('server-generated response request_id is validated as UUID but is not compared to the local request_id', async () => {
  const value = await signedResponse();
  const normalized = normalizeQualificationDeviceRelayResponse(value.response, value.request, { verifyBatchManifest: manifestVerifier() });
  assert.equal(normalized.request_id, IDS.serverRequest);
  const mutated = { ...value.response, request_id: IDS.localRequest };
  assert.doesNotThrow(() => normalizeQualificationDeviceRelayResponse(mutated, value.request, { verifyBatchManifest: manifestVerifier() }));
  assert.throws(() => normalizeQualificationDeviceRelayResponse({ ...value.response, request_id: 'not-a-uuid' }, value.request, { verifyBatchManifest: manifestVerifier() }), /request_id/u);
});

test('manifest verification is mandatory, synchronous, and gates inbox publication', async () => {
  const value = await signedResponse();
  const files = paths(tempRoot());
  try {
    writeRequest(files.requestPath, value.request);
    await assert.rejects(() => claimQualificationDeviceRelay(testOptions(files, { deviceClient: { async claim() { return value.response; } } })), /manifest verifier/u);
    assert.equal(fs.existsSync(files.requestPath), true);
    assert.equal(fs.existsSync(files.inboxPath), false);

    writeRequest(files.requestPath, value.request);
    await assert.rejects(() => claimQualificationDeviceRelay(testOptions(files, { deviceClient: { async claim() { return value.response; } }, verifyBatchManifest: async () => ({ verified: true }) })), /claim failed/u);
    assert.equal(fs.existsSync(files.inboxPath), false);
  } finally { fs.rmSync(files.root, { recursive: true, force: true }); }
});

test('claim client receives the URL batch binding and public Device API body without local request nonce', async () => {
  const value = await signedResponse();
  const files = paths(tempRoot());
  let received;
  try {
    writeRequest(files.requestPath, value.request);
    const result = await claimQualificationDeviceRelay(testOptions(files, {
      verifyBatchManifest: manifestVerifier(),
      deviceClient: { async claim(input) { received = input; return value.response; } }
    }));
    assert.equal(result.ok, true);
    assert.equal(received.batch_id, IDS.batch);
    assert.equal(received.organization_id, IDS.organization);
    assert.equal(received.device_id, IDS.device);
    assert.equal(received.local_request_id, IDS.localRequest);
    assert.equal('request_nonce' in received.request, false);
    assert.deepEqual(Object.keys(received.request).sort(), ['artifact_sha256', 'candidate_checkpoint_sha256', 'candidate_sha256', 'release_trust_sha256', 'schema_version', 'source_commit', 'team_id']);
    assert.equal(fs.existsSync(files.requestPath), false);
    assert.equal(fs.statSync(files.inboxPath).mode & 0o7777, 0o600);
    assert.equal(fs.statSync(files.inboxPath).nlink, 1);
  } finally { fs.rmSync(files.root, { recursive: true, force: true }); }
});

test('custom qualification Grant envelopes are rejected before publication', async () => {
  const value = await signedResponse();
  value.response.batch.steps[0].grant = { schema_version: 1, kind: 'qualification-grant', statement: {}, statement_hash: 'a'.repeat(64), signature: 'x' };
  assert.throws(() => qualificationRelayResponseToSuiteInput(value.response, value.request, { verifyBatchManifest: manifestVerifier() }), /manifest|Grant/u);
});

test('symlink, unsafe mode, partial staging, and recovery are fail-closed', async () => {
  const value = await signedResponse();
  const files = paths(tempRoot());
  try {
    const target = path.join(files.root, 'target-request.json');
    writeRequest(target, value.request);
    fs.symlinkSync(target, files.requestPath);
    await assert.rejects(() => claimQualificationDeviceRelay(testOptions(files, { verifyBatchManifest: manifestVerifier(), deviceClient: { async claim() { return value.response; } } })), /claim request|failed/u);
    fs.unlinkSync(files.requestPath);

    writeRequest(files.requestPath, value.request);
    fs.chmodSync(files.requestPath, 0o644);
    await assert.rejects(() => claimQualificationDeviceRelay(testOptions(files, { verifyBatchManifest: manifestVerifier(), deviceClient: { async claim() { return value.response; } } })), /claim failed|unsafe/u);
    fs.chmodSync(files.requestPath, 0o600);

    const staging = path.join(files.root, `.qualification-relay-input.${process.pid}.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp`);
    fs.writeFileSync(staging, 'partial', { mode: 0o600 });
    writeRequest(files.requestPath, value.request);
    fs.writeFileSync(files.inboxPath, 'partial-output', { mode: 0o600 });
    const recovered = recoverQualificationDeviceRelay(testOptions(files));
    assert.equal(recovered.action, 'recovered');
    assert.equal(fs.existsSync(files.requestPath), false);
    assert.equal(fs.existsSync(files.inboxPath), false);
    assert.equal(fs.existsSync(staging), false);
  } finally { fs.rmSync(files.root, { recursive: true, force: true }); }
});

test('CLI exposes only fixed claim and recover operations', () => {
  assert.deepEqual(parseQualificationDeviceRelayCLI(['claim']), { operation: 'claim' });
  assert.deepEqual(parseQualificationDeviceRelayCLI(['recover']), { operation: 'recover' });
  for (const args of [[], ['claim', '/tmp/proof'], ['recover', '/tmp/path'], ['claim', '--endpoint', 'https://evil.test']]) assert.throws(() => parseQualificationDeviceRelayCLI(args), /usage/u);
  assert.equal(QUALIFICATION_RELAY_INBOX_PATH, '/private/var/db/agentpass-qualification/input.inbox.json');
});
