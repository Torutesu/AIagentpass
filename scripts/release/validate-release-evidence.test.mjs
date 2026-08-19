import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { RELEASE_MANIFEST_SCHEMA_VERSION } from '../../lib/release-candidate-identity.mjs';
import { validateReleaseEvidence } from './validate-release-evidence.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const descriptor = (name, bytes) => ({ name, bytes: bytes.length, sha256: sha256(bytes) });

const createFixture = () => {
  const root = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-release-preflight-'));
  const artifactName = 'AgentPass-v0.18.0-macos-universal.pkg';
  const artifactBytes = Buffer.from('a package is not a signed release');
  const artifactSHA256 = sha256(artifactBytes);
  const candidateID = `release-pkg-sha256-v1-${artifactSHA256}`;
  const submissionID = '01234567-89ab-cdef-0123-456789abcdef';
  const manifest = {
    schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
    product: 'AgentPass',
    version: '0.18.0',
    candidate_id: candidateID,
    artifacts: [{ name: artifactName, role: 'product', media_type: 'application/vnd.apple.installer+xml', bytes: artifactBytes.length, sha256: artifactSHA256 }]
  };
  const manifestBytes = canonicalJSON(manifest);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyBytes = publicKey.export({ type: 'spki', format: 'pem' });
  const signatureBytes = Buffer.from(`${sign(null, manifestBytes, privateKey).toString('base64')}\n`, 'utf8');
  // The production fingerprint is base64url, not a hexadecimal digest.
  const pinnedFingerprint = `SHA256:${createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  const files = {
    [artifactName]: artifactBytes,
    'release-manifest.json': manifestBytes,
    'release-manifest.sig': signatureBytes,
    'release-public.pem': publicKeyBytes,
    'notarytool-result.json': Buffer.from(JSON.stringify({ id: submissionID, status: 'Accepted' }), 'utf8'),
    'notary-ticket.json': canonicalJSON({ schema_version: 1, kind: 'apple-notary-ticket-v1', status: 'accepted', submission_id: submissionID, artifact_sha256: artifactSHA256 }),
    'staple-validation.json': canonicalJSON({ schema_version: 1, kind: 'apple-staple-validation-v1', status: 'validated', ticket_status: 'present', artifact_sha256: artifactSHA256 }),
    'gatekeeper-assessment.json': canonicalJSON({ schema_version: 1, kind: 'apple-gatekeeper-assessment-v1', assessment: 'accepted', assessment_type: 'install', artifact_sha256: artifactSHA256 })
  };
  for (const [name, bytes] of Object.entries(files)) fs.writeFileSync(join(root, name), bytes, { flag: 'wx' });
  const evidence = {
    schema_version: 1,
    kind: 'agentpass-release-preflight-evidence',
    verification_mode: 'offline_evidence',
    candidate: { version: '0.18.0', artifact_name: artifactName, artifact_bytes: artifactBytes.length, artifact_sha256: artifactSHA256, candidate_id: candidateID },
    signature: {
      manifest: descriptor('release-manifest.json', files['release-manifest.json']),
      detached_signature: descriptor('release-manifest.sig', files['release-manifest.sig']),
      public_key: descriptor('release-public.pem', files['release-public.pem']),
      public_key_fingerprint: pinnedFingerprint
    },
    notarization: { submission_id: submissionID, notary_result: descriptor('notarytool-result.json', files['notarytool-result.json']), ticket: descriptor('notary-ticket.json', files['notary-ticket.json']) },
    staple: { validation: descriptor('staple-validation.json', files['staple-validation.json']) },
    gatekeeper: { assessment: descriptor('gatekeeper-assessment.json', files['gatekeeper-assessment.json']) }
  };
  return { root, evidence, files, artifactSHA256 };
};

test('the published schema is closed and accepts the same valid fixture', () => {
  const fixture = createFixture();
  const schema = JSON.parse(fs.readFileSync(new URL('./release-preflight-evidence.schema.json', import.meta.url), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  assert.equal(validate(fixture.evidence), true, JSON.stringify(validate.errors));
  const withUnknownField = structuredClone(fixture.evidence);
  withUnknownField.signature.unexpected = true;
  assert.equal(validate(withUnknownField), false);
});

test('keeps the existing release matrix as the source of external-gate truth', () => {
  const matrix = fs.readFileSync(new URL('../../docs/RELEASE_QUALIFICATION_EVIDENCE_MATRIX.md', import.meta.url), 'utf8');
  assert.match(matrix, /Manifest identity and detached signature/u);
  assert.match(matrix, /Apple notarization and stapled ticket/u);
  assert.match(matrix, /not_proven/u);
  assert.match(matrix, /verify-macos-release\.sh/u);
});

test('validates a complete candidate-bound offline evidence bundle without Apple credentials', () => {
  const fixture = createFixture();
  const result = validateReleaseEvidence(fixture);
  assert.deepEqual(result, {
    ok: true,
    status: 'validated_offline',
    verification_mode: 'offline_evidence',
    candidate_id: fixture.evidence.candidate.candidate_id,
    candidate_sha256: fixture.artifactSHA256,
    manifest_sha256: fixture.evidence.signature.manifest.sha256,
    signature_verified: true,
    notary_evidence_bound: true,
    ticket_evidence_bound: true,
    staple_evidence_bound: true,
    gatekeeper_evidence_bound: true,
    apple_ticket_verified: false,
    gatekeeper_verified: false,
    promotion_ready: false,
    source_manifest_version: '0.18.0'
  });
});

test('rejects candidate digest substitution even when the candidate_id is changed with it', () => {
  const fixture = createFixture();
  fixture.evidence.candidate.artifact_sha256 = 'f'.repeat(64);
  fixture.evidence.candidate.candidate_id = `release-pkg-sha256-v1-${'f'.repeat(64)}`;
  assert.throws(() => validateReleaseEvidence(fixture), /candidate PKG digest|digest does not match|candidate_id/iu);
});

test('rejects unknown fields before any evidence can produce a pass', () => {
  const fixture = createFixture();
  fixture.evidence.gatekeeper.extra = 'passed';
  assert.throws(() => validateReleaseEvidence(fixture), /unknown.*fields/iu);
});

test('rejects a ticket bound to another candidate', () => {
  const fixture = createFixture();
  const wrong = canonicalJSON({ schema_version: 1, kind: 'apple-notary-ticket-v1', status: 'accepted', submission_id: fixture.evidence.notarization.submission_id, artifact_sha256: 'f'.repeat(64) });
  fs.writeFileSync(join(fixture.root, 'notary-ticket.json'), wrong);
  fixture.evidence.notarization.ticket = descriptor('notary-ticket.json', wrong);
  assert.throws(() => validateReleaseEvidence(fixture), /notary ticket evidence\.artifact_sha256/iu);
});

test('fails closed when a declared evidence file is missing or changed', () => {
  const fixture = createFixture();
  fs.unlinkSync(join(fixture.root, 'gatekeeper-assessment.json'));
  assert.throws(() => validateReleaseEvidence(fixture), /Gatekeeper evidence is missing/iu);
  const second = createFixture();
  fs.appendFileSync(join(second.root, second.evidence.candidate.artifact_name), 'tamper');
  assert.throws(() => validateReleaseEvidence(second), /candidate PKG.*declared|digest does not match/iu);
});
