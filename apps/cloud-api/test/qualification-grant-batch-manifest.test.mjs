import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AGENT_SESSION_GRANT_SIGNATURE_DOMAIN,
  createLocalAgentSessionGrantSigner
} from "../src/agent-session-grant.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES,
  QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN,
  QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES,
  createLocalQualificationGrantBatchManifestSigner,
  createQualificationGrantBatchManifestSigner,
  normalizeQualificationGrantBatchManifestStatement,
  qualificationGrantBatchManifestSigningData,
  qualificationGrantBatchManifestStatementHash,
  verifyQualificationGrantBatchManifest
} from "../src/qualification-grant-batch-manifest.mjs";

const NOW = Date.parse("2026-08-14T10:00:00.000Z");
const ISSUED_AT = new Date(NOW).toISOString();
const EXPIRES_AT = new Date(NOW + 600_000).toISOString();
const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  agent: "33333333-3333-4333-8333-333333333333",
  adapter: "44444444-4444-4444-8444-444444444444",
  batch: "55555555-5555-4555-8555-555555555555"
});
const grantKeys = crypto.generateKeyPairSync("ed25519");
const manifestKeys = crypto.generateKeyPairSync("ed25519");
const otherKeys = crypto.generateKeyPairSync("ed25519");

const digest = (value) => crypto.createHash("sha256").update(value, "utf8").digest("hex");
const grantId = (index) => `60000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`;

function grantStatement(index) {
  return {
    version: 1,
    grant_id: grantId(index),
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: "claude-code",
    adapter_id: IDS.adapter,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/project"],
      branches: { allow: ["feature/*"], deny: ["main"] },
      remotes: { allow: ["git@example.test:project.git"], deny: [] }
    },
    max_signatures: 1,
    not_before: ISSUED_AT,
    expires_at: EXPIRES_AT,
    control_sequence: index + 1,
    authority_generation: 7,
    issuer: "agentpass-cloud",
    key_id: "agent-session-2026-08"
  };
}

async function grants() {
  const signer = createLocalAgentSessionGrantSigner({ privateKey: grantKeys.privateKey, keyId: "agent-session-2026-08", now: () => NOW });
  return Promise.all(QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES.map(async (step) => {
    const grant = await signer.signAgentSessionGrant(grantStatement(step.index));
    return {
      ...step,
      run_binding: `qualification-run-${step.index}`,
      grant_id: grant.statement.grant_id,
      grant_hash: digest(canonicalJson(grant)),
      statement_hash: grant.statement_hash,
      grant
    };
  }));
}

async function statement(overrides = {}) {
  return {
    version: 1,
    type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
    batch_id: IDS.batch,
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: "claude-code",
    requested_ttl_seconds: 600,
    candidate_sha256: "b".repeat(64),
    artifact_sha256: "c".repeat(64),
    source_commit: "d".repeat(40),
    team_id: "ABCDE12345",
    release_trust_sha256: "e".repeat(64),
    candidate_checkpoint_sha256: "f".repeat(64),
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    steps: await grants(),
    issuer: "agentpass-cloud",
    key_id: "qualification-batch-2026-08",
    ...overrides
  };
}

async function signedManifest(overrides = {}) {
  const signer = createLocalQualificationGrantBatchManifestSigner({ privateKey: manifestKeys.privateKey, keyId: "qualification-batch-2026-08", now: () => NOW });
  return signer.signQualificationGrantBatchManifest(await statement(overrides));
}

test("signs and verifies a canonical purpose-separated seven-step manifest", async () => {
  const manifest = await signedManifest();
  assert.deepEqual(Object.keys(manifest).sort(), ["signature", "statement", "statement_hash", "type", "version"]);
  assert.equal(manifest.statement.steps.length, 7);
  assert.deepEqual(manifest.statement.steps.map(({ index, kind, scenario, phase }) => ({ index, kind, scenario, phase })), QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES);
  assert.equal(manifest.statement_hash, qualificationGrantBatchManifestStatementHash(manifest.statement));
  assert.deepEqual(verifyQualificationGrantBatchManifest(manifest, { publicKey: manifestKeys.publicKey, now: NOW }), manifest);
  assert.equal(Object.isFrozen(manifest), true);
  assert.equal(Object.isFrozen(manifest.statement.steps[0].grant), true);
  assert.equal(qualificationGrantBatchManifestSigningData(manifest.statement).subarray(0, Buffer.byteLength(QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN)).toString(), QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN);
  assert.notEqual(QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN, AGENT_SESSION_GRANT_SIGNATURE_DOMAIN);
});

test("passes only purpose-bound canonical bytes to a KMS-compatible provider", async () => {
  let metadataCall;
  let signCall;
  const signer = createQualificationGrantBatchManifestSigner({
    keyId: "qualification-batch-2026-08",
    now: () => NOW,
    provider: {
      async publicKeyMetadata(input) { metadataCall = input; return { key_id: input.key_id, algorithm: "ed25519", public_key: manifestKeys.publicKey }; },
      async sign(input) { signCall = input; return crypto.sign(null, input.bytes, manifestKeys.privateKey); }
    }
  });
  const manifest = await signer.signQualificationGrantBatchManifest(await statement());
  assert.deepEqual(metadataCall, { key_id: "qualification-batch-2026-08", purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE });
  assert.deepEqual(Object.keys(signCall).sort(), ["algorithm", "bytes", "key_id", "purpose"]);
  assert.equal(signCall.purpose, QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE);
  assert.equal(signCall.key_id, manifest.statement.key_id);
  assert.equal(signCall.bytes.equals(qualificationGrantBatchManifestSigningData(manifest.statement)), true);
});

test("rejects mutation, reorder, substitution, duplicate identity, and noncanonical input", async () => {
  const manifest = await signedManifest();
  const cases = [
    { ...manifest, statement: { ...manifest.statement, candidate_sha256: "0".repeat(64) } },
    { ...manifest, statement_hash: "0".repeat(64) },
    { ...manifest, signature: Buffer.alloc(64).toString("base64url") },
    { ...manifest, statement: { ...manifest.statement, steps: [...manifest.statement.steps].reverse() } },
    { ...manifest, statement: { ...manifest.statement, steps: manifest.statement.steps.map((step, index) => index === 1 ? { ...step, grant: manifest.statement.steps[2].grant, grant_id: manifest.statement.steps[2].grant_id, grant_hash: manifest.statement.steps[2].grant_hash, statement_hash: manifest.statement.steps[2].statement_hash } : step) } },
    { ...manifest, statement: { ...manifest.statement, steps: manifest.statement.steps.map((step, index) => index === 1 ? { ...step, run_binding: manifest.statement.steps[0].run_binding } : step) } },
    { ...manifest, extra: true }
  ];
  for (const value of cases) assert.throws(() => verifyQualificationGrantBatchManifest(value, { publicKey: manifestKeys.publicKey, now: NOW }), /qualification grant batch manifest/u);
  const accessor = { ...manifest.statement };
  Object.defineProperty(accessor, "candidate_sha256", { enumerable: true, get() { return "0".repeat(64); } });
  assert.throws(() => normalizeQualificationGrantBatchManifestStatement(accessor), { code: QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT });
});

test("rejects cross-purpose signatures and key substitution", async () => {
  const manifest = await signedManifest();
  assert.throws(() => verifyQualificationGrantBatchManifest(manifest, { publicKey: grantKeys.publicKey, now: NOW }), (error) => error.code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
  assert.throws(() => verifyQualificationGrantBatchManifest(manifest, { publicKey: otherKeys.publicKey, now: NOW }), (error) => error.code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
  const grantSigner = createLocalAgentSessionGrantSigner({ privateKey: grantKeys.privateKey, keyId: "agent-session-2026-08", now: () => NOW });
  const ordinaryGrant = await grantSigner.signAgentSessionGrant(grantStatement(0));
  const wrongPurpose = crypto.sign(null, Buffer.concat([Buffer.from(AGENT_SESSION_GRANT_SIGNATURE_DOMAIN), Buffer.from(canonicalJson(manifest.statement))]), grantKeys.privateKey);
  assert.notEqual(crypto.verify(null, qualificationGrantBatchManifestSigningData(manifest.statement), grantKeys.publicKey, wrongPurpose), true);
  assert.equal(ordinaryGrant.type, "agentpass.agent-session-grant");
});

test("enforces manifest and embedded Grant validity windows and max_signatures=1", async () => {
  const manifest = await signedManifest();
  assert.throws(() => verifyQualificationGrantBatchManifest(manifest, { publicKey: manifestKeys.publicKey, now: Date.parse(EXPIRES_AT) }), (error) => error.code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.EXPIRED);
  assert.throws(() => verifyQualificationGrantBatchManifest(manifest, { publicKey: manifestKeys.publicKey, now: NOW - 1 }), (error) => error.code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.NOT_YET_VALID);
  assert.throws(() => normalizeQualificationGrantBatchManifestStatement({ ...manifest.statement, requested_ttl_seconds: 3_601, expires_at: new Date(NOW + 3_601_000).toISOString() }), { code: QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT });
  const alteredSteps = manifest.statement.steps.map((step, index) => index === 0 ? { ...step, grant: { ...step.grant, statement: { ...step.grant.statement, max_signatures: 2 } } } : step);
  assert.throws(() => normalizeQualificationGrantBatchManifestStatement({ ...manifest.statement, steps: alteredSteps }), { code: QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT });
});

test("optionally verifies every unchanged embedded existing Grant envelope", async () => {
  const manifest = await signedManifest();
  assert.equal(verifyQualificationGrantBatchManifest(manifest, { publicKey: manifestKeys.publicKey, grantPublicKey: grantKeys.publicKey, grantKeyId: "agent-session-2026-08", now: NOW }).statement.batch_id, IDS.batch);
  const forged = { ...manifest, statement: { ...manifest.statement, steps: manifest.statement.steps.map((step, index) => index === 0 ? { ...step, grant: { ...step.grant, signature: otherKeys.privateKey ? crypto.sign(null, Buffer.from("wrong"), otherKeys.privateKey).toString("base64url") : step.grant.signature } } : step) } };
  assert.throws(() => verifyQualificationGrantBatchManifest(forged, { publicKey: manifestKeys.publicKey, grantPublicKey: grantKeys.publicKey, now: NOW }), /qualification grant batch manifest/u);
});

test("fails closed on provider metadata and signature output", async () => {
  const base = { keyId: "qualification-batch-2026-08", now: () => NOW };
  const input = await statement();
  const badMetadata = createQualificationGrantBatchManifestSigner({ ...base, provider: { async publicKeyMetadata() { return { key_id: "other", algorithm: "ed25519", public_key: manifestKeys.publicKey }; }, async sign() { return Buffer.alloc(64); } } });
  await assert.rejects(() => badMetadata.signQualificationGrantBatchManifest(input), (error) => error.code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.OUTPUT);
  const badSignature = createQualificationGrantBatchManifestSigner({ ...base, provider: { async publicKeyMetadata() { return { key_id: base.keyId, algorithm: "ed25519", public_key: manifestKeys.publicKey }; }, async sign() { return Buffer.alloc(64); } } });
  await assert.rejects(() => badSignature.signQualificationGrantBatchManifest(input), (error) => error.code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
});
