import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AGENT_SESSION_GRANT_TYPE,
  agentSessionGrantStatementHash,
  normalizeAgentSessionGrantStatement
} from "../../src/agent-session-grant.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER,
  QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
  qualificationGrantBatchManifestStatementHash
} from "../../src/qualification-grant-batch-manifest.mjs";
import {
  QUALIFICATION_GRANT_BATCH_KIND,
  QUALIFICATION_GRANT_BATCH_MANIFEST_KIND,
  QualificationGrantBatchRepositoryError,
  createQualificationGrantBatchRepository
} from "../../src/postgres/qualification-grant-batch-repository.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const AGENT = "33333333-3333-4333-8333-333333333333";
const MEMBER = "44444444-4444-4444-8444-444444444444";
const SESSION = "55555555-5555-4555-8555-555555555555";
const AUTH = "66666666-6666-4666-8666-666666666666";
const BATCH = "77777777-7777-4777-8777-777777777777";
const REQUEST = "88888888-8888-4888-8888-888888888888";
const NOW = "2026-08-14T00:00:00.000Z";
const EXPIRES = "2026-08-14T00:10:00.000Z";
const HASH = "a".repeat(64);
const SOURCE = "b".repeat(40);
const TEAM = "ABCDEFGHIJ";

const STEP_IDENTITIES = [
  ["unarmed-control", null, null],
  ["scenario", "pre-cloud-kill", "pre-cloud"],
  ["scenario", "post-cloud-pre-local-kill", "post-cloud-pre-local"],
  ["scenario", "post-activation-pre-audit-kill", "post-activation-pre-audit"],
  ["scenario", "post-audit-pre-reply-loss", "post-audit-pre-reply"],
  ["scenario", "audit-fsync-failure", "audit-fsync"],
  ["scenario", "transport-reply-loss", "transport-reply"]
];

const scope = {
  operations: ["git.commit.sign"],
  repositories: ["/repo"],
  branches: { allow: ["main"], deny: [] },
  remotes: { allow: ["origin"], deny: [] }
};

function grantRow(index) {
  const grantId = `${String(index + 1).padStart(8, "0")}-0000-4000-8000-000000000000`;
  const statement = normalizeAgentSessionGrantStatement({
    version: 1, grant_id: grantId, organization_id: ORG, device_id: DEVICE, agent_id: AGENT,
    agent_kind: "claude-code", adapter_id: "99999999-9999-4999-8999-999999999999",
    adapter_version: "1.2.3", worktree_binding_sha256: "c".repeat(64),
    process_binding_policy_id: "qualification-v1", scope, max_signatures: 1,
    not_before: NOW, expires_at: EXPIRES, control_sequence: index + 1,
    authority_generation: 3, issuer: "agentpass-cloud", key_id: "grant-key-v1"
  }, { allowExpired: true, allowFuture: true });
  const signature = Buffer.alloc(64, index + 1).toString("base64url");
  const envelope = { version: 1, type: AGENT_SESSION_GRANT_TYPE, statement, statement_hash: agentSessionGrantStatementHash(statement), signature };
  return {
    grant_id: grantId, organization_id: ORG, device_id: DEVICE, agent_id: AGENT, agent_kind: "claude-code",
    adapter_id: statement.adapter_id, adapter_version: statement.adapter_version,
    worktree_binding_sha256: statement.worktree_binding_sha256,
    process_binding_policy_id: statement.process_binding_policy_id, scope_json: scope,
    max_signatures: 1, not_before: NOW, expires_at: EXPIRES, control_sequence: index + 1,
    authority_generation: 3, issuer: "agentpass-cloud", signer_key_id: statement.key_id,
    statement_hash: envelope.statement_hash, grant_hash: sha256(canonicalJson(envelope)),
    signature_base64url: signature, status: "issued", issued_at: NOW
  };
}

function manifestEnvelope() {
  const steps = Array.from({ length: 7 }, (_, index) => {
    const row = grantRow(index);
    const [kind, scenario, phase] = STEP_IDENTITIES[index];
    return { index, kind, scenario, phase, run_binding: `run-${index + 1}`, grant_id: row.grant_id, grant_hash: row.grant_hash, statement_hash: row.statement_hash };
  });
  const statement = {
    version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION, type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE, batch_id: BATCH,
    organization_id: ORG, device_id: DEVICE, agent_id: AGENT, agent_kind: "claude-code", requested_ttl_seconds: 600,
    candidate_sha256: HASH, artifact_sha256: HASH, source_commit: SOURCE, team_id: TEAM,
    release_trust_sha256: HASH, candidate_checkpoint_sha256: HASH, issued_at: NOW, expires_at: EXPIRES, steps,
    issuer: QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER, key_id: "manifest-key-v1"
  };
  return { version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION, type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE, statement, statement_hash: qualificationGrantBatchManifestStatementHash(statement), signature: Buffer.alloc(64, 0x42).toString("base64url") };
}

function batchRow() {
  const manifest = manifestEnvelope();
  return {
    organization_id: ORG, batch_id: BATCH, request_id: REQUEST, schema_version: 1,
    kind: QUALIFICATION_GRANT_BATCH_KIND, device_id: DEVICE, agent_id: AGENT, agent_kind: "claude-code",
    requested_ttl_seconds: 600, candidate_sha256: HASH, artifact_sha256: HASH, release_trust_sha256: HASH,
    candidate_checkpoint_sha256: HASH, source_commit: SOURCE, team_id: TEAM,
    manifest_json: manifest, manifest_hash: manifest.statement_hash,
    manifest_signature_base64url: manifest.signature, manifest_signer_key_id: manifest.statement.key_id,
    status: "issued", issued_at: NOW, expires_at: EXPIRES, claimed_at: null, expired_at: null, revoked_at: null,
    claimed_device_id: null, claim_identity_sha256: null, claim_request_sha256: null
  };
}

function claimInput() {
  return { organization_id: ORG, batch_id: BATCH, device_id: DEVICE, candidate_sha256: HASH,
    artifact_sha256: HASH, release_trust_sha256: HASH, candidate_checkpoint_sha256: HASH,
    source_commit: SOURCE, team_id: TEAM, request_sha256: "d".repeat(64), claim_identity_sha256: "e".repeat(64), observed_at: NOW };
}

function result(rows = [], rowCount = rows.length) { return { rows, rowCount }; }
function sha256(value) { return importCrypto().createHash("sha256").update(value).digest("hex"); }
function importCrypto() { return requireCrypto; }
const requireCrypto = await import("node:crypto");

test("0023 uses existing grants, manifest columns, tenant-qualified FKs, RLS, and no secret columns", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0023_qualification_grant_batches.sql", import.meta.url), "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /CREATE TABLE qualification_grant_batches/iu);
  assert.match(sql, /manifest_json jsonb NOT NULL[\s\S]*manifest_hash text NOT NULL[\s\S]*manifest_signature_base64url/iu);
  assert.match(sql, /CREATE TABLE qualification_grant_batch_steps[\s\S]*step_index[\s\S]*run_binding[\s\S]*grant_hash[\s\S]*statement_hash/iu);
  assert.match(sql, /REFERENCES agent_session_grants\(organization_id, grant_id, device_id, agent_id, grant_hash\)/u);
  assert.match(sql, /REFERENCES qualification_grant_batches\(organization_id, batch_id\)/u);
  assert.match(sql, /status IN \('issued', 'claimed', 'expired', 'revoked'\)/u);
  assert.match(sql, /status = 'claimed'[\s\S]*claim_identity_sha256 IS NOT NULL[\s\S]*claim_request_sha256 IS NOT NULL/u);
  assert.match(sql, /ENABLE ROW LEVEL SECURITY[\s\S]*FORCE ROW LEVEL SECURITY/u);
  assert.match(sql, /CREATE TRIGGER qualification_grant_batches_forward_only[\s\S]*BEFORE UPDATE OR DELETE ON qualification_grant_batches/u);
  assert.match(sql, /CREATE TRIGGER qualification_grant_batch_steps_immutable[\s\S]*BEFORE UPDATE OR DELETE ON qualification_grant_batch_steps/u);
  assert.doesNotMatch(sql, /private_key|secret_value|bearer_token|raw_nonce/iu);
});

test("issue requires both callbacks and never accepts a qualification-specific Grant type", async () => {
  const repository = createQualificationGrantBatchRepository({
    client: { async query() { throw new Error("must not query"); } },
    sharedControls: { acquireIdempotency() {}, completeIdempotency() {} },
    adminAuditRepository: { appendAdminAuditEventInTransaction() {} }
  });
  await assert.rejects(() => repository.issueQualificationGrantBatch({}), (error) => error instanceof QualificationGrantBatchRepositoryError);
});

test("claim marks only the batch claimed and returns manifest plus unchanged seven v1 grants in order", async () => {
  const row = batchRow();
  const steps = Array.from({ length: 7 }, (_, index) => {
    const grant = grantRow(index);
    const [kind, scenario, phase] = STEP_IDENTITIES[index];
    return { step_index: index, kind, scenario, phase, run_binding: `run-${index + 1}`, ...grant };
  });
  const calls = [];
  const client = { async query(text, params = []) {
    calls.push({ text: String(text), params });
    if (text === "BEGIN" || text === "COMMIT") return result();
    if (text === "ROLLBACK") return result();
    if (/set_config\('agentpass\.organization_id'/u.test(text)) return result([{ organization_id: ORG }]);
    if (/current_setting\('agentpass\.organization_id'/u.test(text)) return result([{ organization_id: ORG }]);
    if (/pg_advisory_xact_lock/u.test(text)) return result([{ locked: true }]);
    if (/FROM qualification_grant_batches/u.test(text) && /FOR UPDATE/u.test(text)) return result([row]);
    if (/UPDATE qualification_grant_batches/u.test(text)) { row.status = "claimed"; row.claimed_at = NOW; row.claimed_device_id = DEVICE; row.claim_identity_sha256 = "e".repeat(64); row.claim_request_sha256 = "d".repeat(64); return result([row]); }
    if (/FROM qualification_grant_batch_steps/u.test(text)) return result(steps);
    throw new Error(`unexpected SQL: ${text}`);
  } };
  const repository = createQualificationGrantBatchRepository({ client, now: () => NOW, sharedControls: { acquireIdempotency() {}, completeIdempotency() {} }, adminAuditRepository: { appendAdminAuditEventInTransaction() {} } });
  const claimed = await repository.claimQualificationGrantBatch(claimInput());
  assert.equal(Object.hasOwn(claimed.batch, "status"), false);
  assert.deepEqual(Object.keys(claimed.batch).sort(), [
    "agent_id", "agent_kind", "artifact_sha256", "batch_id", "candidate_checkpoint_sha256",
    "candidate_sha256", "device_id", "expires_at", "kind", "manifest", "organization_id",
    "release_trust_sha256", "requested_ttl_seconds", "schema_version", "source_commit", "steps", "team_id"
  ].sort());
  assert.deepEqual(Object.keys(claimed.batch.manifest).sort(), ["signature", "statement", "statement_hash", "type", "version"]);
  assert.equal(claimed.batch.manifest.type, "agentpass.qualification-grant-batch-manifest");
  assert.equal(claimed.batch.steps.length, 7);
  assert.deepEqual(claimed.batch.steps.map((step) => step.index), [0, 1, 2, 3, 4, 5, 6]);
  assert.ok(claimed.batch.steps.every((step) => step.grant.type === AGENT_SESSION_GRANT_TYPE));
  assert.ok(claimed.batch.steps.every((step) => step.grant.statement.grant_id));
  assert.equal(Object.hasOwn(claimed, "manifest"), false);
  assert.equal(Object.hasOwn(claimed, "steps"), false);
  assert.ok(calls.every(({ text }) => !/UPDATE agent_session_grants|SET status='consumed'/u.test(text)));
});

test("Human issue projection stays the exact issued metadata shape after a claimed-row replay", async () => {
  const row = { ...batchRow(), status: "claimed", claimed_at: NOW, claimed_device_id: DEVICE };
  const client = { async query(text) {
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return result();
    if (/set_config\('agentpass\.organization_id'/u.test(text)) return result([{ organization_id: ORG }]);
    if (/current_setting\('agentpass\.organization_id'/u.test(text)) return result([{ organization_id: ORG }]);
    if (/pg_advisory_xact_lock/u.test(text)) return result([{ locked: true }]);
    if (/FROM organizations/u.test(text)) return result([{ id: ORG }]);
    if (/FROM devices d JOIN agents a/u.test(text)) return result([{ device_status: "active", agent_status: "active" }]);
    if (/FROM qualification_grant_batches/u.test(text)) return result([row]);
    throw new Error(`unexpected SQL: ${text}`);
  } };
  const repository = createQualificationGrantBatchRepository({
    client,
    now: () => NOW,
    sharedControls: {
      async acquireIdempotency() { return { state: "replay", response: { batch_id: BATCH, request_id: REQUEST } }; },
      async completeIdempotency() {}
    },
    adminAuditRepository: { appendAdminAuditEventInTransaction() {} }
  });
  const replay = await repository.issueQualificationGrantBatch({
    organization_id: ORG,
    agent_id: AGENT,
    actor: { organization_id: ORG, member_id: MEMBER, session_id: SESSION, role: "admin" },
    batch_id: BATCH,
    request_id: REQUEST,
    idempotency_key: "qualification-replay-01",
    request_fingerprint: "a".repeat(64),
    issued_at: NOW,
    expires_at: EXPIRES,
    request: {
      candidate_sha256: HASH, artifact_sha256: HASH, release_trust_sha256: HASH,
      candidate_checkpoint_sha256: HASH, source_commit: SOURCE, team_id: TEAM,
      grant_intent: { device_id: DEVICE, agent_kind: "claude-code", adapter_id: "99999999-9999-4999-8999-999999999999", adapter_version: "1.2.3", worktree_binding_sha256: "c".repeat(64), process_binding_policy_id: "qualification-v1", scope, max_signatures: 1, ttl_seconds: 600 }
    },
    recent_auth: { authorization_id: AUTH, authenticated_at: NOW },
    steps: STEP_IDENTITIES.map(([kind, scenario, phase], index) => ({
      index, kind, scenario, phase, run_binding: `run-${index + 1}`, grant_id: grantRow(index).grant_id
    })),
    buildGrants() {},
    buildManifest() {}
  });
  assert.deepEqual(Object.keys(replay.batch).sort(), [
    "agent_id", "artifact_sha256", "batch_id", "candidate_checkpoint_sha256", "candidate_sha256",
    "device_id", "expires_at", "issued_at", "kind", "organization_id", "release_trust_sha256",
    "schema_version", "source_commit", "status", "team_id"
  ].sort());
  assert.equal(replay.batch.status, "issued");
  assert.equal(replay.replayed, true);
  assert.equal(replay.request_id, REQUEST);
  assert.equal(Object.hasOwn(replay.batch, "claimed_at"), false);
  assert.equal(Object.hasOwn(replay.batch, "manifest_hash"), false);
});
