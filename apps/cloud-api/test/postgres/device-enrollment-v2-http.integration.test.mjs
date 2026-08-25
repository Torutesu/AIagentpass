import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createApiTokenRecord } from "../../src/auth.mjs";
import { createCloudApi } from "../../src/server.mjs";
import { createLocalPossessionReceiptSigner } from "../../src/possession-receipt-signer.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresControlPlaneResourceRepository } from "../../src/postgres/control-plane-resource-repository.mjs";
import { createPostgresControlPlaneStore } from "../../src/postgres/control-plane-store.mjs";
import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const skipReason = databaseUrl ? false : "set AGENTPASS_TEST_DATABASE_URL to run the live PostgreSQL HTTP idempotency test";
const RECENT_PROOF = "99999999-9999-4999-8999-999999999999";

test("v2 enrollment HTTP issue replay and concurrent completion are single-commit idempotent", { skip: skipReason }, async (t) => {
  const fixture = await createFixture(t);
  const issuePath = `/v1/organizations/${fixture.organization}/device-enrollments`;
  const issueBody = {
    proof_version: 2,
    candidate_id: fixture.candidate.candidate_id,
    device_key_fingerprint: fixture.deviceFingerprint,
    enrollment_id: fixture.enrollmentId,
    device_id: fixture.deviceId,
    label: "HTTP idempotency Mac",
    platform: "macos",
    ttl_ms: 600_000
  };
  const issueHeaders = {
    authorization: `Bearer ${fixture.token}`,
    "content-type": "application/json",
    "idempotency-key": "http-enrollment-v2-issue-0001",
    "agentpass-recent-auth": RECENT_PROOF
  };

  const issued = await fetch(`${fixture.base}${issuePath}`, { method: "POST", headers: issueHeaders, body: JSON.stringify(issueBody) });
  assert.equal(issued.status, 201, JSON.stringify(await issued.clone().json()));
  const invitation = (await issued.json()).enrollment;
  const issueReplay = await fetch(`${fixture.base}${issuePath}`, { method: "POST", headers: issueHeaders, body: JSON.stringify(issueBody) });
  assert.equal(issueReplay.status, 201, JSON.stringify(await issueReplay.clone().json()));
  assert.deepEqual((await issueReplay.json()).enrollment, invitation, "same issue idempotency key must replay the exact HTTP envelope");

  const completion = makeCompletion({ fixture, invitation });
  const completionHeaders = {
    "content-type": "application/json",
    "agentpass-enrollment-credential": invitation.credential,
    "agentpass-enrollment-candidate-binding": canonicalJson(invitation.candidate_binding),
    "agentpass-enrollment-nonce": invitation.nonce,
    "agentpass-enrollment-signature": completion.signature
  };
  const completionUrl = `${fixture.base}${invitation.endpoint}`;
  const responses = await Promise.all([
    fetch(completionUrl, { method: "POST", headers: completionHeaders, body: completion.body }),
    fetch(completionUrl, { method: "POST", headers: completionHeaders, body: completion.body })
  ]);
  const payloads = await Promise.all(responses.map(async (response) => ({ status: response.status, body: await response.json() })));
  assert.equal(payloads[0].status, 201, JSON.stringify(payloads));
  assert.equal(payloads[1].status, 201, JSON.stringify(payloads));
  assert.deepEqual(payloads[0].body.enrollment, payloads[1].body.enrollment, "concurrent identical completions must converge on the same committed enrollment result");
  assert.equal(payloads[0].body.enrollment.status, "active");
  assert.equal(payloads[0].body.enrollment.device_key_epoch, 1);

  const completionReplay = await fetch(completionUrl, { method: "POST", headers: completionHeaders, body: completion.body });
  assert.equal(completionReplay.status, 201, JSON.stringify(await completionReplay.clone().json()));
  assert.deepEqual((await completionReplay.json()).enrollment, payloads[0].body.enrollment, "a later retry must replay the same completed enrollment result");

  assert.equal(await scalar(fixture.pool, "SELECT count(*) FROM devices WHERE organization_id=$1 AND id=$2 AND status='active'", [fixture.organization, fixture.deviceId]), 1);
  assert.equal(await scalar(fixture.pool, "SELECT count(*) FROM device_enrollments WHERE organization_id=$1 AND id=$2 AND consumed_at IS NOT NULL", [fixture.organization, fixture.enrollmentId]), 1);
  assert.equal(await scalar(fixture.pool, "SELECT count(*) FROM device_enrollment_possession_receipts WHERE organization_id=$1 AND enrollment_id=$2", [fixture.organization, fixture.enrollmentId]), 1);
  assert.equal(await scalar(fixture.pool, "SELECT count(*) FROM device_key_epochs WHERE organization_id=$1 AND device_id=$2 AND status='active'", [fixture.organization, fixture.deviceId]), 1);
});

function makeCompletion({ fixture, invitation }) {
  const bodyObject = {
    version: 2,
    proof_version: 2,
    enrollment_id: fixture.enrollmentId,
    organization_id: fixture.organization,
    device_id: fixture.deviceId,
    label: invitation.label,
    platform: "macos",
    device_key: { algorithm: "p256-sha256", spki_pem: fixture.devicePublicKey },
    candidate_id: fixture.candidate.candidate_id,
    device_key_fingerprint: fixture.deviceFingerprint,
    challenge: invitation.challenge
  };
  const body = JSON.stringify(bodyObject);
  const proof = Buffer.from([
    "AgentPass-Enrollment-Proof-v2\0POST",
    invitation.endpoint,
    crypto.createHash("sha256").update(body).digest("hex"),
    crypto.createHash("sha256").update(invitation.credential).digest("hex"),
    invitation.nonce,
    crypto.createHash("sha256").update(canonicalJson(invitation.candidate_binding)).digest("hex")
  ].join("\n"));
  return {
    body,
    signature: crypto.sign("sha256", proof, { key: fixture.deviceKeys.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64")
  };
}

async function createFixture(t) {
  const pool = new Pool({ connectionString: databaseUrl, max: 8, connectionTimeoutMillis: 2_000, statement_timeout: 10_000, query_timeout: 12_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "device-enrollment-v2-http-integration" }).run(); }
  finally { migrationClient.release(); }

  const organization = crypto.randomUUID();
  const member = crypto.randomUUID();
  const membership = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const enrollmentId = crypto.randomUUID();
  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const candidate = { candidate_id: `http-enrollment-${enrollmentId.slice(0, 8)}`, source_commit: "a".repeat(40), artifact_sha256: "b".repeat(64), manifest_sha256: "c".repeat(64), team_id: "TEAMID2026" };
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const devicePublicKey = deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const deviceFingerprint = `SHA256:${crypto.createHash("sha256").update(deviceKeys.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const receiptKeys = crypto.generateKeyPairSync("ed25519");
  const receiptSigner = createLocalPossessionReceiptSigner({ privateKey: receiptKeys.privateKey, keyId: "http-possession-v1", algorithm: "ed25519" });
  const bundleKeys = crypto.generateKeyPairSync("ed25519");
  const refreshKeys = crypto.generateKeyPairSync("ed25519");
  const token = `ap_http_owner_${crypto.randomBytes(18).toString("base64url")}`;

  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organization, "HTTP enrollment integration"]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [member, `http-${member}`, "HTTP owner"]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organization, membership, member]);

  const resourceRepository = createPostgresControlPlaneResourceRepository({ client: pool, now: () => now });
  const storedCandidate = await resourceRepository.createReleaseCandidate({ ...candidate, created_at: now });
  const store = createPostgresControlPlaneStore({ client: pool, now: () => now });
  const server = createCloudApi({
    store,
    tokenRecords: [createApiTokenRecord({ token, tokenId: `http-owner-${member}`, organizationId: organization, memberId: member, role: "owner" })],
    bundleSigner: { privateKey: bundleKeys.privateKey, issuer: "agentpass-cloud", keyId: "http-control-v1", ttlMs: 60_000, offlineTtlMs: 120_000 },
    refreshHintService: { publicKeyMetadata: async () => ({ key_id: "http-refresh-v1", algorithm: "ed25519", public_key: refreshKeys.publicKey.export({ type: "spki", format: "pem" }).toString() }), poll: async () => null },
    possessionReceiptSigner: receiptSigner,
    enrollmentCredentialSecret: Buffer.alloc(32, 0x42),
    now: () => nowMs,
    verifyRecentWebAuthn: async ({ proof, principal, organization_id, operation }) => ({ verified: true, consumed: true, challenge_id: proof, member_id: principal.member_id, organization_id, operation, authenticated_at: now })
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); });
  return { pool, base, token, organization, member, candidate: storedCandidate, deviceId, enrollmentId, deviceKeys, devicePublicKey, deviceFingerprint };
}

async function scalar(pool, text, params) {
  const result = await pool.query(text, params);
  assert.equal(result.rowCount, 1);
  return Number(result.rows[0].count);
}
