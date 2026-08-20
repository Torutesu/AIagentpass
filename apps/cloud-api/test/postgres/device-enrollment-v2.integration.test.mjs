import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createLocalPossessionReceiptSigner } from "../../src/possession-receipt-signer.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresControlPlaneResourceRepository } from "../../src/postgres/control-plane-resource-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const postgresSkipReason = databaseUrl ? false : "set AGENTPASS_TEST_DATABASE_URL to run the live PostgreSQL device enrollment integration test";

test("live PostgreSQL v2 enrollment completes atomically, replays exactly, and stores only bound digests", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createFixture(t);
  const enrollment = await fixture.repository.createReleaseCandidate(fixture.candidate);
  assert.equal(enrollment.status, "active");

  const issued = await fixture.repository.createDeviceEnrollmentV2({
    proof_version: 2,
    organization_id: fixture.organization,
    enrollment_id: fixture.enrollmentId,
    device_id: fixture.deviceId,
    label: "Qualification Mac",
    platform: "macos",
    credential_digest: fixture.credentialDigest,
    challenge_nonce_digest: fixture.challengeDigest,
    candidate_id: fixture.candidate.candidate_id,
    device_key_fingerprint: fixture.deviceFingerprint,
    created_at: fixture.now,
    expires_at: fixture.expiresAt,
    created_by: fixture.member,
    principal_id: fixture.member,
    idempotency_key: "integration-enrollment-1"
  });
  assert.equal(issued.proof_version, 2);
  assert.equal(issued.challenge_nonce_digest, fixture.challengeDigest);

  const completed = await fixture.repository.completeDeviceEnrollmentV2(fixture.completion);
  assert.equal(completed.status, "active");
  assert.equal(completed.key_epoch, 1);

  const replay = await fixture.repository.completeDeviceEnrollmentV2(fixture.completion);
  assert.deepEqual(replay, completed);
  const concurrent = await Promise.all([
    fixture.repository.completeDeviceEnrollmentV2(fixture.completion),
    fixture.repository.completeDeviceEnrollmentV2(fixture.completion)
  ]);
  assert.deepEqual(concurrent[0], completed);
  assert.deepEqual(concurrent[1], completed);

  const receipt = await fixture.repository.getDeviceEnrollmentPossessionReceipt({ organization_id: fixture.organization, device_id: fixture.deviceId });
  assert.equal(receipt.statement.challenge_nonce_digest, fixture.challengeDigest);
  assert.equal(receipt.statement.device_key_fingerprint, fixture.deviceFingerprint);
  assert.equal(receipt.statement.device_key_epoch, 1);
  assert.equal(receipt.statement.organization_id, fixture.organization);
  assert.equal(receipt.statement.device_id, fixture.deviceId);
  assert.equal((await scalar(fixture.pool, "SELECT count(*) FROM device_enrollment_possession_receipts WHERE organization_id=$1 AND enrollment_id=$2", [fixture.organization, fixture.enrollmentId])), 1);
  assert.equal((await scalar(fixture.pool, "SELECT count(*) FROM device_key_epochs WHERE organization_id=$1 AND device_id=$2 AND status='active'", [fixture.organization, fixture.deviceId])), 1);
  const stored = await fixture.pool.query("SELECT encode(secret_hash,'hex') AS credential_digest, encode(challenge_nonce_digest,'hex') AS challenge_digest FROM device_enrollments WHERE organization_id=$1 AND id=$2", [fixture.organization, fixture.enrollmentId]);
  assert.equal(stored.rowCount, 1);
  assert.equal(stored.rows[0].credential_digest, fixture.credentialDigest);
  assert.equal(stored.rows[0].challenge_digest, fixture.challengeDigest);
  assert.equal(JSON.stringify(stored.rows[0]).includes(fixture.credential), false);
  assert.equal(JSON.stringify(stored.rows[0]).includes(fixture.challenge), false);
});

async function createFixture(t) {
  const pool = new Pool({ connectionString: databaseUrl, max: 8, connectionTimeoutMillis: 2_000, statement_timeout: 10_000, query_timeout: 12_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "device-enrollment-v2-integration" }).run(); }
  finally { migrationClient.release(); }

  const organization = crypto.randomUUID();
  const member = crypto.randomUUID();
  const membership = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const enrollmentId = crypto.randomUUID();
  const now = new Date(Date.now()).toISOString();
  const expiresAt = new Date(Date.parse(now) + 10 * 60 * 1_000).toISOString();
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const devicePublicKey = deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const deviceFingerprint = `SHA256:${crypto.createHash("sha256").update(deviceKeys.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const credential = crypto.randomBytes(32).toString("base64url");
  const credentialDigest = crypto.createHash("sha256").update(credential, "utf8").digest("hex");
  const challenge = crypto.randomBytes(32).toString("base64url");
  const challengeDigest = crypto.createHash("sha256").update(challenge, "utf8").digest("hex");
  const receiptKeys = crypto.generateKeyPairSync("ed25519");
  const receiptSigner = createLocalPossessionReceiptSigner({ privateKey: receiptKeys.privateKey, keyId: "possession-integration-v1", algorithm: "ed25519" });
  const candidate = { candidate_id: `candidate-integration-${enrollmentId.slice(0, 8)}`, source_commit: "a".repeat(40), artifact_sha256: "b".repeat(64), manifest_sha256: "c".repeat(64), team_id: "TEAMID2026" };
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organization, "Enrollment integration"]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [member, `integration-${member}`, "Integration owner"]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organization, membership, member]);
  await pool.query("INSERT INTO devices (organization_id,id,label,key_algorithm,status) VALUES ($1,$2,$3,'p256-sha256','pending')", [organization, deviceId, "Qualification Mac"]);
  const repository = createPostgresControlPlaneResourceRepository({ client: pool, now: () => now });
  const storedCandidate = await repository.createReleaseCandidate(candidate);
  const receipt = await receiptSigner.signPossessionReceipt({ version: 1, enrollment_id: enrollmentId, organization_id: organization, device_id: deviceId, candidate_id: storedCandidate.candidate_id, artifact_sha256: storedCandidate.artifact_sha256, source_commit: storedCandidate.source_commit, team_id: storedCandidate.team_id, device_key_fingerprint: deviceFingerprint, device_key_epoch: 1, challenge_nonce_digest: challengeDigest, issued_at: now });
  return { pool, repository, organization, member, deviceId, enrollmentId, now, expiresAt, candidate: storedCandidate, credential, credentialDigest, challenge, challengeDigest, deviceFingerprint, completion: { proof_version: 2, organization_id: organization, enrollment_id: enrollmentId, device_id: deviceId, label: "Qualification Mac", platform: "macos", algorithm: "p256-sha256", public_key: devicePublicKey, credential_digest: credentialDigest, candidate_id: storedCandidate.candidate_id, device_key_fingerprint: deviceFingerprint, challenge_nonce_digest: challengeDigest, completed_at: now, possession_receipt: receipt } };
}

async function scalar(pool, text, params) {
  const result = await pool.query(text, params);
  assert.equal(result.rowCount, 1);
  return Number(result.rows[0].count);
}
