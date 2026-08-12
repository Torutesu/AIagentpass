import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import pg from "pg";

import {
  bundleAcknowledgementSigningData,
  normalizeBundleAcknowledgement
} from "../../../../packages/protocol/src/index.mjs";
import { createRefreshHintService } from "../../src/refresh-hint-service.mjs";
import { createEd25519RefreshHintSigner } from "../../src/refresh-hint-signer.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";
import { createPostgresRefreshHintNotifier } from "../../src/postgres/refresh-hint-notifier.mjs";
import { createPostgresOrganizationRepository } from "../../src/postgres/organization-repository.mjs";
import { createPostgresControlPlaneResourceRepository } from "../../src/postgres/control-plane-resource-repository.mjs";

const { Pool } = pg;
const databaseUrl = process.env.AGENTPASS_TEST_POSTGRES_URL;
const HALF_ORDER = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");

test("G4 refresh generation, failover reconstruction, and signed ACK are race-safe on PostgreSQL 17", { skip: !databaseUrl, timeout: 15_000 }, async (t) => {
  const poolA = new Pool({ connectionString: databaseUrl, max: 4 });
  const poolB = new Pool({ connectionString: databaseUrl, max: 4 });

  const migrationClient = await poolA.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "g4-refresh-integration" }).run(); }
  finally { migrationClient.release(); }

  const ids = {
    organization: crypto.randomUUID(),
    member: crypto.randomUUID(),
    removedMember: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    removedMembership: crypto.randomUUID(),
    policy: crypto.randomUUID(),
    deviceA: crypto.randomUUID(),
    deviceB: crypto.randomUUID(),
    revocation: crypto.randomUUID()
  };
  const deviceAKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const deviceBKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const deviceAPublic = deviceAKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const deviceBPublic = deviceBKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await poolA.query("INSERT INTO organizations (id,name) VALUES ($1,'G4 integration')", [ids.organization]);
  await poolA.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'G4 owner'),($3,$4,'G4 removed')", [ids.member, `g4-${ids.member}`, ids.removedMember, `g4-${ids.removedMember}`]);
  await poolA.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [ids.organization, ids.membership, ids.member]);
  await poolA.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'viewer','active')", [ids.organization, ids.removedMembership, ids.removedMember]);
  await poolA.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'Mac A','p256-sha256',$3,'active','{}'::jsonb),($1,$4,'Mac B','p256-sha256',$5,'active','{}'::jsonb)`, [ids.organization, ids.deviceA, deviceAPublic, ids.deviceB, deviceBPublic]);
  await poolA.query(`INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
    VALUES ($1,$2,1,'default',$3::jsonb,'active',$4)`, [ids.organization, ids.policy, JSON.stringify({ operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } }), ids.member]);

  const codec = createRefreshNonceCodec({ keys: { "refresh-nonce-v3": Buffer.alloc(32, 0x73) }, activeKeyId: "refresh-nonce-v3" });
  const repositoryA = createControlPlaneAuthorityRepository({ client: poolA, cursorSecret: Buffer.alloc(32, 0x41), refreshNonceCodec: codec });
  const repositoryB = createControlPlaneAuthorityRepository({ client: poolB, cursorSecret: Buffer.alloc(32, 0x42), refreshNonceCodec: codec });
  const onAuthorityReduction = async ({ tx, organization_id, occurred_at, policy }) => {
    const issuedAt = occurred_at ?? policy?.updated_at;
    const transactionAuthority = createControlPlaneAuthorityRepository({
      client: transactionBoundClient(tx),
      cursorSecret: Buffer.alloc(32, 0x43),
      refreshNonceCodec: codec
    });
    return transactionAuthority.advanceAuthorityGenerationAndEnqueueRefresh({ organization_id, issued_at: issuedAt, expires_at: new Date(Date.parse(issuedAt) + 5 * 60_000).toISOString() });
  };
  const notifier = createPostgresRefreshHintNotifier({ pool: poolB });
  t.after(async () => { await notifier.close(); await Promise.all([poolA.end(), poolB.end()]); });
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 4 * 60_000).toISOString();
  const reduction = {
    organization_id: ids.organization,
    target_type: "device",
    target_id: ids.deviceB,
    reason: "integration-revoke",
    created_by: ids.member,
    revocation_id: ids.revocation,
    created_at: issuedAt,
    issued_at: issuedAt,
    expires_at: expiresAt
  };
  const notification = notifier.waitForRefresh({ organization_id: ids.organization, device_id: ids.deviceA, after_generation: 1, timeout_ms: 2_000 });
  for (let attempt = 0; attempt < 100 && !notifier.snapshot().connected; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(notifier.snapshot().connected, true);
  let left;
  let right;
  try {
    [left, right] = await Promise.all([
      repositoryA.reduceAuthorityAndEnqueueRefresh(reduction),
      repositoryB.reduceAuthorityAndEnqueueRefresh(reduction)
    ]);
  } catch (error) {
    assert.fail(`authority race failed: ${error.cause?.message ?? error.message}`);
  }
  assert.deepEqual([left.generation, right.generation], [2, 2]);
  assert.equal(await notification, true);
  assert.deepEqual([left.devices.length, right.devices.length].sort(), [0, 2]);
  assert.equal([left.revocation.replayed === true, right.revocation.replayed === true].filter(Boolean).length, 1);
  const authority = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(authority.rows[0].generation), 2);
  const outboxCount = await poolA.query("SELECT count(*)::int AS count FROM device_refresh_outbox WHERE organization_id=$1 AND desired_generation=2", [ids.organization]);
  assert.equal(outboxCount.rows[0].count, 2);

  const hintKeys = crypto.generateKeyPairSync("ed25519");
  const signer = createEd25519RefreshHintSigner({ privateKey: hintKeys.privateKey, keyId: "refresh-integration-v1" });
  const serviceA = createRefreshHintService({ source: repositoryA, nonceDeriver: codec, signer });
  const serviceAfterRestart = createRefreshHintService({ source: repositoryB, nonceDeriver: codec, signer });
  const hintA = await serviceA.poll({ organization_id: ids.organization, device_id: ids.deviceA, after_generation: 1, wait_ms: 0 });
  const hintAfterRestart = await serviceAfterRestart.poll({ organization_id: ids.organization, device_id: ids.deviceA, after_generation: 1, wait_ms: 0 });
  assert.equal(hintA.authority_generation, 2);
  assert.equal(hintAfterRestart.nonce, hintA.nonce);
  assert.equal(hintA.key_id, "refresh-integration-v1");

  const bundle = await repositoryA.snapshotAndAssignBundleHead({
    organization_id: ids.organization,
    device_id: ids.deviceA,
    minimum_sequence: 1,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString()
  });
  assert.equal(bundle.desired_generation, 2);
  const acknowledgement = signAcknowledgement({
    privateKey: deviceAKeys.privateKey,
    organizationId: ids.organization,
    deviceId: ids.deviceA,
    generation: 2,
    sequence: bundle.head.sequence,
    statementHash: bundle.head.state_fingerprint,
    nonce: hintA.nonce
  });
  const wrongNonceAcknowledgement = signAcknowledgement({
    privateKey: deviceAKeys.privateKey,
    organizationId: ids.organization,
    deviceId: ids.deviceA,
    generation: 2,
    sequence: bundle.head.sequence,
    statementHash: bundle.head.state_fingerprint,
    nonce: Buffer.alloc(16, 0x99).toString("base64url")
  });
  await assert.rejects(repositoryA.acknowledgeBundle(wrongNonceAcknowledgement), { code: "ERR_ACK_CONFLICT" });
  const beforeValidAck = await poolA.query("SELECT count(*)::int AS count FROM device_bundle_acknowledgements WHERE organization_id=$1 AND device_id=$2", [ids.organization, ids.deviceA]);
  assert.equal(beforeValidAck.rows[0].count, 0);
  const [ackA, ackB] = await Promise.all([
    repositoryA.acknowledgeBundle(acknowledgement),
    repositoryB.acknowledgeBundle(acknowledgement)
  ]);
  assert.deepEqual([ackA.duplicate, ackB.duplicate].sort(), [false, true]);
  assert.equal(ackA.observed_generation, 2);
  assert.equal(ackB.observed_generation, 2);
  assert.equal(ackA.refresh_state, "applied");
  assert.equal(ackB.refresh_state, "applied");
  const acknowledgements = await poolA.query("SELECT count(*)::int AS count FROM device_bundle_acknowledgements WHERE organization_id=$1 AND device_id=$2", [ids.organization, ids.deviceA]);
  assert.equal(acknowledgements.rows[0].count, 1);

  const hintB = await serviceAfterRestart.poll({ organization_id: ids.organization, device_id: ids.deviceB, after_generation: 1, wait_ms: 0 });
  const bundleB = await repositoryB.snapshotAndAssignBundleHead({
    organization_id: ids.organization,
    device_id: ids.deviceB,
    minimum_sequence: 1,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString()
  });
  const blocked = signAcknowledgement({
    privateKey: deviceBKeys.privateKey,
    organizationId: ids.organization,
    deviceId: ids.deviceB,
    generation: 2,
    sequence: bundleB.head.sequence,
    statementHash: bundleB.head.state_fingerprint,
    nonce: hintB.nonce,
    result: "blocked",
    reasonCode: "bundle_expired"
  });
  const blockedResult = await repositoryB.acknowledgeBundle(blocked);
  assert.deepEqual(blockedResult, { duplicate: false, observed_generation: 2, refresh_state: "blocked" });

  await assert.rejects(repositoryA.reduceAuthorityAndEnqueueRefresh({ ...reduction, revocation_id: crypto.randomUUID(), target_id: crypto.randomUUID() }), { code: "ERR_NOT_FOUND" });
  const afterRollback = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(afterRollback.rows[0].generation), 2);

  const organizationRepository = createPostgresOrganizationRepository({
    client: poolA,
    onAuthorityReduction
  });
  const removedAt = new Date().toISOString();
  let removed;
  try {
    removed = await organizationRepository.removeMember({ organization_id: ids.organization, actor_member_id: ids.member, member_id: ids.removedMember, expected_version: 1, removed_at: removedAt, idempotency_key: "g4-member-remove" });
  } catch (error) {
    assert.fail(`membership authority propagation failed: ${error.cause?.message ?? error.message}`);
  }
  assert.equal(removed.status, "revoked");
  const memberGeneration = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(memberGeneration.rows[0].generation), 3);
  const memberOutbox = await poolA.query("SELECT count(*)::int AS count FROM device_refresh_outbox WHERE organization_id=$1 AND desired_generation=3", [ids.organization]);
  assert.equal(memberOutbox.rows[0].count, 2);
  const replayedRemoval = await organizationRepository.removeMember({ organization_id: ids.organization, actor_member_id: ids.member, member_id: ids.removedMember, expected_version: 1, removed_at: new Date().toISOString(), idempotency_key: "g4-member-remove" });
  assert.equal(replayedRemoval.replayed, true);
  const generationAfterReplay = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(generationAfterReplay.rows[0].generation), 3);

  const resourceRepository = createPostgresControlPlaneResourceRepository({ client: poolA, onAuthorityReduction });
  const disabledPolicy = await resourceRepository.updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: { status: "disabled" }, principal_id: ids.member, idempotency_key: "g4-policy-disable" });
  assert.equal(disabledPolicy.status, "disabled");
  const policyGeneration = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(policyGeneration.rows[0].generation), 4);
  const policyOutbox = await poolA.query("SELECT count(*)::int AS count FROM device_refresh_outbox WHERE organization_id=$1 AND desired_generation=4", [ids.organization]);
  assert.equal(policyOutbox.rows[0].count, 2);
  const replayedPolicy = await resourceRepository.updatePolicy({ organization_id: ids.organization, policy_id: ids.policy, expected_version: 1, patch: { status: "disabled" }, principal_id: ids.member, idempotency_key: "g4-policy-disable" });
  assert.equal(replayedPolicy.status, "disabled");
  const policyGenerationAfterReplay = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(policyGenerationAfterReplay.rows[0].generation), 4);
});

function transactionBoundClient(tx) {
  return Object.freeze({
    async query(text, params) {
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return { rows: [], rowCount: 0 };
      return tx.query(text, params);
    }
  });
}

function signAcknowledgement({ privateKey, organizationId, deviceId, generation, sequence, statementHash, nonce, result = "applied", reasonCode }) {
  const unsigned = {
    version: 1,
    type: "agentpass.bundle-ack",
    organization_id: organizationId,
    device_id: deviceId,
    device_key_epoch: 1,
    format_epoch: 2,
    sequence,
    statement_hash: statementHash,
    result,
    observed_at: new Date().toISOString(),
    nonce,
    signature_algorithm: "p256-sha256"
  };
  if (reasonCode !== undefined) unsigned.reason_code = reasonCode;
  const placeholder = { ...unsigned, signature: Buffer.alloc(64, 1).toString("base64url") };
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const signature = crypto.sign("sha256", bundleAcknowledgementSigningData(placeholder), { key: privateKey, dsaEncoding: "ieee-p1363" });
    if (signature.subarray(32).compare(HALF_ORDER) <= 0) return normalizeBundleAcknowledgement({ ...unsigned, signature: signature.toString("base64url") });
  }
  throw new Error("could not produce a canonical low-S test signature");
}
