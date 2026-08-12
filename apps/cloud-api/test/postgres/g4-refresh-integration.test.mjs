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
import { createCapabilityAuthorityRepository } from "../../src/postgres/capability-authority-repository.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createPostgresAdminAuditRepository } from "../../src/postgres/admin-audit-repository.mjs";
import { createAuthorityReductionAuditAppender } from "../../src/postgres/authority-reduction-audit.mjs";

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
    raceMember: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    removedMembership: crypto.randomUUID(),
    raceMembership: crypto.randomUUID(),
    policy: crypto.randomUUID(),
    agent: crypto.randomUUID(),
    capability: crypto.randomUUID(),
    raceCapability: crypto.randomUUID(),
    sessionA: crypto.randomUUID(),
    sessionB: crypto.randomUUID(),
    deviceA: crypto.randomUUID(),
    deviceB: crypto.randomUUID(),
    revocation: crypto.randomUUID()
  };
  const deviceAKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const deviceBKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const deviceAPublic = deviceAKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const deviceBPublic = deviceBKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await poolA.query("INSERT INTO organizations (id,name) VALUES ($1,'G4 integration')", [ids.organization]);
  await poolA.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'G4 owner'),($3,$4,'G4 removed'),($5,$6,'G4 race member')", [ids.member, `g4-${ids.member}`, ids.removedMember, `g4-${ids.removedMember}`, ids.raceMember, `g4-${ids.raceMember}`]);
  await poolA.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [ids.organization, ids.membership, ids.member]);
  await poolA.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'viewer','active')", [ids.organization, ids.removedMembership, ids.removedMember]);
  await poolA.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'admin','active')", [ids.organization, ids.raceMembership, ids.raceMember]);
  await poolA.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'Mac A','p256-sha256',$3,'active','{}'::jsonb),($1,$4,'Mac B','p256-sha256',$5,'active','{}'::jsonb)`, [ids.organization, ids.deviceA, deviceAPublic, ids.deviceB, deviceBPublic]);
  await poolA.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'claude-code','G4 agent',$4,'active')`, [ids.organization, ids.agent, ids.deviceA, deviceAPublic]);
  await poolA.query(`INSERT INTO capabilities (organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at,issued_by_member_id,issued_membership_version)
    VALUES ($1,$2,$3,$4,1,$5,$6,$7,1)`, [ids.organization, ids.capability, ids.agent, ids.deviceA, "a".repeat(64), new Date(Date.now() + 60 * 60_000).toISOString(), ids.member]);
  const sessionCreatedAt = new Date().toISOString();
  const sessionExpiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
  await poolA.query(`INSERT INTO human_sessions (id,member_id,token_hash,created_at,expires_at,organization_id,membership_id,role)
    VALUES ($1,$2,$3,$4,$5,$6,$7,'owner'),($8,$2,$9,$4,$5,$6,$7,'owner')`, [ids.sessionA, ids.member, crypto.randomBytes(32), sessionCreatedAt, sessionExpiresAt, ids.organization, ids.membership, ids.sessionB, crypto.randomBytes(32)]);
  const credentialA = crypto.randomBytes(16);
  const credentialB = crypto.randomBytes(16);
  const credentialC = crypto.randomBytes(16);
  await poolA.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,transports,label,backup_eligible,backup_state)
    VALUES ($1,$2,$3,'{}','Primary',false,false),($4,$2,$5,'{}','Backup',false,false),($6,$2,$7,'{}','Recovery',false,false)`, [credentialA, ids.member, Buffer.alloc(32, 0x51), credentialB, Buffer.alloc(32, 0x52), credentialC, Buffer.alloc(32, 0x53)]);
  await poolA.query(`INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
    VALUES ($1,$2,1,'default',$3::jsonb,'active',$4)`, [ids.organization, ids.policy, JSON.stringify({ operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } }), ids.member]);

  const codec = createRefreshNonceCodec({ keys: { "refresh-nonce-v3": Buffer.alloc(32, 0x73) }, activeKeyId: "refresh-nonce-v3" });
  const repositoryA = createControlPlaneAuthorityRepository({ client: poolA, cursorSecret: Buffer.alloc(32, 0x41), refreshNonceCodec: codec });
  const repositoryB = createControlPlaneAuthorityRepository({ client: poolB, cursorSecret: Buffer.alloc(32, 0x42), refreshNonceCodec: codec });
  const auditAppender = createAuthorityReductionAuditAppender({ adminAuditRepository: createPostgresAdminAuditRepository({ client: poolA }) });
  const onAuthorityReduction = async ({ tx, organization_id, occurred_at, policy, resource, member_id, actor_member_id, capabilities }) => {
    const issuedAt = occurred_at ?? policy?.updated_at;
    const transactionAuthority = createControlPlaneAuthorityRepository({
      client: transactionBoundClient(tx),
      cursorSecret: Buffer.alloc(32, 0x43),
      refreshNonceCodec: codec
    });
    const reduction = await transactionAuthority.advanceAuthorityGenerationAndEnqueueRefresh({ organization_id, issued_at: issuedAt, expires_at: new Date(Date.parse(issuedAt) + 5 * 60_000).toISOString() });
    if (resource === "credential" || resource === "session") {
      await auditAppender.appendAuthorityReductionAudit({ tx, organization_id, actor: { member_id }, resource: { type: "member", id: member_id }, event_type: `${resource}.revoked`, mutation_key: `authority-reduction-${reduction.generation}`, occurred_at: issuedAt, reason: "human_management", source: "management_api", metadata: { generation: reduction.generation } });
    } else if (Array.isArray(capabilities) && capabilities.length > 0) {
      await auditAppender.appendAuthorityReductionAudit({ tx, organization_id, actor: { member_id: actor_member_id }, resource: { type: "member", id: member_id }, event_type: "capability.revoked", mutation_key: `authority-reduction-${reduction.generation}`, occurred_at: issuedAt, reason: "authority_revoked", source: "system", metadata: { revoked_count: capabilities.length, generation: reduction.generation } });
    }
    return reduction;
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

  // Model a Cloud process that commits a reduction and exits before it can
  // publish or answer a poll. A different process must reconstruct and serve
  // the committed hint from PostgreSQL alone.
  const committingProcessPool = new Pool({ connectionString: databaseUrl, max: 2 });
  const committingProcessRepository = createControlPlaneAuthorityRepository({ client: committingProcessPool, cursorSecret: Buffer.alloc(32, 0x44), refreshNonceCodec: codec });
  const failoverIssuedAt = new Date().toISOString();
  const processExitReduction = await committingProcessRepository.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: ids.organization,
    issued_at: failoverIssuedAt,
    expires_at: new Date(Date.parse(failoverIssuedAt) + 5 * 60_000).toISOString()
  });
  assert.equal(processExitReduction.generation, 5);
  await committingProcessPool.end();
  const failoverHint = await serviceAfterRestart.poll({ organization_id: ids.organization, device_id: ids.deviceA, after_generation: 4, wait_ms: 0 });
  assert.equal(failoverHint.authority_generation, 5);
  const failoverOutbox = await poolB.query("SELECT count(*)::int AS count FROM device_refresh_outbox WHERE organization_id=$1 AND desired_generation=5", [ids.organization]);
  assert.equal(failoverOutbox.rows[0].count, 2);

  const capabilityRepository = createCapabilityAuthorityRepository({ client: poolB, onAuthorityReduction });
  const revokedCapabilities = await capabilityRepository.revokeActiveCapabilitiesForMember({ organization_id: ids.organization, member_id: ids.member, actor_member_id: ids.member });
  assert.equal(revokedCapabilities.revoked_count, 1);
  const capabilityGeneration = await poolB.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(capabilityGeneration.rows[0].generation), 6);
  const replayedCapabilityRevocation = await capabilityRepository.revokeActiveCapabilitiesForMember({ organization_id: ids.organization, member_id: ids.member, actor_member_id: ids.member });
  assert.equal(replayedCapabilityRevocation.revoked_count, 0);
  const capabilityGenerationAfterReplay = await poolB.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(capabilityGenerationAfterReplay.rows[0].generation), 6);
  const capabilityAudit = await poolB.query("SELECT count(*)::int AS count FROM admin_audit_events WHERE organization_id=$1 AND action='capability.revoked'", [ids.organization]);
  assert.equal(capabilityAudit.rows[0].count, 1);

  const humanRepository = createPostgresHumanRepository({ client: poolA, onAuthorityReduction });
  const credentialRevokedAt = new Date().toISOString();
  const revokedCredential = await humanRepository.revokeCredential({ session_id: ids.sessionA, actor_session_id: ids.sessionA, member_id: ids.member, organization_id: ids.organization, credential_id: credentialA.toString("base64url"), expected_version: 1, revoked_at: credentialRevokedAt, reason: "integration_management", authority_reduction: true });
  assert.equal(revokedCredential.version, 2);
  const credentialGeneration = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(credentialGeneration.rows[0].generation), 7);
  const sessionRevokedAt = new Date().toISOString();
  const revokedSession = await humanRepository.revokeManagedSession({ actor_session_id: ids.sessionA, target_session_id: ids.sessionB, member_id: ids.member, organization_id: ids.organization, expected_version: 1, revoked_at: sessionRevokedAt, reason: "integration_management", authority_reduction: true });
  assert.equal(revokedSession.version, 2);
  const sessionGeneration = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(sessionGeneration.rows[0].generation), 8);
  const humanAudits = await poolA.query("SELECT action,count(*)::int AS count FROM admin_audit_events WHERE organization_id=$1 AND action IN ('credential.revoked','session.revoked') GROUP BY action ORDER BY action", [ids.organization]);
  assert.deepEqual(humanAudits.rows, [{ action: "credential.revoked", count: 1 }, { action: "session.revoked", count: 1 }]);

  const failingHumanRepository = createPostgresHumanRepository({
    client: poolA,
    onAuthorityReduction: async (input) => {
      await onAuthorityReduction(input);
      throw new Error("injected audit transaction failure");
    }
  });
  await assert.rejects(
    failingHumanRepository.revokeCredential({ session_id: ids.sessionA, actor_session_id: ids.sessionA, member_id: ids.member, organization_id: ids.organization, credential_id: credentialB.toString("base64url"), expected_version: 1, revoked_at: new Date().toISOString(), reason: "rollback_probe", authority_reduction: true }),
    /injected audit transaction failure/u
  );
  const rolledBackCredential = await poolA.query("SELECT revoked_at,version FROM webauthn_credentials WHERE id=$1", [credentialB]);
  assert.equal(rolledBackCredential.rows[0].revoked_at, null);
  assert.equal(Number(rolledBackCredential.rows[0].version), 1);
  const generationAfterAuditFailure = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(generationAfterAuditFailure.rows[0].generation), 8);
  const outboxAfterAuditFailure = await poolA.query("SELECT count(*)::int AS count FROM device_refresh_outbox WHERE organization_id=$1 AND desired_generation=9", [ids.organization]);
  assert.equal(outboxAfterAuditFailure.rows[0].count, 0);
  const auditsAfterFailure = await poolA.query("SELECT count(*)::int AS count FROM admin_audit_events WHERE organization_id=$1 AND action='credential.revoked'", [ids.organization]);
  assert.equal(auditsAfterFailure.rows[0].count, 1);
  await humanRepository.revokeSession({ session_id: ids.sessionA, revoked_at: new Date().toISOString(), reason: "logout" });
  const generationAfterLogout = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(generationAfterLogout.rows[0].generation), 8);

  const raceExpiry = new Date(Date.now() + 60 * 60_000).toISOString();
  const raceResults = await Promise.allSettled([
    capabilityRepository.issueCapabilityMetadata({ organization_id: ids.organization, capability_id: ids.raceCapability, agent_id: ids.agent, device_id: ids.deviceA, sequence: 2, statement_hash: "b".repeat(64), expires_at: raceExpiry, issued_by_member_id: ids.raceMember }),
    organizationRepository.removeMember({ organization_id: ids.organization, actor_member_id: ids.member, member_id: ids.raceMember, expected_version: 1, removed_at: new Date().toISOString(), idempotency_key: "g4-race-member-remove" })
  ]);
  assert.equal(raceResults[1].status, "fulfilled");
  if (raceResults[0].status === "rejected") assert.equal(raceResults[0].reason.code, "ERR_MEMBER_NOT_ACTIVE");
  const activeRaceCapabilities = await poolA.query("SELECT count(*)::int AS count FROM capabilities WHERE organization_id=$1 AND issued_by_member_id=$2 AND revoked_at IS NULL", [ids.organization, ids.raceMember]);
  assert.equal(activeRaceCapabilities.rows[0].count, 0);
  const generationAfterRace = await poolA.query("SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  assert.equal(Number(generationAfterRace.rows[0].generation), 9);
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
