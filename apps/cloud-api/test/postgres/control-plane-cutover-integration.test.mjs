import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresCapabilityReservationRepository } from "../../src/postgres/capability-reservation-repository.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createPostgresControlPlaneResourceRepository } from "../../src/postgres/control-plane-resource-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createSharedControlRepository } from "../../src/postgres/shared-control-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----";
const SCOPE = { operations: ["git.commit.sign"], repositories: ["/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } };

test("G3 authority survives instance switching, restart, replay races, and cross-tenant probes", { skip: !databaseUrl }, async (t) => {
  const poolA = new Pool({ connectionString: databaseUrl, max: 4 });
  const poolB = new Pool({ connectionString: databaseUrl, max: 4 });
  t.after(async () => { await Promise.allSettled([poolA.end(), poolB.end()]); });
  const migration = await poolA.connect();
  try { await createMigrationRunner({ client: migration, applicationVersion: "g3-cutover-integration" }).run(); }
  finally { migration.release(); }

  const ids = Object.fromEntries(["organization", "otherOrganization", "member", "membership", "otherMember", "otherMembership", "device", "agent", "policy"].map((name) => [name, randomUUID()]));
  await poolA.query("INSERT INTO organizations (id,name) VALUES ($1,'G3 integration'),($2,'G3 other tenant')", [ids.organization, ids.otherOrganization]);
  await poolA.query("INSERT INTO members (id,github_subject) VALUES ($1,$2),($3,$4)", [ids.member, `g3-${ids.member}`, ids.otherMember, `g3-${ids.otherMember}`]);
  await poolA.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active'),($4,$5,$6,'owner','active')", [ids.organization, ids.membership, ids.member, ids.otherOrganization, ids.otherMembership, ids.otherMember]);

  const now = new Date().toISOString();
  const resourcesA = createPostgresControlPlaneResourceRepository({ client: poolA, now: () => now });
  const resourcesB = createPostgresControlPlaneResourceRepository({ client: poolB, now: () => now });
  await resourcesA.createDevice({ organization_id: ids.organization, device_id: ids.device, name: "Build Mac", public_key: PUBLIC_KEY, key_algorithm: "ed25519", metadata: { platform: "macos" }, principal_id: ids.member, idempotency_key: "g3-create-device" });
  await resourcesB.createAgent({ organization_id: ids.organization, agent_id: ids.agent, device_id: ids.device, version: 1, name: "Claude", kind: "claude-code", public_key: PUBLIC_KEY, created_at: now, principal_id: ids.member, idempotency_key: "g3-create-agent" });
  await resourcesA.createPolicy({ organization_id: ids.organization, policy_id: ids.policy, name: "default", scope: SCOPE, sequence: 1, created_by: ids.member, principal_id: ids.member, idempotency_key: "g3-create-policy" });
  assert.equal((await resourcesB.listDevices({ organization_id: ids.organization }))[0].metadata.platform, "macos");
  assert.deepEqual(await resourcesB.listDevices({ organization_id: ids.otherOrganization }), []);

  const secret = Buffer.alloc(32, 0x61);
  const reservationsA = createPostgresCapabilityReservationRepository({ client: poolA, nonceSecret: secret, now: () => now });
  const reservationsB = createPostgresCapabilityReservationRepository({ client: poolB, nonceSecret: secret, now: () => now });
  const reservationInput = { organization_id: ids.organization, principal_id: ids.member, created_by: ids.member, agent_id: ids.agent, device_id: ids.device, issuer: "agentpass-cloud", key_id: "control-v2", scope: SCOPE, sequence: 1, ttl_ms: 60_000, issued_at: now, idempotency_key: "g3-capability-reserve" };
  const [reservationA, reservationB] = await Promise.all([reservationsA.reserveCapability(reservationInput), reservationsB.reserveCapability(reservationInput)]);
  assert.deepEqual(reservationB, reservationA);
  assert.equal((await reservationsB.listCapabilities({ organization_id: ids.organization })).length, 1);
  assert.deepEqual(await reservationsB.listCapabilities({ organization_id: ids.otherOrganization }), []);

  const controlsA = createSharedControlRepository({ client: poolA });
  const controlsB = createSharedControlRepository({ client: poolB });
  const nonce = "N".repeat(32);
  const nonceDecisions = await Promise.all([
    controlsA.consumeDeviceRequestNonce({ organizationId: ids.organization, deviceId: ids.device, nonce }),
    controlsB.consumeDeviceRequestNonce({ organizationId: ids.organization, deviceId: ids.device, nonce })
  ]);
  assert.deepEqual(nonceDecisions.map(({ accepted }) => accepted).sort(), [false, true]);
  const rateA = await controlsA.acquireRateLimit({ organizationId: ids.organization, principalType: "human", principalId: ids.member, capacity: 1, refillPerSecond: 1, cost: 1 });
  const rateB = await controlsB.acquireRateLimit({ organizationId: ids.organization, principalType: "human", principalId: ids.member, capacity: 1, refillPerSecond: 1, cost: 1 });
  assert.equal(rateA.allowed, true);
  assert.equal(rateB.allowed, false);

  const authorityA = createControlPlaneAuthorityRepository({ client: poolA, cursorSecret: Buffer.alloc(32, 0x62), now: () => now });
  const authorityB = createControlPlaneAuthorityRepository({ client: poolB, cursorSecret: Buffer.alloc(32, 0x62), now: () => now });
  const expiresAt = new Date(Date.parse(now) + 60_000).toISOString();
  const atomicSnapshot = await authorityA.snapshotAndAssignBundleHead({
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: now, expires_at: expiresAt,
    statement_hash_factory: () => "c".repeat(64)
  });
  assert.equal(atomicSnapshot.snapshot.organization_id, ids.organization);
  assert.equal(atomicSnapshot.snapshot.device_id, ids.device);
  assert.equal(atomicSnapshot.snapshot.active_policy.policy_id, ids.policy);
  assert.deepEqual(atomicSnapshot.snapshot.revocations, []);
  assert.equal(atomicSnapshot.head.sequence, 1);
  assert.equal(atomicSnapshot.head.state_fingerprint, "c".repeat(64));

  // Hold the same organization authority lock used by createRevocation(),
  // commit a revocation while the snapshot is waiting, and prove the
  // snapshot cannot return the pre-revocation authority state.
  const held = await poolA.connect();
  const raceRevocationId = randomUUID();
  try {
    await held.query("BEGIN");
    await held.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:control-plane-authority:organization:${ids.organization}`]);
    await held.query(`INSERT INTO revocations
      (organization_id,id,target_type,target_id,sequence,reason,status,created_by,revoked_by,created_at,revoked_at)
      VALUES ($1,$2,'agent',$3,2,'held-lock-race','active',$4,$4,$5::timestamptz,$5::timestamptz)`, [ids.organization, raceRevocationId, ids.agent, ids.member, now]);

    let settled = false;
    const waitingSnapshot = authorityB.snapshotAndAssignBundleHead({
      organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: now, expires_at: expiresAt,
      statement_hash_factory: () => "d".repeat(64)
    }).then((value) => { settled = true; return value; });
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.equal(settled, false);
    await held.query("COMMIT");
    const afterRevocation = await waitingSnapshot;
    assert.ok(afterRevocation.snapshot.revoked_agents.includes(ids.agent));
  } finally {
    await held.query("ROLLBACK").catch(() => {});
    held.release();
  }

  const firstHead = await authorityA.assignBundleHead({ organization_id: ids.organization, device_id: ids.device, state_fingerprint: "a".repeat(64), minimum_sequence: 1, issued_at: now, expires_at: expiresAt });
  const secondHead = await authorityB.assignBundleHead({ organization_id: ids.organization, device_id: ids.device, state_fingerprint: "b".repeat(64), minimum_sequence: 1, issued_at: now, expires_at: expiresAt });
  assert.equal(firstHead.sequence, atomicSnapshot.head.sequence + 2);
  assert.equal(secondHead.sequence, firstHead.sequence + 1);
  const revocationInput = { organization_id: ids.organization, target_type: "device", target_id: ids.device, reason: "integration-test", created_by: ids.member, principal_id: ids.member, created_at: now, idempotency_key: "g3-revoke-device" };
  const revocation = await authorityA.createRevocation(revocationInput);
  assert.equal((await authorityB.createRevocation(revocationInput)).revocation_id, revocation.revocation_id);
  assert.ok((await authorityB.listRevocations({ organization_id: ids.organization })).some(({ revocation_id }) => revocation_id === revocation.revocation_id));
  assert.deepEqual(await authorityB.listRevocations({ organization_id: ids.otherOrganization }), []);

  await poolA.end();
  const poolAfterRestart = new Pool({ connectionString: databaseUrl, max: 2 });
  try {
    const resourcesAfterRestart = createPostgresControlPlaneResourceRepository({ client: poolAfterRestart, now: () => now });
    assert.equal((await resourcesAfterRestart.listPolicies({ organization_id: ids.organization }))[0].policy_id, ids.policy);
    const reservationsAfterRestart = createPostgresCapabilityReservationRepository({ client: poolAfterRestart, nonceSecret: secret, now: () => now });
    assert.deepEqual(await reservationsAfterRestart.reserveCapability(reservationInput), reservationA);
  } finally { await poolAfterRestart.end(); }
});
