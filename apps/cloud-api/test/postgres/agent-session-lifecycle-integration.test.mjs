import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createPostgresAgentSessionConsumptionRepository } from "../../src/postgres/agent-session-consumption-repository.mjs";
import { createPostgresAgentSessionLifecycleRepository } from "../../src/postgres/agent-session-lifecycle-repository.mjs";
import { createAgentSessionAuthorityRepository } from "../../src/postgres/agent-session-authority-repository.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";
import { createAgentSessionHumanHttpFixture } from "./agent-session-human-http-fixture.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("M2-A3 lifecycle: expiry preserves rows and exact revocation serializes with consume", {
  skip: !DATABASE_URL,
  timeout: 30_000
}, async (t) => {
  const expiredFixture = await createAgentSessionHumanHttpFixture({
    connectionString: DATABASE_URL,
    applicationVersion: "m2-a3-lifecycle",
    options: { issuedAtMs: Date.now() - 700_000 }
  });
  t.after(() => expiredFixture.cleanup());
  const expiredIssue = expiredFixture.issueInput();
  const builtExpired = await expiredIssue.buildGrant({ control_sequence: 7, authority_generation: 1 });
  const expiredAuthority = createAgentSessionAuthorityRepository({ client: expiredFixture.pool });
  const expiredGrant = await expiredAuthority.issueAgentSessionGrant({
    organization_id: expiredFixture.ids.organization,
    grant: builtExpired.grant,
    grant_hash: builtExpired.grant_hash,
    issued_at: expiredIssue.issued_at,
    created_by: expiredFixture.actor.member_id
  });
  const lifecycle = createPostgresAgentSessionLifecycleRepository({ client: expiredFixture.pool });
  const expired = await lifecycle.expireDue({ organization_id: expiredFixture.ids.organization, limit: 10 });
  assert.deepEqual(expired, [1, 0]);
  const expiredStored = await expiredFixture.pool.query(`SELECT status,expired_at,grant_hash,statement_hash
    FROM agent_session_grants WHERE organization_id=$1 AND grant_id=$2`, [expiredFixture.ids.organization, expiredGrant.grant.statement.grant_id]);
  assert.equal(expiredStored.rows.length, 1);
  assert.equal(expiredStored.rows[0].status, "expired");
  assert.ok(expiredStored.rows[0].expired_at);
  assert.match(expiredStored.rows[0].grant_hash, /^[0-9a-f]{64}$/u);
  assert.equal(expiredStored.rows[0].statement_hash, expiredGrant.grant.statement_hash);

  const raceFixture = await createAgentSessionHumanHttpFixture({
    pool: expiredFixture.pool,
    applicationVersion: "m2-a3-lifecycle-race"
  });
  const issued = await raceFixture.repository.issueAgentSessionGrant(raceFixture.issueInput());
  const raceLifecycle = createPostgresAgentSessionLifecycleRepository({ client: raceFixture.pool });
  const consumption = createPostgresAgentSessionConsumptionRepository({ client: raceFixture.pool });
  const consumeInput = {
    organization_id: raceFixture.ids.organization,
    device_id: raceFixture.ids.device,
    grant_id: issued.grant.statement.grant_id,
    grant: issued.grant,
    process_binding_sha256: "c".repeat(64),
    ancestry_binding_sha256: "d".repeat(64)
  };
  const [consumed, revoked] = await Promise.allSettled([
    consumption.consumeAgentSessionGrant(consumeInput),
    raceLifecycle.revokeAuthority({
      organization_id: raceFixture.ids.organization,
      grant_id: issued.grant.statement.grant_id
    })
  ]);
  assert.equal(revoked.status, "fulfilled", revoked.status === "rejected" ? revoked.reason?.message : undefined);

  const state = await raceFixture.pool.query(`SELECT g.status AS grant_status,
      g.grant_hash,g.statement_hash,s.status AS session_status,s.process_binding_sha256,
      (SELECT count(*)::int FROM cloud_agent_audit_events e WHERE e.organization_id=g.organization_id AND e.grant_id=g.grant_id) AS audit_count,
      (SELECT count(*)::int FROM outbox_events o WHERE o.organization_id=g.organization_id AND o.action='agent_session_grant.consumed' AND o.payload->>'grant_id'=g.grant_id::text) AS outbox_count
    FROM agent_session_grants g
    LEFT JOIN agent_sessions s ON s.organization_id=g.organization_id AND s.grant_id=g.grant_id
    WHERE g.organization_id=$1 AND g.grant_id=$2`, [raceFixture.ids.organization, issued.grant.statement.grant_id]);
  assert.equal(state.rows.length, 1);
  const row = state.rows[0];
  if (consumed.status === "fulfilled") {
    assert.equal(row.grant_status, "consumed");
    assert.equal(row.session_status, "revoked");
    assert.equal(row.audit_count, 1);
    assert.equal(row.outbox_count, 1);
    await assert.rejects(consumption.consumeAgentSessionGrant(consumeInput));
  } else {
    assert.equal(row.grant_status, "revoked");
    assert.equal(row.session_status, null);
    assert.equal(row.audit_count, 0);
    assert.equal(row.outbox_count, 0);
  }
  assert.match(row.grant_hash, /^[0-9a-f]{64}$/u);
  assert.equal(row.statement_hash, issued.grant.statement_hash);

  const sessionExpiryFixture = await createAgentSessionHumanHttpFixture({
    pool: expiredFixture.pool,
    applicationVersion: "m2-a3-session-expiry",
    options: { issuedAtMs: Date.now() }
  });
  const shortInput = sessionExpiryFixture.issueInput({ intent: { ttl_seconds: 3 } });
  const shortBuilt = await shortInput.buildGrant({ control_sequence: 7, authority_generation: 1 });
  const shortAuthority = createAgentSessionAuthorityRepository({ client: sessionExpiryFixture.pool });
  const shortGrant = await shortAuthority.issueAgentSessionGrant({
    organization_id: sessionExpiryFixture.ids.organization,
    grant: shortBuilt.grant,
    grant_hash: shortBuilt.grant_hash,
    issued_at: shortInput.issued_at,
    created_by: sessionExpiryFixture.actor.member_id
  });
  const shortConsumption = createPostgresAgentSessionConsumptionRepository({ client: sessionExpiryFixture.pool });
  const shortConsumeInput = {
    organization_id: sessionExpiryFixture.ids.organization,
    device_id: sessionExpiryFixture.ids.device,
    grant_id: shortGrant.grant.statement.grant_id,
    grant: shortGrant.grant,
    process_binding_sha256: "5".repeat(64),
    ancestry_binding_sha256: "6".repeat(64)
  };
  const shortLease = await shortConsumption.consumeAgentSessionGrant(shortConsumeInput);
  await new Promise((resolve) => setTimeout(resolve, 3_100));
  const shortLifecycle = createPostgresAgentSessionLifecycleRepository({ client: sessionExpiryFixture.pool });
  assert.deepEqual(await shortLifecycle.expireDue({ organization_id: sessionExpiryFixture.ids.organization }), [0, 1]);
  const terminalSession = await sessionExpiryFixture.pool.query(`SELECT status,expired_at,grant_hash,process_binding_sha256
    FROM agent_sessions WHERE organization_id=$1 AND session_id=$2`, [sessionExpiryFixture.ids.organization, shortLease.lease.session_id]);
  assert.equal(terminalSession.rows[0].status, "expired");
  assert.ok(terminalSession.rows[0].expired_at);
  assert.equal(terminalSession.rows[0].grant_hash, shortBuilt.grant_hash);
  assert.equal(terminalSession.rows[0].process_binding_sha256, "5".repeat(64));
  await assert.rejects(shortConsumption.consumeAgentSessionGrant(shortConsumeInput));

  const hookFixture = await createAgentSessionHumanHttpFixture({
    pool: expiredFixture.pool,
    applicationVersion: "m2-a3-revocation-hook"
  });
  const hookIssued = await hookFixture.repository.issueAgentSessionGrant(hookFixture.issueInput());
  const hookConsumption = createPostgresAgentSessionConsumptionRepository({ client: hookFixture.pool });
  const hookInput = {
    organization_id: hookFixture.ids.organization,
    device_id: hookFixture.ids.device,
    grant_id: hookIssued.grant.statement.grant_id,
    grant: hookIssued.grant,
    process_binding_sha256: "7".repeat(64),
    ancestry_binding_sha256: "8".repeat(64)
  };
  const hookLease = await hookConsumption.consumeAgentSessionGrant(hookInput);
  const hookLifecycle = createPostgresAgentSessionLifecycleRepository({ client: hookFixture.pool });
  const nonceCodec = createRefreshNonceCodec({
    keys: { "refresh-nonce-v7": Buffer.alloc(32, 0x44) },
    activeKeyId: "refresh-nonce-v7"
  });
  const controlAuthority = createControlPlaneAuthorityRepository({
    client: hookFixture.pool,
    cursorSecret: Buffer.alloc(32, 0x45),
    refreshNonceCodec: nonceCodec,
    onRevocation: ({ tx, revocation }) => hookLifecycle.revokeAuthorityInTransaction({
      tx,
      organization_id: revocation.organization_id,
      agent_id: revocation.target_id,
      revoked_at: revocation.revoked_at
    })
  });
  const revocationAt = new Date().toISOString();
  await controlAuthority.reduceAuthorityAndEnqueueRefresh({
    organization_id: hookFixture.ids.organization,
    target_type: "agent",
    target_id: hookFixture.ids.agent,
    reason: "qualification",
    created_by: hookFixture.actor.member_id,
    revocation_id: crypto.randomUUID(),
    created_at: revocationAt,
    issued_at: revocationAt,
    expires_at: new Date(Date.parse(revocationAt) + 300_000).toISOString()
  });
  const hooked = await hookFixture.pool.query(`SELECT s.status,s.revoked_at,r.status AS revocation_status
    FROM agent_sessions s JOIN revocations r
      ON r.organization_id=s.organization_id AND r.target_type='agent' AND r.target_id=s.agent_id
    WHERE s.organization_id=$1 AND s.session_id=$2`, [hookFixture.ids.organization, hookLease.lease.session_id]);
  assert.equal(hooked.rows[0].status, "revoked");
  assert.ok(hooked.rows[0].revoked_at);
  assert.equal(hooked.rows[0].revocation_status, "active");
  await assert.rejects(hookConsumption.consumeAgentSessionGrant(hookInput));
});
