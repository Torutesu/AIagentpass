import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import {
  AGENT_SESSION_GRANT_ISSUER,
  AGENT_SESSION_GRANT_TYPE,
  agentSessionGrantSigningData,
  agentSessionGrantStatementHash,
  normalizeAgentSessionGrantStatement
} from "../../src/agent-session-grant.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresAdminAuditRepository } from "../../src/postgres/admin-audit-repository.mjs";
import { canonicalJson, normalizeScope } from "../../../../packages/protocol/src/index.mjs";

// This file intentionally targets the forthcoming orchestration repository.
// Keep the import lazy so the normal PostgreSQL-optional test run can skip
// cleanly until AGENTPASS_TEST_DATABASE_URL is configured and the repository
// implementation lands.
const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const CONTROL_SEQUENCE = 7;
const GRANT_KEY_ID = "agent-session-integration-v1";
const SCOPE = Object.freeze({
  operations: ["git.commit.sign"],
  repositories: ["/integration/repository"],
  branches: { allow: ["main"], deny: [] },
  remotes: { allow: ["origin"], deny: [] }
});

test("PostgreSQL issuance replays the exact committed result without signing twice", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const { pool, repositoryFactory } = await openDatabase(t);
  const fixture = await seedFixture(pool);
  const repository = repositoryFactory({ client: pool, now: () => new Date().toISOString(), resolveProcessBindingPolicy: () => true });
  const calls = { buildGrant: 0 };

  const first = await repository.issueAgentSessionGrant(issueInput(fixture, {
    onBuildGrant: () => { calls.buildGrant += 1; }
  }));
  const retry = await repository.issueAgentSessionGrant(issueInput(fixture, {
    // A real retry has new transport request/grant IDs. The idempotency key
    // and canonical request fingerprint are the durable identity.
    request_id: crypto.randomUUID(),
    grant_id: crypto.randomUUID(),
    onBuildGrant: () => { calls.buildGrant += 1; }
  }));

  assert.deepEqual(retry.grant, first.grant);
  assert.equal(retry.request_id, first.request_id);
  assert.equal(calls.buildGrant, 1, "a committed retry must not invoke the signer");
  assert.equal((await countRows(pool, fixture.organizationId, "agent_session_grants", fixture.organizationId))[0].count, 1);
  assert.equal((await countIdempotency(pool, fixture))[0].count, 1);
  assert.equal(await countOrganizationTable(pool, fixture.organizationId, "admin_audit_events"), 1);
  assert.equal(await countOrganizationTable(pool, fixture.organizationId, "outbox_events"), 1);
});

test("PostgreSQL simultaneous issuance converges on one Grant, audit event, and outbox event", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const { pool, repositoryFactory } = await openDatabase(t);
  const fixture = await seedFixture(pool);
  const repository = repositoryFactory({ client: pool, resolveProcessBindingPolicy: () => true });
  let buildCalls = 0;
  const [first, second] = await Promise.all([
    repository.issueAgentSessionGrant(issueInput(fixture, { onBuildGrant: () => { buildCalls += 1; } })),
    repository.issueAgentSessionGrant(issueInput(fixture, { onBuildGrant: () => { buildCalls += 1; } }))
  ]);
  assert.deepEqual(second.grant, first.grant);
  assert.equal(second.request_id, first.request_id);
  assert.equal(buildCalls, 1);
  assert.equal(await countOrganizationTable(pool, fixture.organizationId, "agent_session_grants"), 1);
  assert.equal(await countOrganizationTable(pool, fixture.organizationId, "admin_audit_events"), 1);
  assert.equal(await countOrganizationTable(pool, fixture.organizationId, "outbox_events"), 1);
});

test("PostgreSQL issuance rejects a changed request under the same idempotency key", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const { pool, repositoryFactory } = await openDatabase(t);
  const fixture = await seedFixture(pool);
  const repository = repositoryFactory({ client: pool, now: () => new Date().toISOString(), resolveProcessBindingPolicy: () => true });
  const first = issueInput(fixture);
  await repository.issueAgentSessionGrant(first);

  const changed = issueInput(fixture, {
    intent: { ...first.intent, max_signatures: first.intent.max_signatures + 1 },
    request_id: crypto.randomUUID(),
    grant_id: crypto.randomUUID()
  });
  await assert.rejects(
    repository.issueAgentSessionGrant(changed),
    (error) => /conflict|idempot/iu.test(String(error?.code ?? error?.name ?? error?.message))
  );

  assert.equal((await countRows(pool, fixture.organizationId, "agent_session_grants", fixture.organizationId))[0].count, 1);
  assert.equal((await countIdempotency(pool, fixture))[0].count, 1);
});

test("PostgreSQL issuance fails closed for inactive membership, device, and agent", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const cases = [
    { name: "member", actorMembershipStatus: "revoked", deviceStatus: "active", agentStatus: "active" },
    { name: "device", actorMembershipStatus: "active", deviceStatus: "disabled", agentStatus: "active" },
    { name: "agent", actorMembershipStatus: "active", deviceStatus: "active", agentStatus: "revoked" }
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (nested) => {
      const { pool, repositoryFactory } = await openDatabase(nested);
      const fixture = await seedFixture(pool, scenario);
      const repository = repositoryFactory({ client: pool, now: () => new Date().toISOString(), resolveProcessBindingPolicy: () => true });
      let signerCalled = false;

      await assert.rejects(repository.issueAgentSessionGrant(issueInput(fixture, {
        onBuildGrant: () => { signerCalled = true; }
      })));
      assert.equal(signerCalled, false, `${scenario.name} must be rejected before signing`);
      assert.equal((await countRows(pool, fixture.organizationId, "agent_session_grants", fixture.organizationId))[0].count, 0);
      assert.equal((await countIdempotency(pool, fixture))[0].count, 0, "rejected authority must not leave an idempotency reservation");
    });
  }
});

test("PostgreSQL issuance rolls back the idempotency reservation when signing fails", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const { pool, repositoryFactory } = await openDatabase(t);
  const fixture = await seedFixture(pool);
  const repository = repositoryFactory({ client: pool, now: () => new Date().toISOString(), resolveProcessBindingPolicy: () => true });
  const input = issueInput(fixture, {
    buildGrant: async () => {
      throw new Error("signer failure: private key provider unavailable");
    }
  });

  await assert.rejects(repository.issueAgentSessionGrant(input));
  assert.equal((await countRows(pool, fixture.organizationId, "agent_session_grants", fixture.organizationId))[0].count, 0);
  assert.equal((await countIdempotency(pool, fixture))[0].count, 0, "signer failure must rollback the reservation");
});

test("PostgreSQL issuance rejects scope escalation and stale authority before signing", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const { pool, repositoryFactory } = await openDatabase(t);
  for (const scenario of ["scope", "generation"]) {
    const fixture = await seedFixture(pool);
    if (scenario === "generation") await pool.query("SELECT * FROM agentpass_advance_authority_generation($1)", [fixture.organizationId]);
    const repository = repositoryFactory({ client: pool, resolveProcessBindingPolicy: () => true });
    let signerCalled = false;
    const input = issueInput(fixture, scenario === "scope" ? {
      intent: { scope: { ...SCOPE, repositories: ["/integration/repository", "/outside/policy"] } },
      onBuildGrant: () => { signerCalled = true; }
    } : { onBuildGrant: () => { signerCalled = true; } });
    await assert.rejects(repository.issueAgentSessionGrant(input));
    assert.equal(signerCalled, false, scenario);
    assert.equal(await countOrganizationTable(pool, fixture.organizationId, "agent_session_grants"), 0);
  }
});

test("PostgreSQL audit and outbox failures rollback Grant and idempotency atomically", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const { pool, repositoryFactory } = await openDatabase(t);

  const auditFixture = await seedFixture(pool);
  const auditFailure = repositoryFactory({
    client: pool,
    resolveProcessBindingPolicy: () => true,
    auditRepository: { async appendAdminAuditEventInTransaction() { throw new Error("audit unavailable"); } }
  });
  await assert.rejects(auditFailure.issueAgentSessionGrant(issueInput(auditFixture)));
  assert.equal(await countOrganizationTable(pool, auditFixture.organizationId, "agent_session_grants"), 0);
  assert.equal((await countIdempotency(pool, auditFixture))[0].count, 0);

  const outboxFixture = await seedFixture(pool);
  const failingClient = queryFailingPool(pool, /INSERT INTO outbox_events/u);
  const outboxFailure = repositoryFactory({
    client: failingClient,
    resolveProcessBindingPolicy: () => true,
    auditRepository: createPostgresAdminAuditRepository({ client: failingClient })
  });
  await assert.rejects(outboxFailure.issueAgentSessionGrant(issueInput(outboxFixture)));
  assert.equal(await countOrganizationTable(pool, outboxFixture.organizationId, "agent_session_grants"), 0);
  assert.equal(await countOrganizationTable(pool, outboxFixture.organizationId, "admin_audit_events"), 0);
  assert.equal((await countIdempotency(pool, outboxFixture))[0].count, 0);
});

async function openDatabase(t) {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  t.after(() => pool.end());
  const client = await pool.connect();
  try {
    const migration = await createMigrationRunner({
      client,
      applicationVersion: "agent-session-issuance-integration"
    }).run();
    assert.equal(migration.currentVersion, 36);
  } finally {
    client.release();
  }

  const module = await import("../../src/postgres/agent-session-issuance-repository.mjs");
  assert.equal(typeof module.createPostgresAgentSessionIssuanceRepository, "function");
  return { pool, repositoryFactory: module.createPostgresAgentSessionIssuanceRepository };
}

async function seedFixture(pool, options = {}) {
  const organizationId = crypto.randomUUID();
  const operatorMemberId = crypto.randomUUID();
  const actorMemberId = crypto.randomUUID();
  const operatorMembershipId = crypto.randomUUID();
  const actorMembershipId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const agentId = crypto.randomUUID();
  const policyId = crypto.randomUUID();
  const adapterId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const recentAuthId = crypto.randomUUID();
  const issuedAtMs = Date.now() - 30_000;
  const issuedAt = new Date(issuedAtMs).toISOString();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const actorMembershipStatus = options.actorMembershipStatus ?? "active";
  const deviceStatus = options.deviceStatus ?? "active";
  const agentStatus = options.agentStatus ?? "active";

  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, `issuance-${organizationId}`]);
  await pool.query(
    `INSERT INTO members (id,github_subject,display_name) VALUES
      ($1,$2,'issuance operator'),($3,$4,'issuance actor')`,
    [operatorMemberId, `issuance-operator-${organizationId}`, actorMemberId, `issuance-actor-${organizationId}`]
  );
  await pool.query(
    `INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
      ($1,$2,$3,'owner','active'),($1,$4,$5,'admin','active')`,
    [organizationId, operatorMembershipId, operatorMemberId, actorMembershipId, actorMemberId]
  );
  await pool.query(
    `INSERT INTO human_sessions
      (id,member_id,token_hash,created_at,expires_at,organization_id,membership_id,role,csrf_token_hash)
      VALUES ($1,$2,$3,$4,$5,$6,$7,'admin',$8)`,
    [sessionId, actorMemberId, crypto.randomBytes(32), new Date(issuedAtMs - 60_000).toISOString(), new Date(issuedAtMs + 3_600_000).toISOString(), organizationId, actorMembershipId, crypto.randomBytes(32)]
  );
  await pool.query(
    `INSERT INTO webauthn_challenges
      (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,rp_id,origin,user_verification,status,consumed_at)
      VALUES ($1,$2,$3,$4,'authentication','agent.session_grant.issue',$5,$6,$7,'console.agentpass.test','https://console.agentpass.test','required','consumed',$8)`,
    [recentAuthId, sessionId, actorMemberId, organizationId, crypto.randomBytes(32), new Date(issuedAtMs - 60_000).toISOString(), new Date(issuedAtMs + 300_000).toISOString(), issuedAt]
  );
  await pool.query(
    `UPDATE human_sessions
      SET recent_auth_at=$2::timestamptz,recent_auth_challenge_id=$3,
          recent_auth_organization_id=$4,recent_auth_operation=$5,
          recent_auth_consumed_at=$2::timestamptz
      WHERE id=$1`,
    [sessionId, issuedAt, recentAuthId, organizationId, "agent.session_grant.issue"]
  );
  if (actorMembershipStatus !== "active") {
    await pool.query(
      "UPDATE memberships SET status=$3 WHERE organization_id=$1 AND id=$2",
      [organizationId, actorMembershipId, actorMembershipStatus]
    );
  }
  await pool.query(
    `INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status)
      VALUES ($1,$2,'issuance device','ed25519',$3,$4)`,
    [organizationId, deviceId, publicKeyPem, deviceStatus]
  );
  await pool.query(
    `INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
      VALUES ($1,$2,$3,'claude-code','issuance agent',$4,$5)`,
    [organizationId, agentId, deviceId, publicKeyPem, agentStatus]
  );
  await pool.query(
    `INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
      VALUES ($1,$2,1,'issuance policy',$3::jsonb,'active',$4)`,
    [organizationId, policyId, JSON.stringify(SCOPE), operatorMemberId]
  );

  if (deviceStatus === "active") {
    await pool.query(
      `INSERT INTO bundle_heads (organization_id,device_id,format_epoch,sequence,statement_hash,issued_at,expires_at)
        VALUES ($1,$2,2,$3,$4,clock_timestamp(),clock_timestamp()+interval '1 hour')`,
      [organizationId, deviceId, CONTROL_SEQUENCE, "b".repeat(64)]
    );
    await pool.query(
      `UPDATE device_control_plane_state
        SET observed_generation=1,refresh_state='applied',last_observed_at=clock_timestamp()
        WHERE organization_id=$1 AND device_id=$2`,
      [organizationId, deviceId]
    );
    await pool.query(
      `INSERT INTO bundle_acknowledgements
        (organization_id,device_id,format_epoch,sequence,statement_hash,status,applied_at)
        VALUES ($1,$2,2,$3,$4,'applied',clock_timestamp())`,
      [organizationId, deviceId, CONTROL_SEQUENCE, "b".repeat(64)]
    );
  }

  return Object.freeze({
    organizationId,
    operatorMemberId,
    actorMemberId,
    actorMembershipStatus,
    adapterId,
    sessionId,
    recentAuthId,
    issuedAtMs,
    issuedAt,
    deviceId,
    agentId,
    policyId,
    publicKey,
    privateKey,
    controlSequence: CONTROL_SEQUENCE
  });
}

function issueInput(fixture, overrides = {}) {
  const { intent: intentOverrides = {}, buildGrant: customBuilder, onBuildGrant, ...inputOverrides } = overrides;
  const issuedAtMs = fixture.issuedAtMs;
  const issuedAt = fixture.issuedAt;
  const intent = {
    device_id: fixture.deviceId,
    agent_kind: "claude-code",
    adapter_id: fixture.adapterId,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: fixture.policyId,
    scope: normalizeScope(SCOPE),
    max_signatures: 2,
    ttl_seconds: 600,
    ...intentOverrides
  };
  const requestFingerprint = crypto.createHash("sha256").update(canonicalJson({
    organization_id: fixture.organizationId,
    agent_id: fixture.agentId,
    ...intent
  })).digest("hex");
  const grantId = overrides.grant_id ?? crypto.randomUUID();
  const input = {
    actor: {
      session_id: fixture.sessionId,
      member_id: fixture.actorMemberId,
      organization_id: fixture.organizationId,
      role: "admin"
    },
    organization_id: fixture.organizationId,
    agent_id: fixture.agentId,
    device_id: fixture.deviceId,
    intent,
    idempotency_key: "issuance-integration-key",
    request_fingerprint: requestFingerprint,
    request_id: overrides.request_id ?? crypto.randomUUID(),
    grant_id: grantId,
    issued_at: issuedAt,
    not_before: issuedAt,
    expires_at: new Date(issuedAtMs + 600_000).toISOString(),
    recent_auth: {
      authorization_id: fixture.recentAuthId,
      authenticated_at: issuedAtMs
    },
    buildGrant: customBuilder
      ?? (({ control_sequence = fixture.controlSequence, authority_generation = 1, grant_id = input.grant_id } = {}) => buildSignedGrant(fixture, input, { controlSequence: control_sequence, authorityGeneration: authority_generation, grantId: grant_id }, onBuildGrant))
  };
  return { ...input, ...inputOverrides, intent, request_fingerprint: requestFingerprint };
}

async function buildSignedGrant(fixture, input, { controlSequence, authorityGeneration, grantId }, onCall = undefined) {
  onCall?.();
  const statement = normalizeAgentSessionGrantStatement({
    version: 1,
    grant_id: grantId,
    organization_id: fixture.organizationId,
    device_id: fixture.deviceId,
    agent_id: fixture.agentId,
    agent_kind: input.intent.agent_kind,
    adapter_id: input.intent.adapter_id,
    adapter_version: input.intent.adapter_version,
    worktree_binding_sha256: input.intent.worktree_binding_sha256,
    process_binding_policy_id: input.intent.process_binding_policy_id,
    scope: input.intent.scope,
    max_signatures: input.intent.max_signatures,
    not_before: input.not_before,
    expires_at: input.expires_at,
    control_sequence: controlSequence,
    authority_generation: authorityGeneration,
    issuer: AGENT_SESSION_GRANT_ISSUER,
    key_id: GRANT_KEY_ID
  });
  const statementHash = agentSessionGrantStatementHash(statement);
  const signature = crypto.sign(null, agentSessionGrantSigningData(statement), fixture.privateKey).toString("base64url");
  const grant = { version: 1, type: AGENT_SESSION_GRANT_TYPE, statement, statement_hash: statementHash, signature };
  return { grant, grant_hash: crypto.createHash("sha256").update(canonicalJson(grant)).digest("hex"), statement_hash: statementHash, control_sequence: controlSequence, authority_generation: authorityGeneration };
}

async function countIdempotency(pool, fixture) {
  return pool.query(
    `SELECT count(*)::int AS count FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3`,
    [fixture.organizationId, `agent-session-grant:${fixture.actorMemberId}`, "issuance-integration-key"]
  ).then((result) => result.rows);
}

async function countRows(pool, organizationId, table, whereOrganizationId) {
  assert(new Set(["agent_session_grants", "admin_audit_events", "outbox_events"]).has(table));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('agentpass.organization_id',$1,true)", [organizationId]);
    const result = await client.query(`SELECT count(*)::int AS count FROM ${table} WHERE organization_id=$1`, [whereOrganizationId]);
    await client.query("COMMIT");
    return result.rows;
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch {}
    throw error;
  } finally {
    client.release();
  }
}

async function countOrganizationTable(pool, organizationId, table) {
  const allowed = new Set(["agent_session_grants", "admin_audit_events", "outbox_events"]);
  if (!allowed.has(table)) throw new Error("unsupported integration table");
  const rows = await countRows(pool, organizationId, table, organizationId);
  return rows[0].count;
}

function queryFailingPool(pool, pattern) {
  return {
    query: (...args) => pool.query(...args),
    async connect() {
      const client = await pool.connect();
      return {
        async query(text, params) {
          if (pattern.test(String(text))) throw new Error("injected publication failure");
          return client.query(text, params);
        },
        release: () => client.release()
      };
    }
  };
}
