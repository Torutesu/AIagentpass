import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const postgresSkipReason = databaseUrl
  ? false
  : "set AGENTPASS_TEST_DATABASE_URL to run the live PostgreSQL Native Device audit upload integration test";
const ZERO_HASH = "0".repeat(64);
const NOW = "2026-08-20T00:00:00.000Z";

test("live PostgreSQL Native Device audit upload reconciles response loss as an exact duplicate and preserves head continuity", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createLiveFixture(t);
  const first = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  const second = auditEvent(fixture.agentA, { deviceTimestamp: "2026-08-20T00:00:01.000Z", previousHash: first.event_hash });

  // Commit the upload and intentionally discard the returned response. The
  // retry has no batch-id shortcut: the database event identity must reconcile it.
  await fixture.authority.ingestDeviceAuditEvents({
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    events: [first, second],
    received_at: NOW
  });
  const retry = await fixture.authority.ingestDeviceAuditEvents({
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    events: [first, second],
    received_at: "2026-08-20T00:00:03.000Z"
  });

  assert.deepEqual(retry.accepted, []);
  assert.deepEqual(retry.duplicates, [first.event_id, second.event_id]);
  assert.deepEqual(retry.gaps, []);
  assert.deepEqual(await head(fixture.pool, fixture.organization, fixture.deviceA), {
    sequence: 2,
    last_event_id: second.event_id,
    last_event_hash: second.event_hash,
    chain_status: "continuous",
    gap_count: 0
  });
  assert.equal((await countEvents(fixture.pool, fixture.organization, fixture.deviceA)), 2);
});

test("live PostgreSQL Native Device audit upload records a gap and keeps the head quarantined after continuation", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createLiveFixture(t);
  const first = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  const missingPredecessor = auditEvent(fixture.agentA, {
    deviceTimestamp: "2026-08-20T00:00:01.000Z",
    previousHash: "f".repeat(64)
  });
  const continuation = auditEvent(fixture.agentA, {
    deviceTimestamp: "2026-08-20T00:00:02.000Z",
    previousHash: missingPredecessor.event_hash
  });

  await fixture.authority.ingestDeviceAuditEvents({
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    events: [first],
    received_at: NOW
  });
  const result = await fixture.authority.ingestDeviceAuditEvents({
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    events: [missingPredecessor, continuation],
    received_at: "2026-08-20T00:00:03.000Z"
  });

  assert.deepEqual(result.accepted, [missingPredecessor.event_id, continuation.event_id]);
  assert.equal(result.gaps.length, 1);
  assert.deepEqual(result.gaps[0], {
    gap_id: missingPredecessor.event_id,
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    event_id: missingPredecessor.event_id,
    expected_previous_hash: first.event_hash,
    received_previous_hash: missingPredecessor.previous_hash,
    recorded_at: "2026-08-20T00:00:03.000Z"
  });
  assert.deepEqual(await head(fixture.pool, fixture.organization, fixture.deviceA), {
    sequence: 3,
    last_event_id: continuation.event_id,
    last_event_hash: continuation.event_hash,
    chain_status: "gap",
    gap_count: 1
  });
  assert.equal((await fixture.pool.query(
    "SELECT count(*)::int AS count FROM device_audit_gaps WHERE organization_id=$1 AND device_id=$2 AND resolved_at IS NULL",
    [fixture.organization, fixture.deviceA]
  )).rows[0].count, 1);
});

test("live PostgreSQL Native Device audit upload rejects hash equivocation without moving the committed head", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createLiveFixture(t);
  const original = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  await fixture.authority.ingestDeviceAuditEvents({
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    events: [original],
    received_at: NOW
  });

  const equivocation = withHash({ ...original, decision: "deny", reason: "branch_denied" });
  await assert.rejects(
    () => fixture.authority.ingestDeviceAuditEvents({
      organization_id: fixture.organization,
      device_id: fixture.deviceA,
      events: [equivocation],
      received_at: "2026-08-20T00:00:01.000Z"
    }),
    { code: "ERR_AUDIT_DEDUP_CONFLICT" }
  );

  assert.deepEqual(await head(fixture.pool, fixture.organization, fixture.deviceA), {
    sequence: 1,
    last_event_id: original.event_id,
    last_event_hash: original.event_hash,
    chain_status: "continuous",
    gap_count: 0
  });
  assert.equal((await countEvents(fixture.pool, fixture.organization, fixture.deviceA)), 1);
});

test("live PostgreSQL Native Device audit upload rejects an agent used by the wrong authenticated device", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createLiveFixture(t);
  const event = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });

  await assert.rejects(
    () => fixture.authority.ingestDeviceAuditEvents({
      organization_id: fixture.organization,
      device_id: fixture.deviceB,
      events: [event],
      received_at: NOW
    }),
    { code: "ERR_AUDIT_DEVICE_MISMATCH" }
  );
  assert.equal((await countEvents(fixture.pool, fixture.organization, fixture.deviceB)), 0);
  assert.deepEqual(await head(fixture.pool, fixture.organization, fixture.deviceB), {
    sequence: 0,
    last_event_id: null,
    last_event_hash: ZERO_HASH,
    chain_status: "continuous",
    gap_count: 0
  });
});

test("live PostgreSQL Native Device audit upload enforces forced tenant RLS for events, heads, and gaps", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createLiveFixture(t);
  const other = await createOtherTenant(fixture.pool);
  const otherEvent = auditEvent(other.agent, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  await insertAuditEvent(fixture.pool, other.organization, other.device, otherEvent);

  for (const table of ["device_audit_events", "device_audit_heads", "device_audit_gaps"]) {
    const relation = await fixture.pool.query(`
      SELECT c.relrowsecurity, c.relforcerowsecurity,
             (SELECT count(*)::int FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname) AS policy_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname=$1`, [table]);
    assert.equal(relation.rowCount, 1, `${table} must exist in the live schema`);
    assert.equal(relation.rows[0].relrowsecurity, true, `${table} must enable RLS`);
    assert.equal(relation.rows[0].relforcerowsecurity, true, `${table} must force RLS for the table owner`);
    assert.equal(relation.rows[0].policy_count, 4, `${table} must expose explicit CRUD tenant policies`);

    const policies = await fixture.pool.query(`
      SELECT policyname,cmd,qual,with_check
      FROM pg_policies
      WHERE schemaname='public' AND tablename=$1
      ORDER BY policyname`, [table]);
    assert.deepEqual(policies.rows.map((row) => row.cmd).sort(), ["DELETE", "INSERT", "SELECT", "UPDATE"]);
    for (const policy of policies.rows) {
      assert.match(`${policy.qual ?? ""} ${policy.with_check ?? ""}`, /organization_id\s*=\s*agentpass_current_organization_id\(\)/u,
        `${table}.${policy.policyname} must bind access to the transaction tenant`);
    }
  }

  await withSessionAuthorization(fixture.pool, "agentpass_app", async (client) => {
    await client.query("BEGIN");
    try {
      await client.query("SELECT set_config('agentpass.organization_id',$1,true)", [fixture.organization]);
      const visible = {};
      for (const table of ["device_audit_events", "device_audit_heads", "device_audit_gaps"]) {
        const result = await client.query(`SELECT count(*)::int AS count FROM public.${table}`);
        visible[table] = result.rows[0].count;
      }
      assert.deepEqual(visible, {
        device_audit_events: 0,
        device_audit_heads: 2,
        device_audit_gaps: 0
      }, "agentpass_app must not see another tenant's device audit rows");

      const crossTenantEvent = auditEvent(other.agent, { deviceTimestamp: "2026-08-20T00:00:04.000Z", previousHash: otherEvent.event_hash });
      await client.query("SAVEPOINT native_audit_cross_tenant_insert");
      try {
        await assert.rejects(
          () => client.query(`INSERT INTO public.device_audit_events
            (organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at)
            VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::timestamptz)`, [
            other.organization, other.device, crossTenantEvent.event_id, crossTenantEvent.previous_hash,
            crossTenantEvent.event_hash, crossTenantEvent, "2026-08-20T00:00:04.000Z"
          ]),
          (error) => error?.code === "42501"
        );
      } finally {
        await client.query("ROLLBACK TO SAVEPOINT native_audit_cross_tenant_insert");
      }
    } finally {
      await client.query("ROLLBACK");
    }
  });
});

test("live PostgreSQL Native Device audit upload makes concurrent identical retries one accepted event and one duplicate", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createLiveFixture(t);
  const authorityA = createControlPlaneAuthorityRepository({ client: fixture.pool, cursorSecret: Buffer.alloc(32, 0x67), now: () => NOW });
  const authorityB = createControlPlaneAuthorityRepository({ client: fixture.pool, cursorSecret: Buffer.alloc(32, 0x67), now: () => NOW });
  const event = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  const input = { organization_id: fixture.organization, device_id: fixture.deviceA, events: [event], received_at: NOW };

  const results = await Promise.all([
    authorityA.ingestDeviceAuditEvents(input),
    authorityB.ingestDeviceAuditEvents(input)
  ]);

  assert.equal(results.filter((result) => result.accepted.length === 1).length, 1);
  assert.equal(results.filter((result) => result.duplicates.length === 1).length, 1);
  assert.deepEqual(results.flatMap((result) => result.gaps), []);
  assert.deepEqual(await head(fixture.pool, fixture.organization, fixture.deviceA), {
    sequence: 1,
    last_event_id: event.event_id,
    last_event_hash: event.event_hash,
    chain_status: "continuous",
    gap_count: 0
  });
  assert.equal(await countEvents(fixture.pool, fixture.organization, fixture.deviceA), 1);
});

test("live PostgreSQL Native Device audit upload serializes concurrent appends and preserves the committed head and gap evidence", { skip: postgresSkipReason }, async (t) => {
  const fixture = await createLiveFixture(t);
  const authorities = [
    createControlPlaneAuthorityRepository({ client: fixture.pool, cursorSecret: Buffer.alloc(32, 0x67), now: () => NOW }),
    createControlPlaneAuthorityRepository({ client: fixture.pool, cursorSecret: Buffer.alloc(32, 0x67), now: () => NOW })
  ];
  const events = [
    auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH }),
    auditEvent(fixture.agentA, { deviceTimestamp: "2026-08-20T00:00:01.000Z", previousHash: ZERO_HASH })
  ];

  const results = await Promise.all(events.map((event, index) => authorities[index].ingestDeviceAuditEvents({
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    events: [event],
    received_at: event.device_timestamp
  })));
  assert.deepEqual(results.flatMap((result) => result.duplicates), []);
  assert.equal(results.flatMap((result) => result.accepted).length, 2);
  const gap = results.flatMap((result) => result.gaps);
  assert.equal(gap.length, 1);

  const acceptedIds = results.flatMap((result) => result.accepted);
  const firstEvent = events.find((event) => event.event_id === acceptedIds[0]);
  const secondEvent = events.find((event) => event.event_id === acceptedIds[1]);
  assert.ok(firstEvent && secondEvent);
  assert.deepEqual(gap[0], {
    gap_id: secondEvent.event_id,
    organization_id: fixture.organization,
    device_id: fixture.deviceA,
    event_id: secondEvent.event_id,
    expected_previous_hash: firstEvent.event_hash,
    received_previous_hash: ZERO_HASH,
    recorded_at: secondEvent.device_timestamp
  });
  assert.deepEqual(await head(fixture.pool, fixture.organization, fixture.deviceA), {
    sequence: 2,
    last_event_id: secondEvent.event_id,
    last_event_hash: secondEvent.event_hash,
    chain_status: "gap",
    gap_count: 1
  });
  assert.equal(await countEvents(fixture.pool, fixture.organization, fixture.deviceA), 2);
});

async function createLiveFixture(t) {
  const pool = new Pool({ connectionString: databaseUrl, max: 4, connectionTimeoutMillis: 2_000, statement_timeout: 10_000, query_timeout: 12_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "native-device-audit-upload-integration" }).run();
    assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version, "live Native audit qualification must use the complete PostgreSQL schema head");
  } finally {
    migrationClient.release();
  }

  const organization = crypto.randomUUID();
  const deviceA = crypto.randomUUID();
  const deviceB = crypto.randomUUID();
  const agentA = crypto.randomUUID();
  const publicKeyA = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const publicKeyB = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organization, "Native audit PostgreSQL"]);
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'Native audit A','ed25519',$3,'active','{}'::jsonb),
           ($1,$4,'Native audit B','ed25519',$5,'active','{}'::jsonb)`, [organization, deviceA, publicKeyA, deviceB, publicKeyB]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'cli','Native audit agent',$4,'active')`, [organization, agentA, deviceA, publicKeyA]);
  await pool.query(`INSERT INTO device_audit_heads (organization_id,device_id)
    VALUES ($1,$2),($1,$3)`, [organization, deviceA, deviceB]);

  return {
    pool,
    authority: createControlPlaneAuthorityRepository({ client: pool, cursorSecret: Buffer.alloc(32, 0x67), now: () => NOW }),
    organization,
    deviceA,
    deviceB,
    agentA
  };
}

async function createOtherTenant(pool) {
  const organization = crypto.randomUUID();
  const device = crypto.randomUUID();
  const agent = crypto.randomUUID();
  const publicKey = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organization, "Native audit PostgreSQL other tenant"]);
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'Native audit other','ed25519',$3,'active','{}'::jsonb)`, [organization, device, publicKey]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'cli','Native audit other agent',$4,'active')`, [organization, agent, device, publicKey]);
  return { organization, device, agent };
}

async function insertAuditEvent(pool, organizationId, deviceId, event) {
  await pool.query(`INSERT INTO device_audit_events
    (organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at)
    VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::timestamptz)`, [
    organizationId, deviceId, event.event_id, event.previous_hash, event.event_hash, event, NOW
  ]);
}

async function withSessionAuthorization(pool, roleName, callback) {
  const client = await pool.connect();
  try {
    await client.query(`SET SESSION AUTHORIZATION ${roleName}`);
    const identity = await client.query("SELECT session_user,current_user");
    assert.equal(identity.rows[0].session_user, roleName);
    assert.equal(identity.rows[0].current_user, roleName);
    return await callback(client);
  } finally {
    client.release(true);
  }
}

async function head(pool, organizationId, deviceId) {
  const result = await pool.query(`SELECT sequence,last_event_id,last_event_hash,chain_status,gap_count
    FROM device_audit_heads WHERE organization_id=$1 AND device_id=$2`, [organizationId, deviceId]);
  assert.equal(result.rowCount, 1);
  const row = result.rows[0];
  return {
    sequence: Number(row.sequence),
    last_event_id: row.last_event_id,
    last_event_hash: row.last_event_hash,
    chain_status: row.chain_status,
    gap_count: Number(row.gap_count)
  };
}

async function countEvents(pool, organizationId, deviceId) {
  const result = await pool.query(
    "SELECT count(*)::int AS count FROM device_audit_events WHERE organization_id=$1 AND device_id=$2",
    [organizationId, deviceId]
  );
  return result.rows[0].count;
}

function auditEvent(agentId, { deviceTimestamp, previousHash }) {
  return withHash({
    version: 1,
    event_id: crypto.randomUUID(),
    request_id: crypto.randomUUID(),
    agent_id: agentId,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 1,
    capability_sequence: 1,
    repository: "/work/native-audit",
    branch: "feature/native-audit",
    remote: "git@example.test:native-audit.git",
    payload_digest: "a".repeat(64),
    device_timestamp: deviceTimestamp,
    previous_hash: previousHash
  });
}

function withHash(event) {
  const preimage = { ...event };
  delete preimage.event_hash;
  return { ...event, event_hash: crypto.createHash("sha256").update(canonicalJson(preimage), "utf8").digest("hex") };
}
