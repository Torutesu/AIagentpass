import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
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

async function createLiveFixture(t) {
  const pool = new Pool({ connectionString: databaseUrl, max: 4, connectionTimeoutMillis: 2_000, statement_timeout: 10_000, query_timeout: 12_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "native-device-audit-upload-integration" }).run();
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

  return {
    pool,
    authority: createControlPlaneAuthorityRepository({ client: pool, cursorSecret: Buffer.alloc(32, 0x67), now: () => NOW }),
    organization,
    deviceA,
    deviceB,
    agentA
  };
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
  const { event_hash: _eventHash, ...preimage } = event;
  return { ...event, event_hash: crypto.createHash("sha256").update(canonicalJson(preimage), "utf8").digest("hex") };
}
