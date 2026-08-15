import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson, normalizeAuditEvent } from "../../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  AUDIT_ANCHOR_ZERO_DIGEST,
  auditAnchorStatementHash
} from "../../src/audit-anchor-statement.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresAuditExportIssuanceRepository } from "../../src/postgres/audit-export-issuance-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const CHAINS = Object.freeze(["admin", "device", "cloud_agent"]);
const ORGANIZATION_ID = crypto.randomUUID();
const OTHER_ORGANIZATION_ID = crypto.randomUUID();
const SIGNER_PURPOSE = AUDIT_ANCHOR_PURPOSE;
const ZERO_ROOT = AUDIT_ANCHOR_ZERO_DIGEST;
const MODULE_PATH = "../../src/postgres/audit-export-snapshot-reader.mjs";

test("C2 PostgreSQL snapshot reader derives bounded roots and reservations from all authoritative chains", {
  skip: !DATABASE_URL,
  timeout: 120_000
}, async (t) => {
  const snapshotModule = await import(MODULE_PATH).catch((error) => {
    if (error?.code === "ERR_MODULE_NOT_FOUND") {
      throw new Error(`C2 snapshot-reader module is not implemented yet: ${MODULE_PATH}`, { cause: error });
    }
    throw error;
  });
  const {
    createPostgresAuditExportSnapshotReader,
    AUDIT_EXPORT_ROOT_DOMAIN,
    canonicalAuditExportEntry,
    foldAuditExportRoot
  } = snapshotModule;
  assert.equal(typeof createPostgresAuditExportSnapshotReader, "function");
  assert.equal(typeof AUDIT_EXPORT_ROOT_DOMAIN, "string");
  assert.notEqual(AUDIT_EXPORT_ROOT_DOMAIN.length, 0);
  const canonicalEntry = canonicalAuditExportEntry ?? ((entry) => entry);
  const foldRoot = foldAuditExportRoot ?? ((previousRoot, entry) => domainSeparatedFold(AUDIT_EXPORT_ROOT_DOMAIN, previousRoot, entry));

  const poolA = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const poolB = new Pool({ connectionString: DATABASE_URL, max: 8 });
  t.after(async () => {
    await Promise.all([poolA.end(), poolB.end()]);
  });
  const migrationClient = await poolA.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "audit-export-snapshot-reader-integration" }).run();
    assert.equal(migration.currentVersion, 50);
  } finally {
    migrationClient.release();
  }
  const fixture = await seedFixture(poolA);

  const reader = createPostgresAuditExportSnapshotReader({ maxRecords: 64, maxPayloadBytes: 192 * 1024 });
  const smallReader = createPostgresAuditExportSnapshotReader({ maxRecords: 2, maxPayloadBytes: 192 * 1024 });

  const snapshots = new Map();
  for (const chain of CHAINS) {
    const snapshot = await readSnapshot(poolA, reader, {
      organization_id: ORGANIZATION_ID,
      environment: "production",
      chain,
      export_id: crypto.randomUUID()
    }, boundary());
    assertSnapshotShape(snapshot, chain);
    assertFold(snapshot, canonicalEntry, foldRoot);
    assert.equal(snapshot.range.previous_root_digest, ZERO_ROOT);
    assert.equal(snapshot.range.from_audit_position, 1);
    assert.equal(snapshot.range.record_count, snapshot.range.to_audit_position);
    snapshots.set(chain, snapshot);
  }

  const deviceSnapshot = snapshots.get("device");
  const deviceIds = deviceEntries(deviceSnapshot).map((entry) => entry.source_device_id);
  assert.deepEqual(deviceIds, [fixture.deviceIds[0], fixture.deviceIds[1], fixture.deviceIds[0], fixture.deviceIds[1]], "device export order must be organization-global, not grouped by device");
  assert.deepEqual(deviceEntries(deviceSnapshot).map((entry) => entry.export_position), [1, 2, 3, 4]);
  assert.notEqual(deviceSnapshot.range.root_digest, deviceEntries(deviceSnapshot).at(-1).source_hash, "root must be the domain-separated cumulative fold, not the terminal source hash");

  const firstDeviceChunk = await readSnapshot(poolA, smallReader, {
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "device",
    export_id: crypto.randomUUID()
  }, boundary());
  assert.equal(firstDeviceChunk.range.record_count, 2);
  const secondDeviceChunk = await readSnapshot(poolA, smallReader, {
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "device",
    export_id: crypto.randomUUID()
  }, {
    to_audit_position: firstDeviceChunk.range.to_audit_position,
    root_digest: firstDeviceChunk.range.root_digest
  });
  assert.equal(secondDeviceChunk.range.from_audit_position, 3);
  assert.equal(secondDeviceChunk.range.record_count, 2);
  const chunkEntries = [...deviceEntries(firstDeviceChunk), ...deviceEntries(secondDeviceChunk)];
  assert.deepEqual(chunkEntries.map((entry) => entry.source_id), deviceEntries(deviceSnapshot).map((entry) => entry.source_id));
  assert.equal(secondDeviceChunk.range.root_digest, deviceSnapshot.range.root_digest, "fold result must be independent of chunking");

  const gapEvent = await appendGapDeviceEvent(poolA, fixture);
  const gapSnapshot = await readSnapshot(poolA, reader, {
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "device",
    export_id: crypto.randomUUID()
  }, {
    to_audit_position: deviceSnapshot.range.to_audit_position,
    root_digest: deviceSnapshot.range.root_digest
  });
  assert.equal(gapSnapshot.range.record_count, 1);
  assert.equal(gapSnapshot.payload.entries[0].source_id, gapEvent.eventId);
  assert.deepEqual(gapSnapshot.payload.entries[0].source_gap, {
    expected_previous_hash: gapEvent.expectedPreviousHash,
    received_previous_hash: gapEvent.receivedPreviousHash,
    recorded_at: gapSnapshot.payload.entries[0].source_gap.recorded_at,
    resolved_at: null
  });

  const otherSnapshot = await readSnapshot(poolA, reader, {
    organization_id: OTHER_ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    export_id: crypto.randomUUID()
  }, boundary());
  assertSnapshotShape(otherSnapshot, "admin");
  assert.deepEqual(adminEntries(otherSnapshot).map((entry) => entry.source_id), [fixture.otherAdminEventId]);
  assert.equal(adminEntries(otherSnapshot).some((entry) => entry.source_id === fixture.adminEventIds[0]), false, "RLS must prevent cross-tenant source visibility");

  let repositoryReaderCalls = 0;
  const countedReader = async (...args) => {
    repositoryReaderCalls += 1;
    return reader(...args);
  };
  const repositoryA = createPostgresAuditExportIssuanceRepository({
    client: poolA,
    snapshotReader: countedReader,
    evidenceTtlMs: 120_000,
    claimLeaseMs: 1_000
  });
  const repositoryB = createPostgresAuditExportIssuanceRepository({
    client: poolB,
    snapshotReader: countedReader,
    evidenceTtlMs: 120_000,
    claimLeaseMs: 1_000
  });

  const identity = {
    organization_id: ORGANIZATION_ID,
    export_id: crypto.randomUUID(),
    environment: "production",
    chain: "device",
    idempotency_key: `c2-reader-${process.pid}-${Date.now()}-reclaim`
  };
  const reserved = await repositoryA.reserveAuditExport(identity);
  assert.equal(reserved.state, "reserved");
  assert.equal(repositoryReaderCalls, 1);
  const firstAuthority = authority(reserved);
  await delay(1_250);
  const reclaimed = await repositoryB.reserveAuditExport(identity);
  assert.equal(reclaimed.state, "reserved");
  assert.notEqual(reclaimed.claim_token, reserved.claim_token);
  assert.equal(repositoryReaderCalls, 1, "expired claim reclaim must reuse frozen authority without re-snapshotting");
  assert.deepEqual(authority(reclaimed), firstAuthority);

  const committed = await repositoryB.commitAuditExport({
    ...authority(reclaimed),
    claim_token: reclaimed.claim_token,
    audit_anchor: makeAnchor(authority(reclaimed))
  });
  assert.equal(committed.state, "committed");
  const replay = await repositoryA.replayAuditExport(identity);
  assert.equal(replay.state, "committed");
  assert.deepEqual(replay.range, committed.range);
  assert.equal(replay.payload_digest, committed.payload_digest);
  const persistedPayload = await repositoryA.getAuditExportPayload(identity);
  assert.equal(sha256(canonicalJson(persistedPayload)), committed.payload_digest);
  assert.deepEqual(persistedPayload.range, committed.range);
  assert.equal(Object.isFrozen(persistedPayload), true);
  assert.equal(Object.isFrozen(persistedPayload.entries), true);
  const retrieved = await repositoryA.getCommittedAuditExport({
    organization_id: identity.organization_id,
    export_id: identity.export_id,
    environment: identity.environment,
    chain: identity.chain
  });
  assert.equal(retrieved.state, "committed");
  assert.equal(retrieved.idempotency_key, identity.idempotency_key);
  assert.deepEqual(retrieved.payload, persistedPayload);
  assert.equal(Object.isFrozen(retrieved), true);
  await assert.rejects(repositoryA.getCommittedAuditExport({
    organization_id: identity.organization_id,
    export_id: identity.export_id,
    environment: "staging",
    chain: identity.chain
  }), (error) => error.code === "ERR_AUDIT_EXPORT_ISSUANCE_NOT_FOUND");

  const raceIdentity = {
    organization_id: ORGANIZATION_ID,
    export_id: crypto.randomUUID(),
    environment: "production",
    chain: "admin",
    idempotency_key: `c2-reader-${process.pid}-${Date.now()}-race`
  };
  const race = await Promise.all([
    repositoryA.reserveAuditExport(raceIdentity),
    repositoryB.reserveAuditExport(raceIdentity)
  ]);
  assert.equal(race.filter((result) => result.state === "reserved").length, 1, "one pool must own the same-lane reservation");
  assert.equal(race.filter((result) => result.state === "in_progress").length, 1, "the other pool must observe the in-progress reservation");
  const raceReservation = race.find((result) => result.state === "reserved");
  const raceRepository = race[0].state === "reserved" ? repositoryA : repositoryB;
  await raceRepository.commitAuditExport({
    ...authority(raceReservation),
    claim_token: raceReservation.claim_token,
    audit_anchor: makeAnchor(authority(raceReservation))
  });
});

async function seedFixture(pool) {
  const now = new Date();
  const memberId = crypto.randomUUID();
  const otherMemberId = crypto.randomUUID();
  const deviceIds = [crypto.randomUUID(), crypto.randomUUID()];
  const agentIds = [crypto.randomUUID(), crypto.randomUUID()];
  const adminEventIds = [crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID()];
  const otherAdminEventId = crypto.randomUUID();
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicKeyFingerprint = crypto.createHash("sha256").update(keyPair.publicKey.export({ type: "spki", format: "der" })).digest();

  await withTransaction(pool, async (tx) => {
    await tx.query(`INSERT INTO organizations (id,name) VALUES ($1,$2),($3,$4)`, [ORGANIZATION_ID, `C2 snapshot ${process.pid}`, OTHER_ORGANIZATION_ID, `C2 other ${process.pid}`]);
    await tx.query(`INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3),($4,$5,$6)`, [memberId, `c2-${process.pid}-${memberId}`, "C2 owner", otherMemberId, `c2-${process.pid}-${otherMemberId}`, "C2 other"]);
    await tx.query(`INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active'),($4,$5,$6,'owner','active')`, [ORGANIZATION_ID, crypto.randomUUID(), memberId, OTHER_ORGANIZATION_ID, crypto.randomUUID(), otherMemberId]);
    await tx.query(`SELECT set_config('agentpass.organization_id',$1,true)`, [ORGANIZATION_ID]);
    for (let index = 0; index < deviceIds.length; index += 1) {
      await tx.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status) VALUES ($1,$2,$3,'ed25519',NULL,'pending')`, [ORGANIZATION_ID, deviceIds[index], `C2 device ${index + 1}`]);
      await tx.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status) VALUES ($1,$2,$3,'claude-code',$4,$5,'active')`, [ORGANIZATION_ID, agentIds[index], deviceIds[index], `C2 agent ${index + 1}`, `${publicKeyPem}${index}`]);
    }
    await tx.query(`INSERT INTO managed_signer_key_lifecycles (purpose,algorithm,version,max_keys,max_verification_overlap_ms) VALUES ($1,'ed25519',1,4,7776000000) ON CONFLICT (purpose) DO NOTHING`, [SIGNER_PURPOSE]);
    await tx.query(`INSERT INTO managed_signer_keys (purpose,key_id,key_version,algorithm,public_key_fingerprint,public_key_pem,state,state_version,key_position) VALUES ($1,'c2-audit-key',1,'ed25519',$2,$3,'active',1,0) ON CONFLICT DO NOTHING`, [SIGNER_PURPOSE, publicKeyFingerprint, publicKeyPem]);
    await seedAdminEvents(tx, ORGANIZATION_ID, memberId, adminEventIds, now);
    await tx.query(`SELECT set_config('agentpass.organization_id',$1,true)`, [OTHER_ORGANIZATION_ID]);
    await seedAdminEvents(tx, OTHER_ORGANIZATION_ID, otherMemberId, [otherAdminEventId], now);
    await tx.query(`SELECT set_config('agentpass.organization_id',$1,true)`, [ORGANIZATION_ID]);
    await seedCloudEvents(tx, { organizationId: ORGANIZATION_ID, memberId, deviceIds, agentIds, now });
    await seedDeviceEvents(tx, { organizationId: ORGANIZATION_ID, deviceIds, agentIds, now });
  });
  return Object.freeze({ deviceIds, agentIds, adminEventIds, otherAdminEventId });
}

async function appendGapDeviceEvent(pool, fixture) {
  return withTransaction(pool, async (tx) => {
    await tx.query(`SELECT set_config('agentpass.organization_id',$1,true)`, [ORGANIZATION_ID]);
    const head = await tx.query(`SELECT last_event_hash FROM device_audit_heads WHERE organization_id=$1 AND device_id=$2 FOR UPDATE`, [ORGANIZATION_ID, fixture.deviceIds[0]]);
    const expectedPreviousHash = head.rows[0].last_event_hash;
    const receivedPreviousHash = "9".repeat(64);
    const eventId = crypto.randomUUID();
    const withoutHash = {
      version: 1,
      event_id: eventId,
      request_id: crypto.randomUUID(),
      agent_id: fixture.agentIds[0],
      operation: "git.commit.sign",
      decision: "allow",
      reason: "allowed",
      policy_sequence: 1,
      capability_sequence: 1,
      repository: "/workspace/agentpass",
      branch: "main",
      remote: "origin",
      payload_digest: "b".repeat(64),
      device_timestamp: new Date().toISOString(),
      previous_hash: receivedPreviousHash
    };
    const eventHash = sha256(canonicalJson(withoutHash));
    const stored = normalizeAuditEvent({ ...withoutHash, event_hash: eventHash });
    await tx.query(`INSERT INTO device_audit_events
      (organization_id,device_id,event_id,previous_hash,event_hash,redacted_json)
      VALUES ($1,$2,$3,$4,$5,$6::jsonb)`, [ORGANIZATION_ID, fixture.deviceIds[0], eventId, receivedPreviousHash, eventHash, JSON.stringify(stored)]);
    return Object.freeze({ eventId, expectedPreviousHash, receivedPreviousHash });
  });
}

async function seedAdminEvents(tx, organizationId, actorId, eventIds, now) {
  let previousHash = ZERO_ROOT;
  for (let index = 0; index < eventIds.length; index += 1) {
    const sequence = index + 1;
    const event = {
      version: 1,
      audit_event_id: eventIds[index],
      organization_id: organizationId,
      actor_id: actorId,
      action: index === 0 ? "webauthn.credential.deleted" : "c2.snapshot.seed",
      target_type: "organization",
      target_id: null,
      details: { sequence, source: "integration-test" },
      previous_hash: previousHash,
      sequence
    };
    await tx.query(`INSERT INTO admin_audit_events (organization_id,id,actor_id,action,target_type,target_id,previous_hash,event_hash,sequence,event_json,created_at) VALUES ($1,$2,$3,$4,$5,NULL,$6,$7,$8,$9::jsonb,$10::timestamptz)`, [organizationId, eventIds[index], actorId, event.action, event.target_type, previousHash, "a".repeat(64), sequence, JSON.stringify(event), new Date(now.getTime() + sequence).toISOString()]);
    const eventHash = sha256(JSON.stringify(event));
    await tx.query(`UPDATE admin_audit_events SET event_hash=$3 WHERE organization_id=$1 AND id=$2`, [organizationId, eventIds[index], eventHash]);
    previousHash = eventHash;
  }
  await tx.query(`UPDATE admin_audit_heads SET sequence=$2,event_hash=$3,updated_at=clock_timestamp() WHERE organization_id=$1`, [organizationId, eventIds.length, previousHash]);
}

async function seedCloudEvents(tx, { organizationId, memberId, deviceIds, agentIds, now }) {
  let previousHash = ZERO_ROOT;
  for (let index = 0; index < deviceIds.length; index += 1) {
    const grantId = crypto.randomUUID();
    const sessionId = crypto.randomUUID();
    const adapterId = crypto.randomUUID();
    const eventId = crypto.randomUUID();
    const grantHash = `${String.fromCharCode(99 + index)}${String.fromCharCode(99 + index)}`.repeat(32);
    const statementHash = `${String.fromCharCode(100 + index)}${String.fromCharCode(100 + index)}`.repeat(32);
    const processBindingHash = (index === 0 ? "e" : "f").repeat(64);
    const ancestryBindingHash = (index === 0 ? "a" : "b").repeat(64);
    const worktreeBindingHash = (index === 0 ? "c" : "d").repeat(64);
    const notBefore = new Date(now.getTime() - 10_000).toISOString();
    const expiresAt = new Date(now.getTime() + 3_600_000).toISOString();
    await tx.query(`INSERT INTO agent_session_grants
      (organization_id,grant_id,device_id,agent_id,agent_kind,adapter_id,adapter_version,worktree_binding_sha256,process_binding_policy_id,scope_json,max_signatures,not_before,expires_at,control_sequence,authority_generation,issuer,signer_key_id,statement_hash,grant_hash,signature_base64url,status,issued_at,created_by)
      VALUES ($1,$2,$3,$4,'claude-code',$5,$6,$7,'c2-policy','{}'::jsonb,8,$8::timestamptz,$9::timestamptz,1,1,'agentpass-cloud','c2-agent-key',$10,$11,$12,'issued',$13::timestamptz,$14)`, [organizationId, grantId, deviceIds[index], agentIds[index], adapterId, "1.0.0", worktreeBindingHash, notBefore, expiresAt, statementHash, grantHash, Buffer.alloc(64).toString("base64url"), now.toISOString(), memberId]);
    await tx.query(`INSERT INTO agent_sessions
      (organization_id,session_id,grant_id,device_id,agent_id,agent_kind,adapter_id,adapter_version,process_binding_policy_id,grant_hash,process_binding_sha256,ancestry_binding_sha256,worktree_binding_sha256,control_sequence,authority_generation,max_signatures,status,created_at,not_before,expires_at)
      VALUES ($1,$2,$3,$4,$5,'claude-code',$6,$7,'c2-policy',$8,$9,$10,$11,1,1,8,'challenge_pending',$12::timestamptz,$13::timestamptz,$14::timestamptz)`, [organizationId, sessionId, grantId, deviceIds[index], agentIds[index], adapterId, "1.0.0", grantHash, processBindingHash, ancestryBindingHash, worktreeBindingHash, now.toISOString(), notBefore, expiresAt]);
    await tx.query(`UPDATE agent_sessions SET status='active' WHERE organization_id=$1 AND session_id=$2`, [organizationId, sessionId]);
    const grant = await tx.query(`SELECT consumed_at FROM agent_session_grants WHERE organization_id=$1 AND grant_id=$2`, [organizationId, grantId]);
    const consumedAt = new Date(grant.rows[0].consumed_at).toISOString();
    const preimage = {
      organization_id: organizationId,
      sequence: index + 1,
      event_id: eventId,
      event_type: "agent_session_grant.consumed",
      grant_id: grantId,
      session_id: sessionId,
      device_id: deviceIds[index],
      agent_id: agentIds[index],
      grant_hash: grantHash,
      statement_hash: statementHash,
      signer_key_id: "c2-agent-key",
      process_binding_sha256: processBindingHash,
      ancestry_binding_sha256: ancestryBindingHash,
      worktree_binding_sha256: worktreeBindingHash,
      control_sequence: 1,
      authority_generation: 1,
      consumed_at: consumedAt,
      recorded_at: new Date(now.getTime() + index + 1).toISOString(),
      previous_hash: previousHash
    };
    const eventHash = sha256(canonicalJson(preimage));
    await tx.query(`INSERT INTO cloud_agent_audit_events
      (organization_id,event_id,sequence,event_type,grant_id,session_id,device_id,agent_id,grant_hash,statement_hash,signer_key_id,process_binding_sha256,ancestry_binding_sha256,worktree_binding_sha256,control_sequence,authority_generation,consumed_at,previous_hash,event_hash,recorded_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::timestamptz,$18,$19,$20::timestamptz)`, [organizationId, eventId, index + 1, preimage.event_type, grantId, sessionId, deviceIds[index], agentIds[index], grantHash, statementHash, preimage.signer_key_id, processBindingHash, preimage.ancestry_binding_sha256, preimage.worktree_binding_sha256, 1, 1, consumedAt, previousHash, eventHash, preimage.recorded_at]);
    previousHash = eventHash;
  }
}

async function seedDeviceEvents(tx, { organizationId, deviceIds, agentIds, now }) {
  const previous = new Map(deviceIds.map((deviceId) => [deviceId, ZERO_ROOT]));
  for (let index = 0; index < 4; index += 1) {
    const deviceIndex = index % deviceIds.length;
    const eventId = crypto.randomUUID();
    const deviceId = deviceIds[deviceIndex];
    const event = {
      version: 1,
      event_id: eventId,
      request_id: crypto.randomUUID(),
      agent_id: agentIds[deviceIndex],
      operation: "git.commit.sign",
      decision: "allow",
      reason: "allowed",
      policy_sequence: 1,
      capability_sequence: 1,
      repository: "/workspace/agentpass",
      branch: "main",
      remote: "origin",
      payload_digest: "a".repeat(64),
      device_timestamp: new Date(now.getTime() + index + 1).toISOString(),
      previous_hash: previous.get(deviceId),
      event_hash: "0".repeat(64)
    };
    const { event_hash: _ignored, ...withoutHash } = event;
    const eventHash = sha256(canonicalJson(withoutHash));
    const stored = normalizeAuditEvent({ ...withoutHash, event_hash: eventHash });
    await tx.query(`INSERT INTO device_audit_events (organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::timestamptz)`, [organizationId, deviceId, eventId, stored.previous_hash, stored.event_hash, JSON.stringify(stored), new Date(now.getTime() + index + 1).toISOString()]);
    previous.set(deviceId, eventHash);
  }
}

async function readSnapshot(pool, reader, identity, previousBoundary) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('agentpass.organization_id',$1,true)", [identity.organization_id]);
    const result = await reader(client, Object.freeze({
      ...identity,
      idempotency_key: identity.idempotency_key ?? `c2-direct-${identity.export_id}`
    }), previousBoundary);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function assertSnapshotShape(snapshot, chain) {
  assert.equal(snapshot?.range?.from_audit_position, 1);
  assert.equal(snapshot.range.record_count, snapshot.range.to_audit_position - snapshot.range.from_audit_position + 1);
  assert.equal(snapshot.range.previous_root_digest, ZERO_ROOT);
  assert.equal(snapshot.range.root_digest.length, 64);
  assert.ok(snapshot.range.root_digest !== ZERO_ROOT);
  assert.equal(snapshot.payload?.chain, chain);
  assert.ok(Array.isArray(snapshot.payload?.entries));
  assert.equal(snapshot.payload.entries.length, snapshot.range.record_count);
  assert.equal(typeof snapshot.key_id, "string");
  assert.equal(Number.isSafeInteger(snapshot.key_version), true);
  assert.equal(Number.isSafeInteger(snapshot.lifecycle_version), true);
}

function assertFold(snapshot, canonicalEntry, foldAuditExportRoot) {
  let root = snapshot.range.previous_root_digest;
  for (const entry of snapshot.payload.entries) root = foldAuditExportRoot(root, canonicalEntry(entry));
  assert.equal(root, snapshot.range.root_digest);
}

function domainSeparatedFold(domain, previousRoot, entry) {
  return crypto.createHash("sha256").update(Buffer.concat([
    Buffer.from(domain, "utf8"),
    Buffer.from([0]),
    Buffer.from(previousRoot, "hex"),
    Buffer.from([0]),
    Buffer.from(canonicalJson(entry), "utf8")
  ])).digest("hex");
}

function deviceEntries(snapshot) { return snapshot.payload.entries; }
function adminEntries(snapshot) { return snapshot.payload.entries; }
function boundary() { return { to_audit_position: 0, root_digest: ZERO_ROOT }; }
function authority(result) {
  const { state: _state, claim_token: _claimToken, ...value } = result;
  return value;
}

function makeAnchor(authorityValue) {
  const statement = {
    version: AUDIT_ANCHOR_VERSION,
    type: AUDIT_ANCHOR_TYPE,
    organization_id: authorityValue.organization_id,
    environment: authorityValue.environment,
    chain: authorityValue.chain,
    export_id: authorityValue.export_id,
    audit_position: authorityValue.range.to_audit_position,
    previous_audit_position: authorityValue.range.from_audit_position - 1,
    root_digest: authorityValue.range.root_digest,
    previous_root_digest: authorityValue.range.previous_root_digest,
    export_digest: authorityValue.payload_digest,
    record_count: authorityValue.range.record_count,
    purpose: AUDIT_ANCHOR_PURPOSE,
    protocol_version: 1,
    signing_version: 1,
    lifecycle_version: authorityValue.lifecycle_version,
    key_id: authorityValue.key_id,
    key_version: authorityValue.key_version,
    issued_at: authorityValue.issued_at,
    expires_at: authorityValue.expires_at
  };
  return {
    version: AUDIT_ANCHOR_VERSION,
    type: AUDIT_ANCHOR_TYPE,
    statement,
    statement_hash: auditAnchorStatementHash(statement),
    signature_algorithm: AUDIT_ANCHOR_ALGORITHM,
    signer_key_fingerprint: `SHA256:${"f".repeat(43)}`,
    signature: Buffer.alloc(64, 7).toString("base64url")
  };
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

async function withTransaction(pool, operation) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
