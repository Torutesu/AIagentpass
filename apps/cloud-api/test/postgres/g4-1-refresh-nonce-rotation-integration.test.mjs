import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import pg from "pg";

import { createRefreshHintService, REFRESH_HINT_SERVICE_ERROR_CODES } from "../../src/refresh-hint-service.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";
import { createEd25519RefreshHintSigner } from "../../src/refresh-hint-signer.mjs";

const { Pool } = pg;
const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const OLD_KEY_ID = "refresh-nonce-v1";
const NEW_KEY_ID = "refresh-nonce-v3";
const OLD_KEY = Buffer.alloc(32, 0x51);
const NEW_KEY = Buffer.alloc(32, 0x73);

test("G4.1 rotation survives two PostgreSQL runtime instances and fails closed after old-key removal", { skip: !databaseUrl, timeout: 20_000 }, async (t) => {
  const poolA = new Pool({ connectionString: databaseUrl, max: 4 });
  const poolB = new Pool({ connectionString: databaseUrl, max: 4 });
  t.after(async () => { await Promise.all([poolA.end(), poolB.end()]); });

  const migrationClient = await poolA.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "g4-1-refresh-nonce-rotation" }).run(); }
  finally { migrationClient.release(); }

  const organizationId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const oldOutboxId = crypto.randomUUID();
  const newOutboxId = crypto.randomUUID();
  const deviceKey = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey
    .export({ type: "spki", format: "pem" }).toString().trimEnd();
  await poolA.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, "G4.1 nonce rotation"]);
  await poolA.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'rotation-device','p256-sha256',$3,'active','{}'::jsonb)`, [organizationId, deviceId, deviceKey]);

  const oldWriter = createControlPlaneAuthorityRepository({
    client: poolA,
    cursorSecret: Buffer.alloc(32, 0x41),
    refreshNonceCodec: createRefreshNonceCodec({ keys: { [OLD_KEY_ID]: OLD_KEY }, activeKeyId: OLD_KEY_ID })
  });
  const runtimeACodec = createRefreshNonceCodec({ keys: { [OLD_KEY_ID]: OLD_KEY, [NEW_KEY_ID]: NEW_KEY }, activeKeyId: NEW_KEY_ID });
  const runtimeBCodec = createRefreshNonceCodec({ keys: { [OLD_KEY_ID]: OLD_KEY, [NEW_KEY_ID]: NEW_KEY }, activeKeyId: NEW_KEY_ID });
  const runtimeA = createControlPlaneAuthorityRepository({
    client: poolA,
    cursorSecret: Buffer.alloc(32, 0x42),
    refreshNonceCodec: runtimeACodec
  });
  const runtimeB = createControlPlaneAuthorityRepository({
    client: poolB,
    cursorSecret: Buffer.alloc(32, 0x43),
    refreshNonceCodec: runtimeBCodec
  });

  const oldGeneration = await oldWriter.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: organizationId,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 4 * 60_000).toISOString(),
    outbox_ids: { [deviceId]: oldOutboxId }
  });
  assert.equal(oldGeneration.generation, 2);
  assert.equal(oldGeneration.devices[0].refresh_nonce_key_id, OLD_KEY_ID);

  const signerKeys = crypto.generateKeyPairSync("ed25519");
  const signer = createEd25519RefreshHintSigner({ privateKey: signerKeys.privateKey, keyId: "refresh-hint-rotation-v1" });
  const serviceA = createRefreshHintService({ source: runtimeA, nonceDeriver: runtimeACodec, signer });
  const serviceB = createRefreshHintService({ source: runtimeB, nonceDeriver: runtimeBCodec, signer });
  const [oldHintA, oldHintB] = await Promise.all([
    serviceA.poll({ organization_id: organizationId, device_id: deviceId, after_generation: 1, wait_ms: 0 }),
    serviceB.poll({ organization_id: organizationId, device_id: deviceId, after_generation: 1, wait_ms: 0 })
  ]);
  assert.equal(oldHintA.nonce, oldHintB.nonce);

  const newGeneration = await runtimeB.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: organizationId,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 4 * 60_000).toISOString(),
    outbox_ids: { [deviceId]: newOutboxId }
  });
  assert.equal(newGeneration.generation, 3);
  assert.equal(newGeneration.devices[0].refresh_nonce_key_id, NEW_KEY_ID);

  const newMetadata = await runtimeA.pollDeviceRefresh({ organization_id: organizationId, device_id: deviceId, after_generation: 2 });
  assert.equal(newMetadata.refresh_nonce_key_id, NEW_KEY_ID);
  assert.equal("refresh_nonce" in newMetadata, false);
  assert.equal(JSON.stringify(newMetadata).includes(oldHintA.nonce), false);
  assert.equal(JSON.stringify(newMetadata).includes(newMetadata.refresh_nonce_digest), true);

  const oldOutbox = await poolA.query(`SELECT organization_id,device_id,desired_generation,outbox_id,
      refresh_nonce_key_id,refresh_nonce_digest,created_at,expires_at
    FROM device_refresh_outbox WHERE organization_id=$1 AND outbox_id=$2`, [organizationId, oldOutboxId]);
  assert.equal(oldOutbox.rowCount, 1);
  assert.equal(oldOutbox.rows[0].refresh_nonce_key_id, OLD_KEY_ID);
  const retainedMetadata = toPollMetadata(oldOutbox.rows[0]);
  const newOnlyCodec = createRefreshNonceCodec({ keys: { [NEW_KEY_ID]: NEW_KEY }, activeKeyId: NEW_KEY_ID });
  const retainedSource = {
    async pollDeviceRefresh() { return retainedMetadata; },
    async markDeviceRefreshDelivered() {}
  };
  const failClosedService = createRefreshHintService({ source: retainedSource, nonceDeriver: newOnlyCodec, signer });
  await assert.rejects(
    failClosedService.poll({ organization_id: organizationId, device_id: deviceId, after_generation: 1, wait_ms: 0 }),
    { code: REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE }
  );

  await poolA.query("DELETE FROM device_refresh_delivery_attempts WHERE organization_id=$1 AND outbox_id=$2", [organizationId, oldOutboxId]);
  await poolA.query("DELETE FROM device_refresh_outbox WHERE organization_id=$1 AND outbox_id=$2", [organizationId, oldOutboxId]);
  const afterCleanup = await runtimeA.pollDeviceRefresh({ organization_id: organizationId, device_id: deviceId, after_generation: 1 });
  assert.equal(afterCleanup.outbox_id, newOutboxId);
  assert.equal(afterCleanup.refresh_nonce_key_id, NEW_KEY_ID);
});

function toPollMetadata(row) {
  return {
    organization_id: row.organization_id,
    device_id: row.device_id,
    desired_generation: Number(row.desired_generation),
    refresh_state: "pending",
    outbox_id: row.outbox_id,
    refresh_nonce_key_id: row.refresh_nonce_key_id,
    refresh_nonce_digest: Buffer.from(row.refresh_nonce_digest).toString("hex"),
    published_at: new Date(row.created_at).toISOString(),
    expires_at: new Date(row.expires_at).toISOString()
  };
}
