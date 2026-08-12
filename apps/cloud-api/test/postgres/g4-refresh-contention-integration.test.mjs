import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import pg from "pg";

import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";

const { Pool } = pg;
const databaseUrl = process.env.AGENTPASS_TEST_POSTGRES_URL;
const TENANT_COUNT = 6;
const REDUCTIONS_PER_TENANT = 12;
const DEVICES_PER_TENANT = 2;

test("G4 refresh contention preserves per-tenant monotonicity without pool starvation", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 8,
    options: "-c statement_timeout=5000 -c lock_timeout=2000"
  });
  t.after(() => pool.end());

  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "g4-refresh-contention" }).run(); }
  finally { migrationClient.release(); }

  const key = Buffer.alloc(32, 0x64);
  const codec = createRefreshNonceCodec({ keys: { "refresh-nonce-v4": key }, activeKeyId: "refresh-nonce-v4" });
  const tenants = await Promise.all(Array.from({ length: TENANT_COUNT }, (_, index) => seedTenant(pool, index)));
  const repositories = Array.from({ length: TENANT_COUNT }, (_, index) => createControlPlaneAuthorityRepository({
    client: pool,
    cursorSecret: Buffer.alloc(32, 0x41 + index),
    refreshNonceCodec: codec
  }));

  const startedAt = performance.now();
  const results = await Promise.all(tenants.map(async (tenant, tenantIndex) => {
    const repository = repositories[tenantIndex];
    const generations = [];
    for (let reduction = 0; reduction < REDUCTIONS_PER_TENANT; reduction += 1) {
      const issuedAt = new Date(Date.now() + reduction).toISOString();
      const result = await repository.advanceAuthorityGenerationAndEnqueueRefresh({
        organization_id: tenant.organizationId,
        issued_at: issuedAt,
        expires_at: new Date(Date.parse(issuedAt) + 5 * 60_000).toISOString()
      });
      generations.push(result.generation);
      assert.equal(result.devices.length, DEVICES_PER_TENANT);
      assert.equal(result.devices.every((device) => device.desired_generation === result.generation), true);
      assert.equal(result.devices.every((device) => device.refresh_nonce_key_id === "refresh-nonce-v4"), true);
    }
    return generations;
  }));
  const elapsedMs = performance.now() - startedAt;

  for (const generations of results) {
    assert.deepEqual(generations, Array.from({ length: REDUCTIONS_PER_TENANT }, (_, index) => index + 2));
  }
  assert.ok(elapsedMs < 20_000, `bounded contention run exceeded 20 seconds: ${Math.ceil(elapsedMs)}ms`);

  for (let tenantIndex = 0; tenantIndex < tenants.length; tenantIndex += 1) {
    const tenant = tenants[tenantIndex];
    const repository = repositories[tenantIndex];
    const expectedGeneration = REDUCTIONS_PER_TENANT + 1;
    const generation = await pool.query(`SELECT generation FROM control_plane_authority_generations
      WHERE organization_id=$1 AND superseded_at IS NULL`, [tenant.organizationId]);
    assert.equal(Number(generation.rows[0].generation), expectedGeneration);

    const state = await pool.query(`SELECT device_id,desired_generation,refresh_state
      FROM device_control_plane_state WHERE organization_id=$1 ORDER BY device_id`, [tenant.organizationId]);
    assert.equal(state.rowCount, DEVICES_PER_TENANT);
    assert.equal(state.rows.every((row) => Number(row.desired_generation) === expectedGeneration && row.refresh_state === "pending"), true);

    for (const deviceId of tenant.deviceIds) {
      const pending = await repository.pollDeviceRefresh({
        organization_id: tenant.organizationId,
        device_id: deviceId,
        after_generation: expectedGeneration - 1
      });
      assert.equal(pending.desired_generation, expectedGeneration);
      assert.equal(pending.refresh_nonce_key_id, "refresh-nonce-v4");
      assert.equal("refresh_nonce" in pending, false);
    }
  }

  const poolState = Object.freeze({ total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount });
  assert.ok(poolState.total <= 8);
  assert.equal(poolState.waiting, 0);
});

async function seedTenant(pool, index) {
  const organizationId = crypto.randomUUID();
  const deviceIds = [crypto.randomUUID(), crypto.randomUUID()];
  const keys = deviceIds.map(() => crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey
    .export({ type: "spki", format: "pem" }).toString().trimEnd());
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, `G4 contention ${index}`]);
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,$3,'p256-sha256',$4,'active','{}'::jsonb),
           ($1,$5,$6,'p256-sha256',$7,'active','{}'::jsonb)`, [
    organizationId,
    deviceIds[0], `Mac ${index}-A`, keys[0],
    deviceIds[1], `Mac ${index}-B`, keys[1]
  ]);
  return Object.freeze({ organizationId, deviceIds: Object.freeze(deviceIds) });
}
