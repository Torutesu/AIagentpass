import assert from "node:assert/strict";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import {
  canonicalManagedSignerRequestDigest,
  createPostgresManagedSignerKeyLifecycleRepository
} from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("0037 serializes lifecycle changes and replays exact signatures across PostgreSQL pools", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const purpose = `agentpass.test-managed-signer-${process.pid}`;
  t.after(async () => {
    await firstPool.query("DELETE FROM managed_signer_signing_idempotency WHERE purpose=$1", [purpose]);
    await firstPool.query("DELETE FROM managed_signer_key_lifecycle_operations WHERE purpose=$1", [purpose]);
    await firstPool.query("DELETE FROM managed_signer_keys WHERE purpose=$1", [purpose]);
    await firstPool.query("DELETE FROM managed_signer_key_lifecycles WHERE purpose=$1", [purpose]);
    await Promise.all([firstPool.end(), secondPool.end()]);
  });

  const migrationClient = await firstPool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "managed-signer-lifecycle-integration" }).run();
    assert.equal(migrated.currentVersion, 37);
  } finally {
    migrationClient.release();
  }

  const options = { purpose, now: () => Date.parse("2026-08-14T12:00:00.000Z") };
  const first = createPostgresManagedSignerKeyLifecycleRepository({ client: firstPool, ...options });
  const second = createPostgresManagedSignerKeyLifecycleRepository({ client: secondPool, ...options });
  const initial = {
    version: 1,
    purpose,
    algorithm: "ed25519",
    keys: [{
      key_id: "managed-key-1",
      key_version: 1,
      purpose,
      algorithm: "ed25519",
      public_key_fingerprint: "a".repeat(64),
      state: "active",
      state_version: 1
    }]
  };
  assert.deepEqual(await first.initialize({ snapshot: initial }), initial);
  assert.deepEqual(await second.initialize({ snapshot: initial }), initial);

  const requestDigest = canonicalManagedSignerRequestDigest({ purpose, key_id: "managed-key-1", bytes: "Y29tbWl0" });
  const signing = { operation_id: "sign-once", request_digest: requestDigest, key_id: "managed-key-1", key_version: 1 };
  assert.equal((await first.reserveSignature(signing)).state, "pending");
  const signature = Buffer.alloc(64, 0x5a);
  assert.deepEqual((await first.commitSignature({ ...signing, signature })).signature, signature);
  assert.deepEqual((await second.reserveSignature(signing)).signature, signature);

  const nextKey = {
    key_id: "managed-key-2",
    key_version: 2,
    purpose,
    algorithm: "ed25519",
    public_key_fingerprint: "b".repeat(64),
    state: "active",
    state_version: 1
  };
  const raced = await Promise.allSettled([
    first.rotate({ expected_version: 1, operation_id: "rotate", new_key: nextKey, verification_until: "2026-08-14T13:00:00.000Z" }),
    second.emergencyDisable({ expected_version: 1, operation_id: "disable" })
  ]);
  assert.equal(raced.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(raced.filter(({ status }) => status === "rejected").length, 1);
  assert.equal((await first.snapshot()).version, 2);
});
