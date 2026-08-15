import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import {
  canonicalManagedSignerRequestDigest,
  createPostgresManagedSignerKeyLifecycleRepository
} from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";
import { createDurableManagedSignerProvider } from "../../src/durable-managed-signer-provider.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("0051 fences signing leases across PostgreSQL pools and lifecycle races", {
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
    assert.equal(migrated.currentVersion, 51);
  } finally {
    migrationClient.release();
  }

  const options = { purpose, now: () => Date.parse("2026-08-14T12:00:00.000Z") };
  const first = createPostgresManagedSignerKeyLifecycleRepository({ client: firstPool, ...options });
  const second = createPostgresManagedSignerKeyLifecycleRepository({ client: secondPool, ...options });
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const publicKey = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicKeyFingerprint = crypto.createHash("sha256").update(keyPair.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const initial = {
    version: 1,
    purpose,
    algorithm: "ed25519",
    keys: [{
      key_id: "managed-key-1",
      key_version: 1,
      purpose,
      algorithm: "ed25519",
      public_key_fingerprint: publicKeyFingerprint,
      public_key: publicKey,
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

  let providerSignCalls = 0;
  let releaseConcurrent;
  let concurrent = false;
  const provider = {
    async publicKeyMetadata() { return { key_id: "managed-key-1", algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) {
      providerSignCalls += 1;
      if (concurrent) await new Promise((resolve) => { releaseConcurrent = resolve; });
      return crypto.sign(null, bytes, keyPair.privateKey);
    }
  };
  const firstDurable = createDurableManagedSignerProvider({ provider, repository: first, purpose, keyId: "managed-key-1", keyVersion: 1, version: 1 });
  const secondDurable = createDurableManagedSignerProvider({ provider, repository: second, purpose, keyId: "managed-key-1", keyVersion: 1, version: 1 });
  const durableRequest = { algorithm: "ed25519", bytes: Buffer.from("durable-replay"), key_id: "managed-key-1", purpose, version: 1 };
  const durableSignature = await firstDurable.sign(durableRequest);
  assert.deepEqual(await secondDurable.sign(durableRequest), durableSignature);
  assert.equal(providerSignCalls, 1, "a second replica must replay committed bytes without another KMS call");

  concurrent = true;
  const concurrentRequest = { ...durableRequest, bytes: Buffer.from("two-replica-race") };
  const firstRace = firstDurable.sign(concurrentRequest);
  while (!releaseConcurrent) await new Promise((resolve) => setImmediate(resolve));
  const secondRace = secondDurable.sign(concurrentRequest);
  await assert.rejects(secondRace, { code: "ERR_DURABLE_MANAGED_SIGNER_PENDING" });
  releaseConcurrent();
  await assert.doesNotReject(firstRace);
  assert.equal(providerSignCalls, 2, "the two-replica race must invoke KMS only once for the new payload");

  const nextKey = {
    key_id: "managed-key-2",
    key_version: 2,
    purpose,
    algorithm: "ed25519",
    public_key_fingerprint: "b".repeat(64),
    state: "active",
    state_version: 1
  };
  const fencedDigest = canonicalManagedSignerRequestDigest({ purpose, key_id: "managed-key-1", bytes: "ZmVuY2Vk" });
  const fenced = { operation_id: "sign-fenced", request_digest: fencedDigest, key_id: "managed-key-1", key_version: 1 };
  const reserved = await first.reserveSignature(fenced);
  assert.match(reserved.claim_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal((await firstPool.query("SELECT octet_length(claim_token_digest) AS bytes, reserved_lifecycle_version FROM managed_signer_signing_idempotency WHERE purpose=$1 AND operation_id=$2", [purpose, fenced.operation_id])).rows[0].bytes, 32);
  await first.startSignature({ ...fenced, claim_token: reserved.claim_token });
  const raced = await Promise.allSettled([
    first.rotate({ expected_version: 1, operation_id: "rotate", new_key: nextKey, verification_until: "2026-08-14T13:00:00.000Z" }),
    second.emergencyDisable({ expected_version: 1, operation_id: "disable" })
  ]);
  assert.equal(raced.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(raced.filter(({ status }) => status === "rejected").length, 1);
  assert.equal((await first.snapshot()).version, 2);
  await assert.rejects(first.commitSignature({ ...fenced, claim_token: reserved.claim_token, signature: Buffer.alloc(64, 0x5a) }), { code: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_SIGNING_CLAIM_LOST" });
});
