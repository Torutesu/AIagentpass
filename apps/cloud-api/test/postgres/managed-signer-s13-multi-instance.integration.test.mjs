import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import {
  createDurableManagedSignerProvider,
  DURABLE_MANAGED_SIGNER_ERROR_CODES
} from "../../src/durable-managed-signer-provider.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import {
  canonicalManagedSignerRequestDigest,
  createPostgresManagedSignerKeyLifecycleRepository
} from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL;
const SIGNER_CODES = DURABLE_MANAGED_SIGNER_ERROR_CODES;
const ACTIVE = "active";
const RETIRING = "retiring";
const EMERGENCY_DISABLED = "emergency-disabled";

let migrationReady;

test("S1.3 PostgreSQL qualification: independent instances fence lifecycle races", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run S1.3 PostgreSQL qualification",
  timeout: 120_000
}, async (t) => {
  await reserveReductionRace(t, "reserve-rotate", "rotate");
  await reserveReductionRace(t, "reserve-emergency", "emergency");

  await withFixture(t, "rotate-fence", async (fixture) => {
    const providerAdmissions = { count: 0 };
    const started = deferred();
    const releaseStart = deferred();
    const gatedRepository = Object.freeze({
      ...fixture.first,
      async startSignature(input) {
        const result = await fixture.first.startSignature(input);
        started.resolve(result);
        await releaseStart.promise;
        return result;
      }
    });
    const provider = createProvider({
      pair: fixture.keyPair,
      publicKey: fixture.initial.keys[0].public_key,
      keyId: fixture.keyId,
      admissions: providerAdmissions
    });
    const signer = createDurableManagedSignerProvider({
      provider,
      repository: gatedRepository,
      purpose: fixture.purpose,
      keyId: fixture.keyId,
      keyVersion: 1,
      publicKey: fixture.initial.keys[0].public_key,
      version: 1
    });
    const bytes = Buffer.from("s1.3-rotate-fence");
    const request = signerRequest(fixture, bytes);
    const signPromise = signer.sign(request);

    const startedRecord = await withTimeout(started.promise, "startSignature did not reach the race gate");
    assert.equal(startedRecord.state, "pending");
    const rotated = await fixture.second.rotate({
      expected_version: 1,
      operation_id: "s13-rotate-fence",
      new_key: fixture.nextKey,
      verification_until: futureVerificationUntil()
    });
    assert.equal(rotated.version, 2);
    assert.deepEqual(rotated.keys.map((key) => key.state), [RETIRING, ACTIVE]);

    releaseStart.resolve();
    await assert.rejects(signPromise, { code: SIGNER_CODES.COMMIT });
    assert.equal(providerAdmissions.count, 0, "provider admission must not occur after rotate wins the lifecycle fence");
    const quarantined = await fixture.second.lookupSignature(lookupInput(fixture, request));
    assert.equal(quarantined.state, "uncertain");
    assert.equal(quarantined.reserved_lifecycle_version, 1);
    assert.match(quarantined.provider_started_at, /^\d{4}-\d{2}-\d{2}T/u);
  });

  await withFixture(t, "emergency-fence", async (fixture) => {
    const providerAdmissions = { count: 0 };
    const started = deferred();
    const releaseStart = deferred();
    const gatedRepository = Object.freeze({
      ...fixture.first,
      async startSignature(input) {
        const result = await fixture.first.startSignature(input);
        started.resolve(result);
        await releaseStart.promise;
        return result;
      }
    });
    const signer = createDurableManagedSignerProvider({
      provider: createProvider({
        pair: fixture.keyPair,
        publicKey: fixture.initial.keys[0].public_key,
        keyId: fixture.keyId,
        admissions: providerAdmissions
      }),
      repository: gatedRepository,
      purpose: fixture.purpose,
      keyId: fixture.keyId,
      keyVersion: 1,
      publicKey: fixture.initial.keys[0].public_key,
      version: 1
    });
    const bytes = Buffer.from("s1.3-emergency-fence");
    const request = signerRequest(fixture, bytes);
    const signPromise = signer.sign(request);

    assert.equal((await withTimeout(started.promise, "startSignature did not reach the emergency race gate")).state, "pending");
    const disabled = await fixture.second.emergencyDisable({
      expected_version: 1,
      operation_id: "s13-emergency-fence"
    });
    assert.equal(disabled.version, 2);
    assert.ok(disabled.keys.every((key) => key.state === EMERGENCY_DISABLED));

    releaseStart.resolve();
    await assert.rejects(signPromise, { code: SIGNER_CODES.COMMIT });
    assert.equal(providerAdmissions.count, 0, "provider admission must not occur after emergency disable wins the lifecycle fence");
    const quarantined = await fixture.second.lookupSignature(lookupInput(fixture, request));
    assert.equal(quarantined.state, "uncertain");
    assert.equal(quarantined.reserved_lifecycle_version, 1);
    assert.match(quarantined.provider_started_at, /^\d{4}-\d{2}-\d{2}T/u);
  });
});

test("S1.3 PostgreSQL qualification: started provider loss is quarantined without re-sign", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run S1.3 PostgreSQL qualification",
  timeout: 120_000
}, async (t) => {
  await withFixture(t, "provider-loss", async (fixture) => {
    const providerAdmissions = { count: 0 };
    const provider = {
      async publicKeyMetadata() {
        return { key_id: fixture.keyId, algorithm: "ed25519", public_key: fixture.initial.keys[0].public_key };
      },
      async sign() {
        providerAdmissions.count += 1;
        throw new Error("simulated provider response loss after admission");
      }
    };
    const signer = createDurableManagedSignerProvider({
      provider,
      repository: fixture.first,
      purpose: fixture.purpose,
      keyId: fixture.keyId,
      keyVersion: 1,
      publicKey: fixture.initial.keys[0].public_key,
      version: 1
    });
    const bytes = Buffer.from("s1.3-provider-loss");
    const request = signerRequest(fixture, bytes);

    await assert.rejects(signer.sign(request), { code: SIGNER_CODES.PROVIDER });
    assert.equal(providerAdmissions.count, 1);
    const uncertain = await fixture.second.lookupSignature(lookupInput(fixture, request));
    assert.equal(uncertain.state, "uncertain");
    assert.match(uncertain.provider_started_at, /^\d{4}-\d{2}-\d{2}T/u);

    await assert.rejects(signer.sign(request), { code: SIGNER_CODES.UNCERTAIN });
    const independentSigner = createDurableManagedSignerProvider({
      provider,
      repository: fixture.second,
      purpose: fixture.purpose,
      keyId: fixture.keyId,
      keyVersion: 1,
      publicKey: fixture.initial.keys[0].public_key,
      version: 1
    });
    await assert.rejects(independentSigner.sign(request), { code: SIGNER_CODES.UNCERTAIN });
    assert.equal(providerAdmissions.count, 1, "uncertain operations must never re-enter the provider boundary");
  });
});

test("S1.3 PostgreSQL qualification: lifecycle rollback is atomic and purpose-scoped", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run S1.3 PostgreSQL qualification",
  timeout: 120_000
}, async (t) => {
  await withFixture(t, "isolation", async (fixture) => {
    const otherPurpose = `${fixture.purpose}.other`;
    fixture.purposes.push(otherPurpose);
    const otherKeyPair = crypto.generateKeyPairSync("ed25519");
    const otherKeyId = "shared-purpose-key-1";
    const otherInitial = snapshotFor({
      purpose: otherPurpose,
      keyId: otherKeyId,
      pair: otherKeyPair,
      keyVersion: 1
    });
    const otherFirst = createPostgresManagedSignerKeyLifecycleRepository({ client: fixture.firstPool, purpose: otherPurpose });
    const otherSecond = createPostgresManagedSignerKeyLifecycleRepository({ client: fixture.secondPool, purpose: otherPurpose });
    assert.deepEqual(await otherFirst.initialize({ snapshot: otherInitial }), otherInitial);

    const sharedBytes = Buffer.from("s1.3-purpose-isolation");
    const firstRequest = {
      operation_id: "same-operation-id",
      request_digest: canonicalManagedSignerRequestDigest({ purpose: fixture.purpose, key_id: fixture.keyId, bytes: sharedBytes }),
      key_id: fixture.keyId,
      key_version: 1
    };
    const otherRequest = {
      operation_id: "same-operation-id",
      request_digest: canonicalManagedSignerRequestDigest({ purpose: otherPurpose, key_id: otherKeyId, bytes: sharedBytes }),
      key_id: otherKeyId,
      key_version: 1
    };
    const otherClaim = await otherFirst.reserveSignature(otherRequest);
    assert.equal(otherClaim.state, "pending");
    const firstClaim = await fixture.first.reserveSignature(firstRequest);
    assert.equal(firstClaim.state, "pending");

    const secondKeyPair = crypto.generateKeyPairSync("ed25519");
    const race = await Promise.allSettled([
      fixture.first.rotate({
        expected_version: 1,
        operation_id: "s13-rollback-rotate",
        new_key: keyRecord(fixture.purpose, "rollback-key-2", 2, secondKeyPair),
        verification_until: futureVerificationUntil()
      }),
      fixture.second.emergencyDisable({
        expected_version: 1,
        operation_id: "s13-rollback-disable"
      })
    ]);
    assert.equal(race.filter(({ status }) => status === "fulfilled").length, 1);
    assert.equal(race.filter(({ status }) => status === "rejected").length, 1);

    const reduced = await fixture.first.snapshot();
    assert.equal(reduced.version, 2);
    assert.ok(
      reduced.keys.every((key) => key.state === EMERGENCY_DISABLED)
        || (reduced.keys.length === 2 && reduced.keys[0].state === RETIRING && reduced.keys[1].state === ACTIVE),
      "a losing lifecycle transaction must not leave a partially applied snapshot"
    );
    const lifecycleOperations = await fixture.firstPool.query(
      "SELECT operation_id FROM managed_signer_key_lifecycle_operations WHERE purpose=$1 ORDER BY operation_id",
      [fixture.purpose]
    );
    assert.equal(lifecycleOperations.rowCount, 1, "the losing lifecycle mutation must roll back its operation record");

    const otherSnapshot = await otherSecond.snapshot();
    assert.equal(otherSnapshot.version, 1);
    assert.equal(otherSnapshot.keys[0].state, ACTIVE);
    const otherSignature = crypto.sign(null, sharedBytes, otherKeyPair.privateKey);
    const committed = await otherSecond.commitSignature({
      ...otherRequest,
      claim_token: otherClaim.claim_token,
      signature: otherSignature
    });
    assert.equal(committed.state, "committed");
    assert.deepEqual((await otherFirst.reserveSignature(otherRequest)).signature, otherSignature);
    assert.equal(
      (await fixture.first.lookupSignature({
        operation_id: firstRequest.operation_id,
        request_digest: firstRequest.request_digest
      })).state,
      "pending",
      "purpose A state must remain independent from purpose B completion"
    );
  });
});

async function withFixture(t, label, operation) {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 4, connectionTimeoutMillis: 2_000 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 4, connectionTimeoutMillis: 2_000 });
  const purpose = `agentpass.s13.${label}.${process.pid}.${crypto.randomBytes(5).toString("hex")}`;
  const purposes = [purpose];
  t.after(async () => {
    for (const scopedPurpose of purposes) {
      await firstPool.query("DELETE FROM managed_signer_signing_idempotency WHERE purpose=$1", [scopedPurpose]);
      await firstPool.query("DELETE FROM managed_signer_key_lifecycle_operations WHERE purpose=$1", [scopedPurpose]);
      await firstPool.query("DELETE FROM managed_signer_keys WHERE purpose=$1", [scopedPurpose]);
      await firstPool.query("DELETE FROM managed_signer_key_lifecycles WHERE purpose=$1", [scopedPurpose]);
    }
    await Promise.all([firstPool.end(), secondPool.end()]);
  });

  await ensureSchema(firstPool);
  const firstPid = await backendPid(firstPool);
  const secondPid = await backendPid(secondPool);
  assert.notEqual(firstPid, secondPid, "the qualification must use independent PostgreSQL sessions");

  const keyPair = crypto.generateKeyPairSync("ed25519");
  const keyId = "s13-key-1";
  const initial = snapshotFor({ purpose, keyId, pair: keyPair, keyVersion: 1 });
  const nextPair = crypto.generateKeyPairSync("ed25519");
  const nextKey = keyRecord(purpose, "s13-key-2", 2, nextPair);
  const first = createPostgresManagedSignerKeyLifecycleRepository({ client: firstPool, purpose });
  const second = createPostgresManagedSignerKeyLifecycleRepository({ client: secondPool, purpose });
  assert.deepEqual(await first.initialize({ snapshot: initial }), initial);
  assert.deepEqual(await second.snapshot(), initial);
  await operation({ firstPool, secondPool, first, second, purpose, purposes, keyPair, keyId, initial, nextKey });
}

async function ensureSchema(pool) {
  migrationReady ??= (async () => {
    const client = await pool.connect();
    try {
      const result = await createMigrationRunner({ client, applicationVersion: "managed-signer-s13-qualification" }).run();
      assert.equal(result.currentVersion, POSTGRES_SCHEMA_HEAD.version);
    } finally {
      client.release();
    }
  })();
  await migrationReady;
}

async function backendPid(pool) {
  const client = await pool.connect();
  try {
    return (await client.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
  } finally {
    client.release();
  }
}

function snapshotFor({ purpose, keyId, pair, keyVersion }) {
  return {
    version: 1,
    purpose,
    algorithm: "ed25519",
    keys: [keyRecord(purpose, keyId, keyVersion, pair)]
  };
}

function keyRecord(purpose, keyId, keyVersion, pair, state = ACTIVE, stateVersion = 1) {
  const publicKeyDer = pair.publicKey.export({ type: "spki", format: "der" });
  return {
    key_id: keyId,
    key_version: keyVersion,
    purpose,
    algorithm: "ed25519",
    public_key: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    public_key_fingerprint: crypto.createHash("sha256").update(publicKeyDer).digest("hex"),
    state,
    state_version: stateVersion
  };
}

function signerRequest(fixture, bytes) {
  return {
    algorithm: "ed25519",
    bytes,
    key_id: fixture.keyId,
    purpose: fixture.purpose,
    version: 1
  };
}

function lookupInput(fixture, request) {
  return {
    purpose: fixture.purpose,
    operation_id: `managed-signer-v1-${requestDigest(fixture, request)}`,
    request_digest: requestDigest(fixture, request)
  };
}

function requestDigest(fixture, request) {
  return canonicalManagedSignerRequestDigest({
    algorithm: request.algorithm,
    bytes: request.bytes,
    key_id: fixture.keyId,
    purpose: fixture.purpose,
    version: request.version,
    key_version: 1
  });
}

function createProvider({ pair, publicKey, keyId, admissions }) {
  return {
    async publicKeyMetadata() {
      return { key_id: keyId, algorithm: "ed25519", public_key: publicKey };
    },
    async sign({ bytes }) {
      admissions.count += 1;
      return crypto.sign(null, bytes, pair.privateKey);
    }
  };
}

async function reserveReductionRace(t, label, reduction) {
  await withFixture(t, label, async (fixture) => {
    const bytes = Buffer.from(`s1.3-${label}`);
    const requestDigest = canonicalManagedSignerRequestDigest({
      purpose: fixture.purpose,
      key_id: fixture.keyId,
      bytes
    });
    const request = {
      operation_id: `s13-${label}`,
      request_digest: requestDigest,
      key_id: fixture.keyId,
      key_version: 1
    };
    const reductionPromise = reduction === "rotate"
      ? fixture.second.rotate({
        expected_version: 1,
        operation_id: `s13-${label}-lifecycle`,
        new_key: fixture.nextKey,
        verification_until: futureVerificationUntil()
      })
      : fixture.second.emergencyDisable({
        expected_version: 1,
        operation_id: `s13-${label}-lifecycle`
      });
    const [reservation, lifecycle] = await Promise.allSettled([
      fixture.first.reserveSignature(request),
      reductionPromise
    ]);
    assert.equal(lifecycle.status, "fulfilled");
    assert.equal(lifecycle.value.version, 2);
    if (reservation.status === "fulfilled") {
      assert.equal(reservation.value.state, "pending");
      await fixture.first.markSignatureUncertain({ ...request, claim_token: reservation.value.claim_token });
      assert.equal((await fixture.second.lookupSignature({
        purpose: fixture.purpose,
        operation_id: request.operation_id,
        request_digest: request.request_digest
      })).state, "uncertain");
    } else {
      assert.deepEqual(await fixture.second.lookupSignature({
        purpose: fixture.purpose,
        operation_id: request.operation_id,
        request_digest: request.request_digest
      }), {
        state: "absent",
        purpose: fixture.purpose,
        operation_id: request.operation_id
      });
    }
  });
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function withTimeout(promise, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), 10_000);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function futureVerificationUntil() {
  return new Date(Date.now() + 60_000).toISOString();
}
