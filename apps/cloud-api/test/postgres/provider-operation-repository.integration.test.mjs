import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { SIGNER_PROTOCOL_VERSIONS } from "../../src/managed-signer-provider-contract.mjs";
import { createDurableManagedSignerProvider } from "../../src/durable-managed-signer-provider.mjs";
import { createProviderOperationReconciliationAdapter } from "../../src/provider-operation-reconciliation-adapter.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import {
  canonicalManagedSignerRequestDigest,
  createPostgresManagedSignerKeyLifecycleRepository,
} from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";
import { createPostgresProviderOperationRepository } from "../../src/postgres/provider-operation-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("0041 converges two PostgreSQL-backed adapter instances and recovers a started operation", {
  skip: !DATABASE_URL,
  timeout: 60_000,
}, async (t) => {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const purpose = "agentpass.capability";
  const keyId = "provider-operation-integration-key";
  const keyVersion = "1";
  const suffix = `${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  t.after(async () => {
    await firstPool.query("DELETE FROM managed_signer_provider_operations WHERE purpose=$1 AND operation_id LIKE $2", [purpose, `%${suffix}`]);
    await Promise.all([firstPool.end(), secondPool.end()]);
  });

  const migrationClient = await firstPool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "provider-operation-integration" }).run();
    assert.equal(migrated.currentVersion, 41);
  } finally {
    migrationClient.release();
  }

  const firstRepository = createPostgresProviderOperationRepository({ client: firstPool, purpose, keyId, keyVersion });
  const secondRepository = createPostgresProviderOperationRepository({ client: secondPool, purpose, keyId, keyVersion });
  const keys = crypto.generateKeyPairSync("ed25519");
  let signCalls = 0;
  let releaseProvider;
  let providerStarted;
  const started = new Promise((resolve) => { providerStarted = resolve; });
  const provider = {
    provider_id: "integration-kms-ledger-v1",
    purpose,
    key_id: keyId,
    algorithm: "ed25519",
    version: SIGNER_PROTOCOL_VERSIONS[purpose],
    async publicKeyMetadata() { return { key_id: keyId, algorithm: "ed25519", public_key: keys.publicKey }; },
    async sign({ bytes }) {
      signCalls += 1;
      if (signCalls === 1) {
        providerStarted();
        await new Promise((resolve) => { releaseProvider = resolve; });
      }
      return crypto.sign(null, bytes, keys.privateKey);
    },
  };
  const adapter = (repository) => createProviderOperationReconciliationAdapter({
    provider, providerId: "integration-kms-ledger-v1", repository, purpose, keyId, keyVersion, waitTimeoutMs: 1_000,
  });
  const signingBytes = Buffer.from(`two-instance-provider-operation:${suffix}`);
  const binding = bindingFor({ purpose, keyId, keyVersion, suffix, signingBytes, prefix: "race" });
  const first = adapter(firstRepository).signOnce(binding, signingBytes);
  await started;
  const second = adapter(secondRepository).signOnce(binding, signingBytes);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(signCalls, 1);
  releaseProvider();
  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.deepEqual(secondResult, firstResult);
  assert.equal(signCalls, 1);

  const recoveryBytes = Buffer.from(`started-provider-operation:${suffix}`);
  const recoveryBinding = bindingFor({ purpose, keyId, keyVersion, suffix, signingBytes: recoveryBytes, prefix: "recover" });
  const operation = operationFrom(recoveryBinding, recoveryBytes);
  const reserved = await firstRepository.reserveOperation(operation);
  await firstRepository.startOperation({ ...operation, claim_token: reserved.claim_token });
  await firstRepository.markUncertain({
    ...operation,
    claim_token: reserved.claim_token,
    uncertain_reason: "process_interrupted",
  });
  const recovered = await adapter(secondRepository).lookup(recoveryBinding, recoveryBytes);
  assert.equal(recovered.state, "committed");
  assert.equal(signCalls, 2);
  assert.equal((await firstRepository.getOperation(operation)).state, "committed");
});

test("0041 quarantines only expired started operations with bounded two-pool maintenance", {
  skip: !DATABASE_URL,
  timeout: 60_000,
}, async (t) => {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const suffix = `${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
  const purpose = `agentpass.maintenance.${suffix}`;
  const keyId = `maintenance-key-${suffix}`;
  const keyVersion = "1";
  const boundedIds = ["bounded-001", "bounded-002"];
  const lockedIds = ["locked-001", "locked-002", "locked-003"];
  const terminalIds = ["terminal-failed", "terminal-rejected"];
  const pendingId = "pending-expired";
  const activeId = "started-active";
  const existingUncertainId = "uncertain-existing";
  const markedUncertainId = "uncertain-marked";
  // This is intentionally far older than ordinary stale rows so the
  // deployment-wide bounded function selects this fixture first.
  const expiredClaim = new Date("2000-01-01T00:00:00.000Z");
  const activeClaim = new Date(Date.now() + 120_000);

  t.after(async () => {
    await firstPool.query("DELETE FROM managed_signer_provider_operations WHERE purpose=$1", [purpose]);
    await Promise.all([firstPool.end(), secondPool.end()]);
  });

  const migrationClient = await firstPool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "provider-operation-maintenance-integration" }).run();
    assert.equal(migrated.currentVersion, 41);
  } finally {
    migrationClient.release();
  }

  for (const operationId of [...boundedIds, ...lockedIds]) {
    await insertProviderOperationFixture(firstPool, {
      purpose, operationId, keyId, keyVersion, state: "started", claimExpiresAt: expiredClaim,
      providerStartedAt: new Date(Date.now() - 180_000),
    });
  }
  await insertProviderOperationFixture(firstPool, {
    purpose, operationId: pendingId, keyId, keyVersion, state: "pending", claimExpiresAt: expiredClaim,
  });
  await insertProviderOperationFixture(firstPool, {
    purpose, operationId: activeId, keyId, keyVersion, state: "started", claimExpiresAt: activeClaim,
    providerStartedAt: new Date(Date.now() - 1_000),
  });
  await insertProviderOperationFixture(firstPool, {
    purpose, operationId: existingUncertainId, keyId, keyVersion, state: "uncertain",
    uncertainReason: "provider_timeout", providerStartedAt: new Date(Date.now() - 180_000),
  });
  for (const state of ["failed", "rejected"]) {
    await insertProviderOperationFixture(firstPool, {
      purpose, operationId: state === "failed" ? terminalIds[0] : terminalIds[1], keyId, keyVersion, state,
      providerStartedAt: new Date(Date.now() - 180_000), expiresAt: new Date(Date.now() - 60_000),
    });
  }

  const terminalBefore = await selectProviderOperationMaintenanceRows(firstPool, purpose, terminalIds);
  const nonQuarantineBefore = await selectProviderOperationMaintenanceRows(firstPool, purpose, [
    pendingId, activeId, existingUncertainId,
  ]);
  const bounded = await quarantineExpiredProviderOperations(firstPool, 2);
  assert.equal(bounded, 2, "the first maintenance invocation must honor its batch bound");

  const afterBounded = await selectProviderOperationMaintenanceRows(firstPool, purpose, [
    ...boundedIds, ...lockedIds, pendingId, activeId, existingUncertainId,
  ]);
  const afterBoundedById = new Map(afterBounded.map((row) => [row.operation_id, row]));
  for (const operationId of boundedIds) {
    assert.equal(afterBoundedById.get(operationId).state, "uncertain");
    assert.equal(afterBoundedById.get(operationId).uncertain_reason, "claim_expired_after_start");
    assert.equal(afterBoundedById.get(operationId).claim_token_digest, null);
    assert.equal(afterBoundedById.get(operationId).claim_expires_at, null);
  }
  for (const operationId of lockedIds) assert.equal(afterBoundedById.get(operationId).state, "started");
  assert.equal(afterBoundedById.get(pendingId).state, "pending", "expired pending work must not cross the provider boundary");
  assert.equal(afterBoundedById.get(pendingId).uncertain_reason, null);
  assert.ok(afterBoundedById.get(pendingId).claim_token_digest, "expired pending work must retain its claim");
  assert.ok(afterBoundedById.get(pendingId).claim_expires_at.getTime() < Date.now());
  assert.equal(afterBoundedById.get(activeId).state, "started", "an active claim must not be quarantined");
  assert.ok(afterBoundedById.get(activeId).claim_expires_at.getTime() > Date.now());
  assert.equal(afterBoundedById.get(existingUncertainId).state, "uncertain");
  assert.equal(afterBoundedById.get(existingUncertainId).uncertain_reason, "provider_timeout");
  const nonQuarantineBeforeById = new Map(nonQuarantineBefore.map((row) => [row.operation_id, row]));
  for (const operationId of [pendingId, activeId, existingUncertainId]) {
    assert.deepEqual(afterBoundedById.get(operationId), nonQuarantineBeforeById.get(operationId));
  }

  const lockClient = await firstPool.connect();
  try {
    await lockClient.query("BEGIN");
    await lockClient.query(
      "SELECT operation_id FROM managed_signer_provider_operations WHERE purpose=$1 AND operation_id=$2 FOR UPDATE",
      [purpose, lockedIds[0]],
    );
    const skippedLocked = await quarantineExpiredProviderOperations(secondPool, 2);
    assert.equal(skippedLocked, 2, "the second pool must process the two unlocked rows without waiting on the lock");
    const whileLocked = await selectProviderOperationMaintenanceRows(secondPool, purpose, lockedIds);
    const whileLockedById = new Map(whileLocked.map((row) => [row.operation_id, row]));
    assert.equal(whileLockedById.get(lockedIds[0]).state, "started", "the row locked by pool one must be skipped");
    for (const operationId of lockedIds.slice(1)) {
      assert.equal(whileLockedById.get(operationId).state, "uncertain");
      assert.equal(whileLockedById.get(operationId).uncertain_reason, "claim_expired_after_start");
    }
  } finally {
    await lockClient.query("ROLLBACK");
    lockClient.release();
  }

  const released = await quarantineExpiredProviderOperations(firstPool, 2);
  assert.equal(released, 1, "the released row must be quarantined exactly once");
  const afterReleased = await selectProviderOperationMaintenanceRows(firstPool, purpose, lockedIds);
  assert.equal(afterReleased.filter((row) => row.state === "uncertain").length, 3);
  assert.deepEqual(new Set(afterReleased.map((row) => row.uncertain_reason)), new Set(["claim_expired_after_start"]));

  const markedRepository = createPostgresProviderOperationRepository({
    client: firstPool, purpose, keyId: `${keyId}-mark`, keyVersion,
  });
  const markedOperation = maintenanceOperation({
    purpose, keyId: `${keyId}-mark`, operationId: markedUncertainId,
    bytes: Buffer.from(`mark-uncertain:${suffix}`),
  });
  const reserved = await markedRepository.reserveOperation(markedOperation);
  const started = await markedRepository.startOperation({ ...markedOperation, claim_token: reserved.claim_token });
  const marked = await markedRepository.markUncertain({
    ...markedOperation,
    claim_token: started.claim_token,
    uncertain_reason: "process_interrupted",
  });
  assert.deepEqual(
    { state: marked.state, uncertain_reason: marked.uncertain_reason },
    { state: "uncertain", uncertain_reason: "process_interrupted" },
    "markUncertain must persist the closed uncertain_reason vocabulary",
  );

  const terminalAfter = await selectProviderOperationMaintenanceRows(firstPool, purpose, terminalIds);
  assert.deepEqual(terminalAfter, terminalBefore, "maintenance must not mutate terminal rows");
});

test("0041 converges 100 identical requests across two PostgreSQL pools", {
  skip: !DATABASE_URL,
  timeout: 60_000,
}, async (t) => {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const suffix = `${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
  // The managed-signer binding contract accepts only registered purposes;
  // key and operation identifiers remain unique to this qualification run.
  const purpose = "agentpass.capability";
  const keyId = `convergence-key-${suffix}`;
  const keyVersion = "1";
  const keys = crypto.generateKeyPairSync("ed25519");
  let providerCalls = 0;
  let releaseProvider;
  let providerStarted;
  const providerHasStarted = new Promise((resolve) => { providerStarted = resolve; });
  const provider = {
    purpose,
    key_id: keyId,
    key_version: keyVersion,
    algorithm: "ed25519",
    version: SIGNER_PROTOCOL_VERSIONS[purpose],
    async publicKeyMetadata() {
      return { algorithm: "ed25519", key_id: keyId, public_key: keys.publicKey };
    },
    async sign({ bytes }) {
      providerCalls += 1;
      if (providerCalls === 1) {
        providerStarted();
        await new Promise((resolve) => { releaseProvider = resolve; });
      }
      return crypto.sign(null, bytes, keys.privateKey);
    },
  };
  t.after(async () => {
    await firstPool.query("DELETE FROM managed_signer_provider_operations WHERE purpose=$1 AND key_id=$2", [purpose, keyId]);
    await Promise.all([firstPool.end(), secondPool.end()]);
  });

  const migrationClient = await firstPool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "provider-operation-convergence-integration" }).run();
    assert.equal(migrated.currentVersion, 41);
  } finally {
    migrationClient.release();
  }

  const repositories = [
    createPostgresProviderOperationRepository({
      client: firstPool, purpose, keyId, keyVersion,
    }),
    createPostgresProviderOperationRepository({
      client: secondPool, purpose, keyId, keyVersion,
    }),
  ];
  const adapters = Array.from({ length: 100 }, (_, index) => createProviderOperationReconciliationAdapter({
    provider,
    providerId: `convergence-provider-${suffix}`,
    repository: repositories[index % repositories.length],
    purpose,
    keyId,
    keyVersion,
    publicKey: keys.publicKey,
    waitTimeoutMs: 1_000,
    maxRecoveryAttempts: 2,
  }));
  const signingBytes = Buffer.from(`100-identical-requests:${suffix}`);
  const binding = bindingFor({ purpose, keyId, keyVersion, suffix, signingBytes, prefix: "concurrent" });
  const requests = adapters.map((adapter) => adapter.signOnce(binding, signingBytes));
  await providerHasStarted;
  await new Promise((resolve) => setImmediate(resolve));
  releaseProvider();
  const results = await Promise.all(requests);

  assert.equal(providerCalls, 1, "only one concurrent claimant may cross the provider boundary");
  assert.equal(new Set(results.map((result) => result.signature.value)).size, 1);
  assert.equal(new Set(results.map((result) => result.provider_receipt.receipt_id)).size, 1);
  const operation = operationFrom(binding, signingBytes);
  const persisted = await repositories[0].getOperation(operation);
  assert.equal(persisted.state, "committed");
  const count = await firstPool.query(
    "SELECT count(*)::integer AS count FROM managed_signer_provider_operations WHERE purpose=$1 AND key_id=$2",
    [purpose, keyId],
  );
  assert.equal(count.rows[0].count, 1);
});

test("0041 composes with lifecycle fencing across lost commits and emergency disable", {
  skip: !DATABASE_URL,
  timeout: 60_000,
}, async (t) => {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const purpose = "agentpass.audit-anchor";
  const suffix = `${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  const keyId = `c1-composed-key-${suffix}`;
  const keyVersion = "1";
  const protocolVersion = SIGNER_PROTOCOL_VERSIONS[purpose];
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = crypto.createHash("sha256").update(keys.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  t.after(async () => {
    await firstPool.query("DELETE FROM managed_signer_provider_operations WHERE purpose=$1", [purpose]);
    await firstPool.query("DELETE FROM managed_signer_signing_idempotency WHERE purpose=$1", [purpose]);
    await firstPool.query("DELETE FROM managed_signer_key_lifecycle_operations WHERE purpose=$1", [purpose]);
    await firstPool.query("DELETE FROM managed_signer_keys WHERE purpose=$1", [purpose]);
    await firstPool.query("DELETE FROM managed_signer_key_lifecycles WHERE purpose=$1", [purpose]);
    await Promise.all([firstPool.end(), secondPool.end()]);
  });

  const migrationClient = await firstPool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "provider-operation-composed-integration" }).run();
    assert.equal(migrated.currentVersion, 41);
  } finally {
    migrationClient.release();
  }
  await firstPool.query("DELETE FROM managed_signer_provider_operations WHERE purpose=$1", [purpose]);
  await firstPool.query("DELETE FROM managed_signer_signing_idempotency WHERE purpose=$1", [purpose]);
  await firstPool.query("DELETE FROM managed_signer_key_lifecycle_operations WHERE purpose=$1", [purpose]);
  await firstPool.query("DELETE FROM managed_signer_keys WHERE purpose=$1", [purpose]);
  await firstPool.query("DELETE FROM managed_signer_key_lifecycles WHERE purpose=$1", [purpose]);

  const lifecycleOne = createPostgresManagedSignerKeyLifecycleRepository({ client: firstPool, purpose });
  const lifecycleTwo = createPostgresManagedSignerKeyLifecycleRepository({ client: secondPool, purpose });
  await lifecycleOne.initialize({ snapshot: {
    version: 1,
    purpose,
    algorithm: "ed25519",
    keys: [{
      key_id: keyId,
      key_version: 1,
      purpose,
      algorithm: "ed25519",
      public_key_fingerprint: fingerprint,
      public_key: publicKey,
      state: "active",
      state_version: 1,
    }],
  } });

  let providerCalls = 0;
  const provider = {
    provider_id: "c1-composed-kms-ledger-v1",
    purpose,
    key_id: keyId,
    key_version: keyVersion,
    algorithm: "ed25519",
    version: protocolVersion,
    async publicKeyMetadata() { return { key_id: keyId, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { providerCalls += 1; return crypto.sign(null, bytes, keys.privateKey); },
  };
  const lowOne = createPostgresProviderOperationRepository({ client: firstPool, purpose, keyId, keyVersion });
  const lowTwo = createPostgresProviderOperationRepository({ client: secondPool, purpose, keyId, keyVersion });
  const adapter = (repository) => createProviderOperationReconciliationAdapter({
    provider, providerId: provider.provider_id, repository, purpose, keyId, keyVersion, waitTimeoutMs: 1_000,
  });
  const signer = (repository, managedSignerAdapter) => createDurableManagedSignerProvider({
    provider, managedSignerAdapter, repository, purpose, keyId, keyVersion: 1,
    version: protocolVersion, protocolVersion,
  });

  let loseLowCommit = true;
  const lowCommitLoss = delegateProviderRepository(lowOne, {
    async commitOperation(input) {
      const committed = await lowOne.commitOperation(input);
      if (loseLowCommit) { loseLowCommit = false; throw new Error("lost low-level COMMIT response"); }
      return committed;
    },
  });
  const lowLossBytes = Buffer.from(`low-commit-loss:${suffix}`);
  const lowLossRequest = signRequest({ purpose, keyId, protocolVersion, bytes: lowLossBytes });
  await assert.rejects(signer(lifecycleOne, adapter(lowCommitLoss)).sign(lowLossRequest), { code: "ERR_DURABLE_MANAGED_SIGNER_PROVIDER" });
  const lowLossOperation = operationForDurableRequest({ purpose, keyId, keyVersion, protocolVersion, bytes: lowLossBytes });
  assert.equal((await lowTwo.getOperation(lowLossOperation.provider)).state, "committed");
  assert.equal((await lifecycleTwo.lookupSignature(lowLossOperation.lifecycle)).state, "uncertain");
  assert.equal((await adapter(lowTwo).lookup(bindingFromOperation(lowLossOperation.provider, protocolVersion), lowLossBytes)).state, "committed");
  const recoveredLow = await signer(lifecycleTwo, adapter(lowTwo)).sign(lowLossRequest);
  assert.equal(crypto.verify(null, lowLossBytes, keys.publicKey, recoveredLow), true);
  assert.equal(providerCalls, 1, "a lost low-level COMMIT response must reconcile without another provider call");

  let loseHighCommit = true;
  const highCommitLoss = delegateLifecycleRepository(lifecycleOne, {
    async commitSignature(input) {
      const committed = await lifecycleOne.commitSignature(input);
      if (loseHighCommit) { loseHighCommit = false; throw new Error("lost high-level COMMIT response"); }
      return committed;
    },
  });
  const highLossBytes = Buffer.from(`high-commit-loss:${suffix}`);
  const highLossRequest = signRequest({ purpose, keyId, protocolVersion, bytes: highLossBytes });
  await assert.rejects(signer(highCommitLoss, adapter(lowOne)).sign(highLossRequest), { code: "ERR_DURABLE_MANAGED_SIGNER_COMMIT" });
  const recoveredHigh = await signer(lifecycleTwo, adapter(lowTwo)).sign(highLossRequest);
  assert.equal(crypto.verify(null, highLossBytes, keys.publicKey, recoveredHigh), true);
  assert.equal(providerCalls, 2, "a lost high-level COMMIT response must replay the committed high-level row");

  let releaseAccepted;
  let accepted;
  const acceptedGate = new Promise((resolve) => { accepted = resolve; });
  const gatedBase = adapter(lowOne);
  const gatedAdapter = {
    async signOnce(binding, bytes) {
      const result = await gatedBase.signOnce(binding, bytes);
      accepted();
      await new Promise((resolve) => { releaseAccepted = resolve; });
      return result;
    },
    lookup: (binding, bytes) => gatedBase.lookup(binding, bytes),
  };
  const fencedBytes = Buffer.from(`disable-after-provider-acceptance:${suffix}`);
  const fencedRequest = signRequest({ purpose, keyId, protocolVersion, bytes: fencedBytes });
  const fencedSign = signer(lifecycleOne, gatedAdapter).sign(fencedRequest);
  await acceptedGate;
  await lifecycleTwo.emergencyDisable({ expected_version: 1, operation_id: `disable-${suffix}` });
  releaseAccepted();
  await assert.rejects(fencedSign, { code: "ERR_DURABLE_MANAGED_SIGNER_COMMIT" });
  await assert.rejects(signer(lifecycleTwo, adapter(lowTwo)).sign(fencedRequest), { code: "ERR_DURABLE_MANAGED_SIGNER_COMMIT" });
  assert.equal(providerCalls, 3, "lifecycle fencing may reject a result but must not trigger a blind provider retry");

  const fencedOperation = operationForDurableRequest({ purpose, keyId, keyVersion, protocolVersion, bytes: fencedBytes });
  assert.equal((await lowTwo.getOperation(fencedOperation.provider)).state, "committed");
  assert.equal((await lifecycleTwo.lookupSignature(fencedOperation.lifecycle)).state, "uncertain");
});

function bindingFor({ purpose, keyId, keyVersion, suffix, signingBytes, prefix }) {
  return {
    operation_id: `managed-signer-v1-${prefix}-${suffix}`,
    purpose,
    key_id: keyId,
    key_version: keyVersion,
    algorithm: "ed25519",
    protocol_version: SIGNER_PROTOCOL_VERSIONS[purpose],
    request_digest: { algorithm: "SHA-256", value: crypto.createHash("sha256").update(signingBytes).digest("hex") },
  };
}

async function quarantineExpiredProviderOperations(pool, limit) {
  const result = await pool.query(
    "SELECT agentpass_quarantine_expired_managed_signer_provider_operations($1)::integer AS quarantined",
    [limit],
  );
  assert.equal(result.rowCount, 1);
  return result.rows[0].quarantined;
}

async function insertProviderOperationFixture(pool, {
  purpose,
  operationId,
  keyId,
  keyVersion,
  state,
  claimExpiresAt = null,
  providerStartedAt = null,
  uncertainReason = null,
  createdAt = new Date(Date.now() - 300_000),
  updatedAt = new Date(Date.now() - 300_000),
  expiresAt = new Date(Date.now() + 3_600_000),
} = {}) {
  const requestDigest = crypto.createHash("sha256").update(`${purpose}\0${operationId}`).digest();
  const claimTokenDigest = ["pending", "started"].includes(state) ? crypto.randomBytes(32) : null;
  await pool.query(`INSERT INTO managed_signer_provider_operations
    (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
     claim_token_digest,claim_expires_at,provider_started_at,uncertain_reason,
     signature,public_key_der,provider_receipt_provider,provider_receipt_id,
     created_at,updated_at,expires_at)
    VALUES ($1,$2,'ed25519',1,$3,$4,$5,$6,$7,$8,$9,$10,NULL,NULL,NULL,NULL,$11,$12,$13)`, [
    purpose, operationId, requestDigest, keyId, keyVersion, state, claimTokenDigest,
    claimExpiresAt, providerStartedAt, uncertainReason, createdAt, updatedAt, expiresAt,
  ]);
}

async function selectProviderOperationMaintenanceRows(pool, purpose, operationIds) {
  const result = await pool.query(`SELECT operation_id,state,uncertain_reason,claim_token_digest,
      claim_expires_at,provider_started_at,signature,public_key_der,
      provider_receipt_provider,provider_receipt_id,created_at,updated_at,expires_at
    FROM managed_signer_provider_operations
    WHERE purpose=$1 AND operation_id=ANY($2::text[])
    ORDER BY operation_id`, [purpose, operationIds]);
  assert.equal(result.rowCount, operationIds.length);
  return result.rows;
}

function maintenanceOperation({ purpose, keyId, operationId, bytes }) {
  return {
    algorithm: "ed25519",
    bytes_length: bytes.length,
    key_id: keyId,
    key_version: "1",
    operation_id: operationId,
    purpose,
    request_digest: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

function operationFrom(binding, signingBytes) {
  return {
    algorithm: binding.algorithm,
    bytes_length: signingBytes.length,
    key_id: binding.key_id,
    key_version: binding.key_version,
    operation_id: binding.operation_id,
    purpose: binding.purpose,
    request_digest: binding.request_digest.value,
  };
}

function signRequest({ purpose, keyId, protocolVersion, bytes }) {
  return { algorithm: "ed25519", bytes, key_id: keyId, purpose, version: protocolVersion };
}

function operationForDurableRequest({ purpose, keyId, keyVersion, protocolVersion, bytes }) {
  const requestDigest = canonicalManagedSignerRequestDigest({
    algorithm: "ed25519", bytes, key_id: keyId, purpose, version: protocolVersion, key_version: Number(keyVersion),
  });
  const operationId = `managed-signer-v1-${requestDigest}`;
  return Object.freeze({ provider: {
    algorithm: "ed25519",
    bytes_length: bytes.length,
    key_id: keyId,
    key_version: keyVersion,
    operation_id: operationId,
    purpose,
    request_digest: crypto.createHash("sha256").update(bytes).digest("hex"),
  }, lifecycle: {
    operation_id: operationId,
    request_digest: requestDigest,
    key_id: keyId,
    key_version: Number(keyVersion),
  } });
}

function bindingFromOperation(operation, protocolVersion) {
  return {
    operation_id: operation.operation_id,
    purpose: operation.purpose,
    key_id: operation.key_id,
    key_version: operation.key_version,
    algorithm: operation.algorithm,
    protocol_version: protocolVersion,
    request_digest: { algorithm: "SHA-256", value: operation.request_digest },
  };
}

function delegateProviderRepository(repository, overrides = {}) {
  return Object.freeze(Object.fromEntries([
    "reserveOperation", "claimOperation", "startOperation", "recordAccepted", "commitOperation",
    "reconcileOperation", "markUncertain", "getOperation", "waitForOperation",
  ].map((method) => [method, overrides[method] ?? ((...args) => repository[method](...args))])));
}

function delegateLifecycleRepository(repository, overrides = {}) {
  return Object.freeze(Object.fromEntries([
    "snapshot", "reserveSignature", "startSignature", "commitSignature", "markSignatureUncertain", "reconcileSignature",
  ].map((method) => [method, overrides[method] ?? ((...args) => repository[method](...args))])));
}
