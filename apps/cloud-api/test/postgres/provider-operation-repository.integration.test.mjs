import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { SIGNER_PROTOCOL_VERSIONS } from "../../src/managed-signer-provider-contract.mjs";
import { createProviderOperationReconciliationAdapter } from "../../src/provider-operation-reconciliation-adapter.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresProviderOperationRepository } from "../../src/postgres/provider-operation-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("0040 converges two PostgreSQL-backed adapter instances and recovers a started operation", {
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
    assert.equal(migrated.currentVersion, 40);
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
  await firstRepository.markUncertain({ ...operation, claim_token: reserved.claim_token });
  const recovered = await adapter(secondRepository).lookup(recoveryBinding, recoveryBytes);
  assert.equal(recovered.state, "committed");
  assert.equal(signCalls, 2);
  assert.equal((await firstRepository.getOperation(operation)).state, "committed");
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
