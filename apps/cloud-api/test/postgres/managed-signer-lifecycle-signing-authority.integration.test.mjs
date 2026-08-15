import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import {
  createPostgresManagedSignerKeyLifecycleRepository,
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES,
} from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const ROLES_SQL_PATH = path.join(REPOSITORY_ROOT, "scripts/postgres/roles.sql");
const SQLSTATE_PERMISSION_DENIED = new Set(["42501", "0LP01"]);

function applyRoles(rawUrl) {
  const parsed = new URL(rawUrl);
  const {
    AGENTPASS_DATABASE_URL: _databaseUrl,
    AGENTPASS_TEST_DATABASE_URL: _testDatabaseUrl,
    AGENTPASS_TEST_POSTGRES_URL: _testPostgresUrl,
    DATABASE_URL: _genericDatabaseUrl,
    ...inherited
  } = process.env;
  const result = spawnSync("psql", ["--no-psqlrc", "--quiet", "--set=ON_ERROR_STOP=1", "--file", ROLES_SQL_PATH], {
    encoding: "utf8",
    env: {
      ...inherited,
      PGHOST: parsed.hostname,
      PGPORT: parsed.port || "5432",
      PGUSER: decodeURIComponent(parsed.username),
      PGPASSWORD: decodeURIComponent(parsed.password),
      PGDATABASE: decodeURIComponent(parsed.pathname.slice(1)),
      PGSSLMODE: parsed.searchParams.get("sslmode") ?? "disable",
    },
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.error, undefined, "psql role reconciliation could not start");
  assert.equal(result.status, 0, "psql role reconciliation failed");
}

async function authorizeSigner(pool) {
  const client = await pool.connect();
  await client.query("SET SESSION AUTHORIZATION agentpass_signer");
  return client;
}

async function expectPermissionDenied(operation) {
  await assert.rejects(operation, (error) => SQLSTATE_PERMISSION_DENIED.has(error?.code));
}

test("0051 makes lifecycle and signing function-only for the signer role", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run signer authority qualification",
  timeout: 120_000,
}, async (t) => {
  const adminPool = new Pool({ connectionString: DATABASE_URL, max: 2 });
  const signerPool = new Pool({ connectionString: DATABASE_URL, max: 2 });
  const purpose = `agentpass.lifecycle-authority.${process.pid}.${crypto.randomBytes(5).toString("hex")}`;
  const epochPurpose = `${purpose}.terminal-epoch`;
  const signerClients = [];

  t.after(async () => {
    for (const client of signerClients) {
      try { await client.query("RESET SESSION AUTHORIZATION"); } catch { /* connection is discarded below */ }
      client.release(true);
    }
    for (const scopedPurpose of [purpose, epochPurpose]) {
      await adminPool.query("DELETE FROM managed_signer_signing_idempotency WHERE purpose=$1", [scopedPurpose]);
      await adminPool.query("DELETE FROM managed_signer_key_lifecycle_operations WHERE purpose=$1", [scopedPurpose]);
      await adminPool.query("DELETE FROM managed_signer_keys WHERE purpose=$1", [scopedPurpose]);
      await adminPool.query("DELETE FROM managed_signer_key_lifecycles WHERE purpose=$1", [scopedPurpose]);
    }
    await Promise.all([adminPool.end(), signerPool.end()]);
  });

  const migrationClient = await adminPool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "managed-signer-authority-qualification" }).run();
    assert.equal(migrated.currentVersion, 51);
  } finally {
    migrationClient.release();
  }
  applyRoles(DATABASE_URL);

  const firstClient = await authorizeSigner(signerPool);
  const secondClient = await authorizeSigner(signerPool);
  signerClients.push(firstClient, secondClient);
  const first = createPostgresManagedSignerKeyLifecycleRepository({ client: firstClient, purpose });
  const second = createPostgresManagedSignerKeyLifecycleRepository({ client: secondClient, purpose });
  const initial = {
    version: 1,
    purpose,
    algorithm: "ed25519",
    keys: [{
      key_id: "authority-key-1",
      key_version: 1,
      purpose,
      algorithm: "ed25519",
      public_key_fingerprint: "a".repeat(64),
      state: "active",
      state_version: 1,
    }],
  };
  assert.deepEqual(await first.initialize({ snapshot: initial }), initial);
  assert.deepEqual(await second.snapshot(), initial);
  assert.deepEqual(await first.lookupSignature({ operation_id: "missing-signature", request_digest: "d".repeat(64) }), {
    state: "absent",
    purpose,
    operation_id: "missing-signature",
  });

  const request = {
    operation_id: "sign-authority-1",
    request_digest: crypto.createHash("sha256").update("authority-signing-request").digest("hex"),
    key_id: "authority-key-1",
    key_version: 1,
  };
  const reserved = await first.reserveSignature(request);
  assert.match(reserved.claim_token, /^[A-Za-z0-9_-]{43}$/u);
  await first.startSignature({ ...request, claim_token: reserved.claim_token });
  assert.equal((await first.markSignatureUncertain({ ...request, claim_token: reserved.claim_token })).state, "uncertain");
  const signature = Buffer.alloc(64, 0x51);
  const receipt = { provider: "authority-kms", receipt_id: "receipt-1", operation_id: request.operation_id, key_id: request.key_id, key_version: 1 };
  const reconciled = await second.reconcileSignature({ ...request, signature, provider_receipt: receipt });
  assert.deepEqual(reconciled.signature, signature);
  assert.deepEqual((await first.reserveSignature(request)).signature, signature);
  await assert.rejects(first.reserveSignature({ ...request, request_digest: "b".repeat(64) }), {
    code: MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT,
  });

  for (const table of [
    "managed_signer_key_lifecycles",
    "managed_signer_keys",
    "managed_signer_key_lifecycle_operations",
    "managed_signer_signing_idempotency",
  ]) {
    const privilege = await firstClient.query(
      "SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE') AS allowed",
      [`public.${table}`],
    );
    assert.equal(privilege.rows[0].allowed, false, `signer retained direct authority on ${table}`);
    await expectPermissionDenied(() => firstClient.query(`SELECT * FROM public.${table} LIMIT 1`));
  }

  const epochRepository = createPostgresManagedSignerKeyLifecycleRepository({ client: firstClient, purpose: epochPurpose });
  const epochInitial = {
    ...initial,
    purpose: epochPurpose,
    keys: initial.keys.map((key) => ({ ...key, purpose: epochPurpose, key_id: "epoch-key-1" })),
  };
  await epochRepository.initialize({ snapshot: epochInitial });
  await epochRepository.rotate({
    expected_version: 1,
    operation_id: "epoch-rotate",
    new_key: {
      key_id: "epoch-key-2",
      key_version: 2,
      purpose: epochPurpose,
      algorithm: "ed25519",
      public_key_fingerprint: "c".repeat(64),
      state: "active",
      state_version: 1,
    },
    verification_until: new Date(Date.now() + 60_000).toISOString(),
  });
  await epochRepository.transitionKey({
    expected_version: 2,
    operation_id: "epoch-disable-one",
    key_id: "epoch-key-1",
    to: "emergency-disabled",
  });
  const epochDisabled = await epochRepository.emergencyDisable({ expected_version: 3, operation_id: "epoch-disable-all" });
  assert.equal(epochDisabled.version, 4);
  assert.ok(epochDisabled.keys.every((key) => key.state === "emergency-disabled" && key.state_version === 4));

  const nextKey = {
    key_id: "authority-key-2",
    key_version: 2,
    purpose,
    algorithm: "ed25519",
    public_key_fingerprint: "b".repeat(64),
    state: "active",
    state_version: 1,
  };
  const verificationUntil = new Date(Date.now() + 60_000).toISOString();
  const race = await Promise.allSettled([
    first.rotate({ expected_version: 1, operation_id: "authority-rotate", new_key: nextKey, verification_until: verificationUntil }),
    second.emergencyDisable({ expected_version: 1, operation_id: "authority-disable" }),
  ]);
  assert.equal(race.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(race.filter(({ status }) => status === "rejected").length, 1);
  assert.equal((await first.snapshot()).version, 2);
});
