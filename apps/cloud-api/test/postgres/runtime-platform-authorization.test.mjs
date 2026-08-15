import assert from "node:assert/strict";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";
import {
  PLATFORM_AUTHORIZATION_RESERVE_SQL,
  PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES
} from "../../src/postgres/platform-authorization-repository.mjs";
import { createPostgresRuntime } from "../../src/postgres/runtime.mjs";

const DATABASE_URL = "postgresql://agentpass_app:secret@db.example.test/agentpass?sslmode=verify-full";
const MIGRATION_DATABASE_URL = "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full";
const SIGNER_DATABASE_URL = "postgresql://agentpass_signer:secret@db.example.test/agentpass?sslmode=verify-full";
const HUMAN_CURSOR_SECRET = Buffer.alloc(32, 0x31).toString("base64url");
const CAPABILITY_NONCE_SECRET = Buffer.alloc(32, 0x32).toString("base64url");
const PLATFORM_LIFECYCLE = Object.freeze({
  keyId: "promotion-evidence-2026-08",
  keyVersion: 8,
  lifecycleVersion: 7
});
const AUTHORIZATION = Object.freeze({
  organization_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  session_material_hash: "11".repeat(32),
  csrf_token: Buffer.alloc(32, 0x22).toString("base64url"),
  proof_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  jti: "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
});
const REQUEST = Object.freeze({
  promotion_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`,
  idempotency_key: "platform-promotion-0001"
});

const DATABASE_STATE = { applied: [] };

class RuntimePool {
  static instances = [];

  constructor() {
    this.applied = DATABASE_STATE.applied;
    this.calls = [];
    this.ended = false;
    RuntimePool.instances.push(this);
  }

  async connect() {
    return {
      query: (text, params) => this.query(text, params),
      release() {}
    };
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text === "SELECT 1::integer AS ready" || text === "SELECT 1 AS ready") return { rows: [{ ready: 1 }] };
    if (text === "SELECT to_regclass($1) AS relation") return { rows: [{ relation: params[0] === "schema_migrations" ? "schema_migrations" : null }] };
    if (text.startsWith("SELECT version, checksum FROM schema_migrations")) return { rows: this.applied };
    if (text.startsWith("SELECT version, checksum, status, finished_at FROM schema_migration_attempts")) return { rows: [] };
    if (text.startsWith("INSERT INTO schema_migration_attempts")) return { rowCount: 1, rows: [] };
    if (text.startsWith("UPDATE schema_migration_attempts")) return { rowCount: 1, rows: [] };
    if (text.startsWith("INSERT INTO schema_migrations")) {
      this.applied.push({ version: Number(params[0]), checksum: params[1] });
      return { rows: [] };
    }
    if (text === "SELECT set_config('statement_timeout', $1, false)" || text === "SELECT set_config('lock_timeout', $1, false)") return { rows: [{ set_config: params[0] }] };
    if (text.startsWith("SELECT public.agentpass_health_managed_signer_provider_operations")) return { rowCount: 1, rows: [{ result: { version: 1, states: {}, stale_started: 0, oldest_nonterminal_at: null } }] };
    if (text.startsWith("SELECT public.agentpass_maintain_managed_signer_provider_operations")) return { rowCount: 1, rows: [{ result: { quarantined: 0, reconciled: 0, pruned: 0, total: 0 } }] };
    if (text.startsWith("SELECT agentpass_quarantine_expired_managed_signer_provider_operations")) return { rowCount: 1, rows: [{ quarantined: 0 }] };
    if (text.startsWith("WITH candidates")) return { rowCount: 1, rows: [{ reconciled: 0, pruned: 0 }] };
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK" || text.includes("pg_advisory_xact_lock")) return { rows: [] };
    if (text === PLATFORM_AUTHORIZATION_RESERVE_SQL) throw new Error("atomic reservation unavailable");
    return { rows: [] };
  }

  async end() {
    this.ended = true;
  }
}

function env() {
  return {
    AGENTPASS_DATABASE_URL: DATABASE_URL,
    AGENTPASS_MIGRATION_DATABASE_URL: MIGRATION_DATABASE_URL,
    AGENTPASS_SIGNER_DATABASE_URL: SIGNER_DATABASE_URL,
    AGENTPASS_HUMAN_CURSOR_SECRET: HUMAN_CURSOR_SECRET,
    AGENTPASS_CAPABILITY_NONCE_SECRET: CAPABILITY_NONCE_SECRET
  };
}

async function runtime(options = {}) {
  RuntimePool.instances = [];
  return createPostgresRuntime({
    env: env(),
    PoolClass: RuntimePool,
    platformPromotionVerifyEvidence: async () => false,
    sharedControlMaintenanceAutoStart: false,
    managedSignerProviderOperationMaintenanceAutoStart: false,
    ...options
  });
}

test("routes promotion finalization through the signer pool, never the application pool", async () => {
  const value = await runtime();
  const [applicationPool, _migrationPool, signerPool] = RuntimePool.instances;
  await assert.rejects(value.platformPromotionIssuanceRepository.markPlatformPromotionUncertain({
    ...REQUEST,
    claim_token: Buffer.alloc(32, 0x77).toString("base64url"),
    reason: "commit_failure"
  }));
  assert.equal(
    signerPool.calls.some(({ text }) => typeof text === "string" && text.includes("agentpass_platform_promotion_issuance_uncertain")),
    true
  );
  assert.equal(
    applicationPool.calls.some(({ text }) => typeof text === "string" && text.includes("agentpass_platform_promotion_issuance_uncertain")),
    false
  );
  await value.close();
});

test("does not expose atomic platform authorization without lifecycle binding", async () => {
  const value = await runtime();
  assert.equal(value.platformAuthorizationRepository, undefined);
  assert.equal(typeof value.platformPromotionIssuanceRepository.reservePlatformPromotion, "function");
  assert.equal(typeof value.createPlatformAuthorizationRepository, "function");
  await value.close();
});

test("binds atomic authorization after managed signer lifecycle resolution", async () => {
  const value = await runtime();
  const repository = value.createPlatformAuthorizationRepository(PLATFORM_LIFECYCLE);
  assert.equal(typeof repository.forAuthorization, "function");
  await assert.rejects(
    repository.forAuthorization(AUTHORIZATION).reservePlatformPromotion(REQUEST),
    (error) => error.code === PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE
  );
  const appPoolCall = value.pool.calls.find(({ text }) => text === PLATFORM_AUTHORIZATION_RESERVE_SQL);
  assert.equal(appPoolCall.params[13], PLATFORM_LIFECYCLE.keyId);
  assert.equal(appPoolCall.params[14], PLATFORM_LIFECYCLE.keyVersion);
  assert.equal(appPoolCall.params[15], PLATFORM_LIFECYCLE.lifecycleVersion);
  await value.close();
});

test("exposes an atomic authorization repository bound to the issuance repository and lifecycle", async () => {
  const value = await runtime({ platformPromotionLifecycle: PLATFORM_LIFECYCLE });
  assert.equal(typeof value.platformAuthorizationRepository?.forAuthorization, "function");
  assert.equal(typeof value.platformAuthorizationRepository?.reservePlatformPromotion, "function");

  await assert.rejects(
    value.platformAuthorizationRepository.forAuthorization(AUTHORIZATION).reservePlatformPromotion(REQUEST),
    (error) => error.code === PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE
  );

  const appPoolCall = value.pool.calls.find(({ text }) => text === PLATFORM_AUTHORIZATION_RESERVE_SQL);
  assert.ok(appPoolCall);
  assert.equal(appPoolCall.params[13], PLATFORM_LIFECYCLE.keyId);
  assert.equal(appPoolCall.params[14], PLATFORM_LIFECYCLE.keyVersion);
  assert.equal(appPoolCall.params[15], PLATFORM_LIFECYCLE.lifecycleVersion);
  assert.equal(appPoolCall.params.includes(AUTHORIZATION.csrf_token), false);
  assert.equal(appPoolCall.params.includes(AUTHORIZATION.jti), false);
  await value.close();
});

test("rejects incomplete or extra platform lifecycle configuration before opening pools", async () => {
  await assert.rejects(
    runtime({ platformPromotionLifecycle: { keyId: PLATFORM_LIFECYCLE.keyId, keyVersion: 8 } }),
    /platform promotion lifecycle configuration is invalid/u
  );
  await assert.rejects(
    runtime({ platformPromotionLifecycle: { ...PLATFORM_LIFECYCLE, unexpected: true } }),
    /platform promotion lifecycle configuration is invalid/u
  );
  const value = await runtime();
  assert.throws(
    () => value.createPlatformAuthorizationRepository({ keyId: PLATFORM_LIFECYCLE.keyId, keyVersion: 8 }),
    /platform promotion lifecycle configuration is invalid/u
  );
  await value.close();
});

test("keeps the runtime contract stable when lifecycle binding is frozen", async () => {
  const migrations = await loadSqlMigrations();
  const value = await runtime({ platformPromotionLifecycle: PLATFORM_LIFECYCLE });
  assert.equal(value.pool.applied.length, migrations.length);
  assert.equal(Object.isFrozen(value.platformAuthorizationRepository), true);
  await value.close();
});
