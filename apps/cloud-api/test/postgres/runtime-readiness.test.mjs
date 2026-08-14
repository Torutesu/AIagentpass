import assert from "node:assert/strict";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";
import { createPostgresRuntime } from "../../src/postgres/runtime.mjs";

const DATABASE_URL = "postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full";
const SECRET = Buffer.alloc(32, 0x31).toString("base64url");

class FakePool {
  constructor(options) {
    this.options = options;
    this.totalCount = 1;
    this.idleCount = 1;
    this.waitingCount = 0;
    this.applied = [];
    this.ended = false;
  }

  async connect() {
    return this.client();
  }

  client() {
    return {
      query: (text, params) => this.query(text, params),
      release: () => {}
    };
  }

  async query(text, params = []) {
    if (text === "SELECT 1::integer AS ready" || text === "SELECT 1 AS ready") return { rows: [{ ready: 1 }] };
    if (text === "SELECT to_regclass($1) AS relation") {
      return { rows: [{ relation: params[0] === "schema_migrations" ? "schema_migrations" : null }] };
    }
    if (text.startsWith("SELECT version, checksum FROM schema_migrations")) return { rows: this.applied };
    if (text.startsWith("SELECT version, checksum, status, finished_at FROM schema_migration_attempts")) return { rows: [] };
    if (text.startsWith("INSERT INTO schema_migrations")) {
      this.applied.push({ version: Number(params[0]), checksum: params[1] });
      return { rows: [] };
    }
    if (text === "SELECT set_config('statement_timeout', $1, false)" || text === "SELECT set_config('lock_timeout', $1, false)") return { rows: [{ set_config: params[0] }] };
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK" || text.includes("pg_advisory_xact_lock")) return { rows: [] };
    return { rows: [] };
  }

  async end() {
    this.ended = true;
  }
}

function env() {
  return {
    AGENTPASS_DATABASE_URL: DATABASE_URL,
    AGENTPASS_HUMAN_CURSOR_SECRET: SECRET,
    AGENTPASS_CAPABILITY_NONCE_SECRET: Buffer.alloc(32, 0x32).toString("base64url")
  };
}

test("PostgreSQL runtime exposes exact-schema readiness, tracked work, and bounded drain", async () => {
  const migrations = await loadSqlMigrations();
  const runtime = await createPostgresRuntime({ env: env(), PoolClass: FakePool, applicationVersion: "runtime-readiness-test", resolveProcessBindingPolicy: () => true });
  assert.equal(runtime.pool.applied.length, migrations.length);
  assert.equal(migrations.length, 26);
  assert.equal((await runtime.readiness()).code, "ready");
  assert.equal(typeof runtime.agentSessionIssuanceRepository?.issueAgentSessionGrant, "function");
  assert.equal(typeof runtime.agentSessionConsumptionRepository?.consumeAgentSessionGrant, "function");
  assert.equal(typeof runtime.agentSessionLifecycleRepository?.expireDue, "function");
  assert.equal(typeof runtime.agentSessionLifecycleRepository?.revokeAuthority, "function");
  assert.equal(typeof runtime.qualificationGrantBatchRepository?.issueQualificationGrantBatch, "function");
  assert.equal(typeof runtime.qualificationGrantBatchRepository?.claimQualificationGrantBatch, "function");
  assert.equal(typeof runtime.ownerRecoveryRepository?.createRecoveryRequest, "function");
  assert.equal(typeof runtime.ownerRecoveryRepository?.activateRecoveryInTransaction, "function");
  assert.equal(typeof runtime.ownerRecoveryWebAuthnRepository?.begin, "function");
  assert.equal(typeof runtime.ownerRecoveryWebAuthnRepository?.complete, "function");

  let finish;
  const inFlight = runtime.trackInFlight(() => new Promise((resolve) => { finish = resolve; }));
  runtime.beginDrain();
  const draining = await runtime.readiness();
  assert.equal(draining.ready, false);
  assert.equal(draining.code, "draining");
  assert.equal(draining.checks.drain.in_flight, 1);

  const close = runtime.drain({ timeoutMs: 100 });
  finish();
  await inFlight;
  const drained = await close;
  assert.equal(drained.drained, true);
  assert.equal(runtime.pool.ended, true);
  assert.equal((await runtime.readiness()).code, "closed");
  await runtime.close();
});
