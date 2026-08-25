import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import {
  createPostgresProviderOperationMaintenanceRepository,
  PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES as CODES,
  ProviderOperationMaintenanceRepositoryError
} from "../../src/postgres/provider-operation-maintenance-repository.mjs";

const MAINTENANCE_QUERY =
  "SELECT public.agentpass_maintain_managed_signer_provider_operations($1::integer) AS result";
const HEALTH_QUERY =
  "SELECT public.agentpass_health_managed_signer_provider_operations() AS result";
const RESULT_KEYS = ["quarantined", "reconciled", "pruned", "total"];
const HEALTH_STATE_KEYS = ["pending", "started", "accepted", "uncertain", "committed", "rejected", "failed"];

test("maintains all purposes and key versions through one allow-listed function call", async () => {
  const client = new MaintenanceClient({
    maintenance: { quarantined: 2, reconciled: 1, pruned: 2, total: 5 }
  });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });

  const result = await repository.maintainProviderOperations({ limit: 5 });

  assert.deepEqual(result, { quarantined: 2, reconciled: 1, pruned: 2, total: 5 });
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(Object.keys(result), RESULT_KEYS);
  assert.deepEqual(client.calls, [{ text: MAINTENANCE_QUERY, params: [5] }]);
});

test("passes only a bounded total limit as an opaque function argument", async () => {
  const client = new MaintenanceClient({
    maintenance: { quarantined: 0, reconciled: 0, pruned: 0, total: 0 }
  });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });

  await repository.maintainProviderOperations({ limit: 1_000 });

  assert.deepEqual(client.calls, [{ text: MAINTENANCE_QUERY, params: [1_000] }]);
  assert.doesNotMatch(client.calls[0].text, /\b(?:FROM|JOIN|INSERT|UPDATE|DELETE|TRUNCATE)\b/iu);
});

test("exposes only the two maintenance methods and rejects malformed function rows", async () => {
  const repository = createPostgresProviderOperationMaintenanceRepository({ client: new MaintenanceClient() });
  assert.deepEqual(Object.keys(repository).sort(), ["health", "maintainProviderOperations"]);
  for (const response of [
    { rows: [], rowCount: 0 },
    { rows: [{ result: {} }, { result: {} }], rowCount: 2 },
    { rows: [{ result: { quarantined: 0, reconciled: 0, pruned: 0, total: 0 }, extra: true }], rowCount: 1 },
    { rows: ["not-a-row"], rowCount: 1 }
  ]) {
    const failingClient = new MaintenanceClient({ response });
    const failingRepository = createPostgresProviderOperationMaintenanceRepository({ client: failingClient });
    await assert.rejects(failingRepository.maintainProviderOperations({ limit: 1 }), { code: CODES.DATABASE });
  }
});

test("rejects malformed maintenance JSON instead of widening the result contract", async () => {
  const malformed = [
    { quarantined: 1, reconciled: 0, pruned: 0, total: 2 },
    { quarantined: 1, reconciled: 0, pruned: 0, total: 1, extra: true },
    { quarantined: 1_001, reconciled: 0, pruned: 0, total: 1_001 },
    { quarantined: "not-an-integer", reconciled: 0, pruned: 0, total: 0 },
    null
  ];
  for (const maintenance of malformed) {
    const repository = createPostgresProviderOperationMaintenanceRepository({
      client: new MaintenanceClient({ maintenance })
    });
    await assert.rejects(repository.maintainProviderOperations({ limit: 1_000 }), { code: CODES.DATABASE });
  }
});

test("validates exact deployment-wide input and returns stable opaque errors", async () => {
  assert.throws(() => createPostgresProviderOperationMaintenanceRepository(), {
    code: CODES.CONFIG,
    message: "provider operation maintenance repository configuration is invalid"
  });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client: new MaintenanceClient() });
  for (const input of [undefined, {}, { limit: 0 }, { limit: 1_001 }, { limit: 1, purpose: "tenant-selector" }]) {
    await assert.rejects(repository.maintainProviderOperations(input), (error) => {
      assert.ok(error instanceof ProviderOperationMaintenanceRepositoryError);
      assert.equal(error.code, CODES.INPUT);
      assert.equal(error.message, "provider operation maintenance request is invalid");
      assert.equal(error.cause, undefined);
      return true;
    });
  }
  await assert.rejects(repository.health({ purpose: "selector" }), { code: CODES.INPUT });
});

test("contains database failures and never forwards driver diagnostics", async () => {
  const driverError = new Error("relation secret_operation_dump does not exist");
  driverError.detail = "request bytes and provider diagnostic";
  const repository = createPostgresProviderOperationMaintenanceRepository({
    client: new MaintenanceClient({ failWith: driverError })
  });

  await assert.rejects(repository.maintainProviderOperations({ limit: 1 }), (error) => {
    assert.equal(error.code, CODES.DATABASE);
    assert.equal(error.message, "provider operation maintenance storage is unavailable");
    assert.equal(error.cause, undefined);
    assert.equal(JSON.stringify(error).includes("secret_operation_dump"), false);
    return true;
  });
});

test("exposes fixed-cardinality capped aggregate health through one allow-listed function call", async () => {
  const client = new MaintenanceClient({
    health: {
      version: 1,
      states: {
        pending: "10000", started: "3", accepted: "2", uncertain: "10000",
        committed: "7", rejected: "1", failed: "0"
      },
      stale_started: "10000",
      oldest_nonterminal_at: new Date("2026-08-15T00:00:00.000Z")
    }
  });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });

  const result = await repository.health();

  assert.deepEqual(result, {
    version: 1,
    states: { pending: 10_000, started: 3, accepted: 2, uncertain: 10_000, committed: 7, rejected: 1, failed: 0 },
    stale_started: 10_000,
    oldest_nonterminal_at: "2026-08-15T00:00:00.000Z"
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.states), true);
  assert.deepEqual(client.calls, [{ text: HEALTH_QUERY, params: [] }]);
  assert.doesNotMatch(JSON.stringify(result), /operation|receipt|bytes|tenant|provider/iu);
});

test("rejects malformed health JSON and never exposes identifiers", async () => {
  const malformed = [
    { version: 2, states: {}, stale_started: 0, oldest_nonterminal_at: null },
    { version: 1, states: { pending: "not-an-integer" }, stale_started: 0, oldest_nonterminal_at: null },
    { version: 1, states: Object.fromEntries(HEALTH_STATE_KEYS.map((key) => [key, 0])), stale_started: 10_001, oldest_nonterminal_at: null },
    { version: 1, states: Object.fromEntries(HEALTH_STATE_KEYS.map((key) => [key, 0])), stale_started: 0, oldest_nonterminal_at: "not-a-timestamp", operation_id: "leak" }
  ];
  for (const health of malformed) {
    const repository = createPostgresProviderOperationMaintenanceRepository({
      client: new MaintenanceClient({ health })
    });
    await assert.rejects(repository.health(), { code: CODES.DATABASE });
  }
});

test("JS contains no direct managed signer tables or DML", async () => {
  const source = await readFile(new URL("../../src/postgres/provider-operation-maintenance-repository.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /\b(?:FROM|JOIN|INSERT|UPDATE|DELETE|TRUNCATE)\b/iu);
  assert.doesNotMatch(source, /(?:^|[^A-Za-z0-9_])managed_signer_(?:provider_operations|signing_idempotency)(?:[^A-Za-z0-9_]|$)/u);
  assert.match(source, /SELECT public\.agentpass_maintain_managed_signer_provider_operations\(\$1::integer\) AS result/u);
  assert.match(source, /SELECT public\.agentpass_health_managed_signer_provider_operations\(\) AS result/u);
});

test("0050 defines bounded SECURITY DEFINER maintenance authorities", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0050_managed_signer_provider_operation_maintenance_authority.sql", import.meta.url), "utf8");
  const roles = await readFile(new URL("../../../../scripts/postgres/roles.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_maintain_managed_signer_provider_operations\(\s*p_limit integer/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_health_managed_signer_provider_operations\(\)/u);
  assert.equal((sql.match(/SECURITY DEFINER/gu) ?? []).length, 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/gu) ?? []).length, 2);
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.agentpass_maintain_managed_signer_provider_operations\(integer\) FROM PUBLIC/u);
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.agentpass_health_managed_signer_provider_operations\(\) FROM PUBLIC/u);
  assert.match(roles, /agentpass_maintain_managed_signer_provider_operations\(integer\)/u);
  assert.match(roles, /agentpass_health_managed_signer_provider_operations\(\)/u);
  assert.match(sql, /jsonb_build_object/u);
  assert.match(sql, /total_count > p_limit/u);
  assert.equal((sql.match(/FOR UPDATE SKIP LOCKED/gu) ?? []).length, 1);
  assert.equal((sql.match(/FOR UPDATE OF provider, signing SKIP LOCKED/gu) ?? []).length, 2);
  assert.match(sql, /claim_expires_at <= database_now/u);
  assert.match(sql, /provider\.expires_at <= database_now/u);
  assert.match(sql, /signing\.expires_at <= database_now/u);
  for (const expression of [
    "request_digest", "key_id", "key_version", "signature",
    "provider_receipt_provider", "provider_receipt_id"
  ]) {
    assert.ok((sql.match(new RegExp(`provider\\.${expression} = signing\\.${expression}`, "gu")) ?? []).length >= 2);
  }
  const healthStart = sql.indexOf("CREATE FUNCTION public.agentpass_health_managed_signer_provider_operations");
  assert.notEqual(healthStart, -1);
  const healthSql = sql.slice(healthStart);
  assert.ok((healthSql.match(/LIMIT 10000/gu) ?? []).length >= 8);
  assert.match(healthSql, /oldest_nonterminal_at'[\s\S]*ORDER BY created_at, purpose, operation_id[\s\S]*LIMIT 1/u);
  assert.doesNotMatch(healthSql, /'operation_id'|'purpose'|'key_id'|'provider_receipt/iu);
});

class MaintenanceClient {
  constructor({ maintenance = { quarantined: 0, reconciled: 0, pruned: 0, total: 0 }, health = undefined, failWith = undefined, response = undefined } = {}) {
    this.maintenance = maintenance;
    this.healthResult = health ?? {
      version: 1,
      states: Object.fromEntries(HEALTH_STATE_KEYS.map((key) => [key, "0"])),
      stale_started: "0",
      oldest_nonterminal_at: null
    };
    this.failWith = failWith;
    this.response = response;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params: structuredClone(params) });
    if (this.failWith) throw this.failWith;
    if (this.response) return this.response;
    if (text === MAINTENANCE_QUERY) return { rows: [{ result: this.maintenance }], rowCount: 1 };
    if (text === HEALTH_QUERY) return { rows: [{ result: this.healthResult }], rowCount: 1 };
    throw new Error(`unexpected query: ${text}`);
  }
}
