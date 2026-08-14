import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import {
  createPostgresProviderOperationMaintenanceRepository,
  PROVIDER_OPERATION_MAINTENANCE_REPOSITORY_ERROR_CODES as CODES,
  ProviderOperationMaintenanceRepositoryError
} from "../../src/postgres/provider-operation-maintenance-repository.mjs";

const RESULT_KEYS = ["quarantined", "reconciled", "pruned", "total"];

test("maintains all purposes and key versions under one total budget", async () => {
  const client = new MaintenanceClient({ quarantined: 2, reconciled: 1, pruned: 2 });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });

  const result = await repository.maintainProviderOperations({ limit: 5 });

  assert.deepEqual(result, { quarantined: 2, reconciled: 1, pruned: 2, total: 5 });
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(Object.keys(result), RESULT_KEYS);
  assert.deepEqual(client.budgetCalls, [
    ["quarantine", [5]],
    ["reconcile", [3]],
    ["prune", [2]]
  ]);
  assert.equal(client.calls.filter(({ text }) => text === "BEGIN").length, 1);
  assert.equal(client.calls.filter(({ text }) => text === "COMMIT").length, 1);
});

test("does not spend budget on reconciliation or pruning after quarantine fills it", async () => {
  const client = new MaintenanceClient({ quarantined: 4, reconciled: 0, pruned: 0 });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });

  assert.deepEqual(await repository.maintainProviderOperations({ limit: 4 }), {
    quarantined: 4, reconciled: 0, pruned: 0, total: 4
  });
  assert.deepEqual(client.budgetCalls, [["quarantine", [4]]]);
});

test("reconciliation is limited to exact SQL-only high-level committed correlation", async () => {
  const client = new MaintenanceClient({ quarantined: 0, reconciled: 1, pruned: 0 });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });
  await repository.maintainProviderOperations({ limit: 2 });

  const reconciliation = client.calls.find(({ kind }) => kind === "reconcile");
  assert.ok(reconciliation);
  assert.match(reconciliation.text, /provider\.state IN \('accepted','uncertain'\)/u);
  assert.match(reconciliation.text, /signing\.status='committed'/u);
  assert.match(reconciliation.text, /provider\.request_digest=signing\.request_digest/u);
  assert.match(reconciliation.text, /provider\.signature=signing\.signature/u);
  assert.match(reconciliation.text, /provider\.provider_receipt_provider=signing\.provider_receipt_provider/u);
  assert.match(reconciliation.text, /provider\.provider_receipt_id=signing\.provider_receipt_id/u);
  assert.match(reconciliation.text, /FOR UPDATE OF provider,signing SKIP LOCKED/u);
  assert.match(reconciliation.text, /uncertain_reason=NULL/u);
  assert.doesNotMatch(reconciliation.text, /request_bytes|signing_bytes|provider\.sign\(/iu);
});

test("prunes only correlated committed pairs with one bounded SKIP LOCKED selection", async () => {
  const client = new MaintenanceClient({ quarantined: 0, reconciled: 0, pruned: 2 });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });
  await repository.maintainProviderOperations({ limit: 3 });

  const pruning = client.calls.find(({ kind }) => kind === "prune");
  assert.ok(pruning);
  assert.match(pruning.text, /provider\.state='committed'/u);
  assert.match(pruning.text, /signing\.status='committed'/u);
  assert.match(pruning.text, /provider\.expires_at<=database_clock\.now/u);
  assert.match(pruning.text, /signing\.expires_at<=database_clock\.now/u);
  assert.match(pruning.text, /FOR UPDATE OF provider,signing SKIP LOCKED/u);
  assert.match(pruning.text, /DELETE FROM managed_signer_signing_idempotency/u);
  assert.match(pruning.text, /DELETE FROM managed_signer_provider_operations/u);
  assert.doesNotMatch(pruning.text, /organization_id|tenant_id|request_bytes|private_key/iu);
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

test("exposes capped aggregate health without deployment selectors or sensitive fields", async () => {
  const client = new MaintenanceClient({
    health: {
      pending: "10000",
      started: "3",
      accepted: "2",
      uncertain: "10000",
      committed: "7",
      rejected: "1",
      failed: "0",
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
  const healthCall = client.calls.find(({ kind }) => kind === "health");
  assert.match(healthCall.text, /SELECT 1 FROM managed_signer_provider_operations WHERE state='pending' LIMIT \$1/u);
  assert.match(healthCall.text, /SELECT 1 FROM managed_signer_provider_operations\s+WHERE state='started'[\s\S]*LIMIT \$1/u);
  assert.match(healthCall.text, /clock_timestamp\(\)/u);
  assert.doesNotMatch(JSON.stringify(result), /operation|receipt|bytes|tenant|provider/iu);
});

test("rejects malformed aggregate database rows", async () => {
  const client = new MaintenanceClient({ health: { pending: "not-an-integer" } });
  const repository = createPostgresProviderOperationMaintenanceRepository({ client });
  await assert.rejects(repository.health(), { code: CODES.DATABASE });
});

test("0041 supplies the bounded quarantine authority used by the repository", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0041_managed_signer_provider_operation_maintenance.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE FUNCTION agentpass_quarantine_expired_managed_signer_provider_operations\(\s*p_limit integer/u);
  assert.match(sql, /WHERE state = 'started'[\s\S]*claim_expires_at <= clock_timestamp\(\)/u);
  assert.match(sql, /FOR UPDATE SKIP LOCKED/u);
  assert.doesNotMatch(sql, /WHERE state = 'pending'[\s\S]*uncertain_reason = 'claim_expired_after_start'/u);
});

class MaintenanceClient {
  constructor({ quarantined = 0, reconciled = 0, pruned = 0, health = undefined, failWith = undefined } = {}) {
    this.values = { quarantined, reconciled, pruned };
    this.healthRow = health ?? {
      pending: "0", started: "0", accepted: "0", uncertain: "0", committed: "0", rejected: "0", failed: "0",
      stale_started: "0", oldest_nonterminal_at: null
    };
    this.failWith = failWith;
    this.calls = [];
    this.budgetCalls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params: structuredClone(params) });
    if (this.failWith) throw this.failWith;
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (text.startsWith("SELECT agentpass_quarantine_expired_managed_signer_provider_operations")) {
      this.budgetCalls.push(["quarantine", params]);
      return { rows: [{ quarantined: this.values.quarantined }], rowCount: 1 };
    }
    if (text.startsWith("WITH candidates") && text.includes("UPDATE managed_signer_provider_operations")) {
      this.budgetCalls.push(["reconcile", params]);
      this.calls.at(-1).kind = "reconcile";
      return { rows: [{ reconciled: this.values.reconciled }], rowCount: 1 };
    }
    if (text.startsWith("WITH candidates") && text.includes("DELETE FROM managed_signer_signing_idempotency")) {
      this.budgetCalls.push(["prune", params]);
      this.calls.at(-1).kind = "prune";
      return { rows: [{ pruned: this.values.pruned }], rowCount: 1 };
    }
    if (text.startsWith("SELECT\n        (SELECT count(*)")) {
      this.calls.at(-1).kind = "health";
      return { rows: [this.healthRow], rowCount: 1 };
    }
    throw new Error(`unexpected query: ${text}`);
  }
}
