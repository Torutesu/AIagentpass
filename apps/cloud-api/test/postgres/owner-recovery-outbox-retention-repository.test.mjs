import assert from "node:assert/strict";
import test from "node:test";

import {
  OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES,
  OwnerRecoveryOutboxRetentionRepositoryError,
  createPostgresOwnerRecoveryOutboxRetentionRepository
} from "../../src/postgres/owner-recovery-outbox-retention-repository.mjs";

const ERROR_CODES = OWNER_RECOVERY_OUTBOX_RETENTION_ERROR_CODES;
const SUCCESS = { published: "2", dead_letter: 3, suppressed: 1, total: "6" };

test("prune uses the bounded default and normalizes an exact bigint result row", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 1, rows: [SUCCESS] }));
  const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({ client });

  assert.deepEqual(await repository.prune(), { published: 2, dead_letter: 3, suppressed: 1, total: 6 });
  assert.equal(client.calls.length, 1);
  assert.match(client.calls[0].text, /^SELECT published,dead_letter,suppressed,total FROM agentpass_prune_owner_recovery_outbox_terminal\(\$1::integer\)$/u);
  assert.deepEqual(client.calls[0].params, [100]);
});

test("prune accepts an explicit limit through the hard maximum", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 1, rows: [{ published: 0n, dead_letter: 0n, suppressed: 1000n, total: 1000n }] }));
  const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({ client });

  assert.deepEqual(await repository.prune({ limit: 1000 }), { published: 0, dead_letter: 0, suppressed: 1000, total: 1000 });
  assert.deepEqual(client.calls[0].params, [1000]);
});

test("rejects unknown fields and invalid limits before PostgreSQL", async () => {
  const client = new ScriptedClient(() => { throw new Error("must not query"); });
  const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({ client });
  const unknown = Symbol("unknown");
  const symbolField = { limit: 1, [unknown]: true };

  for (const input of [
    { limit: 1, organization_id: "tenant-secret" },
    symbolField,
    { limit: 0 },
    { limit: 1001 },
    { limit: 1.5 },
    { limit: "1" },
    { limit: Number.MAX_SAFE_INTEGER + 1 },
    null,
    []
  ]) {
    await assert.rejects(() => repository.prune(input), (error) => isError(error, ERROR_CODES.INVALID_REQUEST));
  }
  assert.equal(client.calls.length, 0);
});

test("requires one exact result row and rejects extra keys or row-count disagreement", async () => {
  for (const result of [
    { rowCount: 0, rows: [] },
    { rowCount: 2, rows: [SUCCESS] },
    { rowCount: 1, rows: [SUCCESS, SUCCESS] },
    { rowCount: 1, rows: [{ ...SUCCESS, secret: "should-not-escape" }] },
    { rowCount: 1, rows: [{ published: 2, dead_letter: 3, suppressed: 1 }] },
    { rowCount: 1, rows: [null] }
  ]) {
    const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({ client: new ScriptedClient(() => result) });
    await assert.rejects(() => repository.prune({ limit: 10 }), (error) => isError(error, ERROR_CODES.UNAVAILABLE));
  }
});

test("accepts the node-postgres Result class envelope while keeping its row exact", async () => {
  class PgResult {
    constructor() { this.rowCount = 1; this.rows = [SUCCESS]; }
  }
  const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: new ScriptedClient(() => new PgResult())
  });
  assert.deepEqual(await repository.prune({ limit: 10 }), { published: 2, dead_letter: 3, suppressed: 1, total: 6 });
});

test("rejects negative, fractional, unsafe, noncanonical, and inconsistent counts", async () => {
  for (const row of [
    { published: -1, dead_letter: 0, suppressed: 0, total: 0 },
    { published: 1.5, dead_letter: 0, suppressed: 0, total: 1.5 },
    { published: Number.MAX_SAFE_INTEGER + 1, dead_letter: 0, suppressed: 0, total: 0 },
    { published: "01", dead_letter: 0, suppressed: 0, total: 1 },
    { published: "not-a-count", dead_letter: 0, suppressed: 0, total: 0 },
    { published: 1, dead_letter: 1, suppressed: 1, total: 2 },
    { published: 11, dead_letter: 0, suppressed: 0, total: 11 }
  ]) {
    const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({
      client: new ScriptedClient(() => ({ rowCount: 1, rows: [row] }))
    });
    await assert.rejects(() => repository.prune({ limit: 10 }), (error) => isError(error, ERROR_CODES.UNAVAILABLE));
  }
});

test("maps database diagnostics and malformed output to the same typed secret-free error without a cause", async () => {
  const database = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: new ScriptedClient(() => { throw new Error("postgres password=super-secret"); })
  });
  const malformed = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: new ScriptedClient(() => ({ rowCount: 1, rows: [{ ...SUCCESS, total: 5 }] }))
  });

  const errors = [];
  for (const repository of [database, malformed]) await assert.rejects(() => repository.prune({ limit: 10 }), (error) => {
    errors.push(error);
    assert.ok(error instanceof OwnerRecoveryOutboxRetentionRepositoryError);
    assert.equal(error.code, ERROR_CODES.UNAVAILABLE);
    assert.equal(error.message, "Owner recovery outbox retention storage is unavailable");
    assert.equal(Object.prototype.hasOwnProperty.call(error, "cause"), false);
    assert.equal(error.message.includes("super-secret"), false);
    return true;
  });
  assert.equal(errors[0].message, errors[1].message);
});

test("records only nonzero successful pruning and ignores synchronous and asynchronous metric failures", async () => {
  const calls = [];
  const metrics = {
    recordOwnerRecoveryOutboxPrune(total) {
      calls.push(total);
      throw new Error("metrics secret");
    }
  };
  const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: new ScriptedClient(() => ({ rowCount: 1, rows: [{ published: 0, dead_letter: 0, suppressed: 0, total: 0 }] })),
    metrics
  });
  assert.deepEqual(await repository.prune({ limit: 1 }), { published: 0, dead_letter: 0, suppressed: 0, total: 0 });
  assert.deepEqual(calls, []);

  const asyncCalls = [];
  const asyncMetrics = {
    recordOwnerRecoveryOutboxPrune(total) {
      asyncCalls.push(total);
      return Promise.reject(new Error("async metrics secret"));
    }
  };
  const successful = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: new ScriptedClient(() => ({ rowCount: 1, rows: [SUCCESS] })),
    metrics: asyncMetrics
  });
  assert.deepEqual(await successful.prune({ limit: 10 }), { published: 2, dead_letter: 3, suppressed: 1, total: 6 });
  assert.deepEqual(asyncCalls, [6]);
});

test("does not leak database or metric failures through the returned error boundary", async () => {
  const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: new ScriptedClient(() => ({ rowCount: 1, rows: [{ published: 1, dead_letter: 0, suppressed: 0, total: 1 }] })),
    metrics: { recordOwnerRecoveryOutboxPrune() { throw new Error("metric-secret"); } }
  });
  assert.deepEqual(await repository.prune({ limit: 1 }), { published: 1, dead_letter: 0, suppressed: 0, total: 1 });
});

function isError(error, code) {
  return error instanceof OwnerRecoveryOutboxRetentionRepositoryError && error.code === code;
}

class ScriptedClient {
  constructor(handler) {
    this.handler = handler;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    return this.handler(text, params);
  }
}
