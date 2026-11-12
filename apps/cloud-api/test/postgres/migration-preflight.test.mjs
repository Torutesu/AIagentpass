import assert from "node:assert/strict";
import test from "node:test";

import {
  ControlPlaneCutoverPreflightError,
  PREFLIGHT_DIAGNOSTICS,
  VALIDATION_STATEMENTS,
  runControlPlaneCutoverPreflight
} from "../../../../scripts/postgres/preflight-0011.mjs";

class PreflightClient {
  constructor({ rows = [], failOn = undefined } = {}) {
    this.rows = rows;
    this.failOn = failOn;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (this.failOn?.(text)) throw new Error("database detail must not become a public diagnostic");
    if (text.includes("WITH violations")) return { rows: this.rows };
    return { rows: [] };
  }
}

test("0011 preflight succeeds without mutating when all created_by rows are tenant-consistent", async () => {
  const client = new PreflightClient();
  const result = await runControlPlaneCutoverPreflight({ client });

  assert.deepEqual(result, { ok: true, validated: false, violations: [] });
  assert.equal(client.calls.length, 1);
  assert.match(client.calls[0].text, /device_enrollments/);
  assert.match(client.calls[0].text, /policies/);
  assert.match(client.calls[0].text, /revocations/);
});

test("0011 preflight fails closed with stable, actionable diagnostics", async () => {
  const client = new PreflightClient({ rows: [
    { table_name: "device_enrollments", violation_count: "2" },
    { table_name: "policies", violation_count: "1" }
  ] });

  await assert.rejects(
    runControlPlaneCutoverPreflight({ client }),
    (error) => {
      assert(error instanceof ControlPlaneCutoverPreflightError);
      assert.equal(error.code, PREFLIGHT_DIAGNOSTICS.CROSS_TENANT_CREATED_BY.code);
      assert.equal(error.message, PREFLIGHT_DIAGNOSTICS.CROSS_TENANT_CREATED_BY.message);
      assert.equal(error.remediation, PREFLIGHT_DIAGNOSTICS.CROSS_TENANT_CREATED_BY.remediation);
      assert.deepEqual(error.details, {
        violations: [
          { table: "device_enrollments", count: 2 },
          { table: "policies", count: 1 }
        ],
        total: 3
      });
      return true;
    }
  );
  assert.equal(client.calls.length, 1, "a failed preflight must not begin validation");
});

test("0011 validation is an explicit transaction after a clean preflight", async () => {
  const client = new PreflightClient();
  const result = await runControlPlaneCutoverPreflight({ client, validate: true });

  assert.deepEqual(result, { ok: true, validated: true, violations: [] });
  assert.deepEqual(client.calls.slice(1).map((call) => call.text), ["BEGIN", ...VALIDATION_STATEMENTS, "COMMIT"]);
});

test("validation failure rolls back and redacts database details behind a stable diagnostic", async () => {
  const client = new PreflightClient({ failOn: (text) => text === VALIDATION_STATEMENTS[1] });

  await assert.rejects(
    runControlPlaneCutoverPreflight({ client, validate: true }),
    (error) => error.code === PREFLIGHT_DIAGNOSTICS.VALIDATION_FAILED.code
      && error.message === PREFLIGHT_DIAGNOSTICS.VALIDATION_FAILED.message
      && !error.message.includes("database detail")
  );
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});
