import assert from "node:assert/strict";
import test from "node:test";
import { createMaintenanceJobRepository } from "../../src/postgres/maintenance-job-repository.mjs";

function dbHarness() {
  const calls = [];
  return { calls, db: { async query(text, params) { calls.push({ text, params }); return /reserve_maintenance_effect/u.test(text) ? { rows: [{ effect_id: "effect-1" }], rowCount: 1 } : { rows: [{ result: { status: "reserved", effect_id: "effect-1" } }], rowCount: 1 }; } } };
}

test("job adapter requires an explicit organization/job subject", async () => {
  const { db } = dbHarness();
  const jobs = createMaintenanceJobRepository({ db });
  assert.throws(() => jobs.getJob("job-1"), /organization_id and job_id are required/u);
});
