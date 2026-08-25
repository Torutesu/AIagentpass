import assert from "node:assert/strict";
import test from "node:test";
import { createMaintenanceEffectRepository } from "../../src/postgres/maintenance-effect-repository.mjs";
import { createMaintenanceJobRepository } from "../../src/postgres/maintenance-job-repository.mjs";
import { createMaintenancePullRequestRepository } from "../../src/postgres/maintenance-pull-request-repository.mjs";
import { createMaintenanceResultRepository } from "../../src/postgres/maintenance-result-repository.mjs";

function dbHarness() {
  const calls = [];
  return { calls, db: { async query(text, params) { calls.push({ text, params }); return /reserve_maintenance_effect/u.test(text) ? { rows: [{ effect_id: "effect-1" }], rowCount: 1 } : { rows: [{ result: { status: "reserved", effect_id: "effect-1" } }], rowCount: 1 }; } } };
}

test("maintenance PostgreSQL adapters call authority functions and unwrap result rows", async () => {
  const { db, calls } = dbHarness();
  const jobs = createMaintenanceJobRepository({ db });
  const effects = createMaintenanceEffectRepository({ db });
  const results = createMaintenanceResultRepository({ db });
  const pullRequests = createMaintenancePullRequestRepository({ db });
  const receipts = (await import("../../src/postgres/maintenance-receipt-repository.mjs")).createMaintenanceReceiptRepository({ db });
  const subject = { organization_id: "org-1", job_id: "job-1" };
  assert.deepEqual(await jobs.reserveJob({ job: { organization_id: "org-1", job_id: "job-1", provider_id: "provider-1" }, plan: {} }), { status: "reserved", effect_id: "effect-1" });
  assert.deepEqual(await jobs.getJob(subject), { status: "reserved", effect_id: "effect-1" });
  assert.deepEqual(await jobs.updateJob(subject, { status: "running" }), { status: "reserved", effect_id: "effect-1" });
  assert.equal(await effects.reserve({ job_id: "job-1", organization_id: "org-1", effect_kind: "patch_propose", idempotency_key: "key-1", request_digest: "digest" }), "effect-1");
  assert.deepEqual(await results.saveResult({ organization_id: "org-1", job_id: "job-1", status: "uncertain" }), { status: "reserved", effect_id: "effect-1" });
  assert.deepEqual(await pullRequests.savePullRequest({ organization_id: "org-1", job_id: "job-1", state: "draft" }), { status: "reserved", effect_id: "effect-1" });
  assert.deepEqual(await receipts.saveReceipt({ organization_id: "org-1", job_id: "job-1", receipt_digest: "d".repeat(64) }), { status: "reserved", effect_id: "effect-1" });
  const reserveCall = calls.find(({ text }) => /reserve_maintenance_job/u.test(text));
  assert.deepEqual(reserveCall.params[0], { organization_id: "org-1", job_id: "job-1", provider_id: "provider-1" });
  assert.equal(calls.some(({ text }) => /agentpass_get_maintenance_job/u.test(text)), true);
  assert.equal(calls.some(({ text }) => /\b(?:INSERT|UPDATE|DELETE)\b/iu.test(text)), false);
});

test("job adapter requires an explicit organization/job subject", async () => {
  const { db } = dbHarness();
  const jobs = createMaintenanceJobRepository({ db });
  assert.throws(() => jobs.getJob("job-1"), /organization_id and job_id are required/u);
});
