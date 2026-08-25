import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { planMaintenanceJob } from "../src/maintenance/planner.mjs";
import { createPatchProposal } from "../src/maintenance/patch-agent.mjs";
import { createMaintenanceOrchestrator } from "../src/maintenance/orchestrator.mjs";

const read = (name) => JSON.parse(fs.readFileSync(new URL(`../../../contracts/fixtures/${name}`, import.meta.url)));
const advisory = read("maintenance-advisory-endpoint.valid.json");
const snapshot = { schema_version: 1, kind: "agentpass.maintenance.repository-snapshot", snapshot_id: "snapshot-1", organization_id: "org-1", app_id: "app-1", repository_id: "repo-1", repository_name: "widgets", default_branch: "main", base_commit: "commit-1", source_digest: "a".repeat(64), captured_at: "2026-08-25T00:00:00.000Z" };
const policy = { ...read("maintenance-policy.valid.json"), generation: 3 };
const usage = { ...read("maintenance-usage-attestation.valid.json"), snapshot_id: "snapshot-1", classification: "confirmed", source_commit: "commit-1", usages: [{ selector: "GET /v1/widgets", file: "/src/client.ts", line: 12 }] };

function harness() {
  const calls = [];
  const repositories = {
    jobs: { async reserveJob(input) { calls.push(["reserveJob", input]); return input.job; }, async getJob(input) { calls.push(["getJob", input]); return input; }, async updateJob(input, patch) { calls.push(["updateJob", input, patch]); return { ...input, ...patch }; } },
    effects: { async reserve(input) { calls.push(["reserveEffect", input]); return { effect_id: "effect-1" }; }, async complete(...input) { calls.push(["completeEffect", input]); }, async reconcile(...input) { calls.push(["reconcileEffect", input]); } },
    results: { async saveResult(value) { calls.push(["saveResult", value]); return value; } },
    pullRequests: { async savePullRequest(value) { calls.push(["savePullRequest", value]); return value; } },
    receipts: { async saveReceipt(value) { calls.push(["saveReceipt", value]); return value; } }
  };
  return { calls, repositories, orchestrator: createMaintenanceOrchestrator(repositories) };
}

test("orchestrator persists the planned job and keeps receipt persistence explicit", async () => {
  const planned = planMaintenanceJob({ advisory, snapshot, usage, policy, now: "2026-08-25T00:00:00.000Z" });
  const proposal = createPatchProposal({ ...planned, advisory, snapshot, policy, changes: [{ path: "/src/client.ts", operation: "modify", diff: "@@ -1 +1 @@\n-old\n+new\n" }], createdAt: "2026-08-25T00:00:00.000Z" });
  const { calls, orchestrator } = harness();
  const reserved = await orchestrator.reserveJob({ advisory, snapshot, usage, policy, now: "2026-08-25T00:00:00.000Z" });
  assert.equal(reserved.stored.job_id, planned.job.job_id);
  assert.deepEqual(calls[0], ["reserveJob", { job: planned.job, plan: planned.plan, preimage: planned.preimage }]);
  const proposed = await orchestrator.proposePatch({ job: planned.job, plan: planned.plan, advisory, snapshot, policy, changes: [{ path: "/src/client.ts", operation: "modify", diff: "@@ -1 +1 @@\n-old\n+new\n" }], createdAt: "2026-08-25T00:00:00.000Z" });
  assert.equal(proposed.effect.effect_id, "effect-1");
  const verified = await orchestrator.verifyPatch({ job: planned.job, proposal: proposed.proposal, evidence: { syntax: { status: "passed" }, repository: { status: "passed" }, security: { status: "passed" }, authority_delta: { status: "passed" } }, createdAt: "2026-08-25T00:00:00.000Z" });
  assert.equal(verified.verification_status, "passed");
  assert.equal(calls.some(([kind]) => kind === "saveResult"), true);
  const receipt = { schema_version: 1, kind: "agentpass.maintenance.receipt", receipt_id: "receipt-1", organization_id: "org-1", job_id: planned.job.job_id, source_commit: "a".repeat(40), patch_digest: "b".repeat(64), verification_status: "passed", created_at: "2026-08-25T00:00:00.000Z", uncertainty: [] };
  const savedReceipt = await orchestrator.saveReceipt(receipt);
  assert.equal(savedReceipt.receipt_digest.length, 64);
  assert.deepEqual(calls.find(([kind]) => kind === "saveReceipt")[1], { ...receipt, receipt_digest: savedReceipt.receipt_digest });
});

test("orchestrator without a receipt repository fails closed", async () => {
  const { orchestrator } = harness();
  const noReceipt = createMaintenanceOrchestrator({ jobs: harness().repositories.jobs, effects: harness().repositories.effects, results: harness().repositories.results, pullRequests: harness().repositories.pullRequests });
  await assert.rejects(noReceipt.saveReceipt({}), { code: "maintenance.invalid_configuration" });
  assert.ok(orchestrator);
});
