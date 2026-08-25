import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { planMaintenanceJob } from "../src/maintenance/planner.mjs";
import { createPatchProposal } from "../src/maintenance/patch-agent.mjs";
import { verifyMaintenancePatch, VERIFICATION_ERROR_CODES } from "../src/maintenance/verification.mjs";

const read = (name) => JSON.parse(fs.readFileSync(new URL(`../../../contracts/fixtures/${name}`, import.meta.url)));
const advisory = read("maintenance-advisory-endpoint.valid.json");
const snapshot = { schema_version: 1, kind: "agentpass.maintenance.repository-snapshot", snapshot_id: "snapshot-1", organization_id: "org-1", app_id: "app-1", repository_id: "repo-1", repository_name: "widgets", default_branch: "main", base_commit: "commit-1", source_digest: "a".repeat(64), captured_at: "2026-08-25T00:00:00.000Z" };
const policy = { ...read("maintenance-policy.valid.json"), generation: 3 };
const usage = { ...read("maintenance-usage-attestation.valid.json"), snapshot_id: "snapshot-1", classification: "confirmed", source_commit: "commit-1", usages: [{ selector: "GET /v1/widgets", file: "/src/client.ts", line: 12 }] };
const context = () => {
  const planned = planMaintenanceJob({ advisory, snapshot, usage, policy, now: "2026-08-25T00:00:00.000Z" });
  const proposal = createPatchProposal({ ...planned, advisory, snapshot, policy, changes: [{ path: "/src/client.ts", operation: "modify", diff: "@@ -1 +1 @@\n-old\n+new\n" }], createdAt: "2026-08-25T00:00:00.000Z" });
  return { job: planned.job, proposal };
};

test("verification is explicit and never upgrades missing evidence", () => {
  const { job, proposal } = context();
  const result = verifyMaintenancePatch({ job, proposal, createdAt: "2026-08-25T00:00:00.000Z" });
  assert.equal(result.status, "uncertain");
  assert.equal(result.verification_status, "not_run");
  assert.deepEqual(result.evidence.uncertainty, ["syntax:not_run", "repository:not_run", "security:not_run", "authority_delta:not_run"]);
  assert.equal(result.evidence.layers.conformance.status, "not_proven");
});

test("agent-generated success cannot replace independent repository evidence", () => {
  const { job, proposal } = context();
  assert.throws(() => verifyMaintenancePatch({ job, proposal, evidence: { agent: { status: "passed" } } }), { code: VERIFICATION_ERROR_CODES.INDEPENDENT_EVIDENCE_REQUIRED });
});

test("verification passes only when every required independent layer passes", () => {
  const { job, proposal } = context();
  const evidence = { syntax: { status: "passed" }, repository: { status: "passed" }, security: { status: "passed" }, authority_delta: { status: "passed" } };
  const result = verifyMaintenancePatch({ job, proposal, evidence, createdAt: "2026-08-25T00:00:00.000Z" });
  assert.equal(result.status, "passed");
  assert.equal(result.verification_status, "passed");
  assert.deepEqual(result.evidence.uncertainty, []);
});
