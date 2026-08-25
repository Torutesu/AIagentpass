import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { planMaintenanceJob, MAINTENANCE_PLANNER_ERROR_CODES } from "../src/maintenance/planner.mjs";

const read = (name) => JSON.parse(fs.readFileSync(new URL(`../../../contracts/fixtures/${name}`, import.meta.url)));
const snapshot = (overrides = {}) => ({
  schema_version: 1, kind: "agentpass.maintenance.repository-snapshot", snapshot_id: "snapshot-1",
  organization_id: "org-1", app_id: "app-1", repository_id: "repo-1", repository_name: "widgets",
  default_branch: "main", base_commit: "commit-1", source_digest: "a".repeat(64),
  captured_at: "2026-08-25T00:00:00.000Z", ...overrides
});
const usage = (overrides = {}) => ({
  ...read("maintenance-usage-attestation.valid.json"), snapshot_id: "snapshot-1", classification: "confirmed",
  source_commit: "commit-1", usages: [{ selector: "GET /v1/widgets", file: "/src/client.ts", line: 12 }], ...overrides
});

test("planner emits stable content-addressed plan and job identities", () => {
  const input = {
    advisory: read("maintenance-advisory-endpoint.valid.json"), snapshot: snapshot(), usage: usage(),
    policy: { ...read("maintenance-policy.valid.json"), generation: 3 }, now: "2026-08-25T00:00:00.000Z"
  };
  const first = planMaintenanceJob(input);
  const second = planMaintenanceJob(input);
  assert.deepEqual(first, second);
  assert.match(first.plan.plan_id, /^plan-[0-9a-f]{32}$/u);
  assert.match(first.job.job_id, /^job-[0-9a-f]{32}$/u);
  assert.deepEqual(first.plan.files, ["/src/client.ts"]);
  assert.deepEqual(first.plan.authority.operations, ["read_source", "write_patch", "run_tests", "create_draft_pr"]);
  assert.equal(first.job.plan_digest, first.plan.plan_digest);
});

test("planner binds advisory, snapshot, usage, policy, branch and exact paths", () => {
  const base = {
    advisory: read("maintenance-advisory-endpoint.valid.json"), snapshot: snapshot(), usage: usage(),
    policy: read("maintenance-policy.valid.json"), now: "2026-08-25T00:00:00.000Z"
  };
  for (const [field, value] of [["provider_id", "other.api"], ["organization_id", "org-2"]]) {
    const bad = { ...base, usage: { ...base.usage, [field]: value } };
    assert.throws(() => planMaintenanceJob(bad), { code: MAINTENANCE_PLANNER_ERROR_CODES.BINDING_MISMATCH });
  }
  assert.throws(() => planMaintenanceJob({ ...base, usage: { ...base.usage, classification: "possible" } }), { code: MAINTENANCE_PLANNER_ERROR_CODES.NO_ACTION });
  assert.throws(() => planMaintenanceJob({ ...base, usage: { ...base.usage, usages: [{ selector: "GET /v1/widgets", file: "/secret.ts", line: 1 }] } }), { code: MAINTENANCE_PLANNER_ERROR_CODES.POLICY_DENIED });
});

test("notify policy never receives patch or PR authority", () => {
  const result = planMaintenanceJob({
    advisory: read("maintenance-advisory-endpoint.valid.json"), snapshot: snapshot(), usage: usage(),
    policy: { ...read("maintenance-policy.valid.json"), mode: "notify" }, now: "2026-08-25T00:00:00.000Z"
  });
  assert.equal(result.decision, "notify");
  assert.deepEqual(result.plan.authority.operations, ["read_source"]);
});

test("expired policy and withdrawn advisory fail closed", () => {
  const input = {
    advisory: read("maintenance-advisory-endpoint.valid.json"), snapshot: snapshot(), usage: usage(),
    policy: read("maintenance-policy.valid.json"), now: "2026-10-01T00:00:00.000Z"
  };
  assert.throws(() => planMaintenanceJob(input), { code: MAINTENANCE_PLANNER_ERROR_CODES.POLICY_DENIED });
  assert.throws(() => planMaintenanceJob({ ...input, now: "2026-08-25T00:00:00.000Z", advisory: { ...input.advisory, event: "withdrawal" } }), { code: MAINTENANCE_PLANNER_ERROR_CODES.NO_ACTION });
});
