import assert from "node:assert/strict";
import test from "node:test";
import { sha256 } from "../../../packages/maintenance-contracts/src/index.mjs";
import { planMaintenanceJob } from "../src/maintenance/planner.mjs";
import {
  PR_WORKFLOW_ERROR_CODES,
  buildDraftPullRequestIntent,
  evaluateDraftPullRequest,
  maintenanceResultBindingDigest,
  markPullRequestOperationUncertain,
  reconcilePullRequestOperation
} from "../src/maintenance/pr-workflow.mjs";

const now = "2026-08-25T00:00:00.000Z";
const digest = (letter) => letter.repeat(64);
const base = () => {
  const snapshot = { schema_version: 1, kind: "agentpass.maintenance.repository-snapshot", snapshot_id: "snapshot-1", organization_id: "org-1", app_id: "app-1", repository_id: "repo-1", repository_name: "widgets", default_branch: "main", base_commit: "commit-1", source_digest: digest("a"), captured_at: now };
  const advisory = { schema_version: 1, kind: "agentpass.maintenance.advisory", advisory_id: "advisory-1", provider_id: "sample.api", provider_key_id: "key-1", sequence: 1, event: "publish", severity: "low", published_at: now, effective_at: now, selectors: [{ type: "endpoint", path: "/v1/widgets" }], old_contract_digest: digest("a"), new_contract_digest: digest("b"), signature_algorithm: "ed25519", signature: "A".repeat(86) };
  const usage = { schema_version: 1, kind: "agentpass.maintenance.usage-attestation", attestation_id: "attestation-1", organization_id: "org-1", app_id: "app-1", provider_id: "sample.api", snapshot_id: "snapshot-1", source_digest: digest("a"), observed_at: now, classification: "confirmed", usages: [{ selector: "GET /v1/widgets", file: "/src/client.ts", line: 1 }] };
  const policy = { schema_version: 1, kind: "agentpass.maintenance.policy", policy_id: "policy-1", organization_id: "org-1", mode: "draft_pr", allowed_provider_ids: ["sample.api"], allowed_branches: ["main"], allowed_paths: ["/src"], max_files: 10, expires_at: "2026-08-26T00:00:00.000Z" };
  const planned = planMaintenanceJob({ advisory, snapshot, usage, policy, now });
  const result = { schema_version: 1, kind: "agentpass.maintenance.result", result_id: "result-1", job_id: planned.job.job_id, organization_id: "org-1", source_commit: "commit-1", result_commit: "commit-2", result_tree: "tree-2", patch_digest: digest("c"), changed_paths: ["/src/client.ts"], status: "passed", verification_status: "passed", created_at: now };
  result.result_digest = maintenanceResultBindingDigest({ job: planned.job, plan: planned.plan, result });
  const checkRuns = [{ check_run_id: "check-1", name: "unit", status: "completed", conclusion: "success", head_commit: "commit-2", completed_at: now, output_digest: digest("d") }];
  const approval = { approval_id: "approval-1", job_id: planned.job.job_id, organization_id: "org-1", plan_digest: planned.plan.plan_digest, patch_digest: result.patch_digest, decision: "approved", approved_at: now, expires_at: "2026-08-26T00:00:00.000Z" };
  approval.approval_digest = sha256({ schema_version: 1, approval_id: approval.approval_id, job_id: approval.job_id, organization_id: approval.organization_id, plan_digest: approval.plan_digest, patch_digest: approval.patch_digest, decision: approval.decision, approved_at: approval.approved_at, expires_at: approval.expires_at });
  return { ...planned, result, checkRuns, approval };
};

test("draft PR workflow is approval-gated and binds result/check evidence", () => {
  const value = base();
  const { approval: _approval, ...withoutApproval } = value;
  assert.equal(evaluateDraftPullRequest({ ...withoutApproval, title: "Update API", now }).state, "awaiting_approval");
  const intent = buildDraftPullRequestIntent({ ...value, title: "Update API", now });
  assert.equal(intent.state, "pr_create_intent"); assert.equal(intent.draft, true);
  assert.equal(intent.base_commit, value.plan.base_commit); assert.equal(intent.head_commit, value.result.result_commit);
  assert.equal(Object.hasOwn(intent, "external_number"), false); assert.equal(Object.hasOwn(intent, "url"), false);
  assert.throws(() => buildDraftPullRequestIntent({ ...value, result: { ...value.result, result_digest: digest("e") }, title: "Update API", now }), { code: PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH });
  assert.throws(() => buildDraftPullRequestIntent({ ...value, checkRuns: [{ ...value.checkRuns[0], conclusion: "neutral" }], title: "Update API", now }), { code: PR_WORKFLOW_ERROR_CODES.CHECKS_FAILED });
});

test("uncertain provider response is reconciled without retry authority", () => {
  const uncertain = markPullRequestOperationUncertain({ operationId: "operation-1", requestDigest: digest("f"), jobId: "job-1", organizationId: "org-1", now });
  const pending = reconcilePullRequestOperation({ uncertain, observation: { operation_id: uncertain.operation_id, request_digest: uncertain.request_digest, provider_state: "unknown", observed_at: now }, now });
  assert.equal(pending.state, "reconcile_required"); assert.equal(pending.retry_allowed, false);
  const done = reconcilePullRequestOperation({ uncertain, observation: { operation_id: uncertain.operation_id, request_digest: uncertain.request_digest, provider_state: "draft", response_digest: digest("a"), observed_at: now }, now });
  assert.equal(done.state, "reconciled"); assert.equal(done.retry_allowed, false);
});
