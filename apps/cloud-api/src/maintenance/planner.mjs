import {
  advisoryDigest,
  canonicalJson,
  sha256,
  validateAdvisory,
  validateMaintenanceJob,
  validateMaintenancePlan,
  validateMaintenancePolicy,
  validateRepositorySnapshot,
  validateUsageClassification
} from "../../../../packages/maintenance-contracts/src/index.mjs";

export const MAINTENANCE_PLANNER_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "maintenance.planner.invalid_input",
  POLICY_DENIED: "maintenance.planner.policy_denied",
  NO_ACTION: "maintenance.planner.no_action",
  STALE_USAGE: "maintenance.planner.stale_usage",
  BINDING_MISMATCH: "maintenance.planner.binding_mismatch",
  LIMIT_EXCEEDED: "maintenance.planner.limit_exceeded"
});

export class MaintenancePlannerError extends Error {
  constructor(code, message) { super(message); this.name = "MaintenancePlannerError"; this.code = code; }
}

const fail = (code, message) => { throw new MaintenancePlannerError(code, message); };
const timestamp = (value) => new Date(value).toISOString();
const string = (value, name) => { if (typeof value !== "string" || value.length === 0) fail(MAINTENANCE_PLANNER_ERROR_CODES.INVALID_INPUT, `${name} is invalid`); return value; };

/**
 * Computes a maintenance decision without I/O. The returned plan and job are
 * derived solely from canonical input, so a retry cannot mint a second job.
 * This function deliberately accepts evidence, never source or credentials.
 */
export function planMaintenanceJob({ advisory, snapshot, usage, policy, now = new Date().toISOString(), idempotencyKey = undefined } = {}) {
  try { validateAdvisory(advisory); validateRepositorySnapshot(snapshot); validateUsageClassification(usage); validateMaintenancePolicy(policy); }
  catch (error) { fail(MAINTENANCE_PLANNER_ERROR_CODES.INVALID_INPUT, "maintenance planning input is invalid"); }
  let observedAt;
  try { observedAt = timestamp(now); } catch { fail(MAINTENANCE_PLANNER_ERROR_CODES.INVALID_INPUT, "now is invalid"); }
  if (advisory.event === "withdrawal") fail(MAINTENANCE_PLANNER_ERROR_CODES.NO_ACTION, "withdrawn advisories cannot create maintenance jobs");
  for (const [left, right, label] of [
    [advisory.provider_id, usage.provider_id, "provider"],
    [usage.organization_id, snapshot.organization_id, "organization"],
    [usage.app_id, snapshot.app_id, "app"],
    [usage.source_commit, snapshot.base_commit, "source commit"]
  ]) if (right !== undefined && left !== undefined && left !== right) fail(MAINTENANCE_PLANNER_ERROR_CODES.BINDING_MISMATCH, `${label} binding does not match`);
  if (usage.snapshot_id !== undefined && usage.snapshot_id !== snapshot.snapshot_id) fail(MAINTENANCE_PLANNER_ERROR_CODES.BINDING_MISMATCH, "usage snapshot binding does not match");
  if (policy.organization_id !== snapshot.organization_id) fail(MAINTENANCE_PLANNER_ERROR_CODES.BINDING_MISMATCH, "policy organization binding does not match");
  if (Date.parse(policy.expires_at) <= Date.parse(observedAt)) fail(MAINTENANCE_PLANNER_ERROR_CODES.POLICY_DENIED, "maintenance policy is expired");
  if (!policy.allowed_provider_ids.includes(advisory.provider_id)) fail(MAINTENANCE_PLANNER_ERROR_CODES.POLICY_DENIED, "provider is not allowed by policy");
  const branch = snapshot.branch ?? snapshot.default_branch;
  if (!policy.allowed_branches.includes(branch)) fail(MAINTENANCE_PLANNER_ERROR_CODES.POLICY_DENIED, "branch is not allowed by policy");
  const classification = usage.classification ?? "unknown";
  if (!["confirmed", "probable"].includes(classification)) fail(MAINTENANCE_PLANNER_ERROR_CODES.NO_ACTION, `impact classification ${classification} is not eligible for private-alpha maintenance`);
  const files = [...new Set(usage.usages.map((item) => item.file))].sort();
  if (files.length === 0) fail(MAINTENANCE_PLANNER_ERROR_CODES.NO_ACTION, "usage evidence contains no files");
  if (files.length > policy.max_files) fail(MAINTENANCE_PLANNER_ERROR_CODES.LIMIT_EXCEEDED, "usage evidence exceeds policy file limit");
  for (const file of files) if (!policy.allowed_paths.some((root) => file === root || file.startsWith(`${root.replace(/\/$/u, "")}/`))) fail(MAINTENANCE_PLANNER_ERROR_CODES.POLICY_DENIED, "usage file is outside policy paths");
  const selectorDigests = advisory.selectors.map((selector) => sha256(canonicalJson(selector))).sort();
  const usageDigest = usage.result_digest ?? sha256(usage);
  const preimage = {
    schema_version: 1,
    advisory_digest: advisoryDigest(advisory),
    snapshot_id: snapshot.snapshot_id,
    source_digest: snapshot.source_digest ?? snapshot.base_commit,
    usage_attestation_id: usage.attestation_id,
    usage_digest: usageDigest,
    policy_id: policy.policy_id,
    policy_generation: policy.generation ?? 1,
    branch,
    files,
    classification,
    mode: policy.mode,
    idempotency_key: idempotencyKey ?? null
  };
  const planDigest = sha256(preimage);
  const planId = `plan-${planDigest.slice(0, 32)}`;
  const jobId = `job-${sha256({ ...preimage, plan_digest: planDigest }).slice(0, 32)}`;
  const authority = {
    purpose: "agentpass.maintenance.plan",
    operations: policy.mode === "draft_pr" ? ["read_source", "write_patch", "run_tests", "create_draft_pr"] : ["read_source"]
  };
  const plan = {
    schema_version: 1, kind: "agentpass.maintenance.plan", plan_id: planId,
    organization_id: snapshot.organization_id, app_id: snapshot.app_id, repository_id: snapshot.repository_id,
    branch, advisory_id: advisory.advisory_id, snapshot_id: snapshot.snapshot_id,
    usage_attestation_id: usage.attestation_id, base_commit: snapshot.base_commit,
    active_release_id: snapshot.active_release_id, policy_id: policy.policy_id,
    policy_generation: policy.generation ?? 1, plan_digest: planDigest,
    selector_digests: selectorDigests, files, authority, created_at: observedAt,
    expires_at: policy.expires_at, idempotency_key: idempotencyKey ?? `maintenance-${planDigest}`
  };
  validateMaintenancePlan(plan);
  const job = {
    schema_version: 1, kind: "agentpass.maintenance.job", job_id: jobId,
    organization_id: snapshot.organization_id, app_id: snapshot.app_id, repository_id: snapshot.repository_id,
    branch, provider_id: advisory.provider_id, advisory_id: advisory.advisory_id,
    snapshot_id: snapshot.snapshot_id, usage_attestation_id: usage.attestation_id,
    policy_id: policy.policy_id, policy_generation: policy.generation ?? 1,
    plan_id: planId, plan_digest: planDigest, status: "planned",
    created_at: observedAt, updated_at: observedAt, idempotency_key: plan.idempotency_key
  };
  validateMaintenanceJob(job);
  return Object.freeze({ decision: policy.mode === "notify" ? "notify" : classification, plan: Object.freeze(plan), job: Object.freeze(job), preimage: Object.freeze(preimage) });
}

export const createMaintenanceJobPlan = planMaintenanceJob;
export const createDeterministicMaintenanceJobPlanner = () => Object.freeze({ plan: planMaintenanceJob });
