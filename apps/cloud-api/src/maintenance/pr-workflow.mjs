import {
  canonicalJson,
  sha256,
  validateMaintenanceJob,
  validateMaintenancePlan,
  validateMaintenanceResult
} from "../../../../packages/maintenance-contracts/src/index.mjs";

/**
 * The PR adapter is deliberately an intent adapter.  It produces the exact
 * data that a separately authorised GitHub worker may submit, but it never
 * opens a network connection, accepts a token, or treats a provider response
 * as proof of success.
 */
export const PR_WORKFLOW_STATES = Object.freeze([
  "awaiting_approval", "pr_create_intent", "uncertain", "reconcile_required", "reconciled"
]);

export const PR_WORKFLOW_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "maintenance.pr_workflow.invalid_input",
  BINDING_MISMATCH: "maintenance.pr_workflow.binding_mismatch",
  POLICY_DENIED: "maintenance.pr_workflow.policy_denied",
  CHECKS_FAILED: "maintenance.pr_workflow.checks_failed",
  APPROVAL_REQUIRED: "maintenance.pr_workflow.approval_required",
  OPERATION_UNCERTAIN: "maintenance.pr_workflow.operation_uncertain",
  RECONCILIATION_REQUIRED: "maintenance.pr_workflow.reconciliation_required"
});

export class MaintenancePrWorkflowError extends Error {
  constructor(code, message) { super(message); this.name = "MaintenancePrWorkflowError"; this.code = code; }
}

const fail = (code, message) => { throw new MaintenancePrWorkflowError(code, message); };
const DIGEST = /^[0-9a-f]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const BRANCH = /^agentpass\/maintenance\/(job-[A-Za-z0-9._:/-]{1,120})\/([0-9a-f]{16})$/u;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const CHECK_STATUSES = new Set(["completed"]);
const CHECK_CONCLUSIONS = new Set(["success"]);
const PROVIDER_STATES = new Set(["draft", "open", "closed", "merged", "not_found", "unknown"]);

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, `${label} must be an object`);
  return value;
}

function string(value, label, max = 2048) {
  if (typeof value !== "string" || value.length === 0 || value.length > max || /[\0\n\r]/u.test(value)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, `${label} is invalid`);
  return value;
}

function text(value, label, max) {
  if (typeof value !== "string" || value.length > max || /[\0\n\r]/u.test(value)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, `${label} is invalid`);
  return value;
}

function id(value, label) {
  if (typeof value !== "string" || !ID.test(value)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, `${label} is invalid`);
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, `${label} is invalid`);
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string" || !TS.test(value) || Number.isNaN(Date.parse(value))) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, `${label} is invalid`);
  return value;
}

function validateDateOrder(issuedAt, expiresAt, code = PR_WORKFLOW_ERROR_CODES.INVALID_INPUT) {
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) fail(code, "expiry must be after issuance");
}

function validateWorkflowInputs({ job, plan, result }) {
  // result_digest is an adapter-level binding; older maintenance result
  // records remain valid without it, so omit it from the base contract call.
  const { result_digest: _resultDigest, ...contractResult } = result ?? {};
  try { validateMaintenanceJob(job); validateMaintenancePlan(plan); validateMaintenanceResult(contractResult); }
  catch { fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "maintenance workflow input is invalid"); }
  if (job.organization_id !== plan.organization_id || job.repository_id !== plan.repository_id || job.plan_id !== plan.plan_id || job.plan_digest !== plan.plan_digest) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "job and plan bindings do not match");
  if (result.job_id !== undefined && result.job_id !== job.job_id) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "result job binding does not match");
  if (result.organization_id !== job.organization_id) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "result organization binding does not match");
  if (result.status !== "passed" || result.verification_status !== "passed") fail(PR_WORKFLOW_ERROR_CODES.CHECKS_FAILED, "patch result is not verified");
  if (!result.source_commit || result.source_commit !== plan.base_commit) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "result source commit does not match the plan base");
  if (!result.result_commit || !result.result_tree || !result.patch_digest) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "result commit, tree, and patch digest are required");
  digest(result.patch_digest, "patch_digest");
  if (!Array.isArray(result.changed_paths) || result.changed_paths.length === 0 || result.changed_paths.length > 256) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "changed_paths must be bounded and non-empty");
  if (result.result_digest !== undefined && result.result_digest !== resultBindingDigest({ job, plan, result })) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "result digest does not bind the patch result");
  return { job, plan, result };
}

/** A deterministic branch name, scoped to the durable job and patch digest. */
export function maintenanceBranchName({ job, patchDigest } = {}) {
  object(job, "job");
  id(job.job_id, "job_id");
  digest(patchDigest, "patch_digest");
  const branch = `agentpass/maintenance/${job.job_id}/${patchDigest.slice(0, 16)}`;
  if (!BRANCH.test(branch)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "derived branch name is invalid");
  return branch;
}

export const deriveMaintenanceBranch = maintenanceBranchName;

/**
 * Check-run evidence is copied into the intent as data.  A check is passing
 * only when it is completed, successful, and points at this exact result
 * commit.  Queued/in-progress/neutral/skipped checks cannot open the gate.
 */
export function validateCheckRunEvidence(checkRuns, { headCommit } = {}) {
  if (!Array.isArray(checkRuns) || checkRuns.length === 0 || checkRuns.length > 64) fail(PR_WORKFLOW_ERROR_CODES.CHECKS_FAILED, "check-run evidence is required and bounded");
  const seenIds = new Set();
  const seenNames = new Set();
  const normalized = checkRuns.map((run) => {
    const value = object(run, "check run");
    const checkRunId = id(value.check_run_id, "check_run_id");
    const name = string(value.name, "check run name", 200);
    if (seenIds.has(checkRunId) || seenNames.has(name)) fail(PR_WORKFLOW_ERROR_CODES.CHECKS_FAILED, "check-run IDs and names must be unique");
    seenIds.add(checkRunId); seenNames.add(name);
    if (!CHECK_STATUSES.has(value.status) || !CHECK_CONCLUSIONS.has(value.conclusion)) fail(PR_WORKFLOW_ERROR_CODES.CHECKS_FAILED, "all check runs must be completed successfully");
    if (headCommit !== undefined && value.head_commit !== headCommit) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "check-run head commit does not match result commit");
    string(value.head_commit, "check run head commit", 256);
    timestamp(value.completed_at, "check run completed_at");
    digest(value.output_digest, "check run output_digest");
    if (value.details_url !== undefined) string(value.details_url, "check run details_url", 2048);
    return Object.freeze({ check_run_id: checkRunId, name, status: value.status, conclusion: value.conclusion, head_commit: value.head_commit, completed_at: value.completed_at, output_digest: value.output_digest, ...(value.details_url === undefined ? {} : { details_url: value.details_url }) });
  });
  return Object.freeze(normalized);
}

export const checkRunEvidenceDigest = (checkRuns, options = {}) => sha256(validateCheckRunEvidence(checkRuns, options));

function resultBindingDigest({ job, plan, result }) {
  return sha256({
    schema_version: 1,
    job_id: job.job_id,
    organization_id: job.organization_id,
    plan_digest: plan.plan_digest,
    source_commit: result.source_commit,
    result_commit: result.result_commit,
    result_tree: result.result_tree,
    patch_digest: result.patch_digest,
    changed_paths: result.changed_paths
  });
}

export const maintenanceResultBindingDigest = resultBindingDigest;

function approvalPreimage(approval) {
  return {
    schema_version: 1,
    approval_id: approval.approval_id,
    job_id: approval.job_id,
    organization_id: approval.organization_id,
    plan_digest: approval.plan_digest,
    patch_digest: approval.patch_digest,
    decision: approval.decision,
    approved_at: approval.approved_at,
    expires_at: approval.expires_at
  };
}

function validateApproval(approval, { job, plan, result, now }) {
  const value = object(approval, "approval");
  id(value.approval_id, "approval_id");
  if (value.job_id !== job.job_id || value.organization_id !== job.organization_id || value.plan_digest !== plan.plan_digest || value.patch_digest !== result.patch_digest) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "approval is not bound to this patch");
  if (value.decision !== "approved") fail(PR_WORKFLOW_ERROR_CODES.APPROVAL_REQUIRED, "approval decision is not approved");
  timestamp(value.approved_at, "approved_at"); timestamp(value.expires_at, "expires_at");
  validateDateOrder(value.approved_at, value.expires_at);
  timestamp(now, "now");
  if (Date.parse(value.expires_at) <= Date.parse(now)) fail(PR_WORKFLOW_ERROR_CODES.APPROVAL_REQUIRED, "approval is expired");
  digest(value.approval_digest, "approval_digest");
  if (value.approval_digest !== sha256(approvalPreimage(value))) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "approval digest does not match its statement");
  return Object.freeze({ ...approvalPreimage(value), approval_digest: value.approval_digest });
}

function authorityAllowsDraftPr(plan) {
  if (!Array.isArray(plan.authority?.operations) || !plan.authority.operations.includes("create_draft_pr")) fail(PR_WORKFLOW_ERROR_CODES.POLICY_DENIED, "plan does not grant draft PR creation");
}

function intentPreimage({ job, plan, result, branch, checks, approval, title, body, createdAt }) {
  return {
    schema_version: 1,
    job_id: job.job_id,
    organization_id: job.organization_id,
    repository_id: job.repository_id,
    plan_digest: plan.plan_digest,
    source_commit: result.source_commit,
    result_commit: result.result_commit,
    result_tree: result.result_tree,
    patch_digest: result.patch_digest,
    result_digest: resultBindingDigest({ job, plan, result }),
    changed_paths: result.changed_paths,
    check_runs_digest: sha256(checks),
    approval_id: approval.approval_id,
    base_branch: plan.branch,
    head_branch: branch,
    title,
    body,
    draft: true,
    created_at: createdAt
  };
}

/**
 * Build a provider-neutral draft PR creation intent.  The returned object has
 * no external number or URL because no GitHub operation has happened yet.
 */
export function buildDraftPullRequestIntent({ job, plan, result, checkRuns, approval, title, body = "", now } = {}) {
  validateWorkflowInputs({ job, plan, result });
  authorityAllowsDraftPr(plan);
  const checks = validateCheckRunEvidence(checkRuns, { headCommit: result.result_commit });
  const branch = maintenanceBranchName({ job, patchDigest: result.patch_digest });
  string(title, "title", 256); text(body, "body", 32_768);
  const createdAt = now ?? new Date().toISOString();
  timestamp(createdAt, "now");
  if (!approval) fail(PR_WORKFLOW_ERROR_CODES.APPROVAL_REQUIRED, "explicit approval is required before draft PR creation");
  const approved = validateApproval(approval, { job, plan, result, now: createdAt });
  const preimage = intentPreimage({ job, plan, result, branch, checks, approval: approved, title, body, createdAt });
  const requestDigest = sha256(preimage);
  const intent = Object.freeze({
    schema_version: 1,
    kind: "agentpass.maintenance.pull-request-intent",
    intent_id: `intent-${requestDigest.slice(0, 32)}`,
    job_id: job.job_id,
    organization_id: job.organization_id,
    repository_id: job.repository_id,
    base_branch: plan.branch,
    head_branch: branch,
    base_commit: plan.base_commit,
    head_commit: result.result_commit,
    plan_digest: plan.plan_digest,
    patch_digest: result.patch_digest,
    result_digest: preimage.result_digest,
    changed_paths: Object.freeze([...result.changed_paths]),
    check_runs_digest: preimage.check_runs_digest,
    approval_id: approved.approval_id,
    title,
    body,
    draft: true,
    request_digest: requestDigest,
    state: "pr_create_intent",
    created_at: createdAt
  });
  return intent;
}

export const createDraftPullRequestIntent = buildDraftPullRequestIntent;

/** Evaluate the gate without throwing when human approval is still pending. */
export function evaluateDraftPullRequest({ job, plan, result, checkRuns, title, body = "", now, approval } = {}) {
  validateWorkflowInputs({ job, plan, result });
  authorityAllowsDraftPr(plan);
  const checks = validateCheckRunEvidence(checkRuns, { headCommit: result.result_commit });
  const branch = maintenanceBranchName({ job, patchDigest: result.patch_digest });
  string(title, "title", 256); text(body, "body", 32_768);
  const createdAt = now ?? new Date().toISOString(); timestamp(createdAt, "now");
  if (!approval) return Object.freeze({ state: "awaiting_approval", branch, check_runs_digest: sha256(checks), patch_digest: result.patch_digest, result_digest: resultBindingDigest({ job, plan, result }), approval_required: true });
  return Object.freeze({ state: "pr_create_intent", intent: buildDraftPullRequestIntent({ job, plan, result, checkRuns: checks, approval, title, body, now: createdAt }) });
}

export function markPullRequestOperationUncertain({ operationId, requestDigest, jobId, organizationId, now, reason = "provider response was lost" } = {}) {
  id(operationId, "operation_id"); digest(requestDigest, "request_digest"); id(jobId, "job_id"); id(organizationId, "organization_id"); timestamp(now, "now"); string(reason, "reason", 512);
  return Object.freeze({ schema_version: 1, kind: "agentpass.maintenance.pull-request-operation", operation_id: operationId, request_digest: requestDigest, job_id: jobId, organization_id: organizationId, state: "uncertain", reason, occurred_at: now, retry_allowed: false });
}

export const uncertainPullRequestOperation = markPullRequestOperationUncertain;

/**
 * Reconcile an uncertain provider operation.  A missing/unknown observation
 * remains reconcile_required; it never authorises a blind second create.
 */
export function reconcilePullRequestOperation({ uncertain, observation, now } = {}) {
  const pending = object(uncertain, "uncertain operation");
  if (pending.state !== "uncertain") fail(PR_WORKFLOW_ERROR_CODES.RECONCILIATION_REQUIRED, "operation is not uncertain");
  id(pending.operation_id, "operation_id"); digest(pending.request_digest, "request_digest");
  const seen = object(observation, "provider observation");
  if (seen.operation_id !== pending.operation_id || seen.request_digest !== pending.request_digest) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "reconciliation observation does not match the uncertain operation");
  if (!PROVIDER_STATES.has(seen.provider_state)) fail(PR_WORKFLOW_ERROR_CODES.RECONCILIATION_REQUIRED, "provider state is not reconcilable");
  timestamp(seen.observed_at, "observed_at"); timestamp(now, "now");
  if (Date.parse(seen.observed_at) > Date.parse(now)) fail(PR_WORKFLOW_ERROR_CODES.RECONCILIATION_REQUIRED, "observation is from the future");
  if (seen.provider_state === "unknown" || seen.provider_state === "not_found") return Object.freeze({ ...pending, state: "reconcile_required", observed_at: seen.observed_at, provider_state: seen.provider_state, retry_allowed: false, reconciled_at: now });
  digest(seen.response_digest, "response_digest");
  return Object.freeze({ ...pending, state: "reconciled", provider_state: seen.provider_state, response_digest: seen.response_digest, external_number: seen.external_number, url: seen.url, observed_at: seen.observed_at, reconciled_at: now, retry_allowed: false });
}

export const reconcileUncertainPullRequestOperation = reconcilePullRequestOperation;

/**
 * Project a provider-neutral, redacted status for CLI/MCP/Console readers.
 * The projection intentionally excludes PR body, check-run names/URLs, and
 * any provider response payload; only already-bound digests and identifiers
 * cross this read boundary.
 */
export function projectMaintenancePrStatus({ job, plan, workflow, now } = {}) {
  validateWorkflowJobPlan(job, plan);
  const value = object(workflow, "workflow status");
  const state = value.state;
  if (!PR_WORKFLOW_STATES.includes(state)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "workflow state is invalid");
  const updatedAt = now ?? value.reconciled_at ?? value.occurred_at ?? value.created_at;
  timestamp(updatedAt, "updated_at");
  const result = {
    schema_version: 1,
    kind: "agentpass.maintenance.pull-request-status",
    organization_id: job.organization_id,
    job_id: job.job_id,
    repository_id: job.repository_id,
    plan_digest: plan.plan_digest,
    state,
    approval_required: state === "awaiting_approval",
    draft: state === "pr_create_intent" || state === "awaiting_approval",
    retry_allowed: false,
    updated_at: updatedAt
  };
  const branch = value.head_branch ?? value.branch;
  if (branch !== undefined) {
    if (typeof branch !== "string" || !BRANCH.test(branch)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "workflow branch is invalid");
    result.head_branch = branch;
  }
  for (const key of ["patch_digest", "result_digest", "check_runs_digest", "request_digest", "response_digest"]) {
    if (value[key] !== undefined) digest(value[key], key);
    if (value[key] !== undefined) result[key] = value[key];
  }
  if (state === "pr_create_intent") {
    const intent = object(value.intent, "pull-request intent");
    if (intent.job_id !== job.job_id || intent.organization_id !== job.organization_id || intent.repository_id !== job.repository_id || intent.plan_digest !== plan.plan_digest || intent.draft !== true || intent.state !== "pr_create_intent") fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "intent is not bound to the status subject");
    if (intent.base_commit !== plan.base_commit || typeof intent.head_commit !== "string" || intent.head_commit.length === 0) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "intent commit binding is invalid");
    result.base_commit = intent.base_commit;
    result.head_commit = intent.head_commit;
    if (typeof intent.head_branch !== "string" || !BRANCH.test(intent.head_branch)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "intent branch is invalid");
    result.head_branch = intent.head_branch;
    for (const key of ["patch_digest", "result_digest", "check_runs_digest", "request_digest"]) {
      result[key] = digest(intent[key], key);
    }
    result.approval_id = id(intent.approval_id, "approval_id");
    result.intent_id = id(intent.intent_id, "intent_id");
  } else if (state === "uncertain" || state === "reconcile_required" || state === "reconciled") {
    if (value.job_id !== job.job_id || value.organization_id !== job.organization_id) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "operation is not bound to the status subject");
    result.operation_id = id(value.operation_id, "operation_id");
    result.request_digest = digest(value.request_digest, "request_digest");
    if (typeof value.reason === "string") result.uncertainty = value.reason;
    if (state !== "uncertain") {
      if (!PROVIDER_STATES.has(value.provider_state)) fail(PR_WORKFLOW_ERROR_CODES.RECONCILIATION_REQUIRED, "provider state is invalid");
      result.provider_state = value.provider_state;
    }
    if (state === "reconciled") {
      if (value.external_number !== undefined && (!Number.isSafeInteger(value.external_number) || value.external_number < 1)) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "external_number is invalid");
      if (value.url !== undefined && (typeof value.url !== "string" || !/^https:\/\/[^\s\0]{1,2048}$/u.test(value.url))) fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "provider URL is invalid");
      if (value.external_number !== undefined) result.external_number = value.external_number;
      if (value.url !== undefined) result.url = value.url;
    }
  } else {
    result.patch_digest = digest(value.patch_digest, "patch_digest");
    result.result_digest = digest(value.result_digest, "result_digest");
    result.check_runs_digest = digest(value.check_runs_digest, "check_runs_digest");
    result.head_branch = maintenanceBranchName({ job, patchDigest: value.patch_digest });
  }
  return Object.freeze(result);
}

function validateWorkflowJobPlan(job, plan) {
  try { validateMaintenanceJob(job); validateMaintenancePlan(plan); }
  catch { fail(PR_WORKFLOW_ERROR_CODES.INVALID_INPUT, "maintenance status subject is invalid"); }
  if (job.organization_id !== plan.organization_id || job.repository_id !== plan.repository_id || job.plan_id !== plan.plan_id || job.plan_digest !== plan.plan_digest) fail(PR_WORKFLOW_ERROR_CODES.BINDING_MISMATCH, "status subject bindings do not match");
}

export const projectPullRequestStatus = projectMaintenancePrStatus;
export const projectPrWorkflowStatus = projectMaintenancePrStatus;

export function createPullRequestWorkflowAdapter() {
  return Object.freeze({
    branchName: maintenanceBranchName,
    checkRunEvidence: validateCheckRunEvidence,
    checkRunEvidenceDigest,
    resultBindingDigest: maintenanceResultBindingDigest,
    prepare: evaluateDraftPullRequest,
    createDraftPullRequestIntent: buildDraftPullRequestIntent,
    markUncertain: markPullRequestOperationUncertain,
    reconcile: reconcilePullRequestOperation,
    projectStatus: projectMaintenancePrStatus
  });
}

export const createMaintenancePrWorkflowAdapter = createPullRequestWorkflowAdapter;
