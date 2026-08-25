import {
  canonicalDigest,
  normalizeDeploymentReceipt,
  normalizePublishPlan,
  normalizeSourceBundleStatement,
} from "../../../../packages/small-software-contracts/src/index.mjs";
import { SmallSoftwareError, SMALL_SOFTWARE_ERROR_CODES } from "./errors.mjs";
import { smallSoftwareProvider, smallSoftwareRepository, smallSoftwareUuid, smallSoftwareClock, smallSoftwareWorkflowRepository } from "./interfaces.mjs";
import { createSmallSoftwareBuildService } from "./build-service.mjs";
import { createSmallSoftwareSourceStorage } from "./source-storage.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SECRET_FIELD = /(secret|token|password|private.?key|api.?key|authorization|cookie|credential)/i;
const fail = (code, details) => { throw new SmallSoftwareError(code, details); };

/**
 * Orchestrates the cloud-owned source -> build -> plan -> deployment receipt
 * lifecycle. The source store, runner, and runtime provider are explicit
 * boundaries: this module contains no provider SDK calls, credentials, or
 * deployment implementation.
 */
export function createSmallSoftwareOrchestrationService({
  repository,
  sourceStorage,
  buildRunner,
  runtimeProvider,
  clock,
  uuid,
  profile = "hosted",
} = {}) {
  if (!uuid || typeof uuid.randomUUID !== "function" || !clock || typeof clock.now !== "function") fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  const repo = smallSoftwareRepository(repository);
  const workflowRepo = smallSoftwareWorkflowRepository(repository);
  const source = createSmallSoftwareSourceStorage({ storage: sourceStorage, profile });
  const build = createSmallSoftwareBuildService({ runner: buildRunner, clock, uuid, profile });
  const provider = smallSoftwareProvider(runtimeProvider);
  const time = smallSoftwareClock(clock);
  const ids = smallSoftwareUuid(uuid);

  return Object.freeze({
    preparePreview: (input) => run(input),
    orchestratePreview: (input) => run(input),
    publishPreview: (input) => run(input),
  });

  async function run(input = {}) {
    const request = normalizeRequest(input);
    const requestDigest = canonicalDigest(request.digest_preimage);
    let workflow = await loadWorkflow(request);
    if (workflow !== undefined && workflow !== null) {
      if (workflow.request_digest !== requestDigest) fail(SMALL_SOFTWARE_ERROR_CODES.IDEMPOTENCY_CONFLICT, { field: "idempotency_key" });
      if (workflow.state === "complete" && workflow.deployment_receipt) return resultFromWorkflow(workflow);
    } else {
      workflow = {
        version: 1,
        organization_id: request.organization_id,
        app_id: request.app_id,
        idempotency_key: request.idempotency_key,
        request_digest: requestDigest,
        state: "source_pending",
      };
      await saveWorkflow(workflow);
    }

    await assertApplicationTenant(request);
    const sourceDigest = canonicalDigest(request.source_bundle);
    if (workflow.source_bundle_digest && workflow.source_bundle_digest !== sourceDigest) fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "source_bundle_digest" });
    if (!workflow.source_bundle_digest) {
      if (request.source_bytes === undefined) await source.getBundle(sourceDigest);
      else await source.putBundle({ statement: request.source_bundle, bytes: request.source_bytes });
      workflow = await advance(workflow, { state: "source_ready", source_bundle_digest: sourceDigest });
    }

    let buildReceipt;
    if (workflow.build_receipt) {
      buildReceipt = workflow.build_receipt;
    } else {
      const reservation = workflow.build_operation_id
        ? { operationId: workflow.build_operation_id }
        : await build.reserve({
          operation_id: ids.randomUUID(),
          organization_id: request.organization_id,
          app_id: request.app_id,
          source_bundle_digest: sourceDigest,
          request_digest: requestDigest,
        });
      workflow = await advance(workflow, { state: "build_pending", build_operation_id: reservation.operationId });
      try {
        buildReceipt = await build.inspect(reservation.operationId, sourceDigest);
      } catch (error) {
        if (error instanceof SmallSoftwareError && error.code === SMALL_SOFTWARE_ERROR_CODES.OPERATION_NOT_FOUND) {
          buildReceipt = await build.reconcile(reservation.operationId, sourceDigest);
        } else throw error;
      }
      const persisted = await repo.saveBuildReceipt(request.app_id, buildReceipt);
      if (persisted && typeof persisted === "object") buildReceipt = persisted;
      workflow = await advance(workflow, {
        state: "build_ready",
        build_receipt: buildReceipt,
        build_receipt_digest: canonicalDigest(buildReceipt),
      });
    }
    if (buildReceipt.source_bundle_digest !== sourceDigest) fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "build_receipt.source_bundle_digest" });
    const buildDigest = canonicalDigest(buildReceipt);

    let plan;
    if (workflow.publish_plan) {
      plan = workflow.publish_plan;
    } else {
      plan = makePlan(request.publish_plan, request, sourceDigest, buildDigest, buildReceipt.artifact_digest, ids.randomUUID(), time.now());
      if (plan.source_bundle_digest !== sourceDigest || plan.build_receipt_digest !== buildDigest || plan.artifact_digest !== buildReceipt.artifact_digest) fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "publish_plan" });
      await repo.savePublishPlan(plan);
      workflow = await advance(workflow, { state: "plan_ready", publish_plan: plan, publish_plan_digest: canonicalDigest(plan) });
    }
    const planDigest = canonicalDigest(plan);

    let deploymentReceipt;
    if (workflow.deployment_receipt) {
      deploymentReceipt = workflow.deployment_receipt;
    } else {
      const deploymentOperationId = workflow.deployment_operation_id ?? ids.randomUUID();
      workflow = await advance(workflow, { state: "deployment_pending", deployment_operation_id: deploymentOperationId });
      let reserved;
      try {
        reserved = await provider.reserveOperation({
          operationId: deploymentOperationId,
          operation_id: deploymentOperationId,
          kind: "preview-deployment",
          organization_id: request.organization_id,
          app_id: request.app_id,
          release_id: plan.release_id,
          request_digest: planDigest,
          idempotency_key: request.idempotency_key,
        });
      } catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, { stage: "deployment" }); }
      // Reservation is intentionally not treated as provider success.
      if (reserved === undefined || reserved === null) fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, { stage: "deployment" });
      let observed;
      try { observed = await provider.inspectOperation(deploymentOperationId); }
      catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, { stage: "deployment" }); }
      if (observed === undefined || observed === null) fail(SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED, { stage: "deployment" });
      let reconciled;
      try { reconciled = await provider.reconcileOperation(deploymentOperationId); }
      catch { fail(SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED, { stage: "deployment" }); }
      if (reconciled === undefined || reconciled === null) fail(SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED, { stage: "deployment" });
      deploymentReceipt = makeDeploymentReceipt(reconciled, plan, request, deploymentOperationId, ids.randomUUID(), time.now());
      await repo.saveDeploymentReceipt(deploymentReceipt);
      workflow = await advance(workflow, { state: deploymentReceipt.state === "active" ? "complete" : "reconciliation_required", deployment_receipt: deploymentReceipt, deployment_receipt_digest: canonicalDigest(deploymentReceipt) });
    }
    if (deploymentReceipt.publish_plan_digest !== planDigest || deploymentReceipt.artifact_digest !== plan.artifact_digest) fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "deployment_receipt" });
    if (deploymentReceipt.state !== "active") fail(SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED, { stage: "deployment" });
    return resultFromWorkflow({ ...workflow, state: "complete", publish_plan: plan, build_receipt: buildReceipt, deployment_receipt: deploymentReceipt });
  }

  async function loadWorkflow(request) {
    try { return await workflowRepo.getWorkflow({ organization_id: request.organization_id, app_id: request.app_id, idempotency_key: request.idempotency_key }); }
    catch { fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE); }
  }

  async function saveWorkflow(value) {
    try { return (await workflowRepo.saveWorkflow(value)) ?? value; }
    catch { fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE); }
  }

  async function advance(workflow, fields) {
    return saveWorkflow(Object.freeze({ ...workflow, ...fields }));
  }

  async function assertApplicationTenant(request) {
    let app;
    try { app = await repo.getApplication(request.app_id); }
    catch { fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE); }
    if (app && app.organization_id !== undefined && app.organization_id !== request.organization_id) fail(SMALL_SOFTWARE_ERROR_CODES.CONFLICT, { field: "organization_id" });
    return app;
  }
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
  for (const [key, value] of Object.entries(input)) {
    if (SECRET_FIELD.test(key) || containsSecretKey(value)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "secret_like_input" });
  }
  const organizationId = input.organization_id;
  const appId = input.app_id;
  if (!UUID.test(organizationId ?? "") || !UUID.test(appId ?? "")) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "tenant_identity" });
  if (typeof input.idempotency_key !== "string" || !IDEMPOTENCY.test(input.idempotency_key)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "idempotency_key" });
  let sourceBundle;
  try { sourceBundle = normalizeSourceBundleStatement(input.source_bundle); }
  catch { fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "source_bundle" }); }
  if (sourceBundle.organization_id !== organizationId || sourceBundle.app_id !== appId) fail(SMALL_SOFTWARE_ERROR_CODES.CONFLICT, { field: "source_bundle.identity" });
  if (input.source_bytes !== undefined && !(input.source_bytes instanceof Uint8Array || Buffer.isBuffer(input.source_bytes))) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "source_bytes" });
  const digestPreimage = { organization_id: organizationId, app_id: appId, idempotency_key: input.idempotency_key, source_bundle: sourceBundle, publish_plan: input.publish_plan ?? null };
  return { organization_id: organizationId, app_id: appId, idempotency_key: input.idempotency_key, source_bundle: sourceBundle, source_bytes: input.source_bytes, publish_plan: input.publish_plan, digest_preimage: digestPreimage };
}

function makePlan(input, request, sourceDigest, buildDigest, artifactDigest, releaseId, now) {
  const candidate = input ?? {
    version: 1,
    kind: "agentpass.publish-plan",
    organization_id: request.organization_id,
    app_id: request.app_id,
    release_id: releaseId,
    source_bundle_digest: sourceDigest,
    build_receipt_digest: buildDigest,
    artifact_digest: artifactDigest,
    audience: "self",
    lifetime_seconds: 86400,
    approval_required: false,
    risk_classification: "low",
    created_at: now,
  };
  let plan;
  try { plan = normalizePublishPlan(candidate); }
  catch { fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "publish_plan" }); }
  if (plan.organization_id !== request.organization_id || plan.app_id !== request.app_id) fail(SMALL_SOFTWARE_ERROR_CODES.CONFLICT, { field: "publish_plan.identity" });
  return plan;
}

function makeDeploymentReceipt(observed, plan, request, operationId, orchestratorId, now) {
  const source = observed.receipt ?? observed.deployment_receipt ?? (observed.kind === "agentpass.deployment-receipt" ? observed : undefined);
  const candidate = source ?? {
    version: 1,
    kind: "agentpass.deployment-receipt",
    organization_id: request.organization_id,
    app_id: request.app_id,
    release_id: plan.release_id,
    publish_plan_digest: canonicalDigest(plan),
    artifact_digest: plan.artifact_digest,
    runtime_provider: observed.runtime_provider ?? observed.provider ?? "test-runtime",
    provider_deployment_id: observed.provider_deployment_id ?? observed.deployment_id ?? operationId,
    ...(observed.provider_version_id ? { provider_version_id: observed.provider_version_id } : {}),
    ...(observed.route ? { route: observed.route } : {}),
    active_generation: observed.active_generation ?? 1,
    orchestrator_id: orchestratorId,
    started_at: observed.started_at ?? now,
    finished_at: observed.finished_at ?? now,
    state: observed.state === "active" || observed.state === "succeeded" || observed.state === "committed"
      ? "active"
      : observed.state === "failed" ? "failed" : "reconciliation_required",
    ...(observed.reconciliation_digest ? { reconciliation_digest: observed.reconciliation_digest } : {}),
  };
  let receipt;
  try { receipt = normalizeDeploymentReceipt(candidate); }
  catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, { stage: "deployment_receipt" }); }
  if (receipt.organization_id !== request.organization_id || receipt.app_id !== request.app_id || receipt.release_id !== plan.release_id) fail(SMALL_SOFTWARE_ERROR_CODES.CONFLICT, { field: "deployment_receipt.identity" });
  return receipt;
}

function resultFromWorkflow(workflow) {
  return Object.freeze({
    state: workflow.state,
    organization_id: workflow.organization_id,
    app_id: workflow.app_id,
    idempotency_key: workflow.idempotency_key,
    source_bundle_digest: workflow.source_bundle_digest,
    build_receipt: workflow.build_receipt,
    publish_plan: workflow.publish_plan,
    deployment_receipt: workflow.deployment_receipt,
  });
}

function containsSecretKey(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(containsSecretKey);
  return Object.entries(value).some(([key, child]) => SECRET_FIELD.test(key) || containsSecretKey(child));
}
