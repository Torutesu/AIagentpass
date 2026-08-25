import test from "node:test";
import assert from "node:assert/strict";
import {
  SMALL_SOFTWARE_ERROR_CODES,
  createMemorySmallSoftwareSourceStorage,
  createSmallSoftwareOrchestrationService,
} from "../src/small-software/index.mjs";
import { canonicalDigest } from "../../../packages/small-software-contracts/src/index.mjs";

const ids = [
  "00000000-0000-4000-8000-000000000001",
  "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003",
  "00000000-0000-4000-8000-000000000004",
  "00000000-0000-4000-8000-000000000005",
  "00000000-0000-4000-8000-000000000006",
];
const source = (organization_id = ids[0], app_id = ids[1]) => ({
  version: 1, kind: "agentpass.source-bundle", organization_id, app_id,
  project_id: ids[2], agent_session_id: ids[3], device_id: ids[4],
  file_merkle_root: "a".repeat(64), manifest_digest: "b".repeat(64), total_bytes: 3,
  created_at: "2026-08-25T00:00:00.000Z", expires_at: "2026-08-26T00:00:00.000Z",
});
const clock = { testOnly: true, now: () => "2026-08-25T00:00:01.000Z" };
const uuid = (() => { let i = 0; return { testOnly: true, randomUUID: () => ids[Math.min(i++, ids.length - 1)] }; })();

function makeHarness({ providerResult = { state: "active", provider: "fake-runtime", deployment_id: "deployment-1", active_generation: 1 } } = {}) {
  const workflows = new Map();
  const plans = [];
  const deployments = [];
  const receipts = [];
  const repository = {
    testOnly: true,
    async getApplication() { return { organization_id: ids[0] }; },
    async saveBuildReceipt(_appId, receipt) { receipts.push(receipt); return receipt; },
    async getWorkflow({ idempotency_key }) { return workflows.get(idempotency_key); },
    async saveWorkflow(workflow) { workflows.set(workflow.idempotency_key, workflow); return workflow; },
    async savePublishPlan(plan) { plans.push(plan); return plan; },
    async saveDeploymentReceipt(receipt) { deployments.push(receipt); return receipt; },
  };
  const sourceStorage = createMemorySmallSoftwareSourceStorage();
  const buildRunner = {
    testOnly: true,
    async reserve(request) { this.request = request; return { status: "reserved" }; },
    async inspect() {
      const sourceDigest = this.request.source_bundle_digest;
      return { status: "succeeded", receipt: {
        version: 1, kind: "agentpass.build-receipt", organization_id: ids[0], app_id: ids[1],
        release_id: ids[5], source_bundle_digest: sourceDigest, builder_image_digest: "c".repeat(64),
        sandbox_instance_id: ids[3], artifact_digest: "d".repeat(64), started_at: "2026-08-25T00:00:00.000Z",
        finished_at: "2026-08-25T00:00:01.000Z", result: "succeeded",
      } };
    },
    async reconcile() { return this.inspect(); },
  };
  const runtimeProvider = {
    testOnly: true,
    async reserveOperation() { return { status: "accepted" }; },
    async inspectOperation() { return { state: "accepted" }; },
    async reconcileOperation() { return providerResult; },
  };
  const service = createSmallSoftwareOrchestrationService({ repository, sourceStorage, buildRunner, runtimeProvider, clock, uuid, profile: "test" });
  return { service, repository, workflows, plans, deployments, receipts, sourceStorage };
}

test("orchestrates source, build, plan, and reconciled deployment receipt", async () => {
  const h = makeHarness();
  const result = await h.service.preparePreview({ organization_id: ids[0], app_id: ids[1], idempotency_key: "preview-001", source_bundle: source(), source_bytes: Buffer.from("app") });
  assert.equal(result.state, "complete");
  assert.equal(result.publish_plan.source_bundle_digest, canonicalDigest(result.publish_plan.source_bundle_digest ? source() : source()));
  assert.equal(result.deployment_receipt.state, "active");
  assert.equal(h.plans.length, 1);
  assert.equal(h.deployments.length, 1);
});

test("replaying an idempotency key returns the same receipt and does not deploy twice", async () => {
  const h = makeHarness();
  const request = { organization_id: ids[0], app_id: ids[1], idempotency_key: "preview-002", source_bundle: source(), source_bytes: Buffer.from("app") };
  const first = await h.service.preparePreview(request);
  const second = await h.service.preparePreview(request);
  assert.deepEqual(second.deployment_receipt, first.deployment_receipt);
  assert.equal(h.deployments.length, 1);
});

test("reusing an idempotency key with changed source fails closed", async () => {
  const h = makeHarness();
  const request = { organization_id: ids[0], app_id: ids[1], idempotency_key: "preview-003", source_bundle: source(), source_bytes: Buffer.from("app") };
  await h.service.preparePreview(request);
  await assert.rejects(() => h.service.preparePreview({ ...request, source_bundle: { ...source(), file_merkle_root: "e".repeat(64) } }), (error) => error.code === SMALL_SOFTWARE_ERROR_CODES.IDEMPOTENCY_CONFLICT);
});

test("provider reservation alone cannot produce an active deployment receipt", async () => {
  const h = makeHarness({ providerResult: null });
  await assert.rejects(() => h.service.preparePreview({ organization_id: ids[0], app_id: ids[1], idempotency_key: "preview-004", source_bundle: source(), source_bytes: Buffer.from("app") }), (error) => error.code === SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED);
});
