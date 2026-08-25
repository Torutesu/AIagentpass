import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  PLATFORM_AUTH_QUALIFICATION_KIND,
  PLATFORM_AUTH_SCENARIO_CHECKS,
  PLATFORM_AUTH_SCENARIOS,
  canonicalPlatformAuthQualificationEvidence,
  normalizePlatformAuthQualificationEvidence,
  platformAuthScenarioEvidenceSHA256,
  runPlatformAuthQualification,
  verifyPlatformAuthQualificationEvidence
} from "./platform-auth.mjs";

const SHA = "a".repeat(40);
const TREE = "b".repeat(40);
const RUN_ID = "42";
const JOB_ID = "1002";
const NOW = new Date("2026-08-20T00:00:00.000Z");
const digest = (index) => String(index + 1).repeat(64).slice(0, 64);
const DEPLOYMENT_DIGESTS = { primary: digest(0), secondary: digest(1) };

function probe({ failScenario } = {}) {
  return async ({ name, source_tree: sourceTree, run_id: runId, job_id: jobId, expected_deployment_digest: deploymentDigest }) => ({
    name,
    source_commit: SHA,
    deployment_digest: deploymentDigest,
    scenarios: PLATFORM_AUTH_SCENARIOS.map((scenario, index) => {
      const status = scenario === failScenario ? "failed" : "passed";
      if (!["rotation", "resilience"].includes(scenario)) {
        return { scenario, status, evidence_sha256: digest(index + (name === "primary" ? 2 : 3)) };
      }
      const evidence = {
        schema_version: 1,
        kind: `${PLATFORM_AUTH_QUALIFICATION_KIND}-scenario`,
        scenario,
        status,
        instance: name,
        source_commit: SHA,
        source_tree: sourceTree,
        deployment_digest: deploymentDigest,
        run_id: runId,
        job_id: jobId,
        started_at: NOW.toISOString(),
        completed_at: NOW.toISOString(),
        checks: PLATFORM_AUTH_SCENARIO_CHECKS[scenario].map((check_id) => ({
          check_id,
          status,
          expected: { type: "boolean", value: true },
          result: { type: "boolean", value: status === "passed" }
        }))
      };
      return { scenario, status, evidence, evidence_sha256: platformAuthScenarioEvidenceSHA256(evidence) };
    })
  });
}

test("returns not_run unless production Platform qualification is explicitly armed", async () => {
  const result = await runPlatformAuthQualification({ env: {}, now: () => NOW, instanceProbe: probe() });
  assert.equal(result.status, "not_run");
  assert.equal(result.qualified, false);
  assert.equal(result.reason, "provider_not_configured");
});

test("qualifies exactly two instances and seven redacted scenarios", async () => {
  const result = await runPlatformAuthQualification({
    env: { AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true" },
    sourceCommit: SHA,
    sourceTree: TREE,
    expectedDeploymentDigests: DEPLOYMENT_DIGESTS,
    runId: RUN_ID,
    jobId: JOB_ID,
    now: () => NOW,
    instanceProbe: probe()
  });
  assert.equal(result.kind, PLATFORM_AUTH_QUALIFICATION_KIND);
  assert.equal(result.status, "passed");
  assert.equal(result.qualified, true);
  assert.deepEqual(result.instances.map((item) => item.name), ["primary", "secondary"]);
  assert.equal(result.instances[0].scenarios.length, 7);
  assert.deepEqual(result.instances[0].scenarios.find((item) => item.scenario === "rotation").evidence.checks.map((item) => item.check_id), PLATFORM_AUTH_SCENARIO_CHECKS.rotation);
  const secondaryResilience = result.instances[1].scenarios.find((item) => item.scenario === "resilience").evidence;
  assert.deepEqual({
    instance: secondaryResilience.instance,
    deployment_digest: secondaryResilience.deployment_digest,
    run_id: secondaryResilience.run_id,
    job_id: secondaryResilience.job_id
  }, { instance: "secondary", deployment_digest: DEPLOYMENT_DIGESTS.secondary, run_id: RUN_ID, job_id: JOB_ID });
  assert.doesNotMatch(JSON.stringify(result), /private|secret|token|assertion|credential/iu);
  assert.deepEqual(verifyPlatformAuthQualificationEvidence(Buffer.from(canonicalJson(result)), {
    expectedSourceCommit: SHA, expectedSourceTree: TREE, expectedDeploymentDigests: DEPLOYMENT_DIGESTS, expectedRunId: RUN_ID, expectedJobId: JOB_ID
  }).status, "passed");
});

test("fails closed on scenario failure, source mismatch, missing scenarios, and unknown fields", async () => {
  const failed = await runPlatformAuthQualification({
    env: { AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true" }, sourceCommit: SHA, sourceTree: TREE, expectedDeploymentDigests: DEPLOYMENT_DIGESTS, runId: RUN_ID, jobId: JOB_ID, now: () => NOW,
    instanceProbe: probe({ failScenario: "rotation" })
  });
  assert.equal(failed.status, "failed");
  assert.equal(failed.qualified, false);
  assert.equal(failed.reason, "scenario_failed");
  assert.equal(verifyPlatformAuthQualificationEvidence(failed, {
    expectedSourceCommit: SHA, expectedSourceTree: TREE, expectedDeploymentDigests: DEPLOYMENT_DIGESTS, expectedRunId: RUN_ID, expectedJobId: JOB_ID
  }).status, "failed");
  assert.throws(() => verifyPlatformAuthQualificationEvidence(failed, { expectedSourceCommit: "b".repeat(40) }));
  assert.throws(() => normalizePlatformAuthQualificationEvidence({ ...failed, leaked_secret: "nope" }));
  assert.throws(() => normalizePlatformAuthQualificationEvidence({ ...failed, instances: failed.instances.map((instance) => ({ ...instance, source_commit: "c".repeat(40) })) }));
  assert.throws(() => normalizePlatformAuthQualificationEvidence({ ...failed, status: "passed", qualified: true, reason: null, instances: [] }));
  assert.throws(() => normalizePlatformAuthQualificationEvidence({ ...failed, reason: null }));
  assert.throws(() => normalizePlatformAuthQualificationEvidence({ ...failed, instances: [], reason: null }));
  assert.throws(() => normalizePlatformAuthQualificationEvidence({
    ...failed,
    instances: failed.instances.map((instance) => ({
      ...instance,
      scenarios: instance.scenarios.map((scenario) => scenario.scenario === "rotation"
        ? { scenario: scenario.scenario, status: scenario.status, evidence_sha256: scenario.evidence_sha256 }
        : scenario)
    }))
  }));
});

test("preserves deployment binding when a provider probe throws before instances are emitted", async () => {
  const result = await runPlatformAuthQualification({
    env: { AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true" },
    sourceCommit: SHA,
    sourceTree: TREE,
    expectedDeploymentDigests: DEPLOYMENT_DIGESTS,
    runId: RUN_ID,
    jobId: JOB_ID,
    now: () => NOW,
    instanceProbe: async () => { throw new Error("provider unavailable"); }
  });
  assert.equal(result.status, "failed");
  assert.deepEqual(result.deployment_digests, DEPLOYMENT_DIGESTS);
  assert.deepEqual(result.instances, []);
  assert.deepEqual(verifyPlatformAuthQualificationEvidence(result, {
    expectedSourceCommit: SHA,
    expectedSourceTree: TREE,
    expectedDeploymentDigests: DEPLOYMENT_DIGESTS,
    expectedRunId: RUN_ID,
    expectedJobId: JOB_ID
  }).deployment_digests, DEPLOYMENT_DIGESTS);
  assert.throws(() => verifyPlatformAuthQualificationEvidence({
    ...result,
    deployment_digests: { ...DEPLOYMENT_DIGESTS, secondary: digest(8) }
  }, { expectedDeploymentDigests: DEPLOYMENT_DIGESTS }));
});

test("emits canonical protected evidence and rejects source-tree/run substitutions", async () => {
  const result = await runPlatformAuthQualification({ env: { AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true" }, sourceCommit: SHA, sourceTree: TREE, expectedDeploymentDigests: DEPLOYMENT_DIGESTS, runId: RUN_ID, jobId: JOB_ID, now: () => NOW, instanceProbe: probe() });
  assert.equal(canonicalPlatformAuthQualificationEvidence(result), canonicalJson(result));
  assert.throws(() => verifyPlatformAuthQualificationEvidence({ ...result, source_tree: "c".repeat(40) }, { expectedSourceCommit: SHA, expectedSourceTree: TREE }));
  assert.throws(() => verifyPlatformAuthQualificationEvidence({ ...result, job_id: "43" }, { expectedSourceCommit: SHA, expectedJobId: JOB_ID }));
  assert.throws(() => normalizePlatformAuthQualificationEvidence({ ...result, run_id: "0" }));
  assert.throws(() => verifyPlatformAuthQualificationEvidence(result, { expectedSourceCommit: SHA, expectedSourceTree: TREE, expectedDeploymentDigests: { ...DEPLOYMENT_DIGESTS, secondary: digest(8) }, expectedRunId: RUN_ID, expectedJobId: JOB_ID }));
  const rotation = result.instances[0].scenarios.find((item) => item.scenario === "rotation");
  assert.throws(() => normalizePlatformAuthQualificationEvidence({
    ...result,
    instances: result.instances.map((instance) => instance.name === "primary"
      ? { ...instance, scenarios: instance.scenarios.map((item) => item.scenario === "rotation"
        ? { ...item, evidence: { ...item.evidence, checks: item.evidence.checks.map((check, index) => index === 0 ? { ...check, result: { type: "boolean", value: false } } : check) } }
        : item) }
      : instance)
  }));
  assert.equal(rotation.evidence.source_tree, TREE);
});

test("rejects equal negative typed results as passed qualification checks", async () => {
  const result = await runPlatformAuthQualification({
    env: { AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true" }, sourceCommit: SHA, sourceTree: TREE,
    expectedDeploymentDigests: DEPLOYMENT_DIGESTS, runId: RUN_ID, jobId: JOB_ID, now: () => NOW,
    instanceProbe: probe()
  });
  const rotation = result.instances[0].scenarios.find((item) => item.scenario === "rotation");
  const tampered = {
    ...result,
    instances: result.instances.map((instance) => instance.name === "primary"
      ? { ...instance, scenarios: instance.scenarios.map((item) => item.scenario === "rotation"
        ? { ...item, evidence: { ...item.evidence, checks: item.evidence.checks.map((check, index) => index === 0
          ? { ...check, expected: { type: "boolean", value: false }, result: { type: "boolean", value: false } }
          : check) } }
        : item) }
      : instance)
  };
  const tamperedEvidence = tampered.instances[0].scenarios.find((item) => item.scenario === "rotation").evidence;
  tampered.instances[0].scenarios.find((item) => item.scenario === "rotation").evidence_sha256 = crypto.createHash("sha256").update(canonicalJson(tamperedEvidence), "utf8").digest("hex");
  assert.throws(() => normalizePlatformAuthQualificationEvidence(tampered));
  assert.equal(rotation.status, "passed");
});

test("does not run with an unbound deployment digest", async () => {
  const result = await runPlatformAuthQualification({
    env: { AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED: "true" }, sourceCommit: SHA, sourceTree: TREE,
    expectedDeploymentDigests: { primary: DEPLOYMENT_DIGESTS.primary, secondary: "invalid" }, runId: RUN_ID, jobId: JOB_ID,
    now: () => NOW, instanceProbe: probe()
  });
  assert.deepEqual(result, {
    schema_version: 1, kind: PLATFORM_AUTH_QUALIFICATION_KIND, status: "not_run", qualified: false,
    reason: "invalid_deployment_binding", started_at: NOW.toISOString(), completed_at: NOW.toISOString()
  });
});
