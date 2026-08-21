#!/usr/bin/env node

import crypto from "node:crypto";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const PLATFORM_AUTH_QUALIFICATION_SCHEMA_VERSION = 1;
export const PLATFORM_AUTH_QUALIFICATION_KIND = "agentpass-platform-auth-qualification";
export const PLATFORM_AUTH_PROVIDER_ADAPTER_CONTRACT_VERSION = 1;
export const PLATFORM_AUTH_INSTANCES = Object.freeze(["primary", "secondary"]);
export const PLATFORM_AUTH_SCENARIOS = Object.freeze([
  "static_config",
  "mtls_peer_binding",
  "workload_identity_binding",
  "webauthn_consumption",
  "http_contract",
  "rotation",
  "resilience"
]);
export const PLATFORM_AUTH_STRUCTURED_SCENARIOS = Object.freeze(["rotation", "resilience"]);
export const PLATFORM_AUTH_SCENARIO_CHECKS = Object.freeze({
  rotation: Object.freeze([
    "old_identifier_rejected",
    "new_identifier_accepted",
    "in_flight_operations_drained",
    "rotation_state_durable",
    "binding_integrity"
  ]),
  resilience: Object.freeze([
    "response_loss_reconciled",
    "restart_state_recovered",
    "provider_outage_fail_closed",
    "database_failover_reconciled",
    "duplicate_operation_prevented"
  ])
});

const REPORT_KEYS = ["completed_at", "deployment_digests", "instances", "job_id", "kind", "qualified", "reason", "run_id", "schema_version", "source_commit", "source_tree", "started_at", "status"];
const SHA = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SAFE_REASON = new Set([
  "provider_not_configured",
  "qualification_dependencies_missing",
  "invalid_source_binding",
  "probe_failed",
  "scenario_failed",
  "incomplete_run",
  "invalid_deployment_binding",
  "invalid_run_binding"
]);

export class PlatformAuthQualificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "PlatformAuthQualificationError";
    this.code = code;
  }
}

/** Production deployments inject this adapter; this module never owns an
 * identity-provider SDK, credential, assertion, or network client. */
export function createPlatformAuthProviderAdapter({ instanceProbe } = {}) {
  if (typeof instanceProbe !== "function") throw new PlatformAuthQualificationError("invalid_configuration");
  return Object.freeze({ contract_version: PLATFORM_AUTH_PROVIDER_ADAPTER_CONTRACT_VERSION, instanceProbe });
}

export async function runPlatformAuthQualification({
  env = process.env,
  now = () => new Date(),
  sourceCommit = env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_COMMIT,
  sourceTree = env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_TREE,
  expectedDeploymentDigests = {
    primary: env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_PRIMARY_DEPLOYMENT_DIGEST,
    secondary: env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SECONDARY_DEPLOYMENT_DIGEST
  },
  runId = env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUN_ID ?? env.GITHUB_RUN_ID,
  jobId = env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_JOB_ID,
  providerAdapter,
  instanceProbe
} = {}) {
  const startedAt = timestamp(now());
  if (env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED !== "true") {
    return notRunEvidence(startedAt, "provider_not_configured");
  }
  if (typeof instanceProbe !== "function" && providerAdapter !== undefined) {
    try { ({ instanceProbe } = createPlatformAuthProviderAdapter(providerAdapter)); } catch { return notRunEvidence(startedAt, "qualification_dependencies_missing"); }
  }
  if (typeof instanceProbe !== "function") return notRunEvidence(startedAt, "qualification_dependencies_missing");
  if (typeof sourceCommit !== "string" || !SHA.test(sourceCommit) || typeof sourceTree !== "string" || !SHA.test(sourceTree)) return notRunEvidence(startedAt, "invalid_source_binding");
  if (!validDeploymentDigests(expectedDeploymentDigests)) return notRunEvidence(startedAt, "invalid_deployment_binding");
  if (!RUN_ID.test(String(runId ?? "")) || !RUN_ID.test(String(jobId ?? ""))) return notRunEvidence(startedAt, "invalid_run_binding");

  try {
    const instances = [];
    for (const name of PLATFORM_AUTH_INSTANCES) {
      instances.push(normalizeInstance(await instanceProbe({
        name,
        scenarios: PLATFORM_AUTH_SCENARIOS,
        source_commit: sourceCommit,
        source_tree: sourceTree,
        expected_deployment_digest: expectedDeploymentDigests[name],
        run_id: String(runId),
        job_id: String(jobId)
      }), name, sourceCommit, expectedDeploymentDigests[name], sourceTree, String(runId), String(jobId)));
    }
    const failed = instances.some((instance) => instance.scenarios.some((item) => item.status !== "passed"));
    return normalizePlatformAuthQualificationEvidence({
      schema_version: PLATFORM_AUTH_QUALIFICATION_SCHEMA_VERSION,
      kind: PLATFORM_AUTH_QUALIFICATION_KIND,
      status: failed ? "failed" : "passed",
      qualified: !failed,
      reason: failed ? "scenario_failed" : null,
      source_commit: sourceCommit,
      source_tree: sourceTree,
      run_id: String(runId),
      job_id: String(jobId),
      started_at: startedAt,
      completed_at: timestamp(now()),
      deployment_digests: { ...expectedDeploymentDigests },
      instances
    });
  } catch (error) {
    return failedEvidence(startedAt, error instanceof PlatformAuthQualificationError ? error.code : "probe_failed", sourceCommit, sourceTree, runId, jobId, expectedDeploymentDigests);
  }
}

export function normalizePlatformAuthQualificationEvidence(value) {
  try {
    exactObject(value, REPORT_KEYS);
    if (value.schema_version !== PLATFORM_AUTH_QUALIFICATION_SCHEMA_VERSION
      || value.kind !== PLATFORM_AUTH_QUALIFICATION_KIND
      || !["passed", "failed"].includes(value.status)
      || value.qualified !== (value.status === "passed")
      || (value.reason !== null && !SAFE_REASON.has(value.reason))
      || typeof value.source_commit !== "string" || !SHA.test(value.source_commit)
      || typeof value.source_tree !== "string" || !SHA.test(value.source_tree)
      || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
      || typeof value.job_id !== "string" || !RUN_ID.test(value.job_id)) fail();
    if (!validDeploymentDigests(value.deployment_digests)) fail();
    timestamp(value.started_at);
    timestamp(value.completed_at);
    if (Date.parse(value.completed_at) < Date.parse(value.started_at)) fail();
    if (!Array.isArray(value.instances)) fail();
    if (value.status === "failed" && value.reason === null) fail();
    if (value.status === "failed" && value.instances.length === 0) return deepFreeze({ ...value, instances: [] });
    if (value.instances.length !== PLATFORM_AUTH_INSTANCES.length) fail();
    const instances = value.instances.map((item, index) => normalizeInstance(
      item,
      PLATFORM_AUTH_INSTANCES[index],
      value.source_commit,
      undefined,
      value.source_tree,
      value.run_id,
      value.job_id
    ));
    if (value.status === "failed" && (value.reason === null || instances.every((item) => item.scenarios.every((scenario) => scenario.status === "passed")))) fail();
    if (value.status === "passed" && (value.reason !== null || instances.some((item) => item.scenarios.some((scenario) => scenario.status !== "passed")))) fail();
    return deepFreeze({ ...value, instances });
  } catch (error) {
    if (error instanceof PlatformAuthQualificationError) throw error;
    fail();
  }
}

export function normalizePlatformAuthNotRunEvidence(value) {
  try {
    exactObject(value, ["completed_at", "kind", "qualified", "reason", "schema_version", "started_at", "status"]);
    if (value.schema_version !== PLATFORM_AUTH_QUALIFICATION_SCHEMA_VERSION
      || value.kind !== PLATFORM_AUTH_QUALIFICATION_KIND || value.status !== "not_run"
      || value.qualified !== false || !["provider_not_configured", "qualification_dependencies_missing", "invalid_source_binding", "invalid_deployment_binding", "invalid_run_binding"].includes(value.reason)) fail();
    timestamp(value.started_at);
    timestamp(value.completed_at);
    if (Date.parse(value.completed_at) < Date.parse(value.started_at)) fail();
    return deepFreeze({ ...value });
  } catch (error) {
    if (error instanceof PlatformAuthQualificationError) throw error;
    fail();
  }
}

export function verifyPlatformAuthQualificationEvidence(input, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigests, expectedRunId, expectedJobId } = {}) {
  let value;
  let bytes;
  try {
    if (Buffer.isBuffer(input) || input instanceof Uint8Array || typeof input === "string") {
      bytes = Buffer.from(input).toString("utf8");
      value = JSON.parse(bytes);
    } else value = input;
  } catch { fail(); }
  const normalized = value?.status === "not_run" ? normalizePlatformAuthNotRunEvidence(value) : normalizePlatformAuthQualificationEvidence(value);
  if (normalized.status !== "not_run") {
    if (expectedSourceCommit !== undefined && normalized.source_commit !== expectedSourceCommit) fail();
    if (expectedSourceTree !== undefined && normalized.source_tree !== expectedSourceTree) fail();
    if (expectedDeploymentDigests !== undefined) {
      if (!validDeploymentDigests(expectedDeploymentDigests)) fail();
      for (const name of PLATFORM_AUTH_INSTANCES) {
        if (normalized.deployment_digests[name] !== expectedDeploymentDigests[name]) fail();
        const instance = normalized.instances.find((item) => item.name === name);
        if (normalized.instances.length > 0 && instance?.deployment_digest !== expectedDeploymentDigests[name]) fail();
      }
    }
    if (expectedRunId !== undefined && normalized.run_id !== String(expectedRunId)) fail();
    if (expectedJobId !== undefined && normalized.job_id !== String(expectedJobId)) fail();
  }
  if (bytes !== undefined && canonicalPlatformAuthQualificationEvidence(normalized) !== bytes) fail();
  return Object.freeze({
    status: normalized.status,
    qualified: normalized.qualified,
    evidence_sha256: platformAuthQualificationSHA256(normalized),
    ...(normalized.status === "not_run"
      ? { reason: normalized.reason }
      : {
        source_commit: normalized.source_commit,
        source_tree: normalized.source_tree,
        deployment_digests: Object.freeze({ ...normalized.deployment_digests }),
        run_id: normalized.run_id,
        job_id: normalized.job_id
      })
  });
}

export function canonicalPlatformAuthQualificationEvidence(value) {
  const normalized = value?.status === "not_run" ? normalizePlatformAuthNotRunEvidence(value) : normalizePlatformAuthQualificationEvidence(value);
  return canonicalJson(normalized);
}

export function platformAuthQualificationSHA256(value) {
  const normalized = value?.status === "not_run" ? normalizePlatformAuthNotRunEvidence(value) : normalizePlatformAuthQualificationEvidence(value);
  return crypto.createHash("sha256").update(canonicalJson(normalized), "utf8").digest("hex");
}

function normalizeInstance(value, expectedName, expectedSourceCommit, expectedDeploymentDigest = undefined, expectedSourceTree = undefined, expectedRunId = undefined, expectedJobId = undefined) {
  exactObject(value, ["deployment_digest", "name", "scenarios", "source_commit"]);
  if (value.name !== expectedName || typeof value.deployment_digest !== "string" || !DIGEST.test(value.deployment_digest)
    || (expectedDeploymentDigest !== undefined && value.deployment_digest !== expectedDeploymentDigest)
    || typeof value.source_commit !== "string" || !SHA.test(value.source_commit) || value.source_commit !== expectedSourceCommit) fail();
  if (!Array.isArray(value.scenarios) || value.scenarios.length !== PLATFORM_AUTH_SCENARIOS.length) fail();
  const scenarios = value.scenarios.map((item, index) => {
    const scenario = PLATFORM_AUTH_SCENARIOS[index];
    exactObject(item, PLATFORM_AUTH_STRUCTURED_SCENARIOS.includes(scenario)
      ? ["evidence", "evidence_sha256", "scenario", "status"]
      : ["evidence_sha256", "scenario", "status"]);
    if (item.scenario !== PLATFORM_AUTH_SCENARIOS[index] || !["passed", "failed"].includes(item.status)
      || typeof item.evidence_sha256 !== "string" || !DIGEST.test(item.evidence_sha256)) fail();
    if (!PLATFORM_AUTH_STRUCTURED_SCENARIOS.includes(scenario)) {
      return Object.freeze({ scenario: item.scenario, status: item.status, evidence_sha256: item.evidence_sha256 });
    }
    const evidence = normalizePlatformAuthScenarioEvidence(item.evidence, {
      instance: expectedName,
      sourceCommit: expectedSourceCommit,
      sourceTree: expectedSourceTree,
      deploymentDigest: value.deployment_digest,
      runId: expectedRunId,
      jobId: expectedJobId,
      scenario
    });
    if (evidence.status !== item.status || platformAuthScenarioEvidenceSHA256(evidence) !== item.evidence_sha256) fail();
    return Object.freeze({ scenario: item.scenario, status: item.status, evidence_sha256: item.evidence_sha256, evidence });
  });
  return Object.freeze({ name: value.name, source_commit: value.source_commit, deployment_digest: value.deployment_digest, scenarios: Object.freeze(scenarios) });
}

export function normalizePlatformAuthScenarioEvidence(value, {
  instance,
  sourceCommit,
  sourceTree,
  deploymentDigest,
  runId,
  jobId,
  scenario
} = {}) {
  try {
    exactObject(value, [
      "checks", "completed_at", "deployment_digest", "instance", "job_id", "kind",
      "run_id", "scenario", "schema_version", "source_commit", "source_tree", "started_at", "status"
    ]);
    if (value.schema_version !== PLATFORM_AUTH_QUALIFICATION_SCHEMA_VERSION
      || value.kind !== `${PLATFORM_AUTH_QUALIFICATION_KIND}-scenario`
      || !PLATFORM_AUTH_STRUCTURED_SCENARIOS.includes(value.scenario)
      || !["passed", "failed"].includes(value.status)
      || (scenario !== undefined && value.scenario !== scenario)
      || (instance !== undefined && value.instance !== instance)
      || (sourceCommit !== undefined && value.source_commit !== sourceCommit)
      || (sourceTree !== undefined && value.source_tree !== sourceTree)
      || (deploymentDigest !== undefined && value.deployment_digest !== deploymentDigest)
      || (runId !== undefined && value.run_id !== String(runId))
      || (jobId !== undefined && value.job_id !== String(jobId))
      || typeof value.instance !== "string" || !PLATFORM_AUTH_INSTANCES.includes(value.instance)
      || typeof value.source_commit !== "string" || !SHA.test(value.source_commit)
      || typeof value.source_tree !== "string" || !SHA.test(value.source_tree)
      || typeof value.deployment_digest !== "string" || !DIGEST.test(value.deployment_digest)
      || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
      || typeof value.job_id !== "string" || !RUN_ID.test(value.job_id)) fail();
    const startedAt = timestamp(value.started_at);
    const completedAt = timestamp(value.completed_at);
    if (Date.parse(completedAt) < Date.parse(startedAt)) fail();
    if (!Array.isArray(value.checks) || value.checks.length !== PLATFORM_AUTH_SCENARIO_CHECKS[value.scenario].length) fail();
    const checks = value.checks.map((item, index) => normalizeScenarioCheck(
      item,
      PLATFORM_AUTH_SCENARIO_CHECKS[value.scenario][index]
    ));
    const failedCheck = checks.some((item) => item.status === "failed");
    if (value.status === "passed" && failedCheck) fail();
    if (value.status === "failed" && !failedCheck) fail();
    return deepFreeze({ ...value, started_at: startedAt, completed_at: completedAt, checks });
  } catch (error) {
    if (error instanceof PlatformAuthQualificationError) throw error;
    fail();
  }
}

export function canonicalPlatformAuthScenarioEvidence(value) {
  return canonicalJson(normalizePlatformAuthScenarioEvidence(value));
}

export function platformAuthScenarioEvidenceSHA256(value) {
  return crypto.createHash("sha256").update(canonicalPlatformAuthScenarioEvidence(value), "utf8").digest("hex");
}

function normalizeScenarioCheck(value, expectedCheckId) {
  exactObject(value, ["check_id", "expected", "result", "status"]);
  if (value.check_id !== expectedCheckId || !["passed", "failed"].includes(value.status)) fail();
  const expected = normalizeTypedScenarioValue(value.expected);
  const result = normalizeTypedScenarioValue(value.result);
  if (expected.type !== result.type) fail();
  const matches = canonicalJson(expected) === canonicalJson(result);
  if (value.status !== (matches ? "passed" : "failed")) fail();
  // A passed probe must prove a positive outcome. Equal false/not_run values
  // are valid evidence of a failed or incomplete probe, never qualification.
  if (value.status === "passed"
    && ((expected.type === "boolean" && expected.value !== true)
      || (expected.type === "status" && expected.value !== "passed"))) fail();
  return Object.freeze({ check_id: value.check_id, status: value.status, expected, result });
}

function normalizeTypedScenarioValue(value) {
  exactObject(value, ["type", "value"]);
  if (!["boolean", "digest", "identifier", "non_negative_integer", "status"].includes(value.type)) fail();
  if (value.type === "boolean" && typeof value.value !== "boolean") fail();
  if (value.type === "digest" && (typeof value.value !== "string" || !DIGEST.test(value.value))) fail();
  if (value.type === "identifier" && (typeof value.value !== "string" || !IDENTIFIER.test(value.value))) fail();
  if (value.type === "non_negative_integer" && (!Number.isSafeInteger(value.value) || value.value < 0)) fail();
  if (value.type === "status" && !["passed", "failed", "not_run"].includes(value.value)) fail();
  return Object.freeze({ type: value.type, value: value.value });
}

function notRunEvidence(startedAt, reason) {
  return Object.freeze({ schema_version: PLATFORM_AUTH_QUALIFICATION_SCHEMA_VERSION, kind: PLATFORM_AUTH_QUALIFICATION_KIND, status: "not_run", qualified: false, reason, started_at: startedAt, completed_at: startedAt });
}

function validDeploymentDigests(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === PLATFORM_AUTH_INSTANCES.length
    && PLATFORM_AUTH_INSTANCES.every((name) => typeof value[name] === "string" && DIGEST.test(value[name]));
}

function failedEvidence(startedAt, reason, sourceCommit, sourceTree, runId, jobId, expectedDeploymentDigests) {
  return Object.freeze({
    schema_version: PLATFORM_AUTH_QUALIFICATION_SCHEMA_VERSION,
    kind: PLATFORM_AUTH_QUALIFICATION_KIND,
    status: "failed",
    qualified: false,
    reason: SAFE_REASON.has(reason) ? reason : "probe_failed",
    source_commit: typeof sourceCommit === "string" && SHA.test(sourceCommit) ? sourceCommit : "0".repeat(40),
    source_tree: typeof sourceTree === "string" && SHA.test(sourceTree) ? sourceTree : "0".repeat(40),
    run_id: RUN_ID.test(String(runId ?? "")) ? String(runId) : "1",
    job_id: RUN_ID.test(String(jobId ?? "")) ? String(jobId) : "1",
    started_at: startedAt,
    completed_at: startedAt,
    deployment_digests: validDeploymentDigests(expectedDeploymentDigests)
      ? { ...expectedDeploymentDigests }
      : { primary: "0".repeat(64), secondary: "0".repeat(64) },
    instances: []
  });
}

function timestamp(value) {
  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) fail();
    return value.toISOString();
  }
  if (typeof value === "string" && TIMESTAMP.test(value) && Number.isFinite(Date.parse(value))) return value;
  fail();
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) fail();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
  }
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function fail() { throw new PlatformAuthQualificationError("invalid_evidence"); }

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  runPlatformAuthQualification().then((value) => {
    process.stdout.write(`${canonicalPlatformAuthQualificationEvidence(value)}\n`);
    if (value.status !== "passed" || value.qualified !== true) process.exitCode = 1;
  }).catch(() => {
    process.stdout.write(`${JSON.stringify(failedEvidence(new Date().toISOString(), "probe_failed"))}\n`);
    process.exitCode = 1;
  });
}
