import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { projectCutoverDeploymentEvidence as projectEvidence } from "./cutover-evidence.mjs";

const metadata = {
  artifact_sha256: "a".repeat(64), deployment_digest: "b".repeat(64), environment: "staging", image_digest: `sha256:${"1".repeat(64)}`, job_id: "deploy-staging",
  deployment_id: "deployment-123", release_manifest_sha256: "c".repeat(64), revision: "revision-current", rollback_target_revision: "revision-previous", run_attempt: "1", run_id: "123", service: "agentpass-cloud-api",
  schema_digest: "f".repeat(64), catalog_digest: "0".repeat(64), database_schema_digest: "1".repeat(64), source_commit: "d".repeat(40), source_tree: "e".repeat(40), started_at: "2099-08-20T01:00:00Z", completed_at: "2099-08-20T01:05:00Z"
};
const envelope = (command, result, ok = true) => ({ schema: "agentpass.cutover.v1", ok, command, phase: command, code: ok ? "OK" : "AGENTPASS_CUTOVER_NOT_READY", result });
const identity = { version: 1, configured: true, ready: true, source_commit: metadata.source_commit, source_tree: metadata.source_tree, image_digest: metadata.image_digest, deployment_id: metadata.deployment_id, revision: metadata.revision, schema_digest: metadata.schema_digest, catalog_digest: metadata.catalog_digest, database_schema_digest: metadata.database_schema_digest };
const rollbackIdentity = { ...identity, revision: metadata.rollback_target_revision };
const consoleReadiness = { configured: true, ready: true, status: "ready", code: "console_static_ready", deployment_identity: identity };
const application = { configured: true, ready: true, deployment_identity: identity };
function projectCutoverDeploymentEvidence(args) {
  const digest = (value) => crypto.createHash("sha256").update(canonicalJson(value.result === undefined ? Object.fromEntries(Object.entries(value).filter(([key]) => key !== "result")) : value), "utf8").digest("hex");
  return projectEvidence({ ...args, metadata: { ...args.metadata, cutover_sha256: digest(args.cutover), rollback_sha256: args.rollback === undefined ? "0".repeat(64) : digest(args.rollback) } });
}

test("projects successful cutover and executed rollback as passed evidence", () => {
  const evidence = projectCutoverDeploymentEvidence({
    metadata,
    cutover: envelope("cutover", { ready: true, readiness: { ready: true, application }, drain: { ready: true } }),
    rollback: envelope("rollback", { executed: true, action: "rollback_application_traffic", schema_action: "none", down_migration: "forbidden", deployment_id: metadata.deployment_id, current_revision: metadata.revision, rollback_target_revision: metadata.rollback_target_revision, completed_at: "2099-08-20T01:04:00Z", post_rollback_ready: true, deployment_identity: rollbackIdentity }),
    consoleReadiness
  });
  assert.equal(evidence.status, "passed");
  assert.equal(evidence.rollback.tested, true);
  assert.deepEqual(evidence.checks.map((check) => check.status), ["passed", "passed", "passed", "passed"]);
});

test("missing rollback is not_run and cannot qualify", () => {
  const evidence = projectCutoverDeploymentEvidence({
    metadata,
    cutover: envelope("cutover", { ready: true, readiness: { ready: true, application }, drain: { ready: true } }),
    consoleReadiness
  });
  assert.equal(evidence.status, "not_run");
  assert.equal(evidence.rollback.status, "not_run");
  assert.equal(evidence.qualified, false);
});

test("failed cutover and rollback remain failed evidence", () => {
  const evidence = projectCutoverDeploymentEvidence({
    metadata,
    cutover: envelope("cutover", { ready: false, readiness: { ready: false, application: { ...application, ready: false } }, drain: { ready: false } }, false),
    rollback: envelope("rollback", { executed: false, deployment_id: metadata.deployment_id, current_revision: metadata.revision, rollback_target_revision: metadata.rollback_target_revision, completed_at: "2099-08-20T01:04:00Z", post_rollback_ready: false }, false),
    consoleReadiness
  });
  assert.equal(evidence.status, "failed");
  assert.equal(evidence.checks[0].status, "failed");
  assert.equal(evidence.rollback.status, "failed");
});

test("an attempted cutover without a result is failed, not not_run", () => {
  const evidence = projectCutoverDeploymentEvidence({
    metadata,
    cutover: envelope("cutover", undefined, false),
    consoleReadiness
  });
  assert.equal(evidence.status, "failed");
  assert.deepEqual(evidence.checks.map((check) => check.status), ["failed", "failed", "failed", "passed"]);
});

test("rejects an accessor or secret-shaped envelope", () => {
  const cutover = envelope("cutover", { ready: true, readiness: { ready: true, application }, drain: { ready: true }});
  Object.defineProperty(cutover, "code", { enumerable: true, get() { throw new Error("secret"); } });
  assert.throws(() => projectCutoverDeploymentEvidence({ metadata, cutover }));
  assert.throws(() => projectCutoverDeploymentEvidence({ metadata: { ...metadata, provider_token: "secret" }, cutover }));
});

test("rejects nested accessors and non-plain result prototypes", () => {
  const cutover = envelope("cutover", { ready: true, readiness: { ready: true, application }, drain: { ready: true }});
  Object.defineProperty(cutover.result.readiness, "ready", { enumerable: true, get() { throw new Error("secret"); } });
  assert.throws(() => projectCutoverDeploymentEvidence({ metadata, cutover }));
  const second = envelope("cutover", { ready: true, readiness: { ready: true, application }, drain: { ready: true }});
  Object.setPrototypeOf(second.result, new Date());
  assert.throws(() => projectCutoverDeploymentEvidence({ metadata, cutover: second }));
});

test("console readiness is mandatory for a passed evidence record", () => {
  const cutover = envelope("cutover", { ready: true, readiness: { ready: true, application }, drain: { ready: true }});
  const rollback = envelope("rollback", { executed: true, deployment_id: metadata.deployment_id, current_revision: metadata.revision, rollback_target_revision: metadata.rollback_target_revision, completed_at: "2099-08-20T01:04:00Z", post_rollback_ready: true, deployment_identity: rollbackIdentity });
  const evidence = projectCutoverDeploymentEvidence({ metadata, cutover, rollback });
  assert.equal(evidence.status, "not_run");
  assert.equal(evidence.checks.at(-1).check_id, "console_readiness");
  assert.equal(evidence.checks.at(-1).status, "not_run");
  const degraded = projectCutoverDeploymentEvidence({ metadata, cutover, rollback, consoleReadiness: { ...consoleReadiness, ready: false, status: "not_ready", code: "console_unavailable" } });
  assert.equal(degraded.status, "failed");
  assert.equal(degraded.checks.at(-1).status, "failed");
});

test("rejects cutover or Console readiness identity substitution", () => {
  const cutover = envelope("cutover", { ready: true, readiness: { ready: true, application: { ...application, deployment_identity: { ...identity, revision: "revision-other" } } }, drain: { ready: true } });
  const rollback = envelope("rollback", { executed: true, deployment_id: metadata.deployment_id, current_revision: metadata.revision, rollback_target_revision: metadata.rollback_target_revision, completed_at: "2099-08-20T01:04:00Z", post_rollback_ready: true });
  const cutoverMismatch = projectCutoverDeploymentEvidence({ metadata, cutover, rollback, consoleReadiness });
  assert.equal(cutoverMismatch.status, "failed");
  const consoleMismatch = projectCutoverDeploymentEvidence({ metadata, cutover: envelope("cutover", { ready: true, readiness: { ready: true, application }, drain: { ready: true } }), rollback, consoleReadiness: { ...consoleReadiness, deployment_identity: { ...identity, catalog_digest: "9".repeat(64) } } });
  assert.equal(consoleMismatch.status, "failed");
});

test("binds application and rollback readiness identities to the exact database schema digest", () => {
  const cutover = envelope("cutover", { ready: true, readiness: { ready: true, application: { ...application, deployment_identity: { ...identity, database_schema_digest: "9".repeat(64) } } }, drain: { ready: true } });
  const rollback = envelope("rollback", { executed: true, deployment_id: metadata.deployment_id, current_revision: metadata.revision, rollback_target_revision: metadata.rollback_target_revision, completed_at: "2099-08-20T01:04:00Z", post_rollback_ready: true, deployment_identity: { ...rollbackIdentity, database_schema_digest: "9".repeat(64) } });
  const evidence = projectCutoverDeploymentEvidence({ metadata, cutover, rollback, consoleReadiness });
  assert.equal(evidence.status, "failed");
  assert.equal(evidence.checks.find((check) => check.check_id === "application_readiness").status, "failed");
  assert.equal(evidence.rollback.status, "failed");
});
