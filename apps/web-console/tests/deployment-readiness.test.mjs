import assert from "node:assert/strict";
import test from "node:test";
import { DeploymentReadinessParseError, parseDeploymentReadiness } from "../app/deployment-readiness.ts";

const identity = {
  version: 1, configured: true, ready: true,
  source_commit: "a".repeat(40), source_tree: "b".repeat(40), image_digest: `sha256:${"c".repeat(64)}`,
  deployment_id: "deployment-1", revision: "revision-1", schema_digest: "d".repeat(64), catalog_digest: "e".repeat(64), database_schema_digest: "f".repeat(64),
};
const value = () => ({ version: 1, ready: true, status: "ready", code: "ready", deployment_identity: { ...identity } });

test("parses the closed deployment readiness identity into an immutable browser view", () => {
  const result = parseDeploymentReadiness(value());
  assert.equal(result.ready, true);
  assert.equal(result.deploymentIdentity.revision, "revision-1");
  assert.throws(() => { result.deploymentIdentity.revision = "tampered"; }, TypeError);
});

test("rejects unknown fields, incomplete identity, and secret-shaped values", () => {
  assert.throws(() => parseDeploymentReadiness({ ...value(), provider_token: "secret" }), DeploymentReadinessParseError);
  assert.throws(() => parseDeploymentReadiness({ ...value(), deployment_identity: { ...identity, catalog_digest: undefined } }), DeploymentReadinessParseError);
  assert.throws(() => parseDeploymentReadiness({ ...value(), deployment_identity: { ...identity, provider_token: "secret" } }), DeploymentReadinessParseError);
  assert.throws(() => parseDeploymentReadiness({ ...value(), deployment_identity: { ...identity, ready: false } }), DeploymentReadinessParseError);
});
