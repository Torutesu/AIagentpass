import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const readJson = (relative) => JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));

const human = readJson("contracts/openapi/human-v1.json");
const device = readJson("contracts/openapi/device-v1.json");
const publicBatch = readJson("contracts/schemas/qualification-grant-batch-v1.schema.json");
const claim = readJson("contracts/schemas/qualification-grant-batch-claim-v1.schema.json");
const manifest = readJson("contracts/schemas/qualification-grant-batch-manifest-v1.schema.json");

test("qualification batch schemas separate public Human metadata, claim input, and signed Device manifest", () => {
  assert.deepEqual(publicBatch.required, [
    "schema_version", "kind", "batch_id", "organization_id", "device_id", "agent_id",
    "candidate_sha256", "artifact_sha256", "source_commit", "team_id", "release_trust_sha256",
    "candidate_checkpoint_sha256", "issued_at", "expires_at", "status"
  ]);
  assert.equal(publicBatch.maxProperties, 15);
  assert.equal(publicBatch.properties.status.const, "issued");
  assert.equal(Object.hasOwn(publicBatch.properties, "steps"), false);
  assert.equal(Object.hasOwn(publicBatch.properties, "manifest"), false);
  assert.deepEqual(claim.required, [
    "schema_version", "candidate_sha256", "artifact_sha256", "source_commit", "team_id",
    "release_trust_sha256", "candidate_checkpoint_sha256"
  ]);
  assert.equal(claim.maxProperties, 7);
  assert.equal(Object.hasOwn(claim.properties, "batch_id"), false);

  assert.deepEqual(manifest.required, ["version", "type", "statement", "statement_hash", "signature"]);
  assert.equal(manifest.properties.type.const, "agentpass.qualification-grant-batch-manifest");
  assert.deepEqual(manifest.properties.statement, { $ref: "#/$defs/statement" });
  assert.deepEqual(manifest.$defs.statement.required, [
    "version", "type", "batch_id", "organization_id", "device_id", "agent_id", "agent_kind",
    "requested_ttl_seconds", "candidate_sha256", "artifact_sha256", "source_commit", "team_id",
    "release_trust_sha256", "candidate_checkpoint_sha256", "issued_at", "expires_at", "steps", "issuer", "key_id"
  ]);
  assert.equal(manifest.$defs.statement.properties.issuer.const, "agentpass-cloud");
  assert.equal(manifest.$defs.statement.properties.type.const, "agentpass.qualification-grant-batch-manifest");
  assert.equal(manifest.$defs.statement.properties.steps.maxItems, 7);
  assert.equal(manifest.$defs.step.properties.grant.$ref, "https://agentpass.dev/contracts/agent-session-grant-v1.schema.json");
  assert.equal(manifest.$defs.step.maxProperties, 9);
  assert.equal(manifest.$defs.step.properties.grant_hash.$ref, "#/$defs/sha256Hex");
  assert.equal(manifest.$defs.step.properties.statement_hash.$ref, "#/$defs/sha256Hex");
});

test("Human issue endpoint returns public metadata only", () => {
  const route = "/organizations/{organization_id}/agents/{agent_id}/qualification-grant-batches";
  const operation = human.paths[route]?.post;
  assert.ok(operation);
  assert.equal(operation.operationId, "issueQualificationGrantBatch");
  assert.deepEqual(operation.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/IssueQualificationGrantBatch" });
  assert.equal(operation["x-agentpass-recent-auth-operation"], "qualification.grant_batch.issue");
  assert.deepEqual(operation.responses["201"], { $ref: "#/components/responses/QualificationGrantBatchIssued" });
  const response = human.components.schemas.QualificationGrantBatchIssueResponse;
  assert.deepEqual(response.required, ["batch", "request_id"]);
  assert.deepEqual(response.properties.batch, { $ref: "#/components/schemas/QualificationGrantBatchV1" });
  assert.equal(Object.hasOwn(response.properties, "manifest"), false);
  assert.equal(Object.hasOwn(response.properties, "grant"), false);
  assert.equal(Object.hasOwn(response.properties, "grants"), false);
});

test("Device claim endpoint returns a purpose-separated signed manifest with seven steps", () => {
  const route = "/organizations/{organization_id}/devices/{device_id}/qualification-grant-batches/{batch_id}/claim";
  const operation = device.paths[route]?.post;
  assert.ok(operation);
  assert.equal(operation.operationId, "claimQualificationGrantBatch");
  assert.deepEqual(operation.security, [{ deviceSignature: [] }]);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/ClaimQualificationGrantBatch" });
  assert.equal(operation["x-agentpass-authority"]["signature-algorithm"], "ed25519");
  assert.equal(operation["x-agentpass-authority"]["signature-purpose"], "agentpass.qualification-grant-batch-manifest");
  assert.deepEqual(operation.responses["200"], { $ref: "#/components/responses/QualificationGrantBatchClaimed" });
  const response = device.components.schemas.QualificationGrantBatchClaimResponse;
  assert.deepEqual(response.required, ["batch", "request_id"]);
  assert.deepEqual(response.properties.batch, { $ref: "#/components/schemas/QualificationGrantBatchManifestV1" });
  assert.equal(device.components.schemas.QualificationGrantBatchManifestV1.$ref, "../schemas/qualification-grant-batch-manifest-v1.schema.json");
  assert.equal(device.components.schemas.QualificationGrantBatchClaimRequest.$ref, "../schemas/qualification-grant-batch-claim-v1.schema.json");
  assert.equal(device.components.parameters.QualificationBatchId.schema.format, "uuid");
});
