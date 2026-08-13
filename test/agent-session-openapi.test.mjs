import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const readOpenApi = (name) => JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", name), "utf8"));

const HUMAN_ROUTE = "/organizations/{organization_id}/agents/{agent_id}/session-grants";
const DEVICE_ROUTE = "/organizations/{organization_id}/devices/{device_id}/agent-session-grants/{grant_id}/consume";

function assertResponseRefs(operation, expected) {
  assert.deepEqual(Object.keys(operation.responses).sort(), Object.keys(expected).sort());
  for (const [status, ref] of Object.entries(expected)) assert.deepEqual(operation.responses[status], { $ref: ref });
}

function assertHumanOperation(document) {
  const operation = document.paths[HUMAN_ROUTE]?.post;
  assert.ok(operation, "Human Agent Session Grant operation must exist");
  assert.equal(operation.operationId, "issueAgentSessionGrant");
  assert.deepEqual(operation.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/AgentId",
    "#/components/parameters/CsrfToken",
    "#/components/parameters/IdempotencyKey"
  ]);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/IssueAgentSessionGrant" });
  assert.equal(operation["x-agentpass-contract-status"], "frozen-m2");
  assert.equal(operation["x-agentpass-runtime-path"], "/api/v1/organizations/{organization_id}/agents/{agent_id}/session-grants");
  assert.deepEqual(operation["x-agentpass-tenant-scope"], {
    kind: "organization",
    source: "path.organization_id",
    "cross-tenant-disclosure": false,
    additionalProperties: false
  });
  assert.deepEqual(operation["x-agentpass-agent-scope"], {
    kind: "agent",
    source: "path.agent_id",
    "cross-agent-disclosure": false,
    additionalProperties: false
  });
  assert.equal(operation["x-agentpass-minimum-role"], "admin");
  assert.equal(operation["x-agentpass-recent-auth-operation"], "agent.session_grant.issue");
  assert.deepEqual(operation["x-agentpass-idempotency"], {
    "same-key-same-canonical-request": "return-original-committed-result",
    "same-key-different-canonical-request": "idempotency_key_reused",
    additionalProperties: false
  });
  assertResponseRefs(operation, {
    "201": "#/components/responses/AgentSessionGrantIssued",
    "400": "#/components/responses/BadRequest",
    "401": "#/components/responses/Unauthorized",
    "403": "#/components/responses/Forbidden",
    "404": "#/components/responses/NotFound",
    "409": "#/components/responses/IdempotencyConflict",
    "422": "#/components/responses/ValidationError",
    "429": "#/components/responses/TooManyRequests",
    "500": "#/components/responses/InternalError"
  });

  const agentId = document.components.parameters.AgentId;
  assert.deepEqual(agentId, {
    name: "agent_id",
    in: "path",
    required: true,
    description: "Agent identifier, interpreted only together with organization_id. The path value is authoritative for the grant subject.",
    schema: { type: "string", format: "uuid" }
  });

  const requestBody = document.components.requestBodies.IssueAgentSessionGrant;
  assert.equal(requestBody.required, true);
  assert.deepEqual(requestBody.content["application/json"].schema, { $ref: "#/components/schemas/AgentSessionGrantIssueRequest" });
  const request = document.components.schemas.AgentSessionGrantIssueRequest;
  assert.equal(request.type, "object");
  assert.equal(request.additionalProperties, false);
  assert.equal(request.maxProperties, 9);
  assert.deepEqual(request.required, [
    "device_id", "agent_kind", "adapter_id", "adapter_version", "worktree_binding_sha256",
    "process_binding_policy_id", "scope", "max_signatures", "ttl_seconds"
  ]);
  assert.equal(request.properties.scope.$ref, "../schemas/scope-v1.schema.json");
  assert.equal(request.properties.adapter_version.pattern, "^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$");
  for (const forbidden of ["organization_id", "agent_id", "grant_id", "issuer", "key_id", "signature", "not_before", "expires_at", "control_sequence"]) {
    assert.equal(Object.hasOwn(request.properties, forbidden), false, `issuance intent must not accept ${forbidden}`);
  }
  assert.deepEqual(document.components.schemas.AgentSessionGrantV1, { $ref: "../schemas/agent-session-grant-v1.schema.json" });
  const response = document.components.responses.AgentSessionGrantIssued;
  assert.equal(response.headers["Cache-Control"].required, true);
  assert.equal(response.headers["Cache-Control"].schema.const, "no-store, max-age=0");
  assert.deepEqual(response.content["application/json"].schema, { $ref: "#/components/schemas/AgentSessionGrantIssuedResponse" });
  assert.deepEqual(document.components.schemas.AgentSessionGrantIssuedResponse.required, ["grant", "request_id"]);
  assert.deepEqual(document.components.schemas.AgentSessionGrantIssuedResponse.properties.grant, { $ref: "#/components/schemas/AgentSessionGrantV1" });
}

function assertDeviceOperation(document) {
  const operation = document.paths[DEVICE_ROUTE]?.post;
  assert.ok(operation, "Device Agent Session Grant consume operation must exist");
  assert.equal(operation.operationId, "consumeAgentSessionGrant");
  assert.deepEqual(operation.security, [{ deviceSignature: [] }]);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/DeviceId",
    "#/components/parameters/GrantId"
  ]);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/ConsumeAgentSessionGrant" });
  assert.equal(operation["x-agentpass-contract-status"], "frozen-m2");
  assert.equal(operation["x-agentpass-runtime-path"], "/v1/organizations/{organization_id}/devices/{device_id}/agent-session-grants/{grant_id}/consume");
  assert.deepEqual(operation["x-agentpass-grant-binding"], {
    path_grant_id: "grant.statement.grant_id",
    path_organization_id: "grant.statement.organization_id",
    path_device_id: "grant.statement.device_id",
    process_binding: "body.process_binding_sha256",
    ancestry_binding: "body.ancestry_binding_sha256",
    retry_identity: "grant.statement_hash + body.process_binding_sha256 + body.ancestry_binding_sha256",
    consume: "one-time",
    additionalProperties: false
  });
  assertResponseRefs(operation, {
    "201": "#/components/responses/AgentSessionGrantConsumed",
    "400": "#/components/responses/BadRequest",
    "401": "#/components/responses/Unauthorized",
    "403": "#/components/responses/Forbidden",
    "404": "#/components/responses/NotFound",
    "409": "#/components/responses/Conflict",
    "429": "#/components/responses/RateLimited",
    "503": "#/components/responses/ServiceUnavailable"
  });

  const grantId = document.components.parameters.GrantId;
  assert.deepEqual(grantId, {
    name: "grant_id",
    in: "path",
    required: true,
    description: "Agent Session Grant identifier. The body statement.grant_id must exactly equal this path value.",
    schema: { type: "string", format: "uuid" }
  });
  const requestBody = document.components.requestBodies.ConsumeAgentSessionGrant;
  assert.equal(requestBody.required, true);
  assert.deepEqual(requestBody.content["application/json"].schema, { $ref: "#/components/schemas/AgentSessionGrantConsumeRequest" });
  assert.deepEqual(document.components.schemas.AgentSessionGrantConsumeRequest.required, ["grant", "process_binding_sha256", "ancestry_binding_sha256"]);
  assert.equal(document.components.schemas.AgentSessionGrantConsumeRequest.additionalProperties, false);
  assert.deepEqual(document.components.schemas.AgentSessionGrantConsumeRequest.properties.grant, { $ref: "#/components/schemas/AgentSessionGrantV1" });
  assert.ok(document.components.schemas.AgentSessionGrantConsumeRequest.properties.process_binding_sha256, "process_binding_sha256 is required");
  assert.ok(document.components.schemas.AgentSessionGrantConsumeRequest.properties.ancestry_binding_sha256, "ancestry_binding_sha256 is required");
  assert.equal(document.components.schemas.AgentSessionGrantConsumeRequest.properties.process_binding_sha256.pattern, "^[0-9a-f]{64}$");
  assert.equal(document.components.schemas.AgentSessionGrantConsumeRequest.properties.ancestry_binding_sha256.pattern, "^[0-9a-f]{64}$");
  for (const forbidden of ["lease", "pid", "pid_version", "audit_token", "ancestry", "session_token"]) {
    assert.equal(Object.hasOwn(document.components.schemas.AgentSessionGrantConsumeRequest.properties, forbidden), false);
  }
  assert.deepEqual(document.components.schemas.AgentSessionGrantV1, { $ref: "../schemas/agent-session-grant-v1.schema.json" });
  assert.deepEqual(document.components.schemas.AgentSessionLeaseV1, { $ref: "../schemas/agent-session-lease-v1.schema.json" });
  const response = document.components.responses.AgentSessionGrantConsumed;
  assert.equal(response.headers["Cache-Control"].$ref, "#/components/headers/CacheControl");
  assert.deepEqual(response.content["application/json"].schema, { $ref: "#/components/schemas/AgentSessionLeaseResponse" });
  assert.deepEqual(document.components.schemas.AgentSessionLeaseResponse.required, ["lease", "request_id"]);
  assert.deepEqual(document.components.schemas.AgentSessionLeaseResponse.properties.lease, { $ref: "#/components/schemas/AgentSessionLeaseV1" });
}

test("M2 OpenAPI operations freeze Human grant issuance and Device grant consumption", () => {
  const human = readOpenApi("human-v1.json");
  const device = readOpenApi("device-v1.json");
  assertHumanOperation(human);
  assertDeviceOperation(device);
  assert.ok(human.paths["/organizations/{organization_id}/device-enrollments"], "existing Human enrollment path must remain");
  assert.ok(device.paths["/organizations/{organization_id}/devices/{device_id}/enrollment-receipt"], "existing Device receipt path must remain");
});

test("M2 OpenAPI assertions reject weakened authentication or request bindings", () => {
  const human = readOpenApi("human-v1.json");
  const device = readOpenApi("device-v1.json");
  assertHumanOperation(human);
  assertDeviceOperation(device);

  const withoutRecentWebAuthn = structuredClone(human);
  withoutRecentWebAuthn.paths[HUMAN_ROUTE].post.security = [{ humanSession: [] }];
  assert.throws(() => assertHumanOperation(withoutRecentWebAuthn), /deep-equal|recentWebAuthn/i);

  const withoutIdempotency = structuredClone(human);
  withoutIdempotency.paths[HUMAN_ROUTE].post.parameters.pop();
  assert.throws(() => assertHumanOperation(withoutIdempotency), /IdempotencyKey|deep-equal/i);

  const wrappedGrant = structuredClone(device);
  wrappedGrant.components.requestBodies.ConsumeAgentSessionGrant.content["application/json"].schema = { $ref: "#/components/schemas/LooseGrant" };
  assert.throws(() => assertDeviceOperation(wrappedGrant), /AgentSessionGrantConsumeRequest|deep-equal/i);

  const withoutProcessBinding = structuredClone(device);
  delete withoutProcessBinding.components.schemas.AgentSessionGrantConsumeRequest.properties.process_binding_sha256;
  assert.throws(() => assertDeviceOperation(withoutProcessBinding), /process_binding_sha256/i);

  const bearerDevice = structuredClone(device);
  bearerDevice.paths[DEVICE_ROUTE].post.security = [{ deviceSignature: [] }, { humanSession: [] }];
  assert.throws(() => assertDeviceOperation(bearerDevice), /deep-equal|deviceSignature/i);
});
