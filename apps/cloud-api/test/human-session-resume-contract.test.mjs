import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "../../..");
const human = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "contracts/openapi/human-v1.json"), "utf8"));
const catalog = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "contracts/catalog-v1.json"), "utf8"));

const operation = human.paths["/auth/session/resume"]?.post;
const catalogEntry = catalog.entries.find((entry) => entry.id === "api.human.resumeHumanSession");

test("session resume is machine-readable as the cookie-bound runtime child of /api/auth/session", () => {
  assert.ok(operation);
  assert.equal(human.servers[0].url, "https://app.ai-agentpass.com/api/v1");
  assert.equal(human.paths["/auth/session"].post["x-agentpass-runtime-path"], "/api/auth/session");
  assert.equal(operation["x-agentpass-runtime-path"], "/api/auth/session/resume");
  assert.equal(operation.operationId, "resumeHumanSession");
  assert.deepEqual(operation.security, [{ humanSession: [] }]);
  assert.equal(operation.requestBody.$ref, "#/components/requestBodies/SessionResume");
  assert.deepEqual(operation["x-agentpass-empty-body"], {
    required: true,
    content_type: "application/json",
    schema_ref: "#/components/schemas/SessionBootstrapRequest",
    required_properties: 0,
    additionalProperties: false
  });
  assert.deepEqual(operation["x-agentpass-accepted-headers"], ["Origin", "Content-Type"]);
  assert.deepEqual(operation["x-agentpass-rejected-headers"], ["Authorization", "agentpass-console-identity", "agentpass-csrf", "X-CSRF-Token", "Idempotency-Key"]);
  const requestBody = human.components.requestBodies.SessionResume;
  assert.equal(requestBody.required, true);
  assert.deepEqual(Object.keys(requestBody.content), ["application/json"]);
  assert.equal(requestBody.content["application/json"].schema.$ref, "#/components/schemas/SessionBootstrapRequest");
  const requestSchema = human.components.schemas.SessionBootstrapRequest;
  assert.equal(requestSchema.type, "object");
  assert.equal(requestSchema.additionalProperties, false);
  assert.deepEqual(requestSchema.required, []);
  assert.equal(requestSchema.minProperties, 0);
  assert.equal(requestSchema.maxProperties, 0);
  assert.deepEqual(operation["x-agentpass-origin-policy"], {
    header: "Origin",
    required: true,
    match: "exact-configured-console-origin",
    null_origin: "reject",
    additionalProperties: false
  });
  assert.deepEqual(operation["x-agentpass-cookie-binding"], {
    cookie: "__Host-agentpass_session",
    lookup: "sha256(cookie_value)",
    raw_cookie: "transport-only",
    additionalProperties: false
  });
  assert.equal(operation["x-agentpass-atomic-rotation"].repository_method, "rotateSession");
  assert.equal(operation["x-agentpass-atomic-rotation"].transaction, "single-database-transaction");
  assert.equal(operation["x-agentpass-atomic-rotation"].old_cookie_replay, "reject-without-new-cookie");
  assert.deepEqual(operation["x-agentpass-csrf-policy"], {
    caller_header: null,
    response: "new-ephemeral-csrf-token",
    origin_remains_required: true,
    additionalProperties: false
  });
  assert.deepEqual(Object.keys(operation.responses).sort(), ["201", "400", "401", "403", "503"]);
  assert.equal(operation.responses["201"].$ref, "#/components/responses/SessionResumed");
  assert.equal(human.components.responses.SessionResumed.content["application/json"].schema.$ref, "#/components/schemas/SessionBootstrapResponse");
  assert.equal(human.components.responses.SessionResumed.headers["Set-Cookie"].required, true);
  assert.equal(human.components.responses.SessionResumed.headers["Cache-Control"].schema.const, "no-store, max-age=0");
});

test("catalog binds resume to the implemented human-session authority", () => {
  assert.ok(catalogEntry);
  assert.equal(catalogEntry.kind, "openapi-operation");
  assert.equal(catalogEntry.source, "openapi/human-v1.json");
  assert.equal(catalogEntry.method, "POST");
  assert.equal(catalogEntry.path, "/auth/session/resume");
  assert.equal(catalogEntry.operation_id, "resumeHumanSession");
  assert.equal(catalogEntry.profile, "human-session");
  assert.equal(catalogEntry.implementation_status, "implemented");
  assert.deepEqual(catalogEntry.tenant_binding, undefined);
  assert.deepEqual(catalogEntry.actor_binding, undefined);
  assert.ok(catalogEntry.compatibility_fixtures.includes("apps/cloud-api/test/human-session-resume-contract.test.mjs"));
  assert.ok(catalogEntry.compatibility_fixtures.includes("apps/web-console/tests/console-session-ui.test.mjs"));
});
