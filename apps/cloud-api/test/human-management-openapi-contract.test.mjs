import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "../../..");
const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts/openapi/human-v1.json"), "utf8"));
const catalog = JSON.parse(fs.readFileSync(path.join(root, "contracts/catalog-v1.json"), "utf8"));
const pathItem = openapi.paths["/auth/management/sessions/revoke-others"];

test("human-v1 freezes the revoke-other-sessions route and exact empty request", () => {
  assert.ok(pathItem?.post);
  assert.equal(pathItem.post.operationId, "revokeOtherHumanSessions");
  assert.deepEqual(pathItem.post.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.deepEqual(pathItem.post.parameters, [
    { $ref: "#/components/parameters/CsrfToken" },
    { $ref: "#/components/parameters/RecentAuth" }
  ]);
  assert.deepEqual(pathItem.post.requestBody, { $ref: "#/components/requestBodies/RevokeOtherSessions" });
  assert.deepEqual(pathItem.post.responses["200"], { $ref: "#/components/responses/OtherSessionsRevoked" });

  const request = openapi.components.requestBodies.RevokeOtherSessions.content["application/json"].schema;
  assert.deepEqual(request, { $ref: "#/components/schemas/RevokeOtherSessionsRequest" });
  assert.deepEqual(openapi.components.schemas.RevokeOtherSessionsRequest, {
    type: "object",
    additionalProperties: false,
    required: [],
    minProperties: 0,
    maxProperties: 0,
    description: "Exactly {}. No organization_id, member_id, session_id, target list, reason, or timestamp is accepted from the caller."
  });
});

test("human-v1 freezes the exact committed response envelope and catalog ownership", () => {
  const response = openapi.components.schemas.RevokeOtherSessionsResponse;
  assert.deepEqual(response.required, ["revoked_sessions", "revoked_count", "truncated"]);
  assert.equal(response.additionalProperties, false);
  assert.deepEqual(response["x-agentpass-invariants"], ["revoked_count is the exact committed total", "truncated is true exactly when revoked_count exceeds revoked_sessions.length", "revoked_sessions contains at most the first 100 committed records", "every revoked_sessions item has status=revoked and is_current=false"]);
  assert.deepEqual(response.properties.revoked_sessions.items, { $ref: "#/components/schemas/ManagedHumanSession" });
  assert.equal(response.properties.revoked_sessions.maxItems, 100);
  assert.deepEqual(response.properties.revoked_count, { type: "integer", minimum: 0 });
  assert.deepEqual(response.properties.truncated, { type: "boolean" });
  assert.deepEqual(openapi.components.schemas.ManagedHumanSession.properties.is_current, { type: "boolean", const: false });
  assert.deepEqual(openapi.components.schemas.ManagedHumanSession.properties.status, { const: "revoked" });

  const entry = catalog.entries.find(({ id }) => id === "api.human.revokeOtherHumanSessions");
  assert.deepEqual(entry, {
    id: "api.human.revokeOtherHumanSessions",
    kind: "openapi-operation",
    source: "openapi/human-v1.json",
    method: "POST",
    path: "/auth/management/sessions/revoke-others",
    operation_id: "revokeOtherHumanSessions",
    version: 1,
    profile: "human-session",
    purpose: "api.human.revoke-other-human-sessions",
    implementation_refs: [
      "apps/cloud-api/src/human-auth/management/http-api.mjs",
      "apps/cloud-api/src/human-auth/management/postgres-adapter.mjs",
      "apps/cloud-api/src/postgres/human-repository.mjs",
      "apps/cloud-api/src/human-auth/router.mjs"
    ],
    compatibility_fixtures: [
      "apps/cloud-api/test/human-auth-management-http-api.test.mjs",
      "apps/cloud-api/test/human-auth-router.test.mjs",
      "apps/cloud-api/test/postgres/human-repository.test.mjs"
    ]
  });
});
