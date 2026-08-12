import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");

test("machine-readable platform contracts pass the offline validator", () => {
  const result = spawnSync(process.execPath, [path.join(root, "scripts", "validate-contracts.mjs")], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /validated 5 schemas, 2 OpenAPI documents, 3 fixtures, and 9 PostgreSQL migrations/);
});

const humanOpenapi = () => JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "human-v1.json"), "utf8"));

function operationFor(document, operationId) {
  for (const [route, methods] of Object.entries(document.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (["get", "post", "patch", "put", "delete"].includes(method) && operation.operationId === operationId) return { route, method, operation };
    }
  }
  throw new Error(`missing operation ${operationId}`);
}

function hasParameter(operation, componentName) {
  return (operation.parameters ?? []).some((parameter) => parameter.$ref === `#/components/parameters/${componentName}`);
}

function assertHumanP1Semantics(document) {
  const operations = [
    "listOrganizations", "createOrganization", "renameOrganization",
    "listMembers", "updateMemberRole", "removeMember",
    "listInvitations", "createInvitation", "revokeInvitation", "acceptInvitation"
  ].map((operationId) => operationFor(document, operationId));

  for (const { route, method, operation } of operations) {
    assert.ok(operation.security?.some((scheme) => Object.hasOwn(scheme, "humanSession")), `${operation.operationId} must require humanSession`);
    assert.ok(operation["x-agentpass-tenant-scope"], `${operation.operationId} must declare tenant scope`);
    if (route.includes("{organization_id}")) {
      assert.match(route, /\{organization_id\}/, `${operation.operationId} must be tenant-qualified in its route`);
      assert.ok(hasParameter(operation, "OrganizationId"), `${operation.operationId} must bind OrganizationId`);
    }
    if (["post", "patch", "delete"].includes(method)) {
      assert.ok(hasParameter(operation, "CsrfToken"), `${operation.operationId} must require CSRF`);
      assert.ok(hasParameter(operation, "IdempotencyKey"), `${operation.operationId} must require idempotency`);
      assert.ok(operation["x-agentpass-atomic-admin-audit-outbox"], `${operation.operationId} must document atomic admin-audit/outbox behavior`);
      for (const status of ["400", "401", "409"]) assert.ok(operation.responses?.[status], `${operation.operationId} must expose stable ${status} errors`);
    }
    if (operation["x-agentpass-requires-expected-version"]) {
      assert.ok(hasParameter(operation, "ExpectedVersion"), `${operation.operationId} must require expected version`);
    }
  }
}

test("Human P1 organization, member, and invitation operations declare security and tenant semantics", () => {
  const openapi = humanOpenapi();
  assertHumanP1Semantics(openapi);

  const invitationRole = openapi.components.schemas.InviteRole;
  assert.deepEqual(invitationRole.enum, ["admin", "auditor", "viewer"]);
  assert.equal(openapi.components.schemas.InvitationCreatedResponse.properties.one_time_token.writeOnly, true);
  assert.match(openapi.paths["/invitations/accept"].post.description, /not bound to an email/i);
  assert.match(openapi.components.schemas.AcceptInvitationRequest.description, /no email field/i);
  assert.match(openapi.paths["/organizations/{organization_id}/members/{member_id}/remove"].post["x-agentpass-final-owner-invariant"], /at least one active owner/i);
  assert.equal(openapi.components.parameters.Cursor.schema.maxLength, 512);
  assert.equal(openapi.components.parameters.Cursor.schema.pattern, "^[A-Za-z0-9_-]+$");
  assert.match(openapi.components.parameters.Cursor.description, /authenticated keyset cursor/i);
  assert.equal(openapi.components.parameters.Limit.schema.default, 50);
});

test("Human P1 contract assertions reject missing security, idempotency, or tenant semantics", () => {
  const baseline = humanOpenapi();
  assertHumanP1Semantics(baseline);

  const withoutSecurity = structuredClone(baseline);
  delete operationFor(withoutSecurity, "listInvitations").operation.security;
  assert.throws(() => assertHumanP1Semantics(withoutSecurity), /listInvitations must require humanSession/);

  const withoutIdempotency = structuredClone(baseline);
  const rename = operationFor(withoutIdempotency, "renameOrganization").operation;
  rename.parameters = rename.parameters.filter((parameter) => !parameter.$ref.endsWith("/IdempotencyKey"));
  assert.throws(() => assertHumanP1Semantics(withoutIdempotency), /renameOrganization must require idempotency/);

  const withoutTenant = structuredClone(baseline);
  delete operationFor(withoutTenant, "acceptInvitation").operation["x-agentpass-tenant-scope"];
  assert.throws(() => assertHumanP1Semantics(withoutTenant), /acceptInvitation must declare tenant scope/);
});

test("human high-risk operations require role and recent WebAuthn", () => {
  const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "human-v1.json"), "utf8"));
  const stop = openapi.paths["/organizations/{organization_id}/emergency-stop"].post;
  assert.equal(stop["x-agentpass-minimum-role"], "owner");
  assert.deepEqual(stop.security, [{ humanSession: [], recentWebAuthn: [] }]);
});

test("Human session bootstrap freezes the BFF-only SIWC signed assertion contract", () => {
  const openapi = humanOpenapi();
  const operation = openapi.paths["/auth/session"].post;
  assert.equal(operation.operationId, "exchangeSignedConsoleIdentityForSession");
  assert.equal(operation["x-agentpass-runtime-path"], "/api/auth/session");
  assert.equal(operation["x-agentpass-bff-only"], true);
  assert.equal(operation["x-agentpass-no-browser-redirect"], true);
  assert.deepEqual(operation["x-agentpass-accepted-headers"], ["Origin", "Content-Type", "agentpass-console-identity"]);
  assert.deepEqual(operation["x-agentpass-rejected-identity-headers"], ["Authorization", "agentpass-console-user-id", "agentpass-member-id", "agentpass-role"]);
  assert.deepEqual(operation.parameters, [{ $ref: "#/components/parameters/ConsoleIdentityAssertion" }]);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/SessionBootstrap" });
  assert.ok(operation.responses["201"]);
  assert.ok(operation.responses["401"]);
  assert.ok(operation.responses["409"]);

  const assertion = operation["x-agentpass-assertion"];
  assert.deepEqual(assertion.header, {
    alg: "EdDSA",
    kid: "deployment-selected-key-id",
    typ: "agentpass.console.identity",
    version: 1,
    canonical: true,
    additionalProperties: false
  });
  assert.deepEqual(assertion.payload.claims, ["aud", "exp", "iat", "iss", "jti", "nbf", "org", "origin", "provider", "sub"]);
  assert.equal(assertion.payload.claims.includes("redirect_uri"), false);
  assert.equal(assertion.payload.additionalProperties, false);
  assert.equal(assertion.payload.max_ttl_seconds, 60);
  assert.deepEqual(assertion.forbidden_claims, ["redirect_uri"]);
  assert.match(assertion.verification.join(" "), /consume SHA-256.*exactly once/i);
  assert.deepEqual(assertion.replay, {
    digest: "SHA-256(iss || U+0000 || aud || U+0000 || jti)",
    table: "human_identity_assertion_replays",
    atomic_consume_function: "agentpass_consume_human_identity_assertion",
    stored_fields: ["jti_digest", "expires_at"]
  });

  const header = openapi.components.parameters.ConsoleIdentityAssertion;
  assert.equal(header.name, "agentpass-console-identity");
  assert.equal(header.in, "header");
  assert.equal(header.required, true);
  assert.equal(header["x-agentpass-bff-only"], true);
  assert.match(header.schema.pattern, /\\\./);
  assert.equal(openapi.components.schemas.SessionBootstrapRequest.type, "object");
  assert.equal(openapi.components.schemas.SessionBootstrapRequest.minProperties, 0);
  assert.equal(openapi.components.schemas.SessionBootstrapRequest.maxProperties, 0);
  assert.equal(openapi.components.schemas.SessionBootstrapRequest.additionalProperties, false);
  assert.deepEqual(openapi.components.schemas.SessionBootstrapResponse.required, ["session", "csrf_token"]);
  assert.deepEqual(openapi.components.schemas.HumanSession.required, ["version", "session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"]);
  assert.equal(openapi.components.schemas.HumanSession.additionalProperties, false);
  assert.equal(openapi.components.responses.SessionBootstrapCreated.headers["Set-Cookie"].required, true);
  assert.equal(openapi.components.responses.SessionBootstrapCreated.headers["Cache-Control"].required, true);
});

test("device operations use device signatures and tenant-qualified paths", () => {
  const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "device-v1.json"), "utf8"));
  for (const [route, methods] of Object.entries(openapi.paths)) {
    if (route.startsWith("/enrollments/")) continue;
    assert.match(route, /\{organization_id\}/);
    for (const operation of Object.values(methods)) assert.deepEqual(operation.security, [{ deviceSignature: [] }]);
  }
});

test("PostgreSQL contract prevents cross-tenant device references", () => {
  const sql = fs.readFileSync(path.join(root, "contracts", "postgres", "0001_control_plane.sql"), "utf8");
  assert.match(sql, /PRIMARY KEY \(organization_id, id\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id\) REFERENCES devices\(organization_id, id\)/);
  assert.match(sql, /PRIMARY KEY \(organization_id, principal_id, idempotency_key\)/);
});
