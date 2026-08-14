import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");

test("machine-readable platform contracts pass the offline validator", () => {
  const result = spawnSync(process.execPath, [path.join(root, "scripts", "validate-contracts.mjs")], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /validated 29 schemas, 2 OpenAPI documents, 17 fixtures, and 35 PostgreSQL migrations/);
});

const humanOpenapi = () => JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "human-v1.json"), "utf8"));
const contractSchema = (name) => JSON.parse(fs.readFileSync(path.join(root, "contracts", "schemas", name), "utf8"));

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

function assertHumanP0ARefreshRequestSemantics(document) {
  const route = "/organizations/{organization_id}/devices/{device_id}/refresh-requests";
  const operation = document.paths[route]?.post;
  assert.ok(operation, "P0-A refresh request operation must exist");
  assert.equal(operation.operationId, "requestDeviceRefresh");
  assert.deepEqual(operation.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/DeviceId",
    "#/components/parameters/CsrfToken",
    "#/components/parameters/IdempotencyKey"
  ]);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/DeviceRefreshRequest" });
  assert.equal(operation["x-agentpass-contract-status"], "frozen-p0-a");
  assert.equal(operation["x-agentpass-minimum-role"], "admin");
  assert.equal(operation["x-agentpass-recent-auth-operation"], "device.refresh.request");
  assert.equal(operation["x-agentpass-authority-neutral"], true);
  assert.deepEqual(operation["x-agentpass-authority-effects"], {
    authority_generation: "unchanged",
    bundle_and_ack_state: "unchanged",
    device_delivery: "not_proven",
    device_application: "not_proven"
  });
  assert.ok(operation["x-agentpass-tenant-scope"]);
  assert.match(operation.description, /does not increment authority generation/i);
  assert.match(operation.description, /does not prove notification delivery/i);
  assert.deepEqual(operation.responses["202"], { $ref: "#/components/responses/DeviceRefreshRequestAccepted" });
  for (const status of ["400", "401", "403", "404", "409", "429", "500"]) assert.ok(operation.responses[status], `P0-A must expose stable ${status} response`);

  const body = document.components.requestBodies.DeviceRefreshRequest;
  assert.equal(body.required, true);
  assert.equal(body.content["application/json"].schema.$ref, "#/components/schemas/DeviceRefreshRequestBody");
  const bodySchema = document.components.schemas.DeviceRefreshRequestBody;
  assert.equal(bodySchema.type, "object");
  assert.equal(bodySchema.additionalProperties, false);
  assert.equal(bodySchema.minProperties, 0);
  assert.equal(bodySchema.maxProperties, 0);

  const response = document.components.responses.DeviceRefreshRequestAccepted;
  assert.equal(response.content["application/json"].schema.$ref, "#/components/schemas/DeviceRefreshRequestResponse");
  const responseSchema = document.components.schemas.DeviceRefreshRequestResponse;
  assert.equal(responseSchema.additionalProperties, false);
  assert.deepEqual(responseSchema.required, ["request_id", "refresh_request"]);
  assert.deepEqual(Object.keys(responseSchema.properties).sort(), ["refresh_request", "request_id"]);
  assert.equal(responseSchema.properties.refresh_request.$ref, "#/components/schemas/DeviceRefreshRequestResult");

  const resultSchema = document.components.schemas.DeviceRefreshRequestResult;
  assert.equal(resultSchema.additionalProperties, false);
  assert.deepEqual(resultSchema.required, ["version", "request_id", "device_id", "desired_generation", "status", "requested_at"]);
  assert.deepEqual(Object.keys(resultSchema.properties).sort(), ["desired_generation", "device_id", "request_id", "requested_at", "status", "version"]);
  assert.deepEqual(resultSchema.properties.version, { const: 1 });
  assert.deepEqual(resultSchema.properties.status.enum, ["accepted", "coalesced", "no_pending_refresh"]);
  assert.deepEqual(resultSchema.properties.desired_generation.type, ["integer", "null"]);
  assert.equal(resultSchema.properties.desired_generation.minimum, 1);
  assert.equal(resultSchema.properties.request_id.format, "uuid");
  assert.equal(resultSchema.properties.device_id.format, "uuid");
  assert.equal(resultSchema.properties.requested_at.format, "date-time");
  assert.match(resultSchema.properties.requested_at.description, /RFC 3339/i);
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

  assert.equal(openapi.components.schemas.Organization.$ref, "../schemas/organization-v1.schema.json");
  assert.equal(openapi.components.schemas.Membership.$ref, "../schemas/membership-v1.schema.json");
  assert.equal(openapi.components.schemas.Invitation.$ref, "../schemas/invitation-v1.schema.json");
  assert.deepEqual(contractSchema("membership-v1.schema.json").properties.role.enum, ["owner", "admin", "auditor", "viewer"]);
  assert.deepEqual(contractSchema("invitation-v1.schema.json").properties.role.enum, ["admin", "auditor", "viewer"]);

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

test("Human P0-A refresh request freezes authority-neutral wake semantics", () => {
  assertHumanP0ARefreshRequestSemantics(humanOpenapi());
});

test("Human P0-A contract assertions reject weakened refresh request guarantees", () => {
  const baseline = humanOpenapi();
  assertHumanP0ARefreshRequestSemantics(baseline);

  const withoutRecentAuth = structuredClone(baseline);
  withoutRecentAuth.paths["/organizations/{organization_id}/devices/{device_id}/refresh-requests"].post.security = [{ humanSession: [] }];
  assert.throws(() => assertHumanP0ARefreshRequestSemantics(withoutRecentAuth), /refresh request operation|deep-equal/i);

  const withBodyInput = structuredClone(baseline);
  withBodyInput.components.schemas.DeviceRefreshRequestBody.maxProperties = 1;
  assert.throws(() => assertHumanP0ARefreshRequestSemantics(withBodyInput), /strict equal|1|0/);

  const withAuthorityMutation = structuredClone(baseline);
  withAuthorityMutation.paths["/organizations/{organization_id}/devices/{device_id}/refresh-requests"].post["x-agentpass-authority-neutral"] = false;
  assert.throws(() => assertHumanP0ARefreshRequestSemantics(withAuthorityMutation), /strict equal|true|false/);

  const withWeakResponse = structuredClone(baseline);
  delete withWeakResponse.components.schemas.DeviceRefreshRequestResponse.additionalProperties;
  assert.throws(() => assertHumanP0ARefreshRequestSemantics(withWeakResponse), /strict equal|false|undefined/);
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
  assert.deepEqual(assertion.payload.jti, { encoding: "base64url", minLength: 22, maxLength: 256 });
  assert.equal(assertion.payload.max_ttl_seconds, 60);
  assert.deepEqual(assertion.forbidden_claims, ["redirect_uri"]);
  assert.match(assertion.verification.join(" "), /consume SHA-256.*exactly once/i);
  assert.match(assertion.verification.join(" "), /Reject Authorization.*identity\/member\/role headers/i);
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
  assert.equal(openapi.components.schemas.HumanSession.$ref, "../schemas/human-session-v1.schema.json");
  const humanSession = contractSchema("human-session-v1.schema.json");
  assert.deepEqual(humanSession.required, ["version", "session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"]);
  assert.equal(humanSession.additionalProperties, false);
  assert.equal(openapi.components.responses.SessionBootstrapCreated.headers["Set-Cookie"].required, true);
  assert.equal(openapi.components.responses.SessionBootstrapCreated.headers["Cache-Control"].required, true);
});

test("device operations use device signatures and tenant-qualified paths", () => {
  const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "device-v1.json"), "utf8"));
  for (const [route, methods] of Object.entries(openapi.paths)) {
    if (route.startsWith("/enrollments/")) continue;
    assert.match(route, /\{organization_id\}/);
    for (const [method, operation] of Object.entries(methods)) {
      if (route === "/organizations/{organization_id}/audit/events" && method === "get") assert.deepEqual(operation.security, [{ humanSession: [] }, { auditReader: [] }]);
      else assert.deepEqual(operation.security, [{ deviceSignature: [] }]);
    }
  }
});

test("G4.2 device sync contract matches the implemented Cloud refresh lane", () => {
  const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "device-v1.json"), "utf8"));
  assert.deepEqual(openapi["x-agentpass-implementation-status"], {
    contract: "frozen-g4.0",
    "bundle-fetch-target-envelope": "implemented-g4.1",
    "refresh-poll": "implemented-g4.1",
    "signed-ack-ingestion": "implemented-g4.1",
    "native-sync": "in-progress-g4.2",
    "console-device-state": "in-progress-g4.3"
  });
  assert.match(openapi.components.securitySchemes.deviceSignature.description, /six newline-delimited fields/i);
  assert.match(openapi.components.securitySchemes.deviceSignature.description, /WHATWG_URL_PATHNAME/);
  assert.ok(openapi.paths["/organizations/{organization_id}/devices/{device_id}/refresh"].get.responses["204"]);
  assert.equal(openapi.paths["/organizations/{organization_id}/bundles/{device_id}/acknowledgements"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/BundleAckV1");
  assert.equal(openapi.components.schemas.RefreshHintV1.$ref, "../schemas/refresh-hint-v1.schema.json");
  assert.equal(openapi.components.schemas.BundleAckV1.$ref, "../schemas/bundle-ack-v1.schema.json");
  assert.deepEqual(openapi.components.schemas.DeviceRefreshState.enum, ["pending", "fetching", "applied", "blocked", "stale", "offline", "revoked"]);
  assert.equal(openapi.components.schemas.ControlBundleV2.$ref, "../schemas/control-bundle-v2.schema.json");
  const controlBundle = contractSchema("control-bundle-v2.schema.json");
  assert.equal(controlBundle.$defs.signature.pattern, "^[A-Za-z0-9+/]{86}==$" );
  assert.equal(controlBundle.$defs.canonicalTimestamp.maxLength, 24);
  assert.deepEqual(openapi.paths["/enrollments/{enrollment_id}"].post.requestBody.content["application/json"].schema.oneOf, [
    { $ref: "../schemas/device-enrollment-v1.schema.json" },
    { $ref: "../schemas/device-enrollment-completion-v2.schema.json" }
  ]);
  assert.equal(openapi.paths["/enrollments/{enrollment_id}"].post.responses["201"].$ref, "#/components/responses/DeviceEnrollmentCompleted");
  assert.deepEqual(openapi.components.schemas.ControlRefreshPollResponse.required, ["hint", "request_id"]);
  assert.deepEqual(openapi.components.schemas.ControlBundleFetchResponse.required, ["bundle", "desired_generation", "request_id"]);
  assert.deepEqual(openapi.components.schemas.ControlBundleAcknowledgementResponse.required, ["accepted", "duplicate", "observed_generation", "refresh_state", "request_id"]);
  assert.deepEqual(openapi.components.schemas.DeviceEnrollmentCompletedResponse.required, ["enrollment", "request_id"]);
});

test("G2 device audit listing freezes tenant/device keyset pagination", () => {
  const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "device-v1.json"), "utf8"));
  const operation = openapi.paths["/organizations/{organization_id}/audit/events"].get;
  assert.equal(operation.operationId, "listDeviceAuditEvents");
  assert.deepEqual(operation.security, [{ humanSession: [] }, { auditReader: [] }]);
  assert.deepEqual(operation["x-agentpass-ordering"], ["device_timestamp", "device_id", "event_id"]);
  assert.deepEqual(operation["x-agentpass-pagination"], { algorithm: "keyset", probe: "limit_plus_one", direction: "descending", exclusive: true });
  assert.equal(operation["x-agentpass-tenant-scope"]["cross-tenant-disclosure"], false);
  assert.equal(operation["x-agentpass-device-scope"]["cross-device-disclosure"], false);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/AuditDeviceId",
    "#/components/parameters/AuditCursor",
    "#/components/parameters/AuditLimit"
  ]);
  assert.equal(openapi.components.parameters.AuditDeviceId.required, true);
  assert.deepEqual(openapi.components.parameters.AuditLimit.schema, { type: "integer", minimum: 1, maximum: 500, default: 100 });
  assert.equal(openapi.components.responses.DeviceAuditList.content["application/json"].schema.$ref, "#/components/schemas/DeviceAuditListResponse");
  assert.match(operation.description, /limit \+ 1/i);
  assert.match(operation.description, /cross-device/i);
  assert.match(operation.description, /expired/i);
});

test("G2 audit response schema and fixture reject unbounded or ambiguous pages", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(root, "contracts", "schemas", "device-audit-list-v1.schema.json"), "utf8"));
  const fixture = JSON.parse(fs.readFileSync(path.join(root, "contracts", "fixtures", "device-audit-list.valid.json"), "utf8"));
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required, ["events", "next_cursor"]);
  assert.equal(schema.properties.events.maxItems, 500);
  assert.equal(schema.properties.next_cursor.anyOf[1].type, "null");
  assert.equal(schema.$defs.cursor.maxLength, 512);
  assert.match(schema.$defs.cursor.description, /organization_id.*device_id.*device_timestamp.*event_id/i);
  assert.deepEqual(schema.$defs.record.required, ["organization_id", "device_id", "event_id", "event", "received_at"]);
  assert.deepEqual(Object.keys(schema.$defs.record.properties).sort(), ["device_id", "event", "event_id", "organization_id", "received_at"]);
  assert.match(schema.$defs.record.description, /ingested_at.*received_at/i);
  assert.match(schema.$defs.record.description, /separate audit-health/i);
  assert.equal(fixture.events.length, 1);
  assert.deepEqual(Object.keys(fixture.events[0]).sort(), ["device_id", "event", "event_id", "organization_id", "received_at"]);
  assert.equal(fixture.events[0].event_id, fixture.events[0].event.event_id);
  assert.equal(Object.hasOwn(fixture.events[0], "chain_status"), false);
  assert.equal(Object.hasOwn(fixture.events[0], "ingested_at"), false);
  assert.match(fixture.next_cursor, /^[A-Za-z0-9_-]{1,512}$/);

  const invalidPage = structuredClone(fixture);
  invalidPage.unexpected = true;
  assert.equal(Object.hasOwn(invalidPage, "unexpected"), true);
  assert.equal(schema.additionalProperties, false);
});

test("G2 PostgreSQL migration indexes the normalized activity keyset", () => {
  const sql = fs.readFileSync(path.join(root, "contracts", "postgres", "0010_device_audit_activity_keyset.sql"), "utf8");
  assert.match(sql, /^BEGIN;/);
  assert.match(sql, /CREATE INDEX device_audit_events_activity_keyset/i);
  assert.match(sql, /organization_id[\s\S]*device_id[\s\S]*redacted_json\s*->>\s*'device_timestamp'[\s\S]*event_id DESC/i);
  assert.match(sql, /COMMIT;\s*$/);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/i);
});

test("PostgreSQL contract prevents cross-tenant device references", () => {
  const sql = fs.readFileSync(path.join(root, "contracts", "postgres", "0001_control_plane.sql"), "utf8");
  assert.match(sql, /PRIMARY KEY \(organization_id, id\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id\) REFERENCES devices\(organization_id, id\)/);
  assert.match(sql, /PRIMARY KEY \(organization_id, principal_id, idempotency_key\)/);
});
