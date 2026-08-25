import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { Readable } from "node:stream";

import {
  PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH,
  PLATFORM_PROMOTION_ISSUE_PATH,
  PLATFORM_PROMOTION_REPLAY_PATH
} from "../src/platform-promotion-http-contract.mjs";
import {
  PLATFORM_PROMOTION_JTI_HEADER,
  PLATFORM_PROMOTION_PROOF_ID_HEADER
} from "../src/platform-promotion-http-api.mjs";
import { PLATFORM_SESSION_HTTP_PATHS } from "../src/platform-session-http-api.mjs";
import {
  PLATFORM_SESSION_COOKIE_NAME,
  PLATFORM_SESSION_CSRF_HEADER
} from "../src/platform-session-transport.mjs";
import { createCloudApi } from "../src/server.mjs";
import { CLOUD_RUNTIME_PROFILE_ERROR_CODES, parseCloudRuntimeProfile } from "../src/runtime-profile.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "../../..");
const matrix = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "contracts/route-profile-authority-matrix-v1.json"), "utf8"));
const platformOpenApi = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "contracts/openapi/platform-v1.json"), "utf8"));
const runtimeSource = fs.readFileSync(path.join(repositoryRoot, "apps/cloud-api/src/runtime.mjs"), "utf8");
const serverSource = fs.readFileSync(path.join(repositoryRoot, "apps/cloud-api/src/server.mjs"), "utf8");

const routeById = new Map(matrix.routes.map((route) => [route.id, route]));
const legacyById = new Map(matrix.legacy_routes.map((route) => [route.id, route]));

function routeShape(route) {
  return `${route.method} ${route.path}`;
}

async function dispatch(server, { method = "POST", url, headers = {}, body = "" } = {}) {
  const request = Readable.from([Buffer.from(body)]);
  request.method = method;
  request.url = url;
  request.headers = headers;
  request.socket = { remoteAddress: "203.0.113.9" };
  return new Promise((resolve, reject) => {
    const response = {
      headersSent: false,
      statusCode: 200,
      headers: {},
      writeHead(status, values = {}) { this.statusCode = status; this.headers = { ...values }; this.headersSent = true; },
      setHeader(name, value) { this.headers[name] = value; },
      end(value) { this.body = value; resolve(this); },
      destroy(error) { reject(error ?? new Error("response destroyed")); }
    };
    server.emit("request", request, response);
  });
}

test("matrix freezes the exact hosted Platform Session and promotion route set", () => {
  const hosted = matrix.profiles.hosted;
  assert.deepEqual(hosted.active_routes, [
    "platform.session.challenge",
    "platform.session.assertion",
    "platform.session.revoke",
    "platform.promotion.issue"
  ]);
  assert.deepEqual(
    hosted.active_routes.map((id) => routeShape(routeById.get(id))),
    [
      "POST /api/platform/v1/sessions/challenges",
      "POST /api/platform/v1/sessions",
      "POST /api/platform/v1/sessions/revoke",
      "POST /api/platform/v1/promotions"
    ]
  );
  assert.deepEqual(PLATFORM_SESSION_HTTP_PATHS, {
    challenge: "/api/platform/v1/sessions/challenges",
    begin: "/api/platform/v1/sessions/challenges",
    assertion: "/api/platform/v1/sessions",
    verify: "/api/platform/v1/sessions",
    revoke: "/api/platform/v1/sessions/revoke"
  });
  assert.equal(PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH, "/api/platform/v1/promotions");
  assert.deepEqual(
    Object.entries(platformOpenApi.paths).map(([route, methods]) => `${Object.keys(methods).find((method) => method !== "parameters").toUpperCase()} ${route}`).sort(),
    [
      "POST /api/platform/v1/promotions",
      "POST /api/platform/v1/sessions",
      "POST /api/platform/v1/sessions/challenges",
      "POST /api/platform/v1/sessions/revoke"
    ].sort()
  );
});

test("matrix freezes authentication transport and database authority", () => {
  const challenge = routeById.get("platform.session.challenge");
  const assertion = routeById.get("platform.session.assertion");
  const revoke = routeById.get("platform.session.revoke");
  const promotion = routeById.get("platform.promotion.issue");
  assert.equal(challenge.authentication_transport.cookie, "__Host-agentpass_session");
  assert.equal(assertion.authentication_transport.cookie, null);
  assert.equal(revoke.authentication_transport.cookie, PLATFORM_SESSION_COOKIE_NAME);
  assert.equal(promotion.authentication_transport.cookie, PLATFORM_SESSION_COOKIE_NAME);
  assert.deepEqual(revoke.authentication_transport.headers, ["Origin", PLATFORM_SESSION_CSRF_HEADER]);
  assert.deepEqual(promotion.authentication_transport.headers, [
    "Origin",
    PLATFORM_SESSION_CSRF_HEADER,
    PLATFORM_PROMOTION_PROOF_ID_HEADER,
    PLATFORM_PROMOTION_JTI_HEADER,
    "Idempotency-Key"
  ]);
  assert.equal(promotion.authority.source, "postgresql");
  assert.match(promotion.authority.operation, /0054 atomic Platform authorization reservation/u);
  assert.equal(challenge.authority.source, "postgresql");
  assert.equal(assertion.authority.source, "postgresql");
  assert.equal(revoke.authority.source, "postgresql");

  assert.match(runtimeSource, /postgresRuntime\.platformSessionWebAuthnRepository/u);
  assert.match(runtimeSource, /postgresRuntime\.createPlatformAuthorizationRepository/u);
  assert.match(runtimeSource, /createPlatformPromotionHttpApi\(/u);
  assert.match(runtimeSource, /platformSessionHttpApi\.expectedOrigin/u);
  assert.match(serverSource, /isPlatformSessionHttpPath\(request\.url/u);
  assert.match(serverSource, /isPlatformPromotionHttpIssuePath\(request\.url/u);
});

test("hosted raw dispatch reaches only the authorized boundaries and never legacy routes", async () => {
  const calls = [];
  const humanCalls = [];
  const platformSessionHttpApi = {
    paths: PLATFORM_SESSION_HTTP_PATHS,
    async handle(request, response) {
      calls.push(["session", request.method, request.url]);
      for await (const _chunk of request) {}
      response.writeHead(209);
      response.end(JSON.stringify({ ok: true }));
    }
  };
  const platformPromotionHttpApi = {
    paths: { issue: PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH },
    async handle(request, response) {
      calls.push(["promotion", request.method, request.url]);
      for await (const _chunk of request) {}
      response.writeHead(210);
      response.end(JSON.stringify({ ok: true }));
    }
  };
  const server = createCloudApi({
    store: {},
    platformSessionHttpApi,
    platformPromotionHttpApi,
    humanSession: { async authenticateRequest(input) { humanCalls.push(input); return { session: {} }; } }
  });

  const session = await dispatch(server, { url: PLATFORM_SESSION_HTTP_PATHS.challenge, body: "{}" });
  const promotion = await dispatch(server, { url: PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH, body: "{}" });
  const legacyIssue = await dispatch(server, { url: PLATFORM_PROMOTION_ISSUE_PATH, body: "{}" });
  const legacyReplay = await dispatch(server, { url: PLATFORM_PROMOTION_REPLAY_PATH, body: "{}" });
  const sessionReplay = await dispatch(server, { url: "/api/platform/v1/sessions/replay", body: "{}" });

  assert.equal(session.statusCode, 209);
  assert.equal(promotion.statusCode, 210);
  assert.equal(legacyIssue.statusCode, 404);
  assert.equal(legacyReplay.statusCode, 404);
  assert.equal(sessionReplay.statusCode, 404);
  assert.deepEqual(calls, [
    ["session", "POST", PLATFORM_SESSION_HTTP_PATHS.challenge],
    ["promotion", "POST", PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH]
  ]);
  assert.deepEqual(humanCalls, []);
  assert.equal(legacyById.get("legacy.platform.promotion.issue").profiles.hosted, "absent");
  assert.equal(legacyById.get("legacy.platform.promotion.replay").profiles.hosted, "absent");
});

test("evaluation is explicit and development cannot become an implicit authority profile", () => {
  assert.equal(matrix.profiles.evaluation.runtime_status, "accepted");
  assert.deepEqual(matrix.profiles.evaluation.active_routes, []);
  assert.equal(matrix.profiles.evaluation.legacy_route_policy, "not-composed");
  assert.throws(
    () => parseCloudRuntimeProfile({ AGENTPASS_CLOUD_PROFILE: "development" }),
    (error) => error?.code === CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_UNKNOWN
  );
  assert.equal(matrix.profiles.development.runtime_status, "rejected");
  assert.equal(matrix.profiles.development.rejection_code, CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_UNKNOWN);
});
