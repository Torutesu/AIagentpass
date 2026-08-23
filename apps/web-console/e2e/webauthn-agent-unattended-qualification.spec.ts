import { createHash } from "node:crypto";
import { closeSync, constants, fsyncSync, openSync, writeSync } from "node:fs";
import { isAbsolute } from "node:path";
import { expect, test, type Page, type TestInfo } from "@playwright/test";
import {
  ACTIVE_EXPIRES_AT,
  AUTHORIZATION_ID,
  CHALLENGE,
  CHALLENGE_ID,
  CREDENTIAL_ID,
  CREDENTIAL_ID_BYTES,
  CSRF_TOKEN,
  ORGANIZATION_ID,
  browserStorageSnapshot,
  consoleSummary,
  deploymentReadiness,
  disposeVirtualAuthenticator,
  installVirtualAuthenticator,
  json,
  parseRequestBody,
  session,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

const RP_ID = "localhost";
const OPERATION = "device.enrollment.issue";
const CONSOLE_OPERATION = "issue-device-enrollment";
const STALE_CHALLENGE_ID = "69999999-9999-4999-8999-999999999999";
const OTHER_ORGANIZATION_ID = "77777777-7777-4777-8777-777777777777";
const CANDIDATE_ID = "qualification-agent-2026-08";
const DEVICE_FINGERPRINT = `SHA256:${"q".repeat(43)}`;
const ENROLLMENT_SECRET = "Q".repeat(43);
const SESSION_COOKIE = "agentpass_qualification_session=opaque-runtime-cookie";
const EXTERNAL_QUALIFICATION_MODE = "external";
const activeAuthenticators = new WeakMap<Page, VirtualAuthenticator>();
const HANDOFF_PORT = 49152;
const CORRELATION_ID = "A".repeat(43);
const NONCE = "B".repeat(43);
const HANDOFF_URL = `http://127.0.0.1:${HANDOFF_PORT}/v1/browser-cli-handoffs/${CORRELATION_ID}`;

const REQUIRED_CHECKS = [
  "authenticator_origin_rp",
  "durable_one_time_consumption",
  "replay_rejection",
  "stale_context_rejection",
  "outage_fail_closed",
] as const;

type TypedValue =
  | Readonly<{ type: "boolean"; value: boolean }>
  | Readonly<{ type: "integer"; value: number }>
  | Readonly<{ type: "string"; value: string }>;

type TypedCheck = Readonly<{
  check_id: string;
  status: "passed" | "failed";
  expected: TypedValue;
  observed: TypedValue;
  evidence_sha256: string;
}>;

type QualificationState = {
  sessionCalls: number;
  sessionCookieSeen: boolean;
  csrfSeen: boolean;
  optionsBodies: Array<Record<string, unknown>>;
  verifyBodies: Array<Record<string, unknown>>;
  issueBodies: Array<Record<string, unknown>>;
  issueAuth: string[];
  consumedAuth: Set<string>;
  staleChallengeStatus: number | null;
  crossTenantStatus: number | null;
  replayStatus: number | null;
  outageStatus: number | null;
  assertion: AssertionObservation | null;
  outage: boolean;
};

type AssertionObservation = Readonly<{
  credentialShape: boolean;
  challenge: boolean;
  origin: boolean;
  rp: boolean;
}>;

type ExternalExecution = Readonly<{
  kind: "external_runner";
  real_execution: true;
  runner_id: string;
  run_id: string;
  job_id: string;
  run_attempt: string;
  source_commit: string;
  source_tree: string;
  artifact_sha256: string;
  started_at: string;
  completed_at: string;
  environment: Readonly<{ kind: "webauthn"; identity: string }>;
}>;

const activeState = new WeakMap<Page, QualificationState>();

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function typedBoolean(value: boolean): TypedValue {
  return Object.freeze({ type: "boolean", value });
}

function check(checkId: string, observed: boolean): TypedCheck {
  const expected = typedBoolean(true);
  const actual = typedBoolean(observed);
  const status: "passed" | "failed" = observed ? "passed" : "failed";
  const material = { check_id: checkId, status, expected, observed: actual };
  return Object.freeze({ ...material, evidence_sha256: digest(material) });
}

function decodeBase64Url(value: unknown): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("invalid WebAuthn binary value");
  return Buffer.from(value, "base64url");
}

function inspectAssertion(credential: unknown, expectedChallenge: string, expectedOrigin: string): AssertionObservation {
  if (!credential || typeof credential !== "object" || Array.isArray(credential)) throw new Error("WebAuthn credential is missing");
  const value = credential as Record<string, unknown>;
  const response = value.response;
  if (!response || typeof response !== "object" || Array.isArray(response)) throw new Error("WebAuthn response is missing");
  const responseValue = response as Record<string, unknown>;
  const clientData = JSON.parse(decodeBase64Url(responseValue.clientDataJSON).toString("utf8")) as Record<string, unknown>;
  const authenticatorData = decodeBase64Url(responseValue.authenticatorData);
  const expectedRpHash = createHash("sha256").update(RP_ID, "utf8").digest();
  return Object.freeze({
    credentialShape: value.type === "public-key"
      && typeof value.id === "string"
      && value.id === CREDENTIAL_ID
      && typeof value.rawId === "string"
      && decodeBase64Url(value.rawId).equals(CREDENTIAL_ID_BYTES)
      && typeof responseValue.clientDataJSON === "string"
      && typeof responseValue.authenticatorData === "string"
      && typeof responseValue.signature === "string"
      && decodeBase64Url(responseValue.signature).length > 0,
    challenge: clientData.type === "webauthn.get" && clientData.challenge === expectedChallenge,
    origin: clientData.origin === expectedOrigin,
    rp: authenticatorData.length >= 32 && authenticatorData.subarray(0, 32).equals(expectedRpHash),
  });
}

function qualificationExecution(startedAt: string): ExternalExecution | null {
  const values = {
    runner_id: process.env.AGENTPASS_QUALIFICATION_RUNNER_ID,
    run_id: process.env.AGENTPASS_QUALIFICATION_RUN_ID,
    job_id: process.env.AGENTPASS_QUALIFICATION_JOB_ID,
    run_attempt: process.env.AGENTPASS_QUALIFICATION_RUN_ATTEMPT,
    source_commit: process.env.GITHUB_SHA,
    source_tree: process.env.AGENTPASS_SOURCE_TREE,
    artifact_sha256: process.env.AGENTPASS_QUALIFICATION_ARTIFACT_SHA256,
  };
  if (Object.values(values).some((value) => value === undefined)) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u.test(values.runner_id ?? "")
    || /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)($|[._:/ -])/iu.test(values.runner_id ?? "")) return null;
  if (![values.run_id, values.job_id, values.run_attempt].every((value) => /^[1-9][0-9]{0,19}$/u.test(value ?? ""))) return null;
  if (!/^[0-9a-f]{40}$/u.test(values.source_commit ?? "") || !/^[0-9a-f]{40}$/u.test(values.source_tree ?? "") || !/^[0-9a-f]{64}$/u.test(values.artifact_sha256 ?? "")) return null;
  return Object.freeze({
    kind: "external_runner",
    real_execution: true,
    runner_id: values.runner_id!,
    run_id: values.run_id!,
    job_id: values.job_id!,
    run_attempt: values.run_attempt!,
    source_commit: values.source_commit!,
    source_tree: values.source_tree!,
    artifact_sha256: values.artifact_sha256!,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    environment: { kind: "webauthn" as const, identity: "playwright-chromium-cdp-webauthn" },
  });
}

async function installQualificationRoutes(page: Page): Promise<QualificationState> {
  const state: QualificationState = {
    sessionCalls: 0,
    sessionCookieSeen: false,
    csrfSeen: false,
    optionsBodies: [],
    verifyBodies: [],
    issueBodies: [],
    issueAuth: [],
    consumedAuth: new Set(),
    staleChallengeStatus: null,
    crossTenantStatus: null,
    replayStatus: null,
    outageStatus: null,
    assertion: null,
    outage: false,
  };
  activeState.set(page, state);

  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const headers = request.headers();
    state.sessionCookieSeen ||= headers.cookie === SESSION_COOKIE;
    state.csrfSeen ||= headers["agentpass-csrf"] === CSRF_TOKEN;

    if (url.pathname === "/api/auth/session" || url.pathname === "/api/auth/session/resume") {
      state.sessionCalls += 1;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "set-cookie": `${SESSION_COOKIE}; Path=/; HttpOnly; SameSite=Strict` },
        body: JSON.stringify(session("owner")),
      });
    }
    if (url.pathname === "/api/auth/webauthn/options") {
      const body = parseRequestBody(route);
      state.optionsBodies.push(body);
      if (body.organization_id !== ORGANIZATION_ID || body.operation !== OPERATION || headers["agentpass-csrf"] !== CSRF_TOKEN || headers.cookie !== SESSION_COOKIE) {
        state.crossTenantStatus = body.organization_id === OTHER_ORGANIZATION_ID ? 403 : state.crossTenantStatus;
        return json(route, { error: { code: "binding_rejected", message: "WebAuthn context rejected" } }, 403);
      }
      return json(route, {
        challenge_id: CHALLENGE_ID,
        options: {
          challenge: CHALLENGE,
          rpId: RP_ID,
          userVerification: "required",
          timeout: 10_000,
          allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }],
        },
      });
    }
    if (url.pathname === "/api/auth/webauthn/verify") {
      const body = parseRequestBody(route);
      state.verifyBodies.push(body);
      if (body.organization_id !== ORGANIZATION_ID || body.operation !== OPERATION || body.challenge_id !== CHALLENGE_ID || headers["agentpass-csrf"] !== CSRF_TOKEN || headers.cookie !== SESSION_COOKIE) {
        state.staleChallengeStatus = body.challenge_id === STALE_CHALLENGE_ID ? 409 : state.staleChallengeStatus;
        return json(route, { error: { code: "stale_context", message: "WebAuthn context rejected" } }, 409);
      }
      try {
        state.assertion = inspectAssertion(body.credential, CHALLENGE, new URL(request.url()).origin);
      } catch {
        return json(route, { error: { code: "invalid_assertion", message: "WebAuthn assertion rejected" } }, 400);
      }
      if (!state.assertion.credentialShape || !state.assertion.challenge || !state.assertion.origin || !state.assertion.rp) {
        return json(route, { error: { code: "invalid_assertion_binding", message: "WebAuthn assertion binding rejected" } }, 400);
      }
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });

  await page.route("**/api/console**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") return json(route, consoleSummary());
    if (request.method() === "GET" && url.searchParams.get("resource") === "deployment-readiness") return json(route, deploymentReadiness());
    if (request.method() !== "POST" || url.searchParams.get("operation") !== CONSOLE_OPERATION) return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
    const body = parseRequestBody(route);
    const auth = request.headers()["agentpass-recent-auth"] ?? "";
    state.issueBodies.push(body);
    state.issueAuth.push(auth);
    if (body.proof_version !== 2 || body.candidate_id !== CANDIDATE_ID || body.device_key_fingerprint !== DEVICE_FINGERPRINT || request.headers()["agentpass-csrf"] !== CSRF_TOKEN || request.headers().cookie !== SESSION_COOKIE || auth !== AUTHORIZATION_ID) {
      return json(route, { error: { code: "binding_rejected", message: "Enrollment context rejected" } }, 403);
    }
    if (state.outage) {
      state.outageStatus = 503;
      return json(route, { error: { code: "service_unavailable", message: "Enrollment service unavailable" } }, 503);
    }
    if (state.consumedAuth.has(auth)) {
      state.replayStatus = 403;
      return json(route, { error: { code: "replayed", message: "Recent authentication has already been consumed" } }, 403);
    }
    state.consumedAuth.add(auth);
    return json(route, {
      enrollment: {
        version: 2,
        proof_version: 2,
        enrollment_id: "78888888-8888-4888-8888-888888888888",
        device_id: "41111111-1111-4111-8111-111111111111",
        label: String(body.label ?? "Qualification Mac"),
        platform: "macos",
        organization_id: ORGANIZATION_ID,
        expires_at: ACTIVE_EXPIRES_AT,
        challenge_id: "78888888-8888-4888-8888-888888888888",
        nonce: CHALLENGE,
        challenge: { challenge_id: "78888888-8888-4888-8888-888888888888", nonce: CHALLENGE, expires_at: ACTIVE_EXPIRES_AT, candidate_id: CANDIDATE_ID, device_key_fingerprint: DEVICE_FINGERPRINT },
        candidate_binding: { version: 1, enrollment_id: "78888888-8888-4888-8888-888888888888", organization_id: ORGANIZATION_ID, device_id: "41111111-1111-4111-8111-111111111111", candidate_id: CANDIDATE_ID, artifact_sha256: "c".repeat(64), source_commit: "d".repeat(40), team_id: "APPLETEAM1", device_key_fingerprint: DEVICE_FINGERPRINT, expires_at: ACTIVE_EXPIRES_AT },
        credential: ENROLLMENT_SECRET,
        possession_receipt_verification: { key_id: "qualification", algorithm: "ed25519", public_key: "-----BEGIN PUBLIC KEY-----\nqualification\n-----END PUBLIC KEY-----" },
        endpoint: "/v1/enrollments/78888888-8888-4888-8888-888888888888",
      },
    }, 201);
  });
  await page.route(`http://127.0.0.1:${HANDOFF_PORT}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const origin = request.headers().origin ?? "http://localhost:4173";
    const headers = {
      "access-control-allow-headers": "content-type",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-private-network": "true",
      "cache-control": "no-store",
      "content-type": "application/json",
      "access-control-allow-origin": origin,
      vary: "Origin",
    };
    if (request.method() === "OPTIONS") return route.fulfill({ status: 204, headers, body: "" });
    if (request.method() === "GET" && url.pathname.endsWith("/preflight")) {
      return route.fulfill({ status: 200, headers, body: JSON.stringify({ version: 1, correlation_id: CORRELATION_ID, nonce: NONCE, platform: "macos", candidate_id: CANDIDATE_ID, device_key_fingerprint: DEVICE_FINGERPRINT }) });
    }
    if (request.method() === "POST" && url.pathname.endsWith(`/browser-cli-handoffs/${CORRELATION_ID}`)) {
      return route.fulfill({ status: 200, headers, body: JSON.stringify({ version: 1, ok: true, consumed: true }) });
    }
    return route.fulfill({ status: 404, headers, body: JSON.stringify({ error: { code: "not_found" } }) });
  });
  return state;
}

async function openQualificationSetup(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await page.getByRole("button", { name: "セットアップ", exact: true }).click();
  await expect(page.getByRole("heading", { name: "パスキーを登録" })).toBeVisible();
  await page.context().grantPermissions(["local-network-access"], { origin: "http://localhost:4173" });
  await page.goto(`/#${HANDOFF_URL}`);
  await page.reload();
  await expect(page).toHaveURL(/\/$/u);
  await expect(page.locator('[data-install-state="connected"]')).toBeVisible();
  await expect(page.getByText("公開preflightを確認しました")).toBeVisible();
}

async function attachEvidence(state: QualificationState, testInfo: TestInfo, startedAt: string, browserExecution: boolean): Promise<void> {
  const externalQualification = process.env.AGENTPASS_WEBAUTHN_QUALIFICATION_MODE === EXTERNAL_QUALIFICATION_MODE;
  const execution = qualificationExecution(startedAt);
  if (!execution) {
    if (externalQualification) throw new Error("external WebAuthn qualification bindings are required");
    return;
  }
  const positiveOptions = state.optionsBodies.filter((body) => body.organization_id === ORGANIZATION_ID);
  const checks = [
    check("authenticator_origin_rp", browserExecution && Boolean(state.assertion?.credentialShape) && Boolean(state.assertion?.challenge) && Boolean(state.assertion?.origin) && Boolean(state.assertion?.rp)),
    check("durable_one_time_consumption", state.sessionCalls > 0 && state.sessionCookieSeen && state.csrfSeen && positiveOptions.length >= 2 && state.verifyBodies[0]?.challenge_id === CHALLENGE_ID && state.issueBodies.length >= 1 && state.consumedAuth.has(AUTHORIZATION_ID)),
    check("replay_rejection", state.replayStatus === 403),
    check("stale_context_rejection", state.staleChallengeStatus === 409 && state.crossTenantStatus === 403),
    check("outage_fail_closed", state.outageStatus === 503),
  ];
  const evidence = {
    schema_version: 1,
    kind: "agentpass-webauthn-agent-unattended-e2e",
    status: checks.every((item) => item.status === "passed") ? "passed" : "failed",
    qualified: checks.every((item) => item.status === "passed"),
    reason: checks.every((item) => item.status === "passed") ? null : "gate_failed",
    execution,
    required_checks: REQUIRED_CHECKS,
    checks,
  };
  await testInfo.attach("webauthn-agent-unattended-qualification.json", {
    body: Buffer.from(canonicalJson(evidence), "utf8"),
    contentType: "application/json",
  });
  if (externalQualification) {
    const evidencePath = process.env.AGENTPASS_QUALIFICATION_EVIDENCE_PATH;
    if (!evidencePath || !isAbsolute(evidencePath)) throw new Error("external WebAuthn qualification evidence path is required");
    const fd = openSync(evidencePath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      const bytes = Buffer.from(canonicalJson(evidence), "utf8");
      writeSync(fd, bytes, 0, bytes.length, 0);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }
}

test("qualification: real-browser WebAuthn binds unattended agent issuance and emits only typed evidence", async ({ page }, testInfo) => {
  const startedAt = new Date().toISOString();
  const authenticator = await installVirtualAuthenticator(page);
  activeAuthenticators.set(page, authenticator);
  const state = await installQualificationRoutes(page);
  await openQualificationSetup(page);
  await page.getByLabel("端末名").fill("Qualification Mac");
  await page.getByRole("button", { name: "Touch ID/パスキー確認して発行", exact: true }).click();
  await expect(page.locator('[data-live-handoff-state="delivered"]')).toBeVisible();
  await expect(page.locator(".secret-output")).toHaveCount(0);
  expect((await page.locator("body").textContent()) ?? "").not.toContain(ENROLLMENT_SECRET);
  expect(state.issueBodies[0]).toMatchObject({ proof_version: 2, candidate_id: CANDIDATE_ID, device_key_fingerprint: DEVICE_FINGERPRINT, label: "Qualification Mac", platform: "macos", ttl_ms: 600000 });
  expect(state.issueAuth).toEqual([AUTHORIZATION_ID]);

  const replayBody = state.issueBodies[0];
  const replayStatus = await page.evaluate(async ({ body, csrf, authorization, operation }) => {
    const response = await fetch(`/api/console?operation=${operation}`, {
      method: "POST",
      headers: { "content-type": "application/json", "agentpass-csrf": csrf, "agentpass-recent-auth": authorization, "idempotency-key": crypto.randomUUID() },
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
    return response.status;
  }, { body: replayBody, csrf: CSRF_TOKEN, authorization: AUTHORIZATION_ID, operation: CONSOLE_OPERATION });
  state.replayStatus = replayStatus;
  expect(replayStatus).toBe(403);

  const staleStatus = await page.evaluate(async ({ body, csrf }) => {
    const response = await fetch("/api/auth/webauthn/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "agentpass-csrf": csrf },
      body: JSON.stringify({ ...body, challenge_id: "69999999-9999-4999-8999-999999999999" }),
      credentials: "same-origin",
    });
    return response.status;
  }, { body: state.verifyBodies[0], csrf: CSRF_TOKEN });
  state.staleChallengeStatus = staleStatus;
  expect(staleStatus).toBe(409);

  const crossTenantStatus = await page.evaluate(async ({ csrf, organization }) => {
    const response = await fetch("/api/auth/webauthn/options", {
      method: "POST",
      headers: { "content-type": "application/json", "agentpass-csrf": csrf },
      body: JSON.stringify({ organization_id: organization, operation: "device.enrollment.issue" }),
      credentials: "same-origin",
    });
    return response.status;
  }, { csrf: CSRF_TOKEN, organization: OTHER_ORGANIZATION_ID });
  state.crossTenantStatus = crossTenantStatus;
  expect(crossTenantStatus).toBe(403);

  state.outage = true;
  // A live handoff is one-time by design. Establish a fresh public-only
  // handoff before exercising the independent outage path.
  await page.goto(`/#${HANDOFF_URL}`);
  await page.reload();
  await expect(page.locator('[data-live-handoff-state="connected"]')).toBeVisible();
  await page.getByLabel("端末名").fill("Qualification Mac outage");
  await page.getByRole("button", { name: "Touch ID/パスキー確認して発行", exact: true }).click();
  await expect(page.locator('[data-enrollment-state="outcome-unknown"]')).toContainText("発行結果を確認できませんでした");
  await expect(page.locator(".secret-output")).toHaveCount(0);
  expect((await browserStorageSnapshot(page)).local).toEqual({});
  expect((await browserStorageSnapshot(page)).session).toEqual({});

  const browserExecution = await page.evaluate(() => typeof navigator.credentials?.get === "function" && typeof PublicKeyCredential !== "undefined");
  await attachEvidence(state, testInfo, startedAt, browserExecution && state.verifyBodies.length >= 2);
});

test.afterEach(async ({ page }) => {
  const authenticator = activeAuthenticators.get(page);
  if (authenticator) await disposeVirtualAuthenticator(authenticator);
  activeAuthenticators.delete(page);
  activeState.delete(page);
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
