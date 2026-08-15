import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const DEFAULT_ROOT = path.resolve(import.meta.dirname, "..");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const EXPECTED_ROUTE_IDS = [
  "hosted.github.start",
  "hosted.github.callback",
  "hosted.bootstrap.status",
  "hosted.bootstrap.organization.create",
  "hosted.bootstrap.webauthn.options",
  "hosted.bootstrap.webauthn.verify"
];
const FORBIDDEN_FIELDS = ["provider", "subject", "github_subject", "email", "member_id", "organization_id", "membership_id", "role"];
const REQUIRED_FILES = [
  "contracts/postgres/0001_control_plane.sql",
  "contracts/postgres/0004_human_identity_and_webauthn_registration.sql",
  "contracts/postgres/0057_hosted_identity_bootstrap.sql",
  "contracts/postgres/0058_hosted_oauth_pkce_envelope.sql",
  "contracts/schemas/human-session-v1.schema.json",
  "contracts/schemas/webauthn-ceremony-v1.schema.json",
  "apps/cloud-api/src/human-session.mjs",
  "apps/cloud-api/src/human-auth/identity/signed-console.mjs",
  "apps/cloud-api/src/human-auth/organizations/postgres-service.mjs",
  "apps/cloud-api/src/human-auth/webauthn/registration.mjs"
];

export const CONTRACT_PATH = "contracts/hosted-identity-bootstrap-v1.contract.json";

export function validateHostedIdentityBootstrapContract(document, { root = DEFAULT_ROOT } = {}) {
  const failures = [];
  const fail = (message) => failures.push(message);
  const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const exactKeys = (value, keys, label) => {
    if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`${label} has an unexpected field set`);
  };
  const includes = (array, value, label) => {
    if (!Array.isArray(array) || !array.includes(value)) fail(`${label} is missing ${value}`);
  };

  if (!isObject(document)) fail("contract must be an object");
  if (isObject(document)) {
    if (document.contract_type !== "agentpass.hosted_identity_bootstrap") fail("contract_type is not the hosted identity/bootstrap contract");
    if (document.contract_id !== "agentpass.hosted-identity-bootstrap") fail("contract_id is not pinned");
    if (document.version !== 1 || document.status !== "frozen" || document.profile !== "hosted") fail("contract version/status/profile is not frozen Hosted v1");
    if (document.activation?.prerequisite_forward_migration !== "0056_identity_epoch_invalidation"
      || document.activation?.planned_forward_migration !== "0057_hosted_identity_bootstrap"
      || document.activation?.pkce_hardening_forward_migration !== "0058_hosted_oauth_pkce_envelope") fail("migration ordering is not pinned after identity epoch invalidation");

    const authority = document.authority;
    if (!isObject(authority) || authority.identity_provider !== "github" || authority.server_authority !== "postgresql") fail("authority is not GitHub/PostgreSQL");
    if (!isObject(authority) || authority.subject_verification?.some((item) => /browser-supplied access token|server calls github \/user/i.test(item)) !== true) fail("server-side GitHub subject verification is not encoded");
    for (const field of FORBIDDEN_FIELDS) includes(authority.forbidden_caller_authority_fields, field, "forbidden caller authority fields");
    if (!authority.forbidden_identity_sources?.some((item) => /ChatGPT-only ambient identity/i.test(item))) fail("ChatGPT-only ambient identity is not forbidden");

    const routes = document.routes;
    if (!Array.isArray(routes) || JSON.stringify(routes.map((route) => route.id)) !== JSON.stringify(EXPECTED_ROUTE_IDS)) fail("route inventory/order is not the frozen six-route path");
    const routeIds = new Set();
    const routePaths = new Set();
    for (const route of routes ?? []) {
      if (!isObject(route) || typeof route.id !== "string" || routeIds.has(route.id)) fail("route ids must be unique");
      routeIds.add(route.id);
      const pathKey = `${route.method} ${route.path}`;
      if (routePaths.has(pathKey)) fail(`route is duplicated: ${pathKey}`);
      routePaths.add(pathKey);
      if (!/^\/api\/auth\/bootstrap\/|^\/api\/auth\/bootstrap\/github\//u.test(route.path)) fail(`route path is outside bootstrap namespace: ${route.path}`);
      if (route.method !== "GET" && route.method !== "POST") fail(`unsupported method in ${route.id}`);
      const request = route.request;
      if (!isObject(request)) fail(`${route.id} request contract is missing`);
      if (route.id === "hosted.bootstrap.organization.create") {
        if (JSON.stringify(request.body_exact_keys) !== JSON.stringify(["name"])) fail("organization create body is not exactly name");
        for (const field of FORBIDDEN_FIELDS) includes(request.forbidden_body_keys, field, "organization create forbidden body fields");
        includes(request.headers, "Origin", "organization create headers");
        includes(request.headers, "agentpass-bootstrap-csrf", "organization create headers");
        includes(request.headers, "Idempotency-Key", "organization create headers");
        if (route.response?.first_status !== 201 || route.response?.replay_status !== 200) fail("organization create idempotent statuses are not pinned");
      }
      if (route.id.includes("webauthn")) {
        includes(request.headers, "Origin", `${route.id} headers`);
        includes(request.headers, "agentpass-bootstrap-csrf", `${route.id} headers`);
        includes(request.cookies, "__Host-agentpass_bootstrap", `${route.id} cookies`);
      }
    }

    const states = document.state_machine?.states;
    for (const state of ["organization_required", "webauthn_required", "ready", "no_membership", "completed", "expired"]) includes(states, state, "state machine states");
    const membership = document.state_machine?.membership_decisions;
    if (!isObject(membership) || !/(zero memberships?|never had a membership)/i.test(membership.existing_user_with_zero_memberships ?? "") || !/revoked/i.test(membership.existing_user_with_revoked_membership_history ?? "")) fail("existing/no-membership behavior is underspecified");
    if (!/server-created as owner/i.test(membership.caller_role ?? "")) fail("caller role authority is not rejected");

    const cookies = document.transport?.cookies;
    const cookieByName = new Map((cookies ?? []).map((cookie) => [cookie.name, cookie]));
    for (const name of ["__Host-agentpass_github_state", "__Host-agentpass_bootstrap", "__Host-agentpass_session"]) {
      const cookie = cookieByName.get(name);
      if (!cookie || cookie.http_only !== true || cookie.secure !== true || cookie.path !== "/") fail(`${name} is not a Host/HttpOnly/Secure/path cookie`);
    }
    if (cookieByName.get("__Host-agentpass_github_state")?.same_site !== "Lax" || cookieByName.get("__Host-agentpass_bootstrap")?.same_site !== "Strict" || cookieByName.get("__Host-agentpass_session")?.same_site !== "Strict") fail("cookie SameSite policy is not pinned");
    if (document.transport?.csrf?.bootstrap_header !== "agentpass-bootstrap-csrf") fail("bootstrap CSRF header is not pinned");
    if (!document.transport?.forbidden_headers?.includes("Authorization")) fail("Authorization header is not forbidden");

    const idempotency = document.idempotency?.organization_create;
    if (!isObject(idempotency) || idempotency.header !== "Idempotency-Key" || idempotency.format !== "8-255 ASCII characters matching [A-Za-z0-9._~-]") fail("organization idempotency contract is not pinned");
    if (!IDEMPOTENCY_KEY.test("bootstrap-2026")) fail("validator idempotency regex is invalid");
    for (const code of ["bootstrap_idempotency_conflict", "bootstrap_already_completed", "bootstrap_no_membership", "bootstrap_webauthn_required", "bootstrap_unavailable"]) {
      if (!document.errors?.some((error) => error.code === code)) fail(`missing stable error ${code}`);
    }
    const errors = document.errors ?? [];
    const errorCodes = new Set();
    for (const error of errors) {
      if (!isObject(error) || typeof error.code !== "string" || errorCodes.has(error.code) || !Number.isInteger(error.status) || error.status < 400 || error.status > 599) fail("error inventory contains duplicate or invalid entries");
      errorCodes.add(error.code);
    }
    if (!/restart GitHub OAuth/i.test(document.recovery_boundary?.bootstrap ?? "") || !/existing owner recovery/i.test(document.recovery_boundary?.post_onboarding ?? "")) fail("recovery boundary is not explicit");
    if (!/forward migration/i.test(document.migration_compatibility?.forward_only_requirement ?? "") || !/v2/i.test(document.migration_compatibility?.versioning ?? "")) fail("migration/version policy is not explicit");
    if (JSON.stringify(document).match(/PRIVATE KEY|client_secret|access_token|raw_token|csrf_token_hash/iu)) fail("contract contains secret material or server-only hash fields");
  }

  for (const relative of REQUIRED_FILES) if (!fs.existsSync(path.join(root, relative))) fail(`required compatibility file is missing: ${relative}`);
  if (failures.length > 0) throw new Error(`Hosted identity/bootstrap contract invalid: ${failures.join("; ")}`);
  return Object.freeze({ contract_id: document.contract_id, version: document.version, route_count: document.routes.length, error_count: document.errors.length });
}

export function readAndValidateHostedIdentityBootstrapContract({ root = DEFAULT_ROOT, contractPath = path.join(root, CONTRACT_PATH) } = {}) {
  let document;
  try { document = JSON.parse(fs.readFileSync(contractPath, "utf8")); }
  catch (error) { throw new Error(`Hosted identity/bootstrap contract cannot be read: ${error.message}`); }
  return validateHostedIdentityBootstrapContract(document, { root });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const result = readAndValidateHostedIdentityBootstrapContract({ root: path.resolve(process.env.AGENTPASS_REPOSITORY_ROOT ?? DEFAULT_ROOT) });
    process.stdout.write(`hosted identity/bootstrap contract valid: ${result.contract_id} v${result.version}, ${result.route_count} routes, ${result.error_count} errors\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
