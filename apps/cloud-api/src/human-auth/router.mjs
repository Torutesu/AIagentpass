const SESSION_PATH = "/api/auth/session";
const OPTIONS_PATH = "/api/auth/webauthn/options";
const VERIFY_PATH = "/api/auth/webauthn/verify";
const REGISTRATION_OPTIONS_PATH = "/api/auth/webauthn/registration/options";
const REGISTRATION_VERIFY_PATH = "/api/auth/webauthn/registration/verify";
const ORGANIZATIONS_PATH = "/api/auth/organizations";
const AGENT_SESSION_GRANTS_PATH = "/api/v1/organizations";
const ACCEPT_INVITATION_PATH = "/api/auth/invitations/accept";
const UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89a-fA-F][0-9a-fA-F]{3}-[0-9a-fA-F]{12}";
const ORGANIZATION_ROUTE = new RegExp(`^${ORGANIZATIONS_PATH}(?:/${UUID}(?:/members(?:/${UUID}/(?:role|remove))?|/invitations(?:/${UUID}/revoke)?)?)?$`);
const AGENT_SESSION_GRANT_ROUTE = new RegExp(`^${AGENT_SESSION_GRANTS_PATH}/${UUID}/agents/${UUID}/session-grants$`);

export function createHumanAuthRouter({ sessionApi, webauthnApi, registrationApi, managementApi, organizationApi, agentSessionGrantApi } = {}) {
  if (!sessionApi || typeof sessionApi.handle !== "function") throw new TypeError("sessionApi must expose handle()");
  if (!webauthnApi || typeof webauthnApi.handle !== "function") throw new TypeError("webauthnApi must expose handle()");
  if (!registrationApi || typeof registrationApi.handle !== "function") throw new TypeError("registrationApi must expose handle()");
  if (!managementApi || typeof managementApi.handle !== "function") throw new TypeError("managementApi must expose handle()");
  if (!organizationApi || typeof organizationApi.handle !== "function") throw new TypeError("organizationApi must expose handle()");
  if (agentSessionGrantApi !== undefined && (!agentSessionGrantApi || typeof agentSessionGrantApi.handle !== "function")) throw new TypeError("agentSessionGrantApi must expose handle()");

  async function handle(input) {
    const url = requestUrl(input);
    if (url.pathname === SESSION_PATH && !url.search && !url.hash) {
      return sessionApi.handle(cloneRequest(input, "/session"));
    }
    if ((url.pathname === OPTIONS_PATH || url.pathname === VERIFY_PATH) && !url.search && !url.hash) {
      return webauthnApi.handle(cloneRequest(input, url.pathname));
    }
    if ((url.pathname === REGISTRATION_OPTIONS_PATH || url.pathname === REGISTRATION_VERIFY_PATH) && !url.search && !url.hash) {
      return registrationApi.handle(cloneRequest(input, url.pathname));
    }
    if (isAgentSessionGrantPath(url)) {
      if (!agentSessionGrantApi) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      return agentSessionGrantApi.handle(cloneRequest(input, `${url.pathname}${url.search}`));
    }
    if (isOrganizationPath(url)) {
      const list = isOrganizationListPath(url, input);
      if (url.search && !list) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      return organizationApi.handle(cloneRequest(input, `${url.pathname}${list ? url.search : ""}`));
    }
    if (isManagementPath(url)) return managementApi.handle(cloneRequest(input, `${url.pathname}${url.search}`));
    return response(404, { error: { code: "not_found", message: "Resource not found" } });
  }

  return Object.freeze({ handle, paths: Object.freeze({ session: SESSION_PATH, options: OPTIONS_PATH, verify: VERIFY_PATH, registrationOptions: REGISTRATION_OPTIONS_PATH, registrationVerify: REGISTRATION_VERIFY_PATH, organizations: ORGANIZATIONS_PATH, acceptInvitation: ACCEPT_INVITATION_PATH }) });
}

function isOrganizationPath(url) {
  if (url.hash || url.pathname === ACCEPT_INVITATION_PATH) return url.pathname === ACCEPT_INVITATION_PATH && !url.hash;
  return ORGANIZATION_ROUTE.test(url.pathname);
}

function isAgentSessionGrantPath(url) {
  return !url.hash && AGENT_SESSION_GRANT_ROUTE.test(url.pathname);
}

function isOrganizationListPath(url, input) {
  if (String(input?.method ?? "").toUpperCase() !== "GET") return false;
  if (url.pathname === ORGANIZATIONS_PATH) return true;
  return new RegExp(`^${ORGANIZATIONS_PATH}/${UUID}/(?:members|invitations)$`).test(url.pathname);
}

function isManagementPath(url) {
  if (url.hash) return false;
  return /^\/api\/auth\/management\/(?:credentials(?:\/[A-Za-z0-9_-]+(?:\/revoke)?)?|sessions(?:\/[0-9a-fA-F-]{36}\/revoke)?)$/.test(url.pathname);
}

function requestUrl(input) {
  if (!input || typeof input !== "object") return new URL("/invalid", "https://agentpass.invalid");
  try { return new URL(String(input.url ?? input.path ?? ""), "https://agentpass.invalid"); }
  catch { return new URL("/invalid", "https://agentpass.invalid"); }
}

function cloneRequest(input, url) {
  return { method: input.method, url, headers: input.headers, body: input.body };
}

function response(status, body) {
  return Object.freeze({
    status,
    ok: false,
    headers: Object.freeze({ "Cache-Control": "no-store, max-age=0", "Pragma": "no-cache", "Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff" }),
    body: Object.freeze(body)
  });
}
