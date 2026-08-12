const SESSION_PATH = "/api/auth/session";
const OPTIONS_PATH = "/api/auth/webauthn/options";
const VERIFY_PATH = "/api/auth/webauthn/verify";

export function createHumanAuthRouter({ sessionApi, webauthnApi } = {}) {
  if (!sessionApi || typeof sessionApi.handle !== "function") throw new TypeError("sessionApi must expose handle()");
  if (!webauthnApi || typeof webauthnApi.handle !== "function") throw new TypeError("webauthnApi must expose handle()");

  async function handle(input) {
    const url = requestUrl(input);
    if (url.pathname === SESSION_PATH && !url.search && !url.hash) {
      return sessionApi.handle(cloneRequest(input, "/session"));
    }
    if ((url.pathname === OPTIONS_PATH || url.pathname === VERIFY_PATH) && !url.search && !url.hash) {
      return webauthnApi.handle(cloneRequest(input, url.pathname));
    }
    return response(404, { error: { code: "not_found", message: "Resource not found" } });
  }

  return Object.freeze({ handle, paths: Object.freeze({ session: SESSION_PATH, options: OPTIONS_PATH, verify: VERIFY_PATH }) });
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
