import { authenticateApiToken } from "../auth.mjs";

const USER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ASSERTION_TTL_MS = 30_000;

/**
 * Server-to-server identity seam for the current SIWC Console BFF.
 *
 * The browser never receives the Cloud service token. The BFF first verifies
 * SIWC and then presents its service credential plus the verified upstream
 * subject. Hosted deployments can replace this adapter with OIDC/mTLS without
 * changing the Human Session HTTP boundary.
 */
export function createConsoleIdentityAdapter({ tokenRecords, now = () => Date.now() } = {}) {
  if (!Array.isArray(tokenRecords) || tokenRecords.length < 1) throw new TypeError("tokenRecords are required");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  const issuedAssertions = new WeakSet();

  async function verifyIdentityRequest(request) {
    const headers = request?.headers;
    const authorization = header(headers, "authorization");
    const consoleUserId = header(headers, "agentpass-console-user-id");
    if (typeof authorization !== "string" || !authorization.startsWith("Bearer ") || authorization.length > 8192 || typeof consoleUserId !== "string" || !USER_ID.test(consoleUserId)) throw new Error("console identity request is invalid");
    const principal = authenticateApiToken(authorization.slice(7), tokenRecords);
    const issuedAt = clock(now());
    const assertion = Object.freeze({
      version: 1,
      console_user_id: consoleUserId,
      member_id: principal.member_id,
      organization_id: principal.organization_id,
      role: principal.role,
      issued_at: issuedAt,
      expires_at: issuedAt + ASSERTION_TTL_MS,
    });
    issuedAssertions.add(assertion);
    return assertion;
  }

  async function verify(assertion, context = {}) {
    const current = clock(context.now ?? now());
    if (!plain(assertion) || !issuedAssertions.has(assertion) || !exactKeys(assertion, ["version", "console_user_id", "member_id", "organization_id", "role", "issued_at", "expires_at"]) || assertion.version !== 1 || typeof assertion.console_user_id !== "string" || !USER_ID.test(assertion.console_user_id) || !uuid(assertion.member_id) || !uuid(assertion.organization_id) || !["owner", "admin", "auditor", "viewer"].includes(assertion.role) || !Number.isSafeInteger(assertion.issued_at) || !Number.isSafeInteger(assertion.expires_at) || assertion.expires_at - assertion.issued_at !== ASSERTION_TTL_MS || assertion.issued_at > current + 5_000 || assertion.expires_at <= current) throw new Error("console identity assertion is invalid");
    return Object.freeze({ member_id: assertion.member_id, organization_id: assertion.organization_id, role: assertion.role, assertion_expires_at: assertion.expires_at });
  }

  return Object.freeze({ verifyIdentityRequest, identityAdapter: Object.freeze({ verify }), assertionTtlMs: ASSERTION_TTL_MS });
}

function header(headers, name) {
  if (headers && typeof headers.get === "function") return headers.get(name) ?? undefined;
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return undefined;
  const matches = Object.entries(headers).filter(([key]) => key.toLowerCase() === name);
  if (matches.length !== 1 || typeof matches[0][1] !== "string") return undefined;
  return matches[0][1];
}
function clock(value) { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock is invalid"); return value; }
function uuid(value) { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
function plain(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value, expected) { const actual=Object.keys(value).sort(); const sorted=[...expected].sort(); return actual.length===sorted.length&&actual.every((key,index)=>key===sorted[index]); }
