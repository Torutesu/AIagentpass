import { authenticateApiToken } from "../auth.mjs";

const USER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DEFAULT_PROVIDER = "chatgpt";

/**
 * Server-to-server identity seam for the current SIWC Console BFF.
 *
 * The browser never receives the Cloud service token. The BFF first verifies
 * SIWC and then presents its service credential plus the verified upstream
 * subject. Hosted deployments can replace this adapter with OIDC/mTLS without
 * changing the Human Session HTTP boundary.
 */
export function createConsoleIdentityAdapter({ tokenRecords, identityResolver, provider = DEFAULT_PROVIDER } = {}) {
  if (!Array.isArray(tokenRecords) || tokenRecords.length < 1) throw new TypeError("tokenRecords are required");
  if (!identityResolver || typeof identityResolver.resolveIdentity !== "function" || !identityResolver.identityAdapter || typeof identityResolver.identityAdapter.verify !== "function") throw new TypeError("identityResolver is required");
  if (typeof provider !== "string" || !/^[a-z][a-z0-9._-]{0,63}$/.test(provider)) throw new TypeError("identity provider is invalid");

  async function verifyIdentityRequest(request) {
    const headers = request?.headers;
    const authorization = header(headers, "authorization");
    const consoleUserId = header(headers, "agentpass-console-user-id");
    if (typeof authorization !== "string" || !authorization.startsWith("Bearer ") || authorization.length > 8192 || typeof consoleUserId !== "string" || !USER_ID.test(consoleUserId)) throw new Error("console identity request is invalid");
    const servicePrincipal = authenticateApiToken(authorization.slice(7), tokenRecords);
    return identityResolver.resolveIdentity({
      provider,
      subject: consoleUserId,
      organization_id: servicePrincipal.organization_id
    });
  }

  return Object.freeze({ verifyIdentityRequest, identityAdapter: identityResolver.identityAdapter, assertionTtlMs: identityResolver.assertionTtlMs, provider });
}

function header(headers, name) {
  if (headers && typeof headers.get === "function") return headers.get(name) ?? undefined;
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return undefined;
  const matches = Object.entries(headers).filter(([key]) => key.toLowerCase() === name);
  if (matches.length !== 1 || typeof matches[0][1] !== "string") return undefined;
  return matches[0][1];
}
