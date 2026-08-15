import crypto from "node:crypto";

import { createHostedBootstrapHttpApi, HOSTED_BOOTSTRAP_HTTP_PATHS, HOSTED_BOOTSTRAP_OPERATIONS } from "./http-api.mjs";
import { createGithubOAuthConfig } from "../hosted-identity/github-oauth-config.mjs";
import { createGithubOAuthIdentityAdapter } from "../hosted-identity/github-oauth-adapter.mjs";
import { createHostedIdentityBootstrapService as createIdentityCompletionService } from "../hosted-identity/identity-bootstrap-service.mjs";
import { createHostedBootstrapService } from "../hosted-identity/bootstrap-service.mjs";
import { createHostedOrganizationBootstrapService } from "../hosted-identity/organization-bootstrap-service.mjs";
import { createPkceVerifierCodec } from "../hosted-identity/pkce-verifier-codec.mjs";
import { createPostgresOAuthStateStore } from "../hosted-identity/postgres-oauth-state-store.mjs";
import { createHostedWebAuthnBootstrapService } from "../hosted-identity/webauthn-bootstrap-service.mjs";

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/u;
const OPERATION_BINDINGS = Object.freeze({
  [HOSTED_BOOTSTRAP_OPERATIONS.githubStart]: Object.freeze({ method: "GET", path: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart, capacity: 20, refillPerSecond: 0.25 }),
  [HOSTED_BOOTSTRAP_OPERATIONS.githubCallback]: Object.freeze({ method: "GET", path: HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback, capacity: 30, refillPerSecond: 0.5 }),
  [HOSTED_BOOTSTRAP_OPERATIONS.status]: Object.freeze({ method: "GET", path: HOSTED_BOOTSTRAP_HTTP_PATHS.status, capacity: 120, refillPerSecond: 2 }),
  [HOSTED_BOOTSTRAP_OPERATIONS.organizationCreate]: Object.freeze({ method: "POST", path: HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, capacity: 20, refillPerSecond: 0.25 }),
  [HOSTED_BOOTSTRAP_OPERATIONS.webauthnOptions]: Object.freeze({ method: "POST", path: HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnOptions, capacity: 30, refillPerSecond: 0.5 }),
  [HOSTED_BOOTSTRAP_OPERATIONS.webauthnVerify]: Object.freeze({ method: "POST", path: HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnVerify, capacity: 20, refillPerSecond: 0.25 })
});

/**
 * Composes the complete six-route Hosted bootstrap boundary. Every dependency
 * is production-backed: OAuth correlation and onboarding state live in
 * PostgreSQL, WebAuthn uses the maintained strict verifier, and rate limits
 * converge through shared PostgreSQL control rows.
 */
export function createHostedBootstrapRuntime({
  env = process.env,
  repository,
  registrationVerifier,
  rateLimitRepository,
  rateLimitSecret,
  humanAuthSecret
} = {}) {
  requireMethods(repository, [
    "startOAuthV2", "claimOAuthStateV2", "failOAuthState",
    "completeOAuthStateV2", "getBootstrapStatus", "verifyBootstrapCsrf",
    "commitOrganizationV2", "createChallenge", "claimChallengeV2",
    "completeWebAuthnRegistrationV3", "failChallengeV3"
  ], "Hosted bootstrap repository");
  requireMethods(registrationVerifier, ["generateOptions", "verifyAttestation"], "Hosted WebAuthn registration verifier");
  const config = loadHostedBootstrapRuntimeConfig(env, { humanAuthSecret });
  const oauthConfig = createGithubOAuthConfig(env);
  if (oauthConfig.redirectUri !== `${config.origin}${HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback}`) {
    throw new Error("Hosted GitHub redirect URI does not match the bootstrap callback");
  }

  const verifierCodec = createPkceVerifierCodec({
    activeKeyId: config.pkceKeyId,
    keyResolver: (keyId) => keyId === config.pkceKeyId ? Buffer.from(config.pkceKey) : undefined
  });
  const stateStore = createPostgresOAuthStateStore({ repository, verifierCodec });
  const githubService = createGithubOAuthIdentityAdapter({ config: oauthConfig, stateStore });
  const identityBootstrapService = createIdentityCompletionService({ repository });
  const organizationService = createHostedOrganizationBootstrapService({ repository });
  const bootstrapService = createHostedBootstrapService({
    repository,
    organizationService,
    csrfKey: config.csrfKey
  });
  const webauthnService = createHostedWebAuthnBootstrapService({
    repository,
    registrationVerifier,
    responseKey: config.webauthnResponseKey,
    rpId: config.rpId,
    origin: config.origin
  });
  const rateLimiter = createHostedBootstrapRateLimiter({ repository: rateLimitRepository, secret: rateLimitSecret });
  const api = createHostedBootstrapHttpApi({
    githubService,
    identityBootstrapService,
    bootstrapService,
    webauthnService,
    rateLimiter,
    origin: config.origin,
    rpId: config.rpId,
    consoleOnboardingUrl: config.consoleOnboardingUrl
  });
  return Object.freeze({
    api,
    config: publicConfig(config),
    githubService,
    identityBootstrapService,
    bootstrapService,
    webauthnService,
    rateLimiter
  });
}

export function loadHostedBootstrapRuntimeConfig(env = process.env, { humanAuthSecret } = {}) {
  if (!env || typeof env !== "object" || env.AGENTPASS_CLOUD_PROFILE !== "hosted") throw new Error("Hosted bootstrap requires the hosted profile");
  const origin = exactOrigin(env.AGENTPASS_CONSOLE_ORIGIN, "AGENTPASS_CONSOLE_ORIGIN");
  const rpId = exactRpId(env.AGENTPASS_WEBAUTHN_RP_ID, origin);
  const consoleOnboardingUrl = exactOnboardingUrl(env.AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL, origin);
  const pkceKeyId = exactKeyId(env.AGENTPASS_HOSTED_PKCE_KEY_ID);
  const pkceKey = exactSecret(env.AGENTPASS_HOSTED_PKCE_KEY, "AGENTPASS_HOSTED_PKCE_KEY");
  const csrfKey = exactSecret(env.AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY, "AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY");
  const webauthnResponseKey = exactSecret(env.AGENTPASS_HOSTED_WEBAUTHN_RESPONSE_KEY, "AGENTPASS_HOSTED_WEBAUTHN_RESPONSE_KEY");
  const humanKey = normalizeSecret(humanAuthSecret, "AGENTPASS_HUMAN_AUTH_SECRET");
  assertPurposeSeparated([pkceKey, csrfKey, webauthnResponseKey, humanKey]);
  return Object.freeze({ origin, rpId, consoleOnboardingUrl, pkceKeyId, pkceKey, csrfKey, webauthnResponseKey });
}

export function createHostedBootstrapRateLimiter({ repository, secret } = {}) {
  requireMethods(repository, ["acquireAnonymousRateLimit"], "Hosted bootstrap rate-limit repository");
  const key = normalizeSecret(secret, "Hosted bootstrap rate-limit secret");
  return Object.freeze({
    async authorize(input = {}) {
      if (!isPlainObject(input) || Object.keys(input).sort().join("\0") !== "method\0operation\0path") throw new Error("Hosted bootstrap rate-limit request is invalid");
      const policy = OPERATION_BINDINGS[input.operation];
      if (!policy || input.method !== policy.method || input.path !== policy.path) throw new Error("Hosted bootstrap rate-limit request is invalid");
      const principalId = deriveUuid(key, input.operation);
      const decision = await repository.acquireAnonymousRateLimit({
        operation: input.operation,
        principalId,
        capacity: policy.capacity,
        refillPerSecond: policy.refillPerSecond,
        cost: 1
      });
      if (!decision || typeof decision.allowed !== "boolean") throw new Error("Hosted bootstrap rate limit is unavailable");
      return Object.freeze({ allowed: decision.allowed });
    }
  });
}

function publicConfig(value) {
  return Object.freeze({
    origin: value.origin,
    rpId: value.rpId,
    consoleOnboardingUrl: value.consoleOnboardingUrl,
    pkceKeyId: value.pkceKeyId
  });
}

function exactOrigin(value, name) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${name} is invalid`); }
  if (parsed.protocol !== "https:" || parsed.origin !== value || parsed.pathname !== "/" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error(`${name} is invalid`);
  return value;
}

function exactRpId(value, origin) {
  const hostname = new URL(origin).hostname;
  if (typeof value !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(value)
    || (hostname !== value && !hostname.endsWith(`.${value}`))) throw new Error("AGENTPASS_WEBAUTHN_RP_ID is invalid");
  return value;
}

function exactOnboardingUrl(value, origin) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error("AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL is invalid"); }
  if (parsed.protocol !== "https:" || parsed.origin !== origin || parsed.pathname !== "/onboarding" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL is invalid");
  }
  return value;
}

function exactKeyId(value) {
  if (typeof value !== "string" || !KEY_ID.test(value)) throw new Error("AGENTPASS_HOSTED_PKCE_KEY_ID is invalid");
  return value;
}

function exactSecret(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error(`${name} must be an exact 32-byte base64url secret`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw new Error(`${name} must be an exact 32-byte base64url secret`);
  return bytes;
}

function normalizeSecret(value, name) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength !== 32) throw new Error(`${name} must be an exact 32-byte secret`);
  return Buffer.from(value);
}

function assertPurposeSeparated(keys) {
  for (let left = 0; left < keys.length; left += 1) {
    for (let right = left + 1; right < keys.length; right += 1) {
      if (crypto.timingSafeEqual(keys[left], keys[right])) throw new Error("Hosted bootstrap keys must be purpose-separated");
    }
  }
}

function deriveUuid(secret, operation) {
  const digest = crypto.createHmac("sha256", secret)
    .update("AgentPass-Hosted-Bootstrap-Rate-Limit-v1\0", "utf8")
    .update(operation, "utf8")
    .digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function requireMethods(value, methods, name) {
  if (!value || typeof value !== "object" || methods.some((method) => typeof value[method] !== "function")) throw new Error(`${name} is unavailable`);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

export default createHostedBootstrapRuntime;
