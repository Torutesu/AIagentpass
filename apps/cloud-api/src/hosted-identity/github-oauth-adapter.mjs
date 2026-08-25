import crypto from "node:crypto";

import { parseBoundedJson } from "../../../../lib/control-bundle-v2.mjs";

import { createGithubOAuthConfig } from "./github-oauth-config.mjs";
import {
  GITHUB_OAUTH_ERROR_CODES,
  GithubOAuthError,
  normalizeGithubUserResponse
} from "./github-oauth-normalization.mjs";

const STATE_BYTES = 32;
const PKCE_VERIFIER_BYTES = 32;
const MAX_CODE_LENGTH = 2_048;
const MAX_STATE_LENGTH = 512;
const STATE_HASH_ALGORITHM = "sha256";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const STATE = /^(?<oauthStateId>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.(?<secret>[A-Za-z0-9_-]{43})$/iu;

export function createGithubOAuthIdentityAdapter({
  config = createGithubOAuthConfig(),
  stateStore,
  fetchImpl = globalThis.fetch,
  randomBytes = crypto.randomBytes,
  randomUUID = crypto.randomUUID,
  now = () => Date.now()
} = {}) {
  assertConfig(config);
  if (!stateStore || typeof stateStore.create !== "function" || typeof stateStore.consume !== "function" || typeof stateStore.fail !== "function") {
    throw new TypeError("stateStore must provide create, consume, and fail");
  }
  if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
  if (typeof randomBytes !== "function") throw new TypeError("randomBytes must be a function");
  if (typeof randomUUID !== "function") throw new TypeError("randomUUID must be a function");
  if (typeof now !== "function") throw new TypeError("now must be a function");

  async function start() {
    const attemptId = exactUuid(randomUUID());
    const oauthStateId = exactUuid(randomUUID());
    const state = `${oauthStateId}.${randomToken(STATE_BYTES, randomBytes)}`;
    const pkceVerifier = randomToken(PKCE_VERIFIER_BYTES, randomBytes);
    const stateHash = hash(state);
    const pkceChallenge = base64urlSha256(pkceVerifier);
    const expiresAt = exactNow(now()) + 10 * 60 * 1000;
    let durable;
    try {
      durable = await stateStore.create(Object.freeze({
        attemptId,
        oauthStateId,
        state,
        stateHash,
        pkceVerifier,
        pkceChallenge,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        expiresAt
      }));
    } catch {
      throw providerError();
    }
    const stored = normalizeCreatedState(durable, { attemptId, oauthStateId, expiresAt });

    const authorization = new URL(config.authorizationEndpoint);
    authorization.searchParams.set("client_id", config.clientId);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("redirect_uri", config.redirectUri);
    authorization.searchParams.set("scope", config.scope);
    authorization.searchParams.set("state", state);
    authorization.searchParams.set("code_challenge", pkceChallenge);
    authorization.searchParams.set("code_challenge_method", "S256");

    return Object.freeze({
      authorizationUrl: authorization.toString(),
      state,
      stateCookie: state,
      expiresAt: stored.expiresAt
    });
  }

  async function callback(input) {
    const { code, state, stateCookie } = normalizeCallbackInput(input);
    if (!constantTimeEqual(state, stateCookie)) throw stateError();
    const oauthStateId = parseState(state);

    let record;
    try {
      record = await stateStore.consume(Object.freeze({
        oauthStateId,
        state,
        stateHash: hash(state),
        code,
        redirectUri: config.redirectUri
      }));
    } catch { throw stateError(); }
    const consumed = normalizeConsumedState(record, { oauthStateId, redirectUri: config.redirectUri, now: exactNow(now()) });
    if (base64urlSha256(consumed.pkceVerifier) !== consumed.pkceChallenge) {
      throw stateError();
    }

    let identity;
    try {
      const accessToken = await exchangeCode({ code, verifier: consumed.pkceVerifier });
      identity = await lookupUser(accessToken);
    } catch (error) {
      try {
        await stateStore.fail(Object.freeze({
          oauthStateId: consumed.oauthStateId,
          failureCode: error?.code === GITHUB_OAUTH_ERROR_CODES.SUBJECT_UNVERIFIED ? "subject_unverified" : "provider_unavailable"
        }));
      } catch {
        throw providerError();
      }
      throw error;
    }
    return deepFreeze({
      identity,
      context: { attempt_id: consumed.attemptId, oauth_state_id: consumed.oauthStateId }
    });
  }

  async function exchangeCode({ code, verifier }) {
    const body = new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      redirect_uri: config.redirectUri,
      code_verifier: verifier
    }).toString();
    const parsed = await request(config.tokenEndpoint, {
      method: "POST",
      headers: Object.freeze({
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
      }),
      body
    });
    return normalizeGithubOAuthToken(parsed);
  }

  async function lookupUser(accessToken) {
    const parsed = await request(config.userEndpoint, {
      method: "GET",
      headers: Object.freeze({
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
        "X-GitHub-Api-Version": "2022-11-28"
      })
    });
    return normalizeGithubUserResponse(parsed);
  }

  async function request(url, init) {
    const controller = new AbortController();
    let timer;
    try {
      const response = await Promise.race([
        Promise.resolve().then(async () => {
          const fetched = await fetchImpl(url, { ...init, redirect: "error", signal: controller.signal });
          if (!fetched || fetched.status !== 200) throw providerError();
          return providerJson(fetched);
        }),
        new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(providerError()); }, config.timeoutMs); })
      ]);
      return response;
    } catch (error) {
      if (error instanceof GithubOAuthError) throw error;
      throw providerError();
    } finally {
      clearTimeout(timer);
    }
  }

  return Object.freeze({
    provider: "github",
    start,
    callback
  });

  async function providerJson(response) {
    try {
      assertJsonContentType(response.headers);
      const bytes = await readBoundedBody(response, config.maxResponseBytes);
      try { return parseBoundedJson(bytes, { maxBytes: config.maxResponseBytes, maxDepth: 8 }); }
      catch { throw providerError(); }
    } catch (error) {
      if (error instanceof GithubOAuthError) throw error;
      throw providerError();
    }
  }
}

function normalizeGithubOAuthToken(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || typeof value.access_token !== "string"
    || value.access_token.length === 0
    || value.access_token.length > 8 * 1024
    || /[\u0000-\u001f\u007f]/u.test(value.access_token)) throw providerError();
  return value.access_token;
}

function assertJsonContentType(headers) {
  const value = headers?.get?.("content-type") ?? headers?.["content-type"];
  if (typeof value !== "string" || !/^application[/]json(?:;[ \\t]*charset=utf-8)?$/iu.test(value.trim())) throw providerError();
}

function normalizeCallbackInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw stateError();
  const keys = Object.keys(input).sort();
  if (keys.join(",") !== "code,state,stateCookie") throw stateError();
  const { code, state, stateCookie } = input;
  if (!boundedText(code, MAX_CODE_LENGTH) || !boundedText(state, MAX_STATE_LENGTH) || !boundedText(stateCookie, MAX_STATE_LENGTH)) throw stateError();
  return { code, state, stateCookie };
}

function normalizeCreatedState(value, expected) {
  if (!plainObject(value) || !exactKeys(value, ["attemptId", "oauthStateId", "expiresAt"])
    || value.attemptId !== expected.attemptId || value.oauthStateId !== expected.oauthStateId
    || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= 0 || value.expiresAt > expected.expiresAt) throw providerError();
  return value;
}

function normalizeConsumedState(value, expected) {
  if (!plainObject(value) || !exactKeys(value, ["attemptId", "oauthStateId", "pkceVerifier", "pkceChallenge", "redirectUri", "expiresAt"])
    || !UUID_V4.test(value.attemptId) || value.oauthStateId !== expected.oauthStateId
    || value.redirectUri !== expected.redirectUri || !validVerifier(value.pkceVerifier)
    || !/^[A-Za-z0-9_-]{43}$/u.test(value.pkceChallenge)
    || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= expected.now) throw stateError();
  return value;
}

function parseState(value) {
  const matched = STATE.exec(value);
  if (!matched) throw stateError();
  return matched.groups.oauthStateId.toLowerCase();
}

async function readBoundedBody(response, maxBytes) {
  const contentLength = response.headers?.get?.("content-length") ?? response.headers?.["content-length"];
  if (contentLength !== undefined && (!/^\d+$/u.test(String(contentLength)) || Number(contentLength) > maxBytes)) throw providerError();

  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        const chunk = Buffer.from(next.value);
        total += chunk.length;
        if (total > maxBytes) throw providerError();
        chunks.push(chunk);
      }
    } catch (error) {
      await reader.cancel().catch(() => {});
      throw error;
    } finally {
      reader.releaseLock?.();
    }
    return Buffer.concat(chunks);
  }
  // Production fetch responses are Web streams. Refuse non-streaming
  // substitutes so the byte limit is enforced while reading, never after an
  // unbounded arrayBuffer allocation.
  throw providerError();
}

function assertConfig(config) {
  if (!config || config.provider !== "github" || typeof config.clientId !== "string" || typeof config.clientSecret !== "string"
    || typeof config.redirectUri !== "string"
    || typeof config.authorizationEndpoint !== "string" || typeof config.tokenEndpoint !== "string" || typeof config.userEndpoint !== "string"
    || !Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 100 || config.timeoutMs > 30_000
    || !Number.isSafeInteger(config.maxResponseBytes) || config.maxResponseBytes < 1_024 || config.maxResponseBytes > 1_024 * 1_024
    || !/^[A-Za-z0-9._-]{1,256}$/u.test(config.clientId)
    || !/^[\x21-\x7e]{1,512}$/u.test(config.clientSecret)
    || config.scope !== "read:user"
    || !secureExactUrl(config.redirectUri)
    || config.authorizationEndpoint !== "https://github.com/login/oauth/authorize"
    || config.tokenEndpoint !== "https://github.com/login/oauth/access_token"
    || config.userEndpoint !== "https://api.github.com/user") {
    throw new GithubOAuthError(GITHUB_OAUTH_ERROR_CODES.CONFIG_INVALID);
  }
}

function secureExactUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function randomToken(size, randomBytes) {
  let value;
  try { value = randomBytes(size); } catch { throw providerError(); }
  if (!Buffer.isBuffer(value) || value.length !== size) throw providerError();
  return value.toString("base64url");
}

function hash(value) { return crypto.createHash(STATE_HASH_ALGORITHM).update(value, "utf8").digest("hex"); }
function base64urlSha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("base64url"); }
function validVerifier(value) { return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value); }
function boundedText(value, max) { return typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value); }
function exactNow(value) { if (!Number.isSafeInteger(value) || value < 0) throw providerError(); return value; }

function constantTimeEqual(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function exactUuid(value) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw providerError();
  return value.toLowerCase();
}
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value, expected) { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); } return value; }

function stateError() { return new GithubOAuthError(GITHUB_OAUTH_ERROR_CODES.STATE_INVALID); }
function providerError() { return new GithubOAuthError(GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE); }
