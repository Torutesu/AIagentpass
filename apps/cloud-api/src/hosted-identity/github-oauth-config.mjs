const HTTPS_URL = "https:";
const CLIENT_ID = /^[A-Za-z0-9._-]{1,256}$/u;
const ASCII_SECRET = /^[\x21-\x7e]{1,512}$/u;
const TIMEOUT_DEFAULT_MS = 5_000;
const MAX_RESPONSE_BYTES_DEFAULT = 64 * 1024;
const MAX_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 1_024 * 1_024;

export const GITHUB_OAUTH_ENV = Object.freeze([
  "AGENTPASS_CLOUD_PROFILE",
  "AGENTPASS_GITHUB_CLIENT_ID",
  "AGENTPASS_GITHUB_CLIENT_SECRET",
  "AGENTPASS_GITHUB_REDIRECT_URI",
  "AGENTPASS_GITHUB_AUTHORIZATION_ENDPOINT",
  "AGENTPASS_GITHUB_TOKEN_ENDPOINT",
  "AGENTPASS_GITHUB_USER_ENDPOINT",
  "AGENTPASS_GITHUB_TIMEOUT_MS",
  "AGENTPASS_GITHUB_MAX_RESPONSE_BYTES"
]);

export const GITHUB_OAUTH_DEFAULTS = Object.freeze({
  authorizationEndpoint: "https://github.com/login/oauth/authorize",
  tokenEndpoint: "https://github.com/login/oauth/access_token",
  userEndpoint: "https://api.github.com/user",
  timeoutMs: TIMEOUT_DEFAULT_MS,
  maxResponseBytes: MAX_RESPONSE_BYTES_DEFAULT
});

export function createGithubOAuthConfig(env = process.env) {
  try {
    if (env?.AGENTPASS_CLOUD_PROFILE !== "hosted") throw invalidConfig();

    const clientId = required(CLIENT_ID, env.AGENTPASS_GITHUB_CLIENT_ID);
    const clientSecret = required(ASCII_SECRET, env.AGENTPASS_GITHUB_CLIENT_SECRET);
    const redirectUri = exactHttpsUrl(env.AGENTPASS_GITHUB_REDIRECT_URI);
    const authorizationEndpoint = exactProviderEndpoint(
      env.AGENTPASS_GITHUB_AUTHORIZATION_ENDPOINT ?? GITHUB_OAUTH_DEFAULTS.authorizationEndpoint,
      GITHUB_OAUTH_DEFAULTS.authorizationEndpoint
    );
    const tokenEndpoint = exactProviderEndpoint(
      env.AGENTPASS_GITHUB_TOKEN_ENDPOINT ?? GITHUB_OAUTH_DEFAULTS.tokenEndpoint,
      GITHUB_OAUTH_DEFAULTS.tokenEndpoint
    );
    const userEndpoint = exactProviderEndpoint(
      env.AGENTPASS_GITHUB_USER_ENDPOINT ?? GITHUB_OAUTH_DEFAULTS.userEndpoint,
      GITHUB_OAUTH_DEFAULTS.userEndpoint
    );
    const timeoutMs = boundedInteger(env.AGENTPASS_GITHUB_TIMEOUT_MS, TIMEOUT_DEFAULT_MS, 100, MAX_TIMEOUT_MS);
    const maxResponseBytes = boundedInteger(
      env.AGENTPASS_GITHUB_MAX_RESPONSE_BYTES,
      MAX_RESPONSE_BYTES_DEFAULT,
      1_024,
      MAX_RESPONSE_BYTES
    );

    return Object.freeze({
      provider: "github",
      clientId,
      clientSecret,
      redirectUri,
      authorizationEndpoint,
      tokenEndpoint,
      userEndpoint,
      timeoutMs,
      maxResponseBytes,
      scope: "read:user"
    });
  } catch (error) {
    if (error?.code === GITHUB_OAUTH_CONFIG_ERROR) throw error;
    throw invalidConfig();
  }
}

export const parseGithubOAuthConfig = createGithubOAuthConfig;

function exactHttpsUrl(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048) throw invalidConfig();
  let parsed;
  try { parsed = new URL(value); } catch { throw invalidConfig(); }
  if (parsed.protocol !== HTTPS_URL || parsed.username || parsed.password || parsed.search || parsed.hash) throw invalidConfig();
  return value;
}

function exactProviderEndpoint(value, expected) {
  const parsed = exactHttpsUrl(value);
  if (parsed !== expected) throw invalidConfig();
  return parsed;
}

function required(pattern, value) {
  if (typeof value !== "string" || !pattern.test(value)) throw invalidConfig();
  return value;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const candidate = value === undefined ? fallback : value;
  if (typeof candidate === "number") {
    if (!Number.isSafeInteger(candidate) || candidate < minimum || candidate > maximum) throw invalidConfig();
    return candidate;
  }
  if (typeof candidate !== "string" || !/^\d+$/u.test(candidate)) throw invalidConfig();
  const parsed = Number(candidate);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw invalidConfig();
  return parsed;
}

const GITHUB_OAUTH_CONFIG_ERROR = "github_oauth_config_invalid";

function invalidConfig() {
  return Object.assign(new Error(GITHUB_OAUTH_CONFIG_ERROR), { code: GITHUB_OAUTH_CONFIG_ERROR });
}
