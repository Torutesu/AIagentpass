export const GITHUB_OAUTH_ERROR_CODES = Object.freeze({
  CONFIG_INVALID: "github_oauth_config_invalid",
  STATE_INVALID: "github_oauth_state_invalid",
  SUBJECT_UNVERIFIED: "github_subject_unverified",
  PROVIDER_UNAVAILABLE: "github_provider_unavailable"
});

const MAX_SUBJECT = 20;

export class GithubOAuthError extends Error {
  constructor(code) {
    super(code);
    this.name = "GithubOAuthError";
    this.code = code;
  }
}

export function normalizeGithubUserResponse(value) {
  if (!plainObject(value)
    || typeof value.id !== "number"
    || !Number.isSafeInteger(value.id)
    || value.id <= 0
    || String(value.id).length > MAX_SUBJECT) {
    throw subjectUnverified();
  }
  return Object.freeze({ provider: "github", subject: String(value.id) });
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function providerUnavailable() {
  return new GithubOAuthError(GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE);
}

function subjectUnverified() {
  return new GithubOAuthError(GITHUB_OAUTH_ERROR_CODES.SUBJECT_UNVERIFIED);
}
