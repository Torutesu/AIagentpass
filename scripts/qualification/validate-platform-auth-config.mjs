#!/usr/bin/env node

const PROFILE = "AGENTPASS_CLOUD_PROFILE";
const CONFIG = Object.freeze({
  enabled: "AGENTPASS_PLATFORM_AUTH_ENABLED",
  consoleOrigin: "AGENTPASS_CONSOLE_ORIGIN",
  webauthnRpId: "AGENTPASS_WEBAUTHN_RP_ID",
  mtlsFingerprint: "AGENTPASS_PLATFORM_MTLS_FINGERPRINT256",
  mtlsSpiffeId: "AGENTPASS_PLATFORM_MTLS_SPIFFE_ID",
  workloadId: "AGENTPASS_PLATFORM_WORKLOAD_ID",
  workloadAudience: "AGENTPASS_PLATFORM_WORKLOAD_AUDIENCE",
  principalProvider: "AGENTPASS_PLATFORM_PRINCIPAL_PROVIDER",
  workloadProvider: "AGENTPASS_PLATFORM_WORKLOAD_PROVIDER",
  webauthnProvider: "AGENTPASS_PLATFORM_WEBAUTHN_PROVIDER",
  requiredRole: "AGENTPASS_PLATFORM_REQUIRED_ROLE",
  recentAuthHeader: "AGENTPASS_PLATFORM_RECENT_AUTH_HEADER"
});

const FINGERPRINT_256 = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/iu;
const SPIFFE_ID = /^spiffe:\/\/[^\u0000-\u0020\u007f]{1,480}$/u;
const WORKLOAD_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const AUDIENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const PROVIDER = /^[a-z][a-z0-9._:-]{0,127}$/u;
const ROLE = /^(?:platform_admin|platform_operator|platform_auditor)$/u;
const HEADER = /^[a-z][a-z0-9-]{0,127}$/u;

/**
 * Validate only non-secret deployment metadata. This function intentionally
 * does not inspect database URLs, tokens, private keys, certificates, or
 * provider credentials, and the returned report never contains env values.
 */
export function validatePlatformAuthEnvironment(env = process.env) {
  const checks = [];
  const add = (name, ok, reason) => checks.push({ name, status: ok ? "pass" : "fail", ...(ok ? {} : { reason }) });
  const required = (name, predicate, reason = "missing_or_invalid") => add(name, predicate(env[name]), reason);

  required(PROFILE, (value) => value === "hosted", "hosted_profile_required");
  required(CONFIG.enabled, (value) => value === "true", "explicit_enablement_required");
  required(CONFIG.consoleOrigin, validHttpsOrigin, "https_origin_required");
  required(CONFIG.webauthnRpId, validRpId, "valid_rp_id_required");
  required(CONFIG.mtlsFingerprint, (value) => typeof value === "string" && FINGERPRINT_256.test(value), "sha256_fingerprint_required");
  required(CONFIG.mtlsSpiffeId, (value) => typeof value === "string" && SPIFFE_ID.test(value), "spiffe_id_required");
  required(CONFIG.workloadId, (value) => typeof value === "string" && WORKLOAD_ID.test(value), "workload_id_required");
  required(CONFIG.workloadAudience, (value) => typeof value === "string" && AUDIENCE.test(value), "workload_audience_required");
  required(CONFIG.principalProvider, validProvider, "principal_provider_required");
  required(CONFIG.workloadProvider, validProvider, "workload_provider_required");
  required(CONFIG.webauthnProvider, validProvider, "webauthn_provider_required");

  const workloadIdMatchesSpiffe = typeof env[CONFIG.mtlsSpiffeId] === "string"
    && env[CONFIG.mtlsSpiffeId] === env[CONFIG.workloadId];
  add(`${CONFIG.mtlsSpiffeId}=${CONFIG.workloadId}`, workloadIdMatchesSpiffe, "mTLS_and_workload_identity_must_match");

  const consoleHostMatchesRp = validConsoleRpBinding(env[CONFIG.consoleOrigin], env[CONFIG.webauthnRpId]);
  add(`${CONFIG.consoleOrigin}<->${CONFIG.webauthnRpId}`, consoleHostMatchesRp, "console_origin_must_be_allowed_by_rp_id");

  const requiredRole = env[CONFIG.requiredRole] ?? "platform_operator";
  add(CONFIG.requiredRole, ROLE.test(requiredRole), "invalid_platform_role");
  const recentAuthHeader = env[CONFIG.recentAuthHeader] ?? "agentpass-platform-recent-auth";
  add(CONFIG.recentAuthHeader, HEADER.test(recentAuthHeader), "invalid_recent_auth_header");

  return Object.freeze({
    schema_version: 1,
    qualification: "platform-auth-production-config",
    ok: checks.every((check) => check.status === "pass"),
    secret_values_read: false,
    checks: Object.freeze(checks.map((check) => Object.freeze(check)))
  });
}

function validHttpsOrigin(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === ""
      && url.pathname === "/" && url.search === "" && url.hash === "" && url.hostname.length > 0;
  } catch {
    return false;
  }
}

function validRpId(value) {
  return typeof value === "string" && /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(value);
}

function validConsoleRpBinding(origin, rpId) {
  if (!validHttpsOrigin(origin) || !validRpId(rpId)) return false;
  const hostname = new URL(origin).hostname.toLowerCase();
  const normalizedRpId = rpId.toLowerCase();
  return hostname === normalizedRpId || hostname.endsWith(`.${normalizedRpId}`);
}

function validProvider(value) {
  return typeof value === "string" && PROVIDER.test(value) && !/(?:mock|fake|fixture|stub|test)/u.test(value);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const report = validatePlatformAuthEnvironment();
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.ok) process.exitCode = 1;
}
