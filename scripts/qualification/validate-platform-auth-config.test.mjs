import assert from "node:assert/strict";
import test from "node:test";

import { validatePlatformAuthEnvironment } from "./validate-platform-auth-config.mjs";

const VALID = Object.freeze({
  AGENTPASS_CLOUD_PROFILE: "hosted",
  AGENTPASS_PLATFORM_AUTH_ENABLED: "true",
  AGENTPASS_CONSOLE_ORIGIN: "https://console.example.com/",
  AGENTPASS_WEBAUTHN_RP_ID: "example.com",
  AGENTPASS_PLATFORM_MTLS_FINGERPRINT256: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
  AGENTPASS_PLATFORM_MTLS_SPIFFE_ID: "spiffe://agentpass.example/workload/platform-api",
  AGENTPASS_PLATFORM_WORKLOAD_ID: "spiffe://agentpass.example/workload/platform-api",
  AGENTPASS_PLATFORM_WORKLOAD_AUDIENCE: "agentpass.platform.promotion",
  AGENTPASS_PLATFORM_PRINCIPAL_PROVIDER: "iam",
  AGENTPASS_PLATFORM_WORKLOAD_PROVIDER: "spiffe",
  AGENTPASS_PLATFORM_WEBAUTHN_PROVIDER: "postgres",
  AGENTPASS_PLATFORM_REQUIRED_ROLE: "platform_operator",
  AGENTPASS_PLATFORM_RECENT_AUTH_HEADER: "agentpass-platform-recent-auth"
});

test("accepts complete hosted Platform auth metadata without returning values", () => {
  const report = validatePlatformAuthEnvironment(VALID);
  assert.equal(report.ok, true);
  assert.equal(report.secret_values_read, false);
  assert.equal(JSON.stringify(report).includes("AA:BB"), false);
  assert.equal(JSON.stringify(report).includes("console.example.com"), false);
});

test("fails closed when a factor or binding is absent", () => {
  const missing = { ...VALID };
  delete missing.AGENTPASS_PLATFORM_WORKLOAD_PROVIDER;
  const report = validatePlatformAuthEnvironment(missing);
  assert.equal(report.ok, false);
  assert.deepEqual(report.checks.find((check) => check.name === "AGENTPASS_PLATFORM_WORKLOAD_PROVIDER"), {
    name: "AGENTPASS_PLATFORM_WORKLOAD_PROVIDER",
    status: "fail",
    reason: "workload_provider_required"
  });
});

test("rejects unsafe provider modes and mismatched WebAuthn/mTLS bindings", () => {
  const report = validatePlatformAuthEnvironment({
    ...VALID,
    AGENTPASS_PLATFORM_PRINCIPAL_PROVIDER: "mock",
    AGENTPASS_PLATFORM_WORKLOAD_ID: "spiffe://other.example/workload",
    AGENTPASS_WEBAUTHN_RP_ID: "other.example"
  });
  assert.equal(report.ok, false);
  assert.ok(report.checks.some((check) => check.reason === "mTLS_and_workload_identity_must_match"));
  assert.ok(report.checks.some((check) => check.reason === "console_origin_must_be_allowed_by_rp_id"));
  assert.ok(report.checks.some((check) => check.reason === "principal_provider_required" || check.reason === "missing_or_invalid"));
});
