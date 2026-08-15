import assert from "node:assert/strict";
import test from "node:test";

import {
  CLOUD_RUNTIME_PROFILES,
  CLOUD_RUNTIME_PROFILE_ERROR_CODES,
  CloudRuntimeProfileError,
  parseCloudRuntimeProfile
} from "../src/runtime-profile.mjs";

const SECRET = Buffer.alloc(32, 0x5a).toString("base64url");
const DATABASE_URL = "postgresql://agent:database-password@db.example.test/agentpass?sslmode=verify-full";
const MIGRATION_DATABASE_URL = "postgresql://migrator:database-password@db.example.test/agentpass?sslmode=verify-full";
const SIGNER_DATABASE_URL = "postgresql://signer:database-password@db.example.test/agentpass?sslmode=verify-full";

function evaluationEnv(overrides = {}) {
  return {
    AGENTPASS_CLOUD_PROFILE: "evaluation",
    AGENTPASS_CLOUD_DATA_DIR: "/srv/agentpass/evaluation/data",
    AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: "/srv/agentpass/evaluation/token-records.json",
    ...overrides
  };
}

function hostedEnv(overrides = {}) {
  return {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_DATABASE_URL: DATABASE_URL,
    AGENTPASS_MIGRATION_DATABASE_URL: MIGRATION_DATABASE_URL,
    AGENTPASS_SIGNER_DATABASE_URL: SIGNER_DATABASE_URL,
    AGENTPASS_DATABASE_MAX_CONNECTIONS: "10",
    AGENTPASS_SIGNER_DATABASE_MAX_CONNECTIONS: "4",
    AGENTPASS_DATABASE_CONNECT_TIMEOUT_MS: "5000",
    AGENTPASS_DATABASE_IDLE_TIMEOUT_MS: "30000",
    AGENTPASS_DATABASE_STATEMENT_TIMEOUT_MS: "8000",
    AGENTPASS_DATABASE_LOCK_TIMEOUT_MS: "2000",
    AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test",
    AGENTPASS_WEBAUTHN_RP_ID: "example.test",
    AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-console",
    AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-cloud-session",
    AGENTPASS_IDENTITY_ASSERTION_KID: "console-2026-08",
    AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH: "/srv/agentpass/hosted/console-public.pem",
    AGENTPASS_HUMAN_CURSOR_SECRET: SECRET,
    AGENTPASS_HUMAN_AUTH_SECRET: Buffer.alloc(32, 0x5b).toString("base64url"),
    AGENTPASS_GITHUB_CLIENT_ID: "agentpass-profile-test",
    AGENTPASS_GITHUB_CLIENT_SECRET: "github-profile-test-secret",
    AGENTPASS_GITHUB_REDIRECT_URI: "https://console.example.test/api/auth/bootstrap/github/callback",
    AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL: "https://console.example.test/onboarding",
    AGENTPASS_HOSTED_PKCE_KEY_ID: "hosted-pkce-v1",
    AGENTPASS_HOSTED_PKCE_KEY: Buffer.alloc(32, 0x5c).toString("base64url"),
    AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY: Buffer.alloc(32, 0x5d).toString("base64url"),
    AGENTPASS_HOSTED_WEBAUTHN_RESPONSE_KEY: Buffer.alloc(32, 0x5e).toString("base64url"),
    AGENTPASS_CAPABILITY_NONCE_SECRET: Buffer.alloc(32, 0x33).toString("base64url"),
    AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY: "hosted-refresh-public-key-pin",
    AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_REFRESH_KEY_ID: "refresh-2026-08",
    AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH: "/srv/agentpass/hosted/refresh-nonce-keyring.json",
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "agent-session-2026-08",
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: "hosted-public-key-pin",
    AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH: "/srv/agentpass/hosted/process-policies.json",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID: "qualification-manifest-2026-08",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY: "hosted-qualification-public-key-pin",
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: "possession-receipt-2026-08",
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: "hosted-possession-receipt-public-key-pin",
    AGENTPASS_CLOUD_CONTROL_BUNDLE_KEY_ID: "control-bundle-2026-08",
    AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY: "hosted-control-bundle-public-key-pin",
    AGENTPASS_CLOUD_CONTROL_BUNDLE_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_CAPABILITY_KEY_ID: "capability-2026-08",
    AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY: "hosted-capability-public-key-pin",
    AGENTPASS_CLOUD_CAPABILITY_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID: "audit-anchor-2026-08",
    AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY: "hosted-audit-anchor-public-key-pin",
    AGENTPASS_CLOUD_AUDIT_ANCHOR_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID: "promotion-evidence-2026-08",
    AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY: "hosted-promotion-evidence-public-key-pin",
    AGENTPASS_CLOUD_PROMOTION_EVIDENCE_TIMEOUT_MS: "5000",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL: "https://notifications.example.test/owner-recovery",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL: "https://notifications.example.test/owner-recovery/acceptance",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH: "/srv/agentpass/hosted/notification-authorization.txt",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID: "owner-recovery-primary",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION: "1",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST: "a".repeat(64),
    ...overrides
  };
}

function assertProfileError(action, code) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof CloudRuntimeProfileError);
    assert.equal(error.code, code);
    assert.doesNotMatch(error.message, /database-password|5[a-zA-Z0-9_-]{42}/u);
    return true;
  });
}

test("requires an explicit hosted or evaluation selector", () => {
  assertProfileError(() => parseCloudRuntimeProfile({}), CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_REQUIRED);
  assertProfileError(() => parseCloudRuntimeProfile({ AGENTPASS_CLOUD_PROFILE: "production" }), CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_UNKNOWN);
  assertProfileError(() => parseCloudRuntimeProfile({ AGENTPASS_CLOUD_PROFILE: "" }), CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_REQUIRED);
});

test("accepts evaluation only with the complete reference file-store boundary", () => {
  const profile = parseCloudRuntimeProfile(evaluationEnv());
  assert.deepEqual(profile, {
    profile: CLOUD_RUNTIME_PROFILES.EVALUATION,
    production: false,
    isHosted: false,
    isEvaluation: true,
    usesPostgres: false,
    usesHumanAuth: false,
    usesReferenceFileStore: true,
    postgres: null,
    humanAuth: null,
    fileStore: {
      dataDir: "/srv/agentpass/evaluation/data",
      tokenRecordsPath: "/srv/agentpass/evaluation/token-records.json"
    }
  });
  assertProfileError(() => parseCloudRuntimeProfile({ AGENTPASS_CLOUD_PROFILE: "evaluation" }), CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_FILE_STORE_INCOMPLETE);
  assertProfileError(() => parseCloudRuntimeProfile(evaluationEnv({ AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: undefined })), CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_FILE_STORE_INCOMPLETE);
  assertProfileError(() => parseCloudRuntimeProfile(evaluationEnv({ AGENTPASS_CLOUD_DATA_DIR: "relative/data" })), CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_FILE_STORE_INCOMPLETE);
  assertProfileError(() => parseCloudRuntimeProfile(evaluationEnv({ AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL: "https://notifications.example.test/recovery" })), CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN);
});

test("accepts hosted only with complete PostgreSQL and Human Auth prerequisites", () => {
  const profile = parseCloudRuntimeProfile(hostedEnv());
  assert.equal(profile.profile, CLOUD_RUNTIME_PROFILES.HOSTED);
  assert.equal(profile.production, true);
  assert.equal(profile.isHosted, true);
  assert.equal(profile.isEvaluation, false);
  assert.equal(profile.usesPostgres, true);
  assert.equal(profile.usesHumanAuth, true);
  assert.equal(profile.usesReferenceFileStore, false);
  assert.equal(profile.fileStore, null);
  assert.equal(profile.humanAuth.origin, "https://console.example.test");
  assert.equal(Object.hasOwn(profile.humanAuth, "cursorSecret"), false);
  assert.equal(JSON.stringify(profile).includes(SECRET), false);
  assert.equal(JSON.stringify(profile).includes("database-password"), false);

  for (const name of [
    "AGENTPASS_DATABASE_URL",
    "AGENTPASS_MIGRATION_DATABASE_URL",
    "AGENTPASS_SIGNER_DATABASE_URL",
    "AGENTPASS_CONSOLE_ORIGIN",
    "AGENTPASS_WEBAUTHN_RP_ID",
    "AGENTPASS_IDENTITY_ASSERTION_ISSUER",
    "AGENTPASS_IDENTITY_ASSERTION_AUDIENCE",
    "AGENTPASS_IDENTITY_ASSERTION_KID",
    "AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH",
    "AGENTPASS_HUMAN_CURSOR_SECRET",
    "AGENTPASS_HUMAN_AUTH_SECRET",
    "AGENTPASS_GITHUB_CLIENT_ID",
    "AGENTPASS_GITHUB_CLIENT_SECRET",
    "AGENTPASS_GITHUB_REDIRECT_URI",
    "AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL",
    "AGENTPASS_HOSTED_PKCE_KEY_ID",
    "AGENTPASS_HOSTED_PKCE_KEY",
    "AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY",
    "AGENTPASS_HOSTED_WEBAUTHN_RESPONSE_KEY",
    "AGENTPASS_CAPABILITY_NONCE_SECRET",
    "AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY",
    "AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS",
    "AGENTPASS_CLOUD_REFRESH_KEY_ID",
    "AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH",
    "AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID",
    "AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY",
    "AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH",
    "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID",
    "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY",
    "AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID",
    "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY",
    "AGENTPASS_CLOUD_CONTROL_BUNDLE_KEY_ID",
    "AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY",
    "AGENTPASS_CLOUD_CONTROL_BUNDLE_TIMEOUT_MS",
    "AGENTPASS_CLOUD_CAPABILITY_KEY_ID",
    "AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY",
    "AGENTPASS_CLOUD_CAPABILITY_TIMEOUT_MS",
    "AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID",
    "AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY",
    "AGENTPASS_CLOUD_AUDIT_ANCHOR_TIMEOUT_MS",
    "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID",
    "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY",
    "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_TIMEOUT_MS",
    "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID",
    "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION",
    "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST"
  ]) {
    const env = hostedEnv();
    delete env[name];
    const expected = ["AGENTPASS_MIGRATION_DATABASE_URL", "AGENTPASS_SIGNER_DATABASE_URL"].includes(name)
      ? CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
      : CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE;
    assertProfileError(() => parseCloudRuntimeProfile(env), expected);
  }
});

test("recognizes hosted KMS routing variables and rejects KMS typos or evaluation use", () => {
  const kms = {
    AGENTPASS_KMS_PROVIDER: "aws",
    AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/agent-session",
    AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/qualification-manifest",
    AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/possession-receipt",
    AGENTPASS_KMS_REFRESH_HINT_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/refresh-hint",
    AGENTPASS_KMS_CONTROL_BUNDLE_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/control-bundle",
    AGENTPASS_KMS_CAPABILITY_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/capability",
    AGENTPASS_KMS_AUDIT_ANCHOR_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/audit-anchor",
    AGENTPASS_KMS_PROMOTION_EVIDENCE_KEY_RESOURCE: "arn:aws:kms:us-east-1:123456789012:key/promotion-evidence"
  };
  assert.equal(parseCloudRuntimeProfile(hostedEnv(kms)).isHosted, true);
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ ...kms, AGENTPASS_KMS_PRIVATE_KEY_PATH: "/tmp/key" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.UNKNOWN_CONFIGURATION
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(evaluationEnv(kms)),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN
  );
});

test("accepts a rotation key set as the hosted Agent Session key authority", () => {
  const env = hostedEnv({
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: undefined,
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: undefined,
    AGENTPASS_CLOUD_AGENT_SESSION_VERIFICATION_KEYS_JSON: JSON.stringify({
      version: 1,
      active: { key_id: "agent-session-2026-09", algorithm: "ed25519", public_key: "public-key-pin" },
      retiring: []
    })
  });
  assert.equal(parseCloudRuntimeProfile(env).isHosted, true);
  assertProfileError(
    () => parseCloudRuntimeProfile({ ...env, AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "partial-active" }),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(evaluationEnv({ AGENTPASS_CLOUD_AGENT_SESSION_VERIFICATION_KEYS_JSON: "{}" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN
  );
});

test("rejects hosted file-store compatibility inputs and evaluation auth inputs", () => {
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_CLOUD_DATA_DIR: "/srv/agentpass/data" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_FILE_STORE_FORBIDDEN
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: "/srv/agentpass/tokens.json" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_FILE_STORE_FORBIDDEN
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: "/srv/agentpass/bundle-private.pem" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_FILE_STORE_FORBIDDEN
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(evaluationEnv({ AGENTPASS_DATABASE_URL: DATABASE_URL })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(evaluationEnv({ AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN
  );
});

test("fails closed for partial, malformed, stale, unsafe, and unknown configuration", () => {
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY: undefined })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_GITHUB_REDIRECT_URI: "https://console.example.test/wrong" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY: Buffer.alloc(32, 0x5c).toString("base64url") })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(evaluationEnv({ AGENTPASS_HOSTED_PKCE_KEY: SECRET })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_DATABASE_URL: undefined })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_MIGRATION_DATABASE_URL: undefined })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_SIGNER_DATABASE_URL: DATABASE_URL })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_SIGNER_DATABASE_URL: "postgresql://signer:pw@other.example.test/agentpass?sslmode=verify-full" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_DATABASE_URL: "postgresql://agent:pw@db.example.test/agentpass?sslmode=require" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_DATABASE_URL: "postgresql://agent:pw@db.example.test/agentpass?sslmode=verify-full&connect_timeout=1" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_DATABASE_MAX_CONNECTIONS: "0" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_DATABASE_MAX_CONNECTIONS: "1" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_CONSOLE_ORIGIN: "http://console.example.test" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID
  );
  assertProfileError(
    () => parseCloudRuntimeProfile(hostedEnv({ AGENTPASS_HUMAN_CURSOR_SECRET: "cursor-secret-that-must-not-appear-in-errors" })),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID
  );
  for (const override of [
    { AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID: "Uppercase-Is-Not-Canonical" },
    { AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION: "0" },
    { AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION: "01" },
    { AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION: "2147483648" },
    { AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST: "A".repeat(64) },
    { AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST: "a".repeat(63) }
  ]) {
    assertProfileError(
      () => parseCloudRuntimeProfile(hostedEnv(override)),
      CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE
    );
  }
  assertProfileError(
    () => parseCloudRuntimeProfile({ ...evaluationEnv(), AGENTPASS_CLOUD_UNSUPPORTED_SETTING: "unknown-value" }),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.UNKNOWN_CONFIGURATION
  );
  assertProfileError(
    () => parseCloudRuntimeProfile({ ...evaluationEnv(), AGENTPASS_DATABASE_UNSUPPORTED_SETTING: "unknown-value" }),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.UNKNOWN_CONFIGURATION
  );
  assertProfileError(
    () => parseCloudRuntimeProfile({ ...evaluationEnv(), AGENTPASS_CAPABILITY_UNSUPPORTED_SETTING: "unknown-value" }),
    CLOUD_RUNTIME_PROFILE_ERROR_CODES.UNKNOWN_CONFIGURATION
  );
});

test("does not treat unrelated process environment variables as profile configuration", () => {
  const profile = parseCloudRuntimeProfile({ ...evaluationEnv(), PATH: "/usr/bin", NODE_ENV: "test", AGENTPASS_OTHER_APP_FLAG: "1" });
  assert.equal(profile.isEvaluation, true);
});
