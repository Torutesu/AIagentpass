import path from "node:path";

export const CLOUD_RUNTIME_PROFILES = Object.freeze({
  HOSTED: "hosted",
  EVALUATION: "evaluation"
});

export const CLOUD_RUNTIME_PROFILE_ERROR_CODES = Object.freeze({
  ENVIRONMENT_INVALID: "cloud_profile_environment_invalid",
  PROFILE_REQUIRED: "cloud_profile_required",
  PROFILE_UNKNOWN: "cloud_profile_unknown",
  UNKNOWN_CONFIGURATION: "cloud_profile_unknown_configuration",
  HOSTED_FILE_STORE_FORBIDDEN: "cloud_profile_hosted_file_store_forbidden",
  HOSTED_AUTH_INCOMPLETE: "cloud_profile_hosted_auth_incomplete",
  EVALUATION_AUTH_FORBIDDEN: "cloud_profile_evaluation_auth_forbidden",
  EVALUATION_FILE_STORE_INCOMPLETE: "cloud_profile_evaluation_file_store_incomplete",
  DATABASE_INVALID: "cloud_profile_database_invalid",
  HUMAN_AUTH_INVALID: "cloud_profile_human_auth_invalid"
});

const PROFILE_ENV = "AGENTPASS_CLOUD_PROFILE";
const CAPABILITY_NONCE_SECRET_ENV = "AGENTPASS_CAPABILITY_NONCE_SECRET";
const FILE_STORE_ENV = Object.freeze([
  "AGENTPASS_CLOUD_DATA_DIR",
  "AGENTPASS_CLOUD_TOKEN_RECORDS_PATH"
]);
const HOSTED_REFRESH_ENV = Object.freeze([
  "AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY",
  "AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS",
  "AGENTPASS_CLOUD_REFRESH_KEY_ID",
  "AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH"
]);
const HOSTED_AGENT_SESSION_ENV = Object.freeze([
  "AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID",
  "AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY",
  "AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS",
  "AGENTPASS_CLOUD_AGENT_SESSION_VERIFICATION_KEYS_JSON",
  "AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH"
]);
const HOSTED_QUALIFICATION_MANIFEST_ENV = Object.freeze([
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID",
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY",
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_TIMEOUT_MS",
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_VERIFICATION_KEYS_JSON"
]);
const HOSTED_POSSESSION_RECEIPT_ENV = Object.freeze([
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID",
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY",
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS",
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_VERIFICATION_KEYS_JSON"
]);
const HOSTED_CONTROL_BUNDLE_ENV = Object.freeze([
  "AGENTPASS_CLOUD_CONTROL_BUNDLE_KEY_ID",
  "AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY",
  "AGENTPASS_CLOUD_CONTROL_BUNDLE_TIMEOUT_MS"
]);
const HOSTED_CAPABILITY_ENV = Object.freeze([
  "AGENTPASS_CLOUD_CAPABILITY_KEY_ID",
  "AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY",
  "AGENTPASS_CLOUD_CAPABILITY_TIMEOUT_MS"
]);
const HOSTED_AUDIT_ANCHOR_ENV = Object.freeze([
  "AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID",
  "AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY",
  "AGENTPASS_CLOUD_AUDIT_ANCHOR_TIMEOUT_MS"
]);
const HOSTED_PROMOTION_EVIDENCE_ENV = Object.freeze([
  "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID",
  "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY",
  "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_TIMEOUT_MS"
]);
const HOSTED_KMS_ENV = Object.freeze([
  "AGENTPASS_KMS_PROVIDER",
  "AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE",
  "AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE",
  "AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE",
  "AGENTPASS_KMS_REFRESH_HINT_KEY_RESOURCE",
  "AGENTPASS_KMS_CONTROL_BUNDLE_KEY_RESOURCE",
  "AGENTPASS_KMS_CAPABILITY_KEY_RESOURCE",
  "AGENTPASS_KMS_AUDIT_ANCHOR_KEY_RESOURCE",
  "AGENTPASS_KMS_PROMOTION_EVIDENCE_KEY_RESOURCE"
]);
const DATABASE_ENV = Object.freeze([
  "AGENTPASS_DATABASE_URL",
  "AGENTPASS_DATABASE_MAX_CONNECTIONS",
  "AGENTPASS_DATABASE_CONNECT_TIMEOUT_MS",
  "AGENTPASS_DATABASE_IDLE_TIMEOUT_MS",
  "AGENTPASS_DATABASE_STATEMENT_TIMEOUT_MS",
  "AGENTPASS_DATABASE_LOCK_TIMEOUT_MS"
]);
const HUMAN_AUTH_ENV = Object.freeze([
  "AGENTPASS_DATABASE_URL",
  "AGENTPASS_CONSOLE_ORIGIN",
  "AGENTPASS_WEBAUTHN_RP_ID",
  "AGENTPASS_IDENTITY_PROVIDER",
  "AGENTPASS_IDENTITY_ASSERTION_ISSUER",
  "AGENTPASS_IDENTITY_ASSERTION_AUDIENCE",
  "AGENTPASS_IDENTITY_ASSERTION_KID",
  "AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH",
  "AGENTPASS_HUMAN_CURSOR_SECRET",
  "AGENTPASS_HUMAN_AUTH_SECRET"
]);
const OWNER_RECOVERY_NOTIFICATION_ENV = Object.freeze([
  "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL",
  "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL",
  "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH",
  "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID",
  "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION",
  "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST"
]);
const PROFILE_RELATED_ENV = new Set([
  PROFILE_ENV,
  "AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH",
  "AGENTPASS_CLOUD_ISSUER",
  "AGENTPASS_CLOUD_KEY_ID",
  "AGENTPASS_CLOUD_HOST",
  "AGENTPASS_CLOUD_PORT",
  "AGENTPASS_CLOUD_BUNDLE_TTL_MS",
  "AGENTPASS_CLOUD_OFFLINE_TTL_MS",
  ...HOSTED_REFRESH_ENV,
  ...HOSTED_AGENT_SESSION_ENV,
  ...HOSTED_QUALIFICATION_MANIFEST_ENV,
  ...HOSTED_POSSESSION_RECEIPT_ENV,
  ...HOSTED_CONTROL_BUNDLE_ENV,
  ...HOSTED_CAPABILITY_ENV,
  ...HOSTED_AUDIT_ANCHOR_ENV,
  ...HOSTED_PROMOTION_EVIDENCE_ENV,
  ...HOSTED_KMS_ENV,
  ...FILE_STORE_ENV,
  ...DATABASE_ENV,
  "AGENTPASS_CONSOLE_ORIGIN",
  "AGENTPASS_WEBAUTHN_RP_ID",
  "AGENTPASS_IDENTITY_PROVIDER",
  "AGENTPASS_IDENTITY_ASSERTION_ISSUER",
  "AGENTPASS_IDENTITY_ASSERTION_AUDIENCE",
  "AGENTPASS_IDENTITY_ASSERTION_KID",
  "AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH",
  "AGENTPASS_HUMAN_CURSOR_SECRET",
  "AGENTPASS_HUMAN_AUTH_SECRET",
  ...OWNER_RECOVERY_NOTIFICATION_ENV,
  CAPABILITY_NONCE_SECRET_ENV
]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const OWNER_RECOVERY_BINDING_IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{0,127}$/u;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u;
const IDENTITY_PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/u;
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/u;
const PROFILE_PREFIXES = Object.freeze([
  "AGENTPASS_CLOUD_",
  "AGENTPASS_DATABASE_",
  "AGENTPASS_CONSOLE_",
  "AGENTPASS_WEBAUTHN_",
  "AGENTPASS_IDENTITY_",
  "AGENTPASS_HUMAN_",
  "AGENTPASS_OWNER_RECOVERY_",
  "AGENTPASS_CAPABILITY_",
  "AGENTPASS_KMS_"
]);

const ERROR_MESSAGES = Object.freeze({
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.ENVIRONMENT_INVALID]: "Cloud runtime profile environment is invalid",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_REQUIRED]: "Cloud runtime profile is required",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_UNKNOWN]: "Cloud runtime profile is unknown",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.UNKNOWN_CONFIGURATION]: "Cloud runtime profile configuration is unknown",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_FILE_STORE_FORBIDDEN]: "Hosted Cloud runtime forbids reference file-store configuration",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE]: "Hosted Cloud runtime requires complete PostgreSQL and Human Auth configuration",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN]: "Evaluation Cloud runtime forbids PostgreSQL and Human Auth configuration",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_FILE_STORE_INCOMPLETE]: "Evaluation Cloud runtime requires complete reference file-store configuration",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID]: "Cloud PostgreSQL configuration is invalid",
  [CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID]: "Cloud Human Auth configuration is invalid"
});

export class CloudRuntimeProfileError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[CLOUD_RUNTIME_PROFILE_ERROR_CODES.ENVIRONMENT_INVALID]);
    this.name = "CloudRuntimeProfileError";
    this.code = code;
  }
}

/**
 * Parse and validate the explicit Cloud deployment profile.
 *
 * The returned value contains routing metadata and non-secret configuration
 * only. A caller can use `profile` to choose its authority/store factories;
 * it must not infer a profile from the presence or absence of other values.
 */
export function parseCloudRuntimeProfile(env = process.env) {
  if (!env || typeof env !== "object" || Array.isArray(env)) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.ENVIRONMENT_INVALID);
  rejectUnknownConfiguration(env);

  const profile = configured(env, PROFILE_ENV) ? env[PROFILE_ENV] : undefined;
  if (profile === undefined || profile === "") fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_REQUIRED);
  if (profile !== CLOUD_RUNTIME_PROFILES.HOSTED && profile !== CLOUD_RUNTIME_PROFILES.EVALUATION) {
    fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.PROFILE_UNKNOWN);
  }

  const fileStore = parseFileStore(env);
  const hostedRefresh = parseHostedRefresh(env);
  const hostedAgentSession = parseHostedAgentSession(env);
  const hostedQualificationManifest = parseHostedQualificationManifest(env);
  const hostedPossessionReceipt = parseHostedPossessionReceipt(env);
  const hostedControlBundle = parseHostedPurposeSigner(env, HOSTED_CONTROL_BUNDLE_ENV);
  const hostedCapability = parseHostedPurposeSigner(env, HOSTED_CAPABILITY_ENV);
  const hostedAuditAnchor = parseHostedPurposeSigner(env, HOSTED_AUDIT_ANCHOR_ENV);
  const hostedPromotionEvidence = parseHostedPurposeSigner(env, HOSTED_PROMOTION_EVIDENCE_ENV);
  const ownerRecoveryNotification = parseOwnerRecoveryNotification(env);
  if (profile === CLOUD_RUNTIME_PROFILES.HOSTED) {
    if (fileStore.present || configured(env, "AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH")) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_FILE_STORE_FORBIDDEN);
    const humanAuth = parseHumanAuth(env);
    if (!humanAuth.complete || !hostedRefresh.complete || !hostedAgentSession.complete || !hostedQualificationManifest.complete || !hostedPossessionReceipt.complete
      || !hostedControlBundle.complete || !hostedCapability.complete || !hostedAuditAnchor.complete || !hostedPromotionEvidence.complete
      || !ownerRecoveryNotification.complete || !configured(env, CAPABILITY_NONCE_SECRET_ENV)) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HOSTED_AUTH_INCOMPLETE);
    if (!validCursorSecret(env[CAPABILITY_NONCE_SECRET_ENV])) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID);
    return Object.freeze({
      profile,
      production: true,
      isHosted: true,
      isEvaluation: false,
      usesPostgres: true,
      usesHumanAuth: true,
      usesReferenceFileStore: false,
      postgres: Object.freeze({ configured: true }),
      humanAuth: humanAuth.config,
      fileStore: null
    });
  }

  if (HUMAN_AUTH_ENV.some((name) => configured(env, name)) || DATABASE_ENV.some((name) => configured(env, name))
    || hostedRefresh.present || HOSTED_AGENT_SESSION_ENV.some((name) => configured(env, name))
    || HOSTED_QUALIFICATION_MANIFEST_ENV.some((name) => configured(env, name))
    || HOSTED_POSSESSION_RECEIPT_ENV.some((name) => configured(env, name))
    || HOSTED_CONTROL_BUNDLE_ENV.some((name) => configured(env, name))
    || HOSTED_CAPABILITY_ENV.some((name) => configured(env, name))
    || HOSTED_AUDIT_ANCHOR_ENV.some((name) => configured(env, name))
    || HOSTED_PROMOTION_EVIDENCE_ENV.some((name) => configured(env, name))
    || HOSTED_KMS_ENV.some((name) => configured(env, name))
    || ownerRecoveryNotification.present
    || configured(env, CAPABILITY_NONCE_SECRET_ENV)) {
    fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_AUTH_FORBIDDEN);
  }
  if (!fileStore.complete) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.EVALUATION_FILE_STORE_INCOMPLETE);
  return Object.freeze({
    profile,
    production: false,
    isHosted: false,
    isEvaluation: true,
    usesPostgres: false,
    usesHumanAuth: false,
    usesReferenceFileStore: true,
    postgres: null,
    humanAuth: null,
    fileStore: Object.freeze({ dataDir: fileStore.dataDir, tokenRecordsPath: fileStore.tokenRecordsPath })
  });
}

function parseOwnerRecoveryNotification(env) {
  const present = OWNER_RECOVERY_NOTIFICATION_ENV.some((name) => configured(env, name));
  if (!present) return { present: false, complete: false };
  if (!OWNER_RECOVERY_NOTIFICATION_ENV.every((name) => configured(env, name))
    || !absolutePath(env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH)) {
    return { present: true, complete: false };
  }
  let webhook;
  let confirmation;
  try { webhook = new URL(env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL); }
  catch { return { present: true, complete: false }; }
  try { confirmation = new URL(env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL); }
  catch { return { present: true, complete: false }; }
  const complete = webhook.protocol === "https:"
    && webhook.username === ""
    && webhook.password === ""
    && webhook.hash === ""
    && webhook.hostname.length > 0
    && env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL.length <= 2_048
    && confirmation.protocol === "https:"
    && confirmation.username === ""
    && confirmation.password === ""
    && confirmation.hash === ""
    && confirmation.hostname.length > 0
    && env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL.length <= 2_048
    && OWNER_RECOVERY_BINDING_IDENTIFIER.test(env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID)
    && positiveIntegerText(env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION)
    && /^[0-9a-f]{64}$/u.test(env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST);
  return { present: true, complete };
}

function positiveIntegerText(value) {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/u.test(value)) return false;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= 2_147_483_647;
}

function parseHostedRefresh(env) {
  const present = HOSTED_REFRESH_ENV.some((name) => configured(env, name));
  if (!present) return { present: false, complete: false };
  const complete = HOSTED_REFRESH_ENV.every((name) => configured(env, name))
    && nonEmptyString(env.AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY)
    && positiveIntegerText(env.AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS)
    && absolutePath(env.AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH)
    && IDENTIFIER.test(env.AGENTPASS_CLOUD_REFRESH_KEY_ID);
  return { present: true, complete };
}

function parseHostedAgentSession(env) {
  const present = HOSTED_AGENT_SESSION_ENV.some((name) => configured(env, name));
  if (!present) return { present: false, complete: false };
  const hasKeyId = configured(env, "AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID");
  const hasPublicKey = configured(env, "AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY");
  const hasRotationSet = configured(env, "AGENTPASS_CLOUD_AGENT_SESSION_VERIFICATION_KEYS_JSON");
  const legacyComplete = hasKeyId && hasPublicKey && IDENTIFIER.test(env.AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID)
    && nonEmptyString(env.AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY);
  const rotationComplete = hasRotationSet && nonEmptyString(env.AGENTPASS_CLOUD_AGENT_SESSION_VERIFICATION_KEYS_JSON)
    && (legacyComplete || (!hasKeyId && !hasPublicKey));
  const complete = (legacyComplete || rotationComplete)
    && absolutePath(env.AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH);
  return { present: true, complete };
}

function parseHostedQualificationManifest(env) {
  const present = HOSTED_QUALIFICATION_MANIFEST_ENV.some((name) => configured(env, name));
  if (!present) return { present: false, complete: false };
  const hasKeyId = configured(env, "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID");
  const hasPublicKey = configured(env, "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY");
  const complete = hasKeyId && hasPublicKey
    && IDENTIFIER.test(env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID)
    && nonEmptyString(env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY);
  return { present: true, complete };
}

function parseHostedPossessionReceipt(env) {
  const present = HOSTED_POSSESSION_RECEIPT_ENV.some((name) => configured(env, name));
  if (!present) return { present: false, complete: false };
  const hasKeyId = configured(env, "AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID");
  const hasPublicKey = configured(env, "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY");
  const complete = hasKeyId && hasPublicKey
    && IDENTIFIER.test(env.AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID)
    && nonEmptyString(env.AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY);
  return { present: true, complete };
}

function parseHostedPurposeSigner(env, fields) {
  const present = fields.some((name) => configured(env, name));
  if (!present) return { present: false, complete: false };
  const [keyIdName, publicKeyName, timeoutName] = fields;
  const complete = fields.every((name) => configured(env, name))
    && IDENTIFIER.test(env[keyIdName])
    && nonEmptyString(env[publicKeyName])
    && positiveIntegerText(env[timeoutName]);
  return { present: true, complete };
}

export const validateCloudRuntimeProfile = parseCloudRuntimeProfile;
export const loadCloudRuntimeProfile = parseCloudRuntimeProfile;

function parseFileStore(env) {
  const dataDir = env[FILE_STORE_ENV[0]];
  const tokenRecordsPath = env[FILE_STORE_ENV[1]];
  const dataPresent = configured(env, FILE_STORE_ENV[0]);
  const tokenPresent = configured(env, FILE_STORE_ENV[1]);
  if (!dataPresent && !tokenPresent) return { present: false, complete: false };
  const complete = dataPresent && tokenPresent && absolutePath(dataDir) && absolutePath(tokenRecordsPath);
  return {
    present: true,
    complete,
    ...(complete ? { dataDir: path.resolve(dataDir), tokenRecordsPath: path.resolve(tokenRecordsPath) } : {})
  };
}

function parseDatabase(env) {
  const present = DATABASE_ENV.some((name) => configured(env, name));
  if (!present) return { present: false };
  const raw = env.AGENTPASS_DATABASE_URL;
  if (typeof raw !== "string" || raw.length < 1) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID);
  let url;
  try { url = new URL(raw); } catch { fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID); }
  if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password || url.hash) {
    fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID);
  }
  const sslModes = url.searchParams.getAll("sslmode");
  if (sslModes.length !== 1 || sslModes[0] !== "verify-full") fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID);
  for (const key of url.searchParams.keys()) if (key !== "sslmode") fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID);
  if (!boundedInteger(env.AGENTPASS_DATABASE_MAX_CONNECTIONS, 2, 100)
    || !boundedInteger(env.AGENTPASS_DATABASE_CONNECT_TIMEOUT_MS, 250, 30_000)
    || !boundedInteger(env.AGENTPASS_DATABASE_IDLE_TIMEOUT_MS, 1_000, 300_000)
    || !boundedInteger(env.AGENTPASS_DATABASE_STATEMENT_TIMEOUT_MS, 250, 60_000)
    || !boundedInteger(env.AGENTPASS_DATABASE_LOCK_TIMEOUT_MS, 100, 30_000)) {
    fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.DATABASE_INVALID);
  }
  return { present: true };
}

function parseHumanAuth(env) {
  const present = HUMAN_AUTH_ENV.some((name) => configured(env, name));
  if (!present) return { present: false, complete: false, config: null };
  const required = [
    "AGENTPASS_DATABASE_URL",
    "AGENTPASS_CONSOLE_ORIGIN",
    "AGENTPASS_WEBAUTHN_RP_ID",
    "AGENTPASS_IDENTITY_ASSERTION_ISSUER",
    "AGENTPASS_IDENTITY_ASSERTION_AUDIENCE",
    "AGENTPASS_IDENTITY_ASSERTION_KID",
    "AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH",
    "AGENTPASS_HUMAN_CURSOR_SECRET",
    "AGENTPASS_HUMAN_AUTH_SECRET"
  ];
  if (required.some((name) => !configured(env, name))) return { present: true, complete: false, config: null };
  const database = DATABASE_ENV.some((name) => configured(env, name)) ? parseDatabase(env) : { present: false };
  if (!database.present) return { present: true, complete: false, config: null };
  if (!nonEmptyString(env.AGENTPASS_CONSOLE_ORIGIN) || !nonEmptyString(env.AGENTPASS_WEBAUTHN_RP_ID)
    || !boundedString(env.AGENTPASS_IDENTITY_ASSERTION_ISSUER, 256) || !boundedString(env.AGENTPASS_IDENTITY_ASSERTION_AUDIENCE, 256)
    || !IDENTIFIER.test(env.AGENTPASS_IDENTITY_ASSERTION_KID ?? "") || !absolutePath(env.AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH)
    || !validCursorSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET)
    || !validCursorSecret(env.AGENTPASS_HUMAN_AUTH_SECRET)) {
    fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID);
  }
  let origin;
  try { origin = new URL(env.AGENTPASS_CONSOLE_ORIGIN); } catch { fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID); }
  if (origin.protocol !== "https:" || origin.origin !== env.AGENTPASS_CONSOLE_ORIGIN || origin.pathname !== "/"
    || origin.username || origin.password || origin.search || origin.hash) {
    fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID);
  }
  const rpId = env.AGENTPASS_WEBAUTHN_RP_ID;
  if (!RP_ID.test(rpId) || (origin.hostname !== rpId && !origin.hostname.endsWith(`.${rpId}`))) {
    fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID);
  }
  const identityProvider = env.AGENTPASS_IDENTITY_PROVIDER ?? "chatgpt";
  if (!IDENTITY_PROVIDER.test(identityProvider)) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.HUMAN_AUTH_INVALID);
  return {
    present: true,
    complete: true,
    config: Object.freeze({
      enabled: true,
      origin: env.AGENTPASS_CONSOLE_ORIGIN,
      rpId,
      identityProvider,
      identityAssertionIssuer: env.AGENTPASS_IDENTITY_ASSERTION_ISSUER,
      identityAssertionAudience: env.AGENTPASS_IDENTITY_ASSERTION_AUDIENCE,
      identityAssertionKeyId: env.AGENTPASS_IDENTITY_ASSERTION_KID,
      identityAssertionPublicKeyPath: path.resolve(env.AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH)
    })
  };
}

function rejectUnknownConfiguration(env) {
  for (const name of Object.keys(env)) {
    if (PROFILE_RELATED_ENV.has(name)) continue;
    if (PROFILE_PREFIXES.some((prefix) => name.startsWith(prefix))) fail(CLOUD_RUNTIME_PROFILE_ERROR_CODES.UNKNOWN_CONFIGURATION);
  }
}

function configured(env, name) {
  return Object.hasOwn(env, name) && env[name] !== undefined;
}

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function boundedString(value, max) {
  return nonEmptyString(value) && value.length <= max;
}

function absolutePath(value) {
  return typeof value === "string" && path.isAbsolute(value) && path.basename(value) !== "." && path.basename(value) !== "..";
}

function validCursorSecret(value) {
  if (typeof value !== "string" || !BASE64URL_32_BYTES.test(value)) return false;
  try {
    const bytes = Buffer.from(value, "base64url");
    return bytes.length === 32 && bytes.toString("base64url") === value;
  } catch { return false; }
}

function boundedInteger(value, min, max) {
  if (!configuredValue(value)) return true;
  if (typeof value !== "string" || !/^\d+$/u.test(value)) return false;
  const result = Number(value);
  return Number.isSafeInteger(result) && result >= min && result <= max;
}

function configuredValue(value) {
  return value !== undefined;
}

function fail(code) {
  throw new CloudRuntimeProfileError(code);
}
