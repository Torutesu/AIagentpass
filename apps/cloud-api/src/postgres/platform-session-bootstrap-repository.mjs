const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const HEX_DIGEST = /^[0-9a-f]{64}$/u;
const OPERATION = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$/u;
const ALLOWED_CAPABILITIES = new Set([
  "platform.assignment.manage",
  "platform.promotion.issue",
  "platform.promotion.replay",
  "platform.promotion.verify",
  "platform.promotion.reconcile"
]);

export const PLATFORM_SESSION_BOOTSTRAP_SQL =
  "SELECT * FROM public.agentpass_platform_session_bootstrap_context($1::bytea,$2::uuid,$3::text,$4::text)";

export const PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_METHODS = Object.freeze([
  "resolvePlatformSessionBootstrap"
]);

export const PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_CONFIG",
  INPUT: "ERR_PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_INPUT",
  RESULT: "ERR_PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_RESULT",
  DATABASE: "ERR_PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_DATABASE"
});

export class PlatformSessionBootstrapRepositoryError extends Error {
  constructor(code, cause = undefined) {
    super(code);
    this.name = "PlatformSessionBootstrapRepositoryError";
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

export function createPostgresPlatformSessionBootstrapRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") {
    throw new PlatformSessionBootstrapRepositoryError(PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_ERROR_CODES.CONFIG);
  }

  async function resolvePlatformSessionBootstrap(input = {}) {
    const values = normalizeInput(input);
    let result;
    try {
      result = await client.query(PLATFORM_SESSION_BOOTSTRAP_SQL, [
        values.session_material_hash,
        values.organization_id,
        values.operation,
        values.capability
      ]);
    } catch (error) {
      throw new PlatformSessionBootstrapRepositoryError(PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_ERROR_CODES.DATABASE, error);
    }
    if (!result || !Array.isArray(result.rows) || result.rows.length > 1) {
      throw new PlatformSessionBootstrapRepositoryError(PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_ERROR_CODES.RESULT);
    }
    if (result.rows.length === 0) return null;
    return normalizeResult(result.rows[0]);
  }

  return Object.freeze({ resolvePlatformSessionBootstrap });
}

function normalizeInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("INPUT");
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "capability,operation,organization_id,session_material_hash") fail("INPUT");
  const hash = digestBytes(value.session_material_hash);
  if (!UUID.test(value.organization_id ?? "") || typeof value.operation !== "string"
    || !OPERATION.test(value.operation) || typeof value.capability !== "string"
    || value.operation !== value.capability || !ALLOWED_CAPABILITIES.has(value.capability)) fail("INPUT");
  return Object.freeze({
    session_material_hash: hash,
    organization_id: value.organization_id.toLowerCase(),
    operation: value.operation,
    capability: value.capability
  });
}

function normalizeResult(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("RESULT");
  const required = [
    "human_session_id", "organization_id", "member_id", "membership_id", "role",
    "organization_authority_epoch", "membership_session_epoch", "assignment_id",
    "principal_id", "principal_authority_generation", "assignment_version", "operation",
    "capability", "allowed_webauthn_credential_ids", "platform_credentials"
  ];
  if (Object.keys(value).some((key) => !required.includes(key)) || required.some((key) => !Object.hasOwn(value, key))) fail("RESULT");
  for (const key of ["human_session_id", "organization_id", "member_id", "membership_id", "assignment_id", "principal_id"]) {
    if (!UUID.test(value[key] ?? "")) fail("RESULT");
  }
  for (const key of ["organization_authority_epoch", "membership_session_epoch", "principal_authority_generation", "assignment_version"]) {
    if (!Number.isSafeInteger(Number(value[key])) || Number(value[key]) < 0) fail("RESULT");
  }
  if (typeof value.role !== "string" || value.role.length < 1 || value.role.length > 32
    || typeof value.operation !== "string" || !OPERATION.test(value.operation)
    || typeof value.capability !== "string" || value.operation !== value.capability
    || !ALLOWED_CAPABILITIES.has(value.capability)) fail("RESULT");
  if (!Array.isArray(value.allowed_webauthn_credential_ids)
    || value.allowed_webauthn_credential_ids.length < 1
    || value.allowed_webauthn_credential_ids.length > 16) fail("RESULT");
  const allowed = value.allowed_webauthn_credential_ids.map((id) => {
    if (!Buffer.isBuffer(id) || id.length < 1 || id.length > 1024) fail("RESULT");
    return Buffer.from(id);
  });
  if (!value.platform_credentials || typeof value.platform_credentials !== "object") fail("RESULT");
  return Object.freeze({
    human_session_id: value.human_session_id,
    organization_id: value.organization_id,
    member_id: value.member_id,
    membership_id: value.membership_id,
    role: value.role,
    organization_authority_epoch: Number(value.organization_authority_epoch),
    membership_session_epoch: Number(value.membership_session_epoch),
    assignment_id: value.assignment_id,
    principal_id: value.principal_id,
    principal_authority_generation: Number(value.principal_authority_generation),
    assignment_version: Number(value.assignment_version),
    operation: value.operation,
    capability: value.capability,
    allowed_webauthn_credential_ids: Object.freeze(allowed),
    platform_credentials: value.platform_credentials
  });
}

function digestBytes(value) {
  if (Buffer.isBuffer(value) && value.length === 32) return Buffer.from(value);
  if (typeof value === "string" && HEX_DIGEST.test(value)) return Buffer.from(value, "hex");
  fail("INPUT");
}

function fail(kind) {
  throw new PlatformSessionBootstrapRepositoryError(PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_ERROR_CODES[kind]);
}
