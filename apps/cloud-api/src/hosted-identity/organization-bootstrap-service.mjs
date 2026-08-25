import crypto from "node:crypto";

import {
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES,
  HostedIdentityBootstrapRepositoryError
} from "../postgres/hosted-identity-bootstrap-repository.mjs";
import {
  normalizeHostedOrganizationName
} from "./organization-name.mjs";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const TOKEN = /^[A-Za-z0-9._~-]{16,4096}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

export const HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES = Object.freeze({
  CONFIG: "bootstrap_service_config_invalid",
  INPUT: "bootstrap_invalid_request",
  IDEMPOTENCY_CONFLICT: "bootstrap_idempotency_conflict",
  UNAVAILABLE: "bootstrap_unavailable"
});

const ERROR_MESSAGES = Object.freeze({
  [HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG]: "Hosted organization bootstrap service configuration is invalid",
  [HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT]: "The bootstrap request is invalid",
  [HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The idempotency key conflicts with an earlier request",
  [HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE]: "The bootstrap service is temporarily unavailable"
});

export class HostedOrganizationBootstrapServiceError extends Error {
  constructor(code) {
    const safeCode = Object.hasOwn(ERROR_MESSAGES, code)
      ? code
      : HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE;
    super(ERROR_MESSAGES[safeCode]);
    this.name = "HostedOrganizationBootstrapServiceError";
    this.code = safeCode;
  }
}

/**
 * Application boundary for first-organization bootstrap. The browser may
 * supply only the bootstrap cookie, name, and idempotency key. All durable
 * identifiers and the public response are owned by the server/SQL boundary.
 */
export function createHostedOrganizationBootstrapService({ repository, randomUUID = crypto.randomUUID } = {}) {
  if (!repository || typeof repository.commitOrganizationV2 !== "function" || typeof randomUUID !== "function") {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG);
  }

  async function createOrganization(input = {}) {
    let request;
    try {
      request = normalizeHttpInput(input);
    } catch {
      throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT);
    }
    return commitOrganizationV2({
      bootstrap_cookie: request.bootstrap_token,
      organization_name: request.name,
      idempotency_key: request.idempotency_key
    });
  }

  async function commitOrganizationV2(request) {
    const ids = generateIds(randomUUID);
    const requestHash = sha256(normalizedRequestBytes(request.organization_name));
    let result;
    try {
      result = await repository.commitOrganizationV2(Object.freeze({
        bootstrap_cookie: request.bootstrap_cookie,
        idempotency_key: request.idempotency_key,
        request_hash: requestHash,
        organization_name: request.organization_name,
        organization_id: ids.organization_id,
        membership_id: ids.membership_id,
        audit_event_id: ids.audit_event_id
      }));
    } catch (cause) {
      if (cause instanceof HostedIdentityBootstrapRepositoryError
        && cause.code === HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.CONFLICT) {
        throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.IDEMPOTENCY_CONFLICT);
      }
      throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
    return normalizeCommitResult(result, request.organization_name, ids.organization_id);
  }

  return Object.freeze({ createOrganization });
}

function normalizeHttpInput(value) {
  exactObject(value, ["bootstrap_token", "name", "idempotency_key"]);
  return Object.freeze({
    bootstrap_token: token(value.bootstrap_token),
    name: normalizeHostedOrganizationName(value.name),
    idempotency_key: idempotencyKey(value.idempotency_key)
  });
}

function normalizeCommitResult(value, expectedName, candidateOrganizationId) {
  if (!isPlainObject(value) || !exactKeySet(value, ["response_status", "response_json", "replayed"])) {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  if (value.response_status !== 201 && value.response_status !== 200) {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  if (typeof value.replayed !== "boolean" || value.replayed !== (value.response_status === 200)) {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  const response = normalizePublicResponse(value.response_json);
  if (response.organization.name !== expectedName
    || (!value.replayed && response.organization.organization_id !== candidateOrganizationId)) {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  return Object.freeze({ response_status: value.response_status, response_json: response, replayed: value.replayed });
}

function normalizePublicResponse(value) {
  if (!isPlainObject(value) || !exactKeySet(value, ["version", "organization", "onboarding"]) || value.version !== 1) {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  const organization = value.organization;
  if (!isPlainObject(organization) || !exactKeySet(organization, ["organization_id", "name", "version", "created_at", "updated_at"])
    || !UUID_V4.test(organization.organization_id)
    || !Number.isSafeInteger(organization.version) || organization.version < 1
    || !RFC3339.test(organization.created_at) || Number.isNaN(Date.parse(organization.created_at))
    || !RFC3339.test(organization.updated_at) || Number.isNaN(Date.parse(organization.updated_at))) {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  let name;
  try { name = normalizeHostedOrganizationName(organization.name, { requireCanonical: true }); } catch { throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE); }
  if (!isPlainObject(value.onboarding) || !exactKeySet(value.onboarding, ["state"]) || value.onboarding.state !== "webauthn_required") {
    throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  return Object.freeze({
    version: 1,
    organization: Object.freeze({
      organization_id: organization.organization_id.toLowerCase(),
      name,
      version: organization.version,
      created_at: organization.created_at,
      updated_at: organization.updated_at
    }),
    onboarding: Object.freeze({ state: "webauthn_required" })
  });
}

function generateIds(randomUUID) {
  const values = [];
  for (let index = 0; index < 3; index += 1) {
    let value;
    try { value = randomUUID(); } catch { throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE); }
    if (typeof value !== "string" || !UUID_V4.test(value)) throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    const normalized = value.toLowerCase();
    if (values.includes(normalized)) throw serviceError(HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    values.push(normalized);
  }
  return Object.freeze({ organization_id: values[0], membership_id: values[1], audit_event_id: values[2] });
}

function normalizedRequestBytes(name) { return Buffer.from(name, "utf8"); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function token(value) { if (typeof value !== "string" || !TOKEN.test(value)) throw new TypeError("bootstrap token is invalid"); return value; }
function idempotencyKey(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw new TypeError("idempotency key is invalid"); return value; }
function exactObject(value, required, { optional = [] } = {}) {
  if (!isPlainObject(value)
    || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))
    || required.some((key) => !Object.hasOwn(value, key))) throw new TypeError("input is invalid");
}
function exactKeySet(value, expected) { return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function serviceError(code) { return new HostedOrganizationBootstrapServiceError(code); }

export default createHostedOrganizationBootstrapService;
