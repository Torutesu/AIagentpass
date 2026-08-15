import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  normalizePromotionEvidenceV3,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS
} from "./promotion-evidence-v3-statement.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,127}$/u;
const PRIVATE_FIELD = /(?:private(?:[_ -]?key|[_ -]?material)?|secret|password|credential|authorization|bearer|cookie|token|diagnostic|debug|trace|pem)/iu;

export const PLATFORM_PROMOTION_ISSUE_PATH = "/v1/platform/promotions";
export const PLATFORM_PROMOTION_REPLAY_PATH = "/v1/platform/promotions/replay";
export const PLATFORM_PROMOTION_OPERATIONS = Object.freeze({
  issue: "platform.promotion.issue",
  replay: "platform.promotion.replay"
});
export const PLATFORM_OPERATOR_ROLE = "platform_operator";
export const PLATFORM_PROMOTION_CAPABILITIES = Object.freeze({
  [PLATFORM_PROMOTION_OPERATIONS.issue]: "platform.promotion.issue",
  [PLATFORM_PROMOTION_OPERATIONS.replay]: "platform.promotion.replay"
});

const REQUEST_KEYS = Object.freeze(["promotion_id", "deployment_id", "environment", "candidate_id"]);
const RESPONSE_KEYS = Object.freeze(["promotion_id", "deployment_id", "environment", "candidate_id", "promotion_evidence", "replayed"]);
const AUTHORIZATION_KEYS = Object.freeze(["allowed", "role", "capability"]);

export function normalizePlatformPromotionRequest(body, idempotencyKey) {
  if (!isPlainObject(body) || !sameKeys(body, REQUEST_KEYS) || !IDEMPOTENCY_KEY.test(idempotencyKey ?? "")) {
    throw platformPromotionContractError("request");
  }
  if (!UUID.test(body.promotion_id) || !DEPLOYMENT_ID.test(body.deployment_id)
    || !["staging", "production"].includes(body.environment)
    || !CANDIDATE_ID.test(body.candidate_id)) {
    throw platformPromotionContractError("request");
  }
  return Object.freeze({
    promotion_id: body.promotion_id.toLowerCase(),
    deployment_id: body.deployment_id,
    environment: body.environment,
    candidate_id: body.candidate_id,
    idempotency_key: idempotencyKey
  });
}

export function platformPromotionContextHash(input, operation) {
  if (!isPlainObject(input) || !Object.values(PLATFORM_PROMOTION_OPERATIONS).includes(operation)) {
    throw platformPromotionContractError("request");
  }
  const canonical = {
    version: 1,
    operation,
    promotion_id: input.promotion_id,
    deployment_id: input.deployment_id,
    environment: input.environment,
    candidate_id: input.candidate_id,
    idempotency_key: input.idempotency_key
  };
  return crypto.createHash("sha256").update(canonicalJson(canonical), "utf8").digest("hex");
}

export function normalizePlatformPromotionResult(value, expected) {
  if (!isPlainObject(value) || !sameKeys(value, RESPONSE_KEYS) || value.replayed !== true && value.replayed !== false) {
    throw platformPromotionContractError("response");
  }
  if (value.promotion_id !== expected.promotion_id || value.deployment_id !== expected.deployment_id
    || value.environment !== expected.environment || value.candidate_id !== expected.candidate_id
    || !isPlainObject(value.promotion_evidence)) {
    throw platformPromotionContractError("response");
  }
  let evidence;
  try {
    evidence = normalizePromotionEvidenceV3(value.promotion_evidence, {
      allowExpired: true,
      allowFuture: true,
      maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS
    });
  } catch {
    throw platformPromotionContractError("response");
  }
  assertNoPrivateFields({ ...value, promotion_evidence: evidence });
  return Object.freeze({
    promotion_id: value.promotion_id,
    deployment_id: value.deployment_id,
    environment: value.environment,
    candidate_id: value.candidate_id,
    promotion_evidence: evidence,
    replayed: value.replayed
  });
}

export function normalizePlatformOperatorAuthorization(value, operation) {
  if (!isPlainObject(value) || !sameKeys(value, AUTHORIZATION_KEYS)) {
    throw platformPromotionContractError("authorization");
  }
  if (value.allowed !== true) return Object.freeze({ allowed: false });
  if (value.role !== PLATFORM_OPERATOR_ROLE || value.capability !== PLATFORM_PROMOTION_CAPABILITIES[operation]) {
    throw platformPromotionContractError("authorization");
  }
  return Object.freeze({ allowed: true, role: PLATFORM_OPERATOR_ROLE, capability: value.capability });
}

export function isPlatformPromotionPath(pathname) {
  return pathname === PLATFORM_PROMOTION_ISSUE_PATH || pathname === PLATFORM_PROMOTION_REPLAY_PATH;
}

export function platformPromotionContractError(kind) {
  const error = new Error(`platform promotion ${kind} contract is invalid`);
  error.code = `ERR_PLATFORM_PROMOTION_HTTP_${kind.toUpperCase()}`;
  return error;
}

function assertNoPrivateFields(value) {
  if (!isPlainObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (PRIVATE_FIELD.test(key)) throw platformPromotionContractError("response");
    if (isPlainObject(child)) assertNoPrivateFields(child);
    else if (Array.isArray(child)) for (const item of child) if (isPlainObject(item)) assertNoPrivateFields(item);
  }
}

function sameKeys(value, keys) {
  return Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
