import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { SIGNER_PURPOSE_REGISTRY } from "../../apps/cloud-api/src/signer-purpose-registry.mjs";

export const KMS_QUALIFICATION_SCHEMA_VERSION = 1;
export const KMS_QUALIFICATION_KIND = "agentpass.hosted-kms-qualification";
export const KMS_QUALIFICATION_NAME = "hosted-kms";
export const KMS_QUALIFICATION_SIGNATURE_DOMAIN = "AgentPass-Hosted-KMS-Qualification-v1\0";
export const KMS_QUALIFICATION_PROVIDERS = Object.freeze(["aws", "gcp"]);
export const KMS_QUALIFICATION_SCENARIOS = Object.freeze(["rotation", "disable", "outage", "throttle", "response_loss"]);

const REGISTRY_ENTRIES = Object.freeze(Object.values(SIGNER_PURPOSE_REGISTRY).sort((left, right) => left.purpose.localeCompare(right.purpose)));
if (REGISTRY_ENTRIES.length !== 8) throw new Error("hosted KMS qualification requires exactly eight signer purposes");
export const KMS_QUALIFICATION_PURPOSES = Object.freeze(REGISTRY_ENTRIES.map(({ name, purpose }) => Object.freeze({ name, purpose })));
const PURPOSE_BY_NAME = new Map(KMS_QUALIFICATION_PURPOSES.map((value) => [value.name, REGISTRY_ENTRIES.find(({ name }) => name === value.name)]));
const PURPOSE_BY_PURPOSE = new Map(REGISTRY_ENTRIES.map((value) => [value.purpose, value]));

const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40,64}$/u;
const VERSION = /^[1-9][0-9]{0,19}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const RUN_ID = /^[a-z0-9][a-z0-9._-]{7,127}$/u;
const MIGRATION_HEAD = /^[0-9]{4}_[a-z0-9_]+$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const AWS_RESOURCE = /^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const GCP_RESOURCE = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9][a-z0-9-]{0,62}\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/([1-9][0-9]{0,19})$/u;
const SAFE_TEXT = /^[A-Za-z0-9][A-Za-z0-9 ._:/+@-]{0,255}$/u;
const FORBIDDEN_KEY = /^(?:access[_-]?token|api[_-]?key|authorization|bearer|client[_-]?secret|credential|diagnostic|password|private(?:[_-](?:key|material))?|raw|secret(?:[_-]?(?:access[_-]?)?(?:key|material))?|security[_-]?token|session[_-]?token|stderr|stdout|token|x[_-]?api[_-]?key)$/iu;
const FORBIDDEN_VALUE = /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:ghp|github_pat|xox[baprs])_[A-Za-z0-9_-]{8,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|(?:api|session|security)[_-]?token|(?:private|secret)[_-]?(?:access[_-]?)?(?:key|material)|client[_-]?secret)/iu;
const DIGEST_VALUE = /^sha256:[0-9a-f]{64}$/u;
const EXTERNAL_EVIDENCE_SOURCE = Object.freeze({
  aws: /^aws\.(?:kms[._-]?api|workload[._-]?identity)$/u,
  gcp: /^gcp\.(?:cloud[._-]?kms[._-]?api|workload[._-]?identity)$/u
});

export class KmsQualificationEvidenceError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "KmsQualificationEvidenceError";
    this.code = code;
  }
}

function invalid(code, message = code) {
  throw new KmsQualificationEvidenceError(code, message);
}

function plainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid("invalid_shape", `${label} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid("invalid_shape", `${label} must be a plain object`);
  return value;
}

function ownKeys(value, label) {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key))) invalid("unknown_field", `${label} contains a non-enumerable or symbol field`);
  return keys;
}

function exactKeys(value, expected, label) {
  plainObject(value, label);
  const actual = ownKeys(value, label).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) invalid("unknown_field", `${label} has an unknown or missing field`);
}

function optionalKeys(value, allowed, label) {
  plainObject(value, label);
  for (const key of ownKeys(value, label)) if (!allowed.has(key)) invalid("unknown_field", `${label} has an unknown field`);
}

function safeString(value, label, { maximum = 1024, pattern, allowNul = false } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || (!allowNul && value.includes("\u0000")) || /[\u0001-\u001f\u007f\u2028\u2029\r\n]/u.test(value) || FORBIDDEN_VALUE.test(value)) invalid("unsafe_string", `${label} is invalid`);
  if (pattern && !pattern.test(value)) invalid("invalid_value", `${label} is invalid`);
  return value;
}

function digest(value, label) {
  return safeString(value, label, { maximum: 71, pattern: SHA256 });
}

function fingerprint(value, label) {
  return safeString(value, label, { maximum: 64, pattern: FINGERPRINT });
}

function positiveInteger(value, label, { maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) invalid("invalid_number", `${label} is invalid`);
  return value;
}

function timestamp(value, label) {
  safeString(value, label, { maximum: 24, pattern: ISO_UTC });
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) invalid("invalid_timestamp", `${label} is invalid`);
  return value;
}

function requireTimeOrder(startedAt, completedAt, label) {
  if (Date.parse(completedAt) < Date.parse(startedAt)) invalid("invalid_time_window", `${label} completion precedes start`);
}

function base64url(value, label, expectedBytes = null) {
  safeString(value, label, { maximum: 16 * 1024, pattern: BASE64URL });
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length === 0 || bytes.toString("base64url") !== value || (expectedBytes !== null && bytes.length !== expectedBytes)) invalid("invalid_encoding", `${label} is invalid`);
  return bytes;
}

function safeArray(value, label, { min = 0, max = 256 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) invalid("invalid_array", `${label} is invalid`);
  return value;
}

function recordDigest(value, label) {
  return digest(value, label);
}

function normalizeSource(value) {
  exactKeys(value, ["source_commit", "image_digest", "config_digest"], "source");
  return {
    source_commit: safeString(value.source_commit, "source commit", { maximum: 64, pattern: COMMIT }),
    image_digest: digest(value.image_digest, "image digest"),
    config_digest: digest(value.config_digest, "config digest")
  };
}

function normalizeExecution(value, provider) {
  exactKeys(value, ["run_id", "mode", "credential_source", "zero_skip", "skip_count", "instance_count", "started_at", "completed_at"], "execution");
  const mode = safeString(value.mode, "execution mode", { maximum: 32, pattern: /^(?:mock|protected_external)$/u });
  const credentialSource = safeString(value.credential_source, "credential source", { maximum: 64, pattern: /^[a-z][a-z0-9._-]{2,63}$/u });
  const expectedCredential = mode === "mock" ? "test_fixture" : `${provider}_workload_identity`;
  if (credentialSource !== expectedCredential) invalid("invalid_execution", "credential source does not match execution mode");
  const startedAt = timestamp(value.started_at, "execution start time");
  const completedAt = timestamp(value.completed_at, "execution completion time");
  requireTimeOrder(startedAt, completedAt, "execution");
  const skipCount = Number.isSafeInteger(value.skip_count) && value.skip_count >= 0 ? value.skip_count : invalid("invalid_execution", "skip count is invalid");
  if (value.zero_skip !== (skipCount === 0)) invalid("invalid_execution", "zero_skip does not match skip_count");
  if (value.instance_count !== 2) invalid("invalid_execution", "qualification requires exactly two instances");
  return {
    run_id: safeString(value.run_id, "run id", { maximum: 128, pattern: RUN_ID }),
    mode,
    credential_source: credentialSource,
    zero_skip: value.zero_skip,
    skip_count: skipCount,
    instance_count: value.instance_count,
    started_at: startedAt,
    completed_at: completedAt
  };
}

function normalizeProtection(value, label, mode, provider) {
  exactKeys(value, ["level", "non_exportable", "key_usage", "evidence_source", "evidence_digest", "observed_at"], label);
  const source = safeString(value.evidence_source, `${label} evidence source`, { maximum: 64, pattern: /^[a-z][a-z0-9._-]{2,63}$/u });
  if (value.level !== "HSM" || value.non_exportable !== true || value.key_usage !== "sign_verify") invalid("protection_not_proven", `${label} must prove HSM non-exportability and sign/verify use`);
  if (mode === "protected_external" && !EXTERNAL_EVIDENCE_SOURCE[provider]?.test(source)) {
    invalid("protection_not_proven", `${label} must identify an approved external provider evidence source`);
  }
  return {
    level: value.level,
    non_exportable: value.non_exportable,
    key_usage: value.key_usage,
    evidence_source: source,
    evidence_digest: recordDigest(value.evidence_digest, `${label} evidence digest`),
    observed_at: timestamp(value.observed_at, `${label} observation time`)
  };
}

function normalizeSignVerify(value, label) {
  exactKeys(value, ["status", "verified", "request_digest", "signature_digest", "evidence_digest", "observed_at"], label);
  if (value.status !== "passed" && value.status !== "failed") invalid("invalid_status", `${label} status is invalid`);
  if (value.status === "passed" && value.verified !== true) invalid("sign_verify_not_proven", `${label} passed status requires verified=true`);
  if (value.status === "failed" && value.verified !== false) invalid("sign_verify_not_proven", `${label} failed status requires verified=false`);
  return {
    status: value.status,
    verified: value.verified,
    request_digest: recordDigest(value.request_digest, `${label} request digest`),
    signature_digest: recordDigest(value.signature_digest, `${label} signature digest`),
    evidence_digest: recordDigest(value.evidence_digest, `${label} evidence digest`),
    observed_at: timestamp(value.observed_at, `${label} observation time`)
  };
}

function normalizePurposeBinding(value, provider, mode, index) {
  const label = `purpose binding ${index}`;
  exactKeys(value, ["name", "purpose", "provider", "registry_version", "protocol_version", "signing_version", "algorithm", "key_id", "key_resource", "key_version", "public_key_fingerprint", "lifecycle_epoch", "protection", "sign_verify"], label);
  const expected = PURPOSE_BY_NAME.get(value.name);
  if (!expected || expected.purpose !== value.purpose) invalid("unknown_purpose", `${label} is not one of the frozen purposes`);
  if (value.provider !== provider || value.algorithm !== "ed25519" || value.registry_version !== expected.registry_version || value.protocol_version !== expected.protocol_version || value.signing_version !== expected.signing_version) invalid("purpose_substitution", `${label} does not match the frozen registry`);
  const keyVersion = safeString(value.key_version, `${label} key version`, { maximum: 20, pattern: VERSION });
  const resource = safeString(value.key_resource, `${label} key resource`, { maximum: 2048, pattern: provider === "aws" ? AWS_RESOURCE : GCP_RESOURCE });
  if (provider === "gcp" && GCP_RESOURCE.exec(resource)?.[1] !== keyVersion) invalid("key_version_mismatch", `${label} resource version does not match key version`);
  return {
    name: value.name,
    purpose: value.purpose,
    provider,
    registry_version: expected.registry_version,
    protocol_version: expected.protocol_version,
    signing_version: expected.signing_version,
    algorithm: value.algorithm,
    key_id: safeString(value.key_id, `${label} key id`, { maximum: 256, pattern: KEY_ID }),
    key_resource: resource,
    key_version: keyVersion,
    public_key_fingerprint: fingerprint(value.public_key_fingerprint, `${label} public key fingerprint`),
    lifecycle_epoch: positiveInteger(value.lifecycle_epoch, `${label} lifecycle epoch`),
    protection: normalizeProtection(value.protection, `${label} protection`, mode, provider),
    sign_verify: normalizeSignVerify(value.sign_verify, `${label} sign/verify`)
  };
}

function normalizePurposeBindings(value, provider, mode) {
  safeArray(value, "purpose bindings", { min: 8, max: 8 });
  const seenNames = new Set();
  const seenResources = new Set();
  const seenKeyIds = new Set();
  const seenFingerprints = new Set();
  const normalized = value.map((entry, index) => {
    const normalizedEntry = normalizePurposeBinding(entry, provider, mode, index);
    if (seenNames.has(normalizedEntry.name)) invalid("duplicate_purpose", "purpose bindings are duplicated");
    if (seenResources.has(normalizedEntry.key_resource)) invalid("shared_key_resource", "key resources must be purpose-separated");
    if (seenKeyIds.has(normalizedEntry.key_id)) invalid("shared_key_id", "key ids must be purpose-separated");
    if (seenFingerprints.has(normalizedEntry.public_key_fingerprint)) invalid("shared_key_fingerprint", "public key fingerprints must be purpose-separated");
    seenNames.add(normalizedEntry.name);
    seenResources.add(normalizedEntry.key_resource);
    seenKeyIds.add(normalizedEntry.key_id);
    seenFingerprints.add(normalizedEntry.public_key_fingerprint);
    return normalizedEntry;
  }).sort((left, right) => left.purpose.localeCompare(right.purpose));
  if (normalized.some((entry, index) => entry.name !== KMS_QUALIFICATION_PURPOSES[index].name)) invalid("incomplete_purposes", "purpose bindings must contain the exact eight registry purposes");
  return normalized;
}

function normalizeIamMatrix(value) {
  safeArray(value, "IAM matrix", { min: 64, max: 64 });
  const expectedPairs = new Set();
  for (const requester of KMS_QUALIFICATION_PURPOSES) for (const target of KMS_QUALIFICATION_PURPOSES) expectedPairs.add(`${requester.purpose}\0${target.purpose}`);
  const seen = new Set();
  const normalized = value.map((entry, index) => {
    const label = `IAM matrix entry ${index}`;
    exactKeys(entry, ["requester_purpose", "target_purpose", "action", "expected", "observed", "status", "request_digest", "evidence_digest", "observed_at"], label);
    if (!PURPOSE_BY_PURPOSE.has(entry.requester_purpose) || !PURPOSE_BY_PURPOSE.has(entry.target_purpose)) invalid("unknown_purpose", `${label} has an unknown purpose`);
    const pair = `${entry.requester_purpose}\0${entry.target_purpose}`;
    if (seen.has(pair)) invalid("duplicate_iam_pair", "IAM matrix pairs must be unique");
    seen.add(pair);
    const expected = entry.requester_purpose === entry.target_purpose ? "allow" : "deny";
    if (entry.action !== "sign" || entry.expected !== expected || entry.observed !== expected || entry.status !== "passed") invalid("iam_matrix_failed", `${label} does not prove the exact allow/deny matrix`);
    return {
      requester_purpose: entry.requester_purpose,
      target_purpose: entry.target_purpose,
      action: entry.action,
      expected: entry.expected,
      observed: entry.observed,
      status: entry.status,
      request_digest: recordDigest(entry.request_digest, `${label} request digest`),
      evidence_digest: recordDigest(entry.evidence_digest, `${label} evidence digest`),
      observed_at: timestamp(entry.observed_at, `${label} observation time`)
    };
  }).sort((left, right) => `${left.requester_purpose}\0${left.target_purpose}`.localeCompare(`${right.requester_purpose}\0${right.target_purpose}`));
  if (seen.size !== expectedPairs.size || [...expectedPairs].some((pair) => !seen.has(pair))) invalid("incomplete_iam_matrix", "IAM matrix must contain every ordered purpose pair");
  return normalized;
}

const SCENARIO_EXPECTATIONS = Object.freeze({
  rotation: "new_version_only",
  disable: "disabled_rejected",
  outage: "fail_closed",
  throttle: "bounded_retry",
  response_loss: "reconcile_without_resign"
});

function normalizeScenarios(value, bindings) {
  safeArray(value, "scenario results", { min: 40, max: 40 });
  const bindingVersions = new Map(bindings.map((entry) => [entry.purpose, entry.key_version]));
  const seen = new Set();
  const normalized = value.map((entry, index) => {
    const label = `scenario result ${index}`;
    exactKeys(entry, ["purpose", "scenario", "status", "expected", "observed", "previous_key_version", "current_key_version", "provider_invocations", "client_retries", "replay_safe", "evidence_digest", "observed_at"], label);
    if (!PURPOSE_BY_PURPOSE.has(entry.purpose) || !Object.hasOwn(SCENARIO_EXPECTATIONS, entry.scenario)) invalid("invalid_scenario", `${label} has an unknown purpose or scenario`);
    const id = `${entry.purpose}\0${entry.scenario}`;
    if (seen.has(id)) invalid("duplicate_scenario", "scenario results must be unique");
    seen.add(id);
    const expected = SCENARIO_EXPECTATIONS[entry.scenario];
    if (entry.status !== "passed" && entry.status !== "failed") invalid("invalid_status", `${label} status is invalid`);
    if (entry.expected !== expected || entry.observed !== expected || entry.status !== "passed") invalid("scenario_failed", `${label} does not prove the required lifecycle behavior`);
    if (entry.scenario === "rotation") {
      if (!VERSION.test(entry.previous_key_version ?? "") || !VERSION.test(entry.current_key_version ?? "") || entry.previous_key_version === entry.current_key_version || entry.current_key_version !== bindingVersions.get(entry.purpose)) invalid("rotation_not_proven", `${label} does not bind the immutable rotated version`);
    } else if (entry.previous_key_version !== null || entry.current_key_version !== null) invalid("invalid_scenario", `${label} must not carry rotation versions`);
    if (!Number.isSafeInteger(entry.provider_invocations) || entry.provider_invocations < 0 || entry.provider_invocations > 100000) invalid("invalid_scenario", `${label} provider invocation count is invalid`);
    if (!Number.isSafeInteger(entry.client_retries) || entry.client_retries < 0 || entry.client_retries > 100000) invalid("invalid_scenario", `${label} retry count is invalid`);
    if (entry.scenario === "response_loss" && entry.replay_safe !== true) invalid("response_loss_not_proven", `${label} must prove no re-sign on response loss`);
    return {
      purpose: entry.purpose,
      scenario: entry.scenario,
      status: entry.status,
      expected: entry.expected,
      observed: entry.observed,
      previous_key_version: entry.previous_key_version,
      current_key_version: entry.current_key_version,
      provider_invocations: entry.provider_invocations,
      client_retries: entry.client_retries,
      replay_safe: entry.replay_safe,
      evidence_digest: recordDigest(entry.evidence_digest, `${label} evidence digest`),
      observed_at: timestamp(entry.observed_at, `${label} observation time`)
    };
  }).sort((left, right) => `${left.purpose}\0${left.scenario}`.localeCompare(`${right.purpose}\0${right.scenario}`));
  if (seen.size !== 40) invalid("incomplete_scenarios", "every purpose must prove all five lifecycle/fault scenarios");
  return normalized;
}

function normalizePostgres(value, source, execution) {
  exactKeys(value, ["status", "instance_count", "instances", "image_digest", "migration_head", "operation_table", "binding_scope", "contention_requests", "committed_result_count", "response_loss_reconciled", "evidence_digest", "observed_at"], "PostgreSQL binding");
  if (value.status !== "passed" || value.instance_count !== 2 || value.operation_table !== "managed_signer_provider_operations" || value.binding_scope !== "purpose_key_version_request_digest" || value.response_loss_reconciled !== true) invalid("postgres_binding_failed", "PostgreSQL binding is not qualified");
  if (value.image_digest !== source.image_digest || execution.instance_count !== value.instance_count) invalid("postgres_binding_mismatch", "PostgreSQL binding does not match source execution");
  const instances = safeArray(value.instances, "PostgreSQL instances", { min: 2, max: 2 }).map((entry, index) => {
    const label = `PostgreSQL instance ${index}`;
    exactKeys(entry, ["id", "source_commit", "image_digest", "config_digest", "observed_at"], label);
    if (entry.id !== `instance-${index === 0 ? "a" : "b"}` || entry.source_commit !== source.source_commit || entry.image_digest !== source.image_digest || entry.config_digest !== source.config_digest) invalid("postgres_binding_mismatch", `${label} is not bound to the report source`);
    return {
      id: entry.id,
      source_commit: entry.source_commit,
      image_digest: entry.image_digest,
      config_digest: entry.config_digest,
      observed_at: timestamp(entry.observed_at, `${label} observation time`)
    };
  });
  return {
    status: value.status,
    instance_count: value.instance_count,
    instances,
    image_digest: value.image_digest,
    migration_head: safeString(value.migration_head, "migration head", { maximum: 128, pattern: MIGRATION_HEAD }),
    operation_table: value.operation_table,
    binding_scope: value.binding_scope,
    contention_requests: positiveInteger(value.contention_requests, "contention request count", { maximum: 1000000 }),
    committed_result_count: positiveInteger(value.committed_result_count, "committed result count", { maximum: 1000000 }),
    response_loss_reconciled: value.response_loss_reconciled,
    evidence_digest: recordDigest(value.evidence_digest, "PostgreSQL binding evidence digest"),
    observed_at: timestamp(value.observed_at, "PostgreSQL binding observation time")
  };
}

function normalizeSignature(value) {
  if (value === undefined) return {
    status: "unsigned_ready",
    algorithm: "ed25519",
    domain: KMS_QUALIFICATION_SIGNATURE_DOMAIN,
    key_id: null,
    public_key_der_base64url: null,
    public_key_fingerprint: null,
    signature_base64url: null
  };
  exactKeys(value, ["status", "algorithm", "domain", "key_id", "public_key_der_base64url", "public_key_fingerprint", "signature_base64url"], "signature");
  if (value.algorithm !== "ed25519" || value.domain !== KMS_QUALIFICATION_SIGNATURE_DOMAIN) invalid("invalid_signature", "signature metadata is invalid");
  if (value.status === "unsigned_ready") {
    if (value.key_id !== null || value.public_key_der_base64url !== null || value.public_key_fingerprint !== null || value.signature_base64url !== null) invalid("invalid_signature", "unsigned signature metadata must not contain key material");
    return { status: value.status, algorithm: value.algorithm, domain: value.domain, key_id: null, public_key_der_base64url: null, public_key_fingerprint: null, signature_base64url: null };
  }
  if (value.status !== "signed" || value.key_id === null || value.public_key_der_base64url === null || value.public_key_fingerprint === null || value.signature_base64url === null) invalid("invalid_signature", "signed report signature is incomplete");
  const publicKeyDer = base64url(value.public_key_der_base64url, "signature public key", 44);
  const publicKeyFingerprint = fingerprint(value.public_key_fingerprint, "signature public key fingerprint");
  if (crypto.createHash("sha256").update(publicKeyDer).digest("hex") !== publicKeyFingerprint) invalid("invalid_signature", "signature public key fingerprint does not match");
  let publicKey;
  try { publicKey = crypto.createPublicKey({ key: publicKeyDer, format: "der", type: "spki" }); } catch { invalid("invalid_signature", "signature public key is invalid"); }
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") invalid("invalid_signature", "signature public key algorithm is invalid");
  base64url(value.signature_base64url, "signature", 64);
  return {
    status: value.status,
    algorithm: value.algorithm,
    domain: value.domain,
    key_id: safeString(value.key_id, "signature key id", { maximum: 256, pattern: KEY_ID }),
    public_key_der_base64url: value.public_key_der_base64url,
    public_key_fingerprint: publicKeyFingerprint,
    signature_base64url: value.signature_base64url
  };
}

function normalizeCore(input) {
  scanForForbiddenEvidence(input);
  exactKeys(input, ["schema_version", "evidence_kind", "qualification", "provider", "production", "evidence_origin", "source", "execution", "purpose_bindings", "iam_matrix", "scenario_results", "postgres_binding", "overall", "signature", "report_digest"], "KMS qualification report");
  if (input.schema_version !== KMS_QUALIFICATION_SCHEMA_VERSION || input.evidence_kind !== KMS_QUALIFICATION_KIND || input.qualification !== KMS_QUALIFICATION_NAME) invalid("invalid_schema", "KMS qualification schema is invalid");
  if (!KMS_QUALIFICATION_PROVIDERS.includes(input.provider)) invalid("invalid_provider", "provider must be aws or gcp");
  if (input.production !== true && input.production !== false) invalid("invalid_execution", "production must be boolean");
  const origin = safeString(input.evidence_origin, "evidence origin", { maximum: 32, pattern: /^(?:mock|protected_external)$/u });
  const source = normalizeSource(input.source);
  const execution = normalizeExecution(input.execution, input.provider);
  if (origin !== execution.mode || input.production === true && origin !== "protected_external" || input.production === true && execution.credential_source === "test_fixture") invalid("production_gate_failed", "production evidence must be protected external evidence");
  const purposeBindings = normalizePurposeBindings(input.purpose_bindings, input.provider, execution.mode);
  const iamMatrix = normalizeIamMatrix(input.iam_matrix);
  const scenarioResults = normalizeScenarios(input.scenario_results, purposeBindings);
  const postgresBinding = normalizePostgres(input.postgres_binding, source, execution);
  return { source, execution, origin, purposeBindings, iamMatrix, scenarioResults, postgresBinding };
}

function deriveOverall({ purposeBindings, iamMatrix, scenarioResults, postgresBinding }) {
  const failed = [];
  for (const entry of purposeBindings) {
    if (entry.protection.non_exportable !== true) failed.push(`${entry.purpose}:protection`);
    if (entry.sign_verify.status !== "passed" || entry.sign_verify.verified !== true) failed.push(`${entry.purpose}:sign_verify`);
  }
  if (iamMatrix.some((entry) => entry.status !== "passed")) failed.push("iam_matrix");
  if (scenarioResults.some((entry) => entry.status !== "passed")) failed.push("scenario_results");
  if (postgresBinding.status !== "passed" || postgresBinding.response_loss_reconciled !== true) failed.push("postgres_binding");
  return { status: failed.length === 0 ? "passed" : "failed", failed_checks: [...new Set(failed)].sort() };
}

function reportCore(report) {
  const { report_digest: _reportDigest, signature: _signature, ...core } = report;
  void _reportDigest;
  void _signature;
  return core;
}

function reportDigest(report) {
  return `sha256:${sha256(Buffer.from(canonicalJson(reportCore(report)), "utf8"))}`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

/** RFC 8785-shaped canonical JSON for the report's restricted JSON values. */
export function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid("non_finite_number", "canonical JSON cannot contain a non-finite number");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  invalid("non_json_value", "canonical JSON cannot contain this value");
}

export function signatureInputBytes(report) {
  if (report === null || typeof report !== "object" || report.report_digest !== reportDigest(report)) invalid("invalid_report_digest", "report digest is invalid");
  return Buffer.from(canonicalJson({
    domain: KMS_QUALIFICATION_SIGNATURE_DOMAIN,
    report_digest: report.report_digest,
    schema_version: KMS_QUALIFICATION_SCHEMA_VERSION,
    source_commit: report.source.source_commit
  }), "utf8");
}

export function buildKmsQualificationReport(input) {
  plainObject(input, "KMS qualification input");
  optionalKeys(input, new Set(["schema_version", "evidence_kind", "qualification", "provider", "production", "evidence_origin", "source", "execution", "purpose_bindings", "iam_matrix", "scenario_results", "postgres_binding", "signature"]), "KMS qualification input");
  const schemaVersion = input.schema_version ?? KMS_QUALIFICATION_SCHEMA_VERSION;
  const evidenceKind = input.evidence_kind ?? KMS_QUALIFICATION_KIND;
  const qualification = input.qualification ?? KMS_QUALIFICATION_NAME;
  const provider = input.provider;
  if (provider === undefined) invalid("invalid_provider", "provider is required");
  const source = normalizeSource(input.source);
  const execution = normalizeExecution(input.execution, provider);
  const normalized = normalizeCore({
    schema_version: schemaVersion,
    evidence_kind: evidenceKind,
    qualification,
    provider,
    production: input.production,
    evidence_origin: input.evidence_origin,
    source,
    execution,
    purpose_bindings: input.purpose_bindings,
    iam_matrix: input.iam_matrix,
    scenario_results: input.scenario_results,
    postgres_binding: input.postgres_binding,
    overall: { status: "failed", failed_checks: [] },
    signature: input.signature,
    report_digest: "sha256:" + "0".repeat(64)
  });
  const report = {
    schema_version: KMS_QUALIFICATION_SCHEMA_VERSION,
    evidence_kind: KMS_QUALIFICATION_KIND,
    qualification: KMS_QUALIFICATION_NAME,
    provider,
    production: input.production,
    evidence_origin: normalized.origin,
    source: normalized.source,
    execution: normalized.execution,
    purpose_bindings: normalized.purposeBindings,
    iam_matrix: normalized.iamMatrix,
    scenario_results: normalized.scenarioResults,
    postgres_binding: normalized.postgresBinding,
    overall: deriveOverall(normalized),
    signature: normalizeSignature(input.signature),
    report_digest: ""
  };
  report.report_digest = reportDigest(report);
  return Object.freeze(report);
}

export function parseKmsQualificationReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 16 * 1024 * 1024) invalid("invalid_report", "report bytes are invalid");
  const text = Buffer.from(bytes).toString("utf8");
  let value;
  try { value = JSON.parse(text); } catch { invalid("invalid_json", "report is not JSON"); }
  if (`${canonicalJson(value)}\n` !== text) invalid("noncanonical_json", "report is not canonical JSON");
  exactKeys(value, ["schema_version", "evidence_kind", "qualification", "provider", "production", "evidence_origin", "source", "execution", "purpose_bindings", "iam_matrix", "scenario_results", "postgres_binding", "overall", "signature", "report_digest"], "KMS qualification report");
  const normalized = normalizeCore(value);
  exactKeys(value.overall, ["status", "failed_checks"], "overall");
  const expectedOverall = deriveOverall(normalized);
  if (canonicalJson(value.overall) !== canonicalJson(expectedOverall)) invalid("overall_mismatch", "overall status is not derived from evidence");
  const expected = buildKmsQualificationReport({
    schema_version: value.schema_version,
    evidence_kind: value.evidence_kind,
    qualification: value.qualification,
    provider: value.provider,
    production: value.production,
    evidence_origin: value.evidence_origin,
    source: value.source,
    execution: value.execution,
    purpose_bindings: value.purpose_bindings,
    iam_matrix: value.iam_matrix,
    scenario_results: value.scenario_results,
    postgres_binding: value.postgres_binding,
    signature: value.signature
  });
  if (canonicalJson(expected) !== canonicalJson(value)) invalid("report_binding_mismatch", "report normalization or digest binding is invalid");
  return Object.freeze(value);
}

export function serializeKmsQualificationReport(report) {
  parseKmsQualificationReport(Buffer.from(`${canonicalJson(report)}\n`, "utf8"));
  return Buffer.from(`${canonicalJson(report)}\n`, "utf8");
}

export async function writeKmsQualificationReport(outputFile, report) {
  if (typeof outputFile !== "string" || !path.isAbsolute(outputFile)) invalid("invalid_output_path", "report output path must be absolute");
  const bytes = serializeKmsQualificationReport(report);
  const directory = path.dirname(outputFile);
  const temporary = path.join(directory, `.${path.basename(outputFile)}.${process.pid}.${crypto.randomBytes(12).toString("hex")}.tmp`);
  let handle;
  try {
    handle = await fsp.open(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    // Qualification evidence is immutable audit material. Publish it with an
    // exclusive hard link so an existing report (including a symlink) can
    // never be replaced by a later run.
    await fsp.link(temporary, outputFile);
    await fsp.unlink(temporary);
    const directoryHandle = await fsp.open(directory, fs.constants.O_RDONLY);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } catch (error) {
    await handle?.close().catch(() => {});
    await fsp.rm(temporary, { force: true }).catch(() => {});
    if (error instanceof KmsQualificationEvidenceError) throw error;
    invalid("write_failed", "report could not be written");
  }
}

function resolveHeadCommit(repositoryRoot) {
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) invalid("invalid_repository_path", "repository root is invalid");
  let result;
  try { result = spawnSync("git", ["-C", repositoryRoot, "rev-parse", "--verify", "HEAD^{commit}"], { encoding: "utf8", shell: false, stdio: ["ignore", "pipe", "ignore"] }); } catch { invalid("source_commit_unavailable", "source commit is unavailable"); }
  const commit = result.status === 0 && typeof result.stdout === "string" ? result.stdout.trim() : "";
  if (!COMMIT.test(commit)) invalid("source_commit_unavailable", "source commit is unavailable");
  return commit;
}

export function resolveKmsQualificationSourceCommit(repositoryRoot) {
  return resolveHeadCommit(repositoryRoot);
}

export function verifyKmsQualificationReport(report, {
  repositoryRoot,
  requireProduction = true,
  trustedPublicKeyDer,
  trustedKeyId
} = {}) {
  if (!report || typeof report !== "object") invalid("invalid_report", "report is invalid");
  // A caller may pass a materialized object instead of report bytes. Reparse
  // the canonical representation before any gate check so this API enforces
  // the same closed evidence envelope as the CLI: exact eight purposes,
  // 64-pair IAM matrix, 40 lifecycle scenarios, non-exportability, and all
  // candidate/source bindings cannot be bypassed by a forged projection.
  report = parseKmsQualificationReport(Buffer.from(`${canonicalJson(report)}\n`, "utf8"));
  const currentCommit = resolveHeadCommit(repositoryRoot ?? path.resolve(import.meta.dirname, "../.."));
  if (report.source.source_commit !== currentCommit) invalid("source_commit_mismatch", "report source commit does not match the verifier checkout");
  if (requireProduction && report.production !== true) invalid("not_production", "report is not production evidence");
  if (report.production === true) {
    if (report.evidence_origin !== "protected_external" || report.execution.mode !== "protected_external" || report.execution.zero_skip !== true || report.execution.skip_count !== 0 || report.overall.status !== "passed" || report.overall.failed_checks.length !== 0 || report.signature.status !== "signed") invalid("production_gate_failed", "report does not satisfy the production gate");
    if (!(trustedPublicKeyDer instanceof Uint8Array)
      || trustedPublicKeyDer.byteLength !== 44
      || typeof trustedKeyId !== "string"
      || !KEY_ID.test(trustedKeyId)) {
      invalid("trusted_key_required", "an independently pinned qualification key is required");
    }
    const embeddedPublicKeyDer = Buffer.from(report.signature.public_key_der_base64url, "base64url");
    const trustedDer = Buffer.from(trustedPublicKeyDer);
    const trustedFingerprint = crypto.createHash("sha256").update(trustedDer).digest("hex");
    if (report.signature.key_id !== trustedKeyId
      || report.signature.public_key_fingerprint !== trustedFingerprint
      || embeddedPublicKeyDer.byteLength !== trustedDer.byteLength
      || !crypto.timingSafeEqual(embeddedPublicKeyDer, trustedDer)) {
      invalid("untrusted_signature_key", "report signature key does not match the independent trust pin");
    }
    let publicKey;
    try { publicKey = crypto.createPublicKey({ key: trustedDer, format: "der", type: "spki" }); }
    catch { invalid("untrusted_signature_key", "trusted qualification key is invalid"); }
    if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") invalid("untrusted_signature_key", "trusted qualification key is invalid");
    const valid = crypto.verify(null, signatureInputBytes(report), publicKey, Buffer.from(report.signature.signature_base64url, "base64url"));
    if (!valid) invalid("invalid_signature", "report signature is invalid");
  }
  return Object.freeze({ report_digest: report.report_digest, source_commit: report.source.source_commit, provider: report.provider });
}

export function scanForForbiddenEvidence(value) {
  const walk = (current, pathParts) => {
    if (Array.isArray(current)) return current.forEach((child, index) => walk(child, [...pathParts, String(index)]));
    if (current && typeof current === "object") {
      for (const key of Reflect.ownKeys(current)) {
        if (typeof key !== "string" || FORBIDDEN_KEY.test(key)) invalid("sensitive_field", `sensitive evidence field at ${[...pathParts, String(key)].join(".")}`);
        walk(current[key], [...pathParts, key]);
      }
      return;
    }
    if (typeof current === "string" && FORBIDDEN_VALUE.test(current)) invalid("sensitive_value", `sensitive evidence value at ${pathParts.join(".")}`);
  };
  walk(value, []);
  return true;
}
