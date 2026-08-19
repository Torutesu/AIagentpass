import crypto from "node:crypto";

import {
  KMS_QUALIFICATION_PROVIDERS,
  KMS_QUALIFICATION_PURPOSES,
  canonicalJson,
  scanForForbiddenEvidence
} from "./schema.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "../../apps/cloud-api/src/signer-purpose-registry.mjs";

export const KMS_QUALIFICATION_RUNNER_VERSION = 1;
export const KMS_QUALIFICATION_RUNNER_PROBE_DOMAIN = "AgentPass-Hosted-KMS-Qualification-Probe-v1";
export const KMS_QUALIFICATION_RUNNER_DEFAULTS = Object.freeze({
  timeoutMs: 5_000,
  maxConcurrency: 8
});

const MAX_TIMEOUT_MS = 30_000;
const MAX_CONCURRENCY = 8;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const VERSION = /^[1-9][0-9]{0,19}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SAFE_TEXT = /^[a-z][a-z0-9._-]{2,63}$/u;
const SENSITIVE_VALUE = /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:access[_-]?token|authorization|bearer|credential|diagnostic|password|private|secret|stderr|stdout|token)\b)/iu;
const FIXTURE_SOURCE = /(?:^|[._-])(?:fixture|mock|test)(?:$|[._-])/iu;
const EXTERNAL_EVIDENCE_SOURCE = Object.freeze({
  aws: /^aws\.(?:kms[._-]?api|workload[._-]?identity)$/u,
  gcp: /^gcp\.(?:cloud[._-]?kms[._-]?api|workload[._-]?identity)$/u
});
const AWS_RESOURCE = /^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const GCP_RESOURCE = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9][a-z0-9-]{0,62}\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/([1-9][0-9]{0,19})$/u;
const FORBIDDEN_RESULT_KEY = /^(?:credential|debug|diagnostic|error|message|output|private|raw|response|result|secret|stderr|stdout|token|trace)/iu;
const PURPOSES = Object.freeze(KMS_QUALIFICATION_PURPOSES.map(({ name, purpose }) => {
  const registry = SIGNER_PURPOSE_REGISTRY[name];
  if (!registry || registry.purpose !== purpose) throw new Error("KMS qualification purpose registry mismatch");
  return Object.freeze({
    name,
    purpose,
    registry_version: registry.registry_version,
    protocol_version: registry.protocol_version,
    signing_version: registry.signing_version
  });
}));
const PURPOSE_BY_PURPOSE = new Map(PURPOSES.map((purpose) => [purpose.purpose, purpose]));

export class KmsQualificationRunnerError extends Error {
  constructor(code) {
    super(code);
    this.name = "KmsQualificationRunnerError";
    this.code = code;
  }
}

/**
 * Run the provider-independent part of hosted KMS qualification.
 *
 * Provider-specific code is injected through three narrow operations. Those
 * operations must return already-redacted observations; this function never
 * accepts a provider SDK response, signature, public key, credential, or
 * error object as an evidence value. It creates the request digests itself,
 * and only copies values that pass the exact primitive validators below.
 */
export async function runKmsQualification({
  provider,
  mode = "protected_external",
  operations,
  timeoutMs = KMS_QUALIFICATION_RUNNER_DEFAULTS.timeoutMs,
  maxConcurrency = KMS_QUALIFICATION_RUNNER_DEFAULTS.maxConcurrency,
  signal
} = {}) {
  validateConfiguration({ provider, mode, operations, timeoutMs, maxConcurrency, signal });

  const descriptions = await runBounded(PURPOSES, maxConcurrency, signal, timeoutMs, async (purpose, { signal: operationSignal }) => {
    const result = await operations.describePurpose(purposeContext(purpose), { signal: operationSignal });
    return normalizePurposeDescription(result, provider, mode);
  }, "describe_purpose");

  const bindings = descriptions.map((description, index) => {
    const purpose = PURPOSES[index];
    const requestBytes = purposeProbeBytes(purpose, description);
    const requestDigest = digest(requestBytes);
    return {
      ...purpose,
      provider,
      algorithm: "ed25519",
      key_id: description.key_id,
      key_resource: description.key_resource,
      key_version: description.key_version,
      public_key_fingerprint: description.public_key_fingerprint,
      lifecycle_epoch: description.lifecycle_epoch,
      protection: description.protection,
      request_bytes: requestBytes,
      request_digest: requestDigest
    };
  });

  const signVerify = await runBounded(bindings, maxConcurrency, signal, timeoutMs, async (binding, { signal: operationSignal }) => {
    const result = await operations.signAndVerify({
      ...publicBindingContext(binding),
      request_bytes: Buffer.from(binding.request_bytes),
      request_digest: binding.request_digest
    }, { signal: operationSignal });
    return normalizeSignVerify(result, binding.request_digest, mode);
  }, "sign_verify");

  const purposeBindings = bindings.map((binding, index) => {
    const { request_bytes: _requestBytes, request_digest: _requestDigest, ...publicBinding } = binding;
    void _requestBytes;
    void _requestDigest;
    return Object.freeze({ ...publicBinding, sign_verify: signVerify[index] });
  });

  const iamPairs = [];
  for (const requester of PURPOSES) {
    for (const target of PURPOSES) {
      const expected = requester.purpose === target.purpose ? "allow" : "deny";
      const requestBytes = iamProbeBytes(requester, target, expected);
      iamPairs.push({ requester, target, expected, requestBytes, requestDigest: digest(requestBytes) });
    }
  }
  const iamResults = await runBounded(iamPairs, maxConcurrency, signal, timeoutMs, async (pair, { signal: operationSignal }) => {
    const result = await operations.checkIam({
      requester: purposeContext(pair.requester),
      target: purposeContext(pair.target),
      action: "sign",
      expected: pair.expected,
      request_bytes: Buffer.from(pair.requestBytes),
      request_digest: pair.requestDigest
    }, { signal: operationSignal });
    return normalizeIamResult(result, pair.expected, pair.requestDigest, mode);
  }, "iam_matrix");

  const iamMatrix = iamPairs.map((pair, index) => Object.freeze({
    requester_purpose: pair.requester.purpose,
    target_purpose: pair.target.purpose,
    action: "sign",
    expected: pair.expected,
    ...iamResults[index]
  }));

  const result = {
    runner_version: KMS_QUALIFICATION_RUNNER_VERSION,
    provider,
    evidence_origin: mode === "mock" ? "mock" : "protected_external",
    purpose_bindings: purposeBindings,
    iam_matrix: iamMatrix,
    counts: {
      purpose_sign_verify: purposeBindings.length,
      iam_matrix: iamMatrix.length
    }
  };
  assertSafeEvidence(result);
  return deepFreeze(result);
}

/**
 * Validate a runner result before handing it to report.mjs. This is exported
 * so an external orchestration process can validate a serialized handoff
 * without importing AWS or GCP SDKs.
 */
export function validateKmsQualificationRunnerResult(value, { provider, mode } = {}) {
  assertSafeEvidence(value);
  exactKeys(value, ["counts", "evidence_origin", "iam_matrix", "provider", "purpose_bindings", "runner_version"], "runner result");
  if (value.runner_version !== KMS_QUALIFICATION_RUNNER_VERSION) fail("invalid_runner_result");
  if (provider !== undefined && value.provider !== provider) fail("provider_mismatch");
  if (!KMS_QUALIFICATION_PROVIDERS.includes(value.provider)) fail("invalid_provider");
  if (value.evidence_origin !== "mock" && value.evidence_origin !== "protected_external") fail("invalid_origin");
  if (mode !== undefined && value.evidence_origin !== (mode === "mock" ? "mock" : "protected_external")) fail("mode_mismatch");
  const resolvedMode = value.evidence_origin === "mock" ? "mock" : "protected_external";
  if (!Array.isArray(value.purpose_bindings) || value.purpose_bindings.length !== PURPOSES.length) fail("purpose_count");
  if (!Array.isArray(value.iam_matrix) || value.iam_matrix.length !== PURPOSES.length ** 2) fail("iam_count");
  exactKeys(value.counts, ["iam_matrix", "purpose_sign_verify"], "runner counts");
  if (value.counts.purpose_sign_verify !== PURPOSES.length || value.counts.iam_matrix !== PURPOSES.length ** 2) fail("count_mismatch");

  const names = new Set();
  const resources = new Set();
  const keyIds = new Set();
  const fingerprints = new Set();
  for (const [index, entry] of value.purpose_bindings.entries()) {
    exactKeys(entry, ["algorithm", "key_id", "key_resource", "key_version", "lifecycle_epoch", "name", "protocol_version", "provider", "public_key_fingerprint", "purpose", "protection", "registry_version", "sign_verify", "signing_version"], `purpose binding ${index}`);
    const expected = PURPOSES[index];
    if (entry.name !== expected.name || entry.purpose !== expected.purpose || entry.registry_version !== expected.registry_version
      || entry.protocol_version !== expected.protocol_version || entry.signing_version !== expected.signing_version) fail("purpose_order");
    if (entry.provider !== value.provider || entry.algorithm !== "ed25519") fail("purpose_binding");
    if (names.has(entry.name) || resources.has(entry.key_resource) || keyIds.has(entry.key_id) || fingerprints.has(entry.public_key_fingerprint)) fail("purpose_reuse");
    names.add(entry.name);
    resources.add(entry.key_resource);
    keyIds.add(entry.key_id);
    fingerprints.add(entry.public_key_fingerprint);
    normalizePurposeDescription({
      key_id: entry.key_id,
      key_resource: entry.key_resource,
      key_version: entry.key_version,
      public_key_fingerprint: entry.public_key_fingerprint,
      lifecycle_epoch: entry.lifecycle_epoch,
      protection: entry.protection
    }, value.provider, resolvedMode);
    const { request_digest: requestDigest, ...signVerify } = entry.sign_verify;
    const expectedRequestDigest = digest(purposeProbeBytes(expected, entry));
    if (requestDigest !== expectedRequestDigest) fail("sign_request_binding");
    normalizeSignVerify(signVerify, expectedRequestDigest, resolvedMode);
  }
  const pairs = new Set();
  for (const [index, entry] of value.iam_matrix.entries()) {
    exactKeys(entry, ["action", "evidence_digest", "expected", "observed", "observed_at", "request_digest", "requester_purpose", "status", "target_purpose"], `IAM matrix entry ${index}`);
    if (!PURPOSES.some(({ purpose }) => purpose === entry.requester_purpose) || !PURPOSES.some(({ purpose }) => purpose === entry.target_purpose)) fail("iam_purpose");
    const pair = `${entry.requester_purpose}\0${entry.target_purpose}`;
    if (pairs.has(pair)) fail("iam_duplicate");
    pairs.add(pair);
    const expected = entry.requester_purpose === entry.target_purpose ? "allow" : "deny";
    if (entry.action !== "sign" || entry.expected !== expected) fail("iam_expectation");
    const requester = PURPOSE_BY_PURPOSE.get(entry.requester_purpose);
    const target = PURPOSE_BY_PURPOSE.get(entry.target_purpose);
    const expectedRequestDigest = digest(iamProbeBytes(requester, target, expected));
    if (entry.request_digest !== expectedRequestDigest) fail("iam_request_binding");
    normalizeIamResult({
      observed: entry.observed,
      status: entry.status,
      evidence_digest: entry.evidence_digest,
      observed_at: entry.observed_at
    }, expected, expectedRequestDigest, resolvedMode);
  }
  if (pairs.size !== PURPOSES.length ** 2) fail("iam_incomplete");
  return deepFreeze(structuredClone(value));
}

function validateConfiguration({ provider, mode, operations, timeoutMs, maxConcurrency, signal }) {
  if (!KMS_QUALIFICATION_PROVIDERS.includes(provider)) fail("invalid_provider");
  if (mode !== "mock" && mode !== "protected_external") fail("invalid_mode");
  if (!plainObject(operations) || typeof operations.describePurpose !== "function"
    || typeof operations.signAndVerify !== "function" || typeof operations.checkIam !== "function") fail("invalid_operations");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) fail("invalid_timeout");
  if (!Number.isSafeInteger(maxConcurrency) || maxConcurrency < 1 || maxConcurrency > MAX_CONCURRENCY) fail("invalid_concurrency");
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail("invalid_signal");
}

async function runBounded(items, maxConcurrency, parentSignal, timeoutMs, operation, stage) {
  const results = new Array(items.length);
  const failures = [];
  let next = 0;
  async function worker() {
    while (true) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      try {
        results[index] = await withDeadline(
          (signal) => operation(items[index], { signal }),
          parentSignal,
          timeoutMs
        );
      } catch (error) {
        failures.push({ index, aborted: error?.code === "aborted", timedOut: error?.code === "timeout" });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(maxConcurrency, items.length) }, () => worker()));
  if (failures.length > 0) {
    const error = new KmsQualificationRunnerError(failures.some(({ timedOut }) => timedOut) ? "operation_timeout" : failures.some(({ aborted }) => aborted) ? "operation_aborted" : "operation_failed");
    error.stage = stage;
    error.failure_count = failures.length;
    throw error;
  }
  return results;
}

function withDeadline(operation, parentSignal, timeoutMs) {
  if (parentSignal?.aborted) return Promise.reject(Object.assign(new Error("aborted"), { code: "aborted" }));
  const controller = new AbortController();
  let timer;
  let listener;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (parentSignal && listener) parentSignal.removeEventListener("abort", listener);
      fn(value);
    };
    listener = () => {
      controller.abort();
      finish(reject, Object.assign(new Error("aborted"), { code: "aborted" }));
    };
    if (parentSignal) parentSignal.addEventListener("abort", listener, { once: true });
    timer = setTimeout(() => {
      controller.abort();
      finish(reject, Object.assign(new Error("timeout"), { code: "timeout" }));
    }, timeoutMs);
    Promise.resolve().then(() => operation(controller.signal)).then(
      (value) => finish(resolve, value),
      () => finish(reject, new KmsQualificationRunnerError("operation_failed"))
    );
  });
}

function purposeContext(purpose) {
  return Object.freeze({
    name: purpose.name,
    purpose: purpose.purpose,
    registry_version: purpose.registry_version,
    protocol_version: purpose.protocol_version,
    signing_version: purpose.signing_version,
    algorithm: "ed25519"
  });
}

function publicBindingContext(binding) {
  return Object.freeze({
    ...purposeContext(binding),
    provider: binding.provider,
    key_id: binding.key_id,
    key_resource: binding.key_resource,
    key_version: binding.key_version,
    public_key_fingerprint: binding.public_key_fingerprint,
    lifecycle_epoch: binding.lifecycle_epoch
  });
}

function purposeProbeBytes(purpose, description) {
  return Buffer.from(canonicalJson({
    domain: KMS_QUALIFICATION_RUNNER_PROBE_DOMAIN,
    key_id: description.key_id,
    key_version: description.key_version,
    name: purpose.name,
    protocol_version: purpose.protocol_version,
    purpose: purpose.purpose,
    registry_version: purpose.registry_version,
    signing_version: purpose.signing_version
  }), "utf8");
}

function iamProbeBytes(requester, target, expected) {
  return Buffer.from(canonicalJson({
    action: "sign",
    domain: KMS_QUALIFICATION_RUNNER_PROBE_DOMAIN,
    expected,
    requester_purpose: requester.purpose,
    target_purpose: target.purpose
  }), "utf8");
}

function normalizePurposeDescription(value, provider, mode) {
  assertSafeCallbackValue(value, "purpose description");
  exactKeys(value, ["key_id", "key_resource", "key_version", "lifecycle_epoch", "protection", "public_key_fingerprint"], "purpose description");
  safeString(value.key_id, "key id", KEY_ID);
  safeString(value.key_version, "key version", VERSION);
  const resourcePattern = provider === "aws" ? AWS_RESOURCE : GCP_RESOURCE;
  safeString(value.key_resource, "key resource", resourcePattern);
  if (provider === "gcp" && GCP_RESOURCE.exec(value.key_resource)?.[1] !== value.key_version) fail("key_version_mismatch");
  safeString(value.public_key_fingerprint, "public key fingerprint", FINGERPRINT);
  if (!Number.isSafeInteger(value.lifecycle_epoch) || value.lifecycle_epoch < 1) fail("invalid_lifecycle_epoch");
  const protection = normalizeProtection(value.protection, mode, provider);
  return Object.freeze({
    key_id: value.key_id,
    key_resource: value.key_resource,
    key_version: value.key_version,
    public_key_fingerprint: value.public_key_fingerprint,
    lifecycle_epoch: value.lifecycle_epoch,
    protection
  });
}

function normalizeProtection(value, mode, provider) {
  assertSafeCallbackValue(value, "protection");
  exactKeys(value, ["evidence_digest", "evidence_source", "key_usage", "level", "non_exportable", "observed_at"], "protection");
  if (value.level !== "HSM" || value.non_exportable !== true || value.key_usage !== "sign_verify") fail("protection_not_proven");
  safeString(value.evidence_source, "protection evidence source", SAFE_TEXT);
  if (mode === "protected_external" && !EXTERNAL_EVIDENCE_SOURCE[provider]?.test(value.evidence_source)) fail("external_source_not_proven");
  safeString(value.evidence_digest, "protection evidence digest", DIGEST);
  timestamp(value.observed_at, "protection observed at");
  return Object.freeze({
    level: value.level,
    non_exportable: value.non_exportable,
    key_usage: value.key_usage,
    evidence_source: value.evidence_source,
    evidence_digest: value.evidence_digest,
    observed_at: value.observed_at
  });
}

function normalizeSignVerify(value, requestDigest, mode) {
  assertSafeCallbackValue(value, "sign/verify result");
  exactKeys(value, ["evidence_digest", "observed_at", "signature_digest", "status", "verified"], "sign/verify result");
  if (value.status !== "passed" && value.status !== "failed") fail("invalid_sign_verify_status");
  if (value.verified !== (value.status === "passed")) fail("sign_verify_status_mismatch");
  safeString(requestDigest, "request digest", DIGEST);
  safeString(value.signature_digest, "signature digest", DIGEST);
  safeString(value.evidence_digest, "sign/verify evidence digest", DIGEST);
  timestamp(value.observed_at, "sign/verify observed at");
  if (mode === "protected_external" && value.evidence_digest === "sha256:" + "0".repeat(64)) fail("empty_evidence_digest");
  return Object.freeze({
    status: value.status,
    verified: value.verified,
    request_digest: requestDigest,
    signature_digest: value.signature_digest,
    evidence_digest: value.evidence_digest,
    observed_at: value.observed_at
  });
}

function normalizeIamResult(value, expected, requestDigest, mode) {
  assertSafeCallbackValue(value, "IAM result");
  exactKeys(value, ["evidence_digest", "observed", "observed_at", "status"], "IAM result");
  if (value.observed !== "allow" && value.observed !== "deny") fail("invalid_iam_observation");
  if (value.status !== "passed" && value.status !== "failed") fail("invalid_iam_status");
  if (value.status !== (value.observed === expected ? "passed" : "failed")) fail("iam_status_mismatch");
  safeString(requestDigest, "request digest", DIGEST);
  safeString(value.evidence_digest, "IAM evidence digest", DIGEST);
  timestamp(value.observed_at, "IAM observed at");
  if (mode === "protected_external" && value.evidence_digest === "sha256:" + "0".repeat(64)) fail("empty_evidence_digest");
  return Object.freeze({
    observed: value.observed,
    status: value.status,
    request_digest: requestDigest,
    evidence_digest: value.evidence_digest,
    observed_at: value.observed_at
  });
}

function assertSafeCallbackValue(value, label) {
  if (!plainObject(value)) fail("invalid_callback_result");
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = typeof key === "string" ? Object.getOwnPropertyDescriptor(value, key) : undefined;
    if (typeof key !== "string" || !descriptor?.enumerable || !Object.hasOwn(descriptor, "value") || FORBIDDEN_RESULT_KEY.test(key)) {
      fail("unsafe_callback_result");
    }
  }
  try { scanForForbiddenEvidence(value); } catch { fail("unsafe_callback_result"); }
  void label;
}

function assertSafeEvidence(value) {
  try { scanForForbiddenEvidence(value); } catch { fail("unsafe_evidence"); }
  return value;
}

function exactKeys(value, keys, label) {
  if (!plainObject(value)) fail("invalid_shape");
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => {
    const descriptor = typeof key === "string" ? Object.getOwnPropertyDescriptor(value, key) : undefined;
    return typeof key !== "string" || !descriptor?.enumerable || !Object.hasOwn(descriptor, "value");
  })) fail(`unknown_field:${label}`);
  const expected = [...keys].sort();
  const sorted = actual.sort();
  if (sorted.length !== expected.length || sorted.some((key, index) => key !== expected[index])) fail(`unknown_field:${label}`);
}

function safeString(value, label, pattern) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /[\u0000-\u001f\u007f\u2028\u2029\r\n]/u.test(value) || SENSITIVE_VALUE.test(value) || !pattern.test(value)) fail(`invalid_string:${label}`);
  return value;
}

function timestamp(value, label) {
  safeString(value, label, ISO_UTC);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail(`invalid_timestamp:${label}`);
  return value;
}

function digest(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code) {
  throw new KmsQualificationRunnerError(code);
}
