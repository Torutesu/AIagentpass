import { PROVIDER_OPERATION_UNCERTAIN_REASONS } from "./postgres/provider-operation-repository.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "./signer-purpose-registry.mjs";

/**
 * Deployment-internal contract for an uncertain provider-operation record.
 *
 * This module is deliberately a DTO boundary, not an operator API and not a
 * signing client.  It carries enough public metadata to fence an internal
 * decision while refusing signing bytes, signatures, receipts, claim tokens,
 * provider diagnostics, organization identifiers, and arbitrary terminal
 * states.  The provider-operation ledger is deployment-wide and has no exact
 * organization correlation, so every normalized value is permanently marked
 * as unavailable for human/tenant exposure.
 */

export const MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION = 1;
export const MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ACTIONS = Object.freeze([
  "exact_sql_reconciliation",
  "provider_bound_verification",
  "producer_specific_terminal_handoff",
]);
export const MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_PRODUCERS = Object.freeze([
  "managed_signer_key_lifecycle",
]);
export const MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_OUTCOMES = Object.freeze([
  "reconciled",
  "verified",
  "handed_off",
  "no_match",
  "stale",
  "unsupported",
  "unavailable",
]);
export const MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_PROHIBITED_FIELDS = Object.freeze([
  "organization_id",
  "tenant_id",
  "claim_token",
  "signing_bytes",
  "bytes",
  "signature",
  "provider_receipt",
  "provider_diagnostics",
  "diagnostics",
  "retry_sign",
  "terminal_state",
]);

export const MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "managed_signer_provider_operation_adjudication_invalid_input",
  UNSUPPORTED_ACTION: "managed_signer_provider_operation_adjudication_unsupported_action",
  TENANT_CORRELATION_UNAVAILABLE: "managed_signer_provider_operation_adjudication_tenant_correlation_unavailable",
});

const {
  INVALID_INPUT,
  UNSUPPORTED_ACTION,
  TENANT_CORRELATION_UNAVAILABLE,
} = MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ERROR_CODES;

const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const KEY_VERSION = /^[1-9][0-9]{0,18}$/u;
const MAX_POSTGRES_BIGINT = "9223372036854775807";
const DIGEST = /^[0-9a-f]{64}$/u;
const CURSOR = /^[A-Za-z0-9_-]{1,512}$/u;
const MAX_BYTES = 1024 * 1024;
const MAX_ITEMS = 100;
const ALGORITHM = "ed25519";
const PROVIDER_RESULT_STATES = Object.freeze(["absent", "present"]);
const OPERATION_STATES = Object.freeze(["uncertain"]);
const REGISTERED_PURPOSES = Object.freeze(Object.values(SIGNER_PURPOSE_REGISTRY)
  .map(({ purpose }) => purpose)
  .sort());
const REGISTERED_PURPOSE_SET = new Set(REGISTERED_PURPOSES);
const SUMMARY_FIELDS = Object.freeze([
  "version",
  "purpose",
  "operation_id",
  "algorithm",
  "bytes_length",
  "request_digest",
  "key_id",
  "key_version",
  "state",
  "uncertain_reason",
  "provider_result",
]);
const SUMMARY_OUTPUT_FIELDS = Object.freeze([
  ...SUMMARY_FIELDS,
  "organization_correlation",
  "human_exposure",
]);
const EXPECTED_FIELDS = Object.freeze([
  "algorithm",
  "bytes_length",
  "request_digest",
  "key_id",
  "key_version",
  "state",
  "uncertain_reason",
  "provider_result",
]);
const TARGET_FIELDS = Object.freeze(["purpose", "operation_id"]);
const DEFAULT_OPTIONS = Object.freeze({ providerVerificationPurposes: Object.freeze([]) });

export class ManagedSignerProviderOperationAdjudicationError extends Error {
  constructor(code) {
    super(code === TENANT_CORRELATION_UNAVAILABLE
      ? "managed signer provider operations have no organization correlation"
      : code === UNSUPPORTED_ACTION
        ? "managed signer provider operation adjudication action is unsupported"
        : "managed signer provider operation adjudication input is invalid");
    this.name = "ManagedSignerProviderOperationAdjudicationError";
    this.code = Object.values(MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ERROR_CODES).includes(code)
      ? code
      : INVALID_INPUT;
  }
}

/**
 * Normalize a ledger-derived uncertain summary.  The input is intentionally
 * not a provider-operation repository record: a repository record may contain
 * output bytes encoded as a signature and receipt metadata.  Callers must
 * reduce it to `provider_result` before crossing this boundary.
 */
export function normalizeManagedSignerProviderOperationUncertaintySummary(value) {
  if (!isPlainObject(value)) fail(INVALID_INPUT);
  const keys = Reflect.ownKeys(value);
  const isOutput = keys.length === SUMMARY_OUTPUT_FIELDS.length
    && keys.every((key) => typeof key === "string" && SUMMARY_OUTPUT_FIELDS.includes(key));
  exactKeys(value, isOutput ? SUMMARY_OUTPUT_FIELDS : SUMMARY_FIELDS);
  if (isOutput && (value.organization_correlation !== "unavailable" || value.human_exposure !== "forbidden")) {
    fail(TENANT_CORRELATION_UNAVAILABLE);
  }
  if (value.version !== MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION
    || value.algorithm !== ALGORITHM
    || value.state !== OPERATION_STATES[0]
    || !PURPOSE.test(value.purpose ?? "")
    || !REGISTERED_PURPOSE_SET.has(value.purpose)
    || !OPERATION_ID.test(value.operation_id ?? "")
    || !KEY_ID.test(value.key_id ?? "")
    || !validKeyVersion(value.key_version)
    || !DIGEST.test(value.request_digest ?? "")
    || !Number.isSafeInteger(value.bytes_length)
    || value.bytes_length < 1
    || value.bytes_length > MAX_BYTES
    || !PROVIDER_OPERATION_UNCERTAIN_REASONS.includes(value.uncertain_reason)
    || !PROVIDER_RESULT_STATES.includes(value.provider_result)) {
    fail(INVALID_INPUT);
  }
  return Object.freeze({
    version: MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION,
    purpose: value.purpose,
    operation_id: value.operation_id,
    algorithm: ALGORITHM,
    bytes_length: value.bytes_length,
    request_digest: value.request_digest,
    key_id: value.key_id,
    key_version: value.key_version,
    state: "uncertain",
    uncertain_reason: value.uncertain_reason,
    provider_result: value.provider_result,
    organization_correlation: "unavailable",
    human_exposure: "forbidden",
  });
}

/**
 * Normalize a bounded internal queue page.  This is not a cursor API: the
 * cursor remains opaque and is only carried between trusted deployment
 * components.  No tenant or organization selector is accepted.
 */
export function normalizeManagedSignerProviderOperationUncertaintyList(value) {
  exactKeys(value, ["version", "items", "next_cursor"]);
  if (value.version !== MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION
    || !Array.isArray(value.items)
    || value.items.length > MAX_ITEMS
    || !(value.next_cursor === null || (typeof value.next_cursor === "string" && CURSOR.test(value.next_cursor)))) {
    fail(INVALID_INPUT);
  }
  const items = value.items.map(normalizeManagedSignerProviderOperationUncertaintySummary);
  return Object.freeze({
    version: MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION,
    items: Object.freeze(items),
    next_cursor: value.next_cursor,
    organization_correlation: "unavailable",
    human_exposure: "forbidden",
  });
}

/**
 * Create the deployment-internal action contract. Provider-bound verification
 * is opt-in per exact signer purpose because it requires a provider-specific
 * lookup/verification capability supplied by the server. It never accepts
 * provider output from a caller; the provider adapter must obtain and persist
 * exact output itself.
 */
export function createManagedSignerProviderOperationAdjudicationContract(options = DEFAULT_OPTIONS) {
  exactKeys(options, ["providerVerificationPurposes"]);
  const providerVerificationPurposes = normalizeProviderVerificationPurposes(options.providerVerificationPurposes);
  const providerVerificationPurposeSet = new Set(providerVerificationPurposes);

  function allowedActions(summaryValue) {
    const summary = normalizeManagedSignerProviderOperationUncertaintySummary(summaryValue);
    const actions = [];
    if (summary.provider_result === "present") actions.push("exact_sql_reconciliation");
    if (providerVerificationPurposeSet.has(summary.purpose)) actions.push("provider_bound_verification");
    actions.push("producer_specific_terminal_handoff");
    return Object.freeze(actions);
  }

  function normalizeDetail(value) {
    exactKeys(value, ["summary", "allowed_actions"]);
    const summary = normalizeManagedSignerProviderOperationUncertaintySummary(value.summary);
    const actions = allowedActions(summary);
    if (!Array.isArray(value.allowed_actions)
      || value.allowed_actions.length !== actions.length
      || value.allowed_actions.some((action, index) => action !== actions[index])) {
      fail(INVALID_INPUT);
    }
    return Object.freeze({
      version: MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION,
      summary,
      allowed_actions: actions,
      organization_correlation: "unavailable",
      human_exposure: "forbidden",
    });
  }

  function normalizeCommand(value) {
    if (!isPlainObject(value)) fail(INVALID_INPUT);
    const action = value.action;
    if (!MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ACTIONS.includes(action)) fail(UNSUPPORTED_ACTION);
    const keys = action === "producer_specific_terminal_handoff"
      ? ["version", "action", "target", "expected", "producer"]
      : ["version", "action", "target", "expected"];
    exactKeys(value, keys);
    if (value.version !== MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION) fail(INVALID_INPUT);
    const target = normalizeTarget(value.target);
    const expected = normalizeExpected(value.expected);
    if (action === "exact_sql_reconciliation" && expected.provider_result !== "present") fail(UNSUPPORTED_ACTION);
    if (action === "provider_bound_verification" && !providerVerificationPurposeSet.has(target.purpose)) fail(UNSUPPORTED_ACTION);
    const result = { version: 1, action, target, expected };
    if (action === "producer_specific_terminal_handoff") {
      if (value.producer !== MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_PRODUCERS[0]) fail(INVALID_INPUT);
      result.producer = value.producer;
    }
    return Object.freeze(result);
  }

  function normalizeResult(value) {
    exactKeys(value, ["version", "action", "target", "outcome", "after_state"]);
    if (value.version !== MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION
      || !MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ACTIONS.includes(value.action)
      || !MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_OUTCOMES.includes(value.outcome)
      || !["uncertain", "committed"].includes(value.after_state)) fail(INVALID_INPUT);
    const target = normalizeTarget(value.target);
    if (value.action === "provider_bound_verification" && !providerVerificationPurposeSet.has(target.purpose)) fail(UNSUPPORTED_ACTION);
    validateOutcome(value.action, value.outcome, value.after_state);
    return Object.freeze({
      version: MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION,
      action: value.action,
      target,
      outcome: value.outcome,
      after_state: value.after_state,
      organization_correlation: "unavailable",
      human_exposure: "forbidden",
    });
  }

  return Object.freeze({
    version: MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_VERSION,
    provider_verification_purposes: providerVerificationPurposes,
    allowedActions,
    normalizeDetail,
    normalizeCommand,
    normalizeResult,
  });
}

function normalizeTarget(value) {
  exactKeys(value, TARGET_FIELDS);
  if (!PURPOSE.test(value.purpose ?? "") || !REGISTERED_PURPOSE_SET.has(value.purpose)
    || !OPERATION_ID.test(value.operation_id ?? "")) fail(INVALID_INPUT);
  return Object.freeze({ purpose: value.purpose, operation_id: value.operation_id });
}

function normalizeExpected(value) {
  exactKeys(value, EXPECTED_FIELDS);
  if (value.algorithm !== ALGORITHM
    || value.state !== "uncertain"
    || !Number.isSafeInteger(value.bytes_length)
    || value.bytes_length < 1
    || value.bytes_length > MAX_BYTES
    || !DIGEST.test(value.request_digest ?? "")
    || !KEY_ID.test(value.key_id ?? "")
    || !validKeyVersion(value.key_version)
    || !PROVIDER_OPERATION_UNCERTAIN_REASONS.includes(value.uncertain_reason)
    || !PROVIDER_RESULT_STATES.includes(value.provider_result)) fail(INVALID_INPUT);
  return Object.freeze({
    algorithm: ALGORITHM,
    bytes_length: value.bytes_length,
    request_digest: value.request_digest,
    key_id: value.key_id,
    key_version: value.key_version,
    state: "uncertain",
    uncertain_reason: value.uncertain_reason,
    provider_result: value.provider_result,
  });
}

function normalizeProviderVerificationPurposes(value) {
  if (!Array.isArray(value) || value.length > REGISTERED_PURPOSES.length) fail(INVALID_INPUT);
  const normalized = [...value];
  if (new Set(normalized).size !== normalized.length || normalized.some((purpose) => !REGISTERED_PURPOSE_SET.has(purpose))) {
    fail(INVALID_INPUT);
  }
  return Object.freeze(normalized.sort());
}

function validKeyVersion(value) {
  return typeof value === "string"
    && KEY_VERSION.test(value)
    && (value.length < MAX_POSTGRES_BIGINT.length || value <= MAX_POSTGRES_BIGINT);
}

function validateOutcome(action, outcome, afterState) {
  const terminal = ["reconciled", "verified"].includes(outcome);
  if (terminal && afterState !== "committed") fail(INVALID_INPUT);
  if (!terminal && afterState !== "uncertain") fail(INVALID_INPUT);
  if (action === "exact_sql_reconciliation"
    && !["reconciled", "no_match", "stale", "unavailable"].includes(outcome)) fail(INVALID_INPUT);
  if (action === "provider_bound_verification"
    && !["verified", "no_match", "stale", "unsupported", "unavailable"].includes(outcome)) fail(INVALID_INPUT);
  if (action === "producer_specific_terminal_handoff"
    && !["handed_off", "stale", "unavailable"].includes(outcome)) fail(INVALID_INPUT);
  if (outcome === "handed_off" && afterState !== "uncertain") fail(INVALID_INPUT);
}

function exactKeys(value, keys) {
  if (!isPlainObject(value)) fail(INVALID_INPUT);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail(INVALID_INPUT);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value") || descriptor.value === undefined) {
      fail(INVALID_INPUT);
    }
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function fail(code) {
  throw new ManagedSignerProviderOperationAdjudicationError(code);
}

// Keep the reason import and the tenant boundary visible to contract tests and
// future callers without allowing a mutable Set to escape this module.
export const MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_UNCERTAIN_REASONS = Object.freeze([
  ...PROVIDER_OPERATION_UNCERTAIN_REASONS,
]);

export default createManagedSignerProviderOperationAdjudicationContract;
