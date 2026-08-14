import assert from "node:assert/strict";
import test from "node:test";

import {
  MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ACTIONS,
  MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_ERROR_CODES as CODES,
  MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_PRODUCERS,
  MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_PROHIBITED_FIELDS,
  MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_UNCERTAIN_REASONS,
  ManagedSignerProviderOperationAdjudicationError,
  createManagedSignerProviderOperationAdjudicationContract,
  normalizeManagedSignerProviderOperationUncertaintyList,
  normalizeManagedSignerProviderOperationUncertaintySummary,
} from "../src/managed-signer-provider-operation-adjudication.mjs";

const SUMMARY = {
  version: 1,
  purpose: "agentpass.capability",
  operation_id: "op-adjudication-001",
  algorithm: "ed25519",
  bytes_length: 128,
  request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  key_id: "managed-key-2026",
  key_version: "7",
  state: "uncertain",
  uncertain_reason: "provider_response_lost",
  provider_result: "present",
};

function target() {
  return { purpose: SUMMARY.purpose, operation_id: SUMMARY.operation_id };
}

function expected(providerResult = SUMMARY.provider_result) {
  return {
    algorithm: SUMMARY.algorithm,
    bytes_length: SUMMARY.bytes_length,
    request_digest: SUMMARY.request_digest,
    key_id: SUMMARY.key_id,
    key_version: SUMMARY.key_version,
    state: SUMMARY.state,
    uncertain_reason: SUMMARY.uncertain_reason,
    provider_result: providerResult,
  };
}

function command(action = "exact_sql_reconciliation", providerResult = SUMMARY.provider_result) {
  return {
    version: 1,
    action,
    target: target(),
    expected: expected(providerResult),
    ...(action === "producer_specific_terminal_handoff"
      ? { producer: "managed_signer_key_lifecycle" }
      : {}),
  };
}

function invalidInput(value, code = CODES.INVALID_INPUT) {
  assert.throws(() => normalizeManagedSignerProviderOperationUncertaintySummary(value), (error) => {
    assert.ok(error instanceof ManagedSignerProviderOperationAdjudicationError);
    assert.equal(error.code, code);
    assert.equal(error.cause, undefined);
    return true;
  });
}

test("publishes a frozen, tenant-neutral uncertain summary with no provider output", () => {
  const summary = normalizeManagedSignerProviderOperationUncertaintySummary(SUMMARY);

  assert.deepEqual(summary, {
    ...SUMMARY,
    organization_correlation: "unavailable",
    human_exposure: "forbidden",
  });
  assert.equal(Object.isFrozen(summary), true);
  assert.deepEqual(Object.keys(summary), [
    "version", "purpose", "operation_id", "algorithm", "bytes_length", "request_digest",
    "key_id", "key_version", "state", "uncertain_reason", "provider_result",
    "organization_correlation", "human_exposure",
  ]);
  assert.equal(MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_UNCERTAIN_REASONS.includes(SUMMARY.uncertain_reason), true);
  assert.equal(Object.isFrozen(MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_UNCERTAIN_REASONS), true);

  const normalizedAgain = normalizeManagedSignerProviderOperationUncertaintySummary(summary);
  assert.deepEqual(normalizedAgain, summary);
});

test("rejects provider output, signing material, diagnostics, tenant selectors, and arbitrary fields", () => {
  for (const field of MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_PROHIBITED_FIELDS) {
    invalidInput({ ...SUMMARY, [field]: field === "bytes" || field === "signing_bytes" ? Buffer.from("secret") : "forbidden" });
  }
  invalidInput({ ...SUMMARY, organization_correlation: { organization_id: "org-1" } });
  invalidInput({ ...SUMMARY, human_exposure: "allowed" });
  invalidInput({ ...SUMMARY, unknown: true });
  invalidInput({ ...SUMMARY, state: "committed" });
  invalidInput({ ...SUMMARY, purpose: "agentpass.not-registered" });
  invalidInput({ ...SUMMARY, uncertain_reason: "made_up_reason" });
  invalidInput({ ...SUMMARY, bytes_length: 1_048_577 });
});

test("normalizes a bounded uncertainty page and never accepts an organization selector", () => {
  const page = normalizeManagedSignerProviderOperationUncertaintyList({
    version: 1,
    items: [SUMMARY],
    next_cursor: "opaque_cursor_1",
  });
  assert.equal(Object.isFrozen(page), true);
  assert.equal(Object.isFrozen(page.items), true);
  assert.equal(Object.isFrozen(page.items[0]), true);
  assert.equal(page.organization_correlation, "unavailable");
  assert.equal(page.human_exposure, "forbidden");
  assert.throws(() => normalizeManagedSignerProviderOperationUncertaintyList({
    version: 1,
    items: Array.from({ length: 101 }, () => SUMMARY),
    next_cursor: null,
  }), { code: CODES.INVALID_INPUT });
  assert.throws(() => normalizeManagedSignerProviderOperationUncertaintyList({
    version: 1,
    items: [SUMMARY],
    next_cursor: "not a cursor",
  }), { code: CODES.INVALID_INPUT });
  assert.throws(() => normalizeManagedSignerProviderOperationUncertaintyList({
    version: 1,
    items: [SUMMARY],
    next_cursor: null,
    organization_id: "org-1",
  }), { code: CODES.INVALID_INPUT });
});

test("derives only invariant-safe actions; provider verification is explicit server capability", () => {
  const defaultContract = createManagedSignerProviderOperationAdjudicationContract();
  assert.equal(Object.isFrozen(defaultContract), true);
  assert.deepEqual(defaultContract.provider_verification_purposes, []);
  assert.deepEqual(defaultContract.allowedActions(SUMMARY), [
    "exact_sql_reconciliation",
    "producer_specific_terminal_handoff",
  ]);
  assert.deepEqual(defaultContract.allowedActions({ ...SUMMARY, provider_result: "absent" }), [
    "producer_specific_terminal_handoff",
  ]);
  const detail = defaultContract.normalizeDetail({
    summary: SUMMARY,
    allowed_actions: ["exact_sql_reconciliation", "producer_specific_terminal_handoff"],
  });
  assert.equal(Object.isFrozen(detail), true);
  assert.deepEqual(detail.allowed_actions, defaultContract.allowedActions(SUMMARY));
  assert.equal(detail.human_exposure, "forbidden");
  assert.throws(() => defaultContract.normalizeDetail({
    summary: SUMMARY,
    allowed_actions: ["provider_bound_verification", "producer_specific_terminal_handoff"],
  }), { code: CODES.INVALID_INPUT });

  const providerContract = createManagedSignerProviderOperationAdjudicationContract({
    providerVerificationPurposes: ["agentpass.capability"],
  });
  assert.deepEqual(providerContract.provider_verification_purposes, ["agentpass.capability"]);
  assert.deepEqual(providerContract.allowedActions(SUMMARY), [
    "exact_sql_reconciliation",
    "provider_bound_verification",
    "producer_specific_terminal_handoff",
  ]);
});

test("adjudication commands are exact and reject generic retry, caller output, and tenant mutation", () => {
  const contract = createManagedSignerProviderOperationAdjudicationContract({
    providerVerificationPurposes: ["agentpass.capability"],
  });
  const sql = contract.normalizeCommand(command());
  assert.deepEqual(sql, command());
  assert.equal(Object.isFrozen(sql), true);
  assert.equal(Object.isFrozen(sql.target), true);
  assert.equal(Object.isFrozen(sql.expected), true);

  const verify = contract.normalizeCommand(command("provider_bound_verification"));
  assert.equal(verify.action, "provider_bound_verification");
  const handoff = contract.normalizeCommand(command("producer_specific_terminal_handoff", "absent"));
  assert.equal(handoff.producer, MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION_PRODUCERS[0]);

  for (const action of ["retry_sign", "confirm", "reject", "generic_retry", "caller_supplied_signature"]) {
    assert.throws(() => contract.normalizeCommand({ ...command(), action }), { code: CODES.UNSUPPORTED_ACTION });
  }
  assert.throws(() => contract.normalizeCommand(command("exact_sql_reconciliation", "absent")), { code: CODES.UNSUPPORTED_ACTION });
  assert.throws(() => contract.normalizeCommand({ ...command(), signature: "caller-output" }), { code: CODES.INVALID_INPUT });
  assert.throws(() => contract.normalizeCommand({ ...command(), provider_receipt: "caller-receipt" }), { code: CODES.INVALID_INPUT });
  assert.throws(() => contract.normalizeCommand({ ...command(), provider_diagnostics: "debug" }), { code: CODES.INVALID_INPUT });
  assert.throws(() => contract.normalizeCommand({ ...command(), organization_id: "org-1" }), { code: CODES.INVALID_INPUT });
  assert.throws(() => contract.normalizeCommand({ ...command("producer_specific_terminal_handoff"), producer: "arbitrary-producer" }), { code: CODES.INVALID_INPUT });
  assert.throws(() => contract.normalizeCommand({ ...command("producer_specific_terminal_handoff"), terminal_state: "rejected" }), { code: CODES.INVALID_INPUT });
});

test("provider-bound verification is unavailable until the server supplies that capability", () => {
  const contract = createManagedSignerProviderOperationAdjudicationContract();
  assert.throws(() => contract.normalizeCommand(command("provider_bound_verification")), { code: CODES.UNSUPPORTED_ACTION });
  assert.throws(() => contract.normalizeResult({
    version: 1,
    action: "provider_bound_verification",
    target: target(),
    outcome: "verified",
    after_state: "committed",
  }), { code: CODES.UNSUPPORTED_ACTION });
});

test("provider-bound verification is purpose-bound and denies a different purpose", () => {
  const contract = createManagedSignerProviderOperationAdjudicationContract({
    providerVerificationPurposes: ["agentpass.capability"],
  });
  const otherPurpose = "agentpass.control-bundle";
  const otherSummary = { ...SUMMARY, purpose: otherPurpose, operation_id: "op-other-purpose-001" };
  assert.deepEqual(contract.allowedActions(otherSummary), [
    "exact_sql_reconciliation",
    "producer_specific_terminal_handoff",
  ]);
  assert.throws(() => contract.normalizeCommand({
    ...command("provider_bound_verification"),
    target: { purpose: otherPurpose, operation_id: otherSummary.operation_id },
  }), { code: CODES.UNSUPPORTED_ACTION });
  assert.throws(() => contract.normalizeResult({
    version: 1,
    action: "provider_bound_verification",
    target: { purpose: otherPurpose, operation_id: otherSummary.operation_id },
    outcome: "verified",
    after_state: "committed",
  }), { code: CODES.UNSUPPORTED_ACTION });
  assert.throws(() => createManagedSignerProviderOperationAdjudicationContract({
    providerVerificationPurposes: ["agentpass.not-registered"],
  }), { code: CODES.INVALID_INPUT });
});

test("accepts only PostgreSQL bigint key versions", () => {
  const maximum = "9223372036854775807";
  const valid = normalizeManagedSignerProviderOperationUncertaintySummary({
    ...SUMMARY,
    key_version: maximum,
  });
  assert.equal(valid.key_version, maximum);
  for (const keyVersion of ["9223372036854775808", "9999999999999999999", "1".repeat(32), "01", "0"]) {
    invalidInput({ ...SUMMARY, key_version: keyVersion });
  }
  const commandValue = command();
  assert.throws(() => createManagedSignerProviderOperationAdjudicationContract().normalizeCommand({
    ...commandValue,
    expected: { ...commandValue.expected, key_version: "9223372036854775808" },
  }), { code: CODES.INVALID_INPUT });
});

test("result normalization prevents false terminal outcomes and keeps handoff non-terminal", () => {
  const contract = createManagedSignerProviderOperationAdjudicationContract({
    providerVerificationPurposes: ["agentpass.capability"],
  });
  const reconciled = contract.normalizeResult({
    version: 1,
    action: "exact_sql_reconciliation",
    target: target(),
    outcome: "reconciled",
    after_state: "committed",
  });
  assert.equal(Object.isFrozen(reconciled), true);
  assert.equal(reconciled.organization_correlation, "unavailable");
  assert.equal(reconciled.human_exposure, "forbidden");

  for (const [action, outcome, after_state] of [
    ["exact_sql_reconciliation", "verified", "committed"],
    ["exact_sql_reconciliation", "reconciled", "uncertain"],
    ["provider_bound_verification", "verified", "uncertain"],
    ["producer_specific_terminal_handoff", "handed_off", "committed"],
    ["producer_specific_terminal_handoff", "reconciled", "uncertain"],
  ]) {
    assert.throws(() => contract.normalizeResult({ version: 1, action, target: target(), outcome, after_state }), {
      code: CODES.INVALID_INPUT,
    });
  }

  const handoff = contract.normalizeResult({
    version: 1,
    action: "producer_specific_terminal_handoff",
    target: target(),
    outcome: "handed_off",
    after_state: "uncertain",
  });
  assert.equal(handoff.after_state, "uncertain");
  assert.equal(Object.hasOwn(handoff, "signature"), false);
  assert.equal(Object.hasOwn(handoff, "provider_receipt"), false);
  assert.equal(Object.hasOwn(handoff, "organization_id"), false);
});

test("tenant correlation failure is stable and never leaks driver or operator details", () => {
  assert.throws(() => normalizeManagedSignerProviderOperationUncertaintySummary({
    ...SUMMARY,
    organization_correlation: "org-1",
    human_exposure: "allowed",
  }), (error) => {
    assert.equal(error.code, CODES.TENANT_CORRELATION_UNAVAILABLE);
    assert.equal(error.message.includes("org-1"), false);
    return true;
  });
  assert.throws(() => normalizeManagedSignerProviderOperationUncertaintySummary({
    ...SUMMARY,
    organization_correlation: "unavailable",
    human_exposure: "forbidden",
    extra_secret: "provider diagnostics and signing bytes",
  }), (error) => {
    assert.equal(error.code, CODES.INVALID_INPUT);
    assert.equal(error.message.includes("provider diagnostics"), false);
    return true;
  });
  assert.equal(CODES.TENANT_CORRELATION_UNAVAILABLE, "managed_signer_provider_operation_adjudication_tenant_correlation_unavailable");
});
