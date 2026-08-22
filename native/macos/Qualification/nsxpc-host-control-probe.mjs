const DIGEST = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MACH_SERVICE = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,127}$/u;
const BUNDLE_ID = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,127}$/u;
const DEVELOPER_ID = /^Developer ID Application: [^\r\n()]+ \([A-Z0-9]{10}\)$/u;

export const NSXPC_HOST_CONTROL_PROBE_CONTRACT_VERSION = 1;
export const HOST_MACH_SERVICE = "dev.agentpass.agent-host";
export const HOST_CONTROL_MACH_SERVICE = "dev.agentpass.agent-host-control";
export const HOST_BUNDLE_ID = "dev.agentpass.agent-host";
export const CONTROL_CLIENT_BUNDLE_ID = "dev.agentpass.native-client";

const fail = (message) => { throw new Error(`NSXPC host-control probe: ${message}`); };

function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`);
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${label} must be a positive safe integer`);
}

function uuid(value, label) {
  if (typeof value !== "string" || !UUID.test(value)) fail(`${label} must be a canonical lowercase UUIDv4`);
}

function processIdentity(value, label, expectedBundleID) {
  exact(value, ["pid", "start_time_ns", "code_directory_sha256", "bundle_identifier", "signing_identity"], label);
  positiveInteger(value.pid, `${label}.pid`);
  positiveInteger(value.start_time_ns, `${label}.start_time_ns`);
  if (typeof value.code_directory_sha256 !== "string" || !DIGEST.test(value.code_directory_sha256)) fail(`${label}.code_directory_sha256 is invalid`);
  if (value.bundle_identifier !== expectedBundleID || !BUNDLE_ID.test(value.bundle_identifier)) fail(`${label}.bundle_identifier is not the expected process`);
  if (typeof value.signing_identity !== "string" || !DEVELOPER_ID.test(value.signing_identity)) fail(`${label}.signing_identity is not a Developer ID Application identity`);
}

function validateSeparateProcessClose(value, sessionID, operationID, host, controller) {
  exact(value, ["session_id", "operation_id", "requested_by_pid", "target_host_pid", "distinct_processes", "used_control_mach_service", "receipt"], "separate_process_close");
  if (value.session_id !== sessionID) fail("separate_process_close.session_id is not bound to the probe session");
  if (value.operation_id !== operationID) fail("separate_process_close.operation_id is not bound to the probe operation");
  if (value.requested_by_pid !== controller.pid) fail("separate_process_close.requested_by_pid is not the controller process");
  if (value.target_host_pid !== host.pid) fail("separate_process_close.target_host_pid is not the observed Host process");
  if (value.distinct_processes !== true || value.used_control_mach_service !== true) fail("separate-process control invocation was not proven");
  exact(value.receipt, ["status", "session_id", "operation_id", "closed_at_ms"], "separate_process_close.receipt");
  if (value.receipt.status !== "closed" || value.receipt.session_id !== sessionID || value.receipt.operation_id !== operationID) fail("close receipt is not bound to the requested session and operation");
  positiveInteger(value.receipt.closed_at_ms, "separate_process_close.receipt.closed_at_ms");
}

function validatePostCloseDenial(value, sessionID, host) {
  exact(value, ["session_id", "attempted_by_pid", "attempted_after_close", "status", "reason"], "post_close_sign_rejected");
  if (value.session_id !== sessionID) fail("post_close_sign_rejected.session_id is not bound to the closed session");
  if (value.attempted_by_pid !== host.pid) fail("post_close_sign_rejected.attempted_by_pid is not the Host process");
  if (value.attempted_after_close !== true || value.status !== "rejected" || value.reason !== "endpoint_closed") fail("post-close signing denial was not proven");
}

function validateResponseLossRetry(value, sessionID, operationID) {
  exact(value, ["session_id", "operation_id", "first_attempt_response_lost", "reconnected_before_retry", "retry_attempted", "same_operation_id", "retry_receipt", "no_second_close_effect", "terminal_state", "converged"], "response_loss_retry");
  if (value.session_id !== sessionID || value.operation_id !== operationID) fail("response-loss retry is not bound to the original session and operation");
  if (value.first_attempt_response_lost !== true || value.reconnected_before_retry !== true || value.retry_attempted !== true || value.same_operation_id !== true) fail("response-loss retry did not prove a reconnect and exact-operation retry");
  exact(value.retry_receipt, ["status", "session_id", "operation_id", "closed_at_ms"], "response_loss_retry.retry_receipt");
  if (value.retry_receipt.status !== "closed" || value.retry_receipt.session_id !== sessionID || value.retry_receipt.operation_id !== operationID) fail("retry receipt is not the original idempotent close receipt");
  positiveInteger(value.retry_receipt.closed_at_ms, "response_loss_retry.retry_receipt.closed_at_ms");
  if (value.no_second_close_effect !== true || value.terminal_state !== "closed" || value.converged !== true) fail("response-loss retry did not converge to the closed terminal state");
}

/**
 * Validate the output emitted by the protected, separately supplied macOS
 * NSXPC probe. This is intentionally independent of the probe executable:
 * absence of the executable or any field below must fail the qualification.
 */
export function validateNSXPCHostControlProbe(value) {
  exact(value, [
    "contract_version", "mach_service", "control_mach_service", "connection_accepted", "authorized_client", "wrong_identity_denied",
    "host_process", "control_client_process", "separate_process_close", "post_close_sign_rejected", "response_loss_retry"
  ], "NSXPC host-control observation");
  if (value.contract_version !== NSXPC_HOST_CONTROL_PROBE_CONTRACT_VERSION) fail("unsupported contract version");
  if (value.mach_service !== HOST_MACH_SERVICE || !MACH_SERVICE.test(value.mach_service)) fail("mach_service is not the fixed Host service");
  if (value.control_mach_service !== HOST_CONTROL_MACH_SERVICE || !MACH_SERVICE.test(value.control_mach_service)) fail("control_mach_service is not the fixed control service");
  if (value.connection_accepted !== true || value.authorized_client !== true || value.wrong_identity_denied !== true) fail("baseline authenticated-XPC observations are incomplete");
  processIdentity(value.host_process, "host_process", HOST_BUNDLE_ID);
  processIdentity(value.control_client_process, "control_client_process", CONTROL_CLIENT_BUNDLE_ID);
  if (value.host_process.pid === value.control_client_process.pid && value.host_process.start_time_ns === value.control_client_process.start_time_ns) fail("Host and control client are not separate processes");

  const sessionID = value.separate_process_close.session_id;
  const operationID = value.separate_process_close.operation_id;
  uuid(sessionID, "separate_process_close.session_id");
  uuid(operationID, "separate_process_close.operation_id");
  validateSeparateProcessClose(value.separate_process_close, sessionID, operationID, value.host_process, value.control_client_process);
  validatePostCloseDenial(value.post_close_sign_rejected, sessionID, value.host_process);
  validateResponseLossRetry(value.response_loss_retry, sessionID, operationID);
  return value;
}
