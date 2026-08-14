const BOUNDARIES = [
  "after_claim",
  "before_provider_call",
  "after_provider_acceptance",
  "before_terminal_commit",
  "after_terminal_commit",
  "after_response_encoded"
];

export const OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES = Object.freeze(BOUNDARIES);

export const OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES = Object.freeze({
  INVALID_BOUNDARY: "owner_recovery_delivery_fault_invalid_boundary",
  INJECTED: "owner_recovery_delivery_fault_injected",
  ALREADY_ARMED: "owner_recovery_delivery_fault_already_armed"
});

export class OwnerRecoveryDeliveryFaultError extends Error {
  constructor(boundary) {
    super(`Owner recovery delivery fault injected at ${boundary}`);
    this.name = "OwnerRecoveryDeliveryFaultError";
    this.code = OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INJECTED;
    this.boundary = boundary;
  }
}

/**
 * A deliberately closed, synchronous fault switch for W1.5 tests.
 *
 * The only way to arm a fault is an explicit call made by test code. A known
 * boundary is consumed exactly once; all other known boundaries are no-ops.
 * There is no clock, randomness, process state, environment lookup, request
 * parsing, or implicit default arm.
 */
export function createOwnerRecoveryDeliveryFaultController({ armedBoundary } = {}) {
  let armed = false;
  let consumed = false;
  let selectedBoundary;

  if (armedBoundary !== undefined) {
    validateBoundary(armedBoundary);
    selectedBoundary = armedBoundary;
    armed = true;
  }

  function arm(boundary) {
    validateBoundary(boundary);
    if (armed) throw alreadyArmed();
    selectedBoundary = boundary;
    armed = true;
    consumed = false;
    return snapshot();
  }

  function checkpoint(boundary) {
    validateBoundary(boundary);
    if (!armed || consumed || selectedBoundary !== boundary) return false;
    consumed = true;
    throw new OwnerRecoveryDeliveryFaultError(boundary);
  }

  function snapshot() {
    return Object.freeze({
      armed,
      consumed,
      boundary: selectedBoundary
    });
  }

  return Object.freeze({
    arm,
    checkpoint,
    hit: checkpoint,
    snapshot
  });
}

function validateBoundary(boundary) {
  if (typeof boundary !== "string" || !BOUNDARIES.includes(boundary)) {
    throw Object.assign(new TypeError("Unknown owner recovery delivery fault boundary"), {
      code: OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INVALID_BOUNDARY
    });
  }
}

function alreadyArmed() {
  return Object.assign(new Error("Owner recovery delivery fault controller is already armed"), {
    code: OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.ALREADY_ARMED
  });
}

export default createOwnerRecoveryDeliveryFaultController;
