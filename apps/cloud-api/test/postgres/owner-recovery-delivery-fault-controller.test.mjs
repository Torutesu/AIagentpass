import assert from "node:assert/strict";
import test from "node:test";

import {
  createOwnerRecoveryDeliveryFaultController,
  OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES,
  OwnerRecoveryDeliveryFaultError
} from "../support/owner-recovery-delivery-fault-controller.mjs";

test("rejects unknown boundaries before arming or checkpointing", () => {
  for (const boundary of ["", "after_claim ", "after_claim\n", "provider_call", null, 1]) {
    assert.throws(() => createOwnerRecoveryDeliveryFaultController({ armedBoundary: boundary }), (error) => error.code === OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INVALID_BOUNDARY);
    assert.throws(() => createOwnerRecoveryDeliveryFaultController().arm(boundary), (error) => error.code === OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INVALID_BOUNDARY);
    assert.throws(() => createOwnerRecoveryDeliveryFaultController().checkpoint(boundary), (error) => error.code === OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INVALID_BOUNDARY);
  }
});

test("fires exactly once at the selected boundary", () => {
  const controller = createOwnerRecoveryDeliveryFaultController({ armedBoundary: "after_claim" });
  assert.throws(() => controller.checkpoint("after_claim"), (error) => {
    assert.equal(error instanceof OwnerRecoveryDeliveryFaultError, true);
    assert.equal(error.code, OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INJECTED);
    assert.equal(error.boundary, "after_claim");
    return true;
  });
  assert.deepEqual(controller.snapshot(), { armed: true, consumed: true, boundary: "after_claim" });
  assert.equal(controller.checkpoint("after_claim"), false);
  assert.equal(controller.hit("after_claim"), false);
});
