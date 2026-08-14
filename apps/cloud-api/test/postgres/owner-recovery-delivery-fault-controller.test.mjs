import assert from "node:assert/strict";
import test from "node:test";

import {
  createOwnerRecoveryDeliveryFaultController,
  OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES,
  OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES,
  OwnerRecoveryDeliveryFaultError
} from "../support/owner-recovery-delivery-fault-controller.mjs";

test("exposes exactly the six closed delivery boundaries", () => {
  assert.deepEqual(OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES, [
    "after_claim",
    "before_provider_call",
    "after_provider_acceptance",
    "before_terminal_commit",
    "after_terminal_commit",
    "after_response_encoded"
  ]);
  assert.equal(Object.isFrozen(OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES), true);
});

test("is deterministic and a fresh controller is unarmed", () => {
  const first = createOwnerRecoveryDeliveryFaultController();
  const second = createOwnerRecoveryDeliveryFaultController();
  assert.deepEqual(first.snapshot(), { armed: false, consumed: false, boundary: undefined });
  assert.deepEqual(first.snapshot(), second.snapshot());
  for (const boundary of OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES) {
    assert.equal(first.checkpoint(boundary), false);
    assert.equal(first.hit(boundary), false);
  }
});

test("rejects unknown boundaries before arming or checkpointing", () => {
  for (const boundary of ["", "after_claim ", "after_claim\n", "provider_call", null, 1]) {
    assert.throws(() => createOwnerRecoveryDeliveryFaultController({ armedBoundary: boundary }), (error) => error.code === OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INVALID_BOUNDARY);
    assert.throws(() => createOwnerRecoveryDeliveryFaultController().arm(boundary), (error) => error.code === OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INVALID_BOUNDARY);
    assert.throws(() => createOwnerRecoveryDeliveryFaultController().checkpoint(boundary), (error) => error.code === OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.INVALID_BOUNDARY);
  }
});

test("arms one named boundary and ignores the other five", () => {
  const controller = createOwnerRecoveryDeliveryFaultController();
  assert.deepEqual(controller.arm("before_provider_call"), {
    armed: true,
    consumed: false,
    boundary: "before_provider_call"
  });
  for (const boundary of OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES) {
    if (boundary === "before_provider_call") continue;
    assert.equal(controller.checkpoint(boundary), false);
  }
  assert.deepEqual(controller.snapshot(), {
    armed: true,
    consumed: false,
    boundary: "before_provider_call"
  });
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

test("does not allow a second arm on the same controller", () => {
  const controller = createOwnerRecoveryDeliveryFaultController({ armedBoundary: "after_terminal_commit" });
  assert.throws(() => controller.arm("after_response_encoded"), (error) => error.code === OWNER_RECOVERY_DELIVERY_FAULT_ERROR_CODES.ALREADY_ARMED);
  assert.deepEqual(controller.snapshot(), { armed: true, consumed: false, boundary: "after_terminal_commit" });
});

test("supports every fixed boundary with the same one-shot behavior", () => {
  for (const boundary of OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES) {
    const controller = createOwnerRecoveryDeliveryFaultController({ armedBoundary: boundary });
    assert.throws(() => controller.hit(boundary), (error) => error.boundary === boundary);
    assert.equal(controller.hit(boundary), false);
  }
});

test("has no ambient or request-controlled control surface", () => {
  const source = createOwnerRecoveryDeliveryFaultController.toString();
  assert.doesNotMatch(source, /process\.env|globalThis|fetch|request|response|JSON/u);
  assert.deepEqual(Object.keys(createOwnerRecoveryDeliveryFaultController()), ["arm", "checkpoint", "hit", "snapshot"]);
});
