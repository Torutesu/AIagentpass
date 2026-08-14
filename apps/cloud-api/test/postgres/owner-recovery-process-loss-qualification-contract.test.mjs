import assert from "node:assert/strict";
import test from "node:test";

import {
  launchOwnerRecoveryProcessLossQualificationChild,
  OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES,
  OwnerRecoveryProcessLossQualificationError,
  requireOwnerRecoveryQualificationDatabase
} from "../support/owner-recovery-process-loss-qualification-harness.mjs";
import { OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES } from "../support/owner-recovery-delivery-fault-controller.mjs";

const NO_DATABASE_CONNECTION = "postgresql://qualification.invalid/qualification";
const UUID = "11111111-1111-4111-8111-111111111111";

test("requires the explicit PostgreSQL qualification variable without exposing its value", () => {
  assert.throws(
    () => requireOwnerRecoveryQualificationDatabase({}),
    (error) => error instanceof OwnerRecoveryProcessLossQualificationError
      && error.code === OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.DATABASE_REQUIRED
      && !String(error).includes("postgres")
  );
  assert.throws(
    () => requireOwnerRecoveryQualificationDatabase({ AGENTPASS_TEST_DATABASE_URL: "not-a-dsn" }),
    (error) => error.code === OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.DATABASE_INVALID
      && !String(error).includes("not-a-dsn")
  );
});

test("runs the bounded child protocol without PostgreSQL or production imports", async (t) => {
  const child = launchOwnerRecoveryProcessLossQualificationChild({
    databaseUrl: NO_DATABASE_CONNECTION,
    mode: "contract",
    boundary: "before_provider_call",
    deadlineMs: 3_000,
    maxOutputBytes: 4 * 1024,
    maxMessageBytes: 512
  });
  t.after(async () => { if (!child.snapshot().settled) await child.kill(); });

  assert.deepEqual(await child.waitForMessage("ready"), { type: "ready" });
  child.send({ type: "run" });
  assert.deepEqual(await child.waitForMessage("boundary_reached"), { type: "boundary_reached", boundary: "before_provider_call" });
  child.send({ type: "continue" });
  assert.deepEqual(await child.waitForMessage("completed"), { type: "completed", outcome: "published" });
  assert.deepEqual(await child.waitForExit(), { code: 0, signal: null });
  assert.ok(child.snapshot().stdout_bytes < 4 * 1024);
  assert.equal(child.snapshot().stderr_bytes, 0);
});

test("rejects unknown boundaries before starting a child", () => {
  assert.throws(
    () => launchOwnerRecoveryProcessLossQualificationChild({ databaseUrl: NO_DATABASE_CONNECTION, mode: "contract", boundary: "provider_call" }),
    (error) => error.code === OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.INVALID_ARGUMENT
  );
});

test("keeps the boundary set closed and rejects ambient fault controls", () => {
  assert.deepEqual(OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES, [
    "after_claim",
    "before_provider_call",
    "after_provider_acceptance",
    "before_terminal_commit",
    "after_terminal_commit",
    "after_response_encoded"
  ]);
  const source = String(requireOwnerRecoveryQualificationDatabase);
  assert.doesNotMatch(source, /fault|boundary|provider|request|response|globalThis/iu);
});

test("terminates a child that exceeds the output budget without returning child output", async () => {
  const child = launchOwnerRecoveryProcessLossQualificationChild({
    databaseUrl: NO_DATABASE_CONNECTION,
    mode: "contract_noisy",
    maxOutputBytes: 128,
    maxMessageBytes: 128,
    deadlineMs: 3_000
  });
  await assert.rejects(() => child.waitForMessage("ready"), (error) => error.code === OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.OUTPUT_LIMIT);
  const exit = await child.waitForExit();
  assert.equal(exit.signal, "SIGKILL");
  assert.ok(child.snapshot().stdout_bytes > 128);
});
