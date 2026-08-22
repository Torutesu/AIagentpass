import assert from "node:assert/strict";
import test from "node:test";
import { validateExternalExecutionBoundary } from "./verify-external-artifact-provenance.mjs";

const passing = {
  execution: {
    kind: "external_runner",
    real_execution: true,
    runner_id: "protected-postgresql-runner",
    environment: { kind: "postgresql", identity: "pg16-production-01" }
  }
};

test("promotion boundary rejects not_run evidence with no external execution", () => {
  assert.throws(() => validateExternalExecutionBoundary({ status: "not_run", qualified: false }), /execution identity is missing/u);
});

test("promotion boundary rejects local, static, and simulated runner identities", () => {
  for (const runner_id of ["local-runner", "static-fixture", "simulator-01"]) {
    assert.throws(() => validateExternalExecutionBoundary({ execution: { ...passing.execution, runner_id } }), /runner identity/u);
  }
});

test("promotion boundary rejects unknown or placeholder environment identities", () => {
  for (const identity of ["unknown", "unidentified", "placeholder-db", "redacted-environment"]) {
    assert.throws(() => validateExternalExecutionBoundary({ execution: { ...passing.execution, environment: { ...passing.execution.environment, identity } } }), /environment identity/u);
  }
});

test("promotion boundary rejects substituted execution mode and accepts only a real known identity", () => {
  assert.throws(() => validateExternalExecutionBoundary({ execution: { ...passing.execution, real_execution: false } }), /real external run/u);
  assert.deepEqual(validateExternalExecutionBoundary(passing), {
    runner_id: "protected-postgresql-runner",
    environment_identity: "pg16-production-01"
  });
});
